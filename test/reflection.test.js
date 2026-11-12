"use strict";

// H2: a forged confirmed session turned the lobby into a reflector. Two forged
// datagrams made a session, after which the victim received every player's
// 50 Hz position stream: the audit measured 2.83 MB to the victim for 263
// attacker bytes, about 10 765x. The fix meters the high-volume fan-out
// (positions and the spray drip) against outbound credit a session earns with
// accepted position updates, and gates it on liveness, so a forged endpoint
// that barely sends barely receives. What it cannot do is go below the inherent
// fan-out ratio of a slow REAL client without starving one (see boundFor).

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");

// The bound the metering promises, by construction: per accepted line a session
// may receive the fan-out a receiver at the floor rate needs, i.e.
// (others x 66.7 / floor) x largest info packet, scaled down for a line shorter
// than the 100 B the shipped client sends. Divided by the bytes of that line, the
// worst a forger can get per byte it sends is
//   others x 66.7 / floor x largestInfo / 100.
// This is the inherent fan-out ratio of a slow real client; it cannot be lowered
// without starving low-rate players (review 1, I1).
const boundFor = (server, others) =>
  others * (1000 / 15) / server.config.outboundFloorPps * server.largestInfoBytes() / 100;

const amplification = ({ realN, forgerEvery, forgerOpts, held, seconds = 60 }) => {
  const { server, socket, clock } = h.makeServer({ MAX_PLAYERS: "16" });
  const real = [];
  for (let i = 0; i < realN; i++) {
    const r = h.from(`203.0.113.${i + 10}`, 27000 + i);
    real.push(r);
    server.onDatagram(h.connect(`real${i}`), r);
    server.onDatagram(h.update(`real${i}`), r);
  }
  const victim = h.from("198.51.100.200", 9999);
  let attackerBytes = 0;
  const forge = (b) => { attackerBytes += b.length; server.onDatagram(b, victim); };
  forge(h.connect("reflect"));
  forge(h.update("reflect", forgerOpts));
  const before = socket.sent.length;
  let next = forgerEvery;
  for (let t = 0; t < seconds * 1000; t += 20) {
    for (let i = 0; i < realN; i++) {
      server.onDatagram(h.update(`real${i}`, { position: [t % 1000, i, 0], heldModel: held || "" }), real[i]);
    }
    if (t >= next) { forge(h.update("reflect", Object.assign({ position: [t, 2, 3] }, forgerOpts))); next = t + forgerEvery; }
    clock.advance(20);
  }
  const victimBytes = socket.sent.slice(before).filter((p) => p.address === victim.address)
    .reduce((a, p) => a + p.buffer.length, 0);
  const toReal0 = socket.sent.slice(before)
    .filter((p) => p.address === real[0].address && p.port === real[0].port && p.buffer.readUInt8(0) === packets.TYPE.INFO).length;
  return { ratio: victimBytes / attackerBytes, bound: boundFor(server, realN), toReal0 };
};

test("the audit's forger (one 'l' every 50 s) reflects ~69x, not 10765x", () => {
  const r = amplification({ realN: 8, forgerEvery: 50000 });
  assert.ok(r.ratio <= 80, `amplification ${r.ratio.toFixed(1)}x`);
  // A real player at 50 Hz receives essentially all of the fan-out aimed at it:
  // 7 other players, ~3000 updates each over 60 s.
  assert.ok(r.toReal0 > 20000, `a real player received only ${r.toReal0} position packets`);
});

test("the worst adaptive forger stays within the documented bound (~185x at 16 players)", () => {
  // 15 real players at 50 Hz carrying props; the forger sends the smallest line
  // the server accepts (truncated after yaw) just inside the liveness window.
  const r = amplification({
    realN: 15,
    forgerEvery: 2900,
    forgerOpts: { upTo: "yaw" },
    held: "models/props_c17/oildrum001.mdl",
  });
  assert.ok(r.ratio <= r.bound * 1.05, `amplification ${r.ratio.toFixed(1)}x above the bound ${r.bound.toFixed(1)}x`);
  assert.ok(r.ratio <= 200, `amplification ${r.ratio.toFixed(1)}x (documented as ~185x at 16 players)`);
});

test("a duplicate connect re-sends no spray chunk a receiver already has", () => {
  const { server, clock } = h.makeServer();
  const a = h.from("203.0.113.1", 1);
  const b = h.from("203.0.113.2", 2);
  server.onDatagram(h.connect("A"), a); server.onDatagram(h.update("A"), a);
  server.onDatagram(h.connect("B"), b); server.onDatagram(h.update("B"), b);

  const { blob, crc } = h.sprayBlob(64, 1, true);
  h.uploadSpray(server, a, "A", crc, blob);

  // Let B fully receive the picture (B stays active so it is credited).
  for (let i = 0; i < 400; i++) {
    clock.advance(20);
    server.onDatagram(h.update("B"), b);
    server.dripSprays();
  }
  assert.strictEqual(server.users.get("B").sprayFeeds.size, 0, "B should have the whole picture");

  const before = server.socket.sent.length;
  // Forged duplicate connects from B's endpoint, spaced past the 5 s roster
  // throttle so each one really resends the roster, must not restart delivery -
  // and the drip has to RUN afterwards, or a re-queued picture would go unseen
  // (review 1, minor 10: the first version of this test never ran it).
  for (let i = 0; i < 4; i++) {
    clock.advance(6000);
    server.onDatagram(h.update("B"), b);
    server.onDatagram(h.connect("B"), b);
    for (let k = 0; k < 100; k++) {
      clock.advance(20);
      server.onDatagram(h.update("B"), b);
      server.dripSprays();
    }
  }
  const resent = server.socket.sent.slice(before).filter((p) => p.address === b.address && p.buffer[0] === packets.TYPE.SPRAY_CHUNK).length;
  assert.strictEqual(resent, 0, `a duplicate connect re-sent ${resent} spray chunks`);
});
