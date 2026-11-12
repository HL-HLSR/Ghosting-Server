"use strict";

// I1 + I2 (review 1): the H2 outbound credit was earned per inbound packet of
// ANY opcode at a fixed MAX_PLAYERS*300, so
//   - a forger farmed it with 15-byte empty chats (148-275x measured), and
//   - a real player sending fewer lines than the others (low updaterate, an
//     unfocused window at ~18 fps) or a lobby whose slots were raised live got
//     57-76 % of the position packets: stuttering ghosts.
// Credit is now earned only from ACCEPTED 'l' updates (past the 15 ms throttle),
// sized at use time from the current number of confirmed others and the observed
// largest info packet, so a receiver at the client's floor rate is fully served
// against senders at the protocol's maximum.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { BufferWriter } = require("../src/wire/writer");

const HELD = "models/props_c17/oildrum001.mdl"; // a carried prop makes the info packet ~171 B

// A lobby where each player sends 'l' at its own rate. Returns, for P00, the
// share of the other players' relayed positions it actually received.
const simulate = ({ players, rate, env, live, seconds = 6, held = HELD }) => {
  const { server, socket, clock } = h.makeServer(env || {});
  if (live) server.setMaxPlayers(live);
  const users = [];
  for (let i = 0; i < players; i++) {
    const name = `P${String(i).padStart(2, "0")}xxxxxxxxxxxxxxx`;
    const r = h.from(`10.${i >> 8}.${i & 255}.1`, 50000 + i);
    server.onDatagram(h.connect(name), r);
    users.push({ name, r, interval: 1000 / rate(i), next: 0 });
  }
  for (const u of users) server.onDatagram(h.update(u.name, { map: "d1_canals_01a" }), u.r);
  const t0 = clock.now();
  for (const u of users) u.next = t0;
  // Measured from the first instant: P00 confirmed while it was alone, so its
  // first credit was sized for an empty lobby; the server re-sizes that line's
  // entitlement once the lobby has grown (shouldMeter), so even this first
  // interval is served.
  const warm = t0;
  let mark = null;
  let othersAccepted = 0;
  while (clock.now() < t0 + seconds * 1000) {
    const now = clock.now();
    if (mark === null && now >= warm) mark = socket.sent.length;
    for (let i = 0; i < users.length; i++) {
      const u = users[i];
      if (now < u.next) continue;
      u.next += u.interval;
      const ok = server.onDatagram(h.update(u.name, { map: "d1_canals_01a", position: [now % 977, i, 0], heldModel: held }), u.r);
      if (ok && i !== 0 && mark !== null) othersAccepted += 1;
    }
    clock.advance(1);
  }
  const got = h.sentTo(socket, users[0].r.address, users[0].r.port, mark)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.INFO).length;
  return got / othersAccepted;
};

for (const rx of [10, 15, 20]) {
  test(`I1: a receiver at ${rx} pps gets >= 99 % against 15 senders at 50-66 pps`, () => {
    const share = simulate({ players: 16, rate: (i) => (i === 0 ? rx : 50 + ((i * 7) % 17)) });
    assert.ok(share >= 0.99, `P00 at ${rx} pps received ${(share * 100).toFixed(1)} %`);
  });
}

test("I1: a live maxplayers raise keeps every receiver served", () => {
  // Started with the default 16 slots, raised to 64 while running, 48 players at
  // the ~33 pps the client really sends at updaterate 50.
  const share = simulate({ players: 48, rate: () => 33, live: 64, seconds: 4 });
  assert.ok(share >= 0.99, `P00 received ${(share * 100).toFixed(1)} % after a live slot raise`);
});

test("I2: tiny chat packets earn a forger no outbound credit", () => {
  const run = (tinyPerSecond) => {
    const { server, socket, clock } = h.makeServer();
    const real = [];
    for (let i = 0; i < 15; i++) {
      const r = h.from(`203.0.113.${i + 10}`, 27000 + i);
      real.push(r);
      server.onDatagram(h.connect(`real${i}`), r);
      server.onDatagram(h.update(`real${i}`), r);
    }
    const victim = h.from("198.51.100.200", 9999);
    const w = new BufferWriter();
    w.writeString("m"); w.writeString("rf"); w.writeString("");
    const tiny = w.buffer;
    server.onDatagram(h.connect("rf"), victim);
    server.onDatagram(h.update("rf"), victim);
    const before = socket.sent.length;
    let nextTiny = 0;
    let nextLine = 0;
    for (let t = 0; t < 20000; t += 20) {
      for (let i = 0; i < 15; i++) server.onDatagram(h.update(`real${i}`, { position: [t % 1000, i, 0] }), real[i]);
      if (t >= nextLine) { server.onDatagram(h.update("rf", { position: [1, 2, 3] }), victim); nextLine = t + 2500; }
      if (tinyPerSecond && t >= nextTiny) { server.onDatagram(tiny, victim); nextTiny = t + 1000 / tinyPerSecond; }
      clock.advance(20);
    }
    return socket.sent.slice(before).filter((p) => p.address === victim.address)
      .reduce((a, p) => a + p.buffer.length, 0);
  };
  const plain = run(0);
  const farmed = run(20);
  // Heartbeats are identical in both; a chat earns nothing, so the bytes match.
  assert.ok(farmed <= plain * 1.02, `20 tiny chats/s raised the victim's bytes from ${plain} to ${farmed}`);
});
