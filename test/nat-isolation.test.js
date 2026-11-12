"use strict";

// Sixteen players behind one public address, one of whom turns hostile.
//
// This is the scenario the rate limiting exists to survive, and the one it is
// easiest to get wrong: on a LAN or behind a home router every player shares an
// address, so any defence keyed purely on the address punishes the wrong people.
// The first version of the penalty box did exactly that, and it took a load run
// on loopback to notice.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");

const NAT = "203.0.113.20";
const PLAYERS = 16;
const port = (index) => 41000 + index;
const endpoint = (index) => h.from(NAT, port(index));

// Sixteen players, all on one address, all confirmed.
const fillNat = () => {
  const rig = h.makeServer({
    MAX_PLAYERS: String(PLAYERS),
    MAX_SESSIONS_PER_ADDRESS: String(PLAYERS),
    CONNECT_BURST: String(PLAYERS + 4),
    CONNECT_RATE_PER_MINUTE: "600",
  });
  for (let i = 0; i < PLAYERS; i += 1) {
    rig.server.onDatagram(h.connect(`Player${i}`), endpoint(i));
    rig.server.onDatagram(h.update(`Player${i}`), endpoint(i));
  }
  assert.strictEqual(rig.server.users.count(), PLAYERS, "all sixteen must be on the roster");
  return rig;
};

// One second of everyone playing normally at the client's real cadence.
const playOneSecond = (server, clock, skip = -1) => {
  for (let tick = 0; tick < 25; tick += 1) {
    clock.advance(40);
    for (let i = 0; i < PLAYERS; i += 1) {
      if (i === skip) continue;
      server.onDatagram(h.update(`Player${i}`, { position: [i, tick, 0] }), endpoint(i));
    }
  }
};

test("sixteen players on one address all play at 25 updates a second", () => {
  const { server, socket, clock } = fillNat();

  const mark = socket.sent.length;
  playOneSecond(server, clock);

  for (let i = 0; i < PLAYERS; i += 1) {
    assert.ok(server.users.get(`Player${i}`), `Player${i} was dropped`);
    const received = h.sentTo(socket, NAT, port(i), mark);
    assert.strictEqual(received.length > 100, true, `Player${i} received only ${received.length} packets`);
  }
  assert.strictEqual(server.byAddress.dropped, 0, "shared-address traffic must not be throttled as one flow");
});

test("one player flooding does not cost the other fifteen anything", () => {
  const { server, socket, clock } = fillNat();
  const abuser = 7;

  const junk = Buffer.from([0, 0, 0, 0]);
  const mark = socket.sent.length;

  for (let second = 0; second < 6; second += 1) {
    // Every kind of flood the abuser can produce, from their own endpoint.
    for (let i = 0; i < 400; i += 1) {
      server.onDatagram(junk, endpoint(abuser));
      server.onDatagram(h.connect(`Flood${i}`), endpoint(abuser));
      server.onDatagram(h.spectate(`Player${abuser}`, `Player${(i % PLAYERS)}`), endpoint(abuser));
      server.onDatagram(h.chat(`Player${abuser}`, `spam ${i}`), endpoint(abuser));
      server.onDatagram(h.update(`Player${abuser}`, { position: [i, 0, 0] }), endpoint(abuser));
    }
    playOneSecond(server, clock, abuser);
  }

  // The fifteen keep playing: their updates are accepted and relayed, and they
  // keep receiving heartbeats.
  for (let i = 0; i < PLAYERS; i += 1) {
    if (i === abuser) continue;
    assert.ok(server.users.get(`Player${i}`), `Player${i} was dropped by their neighbour's flood`);
  }

  const heartbeats = h
    .sentTo(socket, NAT, port(3), mark)
    .filter((packet) => packet.buffer.readUInt8(0) === packets.TYPE.HEARTBEAT);
  assert.strictEqual(heartbeats.length >= 2, true, `an innocent player got ${heartbeats.length} heartbeats`);

  const relayed = h
    .sentTo(socket, NAT, port(3), mark)
    .filter((packet) => packet.buffer.readUInt8(0) === packets.TYPE.INFO);
  assert.strictEqual(relayed.length > 500, true, `an innocent player got ${relayed.length} state updates`);

  const chat = h
    .sentTo(socket, NAT, port(3), mark)
    .filter((packet) => packet.buffer.readUInt8(0) === packets.TYPE.CHAT);
  assert.strictEqual(chat.length > 0, true, "chat stopped reaching the innocent players");

  // And the abuser is the one being stopped. The malformed budget runs out
  // first, so their endpoint lands in the penalty box and their packets stop
  // being parsed at all - which is why the session bucket barely registers.
  const abuserKey = `${NAT}:${port(abuser)}`;
  assert.strictEqual(server.penalty.has(abuserKey), true, "the flooder's endpoint was never boxed");
  assert.strictEqual(server.penalty.has(NAT), false, "the shared address must not be boxed");

  const before = server.stats.unknownOpcode;
  for (let i = 0; i < 200; i += 1) server.onDatagram(junk, endpoint(abuser));
  assert.strictEqual(server.stats.unknownOpcode, before, "boxed traffic is still being parsed");

  // Losing the session is the correct consequence for the abuser: boxed traffic
  // is not parsed, so their own updates stop refreshing their idle timer while
  // everyone else keeps theirs alive by playing.
  for (let second = 0; second < 70; second += 1) {
    for (let i = 0; i < 200; i += 1) server.onDatagram(junk, endpoint(abuser));
    playOneSecond(server, clock, abuser);
  }
  assert.strictEqual(server.users.get(`Player${abuser}`), null, "the flooder kept their slot");
  for (let i = 0; i < PLAYERS; i += 1) {
    if (i === abuser) continue;
    assert.ok(server.users.get(`Player${i}`), `Player${i} was lost while their neighbour flooded`);
  }
});

test("a new player can join from the same address once the limits refill", () => {
  const { server, clock } = h.makeServer({
    MAX_PLAYERS: "64",
    MAX_SESSIONS_PER_ADDRESS: "64",
    CONNECT_BURST: "4",
    CONNECT_RATE_PER_MINUTE: "12",
  });

  // Spend the connect budget from this address. Each of these is a different
  // endpoint, so each also spends its own one-token reserve - which is the
  // point of the reserve: an address whose budget somebody else emptied is not
  // a dead address.
  let accepted = 0;
  for (let i = 0; i < 40; i += 1) {
    if (server.onDatagram(h.connect(`Early${i}`), h.from(NAT, 42000 + i))) accepted += 1;
  }
  // Forty, not four, and the difference is the point: CONNECT_BURST bounds what
  // one ADDRESS may spend, and each of these forty endpoints also brought its own
  // one-token reserve. Asserting ">= 4" hid that; asserting the number means a
  // change to either tier moves this line.
  assert.strictEqual(accepted, 40, `connect budget 4 + one reserve token each, got ${accepted}`);
  assert.strictEqual(server.connects.available(NAT) < 1, true, "the address budget should be empty");

  // An endpoint that was admitted by the reserve rather than by the address
  // budget has spent both and gets nothing more: the reserve is one connect,
  // not a second budget.
  assert.strictEqual(server.onDatagram(h.connect("Again"), h.from(NAT, 42020)), false);

  // Five seconds per token at twelve a minute.
  clock.advance(11000);
  assert.strictEqual(server.onDatagram(h.connect("Later"), h.from(NAT, 43000)), true, "a normal client never got back in");
  assert.strictEqual(server.onDatagram(h.update("Later"), h.from(NAT, 43000)), true);
  assert.strictEqual(server.users.get("Later").confirmed, true);
});

test("the connect reserve does not raise the slot ceiling or reflect anything", () => {
  // The reserve exists so a forged flood cannot lock the real owner of an
  // address out. It must not become a way to fill the roster, and a connect it
  // admits must not become a reply aimed at a forged address.
  const rig = h.makeServer({ MAX_SESSIONS_PER_ADDRESS: "4", CONNECT_BURST: "4", CONNECT_RATE_PER_MINUTE: "12" });

  // The window starts before the first connect, so that the ACCEPT path is
  // measured and not only the refuse path. An earlier version took its mark
  // after the roster was already full and therefore measured nothing but
  // silence - the half that was never in doubt.
  const mark = rig.socket.sent.length;
  let bytesIn = 0;
  for (let i = 0; i < 500; i += 1) {
    const buffer = h.connect(`Ghost${i}`);
    bytesIn += buffer.length;
    rig.server.onDatagram(buffer, h.from(NAT, 50000 + i));
  }
  assert.strictEqual(rig.server.sessionsFrom(NAT), 4, "the per-address slot cap was bypassed");

  const replies = rig.socket.sent.slice(mark).filter((packet) => packet.address === NAT);
  const bytesOut = replies.reduce((total, packet) => total + packet.buffer.length, 0);
  // Four sessions are accepted and answered; everything past the cap was
  // admitted only by the reserve, refused, and refused in silence. A reserve
  // that amplifies is a reflector, so the ratio has to stay well under one.
  assert.ok(bytesOut / bytesIn < 0.5, `${(bytesOut / bytesIn).toFixed(2)}x reflected at a forgeable address`);

  // ...and once the cap is reached, nothing at all comes back.
  const quiet = rig.socket.sent.length;
  for (let i = 0; i < 200; i += 1) {
    rig.server.onDatagram(h.connect(`Later${i}`), h.from(NAT, 60000 + i));
  }
  const after = rig.socket.sent.slice(quiet).filter((packet) => packet.address === NAT);
  assert.strictEqual(after.length, 0, `${after.length} datagrams were reflected at a forgeable address`);
});

test("unregistered traffic is still limited per address, not only per endpoint", () => {
  // Otherwise a flooder rotating source ports would get a fresh session bucket
  // for every packet and the per-endpoint limit would mean nothing.
  // `accepted` counts handler verdicts. An earlier version counted
  // `stats.received` going up, which is the first line of onDatagram and is
  // therefore always true - a counter that measured the loop, not the server,
  // and was never asserted on either.
  const { server } = h.makeServer();
  let accepted = 0;
  for (let i = 0; i < 3000; i += 1) {
    if (server.onDatagram(h.connect(`Ghost${i}`), h.from("198.51.100.9", 10000 + i))) accepted += 1;
  }
  assert.ok(accepted < 3000 * 0.05, `${accepted} of 3000 forged connects from one address were handled`);
  assert.strictEqual(server.users.count() <= 4, true, `${server.users.count()} sessions from one flooding address`);
  assert.strictEqual(server.byAddress.dropped > 0, true, "the address budget was never charged");
});
