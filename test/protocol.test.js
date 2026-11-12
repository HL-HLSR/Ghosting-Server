"use strict";

// End to end behaviour of every opcode the mod sends, against the packets the
// mod actually produces. The bytes come from test/helpers/harness.js, which
// encodes the field order in sp/src/game/server/GhostOnlineEngine.cpp.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { RS } = require("../src/game/race");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);

// Connect, then send one update so the session is confirmed and receives
// broadcast traffic. This is what a real client does within about 40 ms.
const join = (server, socket, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

test("a connect is accepted and answered with type 7", () => {
  const { server, socket } = h.makeServer();
  server.onDatagram(h.connect("Alice"), ALICE);

  const user = server.users.get("Alice");
  assert.ok(user);
  assert.strictEqual(user.trailLength, 12);
  assert.strictEqual(user.ghostBlue, 30);
  assert.deepStrictEqual(h.typesSent(socket), [packets.TYPE.CONNECT_ACCEPTED]);
});

test("a joining player gets the roster silently and everyone else gets the join", () => {
  const { server, socket } = h.makeServer();
  join(server, socket, "Alice", ALICE);

  const mark = socket.sent.length;
  server.onDatagram(h.connect("Bob"), BOB);

  const toBob = h.sentTo(socket, BOB.address, BOB.port, mark);
  const toAlice = h.sentTo(socket, ALICE.address, ALICE.port, mark);

  // Bob: accept, then Alice's roster entry with the announce byte clear.
  assert.deepStrictEqual(toBob.map((p) => p.buffer.readUInt8(0)), [packets.TYPE.CONNECT_ACCEPTED, packets.TYPE.CONNECT]);
  assert.strictEqual(toBob[1].buffer[toBob[1].buffer.length - 1], 0, "roster entries must not announce");

  // Alice: Bob's join, announced.
  assert.deepStrictEqual(toAlice.map((p) => p.buffer.readUInt8(0)), [packets.TYPE.CONNECT]);
  assert.strictEqual(toAlice[0].buffer[toAlice[0].buffer.length - 1], 1, "a fresh join must announce");
});

test("a position update is relayed to everyone except the sender", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);

  clock.advance(100);
  const mark = socket.sent.length;
  server.onDatagram(h.update("Alice", { position: [1, 2, 3] }), ALICE);

  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).length, 0);
  const relayed = h.sentTo(socket, BOB.address, BOB.port, mark);
  assert.strictEqual(relayed.length, 1);
  assert.strictEqual(relayed[0].buffer.readUInt8(0), packets.TYPE.INFO);
  assert.strictEqual(server.users.get("Alice").position.x, 1);
});

test("an older client that stops after yaw is still accepted", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  clock.advance(100);

  // Every trailing field is optional; a client built before each one was added
  // simply ends the packet there.
  for (const upTo of ["yaw", "paused", "weapon", "stats", "held"]) {
    clock.advance(100);
    const accepted = server.onDatagram(h.update("Alice", { upTo, position: [7, 7, 7] }), ALICE);
    assert.strictEqual(accepted, true, `an update ending after ${upTo} was rejected`);
    assert.strictEqual(server.users.get("Alice").position.x, 7);
  }

  // The shortest form: everything after yaw is missing and gets its default.
  clock.advance(100);
  server.onDatagram(h.update("Alice", { upTo: "yaw" }), ALICE);
  const user = server.users.get("Alice");
  assert.strictEqual(user.eyeZ, 64, "eye height defaults to standing");
  assert.strictEqual(user.hp, -1, "absent stats mean unknown, not zero");
  assert.strictEqual(user.heldModel, "");
  assert.strictEqual(user.weapon, 0);
});

test("chat is relayed to everyone including the sender", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);

  clock.advance(1000);
  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "hello"), ALICE);

  // The client shows a message only when it comes back, so the sender is
  // included; otherwise they would see their own line twice or not at all.
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).length, 1);
  assert.strictEqual(h.sentTo(socket, BOB.address, BOB.port, mark).length, 1);
});

test("chat ids increase so a client can drop UDP duplicates", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);

  clock.advance(1000);
  const first = socket.sent.length;
  server.onDatagram(h.chat("Alice", "one"), ALICE);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "two"), ALICE);

  const ids = socket.sent
    .slice(first)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT)
    .map((p) => p.buffer.readInt32BE(1));
  assert.strictEqual(ids.length, 2);
  assert.strictEqual(ids[1], ids[0] + 1);
});

test("a spectate change is relayed once and a repeat costs nothing", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);
  clock.advance(1000);

  let mark = socket.sent.length;
  server.onDatagram(h.spectate("Alice", "Bob"), ALICE);
  assert.strictEqual(h.typesSent(socket, mark).filter((t) => t === packets.TYPE.SPECTATE).length, 2);
  assert.strictEqual(server.users.get("Alice").spectating, "Bob");

  // Sending the same target again is a no-op: this was the cheapest amplifier
  // in the protocol, a tiny packet that fanned out to every player.
  mark = socket.sent.length;
  server.onDatagram(h.spectate("Alice", "Bob"), ALICE);
  assert.strictEqual(socket.sent.length, mark);
});

test("spectating somebody who is not connected is cleared, not relayed as text", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  clock.advance(1000);
  server.onDatagram(h.spectate("Alice", "Nobody"), ALICE);
  assert.strictEqual(server.users.get("Alice").spectating, "");
});

test("a disconnect is confirmed rather than applied immediately", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);
  clock.advance(1000);

  server.onDatagram(h.disconnect("Alice"), ALICE);
  // Still present: a single forged datagram must not remove a player.
  assert.ok(server.users.get("Alice"));

  clock.advance(3000);
  assert.strictEqual(server.users.get("Alice"), null);
  const left = socket.sent.filter((p) => p.buffer.readUInt8(0) === packets.TYPE.DISCONNECT);
  assert.strictEqual(left.length, 1);
  assert.strictEqual(left[0].buffer.subarray(-4).toString("latin1"), "left");
});

test("a heartbeat reaches every confirmed player", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);

  const mark = socket.sent.length;
  clock.advance(2100);
  const beats = h.typesSent(socket, mark).filter((t) => t === packets.TYPE.HEARTBEAT);
  assert.strictEqual(beats.length, 2, "one heartbeat per player per tick");
});

test("a silent player is timed out and everyone is told", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);

  // Bob keeps talking, Alice goes quiet.
  for (let i = 0; i < 70; i += 1) {
    clock.advance(1000);
    server.onDatagram(h.update("Bob"), BOB);
  }

  assert.strictEqual(server.users.get("Alice"), null);
  assert.ok(server.users.get("Bob"));
  const goodbye = socket.sent.filter(
    (p) => p.buffer.readUInt8(0) === packets.TYPE.DISCONNECT && p.buffer.subarray(-7).toString("latin1") === "timeout"
  );
  assert.ok(goodbye.length > 0);
});

test("the console kick removes a player and tells them why", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, socket, "Alice", ALICE);
  clock.advance(100);

  const mark = socket.sent.length;
  assert.strictEqual(server.kickByName("Alice"), true);
  assert.strictEqual(server.users.get("Alice"), null);
  const kicks = h.sentTo(socket, ALICE.address, ALICE.port, mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.KICK);
  assert.strictEqual(kicks.length, 1);
  assert.strictEqual(server.kickByName("Nobody"), false);
});

test("the server is full at MAX_PLAYERS and says so", () => {
  const { server, socket } = h.makeServer({ MAX_PLAYERS: "2", MAX_SESSIONS_PER_ADDRESS: "8", CONNECT_BURST: "20" });
  join(server, socket, "One", h.from("10.1.0.1", 1));
  join(server, socket, "Two", h.from("10.1.0.2", 2));

  const third = h.from("10.1.0.3", 3);
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Three"), third);

  assert.strictEqual(server.users.get("Three"), null);
  const reply = h.sentTo(socket, third.address, third.port, mark)[0];
  assert.strictEqual(reply.buffer.readUInt8(0), packets.TYPE.KICK);
  assert.match(reply.buffer.toString("latin1"), /full/);
});

test("a race runs from /race to a finish", () => {
  const { server, socket, clock } = h.makeServer({ RACE_LOBBY_MS: "5000" });
  join(server, socket, "Alice", ALICE);
  join(server, socket, "Bob", BOB);
  clock.advance(1000);

  server.onDatagram(h.chat("Alice", "/race"), ALICE);
  assert.strictEqual(server.race.phase, "lobby");
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), BOB);
  assert.strictEqual(server.race.runners.size, 2);

  // Lobby expires, then the 3-2-1 countdown before the save is loaded.
  clock.advance(4500);
  assert.strictEqual(server.race.phase, "countdown_map");
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "loading");

  // Both report the race map, which is how loading progress is detected.
  const mark = socket.sent.length;
  clock.advance(100);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), ALICE);
  clock.advance(100);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), BOB);
  assert.strictEqual(server.race.phase, "staging");

  // Both reach the pre-teleport point and are frozen until everyone is there.
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), ALICE);
  assert.strictEqual(server.race.paused.has("Alice"), true);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Bob", 1), BOB);
  assert.strictEqual(server.race.phase, "countdown_start");

  clock.advance(4100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "racing");
  assert.strictEqual(server.race.paused.size, 0, "everyone must be released together");

  const forced = socket.sent.slice(mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.FORCE_MAP);
  assert.strictEqual(forced.length, 0, "the force map goes out before loading, not after");

  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 2), ALICE);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Bob", 2), BOB);
  assert.strictEqual(server.race.phase, "idle", "the race ends when everyone has finished");
});

test("race status packets carry the runner flag", () => {
  const { server, socket, clock } = h.makeServer({ RACE_LOBBY_MS: "2000" });
  join(server, socket, "Alice", ALICE);
  clock.advance(1000);

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/race"), ALICE);
  const status = socket.sent.slice(mark).find((p) => p.buffer.readUInt8(0) === packets.TYPE.RACE_STATUS);
  assert.ok(status);
  // Хвост пакета: статус, признак участника, признак идущей гонки. Последний
  // при открытом лобби ноль - у не-участника ещё есть минута написать /ready.
  assert.strictEqual(status.buffer[status.buffer.length - 3], RS.READY);
  assert.strictEqual(status.buffer[status.buffer.length - 2], 1, 'создатель гонки - участник');
  assert.strictEqual(status.buffer[status.buffer.length - 1], 0, 'лобби ещё не гонка');
});
