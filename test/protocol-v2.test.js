"use strict";

// Protocol v2: per-session secrets (design 2026-10-28, section 3.1).
//
// A client that appends u8(2) + C to its connect (C: 8 bytes it chose, never
// all zero) is answered "07 C S", S being 8 random bytes chosen here. From then
// on every packet the host sends that session is [type][C][payload], and every
// packet from that session's endpoint must carry S right after its opcode. A
// packet without the right S is dropped and counted, never punished: it cannot
// be the real client, and punishing it would hand an attacker a way to box or
// kick a player. A connect without the tail is a legacy session, served byte
// for byte as 1.2.0 served it (wire-golden pins those bytes).

const test = require("node:test");
const assert = require("node:assert");
const { Readable } = require("stream");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { Message } = require("../src/wire/reader");
const { attach } = require("../src/console");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);
const CAROL = h.from("10.0.0.3", 40003);
const C_ALICE = Buffer.from("a1a2a3a4a5a6a7a8", "hex");
const C_BOB = Buffer.from("b1b2b3b4b5b6b7b8", "hex");

const NEEDS_V2 = "This server needs the updated Ghosting Mod Renewed";

const endpoint = (rinfo) => `${rinfo.address}:${rinfo.port}`;

const lastTo = (socket, rinfo) => {
  const list = h.sentTo(socket, rinfo.address, rinfo.port);
  return list[list.length - 1];
};

const accepted = (nonce, token) => Buffer.concat([Buffer.from([packets.TYPE.CONNECT_ACCEPTED]), nonce, token]);

// What a v2 client does: announce, take S from the accept, then send its first
// position update with S (which confirms the session). Returns S.
const joinV2 = (server, socket, name, rinfo, nonce) => {
  const mark = socket.sent.length;
  server.onDatagram(h.connectV2(name, nonce), rinfo);
  const accept = h
    .sentTo(socket, rinfo.address, rinfo.port, mark)
    .find((packet) => packet.buffer[0] === packets.TYPE.CONNECT_ACCEPTED);
  assert.ok(accept, `${name} was not accepted`);
  const token = h.stripNonce(accept.buffer).rest;
  assert.strictEqual(server.onDatagram(h.withToken(h.update(name), token), rinfo), true);
  return token;
};

const joinLegacy = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
};

// A type 6 as the client reads it: id, name, text.
const readChat = (buffer) => {
  const message = new Message(buffer.subarray(1), {});
  return { id: message.readInt32(), name: message.readString(), text: message.readString() };
};

// Reassembles a v2 packet with its C removed, so the legacy readers apply.
const unwrap = (buffer) => {
  const { type, rest } = h.stripNonce(buffer);
  return Buffer.concat([Buffer.from([type]), rest]);
};

test("v2 connect gets 07 C S", () => {
  const { server, socket } = h.makeServer();
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE), true);

  const alice = server.users.get("Alice");
  assert.strictEqual(alice.protocol, 2);
  assert.deepStrictEqual(alice.clientNonce, C_ALICE);
  const token = alice.serverToken;
  assert.ok(Buffer.isBuffer(token));
  assert.strictEqual(token.length, 8);
  assert.ok(token.some((byte) => byte !== 0), "S must never be all zero");
  assert.deepStrictEqual(lastTo(socket, ALICE).buffer, accepted(C_ALICE, token));
});

test("two v2 sessions get different S", () => {
  const { server, socket } = h.makeServer();
  const a = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const b = joinV2(server, socket, "Bob", BOB, C_BOB);
  assert.strictEqual(a.equals(b), false);
});

test("legacy connect gets a bare 07", () => {
  const { server, socket } = h.makeServer();
  server.onDatagram(h.connect("Alice"), ALICE);
  assert.deepStrictEqual(lastTo(socket, ALICE).buffer, Buffer.from([0x07]));
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.protocol, 1);
  assert.strictEqual(alice.clientNonce, null);
  assert.strictEqual(alice.serverToken, null);
});

test("every packet to a v2 session carries C after the type; a legacy peer's carry none", () => {
  const { server, socket, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE); // 07
  joinLegacy(server, "Bob", BOB); // Bob's join (0) to Alice
  clock.advance(100);
  server.onDatagram(h.withToken(h.update("Alice", { position: [1, 1, 1] }), token), ALICE);
  server.onDatagram(h.update("Bob", { position: [2, 2, 2] }), BOB); // a peer's position (1)
  server.onDatagram(h.chat("Bob", "hello"), BOB); // chat (6)
  clock.advance(server.config.heartbeatMs); // heartbeat (11)

  const types = new Set();
  for (const packet of h.sentTo(socket, ALICE.address, ALICE.port)) {
    const { type, nonce } = h.stripNonce(packet.buffer);
    assert.deepStrictEqual(nonce, C_ALICE, `type ${type} to a v2 session must carry C`);
    types.add(type);
  }
  const T = packets.TYPE;
  for (const type of [T.CONNECT_ACCEPTED, T.CONNECT, T.INFO, T.CHAT, T.HEARTBEAT]) {
    assert.ok(types.has(type), `no type ${type} reached Alice`);
  }

  // Bob is legacy: exactly what packets.js builds, nothing in front.
  const toBob = h.sentTo(socket, BOB.address, BOB.port).map((packet) => packet.buffer);
  assert.deepStrictEqual(toBob[0], packets.connectAccepted());
  assert.ok(toBob.some((buffer) => buffer.equals(packets.connect(server.users.get("Alice"), false))));
  assert.ok(toBob.some((buffer) => buffer.equals(packets.heartbeat())));
  const info = toBob.find((buffer) => buffer[0] === T.INFO);
  assert.strictEqual(h.readInfo(info).name, "Alice");
  const chat = toBob.find((buffer) => buffer[0] === T.CHAT);
  assert.strictEqual(readChat(chat).text, "hello");
});

test("a tail that is not u8(2) + 8 non-zero bytes is legacy, and not an error", () => {
  const cases = {
    "a version byte of 3": Buffer.concat([h.connect("Alice"), Buffer.from([3]), C_ALICE]),
    "a truncated C": Buffer.concat([h.connect("Alice"), Buffer.from([2]), C_ALICE.subarray(0, 5)]),
    "an all-zero C": h.connectV2("Alice", Buffer.alloc(8)),
  };
  for (const [what, packet] of Object.entries(cases)) {
    const { server, socket } = h.makeServer();
    assert.strictEqual(server.onDatagram(packet, ALICE), true, what);
    assert.deepStrictEqual(lastTo(socket, ALICE).buffer, Buffer.from([0x07]), what);
    assert.strictEqual(server.users.get("Alice").protocol, 1, what);
    assert.strictEqual(server.stats.malformed, 0, what);
    assert.strictEqual(server.penalty.size, 0, what);
  }
});

test("v2 session: l without S is dropped and not punished", () => {
  const { server, socket, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);
  const alice = server.users.get("Alice");
  clock.advance(100);

  const mark = socket.sent.length;
  for (let i = 0; i < 100; i += 1) {
    assert.strictEqual(server.onDatagram(h.update("Alice", { position: [9, 9, 9] }), ALICE), false);
  }
  assert.strictEqual(h.sentTo(socket, BOB.address, BOB.port, mark).length, 0, "nothing relayed");
  assert.strictEqual(server.stats.badToken, 100);
  assert.strictEqual(server.penalty.has(ALICE.address), false);
  assert.strictEqual(server.penalty.has(endpoint(ALICE)), false);
  assert.strictEqual(server.users.get("Alice"), alice, "still in the roster");
  assert.strictEqual(alice.position.x, 0, "no field was applied");

  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice", { position: [5, 0, 0] }), token), ALICE), true);
  const relayed = h.sentTo(socket, BOB.address, BOB.port, mark);
  assert.strictEqual(relayed.length, 1);
  assert.strictEqual(h.readInfo(relayed[0].buffer).name, "Alice");
  assert.strictEqual(alice.position.x, 5);
});

test("wrong S is dropped", () => {
  const { server, socket, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);
  clock.advance(100);

  const wrong = Buffer.from(token);
  wrong[3] ^= 0x10;
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice"), wrong), ALICE), false);
  // An opcode and nothing else: S missing altogether.
  assert.strictEqual(server.onDatagram(Buffer.from([0, 0, 0, 1, 0x6c]), ALICE), false);
  assert.strictEqual(server.stats.badToken, 2);
  assert.strictEqual(server.stats.malformed, 0);
  assert.strictEqual(h.sentTo(socket, BOB.address, BOB.port, mark).length, 0);
});

test("junk from a v2 session's endpoint never boxes or kicks it", () => {
  const { server, socket } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const alice = server.users.get("Alice");

  const unknownOpcode = Buffer.from([0, 0, 0, 2, 0x7a, 0x7a, 0, 0, 0, 0]);
  for (let i = 0; i < 40; i += 1) {
    server.onDatagram(Buffer.alloc(600, 1), ALICE); // oversized
    server.onDatagram(Buffer.from([0, 0, 0, 0x7f]), ALICE); // opcode that cannot be read
    server.onDatagram(unknownOpcode, ALICE); // no S, so never looked up
  }
  assert.strictEqual(server.users.get("Alice"), alice);
  assert.strictEqual(server.penalty.has(endpoint(ALICE)), false);
  assert.strictEqual(server.penalty.has(ALICE.address), false);
  assert.ok(!h.typesSent(socket).includes(packets.TYPE.KICK), "nobody was kicked");
  assert.strictEqual(server.onDatagram(h.withToken(h.chat("Alice", "still here"), token), ALICE), true);
});

test("duplicate v2 connect re-sends the same 07 C S", () => {
  const { server, socket } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const alice = server.users.get("Alice");

  // Without S it is one more unsigned packet from a v2 endpoint.
  let mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE), false);
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).length, 0);
  assert.strictEqual(server.stats.badToken, 1);

  mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.connectV2("Alice", C_ALICE), token), ALICE), true);
  const again = h.sentTo(socket, ALICE.address, ALICE.port, mark);
  assert.deepStrictEqual(again[0].buffer, accepted(C_ALICE, token));
  assert.strictEqual(server.users.get("Alice"), alice);
  assert.deepStrictEqual(alice.serverToken, token);
});

test("a duplicate connect never turns a legacy session into a v2 one", () => {
  const { server, socket } = h.makeServer();
  joinLegacy(server, "Alice", ALICE);
  // A v2 tail on a legacy session's endpoint (forgeable): were it believed, the
  // host would prefix C to every packet for a client that cannot read them.
  const mark = socket.sent.length;
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.protocol, 1);
  assert.strictEqual(alice.clientNonce, null);
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).some((p) => p.buffer[0] === 7), false);
});

test("reconnect from a new port with a new C gets a new S", () => {
  const { server, socket, clock } = h.makeServer();
  const first = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  // 1.3.1 (M3): a confirmed v2 session's name is free once it is stale, not
  // after TAKEOVER_AFTER_MS as for a legacy one.
  clock.advance(server.config.staleTimeoutMs);

  const ALICE2 = h.from(ALICE.address, 40011);
  const C2 = Buffer.from("c1c2c3c4c5c6c7c8", "hex");
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C2), ALICE2), true);
  const accept = h.sentTo(socket, ALICE2.address, ALICE2.port, mark).find((p) => p.buffer[0] === 7);
  const { nonce, rest: second } = h.stripNonce(accept.buffer);
  assert.deepStrictEqual(nonce, C2);
  assert.strictEqual(second.length, 8);
  assert.strictEqual(second.equals(first), false);

  const alice = server.users.get("Alice");
  assert.strictEqual(alice.socket.port, 40011);
  assert.deepStrictEqual(alice.clientNonce, C2);
  assert.deepStrictEqual(alice.serverToken, second);
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice"), second), ALICE2), true);
});

test("REQUIRE_PROTOCOL_V2=1 refuses a legacy connect", () => {
  assert.strictEqual(h.makeServer().config.requireProtocolV2, false, "off by default");

  const { server, socket } = h.makeServer({ REQUIRE_PROTOCOL_V2: "1" });
  assert.strictEqual(server.onDatagram(h.connect("Alice"), ALICE), false);
  const refusal = lastTo(socket, ALICE).buffer;
  assert.strictEqual(refusal[0], packets.TYPE.KICK);
  assert.strictEqual(new Message(refusal.subarray(1), {}).readString(), NEEDS_V2);
  assert.deepStrictEqual(refusal, packets.kick(NEEDS_V2));
  assert.strictEqual(server.users.count(), 0, "no session is created");

  assert.strictEqual(server.onDatagram(h.connectV2("Bob", C_BOB), BOB), true);
  const bob = server.users.get("Bob");
  assert.strictEqual(bob.protocol, 2);
  assert.deepStrictEqual(lastTo(socket, BOB).buffer, accepted(C_BOB, bob.serverToken));
});

test("a refusal answering a v2 announce carries that announce's C", () => {
  const { server, socket } = h.makeServer();
  joinLegacy(server, "Alice", ALICE);
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_BOB), BOB), false);
  const [refusal] = h.sentTo(socket, BOB.address, BOB.port, mark);
  const { type, nonce } = h.stripNonce(refusal.buffer);
  assert.strictEqual(type, packets.TYPE.KICK);
  assert.deepStrictEqual(nonce, C_BOB);
  assert.deepStrictEqual(unwrap(refusal.buffer), packets.kick("Nickname 'Alice' is already in use."));
});

test("largest v2 packets are <= 512", () => {
  const { server, socket, clock } = h.makeServer();
  const LONG = "L".repeat(31);
  const tokenA = joinV2(server, socket, LONG, ALICE, C_ALICE);
  const tokenB = joinV2(server, socket, "Bob", BOB, C_BOB);

  // A client spray piece of 400 bytes from a 31-byte name, with S.
  const { blob, crc } = h.sprayBlob(16, 3, true);
  const total = Math.ceil(blob.length / 400);
  assert.ok(total >= 2, "the picture needs at least one full 400-byte piece");
  let largestIn = 0;
  for (let i = 0; i < total; i += 1) {
    const piece = blob.subarray(i * 400, Math.min((i + 1) * 400, blob.length));
    const datagram = h.withToken(h.sprayChunk(LONG, crc, blob.length, total, i, piece), tokenA);
    largestIn = Math.max(largestIn, datagram.length);
    assert.strictEqual(server.onDatagram(datagram, ALICE), true, `piece ${i}`);
    clock.advance(40);
  }
  assert.strictEqual(largestIn, 468);
  assert.ok(server.users.get(LONG).spray, "the picture was published");

  // The relayed pieces to a v2 receiver, which keeps sending lines meanwhile.
  const mark = socket.sent.length;
  for (let i = 0; i < 8; i += 1) {
    clock.advance(250);
    server.onDatagram(h.withToken(h.update("Bob"), tokenB), BOB);
  }
  const pieces = h
    .sentTo(socket, BOB.address, BOB.port, mark)
    .filter((packet) => packet.buffer[0] === packets.TYPE.SPRAY_CHUNK);
  assert.strictEqual(pieces.length, server.users.get(LONG).spray.total);
  for (const packet of pieces) {
    assert.deepStrictEqual(h.stripNonce(packet.buffer).nonce, C_BOB);
    assert.ok(packet.buffer.length <= 512, `${packet.buffer.length} bytes`);
  }
  assert.strictEqual(Math.max(...pieces.map((packet) => packet.buffer.length)), 464);
});

test("mixed lobby: a v2 player and a legacy player see each other's positions and chat", () => {
  const { server, socket, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);
  clock.advance(100);

  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice", { position: [1, 2, 3] }), token), ALICE), true);
  assert.strictEqual(server.onDatagram(h.update("Bob", { position: [4, 5, 6] }), BOB), true);
  assert.strictEqual(server.onDatagram(h.withToken(h.chat("Alice", "hi bob"), token), ALICE), true);
  assert.strictEqual(server.onDatagram(h.chat("Bob", "hi alice"), BOB), true);

  const toAlice = h.sentTo(socket, ALICE.address, ALICE.port, mark).map((p) => p.buffer);
  for (const buffer of toAlice) assert.deepStrictEqual(h.stripNonce(buffer).nonce, C_ALICE);
  const plainToAlice = toAlice.map(unwrap);
  assert.strictEqual(h.readInfo(plainToAlice.find((b) => b[0] === packets.TYPE.INFO)).name, "Bob");
  const aliceChats = plainToAlice.filter((b) => b[0] === packets.TYPE.CHAT).map(readChat);
  assert.ok(aliceChats.some((c) => c.name === "Bob" && c.text === "hi alice"));

  const toBob = h.sentTo(socket, BOB.address, BOB.port, mark).map((p) => p.buffer);
  assert.strictEqual(h.readInfo(toBob.find((b) => b[0] === packets.TYPE.INFO)).name, "Alice");
  const bobChats = toBob.filter((b) => b[0] === packets.TYPE.CHAT).map(readChat);
  assert.ok(bobChats.some((c) => c.name === "Alice" && c.text === "hi bob"));
});

test("status counts v2 and legacy sessions", () => {
  const rig = h.makeServer();
  const printed = [];
  const handle = attach(rig.server, { input: Readable.from([]), print: (line) => printed.push(line) });
  joinV2(rig.server, rig.socket, "Alice", ALICE, C_ALICE);
  joinLegacy(rig.server, "Bob", BOB);
  joinLegacy(rig.server, "Carol", CAROL);

  assert.deepStrictEqual(rig.server.status().protocol, { v2: 1, legacy: 2 });
  handle.handle("status");
  assert.ok(printed.includes("Protocol: 1 v2, 2 legacy session(s)"), printed.join("\n"));
});

// Ruling 5: the first accept is lost. The client never learned S, so it
// re-announces from the same port with the same C and no S.
test("lost accept: an unsigned re-announce with the same C gets the identical 07 C S", () => {
  const { server, socket } = h.makeServer();
  joinLegacy(server, "Bob", BOB);
  let mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE), true);
  // The test "loses" the accept (Bob's roster entry follows it).
  const lost = h.sentTo(socket, ALICE.address, ALICE.port, mark).find((p) => p.buffer[0] === 7).buffer;
  const alice = server.users.get("Alice");
  const tokensBefore = server.connects.available(ALICE.address);

  mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE), true);
  const again = h.sentTo(socket, ALICE.address, ALICE.port, mark).find((p) => p.buffer[0] === 7);
  assert.ok(again, "the accept was re-sent");
  assert.deepStrictEqual(again.buffer, lost, "the same C and the same S");
  assert.strictEqual(server.users.get("Alice"), alice, "no new session");
  assert.strictEqual(server.users.count(), 2);
  assert.strictEqual(server.stats.badToken, 0);
  assert.strictEqual(server.connects.available(ALICE.address), tokensBefore - 1, "charged like any duplicate connect");

  // The client now has S: its first packet with S confirms and relays.
  const token = h.stripNonce(again.buffer).rest;
  mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice", { position: [3, 0, 0] }), token), ALICE), true);
  assert.strictEqual(alice.confirmed, true);
  const relayed = h.sentTo(socket, BOB.address, BOB.port, mark).filter((p) => p.buffer[0] === packets.TYPE.INFO);
  assert.strictEqual(relayed.length, 1);
  assert.strictEqual(h.readInfo(relayed[0].buffer).name, "Alice");
});

test("lost accept: an unsigned re-announce with a different C, or another name, is dropped", () => {
  const { server, socket } = h.makeServer();
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  const alice = server.users.get("Alice");
  const token = alice.serverToken;

  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_BOB), ALICE), false);
  assert.strictEqual(server.onDatagram(h.connectV2("Mallory", C_ALICE), ALICE), false);
  assert.strictEqual(server.onDatagram(h.connect("Alice"), ALICE), false);
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).length, 0);
  assert.strictEqual(server.stats.badToken, 3);
  assert.strictEqual(server.users.get("Alice"), alice);
  assert.strictEqual(server.users.count(), 1);
  assert.deepStrictEqual(alice.clientNonce, C_ALICE);
  assert.deepStrictEqual(alice.serverToken, token);
  assert.strictEqual(server.penalty.size, 0);
});

test("lost accept: once confirmed, an unsigned re-announce is dropped even with the same C", () => {
  const { server, socket } = h.makeServer();
  joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE), false);
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).length, 0);
  assert.strictEqual(server.stats.badToken, 1);
});

// Ruling 6: the host restarted (or swept or kicked the session) and a v2
// client keeps talking to it with its old S until its own timeout. The host
// has no owner for the endpoint, so S sits where the name length belongs.
test("server restart: a v2 client's S-framed packets to a host that forgot it never box its address", () => {
  const before = h.makeServer();
  const token = joinV2(before.server, before.socket, "Alice", ALICE, C_ALICE);

  const { server, socket, clock } = h.makeServer(); // the restarted host
  for (let t = 0; t < 5000; t += 20) {
    const packet = t % 1000 === 0 ? h.chat("Alice", "anyone?") : h.update("Alice");
    assert.strictEqual(server.onDatagram(h.withToken(packet, token), ALICE), false);
    clock.advance(20);
  }
  server.onDatagram(h.withToken(h.connectV2("Alice", C_ALICE), token), ALICE); // a re-sent signed 'c'
  assert.strictEqual(server.penalty.has(ALICE.address), false);
  assert.strictEqual(server.penalty.has(endpoint(ALICE)), false);
  assert.strictEqual(server.stats.malformed, 0);
  assert.ok(server.log.lines.some((line) => line[0] === "event" && line[1] === "orphan-v2"));

  // The client times out and reconnects from a new port: in at once.
  const ALICE2 = h.from(ALICE.address, 40011);
  const C2 = Buffer.from("c1c2c3c4c5c6c7c8", "hex");
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C2), ALICE2), true);
  const fresh = server.users.get("Alice");
  assert.deepStrictEqual(lastTo(socket, ALICE2).buffer, accepted(C2, fresh.serverToken));
});

test("server restart: junk that does not parse as opcode + 8 bytes + name is still punished", () => {
  const { server } = h.makeServer();
  // "l", then 8 bytes, then a name length far past any cap.
  const junk = Buffer.concat([Buffer.from([0, 0, 0, 1, 0x6c]), Buffer.alloc(8, 7), Buffer.from([0x7f, 0, 0, 0])]);
  for (let i = 0; i < 40; i += 1) server.onDatagram(junk, ALICE);
  assert.ok(server.stats.malformed > 0);
  assert.strictEqual(server.penalty.has(ALICE.address), true);
});

test("no log line carries C or S", () => {
  const { server, socket, log, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  server.onDatagram(h.update("Alice"), ALICE);
  server.onDatagram(h.withToken(h.connectV2("Alice", C_ALICE), token), ALICE);
  clock.advance(server.config.takeoverAfterMs + 1);
  server.onDatagram(h.connectV2("Alice", C_BOB), h.from(ALICE.address, 40011));

  const secrets = [C_ALICE, C_BOB, token, server.users.get("Alice").serverToken];
  const forms = secrets.flatMap((b) => [b.toString("hex"), b.toString("latin1"), b.toString("base64")]);
  for (const line of log.lines) {
    for (const arg of line) {
      assert.ok(!Buffer.isBuffer(arg), `a Buffer was logged: ${line[0]} ${line[1]}`);
      const text = typeof arg === "string" ? arg : JSON.stringify(arg) || "";
      for (const form of forms) assert.ok(!text.includes(form), `a secret was logged: ${text}`);
    }
  }
});

// ---------------------------------------------------------------------------
// The trust rules (design 3.1): what S buys a v2 session. It is confirmed only
// by a packet carrying S, so a forged announce never gets further than its
// accept. Once confirmed it is return-routable - nothing sent to it can land on
// somebody who did not ask - so its fan-out is not metered, and nothing can
// speak for it, so the impersonation guard is never armed for it. Legacy
// sessions keep every 1.2.0 rule (the reflection, slot-squat and guard suites).
// ---------------------------------------------------------------------------

const DAVE = h.from("10.0.0.4", 40004);
const C_DAVE = Buffer.from("d1d2d3d4d5d6d7d8", "hex");
const C_FORGED = Buffer.from("f1f2f3f4f5f6f7f8", "hex");
const HELD = "models/props_c17/oildrum001.mdl"; // a carried prop: the largest info packet

// Type 1 packets naming `name` sent to `rinfo` since `since` (C stripped for a
// v2 receiver).
const infosNaming = (socket, rinfo, since, name, v2) =>
  h
    .sentTo(socket, rinfo.address, rinfo.port, since)
    .map((packet) => (v2 ? unwrap(packet.buffer) : packet.buffer))
    .filter((buffer) => buffer[0] === packets.TYPE.INFO && h.readInfo(buffer).name === name).length;

test("forged v2 connect never confirms", () => {
  const { server, socket, clock } = h.makeServer();
  joinLegacy(server, "Bob", BOB);
  joinLegacy(server, "Carol", CAROL);
  const tokenDave = joinV2(server, socket, "Dave", DAVE, C_DAVE);

  // The forger announces v2 from the victim's endpoint and never sees a reply,
  // so it never learns S: it sends lines without one at 50 Hz for a minute and
  // re-announces every 5 s, the way the client retries.
  const VICTIM = h.from("198.51.100.7", 40007);
  let forgedBytes = 0;
  const forge = (buffer) => {
    forgedBytes += buffer.length;
    server.onDatagram(buffer, VICTIM);
  };
  const mark = socket.sent.length;
  forge(h.connectV2("Mallory", C_FORGED));
  for (let t = 0; t < 60000; t += 20) {
    server.onDatagram(h.update("Bob", { position: [t % 977, 1, 0] }), BOB);
    server.onDatagram(h.update("Carol", { position: [t % 977, 2, 0] }), CAROL);
    server.onDatagram(h.withToken(h.update("Dave", { position: [t % 977, 3, 0] }), tokenDave), DAVE);
    forge(h.update("Mallory", { position: [t % 977, 4, 0] }));
    if (t % 5000 === 4980) forge(h.connectV2("Mallory", C_FORGED));
    clock.advance(20);
  }

  // Nothing but "07 C S" ever went to the victim: no roster, no positions.
  const toVictim = h.sentTo(socket, VICTIM.address, VICTIM.port, mark);
  assert.ok(toVictim.length >= 1, "the announce was answered");
  for (const packet of toVictim) {
    const { type, nonce } = h.stripNonce(packet.buffer);
    assert.strictEqual(type, packets.TYPE.CONNECT_ACCEPTED, `type ${type} reached the victim`);
    assert.deepStrictEqual(nonce, C_FORGED);
    assert.strictEqual(packet.buffer.length, 17);
  }
  const sentBytes = toVictim.reduce((sum, packet) => sum + packet.buffer.length, 0);
  assert.ok(sentBytes <= 2 * forgedBytes, `${sentBytes} bytes out for ${forgedBytes} in`);

  // ...and none of its lines reached the lobby.
  assert.strictEqual(infosNaming(socket, BOB, mark, "Mallory", false), 0);
  assert.strictEqual(infosNaming(socket, CAROL, mark, "Mallory", false), 0);
  assert.strictEqual(infosNaming(socket, DAVE, mark, "Mallory", true), 0);
  const mallory = server.users.get("Mallory");
  assert.ok(!mallory || (!mallory.confirmed && !mallory.v2Confirmed), "a forged v2 session confirmed");
});

test("a v2 session's roster follows its first packet with S", () => {
  const { server, socket } = h.makeServer();
  joinLegacy(server, "Bob", BOB);
  joinLegacy(server, "Carol", CAROL);
  server.onDatagram(h.spectate("Carol", "Bob"), CAROL);

  let mark = socket.sent.length;
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  const alice = server.users.get("Alice");
  const before = h.sentTo(socket, ALICE.address, ALICE.port, mark).map((packet) => packet.buffer);
  assert.deepStrictEqual(before, [accepted(C_ALICE, alice.serverToken)], "only the accept before S");
  assert.strictEqual(alice.v2Confirmed, false);

  mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice"), alice.serverToken), ALICE), true);
  assert.strictEqual(alice.confirmed, true);
  assert.strictEqual(alice.v2Confirmed, true);
  const after = h.sentTo(socket, ALICE.address, ALICE.port, mark).map((packet) => unwrap(packet.buffer));
  assert.ok(after.some((buffer) => buffer.equals(packets.connect(server.users.get("Bob"), false))), "Bob's roster entry");
  assert.ok(after.some((buffer) => buffer.equals(packets.connect(server.users.get("Carol"), false))), "Carol's roster entry");
  assert.ok(after.some((buffer) => buffer.equals(packets.spectate("Carol", "Bob"))), "who is watching whom");
});

test("forged v2 squatters are evicted", () => {
  const { server, socket, clock } = h.makeServer();
  assert.strictEqual(server.config.maxPlayers, 16);
  const squatters = [];
  for (let i = 0; i < 16; i += 1) {
    // Four addresses (MAX_SESSIONS_PER_ADDRESS), four ports each.
    const rinfo = h.from(`198.51.100.${10 + (i >> 2)}`, 41000 + i);
    assert.strictEqual(server.onDatagram(h.connectV2(`Squat${i}`, Buffer.alloc(8, i + 1)), rinfo), true);
    squatters.push({ name: `Squat${i}`, rinfo });
  }
  assert.strictEqual(server.users.count(), 16);

  // A legacy forger confirms with its second packet; these stream lines at
  // 50 Hz and get nowhere without S.
  for (let t = 0; t < 3000; t += 20) {
    for (const squatter of squatters) server.onDatagram(h.update(squatter.name), squatter.rinfo);
    clock.advance(20);
  }
  for (const squatter of squatters) assert.strictEqual(server.users.get(squatter.name).confirmed, false);

  const REAL = h.from("203.0.113.50", 50000);
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Real", C_ALICE), REAL), true);
  const accept = h.sentTo(socket, REAL.address, REAL.port, mark).find((packet) => packet.buffer[0] === 7);
  assert.ok(accept, "the real player was not admitted");
  assert.strictEqual(server.stats.squattersEvicted, 1);
  assert.strictEqual(server.users.count(), 16);
  const token = h.stripNonce(accept.buffer).rest;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Real"), token), REAL), true);
  assert.strictEqual(server.users.get("Real").v2Confirmed, true);
});

test("confirmed v2 receiver is unmetered", () => {
  const { server, socket, clock } = h.makeServer();
  const RX = h.from("10.1.0.1", 50000);
  const tokenRx = joinV2(server, socket, "Receiver", RX, C_ALICE);
  const senders = [];
  for (let i = 0; i < 15; i += 1) {
    const name = `Sender${String(i).padStart(2, "0")}`;
    const rinfo = h.from(`10.2.0.${i + 1}`, 50001 + i);
    joinLegacy(server, name, rinfo);
    senders.push({ name, rinfo, next: clock.now() });
  }

  // The receiver at 10 lines a second, fifteen senders at 66 carrying a prop.
  const mark = socket.sent.length;
  const start = clock.now();
  let rxNext = start;
  let relayed = 0;
  while (clock.now() < start + 6000) {
    const now = clock.now();
    if (now >= rxNext) {
      server.onDatagram(h.withToken(h.update("Receiver", { position: [now % 977, 0, 0] }), tokenRx), RX);
      rxNext += 100;
    }
    for (const sender of senders) {
      if (now < sender.next) continue;
      sender.next += 1000 / 66;
      const line = h.update(sender.name, { position: [now % 977, 1, 0], heldModel: HELD });
      if (server.onDatagram(line, sender.rinfo)) relayed += 1;
    }
    clock.advance(1);
  }
  assert.ok(relayed >= 15 * 66 * 6 - 15, `only ${relayed} lines were accepted`);
  const got = h
    .sentTo(socket, RX.address, RX.port, mark)
    .filter((packet) => h.stripNonce(packet.buffer).type === packets.TYPE.INFO).length;
  assert.strictEqual(got, relayed, `the v2 receiver got ${got} of ${relayed}`);
  assert.strictEqual(server.users.get("Receiver").v2Confirmed, true);
});

// Ruling 9: a confirmed v2 receiver skips only the outbound credit. The
// liveness gate stays: no accepted line for LIVENESS_MS, no fan-out.
test("a confirmed v2 receiver that stops sending gets no fan-out after LIVENESS_MS, positions and spray drip alike", () => {
  // A slow drip, so the picture is still being fed when Alice goes quiet.
  const { server, socket, clock } = h.makeServer({ SPRAY_CHUNKS_PER_TICK: "4" });
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);
  joinLegacy(server, "Carol", CAROL);

  // Carol uploads a many-piece picture while all three keep moving.
  const { blob, crc } = h.sprayBlob(128, 9, true);
  const total = Math.ceil(blob.length / 400);
  for (let i = 0; i < total; i += 1) {
    const piece = blob.subarray(i * 400, Math.min((i + 1) * 400, blob.length));
    server.onDatagram(h.sprayChunk("Carol", crc, blob.length, total, i, piece), CAROL);
    server.onDatagram(h.withToken(h.update("Alice", { position: [i, 0, 0] }), token), ALICE);
    server.onDatagram(h.update("Bob", { position: [i, 1, 0] }), BOB);
    clock.advance(40);
  }
  const published = server.users.get("Carol").spray;
  assert.ok(published, "the picture was published");

  // Then Alice sends nothing more (a crashed client); Bob and Carol go on.
  const alice = server.users.get("Alice");
  const cutoff = alice.lastLineTime + server.config.livenessMs;
  const silence = socket.sent.length;
  let cut = null;
  let relayedLive = 0;
  while (clock.now() < cutoff + server.config.livenessMs) {
    if (cut === null && clock.now() > cutoff) cut = socket.sent.length;
    const ok = server.onDatagram(h.update("Bob", { position: [clock.now() % 977, 1, 0] }), BOB);
    if (ok && cut === null) relayedLive += 1;
    server.onDatagram(h.update("Carol", { position: [clock.now() % 977, 2, 0] }), CAROL);
    clock.advance(20);
  }
  assert.ok(cut !== null);

  // What Alice was sent between two marks, C stripped.
  const toAlice = (from, to) =>
    socket.sent
      .slice(from, to)
      .filter((packet) => packet.address === ALICE.address && packet.port === ALICE.port)
      .map((packet) => unwrap(packet.buffer));
  const live = toAlice(silence, cut);
  const after = toAlice(cut);
  const count = (list, type) => list.filter((buffer) => buffer[0] === type).length;

  // While she is live she gets every position (no credit is charged, and her
  // last line earned only a few lines' worth) and the drip.
  const bobLive = live.filter((buffer) => buffer[0] === packets.TYPE.INFO && h.readInfo(buffer).name === "Bob").length;
  assert.strictEqual(bobLive, relayedLive, "a live v2 receiver missed positions");
  const piecesLive = count(live, packets.TYPE.SPRAY_CHUNK);
  assert.ok(piecesLive > 0 && piecesLive < published.total, `${piecesLive} of ${published.total} pieces while live`);
  // Past LIVENESS_MS: no positions and no spray pieces; heartbeats still go.
  assert.strictEqual(count(after, packets.TYPE.INFO), 0, "positions after LIVENESS_MS");
  assert.strictEqual(count(after, packets.TYPE.SPRAY_CHUNK), 0, "spray pieces after LIVENESS_MS");
  assert.ok(count(after, packets.TYPE.HEARTBEAT) > 0, "heartbeats still reach her");
});

// Ruling 10: the S check runs before every budget, the global ceiling
// included, so forged unsigned packets from a v2 player's exact endpoint never
// count as trusted traffic anywhere.
test("a forged unsigned flood from a confirmed v2 endpoint does not touch the global limiter", () => {
  const run = (flood) => {
    const { server, socket, clock } = h.makeServer({ GLOBAL_PACKETS_PER_SECOND: "1000" });
    const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
    joinLegacy(server, "Bob", BOB);
    clock.advance(100);
    const mark = socket.sent.length;
    let real = 0;
    let accepted = 0;
    for (let ms = 0; ms < 1000; ms += 1) {
      for (let i = 0; i < flood; i += 1) server.onDatagram(h.update("Alice", { position: [9, 9, 9] }), ALICE);
      if (ms % 30 === 0) {
        real += 1;
        if (server.onDatagram(h.withToken(h.update("Alice", { position: [ms, 0, 0] }), token), ALICE)) accepted += 1;
        server.onDatagram(h.update("Bob", { position: [ms, 1, 0] }), BOB);
      }
      clock.advance(1);
    }
    return {
      server,
      real,
      accepted,
      relayed: infosNaming(socket, BOB, mark, "Alice", false),
      limiter: Object.assign({ tokens: server.global.tokens }, server.global.stats()),
    };
  };
  const quiet = run(0);
  const flooded = run(5); // 5000 a second against a ceiling of 1000
  assert.strictEqual(flooded.server.stats.badToken, 5000);
  assert.deepStrictEqual(flooded.limiter, quiet.limiter, "the flood moved the global limiter");
  assert.strictEqual(flooded.accepted, flooded.real, `${flooded.real - flooded.accepted} real lines were dropped`);
  assert.strictEqual(flooded.relayed, flooded.real, "every real line reached Bob");
});

test("no guard for v2", () => {
  const { server, socket, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);

  // A sweep: eight other ports of Alice's own IP name her within 30 s.
  const mark = socket.sent.length;
  for (let i = 0; i < 8; i += 1) {
    assert.strictEqual(server.onDatagram(h.chat("Alice", "not me"), h.from(ALICE.address, 30000 + i)), false);
    clock.advance(1000);
  }
  const alice = server.users.get("Alice");
  assert.strictEqual(server.stats.impersonationGuards, 0);
  assert.strictEqual(server.isGuarded(alice, clock.now()), false);

  assert.strictEqual(server.onDatagram(h.withToken(h.chat("Alice", "still me"), token), ALICE), true);
  const chats = h
    .sentTo(socket, BOB.address, BOB.port, mark)
    .filter((packet) => packet.buffer[0] === packets.TYPE.CHAT)
    .map((packet) => readChat(packet.buffer));
  assert.deepStrictEqual(chats.map((c) => [c.name, c.text]), [["Alice", "still me"]]);
});

test("unsigned packets from a v2 player's own endpoint cannot spend her session budget", () => {
  const { server, socket, clock, log } = h.makeServer();
  assert.strictEqual(server.config.burstPerSession, 240, "the session bucket's normal capacity");
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);
  clock.advance(100);

  // One second: 2000 forged unsigned packets from Alice's exact address:port,
  // and her real signed lines at 33 a second between them (Bob moves too).
  const mark = socket.sent.length;
  let real = 0;
  let realAccepted = 0;
  for (let ms = 0; ms < 1000; ms += 1) {
    server.onDatagram(h.update("Alice", { position: [9, 9, 9] }), ALICE);
    server.onDatagram(h.chat("Alice", "forged"), ALICE);
    if (ms % 30 === 0) {
      real += 1;
      if (server.onDatagram(h.withToken(h.update("Alice", { position: [ms, 0, 0] }), token), ALICE)) realAccepted += 1;
      server.onDatagram(h.update("Bob", { position: [ms, 1, 0] }), BOB);
    }
    clock.advance(1);
  }
  assert.strictEqual(server.stats.badToken, 2000);
  assert.strictEqual(realAccepted, real, `${real - realAccepted} of Alice's ${real} real lines were dropped`);
  assert.strictEqual(infosNaming(socket, BOB, mark, "Alice", false), real, "every real line reached Bob");
  const sessionLimited = log.lines.filter((line) => line[0] === "event" && line[1] === "session-limit");
  assert.strictEqual(sessionLimited.length, 0);
  assert.strictEqual(server.users.get("Alice").position.x, 990, "only the signed lines were applied");
});

// Ruling 11: the rest of the lobby is told a v2 session joined (type 0, the
// announce byte set) when it confirms, not when it connects; a session nobody
// was told about leaves without a type 4. Legacy sessions are unchanged.

// What `rinfo` was told about `name` since `since`: [type 0 with announce 1,
// type 4] counts (C stripped for a v2 receiver).
const toldAbout = (socket, rinfo, since, name, v2) => {
  const buffers = h
    .sentTo(socket, rinfo.address, rinfo.port, since)
    .map((packet) => (v2 ? unwrap(packet.buffer) : packet.buffer))
    .filter((buffer) => buffer[0] === packets.TYPE.CONNECT || buffer[0] === packets.TYPE.DISCONNECT)
    .filter((buffer) => new Message(buffer.subarray(1), {}).readString() === name);
  return {
    joins: buffers.filter((buffer) => buffer[0] === packets.TYPE.CONNECT && buffer[buffer.length - 1] === 1).length,
    leaves: buffers.filter((buffer) => buffer[0] === packets.TYPE.DISCONNECT).length,
  };
};

test("a forged v2 connect that never signs is never announced to others", () => {
  const { server, socket, clock } = h.makeServer();
  joinLegacy(server, "Bob", BOB);
  const tokenDave = joinV2(server, socket, "Dave", DAVE, C_DAVE);
  const VICTIM = h.from("198.51.100.7", 40007);

  // Announces, unsigned lines and retries for a minute: swept after 20 s and
  // announced afresh several times over.
  const mark = socket.sent.length;
  server.onDatagram(h.connectV2("Mallory", C_FORGED), VICTIM);
  for (let t = 0; t < 60000; t += 20) {
    server.onDatagram(h.update("Bob", { position: [t % 977, 1, 0] }), BOB);
    server.onDatagram(h.withToken(h.update("Dave", { position: [t % 977, 3, 0] }), tokenDave), DAVE);
    server.onDatagram(h.update("Mallory"), VICTIM);
    if (t % 5000 === 4980) server.onDatagram(h.connectV2("Mallory", C_FORGED), VICTIM);
    clock.advance(20);
  }
  assert.ok(
    server.log.lines.some((line) => line[0] === "info" && line[1] === "Dropped '%s': %s" && line[2] === "Mallory"),
    "the forged session was swept at least once"
  );
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Mallory", false), { joins: 0, leaves: 0 });
  assert.deepStrictEqual(toldAbout(socket, DAVE, mark, "Mallory", true), { joins: 0, leaves: 0 });
});

test("a v2 session nobody was told about is in nobody's roster, and cannot be spectated", () => {
  const { server, socket } = h.makeServer();
  const VICTIM = h.from("198.51.100.7", 40007);
  server.onDatagram(h.connectV2("Mallory", C_FORGED), VICTIM); // never signs
  const mark = socket.sent.length;

  // Two players join while it is there: one legacy, one v2.
  joinLegacy(server, "Bob", BOB);
  joinV2(server, socket, "Dave", DAVE, C_DAVE);
  // A roster entry, or a spectate line, is as good as an announcement: the
  // client keeps the name until a type 4 that will never come.
  const named = (rinfo, v2) =>
    h
      .sentTo(socket, rinfo.address, rinfo.port, mark)
      .map((packet) => (v2 ? unwrap(packet.buffer) : packet.buffer))
      .filter((buffer) => buffer.includes(Buffer.from("Mallory", "latin1"))).length;
  assert.strictEqual(named(BOB, false), 0, "Bob was told about Mallory");
  assert.strictEqual(named(DAVE, true), 0, "Dave was told about Mallory");

  // Spectating it is spectating nobody.
  server.onDatagram(h.spectate("Bob", "Mallory"), BOB);
  assert.strictEqual(server.users.get("Bob").spectating, "");
  assert.strictEqual(named(BOB, false) + named(DAVE, true), 0);
});

test("a real v2 player is announced exactly once, right after its first signed l", () => {
  const { server, socket } = h.makeServer();
  joinLegacy(server, "Bob", BOB);

  let mark = socket.sent.length;
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  const token = server.users.get("Alice").serverToken;
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Alice", false), { joins: 0, leaves: 0 }, "announced at connect");

  mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice"), token), ALICE), true);
  const toBob = h.sentTo(socket, BOB.address, BOB.port, mark).map((packet) => packet.buffer);
  assert.ok(toBob[0].equals(packets.connect(server.users.get("Alice"), true)), "the join comes first, then her position");
  assert.strictEqual(h.readInfo(toBob[1]).name, "Alice");
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Alice", false), { joins: 1, leaves: 0 });

  // Legacy, for comparison: announced at connect, as in 1.2.0.
  mark = socket.sent.length;
  server.onDatagram(h.connect("Carol"), CAROL);
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Carol", false), { joins: 1, leaves: 0 });
});

test("the duplicate-connect, lost-accept and REQUIRE_PROTOCOL_V2 paths do not announce twice", () => {
  const { server, socket, clock } = h.makeServer({ REQUIRE_PROTOCOL_V2: "1" });
  const tokenBob = joinV2(server, socket, "Bob", BOB, C_BOB);
  const mark = socket.sent.length;

  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE); // lost accept: unsigned, same C
  clock.advance(5000);
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Alice", true), { joins: 0, leaves: 0 }, "announced before S");

  const token = server.users.get("Alice").serverToken;
  for (let i = 0; i < 3; i += 1) {
    assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice", { position: [i, 0, 0] }), token), ALICE), true);
    clock.advance(20);
  }
  // Duplicate connects with S, past the roster throttle.
  for (let i = 0; i < 2; i += 1) {
    clock.advance(5000);
    assert.strictEqual(server.onDatagram(h.withToken(h.connectV2("Alice", C_ALICE), token), ALICE), true);
    server.onDatagram(h.withToken(h.update("Bob"), tokenBob), BOB);
  }
  // A legacy connect, refused under REQUIRE_PROTOCOL_V2.
  assert.strictEqual(server.onDatagram(h.connect("Carol"), CAROL), false);

  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Alice", true), { joins: 1, leaves: 0 });
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Carol", true), { joins: 0, leaves: 0 });
});

test("a v2 session that silently took over a name the lobby knows still says goodbye for it", () => {
  // Alice (legacy, announced) goes quiet; a v2 connect for "Alice" from another
  // port of her address takes the name over silently and never signs. The
  // lobby still has Alice's ghost, so when the sweep removes the new session
  // the lobby must be told - or it keeps that ghost forever.
  const { server, socket, clock } = h.makeServer();
  joinLegacy(server, "Bob", BOB);
  joinLegacy(server, "Alice", ALICE);
  const mark = socket.sent.length;
  for (let t = 0; t <= server.config.takeoverAfterMs; t += 1000) {
    server.onDatagram(h.update("Bob"), BOB);
    clock.advance(1000);
  }
  const ALICE2 = h.from(ALICE.address, 40011);
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE2), true);
  assert.strictEqual(server.users.get("Alice").socket.port, 40011, "the name was taken over");
  for (let t = 0; t < server.config.unconfirmedTimeoutMs + 2 * server.config.sweepIntervalMs; t += 1000) {
    server.onDatagram(h.update("Bob"), BOB);
    clock.advance(1000);
  }
  assert.strictEqual(server.users.get("Alice"), null, "the unconfirmed v2 session was swept");
  assert.deepStrictEqual(toldAbout(socket, BOB, mark, "Alice", false), { joins: 0, leaves: 1 });
});

test("unconfirmedBytes and stats.bytesOut count the 8 bytes of C", () => {
  const { server, socket, clock } = h.makeServer();
  joinLegacy(server, "Bob", BOB);

  let out = server.stats.bytesOut;
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  const alice = server.users.get("Alice");
  // packets.js builds the 1-byte type 7, acceptPacket adds S (9 bytes), and C
  // goes between them on the wire. Nothing else goes out yet: her join waits
  // for her first packet with S (ruling 11).
  assert.strictEqual(lastTo(socket, ALICE).buffer.length, 17);
  assert.strictEqual(alice.unconfirmedBytes, 17);
  assert.strictEqual(server.stats.bytesOut - out, 17);

  // Confirmed: a heartbeat is 1 byte to legacy Bob and 9 to Alice.
  server.onDatagram(h.withToken(h.update("Alice"), alice.serverToken), ALICE);
  out = server.stats.bytesOut;
  const beats = socket.sent.length;
  clock.advance(server.config.heartbeatMs);
  assert.deepStrictEqual(socket.sent.slice(beats).map((packet) => packet.buffer.length).sort(), [1, 9]);
  assert.strictEqual(server.stats.bytesOut - out, 10);
});

test("the unconfirmed budget runs out at the wire size of 07 C S, C included", () => {
  // The smallest budget allowed, and a connect budget that is not the limit.
  const { server, socket } = h.makeServer({ UNCONFIRMED_BUDGET_BYTES: "512", CONNECT_BURST: "100" });
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  for (let i = 0; i < 39; i += 1) server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE); // lost accepts
  const accepts = h.sentTo(socket, ALICE.address, ALICE.port).filter((packet) => packet.buffer[0] === 7);
  assert.strictEqual(accepts.length, Math.floor(512 / 17)); // 30; counted without C it would be 56
  assert.strictEqual(server.stats.reflectionBlocked, 40 - 30);
});

// ---------------------------------------------------------------------------
// 1.3.1, from the final review of protocol v2.
//
// M3: an unsigned connect never takes a confirmed v2 session over and never
// renames it. Such a session is freed only by its own signed goodbye, by the
// stale sweep (STALE_TIMEOUT_MS of silence) or by the server (console, a kick
// for junk that carried its S).
// M4 (ruling 14): a confirmed v2 session is never evicted by the squat rate
// tier; that tier exists against forged squatters, which v2 cannot be.
// M5: a packet carrying the right S is trusted traffic at the address box and
// the address budget even before the session confirms, so a flood of junk from
// other ports of the player's IP cannot starve the first signed line.
// ---------------------------------------------------------------------------

test("an unsigned connect from the player's own IP cannot take a confirmed v2 session over while it is live", () => {
  const { server, socket, clock } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  joinLegacy(server, "Bob", BOB);
  const alice = server.users.get("Alice");

  // Alice loads a level (or sits in the main menu): 15 s of silence, longer
  // than TAKEOVER_AFTER_MS. Bob keeps playing.
  for (let t = 0; t < 15000; t += 1000) {
    server.onDatagram(h.update("Bob"), BOB);
    clock.advance(1000);
  }
  assert.ok(15000 > server.config.takeoverAfterMs);

  // Someone sending from other ports of her IP (a spoofer, a CGNAT neighbour)
  // announces her name, as v2 and as legacy.
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C_FORGED), h.from(ALICE.address, 40099)), false);
  assert.strictEqual(server.onDatagram(h.connect("Alice"), h.from(ALICE.address, 40098)), false);
  assert.strictEqual(server.users.get("Alice"), alice, "the session was replaced");
  assert.strictEqual(alice.socket.port, ALICE.port);
  assert.ok(!h.typesSent(socket, mark).includes(packets.TYPE.DISCONNECT), "somebody was told she left");
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).length, 0, "something reached Alice");

  // She comes back from the load and carries on with the same S.
  const before = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice", { position: [7, 0, 0] }), token), ALICE), true);
  assert.strictEqual(infosNaming(socket, BOB, before, "Alice", false), 1);
});

test("a crashed v2 player's name is free once the session is stale, not before", () => {
  const { server, socket, clock } = h.makeServer();
  joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const ALICE2 = h.from(ALICE.address, 40011);
  const C2 = Buffer.from("c1c2c3c4c5c6c7c8", "hex");

  clock.advance(server.config.staleTimeoutMs - 1000);
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C2), ALICE2), false, "taken over while live");
  assert.strictEqual(server.users.get("Alice").socket.port, ALICE.port);

  clock.advance(1000);
  assert.strictEqual(server.onDatagram(h.connectV2("Alice", C2), ALICE2), true);
  assert.strictEqual(server.users.get("Alice").socket.port, ALICE2.port);
});

test("an unsigned connect from a v2 session's own endpoint never renames or replaces it", () => {
  const { server, socket } = h.makeServer();
  joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const alice = server.users.get("Alice");
  assert.strictEqual(server.onDatagram(h.connect("Mallory"), ALICE), false);
  assert.strictEqual(server.onDatagram(h.connectV2("Mallory", C_FORGED), ALICE), false);
  assert.strictEqual(server.onDatagram(h.connectV2("Mallory", C_ALICE), ALICE), false);
  assert.strictEqual(server.users.get("Mallory"), null);
  assert.strictEqual(server.users.get("Alice"), alice);
  assert.strictEqual(server.stats.badToken, 3);

  // Unconfirmed (her accept was lost): the same C with another name is no
  // lost-accept re-announce either.
  const { server: s2 } = h.makeServer();
  s2.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  assert.strictEqual(s2.onDatagram(h.connectV2("Mallory", C_ALICE), ALICE), false);
  assert.strictEqual(s2.onDatagram(h.connect("Mallory"), ALICE), false);
  assert.strictEqual(s2.users.get("Mallory"), null);
  assert.ok(s2.users.get("Alice"));
});

test("a confirmed v2 player is never evicted by the squat rate tier; the slowest legacy one still is", () => {
  const { server, socket, clock } = h.makeServer();
  assert.strictEqual(server.config.maxPlayers, 16);
  const fast = [];
  for (let i = 0; i < 14; i += 1) {
    const rinfo = h.from(`10.3.0.${i + 1}`, 41000 + i);
    joinLegacy(server, `Fast${i}`, rinfo);
    fast.push({ name: `Fast${i}`, rinfo });
  }
  const SLOW = h.from("10.4.0.1", 42000);
  joinLegacy(server, "SlowLegacy", SLOW);
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  assert.strictEqual(server.users.count(), 16);

  // Over a minute: 14 players at 25 lines a second, a legacy player at one a
  // second, and Alice (v2, loading most of the time) at one every two seconds -
  // the lowest rate on the server.
  for (let t = 0; t <= server.config.squatWindowMs + 1000; t += 40) {
    for (const p of fast) server.onDatagram(h.update(p.name, { position: [t % 977, 0, 0] }), p.rinfo);
    if (t % 1000 === 0) server.onDatagram(h.update("SlowLegacy", { position: [t % 977, 1, 0] }), SLOW);
    if (t % 2000 === 0) server.onDatagram(h.withToken(h.update("Alice", { position: [t % 977, 2, 0] }), token), ALICE);
    clock.advance(40);
  }

  const NEW = h.from("198.51.100.60", 43000);
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connect("Newcomer"), NEW), true);
  assert.ok(server.users.get("Newcomer"), "the newcomer was not admitted");
  assert.ok(server.users.get("Alice"), "a confirmed v2 player was evicted as a squatter");
  assert.strictEqual(server.users.get("SlowLegacy"), null, "the slowest legacy session was not the one to go");
  assert.strictEqual(server.stats.squattersEvicted, 1);
  assert.strictEqual(h.sentTo(socket, ALICE.address, ALICE.port, mark).some((p) => p.buffer[0] === packets.TYPE.KICK), false);
});

test("a full server of confirmed v2 players turns a newcomer away rather than evict a slow one", () => {
  const { server, socket, clock } = h.makeServer();
  const players = [];
  for (let i = 0; i < 16; i += 1) {
    const rinfo = h.from(`10.5.0.${i + 1}`, 44000 + i);
    players.push({ name: `V${i}`, rinfo, token: joinV2(server, socket, `V${i}`, rinfo, Buffer.alloc(8, i + 1)) });
  }
  // All of them at one line a second: every one is under SQUAT_EVICT_PPS.
  for (let t = 0; t <= server.config.squatWindowMs + 1000; t += 1000) {
    for (const p of players) server.onDatagram(h.withToken(h.update(p.name, { position: [t % 977, 0, 0] }), p.token), p.rinfo);
    clock.advance(1000);
  }
  const NEW = h.from("198.51.100.61", 43001);
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.connect("Newcomer"), NEW), false);
  assert.strictEqual(server.users.count(), 16);
  assert.strictEqual(server.stats.squattersEvicted, 0);
  const reply = h.sentTo(socket, NEW.address, NEW.port, mark);
  assert.ok(reply.some((p) => p.buffer.toString("latin1").includes("full")), "the newcomer was not told the server is full");
});

// The first signed line of a session whose accept just arrived, sent at 50 Hz
// while `flood(ms)` runs. Returns how many were sent and accepted.
const firstSignedLinesUnder = (flood, env = {}) => {
  const rig = h.makeServer(env);
  const { server, socket, clock } = rig;
  joinLegacy(server, "Bob", BOB);
  const mark = socket.sent.length;
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  const accept = h.sentTo(socket, ALICE.address, ALICE.port, mark).find((p) => p.buffer[0] === 7);
  const token = h.stripNonce(accept.buffer).rest;
  let sent = 0;
  let accepted = 0;
  for (let ms = 0; ms < 3000; ms += 1) {
    flood(server, ms);
    if (ms >= 50 && ms % 20 === 0) {
      sent += 1;
      if (server.onDatagram(h.withToken(h.update("Alice", { position: [ms, 0, 0] }), token), ALICE)) accepted += 1;
    }
    clock.advance(1);
  }
  return Object.assign(rig, { sent, accepted });
};

test("junk from other ports of a v2 player's IP cannot hold back her first signed line: boxed address", () => {
  // Unknown-opcode junk, one a millisecond: the address is boxed within 20 of
  // them, and the junk drains the box's one-a-second trickle.
  const junk = Buffer.from([0, 0, 0, 2, 0x7a, 0x7a, 0, 0, 0, 0]);
  const { server, sent, accepted } = firstSignedLinesUnder((s, ms) => s.onDatagram(junk, h.from(ALICE.address, 30000 + (ms % 64))));
  assert.ok(server.penalty.has(ALICE.address), "the address was not boxed: the test proves nothing");
  assert.strictEqual(server.users.get("Alice").v2Confirmed, true, "her session never confirmed");
  assert.strictEqual(accepted, sent, `${sent - accepted} of her ${sent} signed lines were dropped`);
});

test("junk from other ports of a v2 player's IP cannot hold back her first signed line: address budget", () => {
  // Well-formed lines naming nobody (sampled noise, never punished), four a
  // millisecond over 64 ports: the address budget is spent, no session budget.
  // The address budget is cut to 100 so that its burst is gone before her
  // first line; at the default 960 a flood needs about 20000 a second to do
  // that within one round trip, and the outcome is the same.
  const flood = (s, ms) => {
    for (let i = 0; i < 4; i += 1) s.onDatagram(h.update("Nobody"), h.from(ALICE.address, 30000 + ((4 * ms + i) % 64)));
  };
  const { server, log, sent, accepted } = firstSignedLinesUnder(flood, { RATE_PER_ADDRESS: "100", BURST_PER_ADDRESS: "100" });
  assert.ok(log.lines.some((line) => line[0] === "event" && line[1] === "address-limit"), "the address budget was never spent");
  assert.strictEqual(server.penalty.has(ALICE.address), false, "boxed: this case is about the budget alone");
  assert.strictEqual(server.users.get("Alice").v2Confirmed, true, "her session never confirmed");
  assert.strictEqual(accepted, sent, `${sent - accepted} of her ${sent} signed lines were dropped`);
});

test("a datagram of 0-3 bytes, or one too short to hold S, from a v2 owner is a bad token, never malformed", () => {
  for (const confirm of [false, true]) {
    const { server, socket } = h.makeServer();
    if (confirm) joinV2(server, socket, "Alice", ALICE, C_ALICE);
    else server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
    const alice = server.users.get("Alice");
    const cases = [
      Buffer.alloc(0),
      Buffer.from([0]),
      Buffer.from([0, 0, 0]),
      Buffer.from([0, 0, 0, 1, 0x6c]), // an opcode, no S
      Buffer.concat([Buffer.from([0, 0, 0, 1, 0x6c]), alice.serverToken.subarray(0, 7)]), // 7 bytes of S
      Buffer.from([0xff, 0xff, 0xff, 0xff, 0x6c]), // an opcode length nothing could hold
    ];
    for (const packet of cases) assert.strictEqual(server.onDatagram(packet, ALICE), false);
    assert.strictEqual(server.stats.badToken, cases.length, `confirmed ${confirm}`);
    assert.strictEqual(server.stats.malformed, 0, `confirmed ${confirm}`);
    assert.strictEqual(server.penalty.size, 0, `confirmed ${confirm}`);
    assert.strictEqual(server.users.get("Alice"), alice, `confirmed ${confirm}`);
  }
});
