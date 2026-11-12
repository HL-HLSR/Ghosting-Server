"use strict";

// Sprays: the first thing on this wire that carries artwork.
//
// The server never looks inside the payload - it stores pieces and hands them
// on - so what is tested here is the shape of the transfer and the limits on
// it, not the picture. The blobs below are deliberately not textures.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const { Message } = require("../src/wire/reader");
const { KIND } = require("../src/game/access");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);

const CRC = 0x1234abcd | 0;

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

const blobOf = (n, seed = 7) => {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (i * seed + 11) & 0xff;
  return b;
};

// Decode a type 15 the way the mod does.
const readChunk = (buffer) => {
  const m = new Message(buffer.subarray(1), {});
  return {
    name: m.readString(),
    crc: m.readInt32(),
    rawBytes: m.readInt32(),
    total: m.readInt32(),
    index: m.readInt32(),
    payload: m.readBytes(limits.SPRAY_CHUNK_BYTES),
  };
};

// Drain the drip, keeping every receiver credited the way a real client stays
// credited: the metered fan-out (H2) spends outbound credit a session earns with
// ACCEPTED position updates, so a receiver that never sends is correctly
// starved. Real clients send ~33-50 a second; here each pass advances 20 ms and
// feeds every confirmed session one (an update inside the 15 ms throttle would
// be refused and earn nothing).
const drain = (server, clock, passes = 400) => {
  for (let i = 0; i < passes; i++) {
    clock.advance(20);
    for (const user of server.users.values()) {
      server.onDatagram(h.update(user.name), { address: user.socket.address, port: user.socket.port, family: "IPv4" });
    }
    server.dripSprays();
  }
};

// Reassemble the chunks a receiver got into the blob the lobby relayed.
const reassemble = (chunks) => Buffer.concat(chunks.map((c) => c.payload));

const chunksTo = (socket, rinfo, since = 0) =>
  h.sentTo(socket, rinfo.address, rinfo.port, since).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPRAY_CHUNK);

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

test("a spray chunk survives the round trip byte for byte", () => {
  const payload = blobOf(limits.SPRAY_CHUNK_BYTES);
  const decoded = readChunk(packets.sprayChunk("Alice", CRC, 9999, 12, 5, payload));

  assert.strictEqual(decoded.name, "Alice");
  assert.strictEqual(decoded.crc, CRC);
  assert.strictEqual(decoded.rawBytes, 9999);
  assert.strictEqual(decoded.total, 12);
  assert.strictEqual(decoded.index, 5);
  assert.ok(decoded.payload.equals(payload), "payload must be unchanged");
});

test("a full chunk stays inside one datagram", () => {
  const buffer = packets.sprayChunk("A".repeat(limits.MAX_NAME_LENGTH), -1, limits.MAX_SPRAY_RAW_BYTES,
    limits.MAX_SPRAY_CHUNKS, limits.MAX_SPRAY_CHUNKS - 1, blobOf(limits.SPRAY_CHUNK_BYTES));
  assert.ok(buffer.length <= limits.MAX_OUTBOUND_BYTES, `${buffer.length} bytes`);
});

test("an inbound chunk at full size stays inside the datagram the server will parse", () => {
  const buffer = h.sprayChunk("A".repeat(limits.MAX_NAME_LENGTH), CRC, 1000, 60, 0, blobOf(limits.SPRAY_CHUNK_BYTES));
  assert.ok(buffer.length <= limits.MAX_DATAGRAM_BYTES, `${buffer.length} bytes`);
});

test("a byte field cannot be used to smuggle past the string budget", () => {
  // Two byte fields in one packet is refused: the cap is per field, so allowing
  // several would let one datagram carry as much as it liked.
  const { BufferWriter } = require("../src/wire/writer");
  const w = new BufferWriter();
  w.writeBytes(blobOf(10));
  w.writeBytes(blobOf(10));
  const m = new Message(w.buffer, {});
  m.readBytes(400);
  assert.throws(() => m.readBytes(400), /more than one byte field/);
});

test("an over-long byte field is refused rather than truncated", () => {
  const { BufferWriter } = require("../src/wire/writer");
  const w = new BufferWriter();
  w.writeBytes(blobOf(300));
  const m = new Message(w.buffer, {});
  assert.throws(() => m.readBytes(100), /bad byte field length/);
});

// ---------------------------------------------------------------------------
// Upload and relay
// ---------------------------------------------------------------------------

test("a spray arrives in pieces and is published once the last one lands", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  // A real, valid picture: the server now inspects the blob and refuses junk.
  const { blob, crc } = h.sprayBlob(64, 1, true);
  const expected = Math.ceil(blob.length / 400);
  const total = h.uploadSpray(server, ALICE, "Alice", crc, blob);

  assert.strictEqual(total, expected);
  assert.ok(alice.spray, "spray should be published");
  assert.strictEqual(alice.spray.crc, crc);
  // The relayed picture is the host's canonical re-encode of the same VTF; the
  // test blob is built the same way, so it is byte-identical.
  assert.strictEqual(alice.spray.bytes, blob.length);
  assert.strictEqual(alice.spray.total, expected);
  assert.strictEqual(alice.sprayIn, null, "the pending upload should be cleared");
});

test("an incomplete spray is not published", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  const blob = blobOf(1000);
  server.onDatagram(h.sprayChunk("Alice", CRC, blob.length, 3, 0, blob.subarray(0, 400)), ALICE);
  server.onDatagram(h.sprayChunk("Alice", CRC, blob.length, 3, 1, blob.subarray(400, 800)), ALICE);

  assert.strictEqual(alice.spray, null);
  assert.ok(alice.sprayIn, "the upload should still be pending");
  assert.strictEqual(alice.sprayIn.have, 2);
});

test("a resent piece is not charged twice", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  const piece = blobOf(400);
  for (let i = 0; i < 5; i++) {
    server.onDatagram(h.sprayChunk("Alice", CRC, 800, 2, 0, piece), ALICE);
  }

  assert.strictEqual(alice.sprayIn.have, 1);
  assert.strictEqual(alice.sprayIn.bytes, 400);
});

test("the pieces reach another player unchanged and in order", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  const mark = socket.sent.length;
  const { blob, crc } = h.sprayBlob(64, 2, true);
  const total = Math.ceil(blob.length / 400);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  drain(server, clock);

  const got = chunksTo(socket, BOB, mark).map((p) => readChunk(p.buffer));
  assert.strictEqual(got.length, total);
  assert.deepStrictEqual(got.map((c) => c.index), got.map((_, i) => i));
  assert.ok(reassemble(got).equals(blob), "reassembled blob must match what was relayed");
  assert.ok(got.every((c) => c.name === "Alice" && c.crc === crc && c.rawBytes === blob.length));
});

test("the sender is not sent their own spray back", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  const mark = socket.sent.length;
  const { blob, crc } = h.sprayBlob(64, 3, true);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  drain(server, clock);

  assert.strictEqual(chunksTo(socket, ALICE, mark).length, 0);
});

test("somebody joining later is sent the sprays already in the lobby", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);

  const { blob, crc } = h.sprayBlob(64, 4, true);
  const total = Math.ceil(blob.length / 400);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);

  const mark = socket.sent.length;
  join(server, "Bob", BOB);
  drain(server, clock);

  const got = chunksTo(socket, BOB, mark).map((c) => readChunk(c.buffer));
  assert.strictEqual(got.length, total);
  assert.ok(reassemble(got).equals(blob));
});

test("the relay is a trickle, not a burst", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  // A picture with comfortably more pieces than one tick delivers. 128x128 of
  // near-incompressible pixels is ~165 chunks, well past sprayChunksPerTick.
  const { blob, crc } = h.sprayBlob(64, 1, true);
  assert.ok(Math.ceil(blob.length / 400) > server.config.sprayChunksPerTick);

  const mark = socket.sent.length;
  h.uploadSpray(server, ALICE, "Alice", crc, blob);

  // Nothing goes out on the upload itself.
  assert.strictEqual(chunksTo(socket, BOB, mark).length, 0, "chunks must be queued, not sent inline");

  // Bob is an active client: his accepted position updates earn the outbound
  // credit the metered drip spends (H2), including the drip's share while he is
  // owed a picture. 4 x 16 ms stays inside one 250 ms tick, so no drip runs yet.
  for (let i = 0; i < 4; i++) {
    clock.advance(16);
    server.onDatagram(h.update("Bob"), BOB);
  }
  assert.strictEqual(chunksTo(socket, BOB, mark).length, 0, "no tick should have run yet");

  server.dripSprays();
  assert.strictEqual(chunksTo(socket, BOB, mark).length, server.config.sprayChunksPerTick);
});

test("a leaver's queued pieces are dropped", () => {
  const { server } = h.makeServer();
  join(server, "Alice", ALICE);
  const bob = join(server, "Bob", BOB);

  const { blob, crc } = h.sprayBlob(64, 5, true);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  assert.ok(bob.sprayFeeds.has("Alice"), "Bob should have a feed for Alice's spray");

  const alice = server.users.get("Alice");
  server.dropUser(alice, null, "left");

  assert.strictEqual(bob.sprayFeeds.has("Alice"), false, "the leaver's feed must be gone");
});

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

test("a spray past the byte ceiling is dropped whole", () => {
  const { server } = h.makeServer({ SPRAY_UPLOAD_BURST: "4000", SPRAY_UPLOAD_RATE_PER_SECOND: "1000" });
  const alice = join(server, "Alice", ALICE);

  const tooBig = limits.MAX_SPRAY_BYTES + limits.SPRAY_CHUNK_BYTES;
  const total = Math.ceil(tooBig / limits.SPRAY_CHUNK_BYTES);
  for (let i = 0; i < total; i++) {
    server.onDatagram(
      h.sprayChunk("Alice", CRC, 100000, total, i, blobOf(limits.SPRAY_CHUNK_BYTES, i + 1)),
      ALICE
    );
  }

  assert.strictEqual(alice.spray, null, "an oversized spray must not be published");
});

test("a claimed chunk count past the ceiling is refused", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  server.onDatagram(h.sprayChunk("Alice", CRC, 1000, limits.MAX_SPRAY_CHUNKS + 1, 0, blobOf(10)), ALICE);
  assert.strictEqual(alice.sprayIn, null);
});

test("an index outside the claimed total is refused", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  server.onDatagram(h.sprayChunk("Alice", CRC, 1000, 3, 7, blobOf(10)), ALICE);
  assert.strictEqual(alice.sprayIn, null);
});

test("an absurd uncompressed size is refused", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  server.onDatagram(h.sprayChunk("Alice", CRC, limits.MAX_SPRAY_RAW_BYTES + 1, 1, 0, blobOf(10)), ALICE);
  assert.strictEqual(alice.sprayIn, null);
});

test("changing picture mid-upload restarts it rather than mixing the two", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  server.onDatagram(h.sprayChunk("Alice", CRC, 800, 2, 0, blobOf(400, 1)), ALICE);
  server.onDatagram(h.sprayChunk("Alice", CRC + 1, 800, 2, 0, blobOf(400, 2)), ALICE);

  assert.strictEqual(alice.sprayIn.crc, CRC + 1);
  assert.strictEqual(alice.sprayIn.have, 1);
});

// ---------------------------------------------------------------------------
// Stamps
// ---------------------------------------------------------------------------

test("a stamp is relayed to everyone but the sender", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  const { blob, crc } = h.sprayBlob(8, 6);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);

  const mark = socket.sent.length;
  server.onDatagram(h.sprayStamp("Alice", crc, 1, 2, 3), ALICE);

  const toBob = h.sentTo(socket, BOB.address, BOB.port, mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPRAY_STAMP);
  const toAlice = h.sentTo(socket, ALICE.address, ALICE.port, mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPRAY_STAMP);

  assert.strictEqual(toBob.length, 1);
  assert.strictEqual(toAlice.length, 0);

  const m = new Message(toBob[0].buffer.subarray(1), {});
  assert.strictEqual(m.readString(), "Alice");
  assert.strictEqual(m.readInt32(), crc);
  assert.strictEqual(m.readFloat(), 1);
});

test("a stamp for a picture nobody has is not relayed", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  const mark = socket.sent.length;
  server.onDatagram(h.sprayStamp("Alice", CRC, 1, 2, 3), ALICE);

  assert.strictEqual(h.typesSent(socket, mark).filter((t) => t === packets.TYPE.SPRAY_STAMP).length, 0);
});

// ---------------------------------------------------------------------------
// Moderation
// ---------------------------------------------------------------------------

test("a spray-banned player cannot publish", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);
  server.access.ban(KIND.SPRAY, "Alice", {});

  const { blob, crc } = h.sprayBlob(8, 7);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  assert.strictEqual(alice.spray, null);
});

test("a spray ban does not remove the player from the server", () => {
  const { server } = h.makeServer();
  join(server, "Alice", ALICE);
  server.access.ban(KIND.SPRAY, "Alice", {});

  assert.strictEqual(server.access.banFor("Alice", ALICE.address), null, "a spray ban must not read as a server ban");
  assert.ok(server.users.get("Alice"), "the player stays");
});

test("banning takes the published picture away and cancels what is in flight", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);
  const bob = join(server, "Bob", BOB);

  const { blob, crc } = h.sprayBlob(64, 8, true);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  assert.ok(alice.spray);
  assert.ok(bob.sprayFeeds.has("Alice"));

  const record = server.access.ban(KIND.SPRAY, "Alice", {}).record;
  server.revokeSpray(record.key, "Alice");

  assert.strictEqual(alice.spray, null);
  assert.strictEqual(bob.sprayFeeds.has("Alice"), false);
});

test("a spray ban survives a rename by case, like every other ban", () => {
  const { server } = h.makeServer();
  server.access.ban(KIND.SPRAY, "Alice", {});
  assert.strictEqual(server.access.maySpray("ALICE"), false);
  assert.strictEqual(server.access.maySpray("alice"), false);
  assert.strictEqual(server.access.maySpray("Bob"), true);
});
