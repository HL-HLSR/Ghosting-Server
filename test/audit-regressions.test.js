"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { AccessList, KIND } = require("../src/game/access");
const { Message, BufferReadError } = require("../src/wire/reader");
const h = require("./helpers/harness");
const limits = require("../src/wire/limits");

test("empty spray chunks and gaps before the last chunk cannot publish a picture", () => {
  const { server, clock } = h.makeServer();
  const peer = h.from("10.0.0.1", 40001);
  server.onDatagram(h.connect("Alice"), peer);
  server.onDatagram(h.update("Alice"), peer);
  const user = server.users.get("Alice");
  // A compressible picture whose blob is exactly two chunks, so the shape checks
  // below operate on a non-final (index 0) chunk and the completion is a real,
  // validatable picture rather than junk the host now refuses (M3).
  const { blob, crc } = h.sprayBlob(64);
  assert.equal(Math.ceil(blob.length / limits.SPRAY_CHUNK_BYTES), 2);
  for (const payload of [Buffer.alloc(0), Buffer.alloc(1), Buffer.alloc(limits.SPRAY_CHUNK_BYTES - 1)]) {
    clock.advance(100);
    assert.equal(server.onDatagram(h.sprayChunk("Alice", crc, blob.length, 2, 0, payload), peer), false);
    assert.equal(user.spray, null);
    assert.equal(user.sprayIn, null);
  }
  clock.advance(100);
  assert.equal(server.onDatagram(h.sprayChunk("Alice", crc, blob.length, 2, 0, blob.subarray(0, limits.SPRAY_CHUNK_BYTES)), peer), true);
  clock.advance(100);
  assert.equal(server.onDatagram(h.sprayChunk("Alice", crc, blob.length, 2, 1, blob.subarray(limits.SPRAY_CHUNK_BYTES)), peer), true);
  assert.equal(user.spray.bytes, blob.length);
});

test("spray bans survive serialization, including their expiry", () => {
  let now = 1000;
  const first = new AccessList({ now: () => now });
  first.ban(KIND.SPRAY, "Alice", { until: 2000, reason: "abusive spray" });
  first.ban(KIND.NAME, "Bob");
  const restored = new AccessList({ now: () => now });
  restored.fromJSON(JSON.parse(JSON.stringify(first.toJSON())));
  assert.equal(restored.maySpray("ALICE"), false);
  assert.equal(restored.banFor("Alice", "127.0.0.1"), null);
  assert.ok(restored.banFor("Bob", "127.0.0.1"));
  now = 2000;
  assert.equal(restored.maySpray("Alice"), true);
});

test("missing optional fields remain compatible, partial fields fail closed", () => {
  assert.equal(new Message(Buffer.alloc(0), {}).readOptionalFloat(-1), -1);
  assert.equal(new Message(Buffer.alloc(0), {}).readOptionalString(31, ""), "");
  for (let length = 1; length < 4; length++) {
    assert.throws(() => new Message(Buffer.alloc(length), {}).readOptionalFloat(-1), BufferReadError);
    assert.throws(() => new Message(Buffer.alloc(length), {}).readOptionalString(31, ""), BufferReadError);
  }
});

test("a truncated update cannot modify the previously accepted ghost state", () => {
  const { server, clock } = h.makeServer();
  const peer = h.from("10.0.0.1", 40001);
  server.onDatagram(h.connect("Alice"), peer);
  server.onDatagram(h.update("Alice", { position: [1, 2, 3] }), peer);
  clock.advance(100);
  const packet = h.update("Alice", { position: [9, 8, 7] });
  assert.equal(server.onDatagram(packet.subarray(0, packet.length - 1), peer), false);
  assert.equal(server.users.get("Alice").position.x, 1);
});

test("taking an offline operator nickname does not grant administrative rights", () => {
  const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  const alice = h.from("10.0.0.1", 40001);
  const bob = h.from("10.0.0.2", 40002);
  for (const [name, peer] of [["Alice", alice], ["Bob", bob]]) {
    server.onDatagram(h.connect(name), peer);
    server.onDatagram(h.update(name), peer);
  }
  server.access.grantOp("Alice"); // persisted intent, without console session approval
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/kick Bob"), alice);
  assert.equal(server.users.exists("Bob"), true);

  assert.equal(server.grantOp("Alice").ok, true);
  const oldUser = server.users.get("Alice");
  server.dropUser(oldUser, "test", "left");
  const impostor = h.from("10.0.0.3", 40003);
  clock.advance(1000);
  server.onDatagram(h.connect("Alice"), impostor);
  server.onDatagram(h.update("Alice"), impostor);
  server.onDatagram(h.chat("Alice", "/kick Bob"), impostor);
  assert.equal(server.users.exists("Bob"), true);
  assert.equal(server.operatorSessions.size, 0);

  assert.equal(server.grantOp("Alice").ok, true);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/kick Bob"), impostor);
  assert.equal(server.users.exists("Bob"), false);
});
