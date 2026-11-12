"use strict";

// The low-severity audit items: L2 (terminal/log escaping), L3 (console limit
// lookup), L4 (held-prop relay throttle), L5 (bucket pruning), L6 (IPv4-only
// address lists).

const test = require("node:test");
const assert = require("node:assert");
const { Readable } = require("node:stream");

const h = require("./helpers/harness");
const console_ = require("../src/console");
const { sanitizeForLog } = require("../src/wire/text");
const { AccessList, KIND } = require("../src/game/access");
const { Message } = require("../src/wire/reader");
const packets = require("../src/wire/packets");

const u = (s) => Buffer.from(s, "utf8").toString("latin1");

const runConsole = (server, line) => {
  const lines = [];
  const c = console_.attach(server, { input: Readable.from([]), print: (l) => lines.push(l) });
  c.handle(line);
  c.rl.close();
  return lines;
};

// Read the held model out of a relayed type-1 (info) packet.
const heldModelOf = (buffer) => {
  const m = new Message(buffer.subarray(1), {});
  m.readString(); // name
  m.readString(); // map
  for (let i = 0; i < 8; i++) m.readFloat(); // vel3, pos3, pitch, yaw
  m.readUInt8(); // paused
  m.readUInt8(); // weapon
  for (let i = 0; i < 4; i++) m.readFloat(); // hp, armor, clip, ammo
  return m.readString(); // held model
};

// L2 --------------------------------------------------------------------------

test("L2: the sprays table escapes a control byte in a nickname", () => {
  const { server } = h.makeServer();
  const r = h.from("203.0.113.5", 5);
  const name = "Ev\u009b31mil"; // U+009B is CSI, a single terminal control byte
  server.onDatagram(h.connect(name), r);
  server.onDatagram(h.update(name), r);

  const text = runConsole(server, "sprays").join("\n");
  assert.ok(!text.includes("\u009b"), "a raw CSI byte reached the terminal");
  assert.match(text, /\\x9b/, "the control byte should be shown escaped");
});

test("L2: sanitizeForLog escapes bidi and line separators", () => {
  assert.match(sanitizeForLog(u("evil‮name")), /\\u202e/);
  assert.match(sanitizeForLog(u("a b")), /\\u2028/);
  assert.match(sanitizeForLog("x\u009by"), /\\x9b/);
  // A legitimate Cyrillic value is still decoded and printed as itself (as the
  // real UTF-8 string, not a row of escapes).
  assert.strictEqual(sanitizeForLog(u("Пётр")), "Пётр");
});

// L3 --------------------------------------------------------------------------

test("L3: limits __proto__ replies 'no such limit' instead of throwing", () => {
  const { server } = h.makeServer();
  const r1 = server.setLimit("__proto__", 1);
  assert.strictEqual(r1.ok, false);
  assert.match(r1.error, /no such limit/);
  const r2 = server.setLimit("constructor", 1);
  assert.strictEqual(r2.ok, false);
  assert.match(r2.error, /no such limit/);
  // A real knob still works.
  assert.strictEqual(server.setLimit("session.rate", 42).ok, true);
});

// L4 --------------------------------------------------------------------------

test("L4: alternating held models are relayed at most ~4 times a second", () => {
  const { server, clock } = h.makeServer();
  const A = h.from("10.0.0.1", 40001);
  const B = h.from("10.0.0.2", 40002);
  server.onDatagram(h.connect("Alice"), A);
  server.onDatagram(h.update("Alice"), A);
  server.onDatagram(h.connect("Bob"), B);
  server.onDatagram(h.update("Bob"), B);

  const mark = server.socket.sent.length;
  const models = ["models/props/a.mdl", "models/props/b.mdl"];
  // 1 second of Alice alternating her held prop every 20 ms (50 changes/s).
  for (let t = 0; t < 1000; t += 20) {
    clock.advance(20);
    server.onDatagram(h.update("Alice", { heldModel: models[(t / 20) % 2], position: [t, 0, 0] }), A);
    server.onDatagram(h.update("Bob", { position: [0, t, 0] }), B); // keep Bob credited
  }

  const toBob = h.sentTo(server.socket, B.address, B.port, mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.INFO);
  let changes = 0;
  let prev = "";
  for (const p of toBob) {
    const model = heldModelOf(p.buffer);
    if (model !== prev) changes += 1;
    prev = model;
  }
  // 250 ms throttle over 1 s is 4 changes, plus the initial empty->A edge.
  assert.ok(changes <= 5, `held model changed ${changes} times in a second of 50 Hz alternation`);
  assert.ok(toBob.length > 20, "Bob should still be receiving Alice's stream");
});

// L5 --------------------------------------------------------------------------

test("L5: the spray-upload bucket is pruned once it has refilled", () => {
  const { server, clock } = h.makeServer();
  const A = h.from("10.0.0.1", 40001);
  server.onDatagram(h.connect("Alice"), A);
  server.onDatagram(h.update("Alice"), A);
  const { blob, crc } = h.sprayBlob(8, 1);
  h.uploadSpray(server, A, "Alice", crc, blob);
  assert.ok(server.sprayUploads.size > 0, "an upload should create a bucket");

  clock.advance(5000); // past the bucket's full-refill time
  server.sweep();
  assert.strictEqual(server.sprayUploads.size, 0, "an idle spray bucket should be pruned");
});

// L6 --------------------------------------------------------------------------

test("L6: address lists accept IPv4 only, normalising a mapped literal", () => {
  const list = new AccessList({ now: () => 1000 });
  // A pure IPv6 literal cannot match a udp4 client, so it is refused.
  assert.strictEqual(list.ban(KIND.ADDRESS, "2001:db8::1", {}).ok, false);
  // An IPv4-mapped literal is normalised to the address the datagram carries.
  const mapped = list.ban(KIND.ADDRESS, "::ffff:203.0.113.9", {});
  assert.strictEqual(mapped.ok, true);
  assert.strictEqual(mapped.record.value, "203.0.113.9");
  assert.ok(list.banFor("Nobody", "203.0.113.9"), "the normalised address should match");
  // A plain IPv4 literal is unchanged.
  assert.strictEqual(list.ban(KIND.ADDRESS, "198.51.100.7", {}).record.value, "198.51.100.7");
});
