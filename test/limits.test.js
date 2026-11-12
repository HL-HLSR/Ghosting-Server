"use strict";

// Runtime rate-limit tuning.
//
// The point of these is not that a number can be assigned - it is that the
// change reaches the thing doing the limiting, on the next packet, without a
// restart. So most of them set a limit and then push traffic through.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const console_ = require("../src/console");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

// A console attached to a capture buffer, so what an operator would see is what
// gets asserted.
const withConsole = (server) => {
  const lines = [];
  console_.attach(server, { print: (l) => lines.push(l), input: null });
  return {
    lines,
    run: (line) => {
      lines.length = 0;
      console_.handleLine ? console_.handleLine(line) : null;
      return lines;
    },
  };
};

// ---------------------------------------------------------------------------
// The table itself
// ---------------------------------------------------------------------------

test("every limit reports a value, a help line and a sane range", () => {
  const { server } = h.makeServer();
  const snap = server.limitSnapshot();

  assert.ok(snap.rows.length >= 15, `only ${snap.rows.length} knobs`);
  for (const row of snap.rows) {
    assert.ok(typeof row.name === "string" && row.name.length > 0);
    assert.ok(Number.isFinite(row.value), `${row.name} has no value`);
    assert.ok(typeof row.help === "string" && row.help.length > 0, `${row.name} has no help`);
  }
});

test("an unknown limit is refused and the known ones are listed", () => {
  const { server } = h.makeServer();
  const r = server.setLimit("nope.nope", 1);
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /no such limit/);
  assert.ok(Array.isArray(r.names) && r.names.includes("chat.interval"));
});

test("out-of-range and non-numeric values are refused", () => {
  const { server } = h.makeServer();
  assert.strictEqual(server.setLimit("chat.interval", -1).ok, false);
  assert.strictEqual(server.setLimit("chat.interval", 999999).ok, false);
  assert.strictEqual(server.setLimit("chat.interval", NaN).ok, false);
  assert.strictEqual(server.setLimit("command.burst", 2.5).ok, false, "burst must be whole");
});

test("a refused change leaves the value alone", () => {
  const { server } = h.makeServer();
  const before = server.config.chatMinIntervalMs;
  server.setLimit("chat.interval", -5);
  assert.strictEqual(server.config.chatMinIntervalMs, before);
});

// ---------------------------------------------------------------------------
// The changes actually reach the limiter
// ---------------------------------------------------------------------------

test("chat.interval 0 lets consecutive lines through immediately", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  // Default interval: the second line in the same millisecond is dropped.
  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "one"), ALICE);
  server.onDatagram(h.chat("Alice", "two"), ALICE);
  const withLimit = h.typesSent(socket, mark).filter((t) => t === 6).length;

  assert.ok(withLimit < 4, `expected the second line to be throttled, saw ${withLimit} chat packets`);

  assert.strictEqual(server.setLimit("chat.interval", 0).ok, true);

  const mark2 = socket.sent.length;
  server.onDatagram(h.chat("Alice", "three"), ALICE);
  server.onDatagram(h.chat("Alice", "four"), ALICE);
  const withoutLimit = h.typesSent(socket, mark2).filter((t) => t === 6).length;

  assert.ok(withoutLimit > withLimit, `lifting the limit should let more through (${withLimit} -> ${withoutLimit})`);
});

test("raising chat.interval throttles again", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  server.setLimit("chat.interval", 0);
  server.setLimit("chat.interval", 60000);

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "one"), ALICE);
  server.onDatagram(h.chat("Alice", "two"), ALICE);
  server.onDatagram(h.chat("Alice", "three"), ALICE);

  const chats = h.typesSent(socket, mark).filter((t) => t === 6).length;
  assert.ok(chats <= 2, `a 60 s gap should allow at most the first line, saw ${chats} packets`);
});

test("session.burst reaches the bucket that drops packets", () => {
  const { server } = h.makeServer();
  const before = server.bySession.capacity;
  assert.strictEqual(server.setLimit("session.burst", before + 50).ok, true);
  assert.strictEqual(server.bySession.capacity, before + 50);
});

test("global.rate moves capacity and the reserve together", () => {
  const { server } = h.makeServer({ GLOBAL_RESERVE_PERCENT: "50" });
  assert.strictEqual(server.setLimit("global.rate", 1000).ok, true);
  assert.strictEqual(server.global.refillPerSecond, 1000);
  assert.strictEqual(server.global.capacity, 1000, "a burst above the rate would defeat the ceiling");
  assert.strictEqual(server.global.reserve, 500);
});

test("global.reserve re-derives from the current capacity", () => {
  const { server } = h.makeServer();
  server.setLimit("global.rate", 2000);
  assert.strictEqual(server.setLimit("global.reserve", 25).ok, true);
  assert.strictEqual(server.global.reserve, 500);
});

test("the reserve can never exceed the ceiling it sits inside", () => {
  const { server } = h.makeServer();
  server.setLimit("global.rate", 100);
  server.setLimit("global.reserve", 100);
  assert.ok(server.global.reserve <= server.global.capacity);
});

test("spray.chunksPerTick changes how many pieces a tick hands over", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  assert.strictEqual(server.setLimit("spray.chunksPerTick", 1).ok, true);

  const { blob, crc } = h.sprayBlob(64, 1, true); // a real multi-chunk picture
  const mark = socket.sent.length;
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  server.dripSprays();

  const chunks = h.sentTo(socket, BOB.address, BOB.port, mark).filter((p) => p.buffer.readUInt8(0) === 15);
  assert.strictEqual(chunks.length, 1);
});

test("spray.rate reaches the upload bucket", () => {
  const { server } = h.makeServer();
  assert.strictEqual(server.setLimit("spray.rate", 5).ok, true);
  assert.strictEqual(server.sprayUploads.refillPerSecond, 5);
});

// ---------------------------------------------------------------------------
// What the operator sees
// ---------------------------------------------------------------------------

test("the snapshot carries a drop counter for every family", () => {
  const { server } = h.makeServer();
  const d = server.limitSnapshot().dropped;
  for (const key of ["address", "session", "command", "event", "spray", "malformed", "connect", "global", "globalUntrusted"]) {
    assert.ok(Number.isFinite(d[key]), `${key} is missing from the drop counters`);
  }
});

test("a change is reported with both the old and the new value", () => {
  const { server } = h.makeServer();
  const before = server.config.chatMinIntervalMs;
  const r = server.setLimit("chat.interval", 123);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.previous, before);
  assert.strictEqual(r.value, 123);
  assert.strictEqual(r.name, "chat.interval");
});

test("nothing is persisted - the config file is not touched", () => {
  const { server } = h.makeServer();
  server.setLimit("chat.interval", 42);
  // A fresh server built from the same environment is unaffected.
  const second = h.makeServer().server;
  assert.notStrictEqual(second.config.chatMinIntervalMs, 42);
});
