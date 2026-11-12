"use strict";

// Seeing a spray move.
//
// The log has always said a picture arrived and never said it left again, so
// "did my friend actually get it" could not be answered without adding print
// statements to a running server. These cover the report that answers it: what
// is published, what is half-uploaded, and what is still queued for whom.

const test = require("node:test");
const assert = require("node:assert");

const { Readable } = require("node:stream");

const h = require("./helpers/harness");
const console_ = require("../src/console");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);
const CRC = 0x1234abcd | 0;

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

const blobOf = (n, fill = 7) => Buffer.alloc(n, fill);

// An empty stream, not stdin: attach() falls back to process.stdin, which never
// ends, and a test that opens it hangs the runner instead of failing.
const runConsole = (server, line) => {
  const lines = [];
  const c = console_.attach(server, { input: Readable.from([]), print: (l) => lines.push(l) });
  c.handle(line);
  c.rl.close();
  return lines;
};

test("an empty server says so rather than printing a bare table", () => {
  const { server } = h.makeServer();
  const lines = runConsole(server, "sprays");
  assert.match(lines.join("\n"), /Nobody is connected/);
});

test("the report shows a published picture, its size and its piece count", () => {
  const { server } = h.makeServer();
  join(server, "Alice", ALICE);

  const { blob, crc } = h.sprayBlob(64, 1, true);
  const total = h.uploadSpray(server, ALICE, "Alice", crc, blob);

  const snap = server.spraySnapshot();
  const alice = snap.rows.find((r) => r.name === "Alice");
  assert.ok(alice.published, "Alice should be listed as published");
  assert.strictEqual(alice.published.bytes, blob.length);
  assert.strictEqual(alice.published.total, total);
  assert.strictEqual(alice.incoming, null);
});

test("a half-arrived upload is reported as receiving, not as published", () => {
  const { server } = h.makeServer();
  join(server, "Alice", ALICE);

  const blob = blobOf(1000);
  server.onDatagram(h.sprayChunk("Alice", CRC, blob.length, 3, 0, blob.subarray(0, 400)), ALICE);

  const alice = server.spraySnapshot().rows.find((r) => r.name === "Alice");
  assert.strictEqual(alice.published, null, "an incomplete picture is not published");
  assert.ok(alice.incoming, "the partial upload should show up");
  assert.strictEqual(alice.incoming.have, 1);
  assert.strictEqual(alice.incoming.total, 3);
});

test("the queue to another player appears, names its sender, and drains", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  // More pieces than one tick can deliver, so the drip below is partial and the
  // queue is observably shrinking rather than vanishing in one step.
  const { blob, crc } = h.sprayBlob(64, 1, true);
  const total = h.uploadSpray(server, ALICE, "Alice", crc, blob);
  assert.ok(total > server.config.sprayChunksPerTick);

  let bob = server.spraySnapshot().rows.find((r) => r.name === "Bob");
  assert.strictEqual(bob.pending, total, "every piece should be queued for Bob");
  assert.deepStrictEqual(bob.pendingFrom, [{ name: "Alice", count: total }]);
  // Bob has received nothing of his own - the queue is somebody else's picture.
  assert.strictEqual(bob.published, null);

  // Bob is a live, active client: his accepted position updates earn the
  // outbound credit the metered drip spends (H2). Bank a tick's worth (4 x 16 ms
  // stays inside one 250 ms tick), then drip once: the queue shrinking across
  // ticks is the evidence an operator is looking for.
  for (let i = 0; i < 4; i++) {
    clock.advance(16);
    server.onDatagram(h.update("Bob"), BOB);
  }
  server.dripSprays();
  bob = server.spraySnapshot().rows.find((r) => r.name === "Bob");
  assert.strictEqual(bob.pending, total - server.config.sprayChunksPerTick);

  for (let i = 0; i < total; i++) {
    clock.advance(20);
    server.onDatagram(h.update("Bob"), BOB);
    server.dripSprays();
  }
  bob = server.spraySnapshot().rows.find((r) => r.name === "Bob");
  assert.strictEqual(bob.pending, 0, "the queue should empty");
});

test("a spray-banned player is reported as banned, not as having no picture", () => {
  const { server } = h.makeServer();
  join(server, "Alice", ALICE);

  const { KIND } = require("../src/game/access");
  server.access.ban(KIND.SPRAY, "Alice", { reason: "test" });

  const alice = server.spraySnapshot().rows.find((r) => r.name === "Alice");
  assert.strictEqual(alice.banned, true);
  assert.strictEqual(alice.published, null);
});

test("the printed table names both players and their queue", () => {
  const { server } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  const { blob, crc } = h.sprayBlob(64, 1, true);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);

  const text = runConsole(server, "sprays").join("\n");
  assert.match(text, /Alice/);
  assert.match(text, /Bob/);
  assert.match(text, /from Alice/, "the queue should say whose picture it is");
});
