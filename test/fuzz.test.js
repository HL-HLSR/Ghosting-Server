"use strict";

// Fifty thousand hostile datagrams, from a fixed seed.
//
// What is being checked is narrow and worth stating: no datagram may throw out
// of the handler, no datagram may leave a structure growing, and the server has
// to still work afterwards. Passing this does not mean the protocol is safe; it
// means the parser survives everything this corpus knows how to build.

const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const h = require("./helpers/harness");
const corpus = require("./helpers/fuzz-corpus");
const packets = require("../src/wire/packets");

const ITERATIONS = 50000;
const SEED = 0x5eed1234;

test(`${ITERATIONS} deterministic datagrams do not throw`, () => {
  const { server, socket, clock } = h.makeServer({
    MAX_TRACKED_ADDRESSES: "2000",
    MAX_TRACKED_SESSIONS: "4000",
    GLOBAL_PACKETS_PER_SECOND: "5000000",
  });

  const random = corpus.makeRandom(SEED);
  const failures = [];

  for (let i = 0; i < ITERATIONS; i += 1) {
    const buffer = corpus.generate(random);
    const rinfo = corpus.address(random, i);
    try {
      server.onDatagram(buffer, rinfo);
    } catch (error) {
      failures.push({ i, length: buffer.length, message: error.message });
      if (failures.length > 5) break;
    }
    // Time moves so rate limits refill and the sweep runs, which is what a real
    // flood looks like. A frozen clock would leave every bucket empty after the
    // first few hundred packets and stop exercising the parser.
    if (i % 25 === 0) clock.advance(10);
  }

  assert.deepStrictEqual(failures, [], `handler threw on ${failures.length} datagrams`);

  // Nothing may have grown without a bound.
  assert.strictEqual(server.byAddress.size <= 2000, true, `address store: ${server.byAddress.size}`);
  assert.strictEqual(server.bySession.size <= 4000, true, `session store: ${server.bySession.size}`);
  assert.strictEqual(server.connects.size <= 2000, true);
  assert.strictEqual(server.malformed.size <= 2000, true);
  assert.strictEqual(server.penalty.size <= 2000, true);
  assert.strictEqual(server.users.count() <= server.config.maxPlayers, true);
  assert.strictEqual(server.pendingDrops.size <= server.config.maxPlayers, true);

  // And the host still serves a real client.
  clock.advance(120000);
  const fresh = h.from("192.0.2.50", 45000);
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Survivor"), fresh);
  server.onDatagram(h.update("Survivor"), fresh);

  assert.strictEqual(server.users.exists("Survivor"), true, "the server stopped accepting connects");
  const reply = h.sentTo(socket, fresh.address, fresh.port, mark)[0];
  assert.strictEqual(reply.buffer.readUInt8(0), packets.TYPE.CONNECT_ACCEPTED);
});

test("the same seed produces the same corpus", () => {
  // Without this, a crash found in CI could not be reproduced locally.
  const first = corpus.makeRandom(SEED);
  const second = corpus.makeRandom(SEED);
  for (let i = 0; i < 200; i += 1) {
    assert.deepStrictEqual(corpus.generate(first), corpus.generate(second));
  }
});

test("a flood leaves nothing behind once it stops", () => {
  const { server, clock } = h.makeServer({ MAX_TRACKED_ADDRESSES: "5000", MAX_TRACKED_SESSIONS: "5000" });
  const random = corpus.makeRandom(0xabcdef);

  for (let i = 0; i < 5000; i += 1) {
    server.onDatagram(corpus.generate(random), corpus.address(random, i));
    if (i % 50 === 0) clock.advance(10);
  }
  assert.strictEqual(server.byAddress.size > 0, true);

  // Ten minutes of quiet. Every bucket has had time to refill, so none of them
  // holds any information worth the memory.
  clock.advance(600000);
  assert.strictEqual(server.byAddress.size, 0, `${server.byAddress.size} address buckets survived`);
  assert.strictEqual(server.bySession.size, 0);
  assert.strictEqual(server.connects.size, 0);
  assert.strictEqual(server.malformed.size, 0);
  assert.strictEqual(server.penalty.size, 0);
});

test("heap use does not track the number of hostile packets", () => {
  // Measured in a child process under --expose-gc. Reading heapUsed inside the
  // test runner would mostly measure the runner: without a forced collection
  // the number is whatever the collector has not got round to, which is noise
  // an order of magnitude larger than the thing being tested.
  const probe = path.join(__dirname, "tools", "memory-probe.js");
  const output = execFileSync(process.execPath, ["--expose-gc", probe, "20000"], { encoding: "utf8" });
  const result = JSON.parse(output.trim().split("\n").pop());

  // Three identical phases of twenty thousand hostile packets. If anything grew
  // per packet, the second and third steps would be as large as the first.
  assert.strictEqual(
    result.growth2 < 0.25,
    true,
    `heap grew ${Math.round(result.growth2 * 100)}% over the second phase (${JSON.stringify(result)})`
  );
  assert.strictEqual(
    result.growth3 < 0.25,
    true,
    `heap grew ${Math.round(result.growth3 * 100)}% over the third phase (${JSON.stringify(result)})`
  );
  assert.strictEqual(result.trackedAddresses <= 1000, true);
  assert.strictEqual(result.trackedSessions <= 1000, true);
});
