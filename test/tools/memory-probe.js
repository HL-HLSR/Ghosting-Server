#!/usr/bin/env node
"use strict";

// Bounded-memory probe. Run under --expose-gc so the reading is retained heap
// rather than whatever the collector has not got round to yet:
//
//   node --expose-gc test/tools/memory-probe.js [packetsPerPhase]
//
// Prints one JSON line. test/fuzz.test.js spawns this and asserts on it,
// because measuring heap growth inside the test runner's own process gives a
// number dominated by the runner.

const path = require("path");
const h = require(path.join(__dirname, "..", "helpers", "harness"));
const corpus = require(path.join(__dirname, "..", "helpers", "fuzz-corpus"));

const perPhase = Number.parseInt(process.argv[2], 10) || 20000;

const { server, clock } = h.makeServer({
  MAX_TRACKED_ADDRESSES: "1000",
  MAX_TRACKED_SESSIONS: "1000",
  GLOBAL_PACKETS_PER_SECOND: "5000000",
});

// The harness logger keeps every line it is given so tests can assert on them.
// That is a per-packet allocation the server itself does not make, and it would
// be measured as if it were the server's, so this probe throws lines away like
// a real host writing to a journal.
server.log = {
  info() {},
  warn() {},
  error() {},
  event() {
    return true;
  },
  flush() {},
  counts: () => ({}),
};
server.race.deps.log = server.log;

const random = corpus.makeRandom(0x1234);

const run = (count) => {
  for (let i = 0; i < count; i += 1) {
    server.onDatagram(corpus.generate(random), corpus.address(random, i));
    if (i % 100 === 0) clock.advance(5);
  }
};

const settle = () => {
  // Several passes: one collection can leave objects that only become
  // unreachable after the first sweep.
  for (let i = 0; i < 4; i += 1) global.gc();
  return process.memoryUsage().heapUsed;
};

run(perPhase);
const first = settle();

run(perPhase);
const second = settle();

run(perPhase);
const third = settle();

process.stdout.write(
  JSON.stringify({
    perPhase,
    heapAfter1: first,
    heapAfter2: second,
    heapAfter3: third,
    growth2: (second - first) / first,
    growth3: (third - second) / second,
    trackedAddresses: server.byAddress.size,
    trackedSessions: server.bySession.size,
    penaltyBox: server.penalty.size,
    players: server.users.count(),
  }) + "\n"
);
