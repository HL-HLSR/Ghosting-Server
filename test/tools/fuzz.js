#!/usr/bin/env node
"use strict";

// Standalone fuzzer, for runs longer than the one in the test suite.
//
//   node test/tools/fuzz.js [iterations] [seed]
//
// The suite runs 50000 datagrams from a fixed seed on every `npm test`. This is
// for leaving a few million running while you do something else. A failure
// prints the seed and the iteration, which is enough to reproduce it exactly.

const path = require("path");
const h = require(path.join(__dirname, "..", "helpers", "harness"));
const corpus = require(path.join(__dirname, "..", "helpers", "fuzz-corpus"));

const ITERATIONS = Number.parseInt(process.argv[2], 10) || 1000000;
const SEED = Number.parseInt(process.argv[3], 10) || Math.floor(Math.random() * 0xffffffff);

const { server, clock } = h.makeServer({
  MAX_TRACKED_ADDRESSES: "5000",
  MAX_TRACKED_SESSIONS: "5000",
  GLOBAL_PACKETS_PER_SECOND: "5000000",
});

// Throw log lines away: the harness logger keeps them, which would be measured
// as if it were the server's own memory.
server.log = { info() {}, warn() {}, error() {}, event: () => true, flush() {}, counts: () => ({}) };
server.race.deps.log = server.log;

const random = corpus.makeRandom(SEED);
const started = Date.now();
let thrown = 0;

console.log(`fuzzing ${ITERATIONS} datagrams, seed ${SEED}`);

for (let i = 0; i < ITERATIONS; i += 1) {
  const buffer = corpus.generate(random);
  const rinfo = corpus.address(random, i);
  try {
    server.onDatagram(buffer, rinfo);
  } catch (error) {
    thrown += 1;
    console.error(`THREW at iteration ${i} (seed ${SEED}): ${error.stack}`);
    console.error(`datagram: ${buffer.toString("hex").slice(0, 200)}`);
    if (thrown > 10) break;
  }
  if (i % 25 === 0) clock.advance(10);

  if (i > 0 && i % 250000 === 0) {
    const heap = Math.round(process.memoryUsage().heapUsed / 1048576);
    console.log(
      `${i} datagrams, heap ${heap} MB, ` +
        `addresses ${server.byAddress.size}, sessions ${server.bySession.size}, ` +
        `penalty ${server.penalty.size}, players ${server.users.count()}`
    );
  }
}

const seconds = (Date.now() - started) / 1000;
console.log(
  `done: ${ITERATIONS} datagrams in ${seconds.toFixed(1)}s ` +
    `(${Math.round(ITERATIONS / seconds)}/s), ${thrown} threw`
);
console.log(
  `final: heap ${Math.round(process.memoryUsage().heapUsed / 1048576)} MB, ` +
    `addresses ${server.byAddress.size}, sessions ${server.bySession.size}, players ${server.users.count()}`
);
process.exit(thrown ? 1 : 0);
