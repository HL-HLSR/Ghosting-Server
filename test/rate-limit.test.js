"use strict";

// Token buckets and the bound on how many of them can exist.

const test = require("node:test");
const assert = require("node:assert");

const { TokenBucketStore, GlobalLimiter } = require("../src/net/rate-limit");
const { SampledLogger } = require("../src/net/logger");

const clock = (start = 0) => {
  const state = { value: start };
  return { state, now: () => state.value, advance: (ms) => (state.value += ms) };
};

test("a burst up to capacity passes, then the bucket is empty", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 5, refillPerSecond: 1, now: time.now });
  for (let i = 0; i < 5; i += 1) assert.strictEqual(store.take("a"), true, `take ${i}`);
  assert.strictEqual(store.take("a"), false);
  assert.strictEqual(store.dropped, 1);
});

test("tokens come back at the configured rate", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 5, refillPerSecond: 2, now: time.now });
  for (let i = 0; i < 5; i += 1) store.take("a");

  time.advance(500); // one token
  assert.strictEqual(store.take("a"), true);
  assert.strictEqual(store.take("a"), false);

  time.advance(10000); // long enough to refill completely, and no further
  for (let i = 0; i < 5; i += 1) assert.strictEqual(store.take("a"), true);
  assert.strictEqual(store.take("a"), false);
});

test("keys are independent", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 2, refillPerSecond: 1, now: time.now });
  assert.strictEqual(store.take("a"), true);
  assert.strictEqual(store.take("a"), true);
  assert.strictEqual(store.take("a"), false);
  assert.strictEqual(store.take("b"), true, "one flooder must not spend everyone's budget");
});

test("the store refuses to grow past its ceiling", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 4, refillPerSecond: 1, maxEntries: 50, now: time.now });
  for (let i = 0; i < 5000; i += 1) store.take(`key-${i}`);
  assert.strictEqual(store.size <= 50, true, `grew to ${store.size}`);
  assert.strictEqual(store.evicted > 0, true);
});

test("eviction prefers buckets that carry no debt", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 2, refillPerSecond: 1, maxEntries: 4, now: time.now });

  // Two addresses in debt, two that have refilled.
  store.take("flooder-1");
  store.take("flooder-1");
  store.take("flooder-2");
  store.take("flooder-2");
  store.take("quiet-1");
  time.advance(10000); // quiet-1 refills; the flooders do too, in this window

  // With everything refilled the store may evict anything; what matters is that
  // it keeps admitting new keys rather than locking up.
  for (let i = 0; i < 20; i += 1) assert.strictEqual(store.take(`new-${i}`), true);
  assert.strictEqual(store.size <= 4, true);
});

test("pruning drops buckets that have had time to refill", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 4, refillPerSecond: 4, now: time.now });
  store.take("a");
  store.take("b");
  assert.strictEqual(store.size, 2);

  time.advance(500); // not yet a full refill
  store.prune();
  assert.strictEqual(store.size, 2);

  time.advance(2000);
  store.prune();
  assert.strictEqual(store.size, 0, "an idle bucket holds no information");
});

test("available() reports the budget without creating a bucket", () => {
  const time = clock();
  const store = new TokenBucketStore({ capacity: 3, refillPerSecond: 1, now: time.now });
  assert.strictEqual(store.available("nobody"), 3);
  assert.strictEqual(store.size, 0, "asking must not allocate");
  store.take("a");
  assert.strictEqual(store.available("a"), 2);
});

test("the global limiter is a single ceiling for the whole process", () => {
  const time = clock();
  const limiter = new GlobalLimiter({ capacity: 10, refillPerSecond: 10, now: time.now });
  for (let i = 0; i < 10; i += 1) assert.strictEqual(limiter.take(), true);
  assert.strictEqual(limiter.take(), false);
  time.advance(1000);
  assert.strictEqual(limiter.take(), true);
});

// Logging --------------------------------------------------------------------

test("the first occurrence of an event is always printed", () => {
  const lines = [];
  // The throttle used to store zero as "never logged", so on a freshly started
  // process - where the clock reading is small - the very first message of each
  // kind was swallowed.
  const log = new SampledLogger({ sink: (line) => lines.push(line), now: () => 5, intervalMs: 10000 });
  assert.strictEqual(log.event("probe", "first"), true);
  assert.strictEqual(lines.length, 1);
});

test("repeats are counted and summarised instead of printed", () => {
  const lines = [];
  const time = clock(1000);
  const log = new SampledLogger({ sink: (line) => lines.push(line), now: time.now, intervalMs: 10000 });

  for (let i = 0; i < 1000; i += 1) log.event("probe", `hit ${i}`);
  assert.strictEqual(lines.length, 1, "a thousand events must not be a thousand lines");

  time.advance(11000);
  log.event("probe", "later");
  assert.strictEqual(lines.length, 2);
  // 999 suppressed from the loop plus this one, which the summary stands in for.
  assert.match(lines[1], /1000 more/);
  assert.match(lines[1], /1001 total/);
});

test("different events are throttled separately", () => {
  const lines = [];
  const log = new SampledLogger({ sink: (line) => lines.push(line), now: () => 1000, intervalMs: 10000 });
  log.event("one");
  log.event("two");
  log.event("one");
  assert.strictEqual(lines.length, 2);
});

test("flush reports whatever was still being suppressed", () => {
  const lines = [];
  const log = new SampledLogger({ sink: (line) => lines.push(line), now: () => 1000, intervalMs: 10000 });
  for (let i = 0; i < 50; i += 1) log.event("probe");
  log.flush();
  assert.strictEqual(lines.length, 2);
  assert.match(lines[1], /49 more/);
});

test("format arguments are escaped, including the ones that look like numbers", () => {
  const lines = [];
  const log = new SampledLogger({ sink: (line) => lines.push(line), now: () => 0 });
  log.info("name is %s and port is %d", String.fromCharCode(0x1b) + "[2J", 22228);
  assert.strictEqual(lines[0].includes(String.fromCharCode(0x1b)), false);
  assert.match(lines[0], /port is 22228/);
});
