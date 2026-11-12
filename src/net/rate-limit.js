"use strict";

// Token buckets with a hard ceiling on how many of them can exist.
//
// The unbounded map was the memory bug in the old server: `connectAttempts`
// gained an entry per address:port and was only swept every five seconds, so a
// flood with rotating spoofed source ports could add hundreds of thousands of
// entries between sweeps. Here the store refuses to grow past `maxEntries` and
// evicts to make room.
//
// A bucket holds `capacity` tokens and refills at `refillPerSecond`. Taking a
// token costs one packet; an empty bucket means "drop this packet". Bursts up
// to `capacity` pass untouched, which is what makes this usable for a game
// protocol that is bursty by nature (a connect is immediately followed by a
// roster exchange and then 25 updates a second).

class TokenBucketStore {
  constructor(options) {
    const opts = options || {};
    this.capacity = opts.capacity;
    this.refillPerSecond = opts.refillPerSecond;
    this.maxEntries = opts.maxEntries || 10000;
    this.now = opts.now || (() => Date.now());
    this.buckets = new Map();
    // Counters the operator sees in `status`; they are the only trace a dropped
    // packet leaves, because logging one line per drop is the flood.
    this.dropped = 0;
    this.evicted = 0;
  }

  get size() {
    return this.buckets.size;
  }

  // Time to refill an empty bucket completely. A bucket idle for longer than
  // this is indistinguishable from a fresh one, so it can be discarded without
  // giving anyone a free pass.
  get fullRefillMs() {
    return Math.ceil((this.capacity / this.refillPerSecond) * 1000);
  }

  // Evict when full. Entries that have already refilled to capacity carry no
  // debt, so dropping them costs nothing; the scan is bounded so this stays
  // O(1) amortised no matter how large the store is.
  makeRoom(at) {
    if (this.buckets.size < this.maxEntries) return;

    // Evicting a bucket forgets its debt, so eviction is itself an attack: fill
    // the store with junk keys until your own throttled bucket is dropped, then
    // come back with a full allowance. The scan therefore looks for buckets
    // that owe nothing, and only falls back to the least indebted one it saw.
    let removed = 0;
    let scanned = 0;
    let fallbackKey = null;
    let fallbackTokens = -1;

    for (const [key, bucket] of this.buckets) {
      if (scanned++ >= 256) break;
      const tokens = this.peek(bucket, at);
      if (tokens >= this.capacity) {
        this.buckets.delete(key);
        removed += 1;
        if (removed >= 8) break;
        continue;
      }
      if (tokens > fallbackTokens) {
        fallbackTokens = tokens;
        fallbackKey = key;
      }
    }

    // Everything in the scan was still in debt. Something has to go, or the
    // store stops admitting new addresses and a flood locks legitimate players
    // out of the limiter entirely - so the one that owes least is dropped.
    if (removed === 0 && fallbackKey !== null) {
      this.buckets.delete(fallbackKey);
      removed = 1;
    }
    this.evicted += removed;
  }

  peek(bucket, at) {
    const elapsed = Math.max(0, at - bucket.last);
    return Math.min(this.capacity, bucket.tokens + (elapsed / 1000) * this.refillPerSecond);
  }

  // true = the packet is within budget, false = drop it.
  take(key, cost = 1) {
    const at = this.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      this.makeRoom(at);
      bucket = { tokens: this.capacity, last: at };
      this.buckets.set(key, bucket);
    }

    bucket.tokens = this.peek(bucket, at);
    bucket.last = at;

    if (bucket.tokens < cost) {
      this.dropped += 1;
      return false;
    }
    bucket.tokens -= cost;
    return true;
  }

  // Charge without asking. Used where the packet has already been handled but
  // should still count against the budget.
  charge(key, cost = 1) {
    this.take(key, 0);
    const bucket = this.buckets.get(key);
    if (bucket) bucket.tokens = Math.max(0, bucket.tokens - cost);
  }

  // Gives back tokens taken for something that was then not done (review 2,
  // m6: a spray refused after its publish budgets were charged). Never above
  // the capacity, and a no-op for a bucket that no longer exists.
  refund(key, amount = 1) {
    const bucket = this.buckets.get(key);
    if (!bucket) return;
    const at = this.now();
    bucket.tokens = Math.min(this.capacity, this.peek(bucket, at) + amount);
    bucket.last = at;
  }

  // Tokens currently available, without creating a bucket. Used for the cheap
  // "is this address already in the penalty box" check that runs before the
  // parser: a fresh address has never been seen, so it is always over budget.
  available(key) {
    const bucket = this.buckets.get(key);
    if (!bucket) return this.capacity;
    return this.peek(bucket, this.now());
  }

  forget(key) {
    this.buckets.delete(key);
  }

  // Called from the sweep. Buckets that have had time to refill completely hold
  // no information, so dropping them keeps the store small during quiet periods
  // instead of only when it hits the ceiling.
  prune() {
    const at = this.now();
    const idleMs = this.fullRefillMs;
    for (const [key, bucket] of this.buckets) {
      if (at - bucket.last >= idleMs) this.buckets.delete(key);
    }
  }

  stats() {
    return { size: this.buckets.size, dropped: this.dropped, evicted: this.evicted };
  }
}

// One bucket, no keys: the whole-process ceiling. Anything over it is dropped
// before the parser sees it, so a flood costs a counter increment.
//
// The bottom `reserve` tokens are not available to everyone. A plain ceiling is
// first-come-first-served, and under a flood that is the same as
// most-packets-wins: the sixteen players sending 25 datagrams a second lose to
// the attacker sending two hundred thousand, so the ceiling that exists to keep
// the process alive ends up disconnecting the people it is protecting.
// Untrusted traffic can therefore only draw the bucket down to `reserve`;
// traffic from a session that has proved its address may spend the rest.
class GlobalLimiter {
  constructor(options) {
    const opts = options || {};
    this.capacity = opts.capacity;
    this.refillPerSecond = opts.refillPerSecond;
    this.reserve = Math.min(opts.reserve || 0, this.capacity);
    this.now = opts.now || (() => Date.now());
    this.tokens = this.capacity;
    this.last = this.now();
    this.dropped = 0;
    this.droppedUntrusted = 0;
  }

  // `trusted` is the caller's verdict, not the limiter's: see server.js, where
  // it means "a session on this exact address:port has sent a packet that a
  // forged source address could not have sent".
  take(cost = 1, trusted = true) {
    const at = this.now();
    const elapsed = Math.max(0, at - this.last);
    this.tokens = Math.min(this.capacity, this.tokens + (elapsed / 1000) * this.refillPerSecond);
    this.last = at;
    const floor = trusted ? 0 : this.reserve;
    if (this.tokens - cost < floor) {
      this.dropped += 1;
      if (!trusted) this.droppedUntrusted += 1;
      return false;
    }
    this.tokens -= cost;
    return true;
  }

  stats() {
    return { dropped: this.dropped, droppedUntrusted: this.droppedUntrusted, reserve: this.reserve };
  }
}

module.exports = { TokenBucketStore, GlobalLimiter };
