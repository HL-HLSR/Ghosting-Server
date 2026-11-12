"use strict";

// Monotonic time in milliseconds.
//
// Everything in the server that measures an interval - rate limit refills,
// idle timeouts, chat cooldowns, race deadlines - used Date.now(), which is the
// wall clock and can move. An NTP correction backwards freezes every throttle
// and stops the stale sweep; a correction forwards times every player out at
// once. Neither is hypothetical on a rented host that has just booted.
//
// performance.now() is monotonic (it comes from uv_hrtime), and adding
// timeOrigin puts it on roughly the same scale as Date.now(), so log timestamps
// still look like clock time and stored values stay comparable.

const { performance } = require("perf_hooks");

const ORIGIN = performance.timeOrigin;

const monotonicNow = () => Math.round(ORIGIN + performance.now());

module.exports = { monotonicNow, ORIGIN };
