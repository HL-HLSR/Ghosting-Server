"use strict";

// Sampled logging.
//
// Every message about a packet is a message an attacker can ask for. The old
// server printed one line per unknown opcode and one per malformed datagram,
// with no limit: a host under a 50k packets per second probe would write
// millions of lines a minute into whatever file the supervisor redirects stdout
// to, which fills the disk and buries the events that matter.
//
// The rule here: the first occurrence of an event is printed immediately,
// because the operator needs to know it started. After that the event is
// counted, and a summary is printed at most once per interval with the number
// of occurrences that were suppressed.

const { sanitizeForLog } = require("../wire/text");

class SampledLogger {
  constructor(options) {
    const opts = options || {};
    this.intervalMs = opts.intervalMs || 10000;
    this.now = opts.now || (() => Date.now());
    this.sink = opts.sink || console.log.bind(console);
    this.events = new Map();
  }

  stamp() {
    return new Date(this.now()).toISOString();
  }

  // Operational lines: startup, shutdown, a player joining. Not attacker
  // triggered at any rate worth sampling, so they always print.
  info(format, ...args) {
    this.sink(`[${this.stamp()}] ${this.format(format, args)}`);
  }

  warn(format, ...args) {
    this.sink(`[${this.stamp()}] WARN ${this.format(format, args)}`);
  }

  error(format, ...args) {
    this.sink(`[${this.stamp()}] ERROR ${this.format(format, args)}`);
  }

  format(template, args) {
    let index = 0;
    return String(template).replace(/%[sd]/g, (token) => {
      const value = args[index++];
      return token === "%d" ? String(Number(value)) : sanitizeForLog(value, 200);
    });
  }

  // Attacker triggered events. `code` is a short stable identifier the summary
  // groups by; `detail` is free text and is escaped.
  event(code, detail) {
    const at = this.now();
    let state = this.events.get(code);
    if (!state) {
      state = { total: 0, suppressed: 0, lastPrinted: 0, printed: false };
      this.events.set(code, state);
    }
    state.total += 1;

    if (!state.printed) {
      state.printed = true;
      state.lastPrinted = at;
      this.sink(`[${this.stamp()}] ${code}${detail ? ": " + sanitizeForLog(detail, 120) : ""}`);
      return true;
    }

    state.suppressed += 1;
    const sinceLastPrint = at - state.lastPrinted;
    if (sinceLastPrint >= this.intervalMs) {
      const suppressed = state.suppressed;
      state.suppressed = 0;
      state.lastPrinted = at;
      this.sink(
        `[${this.stamp()}] ${code}: ${suppressed} more in ${Math.round(sinceLastPrint / 1000)}s ` +
          `(${state.total} total)${detail ? ", last: " + sanitizeForLog(detail, 120) : ""}`
      );
      return true;
    }
    return false;
  }

  // Emit whatever is still pending. Called on shutdown so a burst that ended
  // just before the interval elapsed is not lost.
  flush() {
    for (const [code, state] of this.events) {
      if (state.suppressed > 0) {
        this.sink(`[${this.stamp()}] ${code}: ${state.suppressed} more (${state.total} total)`);
        state.suppressed = 0;
      }
    }
  }

  counts() {
    const out = {};
    for (const [code, state] of this.events) out[code] = state.total;
    return out;
  }
}

module.exports = { SampledLogger };
