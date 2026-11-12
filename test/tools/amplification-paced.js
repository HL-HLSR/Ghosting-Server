#!/usr/bin/env node
"use strict";

// Amplification, measured against both servers over the same wall clock.
//
//   node test/tools/amplification-paced.js [packetsPerCase]
//
// Why this exists alongside amplification.js and amplification-legacy.js: those
// two do not share a time model. The hardened measurement advances an injected
// clock; the legacy one has no clock to inject and sends its packets in a tight
// loop, which trips that server's 30 ms wall-clock relay gap on almost every
// packet and reports a factor far below what a real attacker gets. Comparing
// the two directly flatters the hardened server on exactly the rows where it
// looks worst, which is the opposite of useful.
//
// Here both servers are driven by real time at a real attacker's pace, so every
// wall-clock throttle in either of them applies equally, and the two columns can
// honestly be put side by side.
//
// Neither server binds a socket: both write into a capture buffer, and no
// timers run, so heartbeats and sweeps are not credited to the attacker.

const path = require("path");

const { load } = require(path.join(__dirname, "..", "..", "src", "config"));
const { GhostingServer } = require(path.join(__dirname, "..", "..", "src", "server"));
const legacy = require(path.join(__dirname, "..", "helpers", "legacy"));
const h = require(path.join(__dirname, "..", "helpers", "harness"));

const PACKETS = Number.parseInt(process.argv[2], 10) || 250;
const ATTACKER_INTERVAL_MS = 20; // 50 Hz: twice what the DLL sends
const CLIENT_INTERVAL_MS = 40; // 25 Hz: what the DLL actually sends
const PLAYERS = 16;
// One address per player, so that the per-address connect budget the forged
// connect case measures is the default one and not something this file relaxed
// in order to seed the roster.
const playerAt = (i) => ({ address: `203.0.113.${i + 1}`, port: 41000 + i, family: "IPv4", size: 0 });
const ATTACKER_INDEX = 3;
const ATTACKER = `Player${ATTACKER_INDEX}`;
const attackerAt = playerAt(ATTACKER_INDEX);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const fmt = (n) => n.toLocaleString("en-US");
const nullLog = { info() {}, warn() {}, error() {}, event: () => true, flush() {}, counts: () => ({}) };

// --- the hardened host, on the real clock, with no timers ------------------
const buildHardened = () => {
  const config = load({});
  const socket = new h.FakeSocket();
  const server = new GhostingServer({ config, socket, log: nullLog });
  server.race.deps.log = nullLog;
  for (let i = 0; i < PLAYERS; i += 1) {
    const at = playerAt(i);
    server.onDatagram(h.connect(`Player${i}`), at);
    server.onDatagram(h.update(`Player${i}`), at);
  }
  return {
    name: "hardened",
    reset: () => {
      socket.sent.length = 0;
    },
    feed: (buffer, rinfo) => server.onDatagram(buffer, rinfo || attackerAt),
    out: () => socket.sent.reduce((acc, p) => ({ packets: acc.packets + 1, bytes: acc.bytes + p.buffer.length }), {
      packets: 0,
      bytes: 0,
    }),
  };
};

// --- the pre-hardening host, executed as it stands -------------------------
const buildLegacy = () => {
  const { api, captured } = legacy.load();
  for (let i = 0; i < PLAYERS; i += 1) {
    api.userManager.registerUser(`Player${i}`, playerAt(i), 12, 255, 0, 0, 10, 20, 30);
  }
  return {
    name: "legacy",
    reset: () => {
      captured.length = 0;
    },
    feed: (buffer, rinfo) => {
      try {
        api.messageHandler.onMessage(new api.Message(buffer, rinfo || attackerAt));
      } catch (error) {
        // The legacy server catches these one level up, in its socket handler.
      }
    },
    out: () => captured.reduce((acc, p) => ({ packets: acc.packets + 1, bytes: acc.bytes + p.buffer.length }), {
      packets: 0,
      bytes: 0,
    }),
  };
};

const measure = async (host, make, intervalMs, rinfo) => {
  host.reset();
  let bytesIn = 0;
  for (let i = 0; i < PACKETS; i += 1) {
    const buffer = make(i);
    bytesIn += buffer.length;
    host.feed(buffer, rinfo);
    if (intervalMs > 0) await sleep(intervalMs);
  }
  const out = host.out();
  host.reset();
  return { packetsIn: PACKETS, bytesIn, packetsOut: out.packets, bytesOut: out.bytes, factor: out.bytes / bytesIn };
};

const CASES = [
  {
    label: "position 'l'",
    who: "attacker",
    interval: ATTACKER_INTERVAL_MS,
    make: (i) => h.update(ATTACKER, { position: [i, 0, 0] }),
  },
  {
    label: "position 'l'",
    who: "legitimate",
    interval: CLIENT_INTERVAL_MS,
    make: (i) => h.update(ATTACKER, { position: [i, 0, 0] }),
  },
  {
    label: "spectate 's' flip-flop",
    who: "attacker",
    interval: ATTACKER_INTERVAL_MS,
    make: (i) => h.spectate(ATTACKER, `Player${i % PLAYERS}`),
  },
  {
    label: "chat 'm'",
    who: "attacker",
    interval: ATTACKER_INTERVAL_MS,
    make: () => h.chat(ATTACKER, "x".repeat(120)),
  },
  {
    label: "slash command",
    who: "attacker",
    interval: ATTACKER_INTERVAL_MS,
    make: () => h.chat(ATTACKER, "/nope"),
  },
  {
    label: "race checkpoint 'r'",
    who: "attacker",
    interval: ATTACKER_INTERVAL_MS,
    make: () => h.checkpoint(ATTACKER, 1),
  },
  {
    label: "unknown opcode",
    who: "attacker",
    interval: 0,
    make: () => Buffer.from([0, 0, 0, 0]),
    rinfo: { address: "198.51.100.8", port: 44444, family: "IPv4", size: 0 },
  },
  {
    label: "malformed (truncated 'l')",
    who: "attacker",
    interval: 0,
    make: () => Buffer.from([0, 0, 0, 1, 0x6c, 0, 0, 0]),
    rinfo: { address: "198.51.100.9", port: 44445, family: "IPv4", size: 0 },
  },
  {
    label: "connect 'c' from a forged address",
    who: "attacker",
    interval: ATTACKER_INTERVAL_MS,
    make: (i) => h.connect(`Ghost${i}`),
    rinfo: { address: "198.51.100.7", port: 44443, family: "IPv4", size: 0 },
  },
];

const main = async () => {
  const hosts = [buildLegacy(), buildHardened()];
  console.log(
    `${PACKETS} packets per case, attacker at ${Math.round(1000 / ATTACKER_INTERVAL_MS)} Hz, ` +
      `a legitimate client at ${Math.round(1000 / CLIENT_INTERVAL_MS)} Hz, ${PLAYERS} players on the roster\n`
  );
  console.log(
    "case".padEnd(34) +
      "sender".padEnd(12) +
      "server".padEnd(10) +
      "in B".padStart(9) +
      "out pkts".padStart(10) +
      "out B".padStart(11) +
      "factor".padStart(9)
  );

  const rows = [];
  for (const testCase of CASES) {
    for (const host of hosts) {
      const result = await measure(host, testCase.make, testCase.interval, testCase.rinfo);
      rows.push(Object.assign({ case: testCase.label, who: testCase.who, server: host.name }, result));
      console.log(
        testCase.label.padEnd(34) +
          testCase.who.padEnd(12) +
          host.name.padEnd(10) +
          fmt(result.bytesIn).padStart(9) +
          fmt(result.packetsOut).padStart(10) +
          fmt(result.bytesOut).padStart(11) +
          `${result.factor.toFixed(2)}x`.padStart(9)
      );
    }
  }

  const worst = (server) =>
    rows.filter((r) => r.server === server && r.who === "attacker").reduce((a, b) => (b.factor > a.factor ? b : a));
  console.log(
    `\nworst attacker factor - legacy: ${worst("legacy").factor.toFixed(2)}x (${worst("legacy").case}), ` +
      `hardened: ${worst("hardened").factor.toFixed(2)}x (${worst("hardened").case})`
  );
  console.log(
    "\nA relay cannot have a factor of one: one player moving is one packet to every\n" +
      "other player, by definition. The number to read is the attacker's factor against\n" +
      "the legitimate client's, on the same row."
  );
  return rows;
};

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = { main };
