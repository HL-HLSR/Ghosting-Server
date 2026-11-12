#!/usr/bin/env node
"use strict";

// The same amplification measurement, against the pre-hardening server.
//
//   node test/tools/amplification-legacy.js
//
// legacy/index.js is executed as it stands in a sandbox where its socket is a
// capture buffer, so these are that server's real numbers rather than an
// estimate of them. Run alongside test/tools/amplification.js to compare.
//
// The legacy server has no clock injection, so a window is simulated by sending
// the same number of packets rather than by advancing time. Its only throttle
// on 'l' is a 30 ms wall-clock gap, which a tight loop trips constantly - so
// for 'l' the figure below is a lower bound on what a real attacker pacing
// their packets would get.

const path = require("path");
const legacy = require(path.join(__dirname, "..", "helpers", "legacy"));
const h = require(path.join(__dirname, "..", "helpers", "harness"));

const PLAYERS = 16;
const PACKETS = 500;
const NAT = "203.0.113.30";

const { api, captured } = legacy.load();

// Fill the roster the same way the hardened measurement does.
for (let i = 0; i < PLAYERS; i += 1) {
  api.userManager.registerUser(`Player${i}`, { address: NAT, port: 41000 + i }, 12, 255, 0, 0, 10, 20, 30);
}

const attackerAt = { address: NAT, port: 41003 };
const ATTACKER = "Player3";

const fmt = (n) => n.toLocaleString("en-US");

const measure = (label, buffers, rinfo) => {
  captured.length = 0;
  let bytesIn = 0;
  for (const buffer of buffers) {
    bytesIn += buffer.length;
    try {
      api.messageHandler.onMessage(new api.Message(buffer, rinfo));
    } catch (error) {
      /* the legacy server catches these one level up, in its socket handler */
    }
  }
  const bytesOut = captured.reduce((total, packet) => total + packet.buffer.length, 0);
  const packetsOut = captured.length;
  captured.length = 0;
  return {
    label,
    packetsIn: buffers.length,
    bytesIn,
    packetsOut,
    bytesOut,
    factor: bytesIn === 0 ? 0 : bytesOut / bytesIn,
    packetFactor: packetsOut / buffers.length,
  };
};

const repeat = (make) => Array.from({ length: PACKETS }, (_, i) => make(i));

const results = [
  measure(
    "spectate 's' flip-flop",
    repeat((i) => h.spectate(ATTACKER, `Player${i % PLAYERS}`)),
    attackerAt
  ),
  measure(
    "chat 'm'",
    repeat(() => h.chat(ATTACKER, "x".repeat(120))),
    attackerAt
  ),
  measure(
    "position 'l'",
    repeat((i) => h.update(ATTACKER, { position: [i, 0, 0] })),
    attackerAt
  ),
  measure(
    "unknown opcode",
    repeat(() => Buffer.from([0, 0, 0, 0])),
    { address: "198.51.100.8", port: 44444 }
  ),
  measure(
    "slash command",
    repeat(() => h.chat(ATTACKER, "/nope")),
    attackerAt
  ),
  measure(
    "race checkpoint 'r'",
    repeat(() => h.checkpoint(ATTACKER, 1)),
    attackerAt
  ),
];

console.log(`pre-hardening server, ${PLAYERS} players, ${PACKETS} packets per case\n`);
console.log(
  "opcode".padEnd(30) +
    "in pkts".padStart(9) +
    "in B".padStart(10) +
    "out pkts".padStart(10) +
    "out B".padStart(12) +
    "x bytes".padStart(10) +
    "x pkts".padStart(9)
);
for (const r of results) {
  console.log(
    r.label.padEnd(30) +
      fmt(r.packetsIn).padStart(9) +
      fmt(r.bytesIn).padStart(10) +
      fmt(r.packetsOut).padStart(10) +
      fmt(r.bytesOut).padStart(12) +
      r.factor.toFixed(2).padStart(10) +
      r.packetFactor.toFixed(2).padStart(9)
  );
}

const worst = results.reduce((a, b) => (b.factor > a.factor ? b : a));
console.log(`\nworst: ${worst.label} at ${worst.factor.toFixed(2)}x by bytes, ${worst.packetFactor.toFixed(2)}x by packets`);

module.exports = { results };
