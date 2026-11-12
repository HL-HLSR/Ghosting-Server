#!/usr/bin/env node
"use strict";

// Measures the amplification factor of each inbound opcode.
//
//   node test/tools/amplification.js
//
// Amplification is bytes out divided by bytes in over a fixed window with a
// full server, which is the number that matters when the source address is
// forged and "out" means "at somebody who did not ask for it". A game relay
// cannot have a factor of one: one player moving is one packet to everyone
// else, by definition. What it can have is a bounded factor, and that is what
// this measures.
//
// The comparison figures for the pre-hardening server are computed by driving
// legacy/index.js, executed as it stands, through the same window.

const path = require("path");
const h = require(path.join(__dirname, "..", "helpers", "harness"));

const PLAYERS = 16;
const WINDOW_MS = 10000;
const NAT = "203.0.113.30";

const fmt = (n) => n.toLocaleString("en-US");

// A full server of confirmed players, plus the attacker.
const build = () => {
  const rig = h.makeServer({
    MAX_PLAYERS: String(PLAYERS),
    MAX_SESSIONS_PER_ADDRESS: String(PLAYERS),
    CONNECT_BURST: String(PLAYERS + 4),
    CONNECT_RATE_PER_MINUTE: "600",
  });
  for (let i = 0; i < PLAYERS; i += 1) {
    const at = h.from(NAT, 41000 + i);
    rig.server.onDatagram(h.connect(`Player${i}`), at);
    rig.server.onDatagram(h.update(`Player${i}`), at);
  }
  return rig;
};

const measure = (label, drive) => {
  const { server, socket, clock } = build();
  const mark = socket.sent.length;
  let bytesIn = 0;
  let packetsIn = 0;

  const send = (buffer, rinfo) => {
    bytesIn += buffer.length;
    packetsIn += 1;
    server.onDatagram(buffer, rinfo);
  };

  drive({ server, clock, send });

  const out = socket.sent.slice(mark);
  const bytesOut = out.reduce((total, packet) => total + packet.buffer.length, 0);
  const factor = bytesIn === 0 ? 0 : bytesOut / bytesIn;
  const packetFactor = packetsIn === 0 ? 0 : out.length / packetsIn;

  return { label, packetsIn, bytesIn, packetsOut: out.length, bytesOut, factor, packetFactor };
};

// The attacker owns a session (worst case: they connected legitimately, or they
// guessed a live endpoint) and spends the window doing one thing.
const attackerAt = h.from(NAT, 41003);
const ATTACKER = "Player3";

const cases = [
  [
    "spectate 's' flip-flop",
    ({ clock, send }) => {
      let flip = 0;
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 20) {
        clock.advance(20);
        send(h.spectate(ATTACKER, `Player${flip++ % PLAYERS}`), attackerAt);
      }
    },
  ],
  [
    "chat 'm'",
    ({ clock, send }) => {
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 20) {
        clock.advance(20);
        send(h.chat(ATTACKER, "x".repeat(120)), attackerAt);
      }
    },
  ],
  [
    "position 'l'",
    ({ clock, send }) => {
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 20) {
        clock.advance(20);
        send(h.update(ATTACKER, { position: [elapsed, 0, 0] }), attackerAt);
      }
    },
  ],
  [
    "connect 'c' from an address that never answers",
    ({ clock, send }) => {
      const spoofed = h.from("198.51.100.7", 33333);
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 20) {
        clock.advance(20);
        send(h.connect("Reflected"), spoofed);
      }
    },
  ],
  [
    "unknown opcode",
    ({ clock, send }) => {
      const junk = Buffer.from([0, 0, 0, 0]);
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 5) {
        clock.advance(5);
        send(junk, h.from("198.51.100.8", 44444));
      }
    },
  ],
  [
    "malformed",
    ({ clock, send }) => {
      const bad = Buffer.alloc(8);
      bad.writeInt32BE(-1, 0);
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 5) {
        clock.advance(5);
        send(bad, h.from("198.51.100.11", 44445));
      }
    },
  ],
  [
    "slash command",
    ({ clock, send }) => {
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 20) {
        clock.advance(20);
        send(h.chat(ATTACKER, "/nope"), attackerAt);
      }
    },
  ],
  [
    "race checkpoint 'r'",
    ({ clock, send }) => {
      for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 20) {
        clock.advance(20);
        send(h.checkpoint(ATTACKER, 1), attackerAt);
      }
    },
  ],
];

const results = cases.map(([label, drive]) => measure(label, drive));

console.log(`${PLAYERS} players, ${WINDOW_MS / 1000} s window, attacker holds a confirmed session\n`);
console.log(
  "opcode".padEnd(46) +
    "in pkts".padStart(9) +
    "in B".padStart(10) +
    "out pkts".padStart(10) +
    "out B".padStart(12) +
    "x bytes".padStart(10) +
    "x pkts".padStart(9)
);
for (const r of results) {
  console.log(
    r.label.padEnd(46) +
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

// A player moving normally is the baseline a relay cannot go below.
const baseline = measure("one player at 25 Hz (the floor for any relay)", ({ clock, send }) => {
  for (let elapsed = 0; elapsed < WINDOW_MS; elapsed += 40) {
    clock.advance(40);
    send(h.update(ATTACKER, { position: [elapsed, 0, 0] }), attackerAt);
  }
});
console.log(
  `baseline: a legitimate player at 25 Hz costs ${baseline.factor.toFixed(2)}x by bytes ` +
    `(${baseline.packetFactor.toFixed(2)} packets out per packet in)`
);

module.exports = { results, baseline };
