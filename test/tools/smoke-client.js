"use strict";

// One fake client on a real UDP socket, for the smoke tools (smoke-remote.js,
// smoke-spray.js). It speaks the legacy protocol, or protocol v2 the way the
// mod's own receive thread does (design 2026-10-28, section 3.1):
//
//   announcing  after a v2 'c' and before the accept. A packet whose 8 bytes
//               after the type equal C comes from a v2 host: C is stripped and
//               the packet processed, and a type 7 carries S and switches to v2.
//               A bare type 7 is a legacy host's accept: switch to legacy and
//               replay what was queued. Anything else unprefixed is queued, 32
//               packets at most, and discarded in v2.
//   v2          every packet must carry C or it is dropped and counted; every
//               packet sent carries S right after its opcode (h.withToken).
//   legacy      as before.
//
// Like the client, it ignores datagrams that are not from the host's port or
// are over 512 bytes, and counts them. A smoke run fails on any of those counts:
// a real host never sends either.

const crypto = require("node:crypto");
const dgram = require("node:dgram");

const h = require("../helpers/harness");
const packets = require("../../src/wire/packets");
const { Message } = require("../../src/wire/reader");

const QUEUE_MAX = 32;
const DATAGRAM_MAX = 512;
const NONCE_BYTES = 8;

// C as the client draws it: 8 random bytes, never all zero.
const newNonce = () => {
  let nonce;
  do {
    nonce = crypto.randomBytes(NONCE_BYTES);
  } while (nonce.every((byte) => byte === 0));
  return nonce;
};

const withoutNonce = (buffer) => Buffer.concat([buffer.subarray(0, 1), buffer.subarray(1 + NONCE_BYTES)]);

const readReason = (buffer) => {
  try {
    return new Message(buffer.subarray(1), {}).readString();
  } catch (error) {
    return "?";
  }
};

// `onPacket(client, buffer)` gets every packet the client would process, with
// C already stripped, so the caller reads it exactly as a legacy packet.
const createClient = ({ name, host, port, v2, onPacket }) =>
  new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const client = {
      name,
      socket,
      v2Requested: !!v2,
      mode: v2 ? "announcing" : "legacy",
      nonce: v2 ? newNonce() : null,
      token: null,
      accepted: false,
      dropped: 0, // v2: a packet without C
      foreign: 0, // not from the host's port
      oversize: 0, // over 512 bytes
      queue: [],

      // The announce: u8(2) + C after the appearance when v2 was asked for.
      connect(appearance) {
        const buffer = client.v2Requested ? h.connectV2(name, client.nonce, appearance) : h.connect(name, appearance);
        socket.send(buffer, port, host);
      },

      // Any other packet, built by the harness as the legacy client would; in
      // v2 it gets S after its opcode, the client's GhOnline_BeginPacket.
      send(buffer) {
        socket.send(client.mode === "v2" ? h.withToken(buffer, client.token) : buffer, port, host);
      },

      // A refusal queued while announcing. The client applies one only when its
      // announce gives up without a v2 answer, so a forged refusal cannot break
      // a connect to a v2 host.
      queuedRefusal() {
        const kick = client.queue.find((buffer) => buffer[0] === packets.TYPE.KICK);
        return kick ? readReason(kick) : null;
      },

      close() {
        socket.close();
      },
    };

    const deliver = (buffer) => {
      if (buffer[0] === packets.TYPE.CONNECT_ACCEPTED) client.accepted = true;
      onPacket(client, buffer);
    };

    socket.on("message", (buffer, rinfo) => {
      if (rinfo.port !== port) {
        client.foreign += 1;
        return;
      }
      if (buffer.length > DATAGRAM_MAX) {
        client.oversize += 1;
        return;
      }
      if (buffer.length < 1) return;
      if (client.mode === "legacy") {
        deliver(buffer);
        return;
      }
      const carriesNonce = buffer.length >= 1 + NONCE_BYTES && buffer.subarray(1, 1 + NONCE_BYTES).equals(client.nonce);
      if (client.mode === "v2") {
        if (carriesNonce) deliver(withoutNonce(buffer));
        else client.dropped += 1;
        return;
      }
      // Announcing.
      if (carriesNonce) {
        const plain = withoutNonce(buffer);
        if (plain[0] === packets.TYPE.CONNECT_ACCEPTED) {
          if (plain.length < 1 + NONCE_BYTES) {
            client.dropped += 1; // "07 C" with no S: not an accept the client can use
            return;
          }
          client.token = Buffer.from(plain.subarray(1, 1 + NONCE_BYTES));
          client.mode = "v2";
          client.queue = [];
        }
        deliver(plain);
        return;
      }
      if (buffer[0] === packets.TYPE.CONNECT_ACCEPTED && buffer.length === 1) {
        client.mode = "legacy";
        const queued = client.queue;
        client.queue = [];
        deliver(buffer);
        for (const earlier of queued) deliver(earlier);
        return;
      }
      if (client.queue.length < QUEUE_MAX) client.queue.push(Buffer.from(buffer));
    });

    socket.once("error", reject);
    socket.bind(0, () => resolve(client));
  });

// What the run must report when v2 was asked for: the mode every client ended
// in, and anything the host sent that the client would have thrown away.
// Returns a list of problems (empty when all is well).
const framingProblems = (clients) => {
  const problems = [];
  for (const client of clients) {
    if (client.v2Requested && client.mode !== "v2") {
      problems.push(`${client.name}: the host answered ${client.mode}, not v2 (older than ghserver 1.3.0?)`);
    }
    if (client.dropped) problems.push(`${client.name}: ${client.dropped} packet(s) without C`);
    if (client.oversize) problems.push(`${client.name}: ${client.oversize} packet(s) over ${DATAGRAM_MAX} bytes`);
    if (client.foreign) problems.push(`${client.name}: ${client.foreign} packet(s) from another port`);
  }
  return problems;
};

// `--v2` anywhere on the command line, `--suffix TEXT`, plus the caller's own
// `--name value` options; the rest are positional, in order.
const parseArgs = (argv, valueOptions = []) => {
  const options = { v2: false };
  const positional = [];
  const valued = valueOptions.concat(["--suffix"]);
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--v2") options.v2 = true;
    else if (valued.includes(arg)) options[arg.slice(2)] = argv[(i += 1)];
    else positional.push(arg);
  }
  return { options, positional };
};

// What goes after every nickname in a run: random per run ("_" and 4 hex
// digits), so a run started a few seconds after the last one is not refused
// as "already in use" while the host still holds the previous run's names
// (their goodbyes take 2 s to apply). `--suffix TEXT` picks it instead, and
// `--suffix ""` gives the bare names.
const nameSuffix = (options) =>
  options.suffix !== undefined ? options.suffix : `_${crypto.randomBytes(2).toString("hex")}`;

module.exports = { createClient, framingProblems, parseArgs, nameSuffix };
