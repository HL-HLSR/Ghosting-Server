#!/usr/bin/env node
"use strict";

// Asks a live ghserver 1.4.0+ for its server-browser info over real UDP, the
// way the mod's "Servers" dialog does: the bare query, then the query with the
// challenge it was given. Prints one JSON object and ends with RESULT: PASS or
// RESULT: FAIL.
//
//   node test/tools/server-info.js <host> [port] [--timeout MS] [--expect-name TEXT]
//                                  [--wrong-challenge] [--repeat N]
//
// --wrong-challenge  first sends a made-up challenge: the host must answer with
//                    a challenge (type 17), never the info.
// --repeat N         asks N times in a row (to watch the per-address budget).
// The run fails when a challenge reply is larger than the query that asked for
// it, when a type 18 is over 512 bytes, or when nothing answers in time. A host
// before 1.4.0 does not know the query (it counts it as an unknown opcode) and
// answers nothing: that is a FAIL here and "no reply" in the game's dialog.

const dgram = require("node:dgram");
const crypto = require("node:crypto");
const { BufferWriter } = require("../../src/wire/writer");

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const value = args[i + 1];
  args.splice(i, 2);
  return value;
};
const has = (name) => {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
};

const timeoutMs = Number(flag("--timeout") || 2000);
const expectName = flag("--expect-name");
const repeat = Math.max(1, Number(flag("--repeat") || 1));
const wrongChallenge = has("--wrong-challenge");
const host = args[0];
const port = Number(args[1] || 22228);
if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("usage: node test/tools/server-info.js <host> [port] [--timeout MS] [--expect-name TEXT] [--wrong-challenge] [--repeat N]");
  process.exit(2);
}

const TYPE_CHALLENGE = 17;
const TYPE_INFO = 18;
const PLAYER_FLAGS = ["hlsr", "op", "spectating", "runner", "identified", "v2"];
const SERVER_FLAGS = ["requireV2", "whitelist", "steamIdentity", "opChat"];
const RACE = ["idle", "lobby", "countdown_map", "loading", "staging", "countdown_start", "racing"];

const query = (requestId, challenge) => {
  const w = new BufferWriter();
  w.writeString("i");
  w.writeUInt8(1);
  w.writeInt32(requestId | 0);
  w.writeInt32(challenge | 0);
  return w.buffer;
};

const bits = (value, names) => names.filter((_, i) => value & (1 << i));
const utf8 = (latin1) => Buffer.from(latin1, "latin1").toString("utf8");

const parseInfo = (b) => {
  let at = 1;
  const u8 = () => b.readUInt8(at++);
  const u32 = () => { const v = b.readUInt32BE(at); at += 4; return v; };
  const str = () => { const n = u32(); const s = b.toString("latin1", at, at + n); at += n; return s; };
  const out = { requestId: u32(), format: u8(), name: utf8(str()), version: str(), protocol: u8() };
  out.flags = bits(u8(), SERVER_FLAGS);
  out.players = u8();
  out.maxPlayers = u8();
  out.race = RACE[u8()] || "unknown";
  out.map = str();
  const n = u8();
  out.list = [];
  for (let i = 0; i < n; i += 1) out.list.push({ name: utf8(str()), flags: bits(u8(), PLAYER_FLAGS) });
  out.trailing = b.length - at;
  return out;
};

const socket = dgram.createSocket("udp4");
const result = { host, port, rounds: [] };
const problems = [];

const exchange = (packet) =>
  new Promise((resolve) => {
    const sentAt = process.hrtime.bigint();
    const timer = setTimeout(() => {
      socket.removeListener("message", onMessage);
      resolve(null);
    }, timeoutMs);
    const onMessage = (msg, rinfo) => {
      if (rinfo.port !== port) return;
      clearTimeout(timer);
      socket.removeListener("message", onMessage);
      resolve({ msg, ms: Number(process.hrtime.bigint() - sentAt) / 1e6 });
    };
    socket.on("message", onMessage);
    socket.send(packet, port, host);
  });

const round = async () => {
  const requestId = crypto.randomBytes(4).readUInt32BE(0);
  const r = { requestId };
  if (wrongChallenge) {
    const q = query(requestId, 0x5a5a5a5a);
    const got = await exchange(q);
    r.wrongChallengeReply = got ? { type: got.msg[0], bytes: got.msg.length } : null;
    if (!got || got.msg[0] !== TYPE_CHALLENGE) problems.push("a wrong challenge was not answered with a type 17");
  }
  const bare = query(requestId, 0);
  const first = await exchange(bare);
  if (!first) {
    problems.push("no answer to the bare query (offline, firewalled, or a host before 1.4.0)");
    return r;
  }
  r.queryBytes = bare.length;
  r.challengeBytes = first.msg.length;
  r.challengeMs = Math.round(first.ms * 100) / 100;
  if (first.msg[0] !== TYPE_CHALLENGE) problems.push(`the bare query got type ${first.msg[0]}, not 17`);
  if (first.msg.length > bare.length) problems.push(`challenge ${first.msg.length} B > query ${bare.length} B`);
  if (first.msg.readUInt32BE(1) !== requestId) problems.push("the challenge did not echo the request id");
  const challenge = first.msg.readUInt32BE(5);
  const second = await exchange(query(requestId, challenge));
  if (!second) {
    problems.push("no answer to the query with the challenge");
    return r;
  }
  r.replyBytes = second.msg.length;
  r.pingMs = Math.round(second.ms * 100) / 100;
  if (second.msg[0] !== TYPE_INFO) {
    problems.push(`the query with the challenge got type ${second.msg[0]}, not 18`);
    return r;
  }
  if (second.msg.length > 512) problems.push(`type 18 is ${second.msg.length} B, over 512`);
  r.info = parseInfo(second.msg);
  if (r.info.requestId !== requestId) problems.push("the info did not echo the request id");
  if (expectName !== undefined && r.info.name !== expectName) problems.push(`name ${JSON.stringify(r.info.name)} != ${JSON.stringify(expectName)}`);
  return r;
};

(async () => {
  for (let i = 0; i < repeat; i += 1) result.rounds.push(await round());
  socket.close();
  result.problems = problems;
  console.log(JSON.stringify(result, null, 2));
  console.log(`RESULT: ${problems.length === 0 ? "PASS" : "FAIL"}`);
  process.exit(problems.length === 0 ? 0 : 1);
})();
