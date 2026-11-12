#!/usr/bin/env node
"use strict";

// Smoke test for a running ghserver: N fake clients over real UDP.
//
//   node test/tools/smoke-remote.js <host> [port=22228] [clients=3] [seconds=20] [pps=33] [--v2] [--suffix TEXT] [--emote-pack VALUE|none]
//
// The clients are SmokeA, SmokeB, ... plus a random per-run suffix (SmokeA_3f9c),
// so a rerun is not refused while the host still holds the last run's names;
// --suffix picks the suffix, and --suffix "" gives the bare names.
//
// Uses the repo's own packet builders. Checks that every connect is accepted
// (type 7), that each client receives the others' positions (type 1, at least
// 95 % of what they sent), that chat fans out to everyone (type 6) and that a
// leave reaches the others (type 4). Prints the per-pair delivery ratio and
// the inter-arrival times.
//
// --v2 announces protocol v2 and frames everything with C/S the way the mod's
// client does (smoke-client.js). The run then also fails if the host answered
// as a legacy host, or sent anything without C or over 512 bytes. Without it
// the clients are legacy, as every build before protocol v2.
//
// --emote-pack VALUE checks the host's EMOTE_PACK (type 14): every client must
// be sent that pack, in its normalised form (set:/user:/twitch:), and nothing
// else; --emote-pack none fails if any client is sent one. Without it the packs
// received are only printed.

const { createClient, framingProblems, parseArgs, nameSuffix } = require("./smoke-client");
const h = require("../helpers/harness");
const packets = require("../../src/wire/packets");
const { Message } = require("../../src/wire/reader");

const { options, positional } = parseArgs(process.argv.slice(2), ["--emote-pack"]);
const HOST = positional[0];
const PORT = Number(positional[1] || 22228);
const N = Number(positional[2] || 3);
const SECONDS = Number(positional[3] || 20);
const PPS = Number(positional[4] || 33);
if (!HOST) {
  console.error("usage: smoke-remote.js <host> [port] [clients] [seconds] [pps] [--v2] [--suffix TEXT] [--emote-pack VALUE|none]");
  process.exit(2);
}
const SUFFIX = nameSuffix(options);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const readName = (buffer) => {
  try {
    return new Message(buffer.subarray(1), {}).readString();
  } catch (error) {
    return "?";
  }
};

const onPacket = (c, buffer) => {
  const type = buffer.readUInt8(0);
  c.types.set(type, (c.types.get(type) || 0) + 1);
  if (type === packets.TYPE.INFO) {
    const from = readName(buffer);
    c.info.set(from, (c.info.get(from) || 0) + 1);
    const now = performance.now();
    if (c.lastAt.has(from)) c.gaps.push(now - c.lastAt.get(from));
    c.lastAt.set(from, now);
  }
  if (type === packets.TYPE.CHAT) c.chats.push(buffer.toString("latin1", 1).replace(/[^\x20-\x7e]/g, "|"));
  if (type === packets.TYPE.DISCONNECT) c.leaves.push(readName(buffer));
  if (type === packets.TYPE.KICK) console.log(`${c.name}: KICK ${readName(buffer)}`);
  if (type === packets.TYPE.EMOTE_PACK) c.packs.push(readName(buffer));
};

const makeClient = async (name) => {
  const c = await createClient({ name, host: HOST, port: PORT, v2: options.v2, onPacket: (client, buffer) => onPacket(client, buffer) });
  Object.assign(c, { sentLines: 0, info: new Map(), lastAt: new Map(), gaps: [], types: new Map(), chats: [], leaves: [], packs: [] });
  return c;
};

(async () => {
  const clients = [];
  for (let i = 0; i < N; i++) clients.push(await makeClient(`Smoke${String.fromCharCode(65 + i)}${SUFFIX}`));
  for (const c of clients) c.connect();
  for (let i = 0; i < 30 && !clients.every((c) => c.accepted); i++) await sleep(100);
  for (const c of clients) {
    const refusal = c.accepted ? "" : c.queuedRefusal();
    console.log(`${c.name}: accepted=${c.accepted} mode=${c.mode}${refusal ? ` refused: ${refusal}` : ""}`);
  }
  if (!clients.every((c) => c.accepted)) {
    console.log("RESULT: FAIL (not all accepted)");
    process.exit(1);
  }

  const t0 = Date.now();
  const tick = setInterval(() => {
    const t = (Date.now() - t0) / 1000;
    clients.forEach((c, i) => {
      c.send(h.update(c.name, { map: "d1_trainstation_01", position: [Math.sin(t + i) * 300, Math.cos(t + i) * 300, 64], yaw: t * 10 }));
      c.sentLines++;
    });
  }, Math.round(1000 / PPS));
  await sleep(2000);
  clients.forEach((c, i) => setTimeout(() => c.send(h.chat(c.name, `smoke hello ${i}`)), 300 * i));
  await sleep(SECONDS * 1000 - 2000);
  clearInterval(tick);
  await sleep(800);

  let ok = true;
  for (const c of clients) {
    const parts = [];
    for (const o of clients) {
      if (o === c) continue;
      const got = c.info.get(o.name) || 0;
      const ratio = got / o.sentLines;
      if (ratio < 0.95) ok = false;
      parts.push(`${o.name} ${got}/${o.sentLines} (${(ratio * 100).toFixed(1)}%)`);
    }
    const g = c.gaps.slice().sort((a, b) => a - b);
    const p = (q) => (g.length ? g[Math.min(g.length - 1, Math.floor(q * g.length))].toFixed(1) : "-");
    const chatsFromOthers = c.chats.filter((s) => /smoke hello/.test(s)).length;
    if (chatsFromOthers < N) ok = false; // own chat is echoed back too
    console.log(
      `${c.name}: positions ${parts.join(", ")} | gap ms p50 ${p(0.5)} p95 ${p(0.95)} p99 ${p(0.99)} max ${p(1)} | ` +
        `chats seen ${chatsFromOthers}/${N} | types ${[...c.types].map(([k, v]) => `${k}:${v}`).join(" ")}`
    );
  }

  // Leave one by one; the rest must see a type 4 for each.
  // The host arms the drop and applies it ~2 s later, so wait past that.
  for (const c of clients) {
    c.send(h.disconnect(c.name));
    await sleep(150);
  }
  await sleep(3500);
  const firstLeft = clients[0].name;
  const sawLeave = clients.slice(1).every((c) => c.leaves.includes(firstLeft));
  if (!sawLeave) ok = false;
  console.log(`leave of ${firstLeft} seen by others: ${sawLeave}`);

  const framing = framingProblems(clients);
  for (const problem of framing) console.log(`framing: ${problem}`);
  if (framing.length) ok = false;

  const wantPack = options["emote-pack"];
  for (const c of clients) {
    console.log(`${c.name}: emote pack ${c.packs.length ? c.packs.join(", ") : "none"}`);
    if (wantPack === undefined) continue;
    const good = wantPack === "none" ? c.packs.length === 0 : c.packs.length > 0 && c.packs.every((pack) => pack === wantPack);
    if (!good) ok = false;
  }
  console.log(`protocol: ${options.v2 ? "v2 requested" : "legacy"}; modes ${clients.map((c) => c.mode).join(" ")}`);

  console.log(`RESULT: ${ok ? "PASS" : "FAIL"}`);
  for (const c of clients) c.close();
  process.exit(ok ? 0 : 1);
})();
