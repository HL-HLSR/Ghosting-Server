#!/usr/bin/env node
"use strict";

// Spray smoke test for a running ghserver. A uploads a spray at the client's
// own pace (one 400-byte piece per 40 ms); B and C receive the relayed pieces,
// put the blob back together and inflate it, and the VTF must be byte-identical
// to the one the spray was built from. Then A stamps it on a wall and B and C
// must get the stamp.
//
//   node test/tools/smoke-spray.js <host> [port=22228] [spray=gh_80123637] [--v2] [--spray-dir DIR] [--suffix TEXT]
//
// The clients are SprayA, SprayB and SprayC plus a random per-run suffix, as
// in smoke-remote.js (--suffix picks it, --suffix "" gives the bare names).
//
// The spray is a real one the mod wrote - <DIR>/<spray>.ghs and the matching
// <spray>.vtf, its crc taken from the name - when --spray-dir (or the
// GH_SPRAY_DIR environment variable) names a folder. Otherwise it is a
// synthetic valid picture built with the test harness (a 128x128 noise image,
// about 64 KB deflated, 165 pieces), so the tool runs anywhere.
//
// --v2 announces protocol v2 and frames everything with C/S the way the mod's
// client does (smoke-client.js); the run then also fails if the host answered
// as a legacy host, or sent anything without C or over 512 bytes.

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const { createClient, framingProblems, parseArgs, nameSuffix } = require("./smoke-client");
const h = require("../helpers/harness");
const packets = require("../../src/wire/packets");
const { Message } = require("../../src/wire/reader");

const { options, positional } = parseArgs(process.argv.slice(2), ["--spray-dir"]);
const HOST = positional[0];
const PORT = Number(positional[1] || 22228);
const SPRAY_DIR = options["spray-dir"] || process.env.GH_SPRAY_DIR || "";
if (!HOST) {
  console.error("usage: smoke-spray.js <host> [port] [spray] [--v2] [--spray-dir DIR] [--suffix TEXT]");
  process.exit(2);
}
const SUFFIX = nameSuffix(options);

// The picture: { label, blob, vtf, crc }. `vtf` is what the receivers' inflated
// copy must equal byte for byte.
const loadSpray = () => {
  if (SPRAY_DIR) {
    const name = positional[2] || "gh_80123637";
    return {
      label: `${name} from ${SPRAY_DIR}`,
      blob: fs.readFileSync(path.join(SPRAY_DIR, `${name}.ghs`)),
      vtf: fs.readFileSync(path.join(SPRAY_DIR, `${name}.vtf`)),
      crc: Number.parseInt(name.slice(3), 16) | 0,
    };
  }
  const { blob, crc } = h.sprayBlob(128, 5, true);
  return { label: "a synthetic 128x128 picture", blob, vtf: zlib.inflateSync(blob.subarray(8)), crc };
};

const { label, blob, vtf, crc } = loadSpray();
const CHUNK = 400;
const total = Math.ceil(blob.length / CHUNK);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const onPacket = (c, buffer) => {
  const type = buffer.readUInt8(0);
  if (type === packets.TYPE.SPRAY_CHUNK) {
    const m = new Message(buffer.subarray(1), {});
    const from = m.readString();
    const pieceCrc = m.readInt32();
    const raw = m.readInt32();
    const pieces = m.readInt32();
    const index = m.readInt32();
    const payload = m.readBytes();
    c.meta = { from, crc: pieceCrc, raw, total: pieces };
    c.pieces.set(index, payload);
  }
  if (type === packets.TYPE.SPRAY_STAMP) {
    const m = new Message(buffer.subarray(1), {});
    c.stamps.push({ from: m.readString(), crc: m.readInt32() });
  }
  if (type === packets.TYPE.KICK) {
    let reason = "?";
    try {
      reason = new Message(buffer.subarray(1), {}).readString();
    } catch (error) {
      // a reason that does not read is still a kick
    }
    console.log(`${c.name}: KICK ${reason}`);
  }
};

const makeClient = async (name) => {
  const c = await createClient({ name, host: HOST, port: PORT, v2: options.v2, onPacket: (client, buffer) => onPacket(client, buffer) });
  Object.assign(c, { pieces: new Map(), meta: null, stamps: [] });
  return c;
};

(async () => {
  const [A, B, C] = [
    await makeClient(`SprayA${SUFFIX}`),
    await makeClient(`SprayB${SUFFIX}`),
    await makeClient(`SprayC${SUFFIX}`),
  ];
  const all = [A, B, C];
  for (const c of all) c.connect();
  for (let i = 0; i < 30 && !all.every((c) => c.accepted); i++) await sleep(100);
  if (!all.every((c) => c.accepted)) {
    for (const c of all) if (!c.accepted) console.log(`${c.name}: not accepted${c.queuedRefusal() ? `, refused: ${c.queuedRefusal()}` : ""}`);
    console.log("RESULT: FAIL (connect)");
    process.exit(1);
  }
  console.log(`modes: ${all.map((c) => `${c.name} ${c.mode}`).join(", ")}`);
  const tick = setInterval(() => all.forEach((c, i) => c.send(h.update(c.name, { position: [i * 50, 0, 64] }))), 30);
  await sleep(500);

  console.log(`uploading ${label}: ${blob.length} bytes in ${total} pieces of ${CHUNK} at 25/s`);
  const t0 = Date.now();
  for (let i = 0; i < total; i++) {
    A.send(h.sprayChunk(A.name, crc, blob.length, total, i, blob.subarray(i * CHUNK, (i + 1) * CHUNK)));
    await sleep(40);
  }
  // Wait for the relay to finish dripping to both receivers.
  const done = () => [B, C].every((c) => c.meta && c.pieces.size === c.meta.total);
  for (let i = 0; i < 600 && !done(); i++) await sleep(100);
  const secs = ((Date.now() - t0) / 1000).toFixed(1);

  let ok = true;
  for (const c of [B, C]) {
    if (!c.meta) {
      console.log(`${c.name}: no pieces received`);
      ok = false;
      continue;
    }
    const parts = [];
    for (let i = 0; i < c.meta.total; i++) parts.push(c.pieces.get(i) || Buffer.alloc(0));
    const got = Buffer.concat(parts);
    let same = false;
    let why = "";
    try {
      if (got.toString("latin1", 0, 4) !== "GHS1") why = "bad magic";
      const declared = got.readUInt32LE(4);
      const inflated = zlib.inflateSync(got.subarray(8));
      same = declared === vtf.length && inflated.equals(vtf);
      if (!same) why = `declared ${declared}, inflated ${inflated.length}, vtf ${vtf.length}`;
    } catch (error) {
      why = error.message;
    }
    if (!same || c.meta.crc !== crc || c.meta.raw !== got.length) ok = false;
    console.log(
      `${c.name}: from ${c.meta.from}, pieces ${c.pieces.size}/${c.meta.total}, relayed blob ${got.length} B (orig ${blob.length}), ` +
        `crc ${c.meta.crc === crc ? "same" : "DIFFERENT"}, rawBytes ${c.meta.raw === got.length ? "consistent" : "INCONSISTENT"}, ` +
        `inflated VTF identical to the original: ${same}${why ? " (" + why + ")" : ""}`
    );
  }
  console.log(`relay complete after ${secs} s`);

  A.send(h.sprayStamp(A.name, crc, 100, 200, 64));
  await sleep(1000);
  for (const c of [B, C]) {
    const stamp = c.stamps.find((x) => x.from === A.name && x.crc === crc);
    if (!stamp) ok = false;
    console.log(`${c.name}: stamp received: ${!!stamp}`);
  }
  clearInterval(tick);
  for (const c of all) c.send(h.disconnect(c.name));
  // The host applies a goodbye 2 s after it arrives. Waiting for that frees
  // this run's slots before the next run (four per address, and every run from
  // one machine is one address) asks for its own.
  await sleep(2500);

  const framing = framingProblems(all);
  for (const problem of framing) console.log(`framing: ${problem}`);
  if (framing.length) ok = false;

  console.log(`RESULT: ${ok ? "PASS" : "FAIL"}`);
  for (const c of all) c.close();
  process.exit(ok ? 0 : 1);
})();
