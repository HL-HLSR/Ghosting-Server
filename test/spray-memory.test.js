"use strict";

// M1: spray relay memory grew as players^2 * 160 KB, because every receiver got
// its own copy of every chunk (the audit measured 674 MB queued at 64 players).
// The chunk packets are now built once per publisher and shared through a
// per-receiver cursor, so the bound is N * blob, not N^2 * blob.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");

// Upload paced so the piece rate stays inside the default upload burst.
const paced = (server, clock, rinfo, name, crc, blob) => {
  const total = Math.ceil(blob.length / 400);
  for (let i = 0; i < total; i++) {
    server.onDatagram(h.sprayChunk(name, crc, blob.length, total, i, blob.subarray(i * 400, Math.min((i + 1) * 400, blob.length))), rinfo);
    if (i % 40 === 39) clock.advance(1100);
  }
  return total;
};

test("16 publishers cost one shared copy each, not one per receiver", () => {
  const { server, clock } = h.makeServer({ MAX_PLAYERS: "16", MAX_SESSIONS_PER_ADDRESS: "64", SPRAY_REENCODE_BURST: "100" }); // memory, not CPU: lift the C1 budget

  const players = [];
  for (let i = 0; i < 16; i++) {
    const r = h.from(`192.0.2.${i + 1}`, 2000 + i);
    players.push(r);
    server.onDatagram(h.connect(`s${i}`), r);
    server.onDatagram(h.update(`s${i}`), r);
  }

  const blobs = [];
  for (let i = 0; i < 16; i++) {
    const { blob, crc } = h.sprayBlob(64, i + 1, true); // ~16 KB, ~42 chunks each
    blobs.push(blob);
    paced(server, clock, players[i], `s${i}`, crc, blob);
  }

  let publishers = 0;
  let sharedBytes = 0;
  for (const user of server.users.values()) {
    if (!user.spray) continue;
    publishers += 1;
    for (const packet of user.spray.packets) sharedBytes += packet.length;
  }
  assert.strictEqual(publishers, 16, "every player published");

  // Receivers hold only cursors (one small object per sender), never buffers.
  let feedCursors = 0;
  for (const user of server.users.values()) feedCursors += user.sprayFeeds.size;

  const blobTotal = blobs.reduce((a, b) => a + b.length, 0);
  // The relay packets add a per-chunk header (~30 bytes), so allow some slack;
  // the point is that it tracks ONE copy of each picture (N * blob), not the
  // N^2 the old per-receiver queue produced (~16x this).
  assert.ok(sharedBytes < blobTotal * 1.2, `relay packets hold ${sharedBytes} bytes for ${blobTotal} of picture`);
  assert.ok(sharedBytes < blobTotal * 16 * 0.25, "memory must not scale with the receiver count");
  // 16 senders, each owed to the other 15 -> 240 cursors, each tiny.
  assert.ok(feedCursors <= 16 * 15, `${feedCursors} cursors`);
});
