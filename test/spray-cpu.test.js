"use strict";

// C1 (review 1): the spray re-encode ran a synchronous level-9 deflate on the
// datagram path. A VALID 256x256 picture of random 2-colour noise drives zlib's
// level-9 worst case (~455 ms measured on a fast desktop core), so a handful of
// sessions publishing at once froze the event loop long enough to time the whole
// lobby out. The re-encode now runs at level 6 (~25 ms worst case), and a
// server-wide re-encode budget bounds how many run back to back, whatever the
// number of sessions or addresses publishing. Review 2 (N3): a picture that
// finds the budget empty waits in a fair queue the tick drains (review2.test.js).

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const spray = require("../src/wire/spray");
const packets = require("../src/wire/packets");
const { Message } = require("../src/wire/reader");

const twoColourNoise = (seed = 7) => {
  const pixels = Buffer.alloc(256 * 256 * 4);
  let s = seed >>> 0 || 1;
  for (let i = 0; i < pixels.length; i++) {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
    pixels[i] = s & 1 ? 0xff : 0x00;
  }
  return h.sprayBlobFromPixels(256, pixels, 1);
};

// SERVER chat lines sent to one destination since a marker.
const serverLinesTo = (socket, rinfo, since) =>
  h.sentTo(socket, rinfo.address, rinfo.port, since)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT)
    .map((p) => {
      const m = new Message(p.buffer.subarray(1), {});
      m.readInt32();
      return { name: m.readString(), text: m.readString() };
    })
    .filter((line) => line.name === "SERVER")
    .map((line) => line.text);

test("C1: re-encoding a worst-case valid picture is fast and uses level <= 6", () => {
  const { blob, crc } = twoColourNoise();
  spray.validateAndReencode(blob, crc); // warm the allocator
  let best = Infinity;
  let out = null;
  for (let i = 0; i < 3; i++) {
    const t = process.hrtime.bigint();
    out = spray.validateAndReencode(blob, crc);
    best = Math.min(best, Number(process.hrtime.bigint() - t) / 1e6);
  }
  assert.strictEqual(out.ok, true, "the picture is valid and must be accepted");
  assert.ok(spray.REENCODE_LEVEL <= 6, `re-encode level ${spray.REENCODE_LEVEL}`);
  // The zlib header's FLEVEL bits say what level actually ran: 7-9 write 0xDA.
  assert.notStrictEqual(out.blob[spray.BLOB_HEADER_BYTES + 1], 0xda, "the output was compressed above level 6");
  // Generous for a slow CI box; level 9 took ~455 ms here, level 6 ~25 ms.
  assert.ok(best < 150, `validate + re-encode took ${best.toFixed(1)} ms`);
});

test("C1: a server-wide re-encode budget bounds back-to-back publications; the rest wait in the queue (N3)", () => {
  const { server, socket, clock } = h.makeServer({ MAX_PLAYERS: "16" });
  const senders = [];
  for (let i = 0; i < 8; i++) {
    const r = h.from(`10.9.${i}.1`, 41000 + i);
    server.onDatagram(h.connect(`S${i}`), r);
    server.onDatagram(h.update(`S${i}`), r);
    senders.push({ r, name: `S${i}`, pic: h.sprayBlob(8, i + 1) });
  }

  // Eight sessions on eight addresses complete a valid picture in the same
  // instant: only the budget's burst is re-encoded now.
  const mark = socket.sent.length;
  for (const s of senders) h.uploadSpray(server, s.r, s.name, s.pic.crc, s.pic.blob);
  const published = senders.filter((s) => server.users.get(s.name).spray).length;
  assert.strictEqual(published, server.config.sprayReencodeBurst, `${published} re-encodes ran back to back`);

  // Review 2 (N3): the rest are queued, not refused, and nobody is sent a
  // notice; a tick re-encodes at most one, at the budget's rate.
  const waiting = senders.filter((s) => !server.users.get(s.name).spray);
  for (const s of waiting) {
    assert.strictEqual(serverLinesTo(socket, s.r, mark).length, 0, `${s.name} was sent a notice`);
  }
  clock.advance(250);
  assert.strictEqual(senders.filter((s) => server.users.get(s.name).spray).length, published, "a tick ran a re-encode the budget had not refilled for");
  clock.advance(60000 / server.config.sprayReencodePerMinute);
  assert.strictEqual(senders.filter((s) => server.users.get(s.name).spray).length, published + 1, "one re-encode per refill");

  // Without the client re-sending anything, every queued picture goes out.
  for (let t = 0; t < 15000; t += 1000) {
    clock.advance(1000);
    for (const s of senders) server.onDatagram(h.update(s.name), s.r);
  }
  for (const s of waiting) assert.ok(server.users.get(s.name).spray, `${s.name} was never published from the queue`);
});

test("C1: the completing datagram of a worst-case picture does not stall the loop", () => {
  const { server, clock } = h.makeServer();
  const a = h.from("10.1.0.1", 40000);
  server.onDatagram(h.connect("Attacker"), a);
  server.onDatagram(h.update("Attacker"), a);
  const { blob, crc } = twoColourNoise(11);
  const total = Math.ceil(blob.length / 400);
  let worst = 0;
  for (let i = 0; i < total; i++) {
    const piece = blob.subarray(i * 400, Math.min((i + 1) * 400, blob.length));
    const t = process.hrtime.bigint();
    server.onDatagram(h.sprayChunk("Attacker", crc, blob.length, total, i, piece), a);
    worst = Math.max(worst, Number(process.hrtime.bigint() - t) / 1e6);
    clock.advance(40);
  }
  assert.ok(server.users.get("Attacker").spray, "the valid picture should publish");
  assert.ok(worst < 150, `the slowest datagram took ${worst.toFixed(1)} ms`);
});
