"use strict";

// M3: the server used to relay spray bytes it never inspected; clients wrote
// them to disk and inflated them with zlib 1.2.5. The host now validates a blob
// strictly (magic, declared size against the legal VTF sizes, bounded inflate to
// exactly that size, the VTF header byte-for-byte against what the client's own
// writer produces, and the pixel crc), then relays a blob it re-encoded with the
// current zlib. Junk is dropped with no fan-out.
//
// Wire compatibility with the shipped client is proven in src/wire/spray.js and
// was checked end to end against the mod's own gh_*.ghs/.vtf files: the pixel
// crc survives the re-encode and the re-encoded blob inflates to the identical
// VTF, so every client-side check still passes.

const test = require("node:test");
const assert = require("node:assert");
const zlib = require("node:zlib");

const h = require("./helpers/harness");
const spray = require("../src/wire/spray");
const packets = require("../src/wire/packets");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

test("a valid picture is accepted and its pixel crc survives the re-encode", () => {
  const { blob, crc } = h.sprayBlob(64, 1, true);
  const v = spray.validateAndReencode(blob, crc);
  assert.strictEqual(v.ok, true, "a real picture must be accepted");

  // The re-encoded blob inflates to the identical VTF, so the pixel crc the
  // client recomputes is unchanged - the whole compatibility argument.
  const original = zlib.inflateSync(blob.subarray(spray.BLOB_HEADER_BYTES));
  const reencoded = zlib.inflateSync(v.blob.subarray(spray.BLOB_HEADER_BYTES));
  assert.ok(reencoded.equals(original), "the re-encoded blob must inflate to the same VTF");
  const side = reencoded.readUInt16LE(16);
  const rgba = spray.swizzle(reencoded.subarray(spray.VTF_HEADER_BYTES, spray.VTF_HEADER_BYTES + side * side * 4));
  assert.strictEqual(zlib.crc32(rgba) >>> 0, crc >>> 0, "pixel crc must be preserved");
});

test("every kind of junk is refused", () => {
  const good = h.sprayBlob(8, 9);

  // Random bytes.
  assert.strictEqual(spray.validateAndReencode(Buffer.alloc(500, 0xab), 0).ok, false);

  // Wrong magic.
  const wrongMagic = Buffer.from(good.blob);
  wrongMagic.write("GHSX", 0, "latin1");
  assert.strictEqual(spray.validateAndReencode(wrongMagic, good.crc).reason, "bad-magic");

  // A declared size that is not one a VTF this mod builds would have.
  const wrongSize = Buffer.from(good.blob);
  wrongSize.writeUInt32LE(999999, 4);
  assert.strictEqual(spray.validateAndReencode(wrongSize, good.crc).reason, "bad-declared-size");

  // A flipped header byte inside the VTF (declared size still legal).
  {
    const side = 8;
    const header = Buffer.from(spray.GOLDEN_VTF_HEADER);
    header.writeUInt16LE(side, 16); header.writeUInt16LE(side, 18);
    header[20] ^= 0xff; // a flag byte the client's reference does not have
    const pixels = Buffer.alloc(side * side * 4, 3);
    const vtf = Buffer.concat([header, pixels]);
    const hdr = Buffer.alloc(8); spray.BLOB_MAGIC.copy(hdr, 0); hdr.writeUInt32LE(vtf.length, 4);
    const blob = Buffer.concat([hdr, zlib.deflateSync(vtf, { level: 9 })]);
    assert.strictEqual(spray.validateAndReencode(blob, zlib.crc32(spray.swizzle(pixels)) | 0).reason, "header");
  }

  // A crc that does not match the pixels.
  assert.strictEqual(spray.validateAndReencode(good.blob, (good.crc ^ 1) | 0).reason, "pixel-crc");

  // A deflate bomb: declares a legal size but inflates to far more.
  const bombHeader = Buffer.alloc(8);
  spray.BLOB_MAGIC.copy(bombHeader, 0);
  bombHeader.writeUInt32LE(262232, 4); // a legal declared size
  const bomb = Buffer.concat([bombHeader, zlib.deflateSync(Buffer.alloc(5 * 1024 * 1024))]);
  assert.strictEqual(spray.validateAndReencode(bomb, 0).reason, "inflate-failed");
});

test("an invalid upload is never fanned out", () => {
  const { server, socket } = h.makeServer();
  const alice = join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  // 400 bytes of junk framed as a one-chunk spray: it completes the upload but
  // fails validation.
  const junk = Buffer.alloc(400, 0x5a);
  const mark = socket.sent.length;
  server.onDatagram(h.sprayChunk("Alice", 0x1234 | 0, junk.length, 1, 0, junk), ALICE);

  assert.strictEqual(alice.spray, null, "junk must not be published");
  const chunks = h.sentTo(socket, BOB.address, BOB.port, mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPRAY_CHUNK);
  assert.strictEqual(chunks.length, 0, "junk must never be fanned out");
});

test("a real picture does fan out to the lobby", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  const bob = join(server, "Bob", BOB);
  const { blob, crc } = h.sprayBlob(64, 2, true);
  h.uploadSpray(server, ALICE, "Alice", crc, blob);
  assert.ok(server.users.get("Alice").spray, "a valid picture must publish");
  assert.ok(bob.sprayFeeds.has("Alice"), "and be queued to the lobby");
});

// ---------------------------------------------------------------------------
// I5 (review 1): a near-cap picture can grow past the client's receive bound
// when it is re-encoded. The client's bound is exactly 163840 B (server.dll:
// gh_spraynet.cpp:43 pData, :303 rawBytes, :308 offset+len, :620 the stored
// size; client.dll: gh_spray.cpp:617 and :662), the same as the upload cap, so
// there is no headroom: such a picture is refused, never relayed in its
// original encoding, and the sender is told why.
// ---------------------------------------------------------------------------

const limits = require("../src/wire/limits");
const { Message } = require("../src/wire/reader");

// 256x256 pixels whose level-9 blob is just under the cap; the first `k` bytes
// are a little noisier, which moves the level-6 re-encode across the cap.
const nearCap = (k) => {
  const pixels = Buffer.alloc(256 * 256 * 4);
  let x = 12345;
  for (let i = 0; i < pixels.length; i++) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    const noisy = i < k ? 60 : 59;
    pixels[i] = (i % 100) < noisy ? x & 0xff : (i >> 9) & 0xff;
  }
  return h.sprayBlobFromPixels(256, pixels, 9);
};

const serverLines = (socket, rinfo) =>
  h.sentTo(socket, rinfo.address, rinfo.port)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT)
    .map((p) => {
      const m = new Message(p.buffer.subarray(1), {});
      m.readInt32();
      return { name: m.readString(), text: m.readString() };
    })
    .filter((l) => l.name === "SERVER")
    .map((l) => l.text);

test("I5: the client's receive bound is the upload cap", () => {
  assert.strictEqual(limits.CLIENT_RECEIVE_MAX_BYTES, 163840);
  assert.strictEqual(limits.CLIENT_RECEIVE_MAX_BYTES, limits.MAX_SPRAY_BYTES);
});

test("I5: a near-cap picture whose re-encode still fits is relayed", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  const { blob, crc } = nearCap(193792);
  assert.ok(blob.length <= limits.MAX_SPRAY_BYTES && blob.length > 163000, `test picture is ${blob.length} B`);
  h.uploadSprayPaced(server, clock, ALICE, "Alice", crc, blob);
  const alice = server.users.get("Alice");
  assert.ok(alice.spray, "a near-cap picture that fits after re-encoding must publish");
  assert.ok(alice.spray.bytes <= limits.CLIENT_RECEIVE_MAX_BYTES);
});

test("I5: a picture that outgrows the bound when re-encoded is refused and the sender told", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  const bob = join(server, "Bob", BOB);
  const { blob, crc } = nearCap(199936);
  assert.ok(blob.length <= limits.MAX_SPRAY_BYTES, `test picture is ${blob.length} B (must be a legal upload)`);
  h.uploadSprayPaced(server, clock, ALICE, "Alice", crc, blob);
  assert.strictEqual(server.users.get("Alice").spray, null, "a picture over the receive bound must not publish");
  assert.strictEqual(bob.sprayFeeds.size, 0, "and nothing may be relayed - certainly not the original encoding");
  assert.ok(serverLines(socket, ALICE).some((t) => /too large/i.test(t)), "the sender was not told why");
});
