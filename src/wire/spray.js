"use strict";

// Spray validation and canonical re-encoding (audit M3).
//
// The old server relayed spray bytes it never inspected: a stranger's deflate
// stream reached every client in the lobby, was written to disk before anything
// looked at it, and was inflated by the client's zlib 1.2.5 (2010, CVE-2016-9840
// / -9841). This module makes the host decide whether a blob is a picture before
// it is ever fanned out, and then relays a blob it re-encoded itself, so the
// shipped clients only ever inflate a stream produced by a current zlib.
//
// WIRE COMPATIBILITY (proven against the mod on branch gh2013_main):
//
//   The blob is `GHS1` + uint32-LE(uncompressed VTF size) + deflate(VTF), built
//   by client.dll's GhSpray_WriteBlob. The RECEIVING client's server.dll
//   (gh_spraynet.cpp GhSprayNet_Think) computes the blob's CRC itself over the
//   bytes it assembled - it is NOT taken from the wire - names the file
//   gh_<pixelCrc>_<blobCrc>.ghs, and the stamp carries that blobCrc. client.dll
//   (gh_spray.cpp GhSpray_BuildRemote) then:
//     * re-hashes the file and checks it equals blobCrc in its name (self-
//       consistent for whatever bytes we relay),
//     * checks the `GHS1` magic and the declared size,
//     * inflates and requires exactly the declared size,
//     * compares the VTF header BYTE FOR BYTE against one it builds itself with
//       the same CreateVTFTexture, and the tail likewise,
//     * swizzles the pixels back to RGBA and requires CRC32(rgba) == the pixel
//       crc the sender announced (the `crc` wire field, which we never change).
//
//   So the only thing the sender controls that the client trusts is the pixel
//   data, and the only identifier that must survive is the pixel crc. Because
//   inflate(deflate(vtf)) === vtf exactly, a canonically re-deflated blob
//   reproduces the identical VTF, so every one of those client checks passes.
//   Verified end to end against four real .ghs/.vtf pairs from the mod's own
//   materials/vgui/logos: Node's zlib.crc32(swizzle(pixels)) equals the
//   filename's pixel crc, and the re-encoded blob inflates to the identical VTF.
//   The server rebuilds total/rawBytes for the (slightly larger) re-encoded
//   blob; the receiving server.dll only bounds-checks rawBytes and sizes the
//   assembly from the chunk lengths, so the new length is carried transparently.
//
// The host therefore FORWARDS a re-encoded blob, never the original bytes. If the
// re-encode comes out larger than the upload cap (a photo-like 256x256 picture
// within ~2 % of the cap), the spray is refused and the sender is told - see
// reencode() and src/server.js.

const zlib = require("node:zlib");
const limits = require("./limits");

// The VTF header client.dll's GhSpray_BuildVTF produces, captured once from the
// mod's own materials/vgui/logos output. It is identical for every spray size
// except the width/height uint16s at offsets 16 and 18, which we patch per size
// before comparing - exactly as the client builds its own reference. Fails
// closed: if a future client changes this header, sprays stop being relayed
// rather than being relayed unchecked (the client would reject them too).
const GOLDEN_VTF_HEADER = Buffer.from(
  "56544600070000000400000058000000000100010c23000001000000000000000000003f0000003f00" +
    "00003f000000000000803f0c00000001ffffffff000001000000000100000000000000000000003000000058000000",
  "hex"
);
const VTF_HEADER_BYTES = GOLDEN_VTF_HEADER.length; // 88

// The blob header client.dll writes: "GHS1" + uint32-LE uncompressed VTF size.
const BLOB_MAGIC = Buffer.from("GHS1", "latin1");
const BLOB_HEADER_BYTES = 8;

// Sizes GhSpray_BuildVTF can produce: a power-of-two square 8..256, one frame,
// no mips, BGRA8888, so the serialized file is exactly header + width*height*4.
const LEGAL_SIDES = [8, 16, 32, 64, 128, 256];
const LEGAL_VTF_SIZES = new Map(
  LEGAL_SIDES.map((n) => [VTF_HEADER_BYTES + n * n * 4, n])
);

// BGRA <-> RGBA. Its own inverse, so this recovers the RGBA the sender hashed.
const swizzle = (bgra) => {
  const out = Buffer.allocUnsafe(bgra.length);
  for (let i = 0; i + 3 < bgra.length; i += 4) {
    out[i] = bgra[i + 2];
    out[i + 1] = bgra[i + 1];
    out[i + 2] = bgra[i];
    out[i + 3] = bgra[i + 3];
  }
  return out;
};

// C1: the compression level the host re-encodes at. Level 9 hits zlib's worst
// case on an attacker-chosen VALID picture (random 2-colour 256x256 noise: ~455 ms
// of synchronous deflate on a fast desktop core, measured), which froze the event
// loop for every player. Level 6 (zlib's default) bounds the same input at ~25 ms
// measured (lazy matching, max chain 128 instead of 4096) at a cost of about 1-2 %
// larger blobs than the client's own level-9 output. The level is the whole
// defence for one spray; the server-wide re-encode budget (src/server.js) bounds
// how many can run back to back.
const REENCODE_LEVEL = 6;

// Validate an assembled blob WITHOUT re-encoding it (cheap: one bounded inflate
// and a CRC). The server calls this first and only spends its re-encode budget on
// a picture that already passed every check.
//
//   { ok: true, vtf, declaredVtf }  - a valid picture; hand vtf to reencode()
//   { ok: false, reason }           - drop it, no fan-out, one sampled log line
//
// `declaredCrc` is the sender's pixel-crc wire field (int32; compared unsigned).
const validate = (assembled, declaredCrc) => {
  if (!Buffer.isBuffer(assembled)) return { ok: false, reason: "not-a-buffer" };
  if (assembled.length <= BLOB_HEADER_BYTES) return { ok: false, reason: "too-short" };
  if (assembled.length > limits.MAX_SPRAY_BYTES) return { ok: false, reason: "too-long" };

  if (!assembled.subarray(0, 4).equals(BLOB_MAGIC)) return { ok: false, reason: "bad-magic" };

  const declaredVtf = assembled.readUInt32LE(4);
  const side = LEGAL_VTF_SIZES.get(declaredVtf);
  if (side === undefined) return { ok: false, reason: "bad-declared-size" };

  // Bounded inflate: a blob claiming to expand to a gigabyte gets a buffer error
  // here instead of a heap. The deflate stream is everything after the 8-byte
  // header.
  let vtf;
  try {
    vtf = zlib.inflateSync(assembled.subarray(BLOB_HEADER_BYTES), { maxOutputLength: declaredVtf });
  } catch (error) {
    return { ok: false, reason: "inflate-failed" };
  }
  // Exactly, not at least: a blob that expands to less than it declared would
  // leave part of the texture unaccounted for.
  if (vtf.length !== declaredVtf) return { ok: false, reason: "wrong-inflated-size" };

  if (vtf.subarray(0, 4).toString("latin1") !== "VTF\0") return { ok: false, reason: "not-vtf" };

  const width = vtf.readUInt16LE(16);
  const height = vtf.readUInt16LE(18);
  if (width !== side || height !== side) return { ok: false, reason: "dimensions" };

  // Header must be byte-for-byte what the client's own writer produces for this
  // size. Everything except the pixels is settled here; only pixels are the
  // sender's to choose.
  const reference = Buffer.from(GOLDEN_VTF_HEADER);
  reference.writeUInt16LE(side, 16);
  reference.writeUInt16LE(side, 18);
  if (!vtf.subarray(0, VTF_HEADER_BYTES).equals(reference)) return { ok: false, reason: "header" };

  // The pixels must hash to the identifier the sender announced.
  const pixelBytes = side * side * 4;
  const rgba = swizzle(vtf.subarray(VTF_HEADER_BYTES, VTF_HEADER_BYTES + pixelBytes));
  if ((zlib.crc32(rgba) >>> 0) !== (declaredCrc >>> 0)) return { ok: false, reason: "pixel-crc" };

  return { ok: true, vtf, declaredVtf };
};

// Re-encode a validated VTF canonically with the current zlib (REENCODE_LEVEL)
// and return the blob to relay. inflate of this reproduces the identical VTF, so
// the client's header, size and pixel-crc checks all still pass (see the
// wire-compatibility note above).
//
//   { ok: true, blob }
//   { ok: false, reason: "too-long-after-reencode", length }
const reencode = (vtf, declaredVtf) => {
  const header = Buffer.alloc(BLOB_HEADER_BYTES);
  BLOB_MAGIC.copy(header, 0);
  header.writeUInt32LE(declaredVtf, 4);
  const blob = Buffer.concat([header, zlib.deflateSync(vtf, { level: REENCODE_LEVEL })]);

  // A picture whose canonical re-encode is larger than what a receiving client
  // accepts is refused - never relayed in its original encoding (that would hand
  // the old client zlib a stranger-crafted stream again).
  if (blob.length > limits.CLIENT_RECEIVE_MAX_BYTES) {
    return { ok: false, reason: "too-long-after-reencode", length: blob.length };
  }
  return { ok: true, blob };
};

// Both steps in one, for callers that do not need to budget the expensive half.
const validateAndReencode = (assembled, declaredCrc) => {
  const v = validate(assembled, declaredCrc);
  if (!v.ok) return v;
  return reencode(v.vtf, v.declaredVtf);
};

module.exports = {
  validate,
  reencode,
  validateAndReencode,
  REENCODE_LEVEL,
  swizzle,
  GOLDEN_VTF_HEADER,
  VTF_HEADER_BYTES,
  BLOB_MAGIC,
  BLOB_HEADER_BYTES,
  LEGAL_SIDES,
  LEGAL_VTF_SIZES,
};
