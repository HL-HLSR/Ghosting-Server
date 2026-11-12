"use strict";

// Writing side of the wire format. Mirrors reader.js: int32 big endian, float
// little endian, string as int32 length plus latin1 bytes.
//
// The old writer concatenated a fresh Buffer per field, so a type 1 update
// allocated two dozen buffers and copied the accumulated packet each time. This
// one writes into a single scratch buffer and copies once at the end, which
// matters when the same packet is built for every player at 25 Hz.

const limits = require("./limits");
const { truncateBytes } = require("./text");

class BufferWriteError extends Error {}

class BufferWriter {
  constructor(capacity = limits.MAX_OUTBOUND_BYTES) {
    this.scratch = Buffer.allocUnsafe(capacity);
    this.length = 0;
  }

  room(n) {
    if (this.length + n > this.scratch.length) {
      throw new BufferWriteError(`outbound packet exceeds ${this.scratch.length} bytes`);
    }
  }

  writeInt8(value) {
    this.room(1);
    this.scratch.writeInt8(value, this.length);
    this.length += 1;
    return this;
  }

  writeUInt8(value) {
    this.room(1);
    this.scratch.writeUInt8(value & 0xff, this.length);
    this.length += 1;
    return this;
  }

  writeInt32(value) {
    this.room(4);
    this.scratch.writeInt32BE(value | 0, this.length);
    this.length += 4;
    return this;
  }

  writeFloat(value) {
    this.room(4);
    // Non-finite values must never reach a client: the ghost ends up at a NaN
    // position and the renderer follows it there.
    this.scratch.writeFloatLE(Number.isFinite(value) ? value : 0, this.length);
    this.length += 4;
    return this;
  }

  writeString(value, maxLength) {
    let text = value == null ? "" : String(value);
    // The limit counts bytes, because on the other end it is the size of a
    // char[] in the compiled client - but the bytes are UTF-8, so the cut has
    // to land on a character boundary. Slicing at the byte count left half a
    // Cyrillic letter at the end of every over-long nickname.
    if (maxLength !== undefined && text.length > maxLength) text = truncateBytes(text, maxLength);
    const bytes = Buffer.byteLength(text, "latin1");
    this.room(4 + bytes);
    this.scratch.writeUInt32BE(bytes, this.length);
    this.length += 4;
    this.scratch.write(text, this.length, bytes, "latin1");
    this.length += bytes;
    return this;
  }

  // Raw bytes, as an int32 length followed by that many bytes.
  //
  // Deliberately not writeString. A string is latin1 and byte preserving, so
  // binary would survive it - but the reader charges strings against a shared
  // budget sized for names and chat (six per datagram, 448 bytes total), and a
  // spray chunk would eat all of it. This is its own field with its own cap,
  // and only the spray packets use it.
  writeBytes(value, maxLength) {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value || []);
    if (maxLength !== undefined && bytes.length > maxLength) {
      throw new BufferWriteError(`byte field of ${bytes.length} exceeds ${maxLength}`);
    }
    this.room(4 + bytes.length);
    this.scratch.writeUInt32BE(bytes.length, this.length);
    this.length += 4;
    bytes.copy(this.scratch, this.length);
    this.length += bytes.length;
    return this;
  }

  // One copy, at the end. The returned buffer is independent of the scratch
  // space, so the writer can be reused or discarded freely.
  get buffer() {
    return Buffer.from(this.scratch.subarray(0, this.length));
  }
}

module.exports = { BufferWriter, BufferWriteError };
