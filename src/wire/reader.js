"use strict";

// Reading side of the wire format.
//
// The layout is fixed by the compiled client: int32 is big endian, float is
// little endian, and a string is an int32 length followed by that many raw
// bytes read as latin1 (byte preserving in both directions, so the ANSI text
// the game sends survives the round trip).
//
// The reader is deliberately paranoid because it is the first thing an
// unauthenticated packet touches. Beyond the per-field length check that was
// always here, it also caps how many strings one datagram may contain and how
// many string bytes it may spend in total, so a datagram cannot buy an
// unbounded amount of work with a small number of bytes.

const limits = require("./limits");

class BufferReadError extends Error {}

class Message {
  constructor(buffer, info) {
    this.buffer = buffer;
    this.socket = info;
    this.offset = 0;
    this.stringCount = 0;
    this.stringBytes = 0;
    this.byteFieldCount = 0;
  }

  get remaining() {
    return this.buffer.length - this.offset;
  }

  ensure(n) {
    if (n < 0 || this.offset + n > this.buffer.length) {
      throw new BufferReadError(
        `read past end of packet (need ${n} byte(s) at offset ${this.offset}, length ${this.buffer.length})`
      );
    }
  }

  readUInt8() {
    this.ensure(1);
    const result = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return result;
  }

  readInt32() {
    this.ensure(4);
    const result = this.buffer.readInt32BE(this.offset);
    this.offset += 4;
    return result;
  }

  readFloat() {
    this.ensure(4);
    const result = this.buffer.readFloatLE(this.offset);
    this.offset += 4;
    return result;
  }

  readString(maxLength = limits.MAX_STRING_LENGTH) {
    if (this.stringCount >= limits.MAX_STRINGS_PER_DATAGRAM) {
      throw new BufferReadError(`too many strings in one packet (limit ${limits.MAX_STRINGS_PER_DATAGRAM})`);
    }

    const size = this.readInt32();
    // Negative lengths used to be the interesting case; the cap matters just as
    // much, because the length is attacker controlled and precedes the bytes.
    const cap = Math.min(maxLength, limits.MAX_STRING_LENGTH);
    if (size < 0 || size > cap) {
      throw new BufferReadError(`bad string length ${size} (limit ${cap})`);
    }
    this.ensure(size);

    this.stringCount += 1;
    this.stringBytes += size;
    if (this.stringBytes > limits.MAX_STRING_BYTES_PER_DATAGRAM) {
      throw new BufferReadError(
        `string budget exhausted (${this.stringBytes} > ${limits.MAX_STRING_BYTES_PER_DATAGRAM})`
      );
    }

    const string = this.buffer.toString("latin1", this.offset, this.offset + size);
    this.offset += size;
    return string;
  }

  // Raw bytes, as an int32 length followed by that many bytes.
  //
  // Kept out of the string path on purpose. latin1 is byte preserving, so a
  // spray chunk could travel as a string - but the string budget above is sized
  // for names and chat lines (six per datagram, 448 bytes in total), and one
  // chunk would spend all of it, leaving a legitimate packet no room. So this
  // has its own cap, passed by the caller, and its own counter: one byte field
  // per datagram, which is all any packet needs.
  //
  // The returned buffer is a copy. The datagram Node hands us is recycled, and
  // a spray chunk is held across ticks while the rest of it arrives.
  readBytes(maxLength) {
    if (this.byteFieldCount >= 1) {
      throw new BufferReadError("more than one byte field in one packet");
    }

    const size = this.readInt32();
    const cap = Math.min(maxLength === undefined ? limits.MAX_BYTES_FIELD : maxLength, limits.MAX_BYTES_FIELD);
    if (size < 0 || size > cap) {
      throw new BufferReadError(`bad byte field length ${size} (limit ${cap})`);
    }
    this.ensure(size);

    this.byteFieldCount += 1;
    const bytes = Buffer.from(this.buffer.subarray(this.offset, this.offset + size));
    this.offset += size;
    return bytes;
  }

  // Exactly n raw bytes with no length in front: protocol v2's 8-byte C and S.
  // The size is the caller's constant, never read from the packet, so unlike
  // readBytes this is not counted against the one-byte-field limit. Copied for
  // the same reason as readBytes: C outlives the datagram it arrived in.
  readFixed(n) {
    this.ensure(n);
    const bytes = Buffer.from(this.buffer.subarray(this.offset, this.offset + n));
    this.offset += n;
    return bytes;
  }

  // Steps over n bytes the caller has already checked in place: protocol v2's
  // S, compared on the raw datagram before the parse (server.js, hasToken).
  skip(n) {
    this.ensure(n);
    this.offset += n;
  }

  // Trailing fields older clients simply never send. `readOptional*` returns the
  // fallback when the packet ends, and still throws on a truncated field, so a
  // packet cut in the middle of a float is an error rather than a default.
  readOptionalUInt8(fallback) {
    if (this.remaining < 1) return fallback;
    return this.readUInt8();
  }

  readOptionalFloat(fallback) {
    if (this.remaining === 0) return fallback;
    return this.readFloat();
  }

  readOptionalString(maxLength, fallback) {
    if (this.remaining === 0) return fallback;
    return this.readString(maxLength);
  }
}

module.exports = { Message, BufferReadError };
