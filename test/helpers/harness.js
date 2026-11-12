"use strict";

// Test rig: a server with a fake socket and a clock the test controls.
//
// Nothing here binds a port. Time does not pass unless a test advances it, so
// rate limits, timeouts and race deadlines are exact rather than flaky.

const zlib = require("node:zlib");
const { load } = require("../../src/config");
const { GhostingServer } = require("../../src/server");
const { BufferWriter } = require("../../src/wire/writer");
const { Message } = require("../../src/wire/reader");
const sprayWire = require("../../src/wire/spray");

class FakeSocket {
  constructor() {
    this.sent = [];
    this.listeners = new Map();
    this.closed = false;
    this.bound = null;
  }

  on(event, fn) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(fn);
    return this;
  }

  once(event, fn) {
    const wrapped = (...args) => {
      this.removeListener(event, wrapped);
      fn(...args);
    };
    return this.on(event, wrapped);
  }

  removeListener(event, fn) {
    const list = this.listeners.get(event);
    if (!list) return this;
    const index = list.indexOf(fn);
    if (index >= 0) list.splice(index, 1);
    return this;
  }

  emit(event, ...args) {
    for (const fn of (this.listeners.get(event) || []).slice()) fn(...args);
  }

  bind(port, address) {
    this.bound = { port, address };
    // Synchronous so a test does not have to wait a tick to be listening.
    this.emit("listening");
  }

  // `buffer` may be a list of buffers, as dgram allows: one datagram, gathered.
  // The server sends a protocol v2 packet that way ([type, C, payload]) so the
  // payload a broadcast shares is never copied per receiver.
  send(buffer, port, address, callback) {
    if (this.closed) throw Object.assign(new Error("not running"), { code: "ERR_SOCKET_DGRAM_NOT_RUNNING" });
    const bytes = Array.isArray(buffer) ? Buffer.concat(buffer) : Buffer.from(buffer);
    this.sent.push({ buffer: bytes, port, address, to: `${address}:${port}` });
    if (callback) callback(this.failNext || null);
    this.failNext = null;
  }

  close(callback) {
    this.closed = true;
    if (callback) callback();
  }

  address() {
    return { address: this.bound ? this.bound.address : "0.0.0.0", port: this.bound ? this.bound.port : 0, family: "IPv4" };
  }
}

class Clock {
  constructor(start = 1000000) {
    this.value = start;
    this.intervals = [];
  }

  now() {
    return this.value;
  }

  // Advances time and fires any interval whose period has elapsed. Steps are
  // capped so a long jump does not run thousands of iterations.
  advance(ms) {
    const target = this.value + ms;
    while (this.value < target) {
      const step = Math.min(50, target - this.value);
      this.value += step;
      for (const timer of this.intervals) {
        if (timer.cancelled) continue;
        while (this.value - timer.last >= timer.ms) {
          timer.last += timer.ms;
          timer.fn();
        }
      }
    }
    this.value = target;
  }

  setInterval(fn, ms) {
    const timer = { fn, ms, last: this.value, cancelled: false };
    this.intervals.push(timer);
    return timer;
  }

  clearInterval(timer) {
    if (timer) timer.cancelled = true;
  }

  // Race countdowns use setTimeout. Tests that care about them drive `pending`
  // directly; tests that do not simply never fire them.
  setTimeout(fn, ms) {
    const timer = { fn, at: this.value + ms, cancelled: false };
    this.pending = this.pending || [];
    this.pending.push(timer);
    return timer;
  }

  clearTimeout(timer) {
    if (timer) timer.cancelled = true;
  }

  // Fire every timeout scheduled for a moment at or before now.
  runTimeouts() {
    const due = (this.pending || []).filter((t) => !t.cancelled && t.at <= this.value);
    this.pending = (this.pending || []).filter((t) => !due.includes(t));
    for (const timer of due) timer.fn();
    return due.length;
  }
}

const silentLogger = () => {
  const lines = [];
  return {
    lines,
    info: (...args) => lines.push(["info", ...args]),
    warn: (...args) => lines.push(["warn", ...args]),
    error: (...args) => lines.push(["error", ...args]),
    event: (code, detail) => {
      lines.push(["event", code, detail]);
      return true;
    },
    flush() {},
    counts: () => ({}),
  };
};

const makeServer = (env = {}) => {
  const config = load(Object.assign({}, env));
  const clock = new Clock();
  const socket = new FakeSocket();
  const log = silentLogger();
  const server = new GhostingServer({
    config,
    socket,
    log,
    now: () => clock.now(),
    // Сроки банов идут по настенным часам (см. access.js), поэтому тесту нужен
    // и этот. Файла у списка нет: ни один тест не должен писать на диск.
    wallNow: () => clock.now(),
    setInterval: (fn, ms) => clock.setInterval(fn, ms),
    clearInterval: (timer) => clock.clearInterval(timer),
  });
  // The race manager takes its timers from its own deps; point them at the
  // clock too so countdowns are deterministic.
  server.race.setTimer = (fn, ms) => clock.setTimeout(fn, ms);
  server.race.clearTimer = (timer) => clock.clearTimeout(timer);
  server.race.now = () => clock.now();

  server.start();
  return { server, socket, clock, log, config };
};

// ---------------------------------------------------------------------------
// Inbound packet builders: exactly what the mod's server.dll puts on the wire
// ---------------------------------------------------------------------------

const opcode = (writer, letter) => writer.writeString(letter);

const connect = (name, appearance = {}) => {
  const w = new BufferWriter();
  opcode(w, "c");
  w.writeString(name);
  w.writeUInt8(appearance.trailLength === undefined ? 12 : appearance.trailLength);
  w.writeUInt8(appearance.trailRed === undefined ? 255 : appearance.trailRed);
  w.writeUInt8(appearance.trailGreen === undefined ? 0 : appearance.trailGreen);
  w.writeUInt8(appearance.trailBlue === undefined ? 0 : appearance.trailBlue);
  w.writeUInt8(appearance.ghostRed === undefined ? 10 : appearance.ghostRed);
  w.writeUInt8(appearance.ghostGreen === undefined ? 20 : appearance.ghostGreen);
  w.writeUInt8(appearance.ghostBlue === undefined ? 30 : appearance.ghostBlue);
  return w.buffer;
};

// Protocol v2 announce: a legacy connect plus the tail u8(2) + C, where C is
// the client's 8-byte nonce for this connect. Written as given, so a test can
// pass an all-zero or short C to see it treated as legacy.
const connectV2 = (name, nonce, appearance = {}) =>
  Buffer.concat([connect(name, appearance), Buffer.from([2]), Buffer.from(nonce)]);

// 1.4.0 identity block, after the v2 tail: u8 tag (1), u8 flags (bit 0 launched
// from HLSR, bit 1 a SteamID follows), then the SteamID64 as 8 big-endian bytes
// (zero when there is none). `raw` lets a test write a malformed one.
const identity = ({ hlsr = false, steamId = null, tag = 1, flags, raw } = {}) => {
  if (raw) return Buffer.from(raw);
  const block = Buffer.alloc(10);
  block[0] = tag;
  block[1] = flags !== undefined ? flags : (hlsr ? 1 : 0) | (steamId ? 2 : 0);
  if (steamId) block.writeBigUInt64BE(BigInt(steamId), 2);
  return block;
};

// What the 1.4.0 mod announces: the v2 connect plus the identity block.
const connectV2Identity = (name, nonce, id = {}, appearance = {}) =>
  Buffer.concat([connectV2(name, nonce, appearance), identity(id)]);

// The server browser's query (1.4.0): opcode "i", u8 query version, u32 request
// id, u32 challenge (0 = none yet). 14 bytes.
const infoQuery = (requestId, challenge = 0, version = 1) => {
  const w = new BufferWriter();
  opcode(w, "i");
  w.writeUInt8(version);
  w.writeInt32(requestId | 0);
  w.writeInt32(challenge | 0);
  return w.buffer;
};

// Type 17: u32 request id, u32 challenge.
const readInfoChallenge = (buffer) => ({
  type: buffer.readUInt8(0),
  requestId: buffer.readUInt32BE(1),
  challenge: buffer.readUInt32BE(5),
  length: buffer.length,
});

// Type 18, read the way client.dll reads it: a plain cursor, because the reply
// carries more strings than the server's own inbound reader allows a datagram.
const readServerInfo = (buffer) => {
  let at = 1;
  const need = (n) => {
    if (at + n > buffer.length) throw new Error(`type 18 cut short at ${at} (+${n}) of ${buffer.length}`);
  };
  const u8 = () => { need(1); return buffer.readUInt8(at++); };
  const u32 = () => { need(4); const v = buffer.readUInt32BE(at); at += 4; return v; };
  const str = () => {
    const n = u32();
    need(n);
    const s = buffer.toString("latin1", at, at + n);
    at += n;
    return s;
  };
  const out = { type: buffer.readUInt8(0), length: buffer.length };
  out.requestId = u32();
  out.format = u8();
  out.name = str();
  out.version = str();
  out.protocol = u8();
  out.flags = u8();
  out.players = u8();
  out.maxPlayers = u8();
  out.race = u8();
  out.map = str();
  const listed = u8();
  out.list = [];
  for (let i = 0; i < listed; i += 1) {
    const name = str();
    const flags = u8();
    out.list.push({ name, flags });
  }
  out.rest = buffer.length - at;
  return out;
};

// A v2 client puts S right after the opcode string of everything it sends.
// The opcode is an sf::Packet string: an int32 length and that many bytes.
const withToken = (buffer, token) => {
  const end = 4 + buffer.readUInt32BE(0);
  return Buffer.concat([buffer.subarray(0, end), Buffer.from(token), buffer.subarray(end)]);
};

// The other direction: a packet to a v2 session is [type][C][payload].
const stripNonce = (buffer) => ({
  type: buffer.readUInt8(0),
  nonce: Buffer.from(buffer.subarray(1, 9)),
  rest: Buffer.from(buffer.subarray(9)),
});

// `fields` lets a test truncate the packet after any trailing optional field,
// which is how an older client's shorter update is reproduced.
const update = (name, options = {}) => {
  const o = Object.assign(
    {
      map: "d1_trainstation_01",
      velocity: [0, 0, 0],
      position: [0, 0, 0],
      pitch: 0,
      yaw: 0,
      paused: 0,
      weapon: 0,
      stats: [100, 50, 30, 90],
      heldModel: "",
      heldPos: [0, 0, 0],
      heldAng: [0, 0, 0],
      eyeZ: 64,
      upTo: "eyeZ",
    },
    options
  );

  const w = new BufferWriter();
  opcode(w, "l");
  w.writeString(name);
  w.writeString(o.map);
  for (const v of o.velocity) w.writeFloat(v);
  for (const v of o.position) w.writeFloat(v);
  w.writeFloat(o.pitch);
  w.writeFloat(o.yaw);
  if (o.upTo === "yaw") return w.buffer;
  w.writeUInt8(o.paused);
  if (o.upTo === "paused") return w.buffer;
  w.writeUInt8(o.weapon);
  if (o.upTo === "weapon") return w.buffer;
  for (const v of o.stats) w.writeFloat(v);
  if (o.upTo === "stats") return w.buffer;
  w.writeString(o.heldModel);
  for (const v of o.heldPos) w.writeFloat(v);
  for (const v of o.heldAng) w.writeFloat(v);
  if (o.upTo === "held") return w.buffer;
  w.writeFloat(o.eyeZ);
  return w.buffer;
};

const disconnect = (name) => {
  const w = new BufferWriter();
  opcode(w, "d");
  w.writeString(name);
  return w.buffer;
};

const chat = (name, text) => {
  const w = new BufferWriter();
  opcode(w, "m");
  w.writeString(name);
  w.writeString(text);
  return w.buffer;
};

// `times` is the trailing block a finishing client appends: its own run time in
// seconds, and LiveSplit's when it is mirroring one (-1 when it is not).
// Omitted entirely for a client built before those fields existed.
const checkpoint = (name, value, times) => {
  const w = new BufferWriter();
  opcode(w, "r");
  w.writeString(name);
  w.writeUInt8(value);
  if (times) {
    w.writeFloat(times.igt);
    if (times.liveSplit !== undefined) w.writeFloat(times.liveSplit);
  }
  return w.buffer;
};

const spectate = (name, target) => {
  const w = new BufferWriter();
  opcode(w, "s");
  w.writeString(name);
  w.writeString(target);
  return w.buffer;
};

// One piece of a spray upload. Field order matches onSprayChunk.
const sprayChunk = (name, crc, rawBytes, total, index, payload) => {
  const w = new BufferWriter();
  opcode(w, "p");
  w.writeString(name);
  w.writeInt32(crc);
  w.writeInt32(rawBytes);
  w.writeInt32(total);
  w.writeInt32(index);
  w.writeBytes(payload);
  return w.buffer;
};

const sprayStamp = (name, crc, x, y, z) => {
  const w = new BufferWriter();
  opcode(w, "q");
  w.writeString(name);
  w.writeInt32(crc);
  w.writeFloat(x);
  w.writeFloat(y);
  w.writeFloat(z);
  return w.buffer;
};

// A VALID wire blob (GHS1 + uint32-LE VTF size + deflated VTF) the strict
// server-side validator accepts, plus its pixel crc. The server now inspects
// every spray (audit M3), so a buffer of random bytes is refused; tests that
// want a publication to succeed build the picture with this. The VTF header is
// exactly what the mod's own GhSpray_BuildVTF writes (see src/wire/spray.js),
// and the pixels are arbitrary - it is only their crc that must match.
//
// Returns { blob, crc }. crc is the int32 the wire carries (zlib.crc32 is
// unsigned; the protocol writes it with writeInt32), so it compares equal to
// what the server reads back and stores.
const sprayBlob = (side = 8, fill = 7, noisy = false) => {
  const header = Buffer.from(sprayWire.GOLDEN_VTF_HEADER);
  header.writeUInt16LE(side, 16);
  header.writeUInt16LE(side, 18);
  const pixels = Buffer.alloc(side * side * 4);
  if (noisy) {
    // xorshift fill: near-incompressible, so the blob has many chunks (used by
    // the drip/trickle/memory tests). `fill` seeds it so distinct sprays differ.
    let x = (0x9e3779b9 ^ (fill * 0x85ebca6b)) >>> 0 || 1;
    for (let i = 0; i < pixels.length; i++) {
      x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
      pixels[i] = x & 0xff;
    }
  } else {
    for (let i = 0; i < pixels.length; i++) pixels[i] = (i * fill + 11) & 0xff;
  }
  const vtf = Buffer.concat([header, pixels]);
  const crc = zlib.crc32(sprayWire.swizzle(pixels)) | 0;
  const blobHeader = Buffer.alloc(sprayWire.BLOB_HEADER_BYTES);
  sprayWire.BLOB_MAGIC.copy(blobHeader, 0);
  blobHeader.writeUInt32LE(vtf.length, 4);
  // Built at the level the server re-encodes at (deterministic), so the blob the
  // lobby receives is byte-identical to this one.
  const blob = Buffer.concat([blobHeader, zlib.deflateSync(vtf, { level: sprayWire.REENCODE_LEVEL })]);
  return { blob, crc };
};

// A valid blob from caller-chosen pixels (BGRA, side*side*4 bytes), compressed
// at `level` - the way an attacker or an unusual client might encode it.
const sprayBlobFromPixels = (side, pixels, level = 9) => {
  const header = Buffer.from(sprayWire.GOLDEN_VTF_HEADER);
  header.writeUInt16LE(side, 16);
  header.writeUInt16LE(side, 18);
  const vtf = Buffer.concat([header, pixels]);
  const crc = zlib.crc32(sprayWire.swizzle(pixels)) | 0;
  const blobHeader = Buffer.alloc(sprayWire.BLOB_HEADER_BYTES);
  sprayWire.BLOB_MAGIC.copy(blobHeader, 0);
  blobHeader.writeUInt32LE(vtf.length, 4);
  return { blob: Buffer.concat([blobHeader, zlib.deflateSync(vtf, { level })]), crc };
};

// Uploads a spray paced the way the client sends it (25 pieces a second), so a
// picture longer than the upload burst still completes. Advances the clock.
const uploadSprayPaced = (server, clock, rinfo, name, crc, blob, chunkSize = 400) => {
  const total = Math.max(1, Math.ceil(blob.length / chunkSize));
  for (let i = 0; i < total; i++) {
    const piece = blob.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, blob.length));
    server.onDatagram(sprayChunk(name, crc, blob.length, total, i, piece), rinfo);
    clock.advance(40);
  }
  return total;
};

// Sends a whole spray, one datagram per piece, the way a client would.
const uploadSpray = (server, rinfo, name, crc, blob, chunkSize = 400) => {
  const total = Math.max(1, Math.ceil(blob.length / chunkSize));
  for (let i = 0; i < total; i++) {
    const piece = blob.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, blob.length));
    server.onDatagram(sprayChunk(name, crc, blob.length, total, i, piece), rinfo);
  }
  return total;
};

const from = (address, port) => ({ address, port, family: "IPv4", size: 0 });

// The writer refuses to put a non-finite float on the wire, which is correct
// for the server and useless for a test that needs to send one. This writes the
// raw bit pattern straight into a built packet.
//
// Layout of 'l' up to position.x: opcode string (5) + name string + map string
// + three velocity floats.
const pokeUpdateFloat = (buffer, name, map, field, value) => {
  const base = 5 + (4 + name.length) + (4 + map.length);
  const offsets = {
    "velocity.x": base,
    "position.x": base + 12,
    pitch: base + 24,
    yaw: base + 28,
    // paused and weapon are one byte each between yaw and the stats block
    hp: base + 34,
    eyeZ: buffer.length - 4,
  };
  const patched = Buffer.from(buffer);
  patched.writeFloatLE(value, offsets[field]);
  return patched;
};

// Decode a type 1 update the way the client does, so a test asserts on fields
// rather than on byte offsets it had to count by hand.
const readInfo = (buffer) => {
  const message = new Message(buffer.subarray(1), {});
  return { name: message.readString(), map: message.readString() };
};

// Packets sent to one destination since a marker index.
const sentTo = (socket, address, port, since = 0) =>
  socket.sent.slice(since).filter((packet) => packet.address === address && packet.port === port);

const typesSent = (socket, since = 0) => socket.sent.slice(since).map((packet) => packet.buffer.readUInt8(0));

module.exports = {
  FakeSocket,
  Clock,
  makeServer,
  silentLogger,
  connect,
  connectV2,
  identity,
  connectV2Identity,
  infoQuery,
  readInfoChallenge,
  readServerInfo,
  withToken,
  stripNonce,
  update,
  disconnect,
  chat,
  checkpoint,
  spectate,
  sprayChunk,
  sprayStamp,
  sprayBlob,
  sprayBlobFromPixels,
  uploadSpray,
  uploadSprayPaced,
  from,
  sentTo,
  typesSent,
  pokeUpdateFloat,
  readInfo,
};
