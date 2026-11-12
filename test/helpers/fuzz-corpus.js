"use strict";

// Deterministic datagram generator.
//
// Deterministic on purpose: a fuzz run that finds a crash is only useful if the
// same seed reproduces it. The generator mixes pure noise with packets that are
// structurally believable, because the interesting bugs are not in "1000 random
// bytes", they are in "a real position update with one field corrupted".

const { BufferWriter } = require("../../src/wire/writer");

// xorshift32: small, fast, and identical on every platform and Node version.
const makeRandom = (seed) => {
  let state = seed >>> 0 || 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x100000000;
  };
};

const OPCODES = ["c", "l", "d", "m", "r", "s"];
const NAMES = ["Alice", "Bob", "SERVER", "", "__proto__", "x".repeat(200), "Ghost"];
const MAPS = ["d1_trainstation_01", "d3_breen_01", "unknown", "../../etc/passwd", "y".repeat(300)];

const pick = (random, list) => list[Math.floor(random() * list.length) % list.length];
const int = (random, max) => Math.floor(random() * max);

const noise = (random) => {
  const length = int(random, 700);
  const buffer = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i += 1) buffer[i] = int(random, 256);
  return buffer;
};

// A packet whose shape is right and whose contents are hostile.
const shaped = (random) => {
  const w = new BufferWriter(4096);
  const opcode = random() < 0.1 ? String.fromCharCode(int(random, 128)) : pick(random, OPCODES);
  w.writeString(opcode);
  w.writeString(pick(random, NAMES));

  if (opcode === "l") {
    w.writeString(pick(random, MAPS));
    for (let i = 0; i < 8; i += 1) w.writeFloat((random() - 0.5) * 1e9);
    if (random() < 0.8) w.writeUInt8(int(random, 256));
    if (random() < 0.8) w.writeUInt8(int(random, 256));
    if (random() < 0.7) for (let i = 0; i < 4; i += 1) w.writeFloat((random() - 0.5) * 1e9);
    if (random() < 0.6) {
      w.writeString(random() < 0.5 ? "models/props_c17/oildrum001.mdl" : "z".repeat(int(random, 150)));
      for (let i = 0; i < 6; i += 1) w.writeFloat((random() - 0.5) * 1e6);
    }
    if (random() < 0.5) w.writeFloat(random() * 300 - 50);
  } else if (opcode === "c") {
    for (let i = 0; i < 7; i += 1) w.writeUInt8(int(random, 256));
  } else if (opcode === "m") {
    w.writeString(random() < 0.3 ? "/" + pick(random, ["race", "ready", "nope"]) : "w".repeat(int(random, 200)));
  } else if (opcode === "r") {
    w.writeUInt8(int(random, 256));
  } else if (opcode === "s") {
    w.writeString(pick(random, NAMES));
  }

  return w.buffer;
};

// A believable packet with the tail chopped off at a random point, which is
// what a truncated or reordered datagram looks like.
const truncated = (random) => {
  const full = shaped(random);
  if (full.length <= 1) return full;
  return full.subarray(0, 1 + int(random, full.length - 1));
};

// A believable packet with a handful of bytes flipped: the case that reaches
// deepest into the parser before something goes wrong.
const corrupted = (random) => {
  const full = Buffer.from(shaped(random));
  const flips = 1 + int(random, 4);
  for (let i = 0; i < flips && full.length > 0; i += 1) {
    full[int(random, full.length)] = int(random, 256);
  }
  return full;
};

// Lengths chosen to sit exactly on a boundary the parser cares about.
const edge = (random) => {
  const cases = [
    Buffer.alloc(0),
    Buffer.from([0]),
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0xff, 0xff, 0xff, 0xff]),
    Buffer.from([0x80, 0x00, 0x00, 0x00]), // most negative int32 length
    Buffer.from([0x7f, 0xff, 0xff, 0xff]), // most positive int32 length
    Buffer.alloc(512),
    Buffer.alloc(513),
    Buffer.alloc(65507),
  ];
  return cases[int(random, cases.length)];
};

const generate = (random) => {
  const roll = random();
  if (roll < 0.3) return shaped(random);
  if (roll < 0.5) return corrupted(random);
  if (roll < 0.7) return truncated(random);
  if (roll < 0.9) return noise(random);
  return edge(random);
};

// Source addresses: a few repeat so rate limits and the penalty box are
// exercised, and many are unique so the bounded maps are exercised too.
const address = (random, index) => {
  if (random() < 0.4) return { address: `10.0.0.${1 + (index % 3)}`, port: 40000 + (index % 3), family: "IPv4" };
  return {
    address: `198.51.${int(random, 256)}.${int(random, 256)}`,
    port: 1024 + int(random, 60000),
    family: "IPv4",
  };
};

module.exports = { makeRandom, generate, address, shaped, corrupted, truncated, noise, edge };
