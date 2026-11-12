"use strict";

// Loads the pre-hardening server as a byte-for-byte reference.
//
// legacy/index.js is the exact file this rewrite replaced: 40570 bytes,
// sha256 95fbdd03f3c6871dea79575c4c7f1c5948cbde127d0373cae7033a59b2c84a0e.
// Nothing here retypes any of it, because a retyped reference proves nothing -
// the file is executed as it stands, in a sandbox where its socket, its
// console and its three timers are stubs, and the packet builders are pulled
// out of the sandbox afterwards.
//
// This is how the compatibility tests can claim "identical bytes" rather than
// "identical to how I remembered it".

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");

const LEGACY_PATH = path.join(__dirname, "..", "..", "legacy", "index.js");
const LEGACY_SHA256 = "95fbdd03f3c6871dea79575c4c7f1c5948cbde127d0373cae7033a59b2c84a0e";

// Appended to the original source so the sandbox can reach bindings that `const`
// and `class` keep in script scope. Nothing above this line is modified.
const EXPORTS = `
;globalThis.__legacy = {
  BufferWriter, User, Vector3, Message, MessageHandler,
  createChatBuffer, sanitizeText, isSaneNumber, socketKey, userManager, messageHandler,
  MAX_NAME_LENGTH, CHAT_MAX_LENGTH, RS,
  sendKick, sendConnectAccepted, sendForceMap, sendServerPause,
  broadcastRaceStatus, broadcastPlaySound, broadcastSpectate,
  __sent: () => globalThis.__captured,
};
`;

let cached = null;

const load = () => {
  if (cached) return cached;

  const source = fs.readFileSync(LEGACY_PATH);
  const digest = crypto.createHash("sha256").update(source).digest("hex");
  if (digest !== LEGACY_SHA256) {
    throw new Error(
      `legacy/index.js has changed (sha256 ${digest}). It is the frozen "before" copy ` +
        "and the whole point of the compatibility tests is that it does not move."
    );
  }

  const captured = [];
  const socket = {
    // The reference builds its packets and hands them to send(); capturing here
    // is how a builder that is not exposed directly still gets tested.
    send(buffer, port, address) {
      captured.push({ buffer: Buffer.from(buffer), port, address });
    },
    on() {},
    close() {},
    bind() {},
    address() {
      return { address: "0.0.0.0", port: 22228, family: "IPv4" };
    },
  };

  const sandbox = {
    Buffer,
    process: { env: {}, uptime: () => 0 },
    console: { log() {}, error() {} },
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    Date,
    Math,
    Number,
    Object,
    Set,
    Map,
    Error,
    JSON,
    String,
    RegExp,
    Array,
    globalThis: null,
    require: (name) => {
      if (name === "dgram") return { createSocket: () => socket };
      if (name === "readline") return { createInterface: () => ({ on() {}, close() {} }) };
      throw new Error(`legacy reference asked for an unexpected module: ${name}`);
    },
  };
  sandbox.globalThis = sandbox;
  sandbox.__captured = captured;

  vm.createContext(sandbox);
  vm.runInContext(source.toString("utf8") + EXPORTS, sandbox, { filename: "legacy/index.js" });

  cached = { api: sandbox.__legacy, captured, sha256: digest, bytes: source.length };
  return cached;
};

// The reference's helpers write straight to the socket. Run one and return the
// single buffer it produced.
const capture = (fn) => {
  const { captured } = load();
  const before = captured.length;
  fn();
  const produced = captured.slice(before);
  captured.length = before;
  if (produced.length !== 1) {
    throw new Error(`expected exactly one packet, got ${produced.length}`);
  }
  return produced[0].buffer;
};

module.exports = { load, capture, LEGACY_PATH, LEGACY_SHA256 };
