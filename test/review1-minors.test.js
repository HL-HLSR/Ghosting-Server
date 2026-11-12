"use strict";

// Review 1, minor findings (server side): 2 (a goodbye lost to the shared events
// bucket), 4 (an old access file with a non-IPv4 row refusing to start),
// 5 (confusables the reserved-name skeleton missed), 10 (a duplicate connect
// re-sending a fully delivered spray), and the L1 symlink check that never ran.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { canonicalizeNickname, REASON } = require("../src/game/nickname");
const { AccessList, KIND } = require("../src/game/access");

const u = (s) => Buffer.from(s, "utf8").toString("latin1");

// --- minor 5 ---------------------------------------------------------------

test("minor 5: accented, Cherokee and small-capital lookalikes of SERVER are reserved", () => {
  for (const raw of [
    "SẸRVẸR", // dot below (Vietnamese; Tahoma/Verdana render it)
    "SÉRVÉR", // acute
    "SERVẸR",
    "ᏚᎬᏒᏙᎬᏒ", // Cherokee
    "ꜱᴇʀᴠᴇʀ", // small capitals
  ]) {
    const v = canonicalizeNickname(u(raw), 31);
    assert.strictEqual(v.reason, REASON.RESERVED, `${raw} was accepted`);
  }
  for (const raw of ["Renée", "Пётр", "Straße", "Servant", "Sever"]) {
    assert.strictEqual(canonicalizeNickname(u(raw), 31).ok, true, `${raw} was refused`);
  }
});

// --- minor 2 ---------------------------------------------------------------

test("minor 2: a goodbye is not lost after a player used up the events budget", () => {
  const { server, clock } = h.makeServer();
  const a = h.from("10.0.0.1", 40001);
  server.onDatagram(h.connect("Alice"), a);
  server.onDatagram(h.update("Alice"), a);
  const b = h.from("10.0.0.2", 40002);
  server.onDatagram(h.connect("Bob"), b);
  server.onDatagram(h.update("Bob"), b);
  // Spectate toggles spend the shared events bucket (burst 10).
  for (let i = 0; i < 12; i++) server.onDatagram(h.spectate("Alice", i % 2 ? "Bob" : ""), a);
  // The client sends 'd' exactly once.
  server.onDatagram(h.disconnect("Alice"), a);
  clock.advance(2500);
  assert.strictEqual(server.users.get("Alice"), null, "the single goodbye was dropped; the ghost would linger 60 s");
});

// --- minor 4 ---------------------------------------------------------------

test("minor 4: an access file with an IPv6 address row still loads", () => {
  const warnings = [];
  const list = new AccessList({ now: () => 1000, log: { warn: (...a) => warnings.push(a), error() {}, info() {} } });
  list.fromJSON({
    version: 1,
    whitelistEnabled: false,
    bans: [
      { kind: "address", value: "2001:db8::1", reason: "", until: 0 },
      { kind: "address", value: "203.0.113.4", reason: "", until: 0 },
      { kind: "name", value: "Griefer", reason: "", until: 0 },
    ],
    whitelist: [{ kind: "address", value: "fe80::1" }],
    ops: [],
  });
  assert.ok(list.banFor("x", "203.0.113.4"), "the IPv4 ban was lost");
  assert.ok(list.banFor("Griefer", "1.2.3.4"), "the name ban was lost");
  assert.strictEqual(list.bans().length, 2, "the IPv6 row should be dropped, not kept");
  assert.ok(warnings.length >= 1, "dropping a row must be warned about");
});

// --- minor 10 --------------------------------------------------------------

test("minor 10: a duplicate connect after full delivery re-sends nothing, even after the drip runs", () => {
  const { server, clock } = h.makeServer();
  const a = h.from("203.0.113.1", 1);
  const b = h.from("203.0.113.2", 2);
  server.onDatagram(h.connect("A"), a); server.onDatagram(h.update("A"), a);
  server.onDatagram(h.connect("B"), b); server.onDatagram(h.update("B"), b);
  const { blob, crc } = h.sprayBlob(64, 1, true);
  h.uploadSpray(server, a, "A", crc, blob);
  for (let i = 0; i < 400; i++) { clock.advance(20); server.onDatagram(h.update("B"), b); server.dripSprays(); }
  assert.strictEqual(server.users.get("B").sprayFeeds.size, 0);

  clock.advance(6000); // past the 5 s roster-resend throttle
  server.onDatagram(h.connect("B"), b);
  const before = server.socket.sent.length;
  for (let i = 0; i < 400; i++) { clock.advance(20); server.onDatagram(h.update("B"), b); server.dripSprays(); }
  const resent = server.socket.sent.slice(before)
    .filter((p) => p.address === b.address && p.buffer[0] === packets.TYPE.SPRAY_CHUNK).length;
  assert.strictEqual(resent, 0, `${resent} chunks of an already delivered picture were sent again`);
});

// --- L1, on Linux ----------------------------------------------------------

test("L1: saving never follows a symlink and leaves the file 0600", { skip: process.platform === "win32" && "symlinks need privileges on Windows" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghs-l1-"));
  const victim = path.join(dir, "victim");
  fs.writeFileSync(victim, "precious\n");
  const file = path.join(dir, "access.json");
  // A symlink planted at the old predictable temp name, and one at the file
  // itself: neither may be followed.
  fs.symlinkSync(victim, `${file}.tmp`);
  fs.symlinkSync(victim, file);
  const list = new AccessList({ now: Date.now, file });
  list.ban(KIND.NAME, "Griefer", {});
  assert.strictEqual(fs.readFileSync(victim, "utf8"), "precious\n", "a symlink was followed");
  assert.strictEqual(fs.lstatSync(file).isSymbolicLink(), false, "the access file is still the planted link");
  assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
  fs.rmSync(dir, { recursive: true, force: true });
});
