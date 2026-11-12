"use strict";

// Active nickname collision protection.
//
// Not authentication. The protocol carries a nickname and a source address and
// nothing else - no SteamID, no launcher token, no session secret, no
// signature - so nobody owns a name here, and nothing in this file should be
// read as saying they do. What it does check is that two people cannot be
// wearing the same name at the same time, including when the second one only
// changed the case or hid a soft hyphen in it.

const test = require("node:test");
const assert = require("node:assert");

const { canonicalizeNickname, nicknameKey, REASON } = require("../src/game/nickname");
const packets = require("../src/wire/packets");
const { makeServer, connect, update, chat, from } = require("./helpers/harness");

const SOFT = String.fromCharCode(0x00ad);

// Reason text of the last type 5 (kick) sent to a destination.
const kickReason = (socket, address, port) => {
  for (let i = socket.sent.length - 1; i >= 0; i -= 1) {
    const packet = socket.sent[i];
    if (packet.address !== address || packet.port !== port) continue;
    if (packet.buffer.readUInt8(0) !== 5) continue;
    const length = packet.buffer.readUInt32BE(1);
    return packet.buffer.toString("latin1", 5, 5 + length);
  }
  return null;
};

// ---------------------------------------------------------------------------
// The pure function
// ---------------------------------------------------------------------------

test("canonicalizeNickname folds case without touching the display name", () => {
  for (const raw of ["Aperture", "aperture", "APERTURE", "ApErTuRe"]) {
    const result = canonicalizeNickname(raw, 31);
    assert.strictEqual(result.ok, true, raw);
    assert.strictEqual(result.key, "APERTURE", raw);
    // The display name is what the player typed, not the key.
    assert.strictEqual(result.display, raw);
  }
});

test("canonicalizeNickname removes the soft hyphen and trims the edges", () => {
  assert.strictEqual(canonicalizeNickname("A" + SOFT + "lice", 31).key, "ALICE");
  assert.strictEqual(canonicalizeNickname("A" + SOFT + "lice", 31).display, "Alice");
  assert.strictEqual(canonicalizeNickname("  Alice  ", 31).display, "Alice");
  assert.strictEqual(canonicalizeNickname("  Alice  ", 31).key, "ALICE");
  // Control bytes were already the wire sanitiser's job; check it is still done.
  assert.strictEqual(canonicalizeNickname("Al" + String.fromCharCode(0x1b) + "ice", 31).key, "ALICE");
});

test("canonicalizeNickname refuses an empty result", () => {
  for (const raw of ["", "   ", SOFT, SOFT + SOFT, String.fromCharCode(0x00, 0x07)]) {
    const result = canonicalizeNickname(raw, 31);
    assert.strictEqual(result.ok, false, JSON.stringify(raw));
    assert.strictEqual(result.reason, REASON.EMPTY);
  }
});

test("canonicalizeNickname keeps different legal names different", () => {
  // No transliteration, no accent stripping, no punctuation stripping: these
  // are separate people and merging them would lock one of them out.
  const distinct = ["Renee", "Renée", "A.B", "AB", "Alice1", "Alice_", "Straße", "Strasse"];
  const keys = distinct.map((name) => canonicalizeNickname(name, 31).key);
  assert.strictEqual(new Set(keys).size, distinct.length, JSON.stringify(keys));
});

test("canonicalizeNickname folds latin1 accented letters one code point at a time", () => {
  // "é" and "É" are the same player; the fold must not change the length.
  assert.strictEqual(canonicalizeNickname("Renée", 31).key, canonicalizeNickname("RENÉE", 31).key);
  assert.strictEqual(canonicalizeNickname("Renée", 31).key.length, 5);
  // The two arithmetic signs inside the latin1 letter block are not letters.
  assert.strictEqual(canonicalizeNickname("a÷b", 31).key, "A÷B");
  assert.strictEqual(canonicalizeNickname("a×b", 31).key, "A×B");
});

test("canonicalizeNickname truncates to the DLL-compatible limit before keying", () => {
  const long = "A".repeat(40) + "b".repeat(40);
  const result = canonicalizeNickname(long, 31);
  assert.strictEqual(result.display.length, 31);
  assert.strictEqual(result.key, result.display.toUpperCase());
  assert.strictEqual(nicknameKey(result.display), result.key);
});

test("SERVER is refused in every case and with invisible characters", () => {
  const attempts = [
    "SERVER",
    "server",
    "Server",
    SOFT + "SERVER",
    "SER" + SOFT + "VER",
    "S-E-R-V-E-R",
    "  server  ",
    "S E R V E R",
    "[SERVER]",
  ];
  for (const raw of attempts) {
    const result = canonicalizeNickname(raw, 31);
    assert.strictEqual(result.ok, false, raw);
    assert.strictEqual(result.reason, REASON.RESERVED, raw);
  }
  // ...and a name that merely contains the letters is fine.
  assert.strictEqual(canonicalizeNickname("Servers", 31).ok, true);
  assert.strictEqual(canonicalizeNickname("Observer", 31).ok, true);
});

// ---------------------------------------------------------------------------
// The roster
// ---------------------------------------------------------------------------

const join = (rig, name, port, address = "10.0.0.1") => {
  const socket = from(address, port);
  const handled = rig.server.onDatagram(connect(name), socket);
  return { handled, socket };
};

// Registers a player and gets them confirmed, which is what an ordinary session
// looks like a frame after connecting.
const joinConfirmed = (rig, name, port, address = "10.0.0.1") => {
  const result = join(rig, name, port, address);
  rig.server.onDatagram(update(name), result.socket);
  return result;
};

for (const [label, second] of [
  ["Alice", "Alice"],
  ["Alice", "alice"],
  ["Alice", "ALICE"],
  ["Alice", "A" + SOFT + "lice"],
]) {
  test(`'${label}' then '${JSON.stringify(second).slice(1, -1)}' - the second is refused`, () => {
    const rig = makeServer();
    joinConfirmed(rig, "Alice", 40001, "10.0.0.1");
    assert.strictEqual(rig.server.users.count(), 1);

    const mark = rig.socket.sent.length;
    const handled = rig.server.onDatagram(connect(second), from("10.0.0.2", 40002));

    assert.strictEqual(handled, false);
    assert.strictEqual(rig.server.users.count(), 1, "a refused connect must not add a roster entry");
    assert.strictEqual(rig.server.users.get("Alice").socket.port, 40001, "the original session is untouched");
    assert.match(kickReason(rig.socket, "10.0.0.2", 40002) || "", /already in use/);
    // No fan-out to the rest of the server, and nothing of the newcomer's
    // choosing relayed to anyone.
    const broadcast = rig.socket.sent.slice(mark).filter((p) => p.address === "10.0.0.1");
    assert.strictEqual(broadcast.length, 0);
  });
}

test("the rejection message fits the buffer the client reads it into", () => {
  // client.dll copies a kick reason into char[64]; packets.js truncates to fit,
  // which would silently cut the sentence short. At the configured name length
  // it must not have to.
  const name = "A".repeat(31);
  const text = `Nickname '${name}' is already in use.`;
  assert.strictEqual(text.length, 61);
  const buffer = packets.kick(text);
  const length = buffer.readUInt32BE(1);
  assert.strictEqual(buffer.toString("latin1", 5, 5 + length), text, "the reason was truncated");
});

test("the first player's display name is what the roster and chat carry", () => {
  const rig = makeServer();
  joinConfirmed(rig, "Aperture", 40001, "10.0.0.1");
  rig.server.onDatagram(connect("APERTURE"), from("10.0.0.2", 40002));

  assert.deepStrictEqual(rig.server.users.names(), ["Aperture"]);
  assert.strictEqual(rig.server.users.get("aperture").name, "Aperture");
  assert.strictEqual(rig.server.users.get("APERTURE").name, "Aperture");

  // A chat line sent under a differently-cased name goes out under the roster's
  // name, so nobody can make "APERTURE" appear in anyone's chat window.
  rig.clock.advance(1000);
  const mark = rig.socket.sent.length;
  rig.server.onDatagram(chat("APERTURE", "hello"), from("10.0.0.1", 40001));
  const line = rig.socket.sent.slice(mark).find((p) => p.buffer.readUInt8(0) === 6);
  assert.ok(line, "no chat packet was relayed");
  const nameLength = line.buffer.readUInt32BE(5);
  assert.strictEqual(line.buffer.toString("latin1", 9, 9 + nameLength), "Aperture");
});

test("a different legal nickname is not blocked", () => {
  const rig = makeServer();
  joinConfirmed(rig, "Alice", 40001, "10.0.0.1");
  const handled = rig.server.onDatagram(connect("Alicia"), from("10.0.0.2", 40002));
  assert.strictEqual(handled, true);
  assert.strictEqual(rig.server.users.count(), 2);
  assert.deepStrictEqual(rig.server.users.names().sort(), ["Alice", "Alicia"]);
});

test("takeover still works on the old timeouts, and folds case too", () => {
  const rig = makeServer();
  joinConfirmed(rig, "Alice", 40001, "10.0.0.1");

  // Too soon: the same address may not take the name yet.
  rig.clock.advance(rig.config.takeoverAfterMs - 1000);
  assert.strictEqual(rig.server.onDatagram(connect("ALICE"), from("10.0.0.1", 40009)), false);
  assert.strictEqual(rig.server.users.get("Alice").socket.port, 40001);

  // Past takeoverAfterMs the same address reclaims it, under the new spelling.
  rig.clock.advance(2000);
  assert.strictEqual(rig.server.onDatagram(connect("ALICE"), from("10.0.0.1", 40009)), true);
  assert.strictEqual(rig.server.users.count(), 1, "a takeover replaces, never duplicates");
  const user = rig.server.users.get("alice");
  assert.strictEqual(user.socket.port, 40009);
  assert.strictEqual(user.name, "ALICE", "the new holder's own spelling is what everyone now sees");
  assert.strictEqual(user.confirmed, false, "a taken-over session starts unconfirmed");
});

test("a stranger's address still has to wait out the full stale timeout", () => {
  const rig = makeServer();
  joinConfirmed(rig, "Alice", 40001, "10.0.0.1");

  rig.clock.advance(rig.config.takeoverAfterMs + 1000);
  assert.strictEqual(rig.server.onDatagram(connect("alice"), from("10.9.9.9", 41000)), false);
  assert.strictEqual(rig.server.users.get("Alice").socket.address, "10.0.0.1");

  rig.clock.advance(rig.config.staleTimeoutMs);
  assert.strictEqual(rig.server.onDatagram(connect("alice"), from("10.9.9.9", 41000)), true);
  assert.strictEqual(rig.server.users.count(), 1);
});

test("a refused newcomer cannot evict the player who is already here", () => {
  const rig = makeServer();
  joinConfirmed(rig, "Alice", 40001, "10.0.0.1");
  const before = rig.server.users.get("Alice");

  for (const attempt of ["alice", "ALICE", "A" + SOFT + "LICE", "  alice  "]) {
    rig.clock.advance(6000); // past the connect budget's refill
    rig.server.onDatagram(connect(attempt), from("10.0.0.2", 40002));
  }

  assert.strictEqual(rig.server.users.count(), 1);
  assert.strictEqual(rig.server.users.get("Alice"), before, "the same user object, never re-registered");
  assert.strictEqual(before.socket.port, 40001);
  // And no type 4 (disconnect) was announced for a player who never left.
  assert.strictEqual(rig.socket.sent.some((p) => p.buffer.readUInt8(0) === 4), false);
});

test("one socket cannot hold two nicknames at once", () => {
  const rig = makeServer();
  const socket = from("10.0.0.1", 40001);
  rig.server.onDatagram(connect("Alice"), socket);
  rig.server.onDatagram(update("Alice"), socket);
  assert.strictEqual(rig.server.users.count(), 1);

  // A genuinely different name from the same endpoint replaces the first.
  rig.clock.advance(6000);
  rig.server.onDatagram(connect("Bob"), socket);
  assert.strictEqual(rig.server.users.count(), 1);
  assert.deepStrictEqual(rig.server.users.names(), ["Bob"]);
  assert.strictEqual(rig.server.users.bySocketKey("10.0.0.1:40001").name, "Bob");
  assert.strictEqual(rig.server.users.exists("Alice"), false);

  // A re-spelling of the same name is a rename of one session, not a second.
  rig.clock.advance(6000);
  rig.server.onDatagram(connect("BOB"), socket);
  assert.strictEqual(rig.server.users.count(), 1);
  assert.strictEqual(rig.server.users.bySocket.size, 1, "no orphan in the reverse index");
});

test("every lookup a handler makes resolves to the one user record", () => {
  const rig = makeServer();
  const socket = from("10.0.0.1", 40001);
  rig.server.onDatagram(connect("Alice"), socket);
  const user = rig.server.users.get("Alice");

  // Each of these used to key its own bookkeeping off the name in the packet.
  rig.clock.advance(100);
  assert.strictEqual(rig.server.onDatagram(update("ALICE"), socket), true);
  rig.clock.advance(1000);
  assert.strictEqual(rig.server.onDatagram(chat("alice", "hi"), socket), true);
  rig.clock.advance(1000);
  rig.server.onDatagram(require("./helpers/harness").spectate("aLiCe", ""), socket);

  assert.strictEqual(rig.server.users.count(), 1);
  assert.strictEqual(rig.server.users.get("Alice"), user);
  assert.strictEqual(user.confirmed, true);

  // A disconnect under another spelling files the pending drop under the
  // roster's name, so the resolver actually finds it.
  rig.clock.advance(1000);
  rig.server.onDatagram(require("./helpers/harness").disconnect("ALICE"), socket);
  assert.deepStrictEqual(Array.from(rig.server.pendingDrops.keys()), ["Alice"]);
  rig.clock.advance(3000);
  rig.server.resolvePendingDrops();
  assert.strictEqual(rig.server.users.count(), 0);
});

test("a race is driven by the roster name, whatever the packets are spelled like", () => {
  const rig = makeServer();
  const a = from("10.0.0.1", 40001);
  rig.server.onDatagram(connect("Alice"), a);
  rig.server.onDatagram(update("Alice"), a);

  rig.clock.advance(1000);
  rig.server.onDatagram(chat("ALICE", "/race"), a);
  assert.deepStrictEqual(rig.server.race.snapshot().runners, ["Alice"]);

  rig.clock.advance(1000);
  rig.server.onDatagram(require("./helpers/harness").checkpoint("alice", 1), a);
  // Not staged: the race is still in the lobby. What matters here is that no
  // second runner called "alice" appeared.
  assert.deepStrictEqual(rig.server.race.snapshot().runners, ["Alice"]);
});

// ---------------------------------------------------------------------------
// M5: homoglyph "SERVER" and bidi / invisible marks
// ---------------------------------------------------------------------------

// The wire carries UTF-8 as a latin1 byte string (see nickname.js), so a test
// that wants a multi-byte character has to present it the same way.
const u = (s) => Buffer.from(s, "utf8").toString("latin1");

test("a homoglyph SERVER is refused as reserved", () => {
  const reserved = [
    "SERVER",                 // plain
    u("SЕRVЕR"),    // Cyrillic Ye for both E
    u("ＳＥＲＶＥＲ"), // fullwidth
    u("ЅERVER"),         // Cyrillic Dze for S
    u("SΕRVER"),         // Greek Epsilon for E
    u("SERVER‮"),        // trailing RLO
    u("‎SERVER"),        // leading LRM
  ];
  for (const raw of reserved) {
    const v = canonicalizeNickname(raw, 31);
    assert.strictEqual(v.ok, false, `${JSON.stringify(raw)} should be refused`);
    assert.strictEqual(v.reason, REASON.RESERVED);
  }
});

test("real names that merely resemble nothing reserved are still accepted", () => {
  for (const raw of [u("Renée"), u("Pёtr"), u("Straße"), "Server1", "aServer", u("Сergey")]) {
    const v = canonicalizeNickname(raw, 31);
    assert.strictEqual(v.ok, true, `${JSON.stringify(raw)} should be accepted`);
  }
});

test("bidi and invisible marks are stripped from the display name", () => {
  // An RLO in the middle of a name is removed, not kept and rendered.
  const v = canonicalizeNickname(u("Ap‮erture"), 31);
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.display, "Aperture");
  // A Hangul filler used to pass as an "invisible" character.
  assert.strictEqual(canonicalizeNickname(u("Bobㅤ"), 31).display, "Bob");
});

test("bidi controls are stripped from chat", () => {
  const { sanitizeChat } = require("../src/wire/text");
  const out = sanitizeChat(u("hello ‮world"));
  assert.strictEqual(out, "hello world");
  // A valid Cyrillic line is untouched (its bytes are not bidi controls).
  assert.strictEqual(sanitizeChat(u("привет")), u("привет"));
});
