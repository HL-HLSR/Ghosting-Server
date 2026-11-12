"use strict";

// The lobby's 7TV emote pack (type 14), back in 1.3.2 as it was before L9.
//
// The host operator names one pack (EMOTE_PACK); the host never talks to 7TV
// and never carries artwork. Each joining session is sent that one identifier
// - ahead of its roster, and a legacy session once more when it confirms -
// and its client hands it to its own launcher. No client sends a pack: there
// is no opcode for it, in the old client or in the restored one, so nothing a
// datagram says can change the pack or make the host relay one.
//
// Protocol v2 adds only the usual C after the type byte (ruling D3). Every test
// in the rest of the suite runs with no pack configured and is unchanged by
// this feature, which is the point: a host that names no pack sends exactly
// what 1.3.1 sent.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const { Message } = require("../src/wire/reader");
const { BufferWriter } = require("../src/wire/writer");
const { load, ConfigError, normaliseEmotePack } = require("../src/config");
const { KIND } = require("../src/game/access");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);
const CAROL = h.from("10.0.0.3", 40003);
const C_ALICE = Buffer.from("a1a2a3a4a5a6a7a8", "hex");
const C_BOB = Buffer.from("b1b2b3b4b5b6b7b8", "hex");

const PACK = "set:01FE9DRF000009TR6M9N941CYW";
const WITH_PACK = { EMOTE_PACK: PACK };

const T = packets.TYPE;
const EMOTE = 14;

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

// What a v2 client does: announce, take S from the accept, then send its first
// position update with S (which confirms the session). Returns S.
const joinV2 = (server, socket, name, rinfo, nonce) => {
  const mark = socket.sent.length;
  server.onDatagram(h.connectV2(name, nonce), rinfo);
  const accept = h
    .sentTo(socket, rinfo.address, rinfo.port, mark)
    .find((packet) => packet.buffer[0] === T.CONNECT_ACCEPTED);
  assert.ok(accept, `${name} was not accepted`);
  const token = h.stripNonce(accept.buffer).rest;
  assert.strictEqual(server.onDatagram(h.withToken(h.update(name), token), rinfo), true);
  return token;
};

const typesTo = (socket, rinfo, since = 0) => h.sentTo(socket, rinfo.address, rinfo.port, since).map((p) => p.buffer[0]);
const packsTo = (socket, rinfo, since = 0) => h.sentTo(socket, rinfo.address, rinfo.port, since).filter((p) => p.buffer[0] === EMOTE);
const anyPack = (socket, since = 0) => socket.sent.slice(since).some((p) => p.buffer[0] === EMOTE);

// The payload as the client reads it: one sf::Packet string (u32 BE length +
// bytes) after the type byte - and, for a v2 session, after C.
const readPack = (buffer, v2) => new Message(buffer.subarray(v2 ? 9 : 1), {}).readString();

// The old client's GhPresence_IsValidEmoteSource (gh_presence.cpp before
// 51a8d1fb), which mirrored the launcher's EMOTE_SOURCE_RE: anything else the
// client throws away as "no pack". Every value the host can send must pass it.
const clientAccepts = (value) => {
  let rest = value;
  let alnum = false;
  let max = 20;
  if (rest.startsWith("twitch:")) rest = rest.slice(7);
  else if (rest.startsWith("set:")) [rest, alnum, max] = [rest.slice(4), true, 32];
  else if (rest.startsWith("user:")) [rest, alnum, max] = [rest.slice(5), true, 32];
  const ok = alnum ? /^[0-9A-Za-z]+$/ : /^[0-9]+$/;
  return rest.length >= 1 && rest.length <= max && ok.test(rest);
};

// ---------------------------------------------------------------------------
// Configuration: EMOTE_PACK is accepted again, with its 0.3.2 meaning and
// validation.
// ---------------------------------------------------------------------------

test("EMOTE_PACK is accepted again and normalised to the tagged form", () => {
  const ulid = "01FE9DRF000009TR6M9N941CYW";
  const objectId = "60ae3e98b2ecb0150535c6b7";
  const cases = {
    [`https://7tv.app/emote-sets/${ulid}`]: `set:${ulid}`,
    [`https://www.7tv.app/emote-sets/${ulid.toLowerCase()}/`]: `set:${ulid}`,
    [`http://7tv.app/emote-sets/${ulid}?tab=emotes#top`]: `set:${ulid}`,
    [`https://7tv.app/users/${ulid}`]: `user:${ulid}`,
    [`https://7tv.app/emote-sets/${objectId.toUpperCase()}`]: `set:${objectId}`,
    [`set:${ulid.toLowerCase()}`]: `set:${ulid}`,
    [`USER:${ulid}`]: `user:${ulid}`,
    [ulid]: `set:${ulid}`,
    [objectId]: `set:${objectId}`,
    "123456789": "twitch:123456789",
    "twitch:22484632": "twitch:22484632",
    [`  ${ulid}  `]: `set:${ulid}`,
  };
  for (const [raw, expected] of Object.entries(cases)) {
    assert.strictEqual(load({ EMOTE_PACK: raw }).emotePack, expected, raw);
    assert.strictEqual(normaliseEmotePack(raw.trim()), expected, raw);
  }
});

test("EMOTE_PACK unset, 0 or off means no pack", () => {
  assert.strictEqual(load({}).emotePack, null);
  assert.strictEqual(load({ EMOTE_PACK: "0" }).emotePack, null);
  assert.strictEqual(load({ EMOTE_PACK: "off" }).emotePack, null);
  assert.strictEqual(load({ EMOTE_PACK: " OFF " }).emotePack, null);
  assert.strictEqual(load({ EMOTE_PACK: "0" }).warnings.length, 0);
});

test("a malformed or oversized EMOTE_PACK stops startup and names the variable", () => {
  const bad = [
    "",
    "   ",
    "hello",
    "set:",
    "set:hello",
    "01FE9DRF000009TR6M9N941CY", // 25: one short of a ULID
    "01FE9DRF000009TR6M9N941CYWX", // 27: one too many
    "01FE9DRF000009TR6M9N941CYI", // I is not Crockford base32
    "60ae3e98b2ecb0150535c6b", // 23: one short of an ObjectID
    "01FE9DRF000009TR6M9N941CKW", // the Kelvin sign, which /i/u would fold to K
    "https://evil.example/emote-sets/01FE9DRF000009TR6M9N941CYW",
    "https://7tv.app/emotes/01FE9DRF000009TR6M9N941CYW",
    "javascript:alert(1)",
    // Surrounding whitespace is trimmed like every variable's; inside it is not.
    "set:01FE9DRF000009TR6M9N941CYW\nset:01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "set:01FE9DRF000009TR6M9N941CYW extra",
    "0123",
    "twitch:0",
    "1234567890123456", // 16 digits, longer than any Twitch id
    "x".repeat(1000),
    `set:${"0".repeat(1000)}`,
    "false",
  ];
  for (const raw of bad) {
    // Refused by the validation itself, not as a retired setting.
    assert.throws(
      () => load({ EMOTE_PACK: raw }),
      (error) =>
        error instanceof ConfigError && error.message.startsWith("EMOTE_PACK:") && !/no longer used/.test(error.message),
      JSON.stringify(raw)
    );
  }
});

test("a user link is accepted with a warning, an emote set without one", () => {
  const user = load({ EMOTE_PACK: "https://7tv.app/users/01FE9DRF000009TR6M9N941CYW" });
  assert.strictEqual(user.warnings.length, 1);
  assert.match(user.warnings[0], /^EMOTE_PACK=user:/);
  assert.strictEqual(load(WITH_PACK).warnings.length, 0);
});

test("the startup log names the pack, and says nothing about one when there is none", () => {
  const named = (log) => log.lines.some((line) => line[0] === "info" && /emote pack/i.test(String(line[1])) && line.includes(PACK));
  assert.strictEqual(named(h.makeServer(WITH_PACK).log), true);
  const quiet = h.makeServer({ EMOTE_PACK: "0" }).log;
  assert.strictEqual(quiet.lines.some((line) => /emote/i.test(line.join(" "))), false);
});

test("every pack the config can produce fits the client's buffer and passes its check", () => {
  const longest = [
    `user:${"Z".repeat(26)}`,
    `set:${"f".repeat(24)}`,
    `twitch:${"9".repeat(15)}`,
  ];
  for (const raw of longest) {
    const pack = load({ EMOTE_PACK: raw }).emotePack;
    assert.ok(Buffer.byteLength(pack) <= limits.MAX_EMOTE_PACK_LENGTH, `${pack} is longer than the client's buffer`);
    assert.ok(clientAccepts(pack), `the client would throw ${pack} away`);
  }
  // The bound is the client's char szPack[40] (gh_presence.cpp), so 39.
  assert.strictEqual(limits.MAX_EMOTE_PACK_LENGTH, 39);
});

// ---------------------------------------------------------------------------
// Wire: one tagged identifier, nothing else.
// ---------------------------------------------------------------------------

test("type 14 is the type byte and one string, and never longer than the client reads", () => {
  assert.strictEqual(T.EMOTE_PACK, EMOTE);
  const expected = new BufferWriter().writeInt8(14).writeString(PACK).buffer;
  assert.deepStrictEqual(packets.emotePack(PACK), expected);
  assert.strictEqual(packets.emotePack(PACK).length, 1 + 4 + PACK.length);

  const long = packets.emotePack("x".repeat(300));
  assert.strictEqual(long.readUInt32BE(1), limits.MAX_EMOTE_PACK_LENGTH);
  assert.strictEqual(long.length, 1 + 4 + limits.MAX_EMOTE_PACK_LENGTH);
});

// ---------------------------------------------------------------------------
// Delivery: who gets it, when, and in which framing.
// ---------------------------------------------------------------------------

test("with no pack configured, or EMOTE_PACK=0, no type 14 is ever sent", () => {
  for (const env of [{}, { EMOTE_PACK: "0" }, { EMOTE_PACK: "off" }]) {
    const { server, socket, clock } = h.makeServer(env);
    join(server, "Alice", ALICE);
    joinV2(server, socket, "Bob", BOB, C_BOB);
    server.onDatagram(h.connect("Carol"), CAROL);
    clock.advance(6000);
    server.onDatagram(h.connect("Alice"), ALICE); // a duplicate re-sends the roster
    server.onDatagram(h.update("Carol"), CAROL);
    assert.strictEqual(anyPack(socket), false, `a type 14 went out with ${JSON.stringify(env)}`);
    // ...and the connect path is the 1.3.1 one: accept and nothing else to a
    // legacy player alone on the host.
    const fresh = h.makeServer(env);
    fresh.server.onDatagram(h.connect("Dave"), ALICE);
    assert.deepStrictEqual(h.typesSent(fresh.socket), [T.CONNECT_ACCEPTED]);
  }
});

test("a legacy player gets the plain pack right after the accept, ahead of the roster", () => {
  const { server, socket } = h.makeServer(WITH_PACK);
  join(server, "Alice", ALICE);

  const mark = socket.sent.length;
  server.onDatagram(h.connect("Bob"), BOB);

  const toBob = h.sentTo(socket, BOB.address, BOB.port, mark);
  assert.deepStrictEqual(
    toBob.map((p) => p.buffer[0]),
    [T.CONNECT_ACCEPTED, EMOTE, T.CONNECT],
    "accept, then the pack, then the roster entry"
  );
  // Legacy framing: exactly what packets.js builds, nothing in front.
  assert.deepStrictEqual(toBob[1].buffer, packets.emotePack(PACK));
  assert.strictEqual(readPack(toBob[1].buffer, false), PACK);
});

test("a legacy player gets the pack a second time when its address confirms", () => {
  const { server, socket } = h.makeServer(WITH_PACK);
  server.onDatagram(h.connect("Alice"), ALICE);
  assert.deepStrictEqual(typesTo(socket, ALICE), [T.CONNECT_ACCEPTED, EMOTE]);

  // The mod announces itself once per session, so without this copy a pack
  // lost in the accept burst would be lost for the whole session.
  const mark = socket.sent.length;
  server.onDatagram(h.update("Alice"), ALICE);
  const after = packsTo(socket, ALICE, mark);
  assert.strictEqual(after.length, 1, "exactly one more copy at confirmation");
  assert.deepStrictEqual(after[0].buffer, packets.emotePack(PACK));

  // Confirmation happens once; later lines carry nothing.
  const later = socket.sent.length;
  for (let i = 0; i < 20; i++) server.onDatagram(h.update("Alice", { position: [i, 0, 0] }), ALICE);
  assert.strictEqual(packsTo(socket, ALICE, later).length, 0);
});

test("a v2 player gets 14 C payload at confirmation, ahead of its roster", () => {
  const { server, socket } = h.makeServer(WITH_PACK);
  join(server, "Bob", BOB);

  // Before its first packet with S a v2 session is sent the accept and nothing
  // else (ruling 11), the pack included.
  server.onDatagram(h.connectV2("Alice", C_ALICE), ALICE);
  assert.deepStrictEqual(typesTo(socket, ALICE), [T.CONNECT_ACCEPTED]);

  const mark = socket.sent.length;
  const token = server.users.get("Alice").serverToken;
  assert.strictEqual(server.onDatagram(h.withToken(h.update("Alice"), token), ALICE), true);
  const toAlice = h.sentTo(socket, ALICE.address, ALICE.port, mark);
  assert.deepStrictEqual(toAlice.map((p) => p.buffer[0]), [EMOTE, T.CONNECT], "the pack, then Bob's roster entry");

  // v2 framing: [14][C][payload], the payload byte for byte the legacy one.
  const pack = toAlice[0].buffer;
  const { type, nonce, rest } = h.stripNonce(pack);
  assert.strictEqual(type, EMOTE);
  assert.deepStrictEqual(nonce, C_ALICE);
  assert.deepStrictEqual(Buffer.concat([Buffer.from([type]), rest]), packets.emotePack(PACK));
  assert.strictEqual(readPack(pack, true), PACK);

  // Its own lines buy nothing more: the second copy waits for the heartbeat
  // (next test), and no clock has moved here.
  const later = socket.sent.length;
  for (let i = 0; i < 20; i++) server.onDatagram(h.withToken(h.update("Alice", { position: [i, 0, 0] }), token), ALICE);
  assert.strictEqual(packsTo(socket, ALICE, later).length, 0);
});

test("a v2 player gets its second copy with the next heartbeat, then the per-session bound holds", () => {
  const { server, socket, clock } = h.makeServer(WITH_PACK);
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  assert.strictEqual(packsTo(socket, ALICE).length, 1, "the copy with the roster, at confirmation");

  // 0.3.2 always sent two (5cdb708:807-814), so one lost datagram could not
  // lose the pack for the session; a v2 client never announces again. The
  // second rides the next heartbeat, as [14][C][payload].
  let mark = socket.sent.length;
  clock.advance(server.config.heartbeatMs);
  const second = packsTo(socket, ALICE, mark);
  assert.strictEqual(second.length, 1, "one more copy with the heartbeat");
  assert.deepStrictEqual(h.stripNonce(second[0].buffer).nonce, C_ALICE);
  assert.strictEqual(readPack(second[0].buffer, true), PACK);
  assert.ok(typesTo(socket, ALICE, mark).includes(T.HEARTBEAT), "it went with a heartbeat tick");

  // Exactly two: later heartbeats and lines carry none.
  mark = socket.sent.length;
  for (let i = 0; i < 10; i++) {
    server.onDatagram(h.withToken(h.update("Alice", { position: [i, 0, 0] }), token), ALICE);
    clock.advance(server.config.heartbeatMs);
  }
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0);

  // ...and the bound is the same one: nothing more this instant however often
  // the roster is re-sent, one copy once 5 s have passed since the last.
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.emotePackSends, 2);
  mark = socket.sent.length;
  for (let i = 0; i < 100; i++) server.sendRoster(alice);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 1, "20 s after the second copy, one more and no more");
  mark = socket.sent.length;
  for (let i = 0; i < 100; i++) server.sendRoster(alice);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0);
});

test("the heartbeat copy is due only once, only to v2, and never inside the same instant's bound", () => {
  const { server, socket, clock } = h.makeServer(WITH_PACK);
  join(server, "Bob", BOB); // legacy: its two copies already went
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const alice = server.users.get("Alice");

  // A roster re-sent before the heartbeat spends the second free copy; the
  // heartbeat then has nothing left to send inside the bound.
  server.sendRoster(alice);
  assert.strictEqual(packsTo(socket, ALICE).length, 2);
  let mark = socket.sent.length;
  clock.advance(server.config.heartbeatMs);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0, "the bound, not the heartbeat, decides");
  assert.strictEqual(packsTo(socket, BOB, mark).length, 0, "a legacy session gets no third copy");

  // Nothing is left due: 5 s later a heartbeat still sends nothing by itself.
  mark = socket.sent.length;
  server.onDatagram(h.withToken(h.update("Alice"), token), ALICE);
  clock.advance(6000);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0);
});

test("with EMOTE_PACK off no heartbeat ever carries a pack", () => {
  for (const env of [{}, { EMOTE_PACK: "0" }]) {
    const { server, socket, clock } = h.makeServer(env);
    joinV2(server, socket, "Alice", ALICE, C_ALICE);
    join(server, "Bob", BOB);
    clock.advance(server.config.heartbeatMs * 5);
    assert.strictEqual(anyPack(socket), false);
    assert.strictEqual(server.users.get("Alice").emotePackSends, 0);
  }
});

test("only the session that joins is sent the pack; a refused connect never is", () => {
  const { server, socket, clock } = h.makeServer(Object.assign({ MAX_PLAYERS: "3" }, WITH_PACK));
  join(server, "Alice", ALICE);
  joinV2(server, socket, "Bob", BOB, C_BOB);

  // The lobby is not sent the pack again when somebody else joins.
  const mark = socket.sent.length;
  join(server, "Carol", CAROL);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0);
  assert.strictEqual(packsTo(socket, BOB, mark).length, 0);
  assert.strictEqual(packsTo(socket, CAROL, mark).length, 2, "Carol: with her roster and at her confirmation");

  // Refusals: a name in use, a full server, a ban. Each is told why and is
  // sent nothing else - no pack.
  clock.advance(1000);
  const refused = socket.sent.length;
  const NAME_TAKEN = h.from("10.0.0.4", 40004);
  const FULL = h.from("10.0.0.5", 40005);
  const BANNED = h.from("10.0.0.6", 40006);
  server.onDatagram(h.connect("Alice"), NAME_TAKEN);
  server.onDatagram(h.connect("Dave"), FULL);
  server.access.ban(KIND.NAME, "Mallory");
  server.onDatagram(h.connect("Mallory"), BANNED);
  for (const rinfo of [NAME_TAKEN, FULL, BANNED]) {
    assert.deepStrictEqual(typesTo(socket, rinfo, refused), [T.KICK], `${rinfo.address} got more than a refusal`);
  }
  assert.strictEqual(anyPack(socket, refused), false);
});

test("the pack is charged first against the unconfirmed budget, so a big roster cannot crowd it out", () => {
  const { server, socket } = h.makeServer(Object.assign({ UNCONFIRMED_BUDGET_BYTES: "512" }, WITH_PACK));
  // Fifteen roster entries of ~44 bytes each are more than 512.
  for (let i = 0; i < 15; i++) join(server, `${"P".repeat(28)}${i}`, h.from(`10.0.1.${i + 1}`, 41000 + i));

  const mark = socket.sent.length;
  server.onDatagram(h.connect("Alice"), ALICE);
  const types = typesTo(socket, ALICE, mark);
  assert.deepStrictEqual(types.slice(0, 2), [T.CONNECT_ACCEPTED, EMOTE]);
  assert.ok(server.stats.reflectionBlocked > 0, "the budget must have bitten for this test to mean anything");
});

test("the pack never bypasses the unconfirmed budget: a spent budget stops a later copy", () => {
  // 520 = accept (1) + pack (35) + eleven 44-byte roster entries (31-byte
  // names), so the first burst spends the budget to the byte.
  const BUDGET = 520;
  const { server, socket, clock } = h.makeServer(Object.assign({ UNCONFIRMED_BUDGET_BYTES: String(BUDGET) }, WITH_PACK));
  for (let i = 0; i < 15; i++) join(server, `${"P".repeat(29)}${String(i).padStart(2, "0")}`, h.from(`10.0.1.${i + 1}`, 41000 + i));

  server.onDatagram(h.connect("Alice"), ALICE); // a legacy session that never confirms
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.confirmed, false);
  assert.strictEqual(alice.unconfirmedBytes, BUDGET, "the first burst must fill the budget exactly");
  assert.strictEqual(packsTo(socket, ALICE).length, 1);
  assert.strictEqual(alice.emotePackSends, 1, "a free copy is left, so only the budget can stop the next one");

  // A duplicate connect after 5 s re-sends the roster, pack first.
  clock.advance(5000);
  const blocked = server.stats.reflectionBlocked;
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Alice"), ALICE);
  assert.ok(server.stats.reflectionBlocked > blocked, "the roster resend must have been tried");
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0, "a type 14 went past the unconfirmed budget");
  assert.ok(alice.unconfirmedBytes <= BUDGET, `${alice.unconfirmedBytes} bytes sent to an unconfirmed session`);
  assert.strictEqual(alice.emotePackSends, 1, "a refused copy is not counted");
});

test("a forged legacy connect to an empty lobby gets at most 37 bytes; REQUIRE_PROTOCOL_V2 removes the pack", () => {
  // The smallest connect the mod can send: opcode "c" (5), a 1-byte name (5),
  // seven appearance bytes = 17. The longest pack the config produces.
  const longest = `user:${"Z".repeat(26)}`;
  const forged = h.connect("x");
  assert.strictEqual(forged.length, 17);

  const { server, socket } = h.makeServer({ EMOTE_PACK: longest });
  server.onDatagram(forged, ALICE);
  const bytes = socket.sent.reduce((sum, packet) => sum + packet.buffer.length, 0);
  assert.deepStrictEqual(h.typesSent(socket), [T.CONNECT_ACCEPTED, EMOTE]);
  assert.ok(bytes <= 37, `${bytes} bytes for a 17-byte connect`);

  // With legacy connects refused there is no session and no pack, only the refusal.
  const strict = h.makeServer({ EMOTE_PACK: longest, REQUIRE_PROTOCOL_V2: "1" });
  strict.server.onDatagram(forged, ALICE);
  assert.deepStrictEqual(h.typesSent(strict.socket), [T.KICK]);
});

// ---------------------------------------------------------------------------
// Bounds: a per-session rate, and nothing kept past the session.
// ---------------------------------------------------------------------------

test("however often a roster is re-sent, a session gets the pack at most once per 5 s after its first two", () => {
  const { server, socket, clock } = h.makeServer(WITH_PACK);
  const alice = join(server, "Alice", ALICE);
  assert.strictEqual(packsTo(socket, ALICE).length, 2);

  // Straight at the roster, past the duplicate-connect throttle that guards it
  // today: the pack's bound must not depend on its callers.
  let mark = socket.sent.length;
  for (let i = 0; i < 100; i++) server.sendRoster(alice);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0, "two copies already went out this instant");

  clock.advance(4999);
  mark = socket.sent.length;
  server.sendRoster(alice);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 0, "not before 5 s");

  clock.advance(1);
  mark = socket.sent.length;
  for (let i = 0; i < 100; i++) server.sendRoster(alice);
  assert.strictEqual(packsTo(socket, ALICE, mark).length, 1, "one copy per 5 s");

  // Through the wire: a duplicate-connect flood from the session's own endpoint
  // for 30 s buys at most one copy every 5 s.
  mark = socket.sent.length;
  for (let ms = 0; ms < 30000; ms += 100) {
    server.onDatagram(h.connect("Alice"), ALICE);
    clock.advance(100);
  }
  const resent = packsTo(socket, ALICE, mark).length;
  assert.ok(resent >= 1 && resent <= 6, `${resent} copies in 30 s`);
});

test("leaving keeps nothing: a rejoin is a newcomer and is sent the pack again", () => {
  const { server, socket, clock } = h.makeServer(WITH_PACK);
  join(server, "Alice", ALICE);
  assert.strictEqual(packsTo(socket, ALICE).length, 2);

  server.onDatagram(h.disconnect("Alice"), ALICE);
  clock.advance(2500);
  server.resolvePendingDrops();
  assert.strictEqual(server.users.get("Alice"), null);

  // At once, from the same endpoint: the per-session bound went with the
  // session, so the new one is fed in full.
  const mark = socket.sent.length;
  join(server, "Alice", ALICE);
  assert.deepStrictEqual(typesTo(socket, ALICE, mark).filter((type) => type === EMOTE).length, 2);
  assert.strictEqual(packsTo(socket, ALICE, mark)[0].buffer.equals(packets.emotePack(PACK)), true);
});

test("no datagram can set or relay a pack: a forged one from a v2 endpoint is a bad token", () => {
  const { server, socket } = h.makeServer(WITH_PACK);
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE);
  join(server, "Bob", BOB);
  const mark = socket.sent.length;
  const badBefore = server.stats.badToken;

  const OTHER = "set:01ARZ3NDEKTSV4RRFFQ69G5FAV";
  // Every shape a pack could arrive in: an opcode carrying one, and the
  // server-to-client type 14 sent back at the host.
  const opcodePack = (op) => new BufferWriter().writeString(op).writeString("Alice").writeString(OTHER).buffer;
  const rawPack = packets.emotePack(OTHER);

  // From the v2 session's endpoint, without S: dropped unparsed, never punished.
  for (const op of ["e", "14", "x"]) server.onDatagram(opcodePack(op), ALICE);
  server.onDatagram(rawPack, ALICE);
  assert.strictEqual(server.stats.badToken - badBefore, 4);

  // With S it is the real client's, and an opcode the host does not know.
  const unknownBefore = server.stats.unknownOpcode;
  server.onDatagram(h.withToken(opcodePack("e"), token), ALICE);
  // From a legacy session: the same, an unknown opcode.
  server.onDatagram(opcodePack("e"), BOB);
  assert.strictEqual(server.stats.unknownOpcode - unknownBefore, 2);

  assert.strictEqual(anyPack(socket, mark), false, "a type 14 went out");
  assert.strictEqual(server.config.emotePack, PACK, "the configured pack changed");
  assert.ok(server.users.get("Alice") && server.users.get("Bob"), "nobody was dropped");
  // 'i' is the 1.4.0 server browser query; it answers with name and counts only.
  for (const op of server.handlers.keys()) assert.ok("cvldmrspqi".includes(op) && op.length === 1, op);
});
