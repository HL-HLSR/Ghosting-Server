"use strict";

// The 1.4.0 identity block: the player's SteamID64 and whether the game was
// started from the HLSR launcher, appended to a protocol v2 announce.
//
//   "c" name 7xu8 u8(2) C(8) | u8(1) u8 flags SteamID64(8, big endian)
//
// flags bit 0: launched from HLSR; bit 1: a SteamID follows (zero otherwise).
//
// Every host before 1.4.0 stops reading a connect after C (1.3.x) or after the
// colours (1.2.0 and the 0.3.2 server), so the block costs them nothing; a 1.3
// client sends no block and is "unknown" here, exactly as before. Both values
// are the client's word - there is no Steam ticket behind the SteamID - so a
// SteamID ban or operator entry is as strong as the client is honest, and the
// tests below pin only what the host does with what it is told.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Readable } = require("stream");

const h = require("./helpers/harness");
const legacy = require("./helpers/legacy");
const packets = require("../src/wire/packets");
const { attach } = require("../src/console");
const { AccessList, KIND, normalizeSteamId } = require("../src/game/access");

const T = packets.TYPE;
const ALICE = h.from("10.0.0.1", 40001);
const ALICE2 = h.from("10.0.0.1", 40002);
const BOB = h.from("10.0.0.2", 40002);
const MALLORY = h.from("10.0.0.66", 40066);
const C_ALICE = Buffer.from("a1a2a3a4a5a6a7a8", "hex");
const C_ALICE2 = Buffer.from("a9aaabacadaeafa0", "hex");
const C_BOB = Buffer.from("b1b2b3b4b5b6b7b8", "hex");
const C_MAL = Buffer.from("e1e2e3e4e5e6e7e8", "hex");
const STEAM_ALICE = "76561198000000001";
const STEAM_BOB = "76561198000000002";
const PIN = "48291377";

const withConsole = (env) => {
  const rig = h.makeServer(env);
  const printed = [];
  const handle = attach(rig.server, { input: Readable.from([]), print: (line) => printed.push(line) });
  return Object.assign(rig, { printed, run: handle.handle });
};

// Announce, take S from the accept, confirm with a signed line. Returns S, or
// null when the host refused (a type 5 came back instead).
const joinV2 = (server, socket, name, rinfo, nonce, id) => {
  const mark = socket.sent.length;
  server.onDatagram(id === undefined ? h.connectV2(name, nonce) : h.connectV2Identity(name, nonce, id), rinfo);
  const replies = h.sentTo(socket, rinfo.address, rinfo.port, mark);
  const accept = replies.find((p) => p.buffer[0] === T.CONNECT_ACCEPTED);
  if (!accept) return null;
  const token = h.stripNonce(accept.buffer).rest;
  assert.strictEqual(server.onDatagram(h.withToken(h.update(name), token), rinfo), true);
  return token;
};

const kickText = (packet) => {
  const { rest } = h.stripNonce(packet.buffer);
  return rest.toString("latin1", 4);
};

const infoLines = (log) => log.lines.filter((l) => l[0] === "info").map((l) => l.slice(1));

// ---------------------------------------------------------------------------
// The block on the wire
// ---------------------------------------------------------------------------

test("a v2 announce with the identity block records HLSR and the SteamID", () => {
  const { server, socket, log } = h.makeServer();
  assert.ok(joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: STEAM_ALICE }));
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.protocol, 2);
  assert.strictEqual(alice.launcher, "hlsr");
  assert.strictEqual(alice.steamId, STEAM_ALICE);
  const registered = infoLines(log).find((args) => /^Registered/.test(args[0]));
  assert.ok(registered, "no Registered line");
  assert.match(registered.slice(1).join(" "), /HLSR/);
  assert.match(registered.slice(1).join(" "), new RegExp(STEAM_ALICE));
});

test("without bit 0 the player is not from HLSR; without bit 1 there is no SteamID", () => {
  const { server, socket } = h.makeServer();
  joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: false, steamId: STEAM_ALICE });
  joinV2(server, socket, "Bob", BOB, C_BOB, { hlsr: true });
  assert.strictEqual(server.users.get("Alice").launcher, "other");
  assert.strictEqual(server.users.get("Bob").launcher, "hlsr");
  assert.strictEqual(server.users.get("Bob").steamId, null);
  // bit 1 clear with bytes present: the bytes are ignored
  const { server: s2, socket: k2 } = h.makeServer();
  const raw = h.identity({ hlsr: false, steamId: STEAM_ALICE });
  raw[1] = 0;
  joinV2(s2, k2, "Carol", ALICE, C_ALICE, { raw });
  assert.strictEqual(s2.users.get("Carol").steamId, null);
});

test("a 1.3 client (v2 without the block) is unknown, not 'not HLSR'", () => {
  const { server, socket, log } = h.makeServer();
  joinV2(server, socket, "Alice", ALICE, C_ALICE);
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.launcher, null);
  assert.strictEqual(alice.steamId, null);
  const registered = infoLines(log).find((args) => /^Registered/.test(args[0]));
  assert.match(registered.slice(1).join(" "), /launcher unknown/);
});

test("the block is read only after a v2 tail: a legacy connect with the same bytes stays legacy and anonymous", () => {
  const { server, socket } = h.makeServer();
  server.onDatagram(Buffer.concat([h.connect("Alice"), h.identity({ hlsr: true, steamId: STEAM_ALICE })]), ALICE);
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.protocol, 1);
  assert.strictEqual(alice.launcher, null);
  assert.strictEqual(alice.steamId, null);
  assert.deepStrictEqual(h.sentTo(socket, ALICE.address, ALICE.port)[0].buffer, Buffer.from([T.CONNECT_ACCEPTED]));
});

test("a SteamID that is not an individual public account is dropped, the connect still accepted", () => {
  for (const bad of ["103582791429521408" /* a group */, "76561197960265728" /* account 0 */, "1"]) {
    const { server, socket } = h.makeServer();
    assert.ok(joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: bad }), bad);
    assert.strictEqual(server.users.get("Alice").steamId, null, bad);
    assert.strictEqual(server.users.get("Alice").launcher, "hlsr");
  }
});

test("another tag, or a block cut short, is no identity and no error", () => {
  const cases = [
    { raw: [7, 3, 1, 2, 3, 4, 5, 6, 7, 8] },
    { raw: [1, 3, 0x01, 0x10] },
    { raw: [1] },
  ];
  for (const id of cases) {
    const { server, socket } = h.makeServer();
    assert.ok(joinV2(server, socket, "Alice", ALICE, C_ALICE, id), JSON.stringify(id));
    const alice = server.users.get("Alice");
    assert.strictEqual(alice.protocol, 2);
    assert.strictEqual(alice.launcher, null);
    assert.strictEqual(alice.steamId, null);
    assert.strictEqual(server.stats.malformed, 0);
  }
});

test("the 0.3.2 server reads an announce with the identity block as it always did", () => {
  const { api } = legacy.load();
  const rinfo = { address: "10.0.0.77", port: 40077 };
  const buffer = h.connectV2Identity("BlockTester", C_ALICE, { hlsr: true, steamId: STEAM_ALICE });
  api.messageHandler.onMessage(new api.Message(buffer, rinfo));
  const user = api.userManager.getUser("BlockTester");
  assert.ok(user, "the 0.3.2 server did not register the announce");
  assert.strictEqual(user.ghostBlue, 30);
});

test("a duplicate connect does not change the identity a session announced with", () => {
  const { server, socket } = h.makeServer();
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: STEAM_ALICE });
  server.onDatagram(h.withToken(h.connectV2Identity("Alice", C_ALICE, { hlsr: false, steamId: STEAM_BOB }), token), ALICE);
  assert.strictEqual(server.users.get("Alice").steamId, STEAM_ALICE);
  assert.strictEqual(server.users.get("Alice").launcher, "hlsr");
});

// ---------------------------------------------------------------------------
// SteamIDs in the access lists
// ---------------------------------------------------------------------------

test("SteamIDs are accepted as SteamID64, STEAM_X:Y:Z and [U:1:N], and normalised to SteamID64", () => {
  assert.strictEqual(normalizeSteamId("76561198000000001"), "76561198000000001");
  assert.strictEqual(normalizeSteamId("STEAM_0:1:19867136"), "76561198000000001");
  assert.strictEqual(normalizeSteamId("STEAM_1:1:19867136"), "76561198000000001");
  assert.strictEqual(normalizeSteamId("[U:1:39734273]"), "76561198000000001");
  assert.strictEqual(normalizeSteamId(" 76561198000000001 "), "76561198000000001");
  for (const bad of ["", "7656119800000000", "765611980000000011", "103582791429521408", "76561197960265728",
    "STEAM_0:2:1", "[G:1:5]", "abc", null, undefined, 76561198000000001]) {
    assert.strictEqual(normalizeSteamId(bad), null, String(bad));
  }
});

test("bansteam refuses a connect carrying that SteamID and removes a connected one", () => {
  const { server, socket, run, printed } = withConsole();
  joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: STEAM_ALICE });
  joinV2(server, socket, "Bob", BOB, C_BOB, { hlsr: true, steamId: STEAM_BOB });
  run(`bansteam ${STEAM_ALICE} 2h cheating`);
  assert.strictEqual(server.users.get("Alice"), null, "the banned SteamID is still connected");
  assert.ok(server.users.get("Bob"));
  assert.match(printed.join("\n"), /Banned steamid '76561198000000001'/);

  // A new name and a new port do not help, as long as the client tells the truth.
  const mark = socket.sent.length;
  assert.strictEqual(joinV2(server, socket, "NotAlice", ALICE2, C_ALICE2, { hlsr: true, steamId: STEAM_ALICE }), null);
  const kick = h.sentTo(socket, ALICE2.address, ALICE2.port, mark).find((p) => p.buffer[0] === T.KICK);
  assert.ok(kick, "the refusal was not spoken");
  assert.match(kickText(kick), /^Banned: cheating/);

  // ...and the honest limit: a client that leaves the SteamID out walks past it.
  assert.ok(joinV2(server, socket, "NotAlice", ALICE2, C_ALICE2, { hlsr: true }));
});

test("bansteam \"Nick\" bans the SteamID that connected player reported; unbansteam lifts it", () => {
  const { server, socket, run, printed } = withConsole();
  joinV2(server, socket, "Alice", ALICE, C_ALICE, { steamId: STEAM_ALICE });
  run('bansteam "Alice"');
  assert.strictEqual(server.users.get("Alice"), null);
  assert.ok(server.access.banFor("Anyone", "10.9.9.9", STEAM_ALICE));
  run(`unbansteam ${STEAM_ALICE}`);
  assert.strictEqual(server.access.banFor("Anyone", "10.9.9.9", STEAM_ALICE), null);
  joinV2(server, socket, "Bob", BOB, C_BOB);
  run('bansteam "Bob"');
  assert.match(printed.join("\n"), /'Bob' reported no SteamID/);
  assert.ok(server.users.get("Bob"));
});

test("whitelist addsteam admits by SteamID; without one the whitelist refuses", () => {
  const { server, socket, run } = withConsole();
  run("whitelist on");
  run(`whitelist addsteam ${STEAM_ALICE}`);
  assert.ok(joinV2(server, socket, "Alice", ALICE, C_ALICE, { steamId: STEAM_ALICE }));
  assert.strictEqual(joinV2(server, socket, "Bob", BOB, C_BOB, { steamId: STEAM_BOB }), null);
  run(`whitelist removesteam ${STEAM_ALICE}`);
  assert.strictEqual(server.access.isAllowed("Zed", "10.9.9.9", STEAM_ALICE), false);
});

test("opsteam approves a v2 session with that SteamID when it confirms; commands need the PIN", () => {
  const { server, socket, run, printed } = withConsole();
  run(`opsteam ${STEAM_ALICE} ${PIN}`);
  assert.doesNotMatch(printed.join("\n"), new RegExp(PIN), "the PIN was printed");
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: STEAM_ALICE });
  joinV2(server, socket, "Bob", BOB, C_BOB, { steamId: STEAM_BOB });
  const alice = server.users.get("Alice");
  assert.strictEqual(server.operatorSessions.get(server.users.key("Alice")), alice);
  assert.strictEqual(alice.opBySteam, true);

  // Without the PIN: refused, Bob stays.
  server.onDatagram(h.withToken(h.chat("Alice", "/kick Bob"), token), ALICE);
  assert.ok(server.users.get("Bob"));
  // With it: done.
  server.onDatagram(h.withToken(h.chat("Alice", `/kick ${PIN} Bob`), token), ALICE);
  assert.strictEqual(server.users.get("Bob"), null);

  run("ops");
  const joined = printed.join("\n");
  assert.match(joined, /steamid '76561198000000001'/);
  assert.doesNotMatch(joined, new RegExp(PIN));
});

test("a SteamID operator is approved only once the v2 session confirms, never a forged announce", () => {
  const { server, socket, run } = withConsole();
  run(`opsteam ${STEAM_ALICE} ${PIN}`);
  server.onDatagram(h.connectV2Identity("Mallory", C_MAL, { steamId: STEAM_ALICE }), MALLORY);
  assert.strictEqual(server.operatorSessions.size, 0, "an announce that never signed is an operator");
});

test("five wrong PINs revoke a SteamID operator's session, and the log says so", () => {
  const { server, socket, run, log, clock } = withConsole();
  run(`opsteam ${STEAM_ALICE} ${PIN}`);
  const token = joinV2(server, socket, "Alice", ALICE, C_ALICE, { steamId: STEAM_ALICE });
  for (let i = 0; i < 5; i += 1) {
    clock.advance(1100); // the command budget, one a second
    server.onDatagram(h.withToken(h.chat("Alice", `/kick 000000${i}0 Bob`), token), ALICE);
  }
  assert.strictEqual(server.operatorSessions.size, 0);
  assert.ok(log.lines.some((l) => l[0] === "warn" && /wrong PINs/.test(l[1])));
});

test("opsteam needs a PIN unless OP_ALLOW_NO_PIN=1; deopsteam ends the live approval", () => {
  const strict = withConsole();
  strict.run(`opsteam ${STEAM_ALICE}`);
  assert.match(strict.printed.join("\n"), /PIN of 6-12 digits is required/);
  assert.strictEqual(strict.server.access.opForSteam(STEAM_ALICE), null);

  const open = withConsole({ OP_ALLOW_NO_PIN: "1" });
  open.run(`opsteam ${STEAM_ALICE}`);
  const token = joinV2(open.server, open.socket, "Alice", ALICE, C_ALICE, { steamId: STEAM_ALICE });
  joinV2(open.server, open.socket, "Bob", BOB, C_BOB);
  open.server.onDatagram(h.withToken(h.chat("Alice", "/kick Bob"), token), ALICE);
  assert.strictEqual(open.server.users.get("Bob"), null, "no-PIN operator could not kick");
  open.run(`deopsteam ${STEAM_ALICE}`);
  assert.strictEqual(open.server.operatorSessions.size, 0);
  assert.strictEqual(open.server.access.opForSteam(STEAM_ALICE), null);
});

test("opsteam \"Nick\" uses the SteamID that player reported and approves them at once", () => {
  const { server, socket, run } = withConsole();
  joinV2(server, socket, "Alice", ALICE, C_ALICE, { steamId: STEAM_ALICE });
  run(`opsteam "Alice" ${PIN}`);
  assert.ok(server.access.opForSteam(STEAM_ALICE));
  assert.strictEqual(server.operatorSessions.get(server.users.key("Alice")), server.users.get("Alice"));
});

test("the access file keeps steamid records, never the PIN, and reloads them", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghserver-steam-"));
  try {
    const file = path.join(dir, "access.json");
    const a = new AccessList({ maxNameLength: 31, now: () => 1000000, file });
    assert.strictEqual(a.ban(KIND.STEAMID, "STEAM_0:1:19867136", { reason: "x" }).ok, true);
    assert.strictEqual(a.whitelistAdd(KIND.STEAMID, STEAM_BOB).ok, true);
    assert.strictEqual(a.grantOpSteam(STEAM_ALICE, { pin: PIN }).ok, true);
    const text = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(text, new RegExp(PIN));
    assert.match(text, /"kind": "steamid"/);

    const b = new AccessList({ maxNameLength: 31, now: () => 1000000, file });
    b.load();
    assert.ok(b.banFor("x", "10.0.0.1", STEAM_ALICE));
    assert.ok(b.whitelist().some((r) => r.kind === KIND.STEAMID && r.value === STEAM_BOB));
    b.setWhitelist(true);
    assert.strictEqual(b.isAllowed("x", "10.0.0.1", STEAM_BOB), true);
    assert.strictEqual(b.isAllowed("x", "10.0.0.1", STEAM_ALICE), false);
    const op = b.opForSteam(STEAM_ALICE);
    assert.ok(op);
    assert.strictEqual(b.checkPin(op, PIN), true);
    assert.strictEqual(b.checkPin(op, "12345678"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("list shows HLSR, not HLSR and unknown, with the SteamID; status counts them", () => {
  const { server, socket, run, printed } = withConsole();
  joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: STEAM_ALICE });
  joinV2(server, socket, "Bob", BOB, C_BOB, { hlsr: false });
  server.onDatagram(h.connect("Carol"), h.from("10.0.0.3", 40003));
  server.onDatagram(h.update("Carol"), h.from("10.0.0.3", 40003));
  run("list");
  const joined = printed.join("\n");
  assert.match(joined, /Alice .*HLSR, steam 76561198000000001/);
  assert.match(joined, /Bob .*not HLSR, no SteamID/);
  assert.match(joined, /Carol .*launcher unknown/);
  printed.length = 0;
  run("status");
  assert.match(printed.join("\n"), /Launcher: 1 from HLSR, 1 not, 1 unknown; 1 with a SteamID/);
});
