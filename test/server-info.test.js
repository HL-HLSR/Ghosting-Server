"use strict";

// The server browser's query (1.4.0).
//
// The mod's "Servers" dialog asks a host for its name, version, player count and
// lobby without joining it, the way the engine's server browser asks a Source
// server (A2S). That makes it a connectionless request from an address nobody
// has verified, which is exactly the shape of a reflection attack, so the design
// is A2S's:
//
//   - a bare query (challenge 0, or a wrong or stale one) is answered with a
//     9-byte challenge, smaller than the 14-byte query it answers;
//   - only a query carrying the challenge this host issued to that same
//     address:port, within its short life, gets the full reply - and the full
//     reply is capped at 512 bytes;
//   - every query goes through the ordinary inbound checks first (global
//     ceiling, penalty box, size, address and session budgets) and then through
//     a per-address and a global info budget of its own.
//
// Nothing about a query touches the roster: it creates no session, and nobody in
// the lobby is told about it.

const test = require("node:test");
const assert = require("node:assert");
const { Readable } = require("stream");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const pkg = require("../package.json");
const { attach } = require("../src/console");

const T = packets.TYPE;
const PF = packets.INFO_PLAYER_FLAG;
const SF = packets.INFO_SERVER_FLAG;

const BROWSER = h.from("198.51.100.7", 51000);
const BROWSER_OTHER_PORT = h.from("198.51.100.7", 51001);
const STRANGER = h.from("203.0.113.99", 51000);
const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);
const CAROL = h.from("10.0.0.3", 40003);
const DAN = h.from("10.0.0.4", 40004);
const C_ALICE = Buffer.from("a1a2a3a4a5a6a7a8", "hex");
const C_CAROL = Buffer.from("c1c2c3c4c5c6c7c8", "hex");
const C_DAN = Buffer.from("d1d2d3d4d5d6d7d8", "hex");
const STEAM_ALICE = "76561198000000001";
const STEAM_CAROL = "76561198000000003";

const sentSince = (socket, rinfo, mark) => h.sentTo(socket, rinfo.address, rinfo.port, mark);

// Asks once and returns what came back to that endpoint.
const ask = (server, socket, rinfo, requestId, challenge) => {
  const mark = socket.sent.length;
  server.onDatagram(h.infoQuery(requestId, challenge), rinfo);
  return sentSince(socket, rinfo, mark);
};

// The two-step exchange a browser makes: bare query, then the query with the
// challenge it was given. Returns the parsed type 18.
const query = (server, socket, rinfo, requestId = 1234) => {
  const first = ask(server, socket, rinfo, requestId, 0);
  assert.strictEqual(first.length, 1, "a bare query gets exactly one reply");
  const challenge = h.readInfoChallenge(first[0].buffer);
  assert.strictEqual(challenge.type, T.INFO_CHALLENGE);
  const second = ask(server, socket, rinfo, requestId, challenge.challenge);
  assert.strictEqual(second.length, 1, "a query with the challenge gets exactly one reply");
  assert.strictEqual(second[0].buffer[0], T.SERVER_INFO);
  return h.readServerInfo(second[0].buffer);
};

const joinV2 = (server, socket, name, rinfo, nonce, id) => {
  const mark = socket.sent.length;
  server.onDatagram(id ? h.connectV2Identity(name, nonce, id) : h.connectV2(name, nonce), rinfo);
  const accept = sentSince(socket, rinfo, mark).find((p) => p.buffer[0] === T.CONNECT_ACCEPTED);
  assert.ok(accept, `${name} was not accepted`);
  const token = h.stripNonce(accept.buffer).rest;
  assert.strictEqual(server.onDatagram(h.withToken(h.update(name), token), rinfo), true);
  return token;
};

const joinLegacy = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
};

test("a bare query gets only a challenge, smaller than the query", () => {
  const { server, socket } = h.makeServer();
  const queryBytes = h.infoQuery(77, 0).length;
  assert.strictEqual(queryBytes, 14);

  const replies = ask(server, socket, BROWSER, 77, 0);
  assert.strictEqual(replies.length, 1);
  const reply = h.readInfoChallenge(replies[0].buffer);
  assert.strictEqual(reply.type, T.INFO_CHALLENGE);
  assert.strictEqual(reply.length, 9);
  assert.ok(reply.length <= queryBytes, `challenge ${reply.length} B for a ${queryBytes} B query`);
  assert.strictEqual(reply.requestId, 77);
  assert.notStrictEqual(reply.challenge, 0);
  assert.strictEqual(socket.sent.some((p) => p.buffer[0] === T.SERVER_INFO), false);
});

test("the query with its challenge gets the server info", () => {
  const { server, socket } = h.makeServer();
  const info = query(server, socket, BROWSER, 0xfedcba98);
  assert.strictEqual(info.requestId, 0xfedcba98);
  assert.strictEqual(info.format, 1);
  assert.strictEqual(info.name, "Ghosting server");
  assert.strictEqual(info.version, pkg.version);
  assert.strictEqual(info.protocol, 2);
  assert.strictEqual(info.players, 0);
  assert.strictEqual(info.maxPlayers, 16);
  assert.strictEqual(info.race, packets.RACE_PHASE.idle);
  assert.strictEqual(info.map, "");
  assert.deepStrictEqual(info.list, []);
  assert.strictEqual(info.rest, 0);
  assert.strictEqual(info.flags & SF.STEAM_IDENTITY, SF.STEAM_IDENTITY);
  assert.strictEqual(info.flags & SF.OP_CHAT, SF.OP_CHAT);
  assert.strictEqual(info.flags & SF.REQUIRE_V2, 0);
  assert.strictEqual(info.flags & SF.WHITELIST, 0);
});

test("the version in the reply is package.json's, and it is 1.4.0", () => {
  assert.strictEqual(pkg.version, "1.4.0");
  const { server, socket } = h.makeServer();
  assert.strictEqual(query(server, socket, BROWSER).version, "1.4.0");
});

test("the challenge is bound to the address and port it was sent to", () => {
  const { server, socket } = h.makeServer();
  const first = h.readInfoChallenge(ask(server, socket, BROWSER, 5, 0)[0].buffer);

  for (const other of [BROWSER_OTHER_PORT, STRANGER]) {
    const replies = ask(server, socket, other, 5, first.challenge);
    assert.strictEqual(replies.length, 1);
    assert.strictEqual(replies[0].buffer[0], T.INFO_CHALLENGE, `${other.address}:${other.port} used someone else's challenge`);
  }
  assert.strictEqual(ask(server, socket, BROWSER, 5, first.challenge)[0].buffer[0], T.SERVER_INFO);
});

test("a challenge lives at most 30 seconds", () => {
  const { server, socket, clock } = h.makeServer();
  const c1 = h.readInfoChallenge(ask(server, socket, BROWSER, 1, 0)[0].buffer).challenge;
  clock.advance(14000);
  assert.strictEqual(ask(server, socket, BROWSER, 1, c1)[0].buffer[0], T.SERVER_INFO, "a 14 s old challenge still works");

  const c2 = h.readInfoChallenge(ask(server, socket, BROWSER, 2, 0)[0].buffer).challenge;
  clock.advance(server.infoChallengeLifeMs + 1);
  const late = ask(server, socket, BROWSER, 2, c2);
  assert.strictEqual(late.length, 1);
  assert.strictEqual(late[0].buffer[0], T.INFO_CHALLENGE, "an expired challenge gets a fresh one, not the info");
  assert.ok(server.infoChallengeLifeMs <= 30000);
});

test("wrong challenges get a fresh challenge, never the info, and are never punished", () => {
  const { server, socket, clock } = h.makeServer();
  for (let i = 0; i < 40; i += 1) {
    const replies = ask(server, socket, BROWSER, i, 0x1000 + i);
    // the per-address info budget answers some of them; none is ever the info
    for (const reply of replies) assert.strictEqual(reply.buffer[0], T.INFO_CHALLENGE);
    clock.advance(600);
  }
  assert.strictEqual(server.penalty.size, 0, "a stale challenge is not malformed traffic");
  assert.strictEqual(server.stats.malformed, 0);
  assert.strictEqual(socket.sent.some((p) => p.buffer[0] === T.SERVER_INFO), false);
});

test("the reply lists confirmed players with HLSR, operator, spectator and runner flags", () => {
  const { server, socket, clock } = h.makeServer({ SERVER_NAME: "Лаборатория призраков" });
  const tokenA = joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true, steamId: STEAM_ALICE });
  joinLegacy(server, "Bob", BOB);
  joinV2(server, socket, "Carol", CAROL, C_CAROL, { hlsr: false, steamId: STEAM_CAROL });
  const tokenD = joinV2(server, socket, "Dan", DAN, C_DAN, { hlsr: true });
  // A connect that never confirmed is not a player yet.
  server.onDatagram(h.connect("Ghostly"), h.from("10.0.0.9", 40009));

  assert.strictEqual(server.grantOp("Carol", { pin: "482913" }).ok, true);
  clock.advance(100);
  server.onDatagram(h.withToken(h.spectate("Dan", "Alice"), tokenD), DAN);
  server.onDatagram(h.withToken(h.chat("Alice", "/race"), tokenA), ALICE);

  const info = query(server, socket, BROWSER);
  assert.strictEqual(Buffer.from(info.name, "latin1").toString("utf8"), "Лаборатория призраков");
  assert.strictEqual(info.players, 4);
  assert.strictEqual(info.race, packets.RACE_PHASE.lobby);
  assert.strictEqual(info.map, "d1_trainstation_01");
  const by = Object.fromEntries(info.list.map((row) => [row.name, row.flags]));
  assert.deepStrictEqual(Object.keys(by).sort(), ["Alice", "Bob", "Carol", "Dan"]);

  assert.strictEqual(by.Alice & PF.HLSR, PF.HLSR);
  assert.strictEqual(by.Alice & PF.RUNNER, PF.RUNNER);
  assert.strictEqual(by.Alice & PF.IDENTIFIED, PF.IDENTIFIED);
  assert.strictEqual(by.Alice & PF.V2, PF.V2);
  assert.strictEqual(by.Alice & PF.OP, 0);

  assert.strictEqual(by.Bob, 0, "a legacy client reports nothing, so nothing is claimed for it");

  assert.strictEqual(by.Carol & PF.OP, PF.OP);
  assert.strictEqual(by.Carol & PF.HLSR, 0);
  assert.strictEqual(by.Carol & PF.IDENTIFIED, PF.IDENTIFIED);

  assert.strictEqual(by.Dan & PF.SPECTATING, PF.SPECTATING);
  assert.strictEqual(by.Dan & PF.HLSR, PF.HLSR);
  // No SteamID ever leaves the host in the reply.
  const reply = socket.sent[socket.sent.length - 1].buffer.toString("latin1");
  assert.strictEqual(reply.includes(STEAM_ALICE) || reply.includes(STEAM_CAROL), false);
});

test("the reply never exceeds 512 bytes, however many players and however long their names", () => {
  const longName = (i) => `${String(i).padStart(2, "0")}${"W".repeat(29)}`;
  const { server, socket } = h.makeServer({
    MAX_PLAYERS: "64",
    MAX_SESSIONS_PER_ADDRESS: "64",
    SERVER_NAME: "Я".repeat(31) + "x",
  });
  for (let i = 0; i < 64; i += 1) joinLegacy(server, longName(i), h.from(`10.1.${i}.1`, 30000 + i));
  assert.strictEqual(server.users.count(), 64);

  const info = query(server, socket, BROWSER);
  assert.ok(info.length <= limits.MAX_INFO_REPLY_BYTES, `reply ${info.length} B`);
  assert.strictEqual(limits.MAX_INFO_REPLY_BYTES, 512);
  assert.strictEqual(info.players, 64, "the count is the whole lobby");
  assert.ok(info.list.length > 0 && info.list.length < 64, `listed ${info.list.length}`);
  assert.ok(info.list.length <= limits.INFO_MAX_LISTED);
  assert.strictEqual(info.rest, 0);
  assert.strictEqual(Buffer.byteLength(info.name, "latin1"), 63);
});

test("one address gets a bounded number of replies however fast it asks", () => {
  const { server, socket } = h.makeServer();
  let replies = 0;
  for (let i = 0; i < 100; i += 1) replies += ask(server, socket, BROWSER, i, 0).length;
  assert.ok(replies <= server.config.infoBurst, `${replies} replies to one address in one instant`);
  assert.ok(replies >= 2, "a browser's two-step exchange fits in the burst");
  // Another address is not starved by it.
  assert.strictEqual(ask(server, socket, STRANGER, 1, 0).length, 1);
});

test("many addresses together get no more than the global info budget", () => {
  const { server, socket } = h.makeServer({ INFO_GLOBAL_PER_SECOND: "50" });
  let replies = 0;
  for (let i = 0; i < 400; i += 1) replies += ask(server, socket, h.from(`10.9.${i >> 8}.${i & 255}`, 9000), i, 0).length;
  assert.ok(replies <= 50, `${replies} replies in one instant against a global budget of 50`);
  assert.ok(server.stats.infoDropped >= 350);
});

test("a query is ordinary inbound traffic first: a truncated one is malformed, an oversized one is dropped", () => {
  const { server, socket } = h.makeServer();
  const short = h.infoQuery(1, 0).subarray(0, 10);
  assert.strictEqual(server.onDatagram(short, BROWSER), false);
  assert.strictEqual(server.stats.malformed, 1);

  const big = Buffer.concat([h.infoQuery(1, 0), Buffer.alloc(600)]);
  assert.strictEqual(server.onDatagram(big, STRANGER), false);
  assert.strictEqual(server.stats.oversized, 1);
  assert.strictEqual(socket.sent.length, 0);
});

test("a boxed address gets no info, beyond the trickle every boxed address gets", () => {
  const { server, socket, clock } = h.makeServer();
  for (let i = 0; i < 30; i += 1) server.onDatagram(Buffer.from([0, 0, 0, 0]), BROWSER);
  assert.ok(server.penalty.has(BROWSER.address), "the address was boxed");
  let replies = 0;
  for (let i = 0; i < 50; i += 1) {
    replies += ask(server, socket, BROWSER, i, 0).length;
    clock.advance(20);
  }
  assert.ok(replies <= 3, `${replies} replies to a boxed address in one second`);
});

test("a query creates no session and tells the lobby nothing", () => {
  const { server, socket } = h.makeServer();
  joinLegacy(server, "Bob", BOB);
  const mark = socket.sent.length;
  query(server, socket, BROWSER);
  assert.strictEqual(server.users.count(), 1);
  assert.strictEqual(sentSince(socket, BOB, mark).length, 0, "Bob was told something about a query");
});

test("from a v2 session's own endpoint a query without S is a bad token, unanswered", () => {
  const { server, socket } = h.makeServer();
  joinV2(server, socket, "Alice", ALICE, C_ALICE, { hlsr: true });
  const before = server.stats.badToken;
  assert.strictEqual(ask(server, socket, ALICE, 1, 0).length, 0);
  assert.strictEqual(server.stats.badToken, before + 1);
});

test("an unknown query version is ignored, not punished", () => {
  const { server, socket } = h.makeServer();
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.infoQuery(1, 0, 9), BROWSER), false);
  assert.strictEqual(socket.sent.length, mark);
  assert.strictEqual(server.stats.malformed, 0);
  assert.strictEqual(server.penalty.size, 0);
});

test("SERVER_INFO=0 answers nothing; SERVER_INFO_PLAYERS=0 sends the count without the names", () => {
  const off = h.makeServer({ SERVER_INFO: "0" });
  assert.strictEqual(ask(off.server, off.socket, BROWSER, 1, 0).length, 0);
  assert.strictEqual(off.server.stats.malformed, 0);

  const quiet = h.makeServer({ SERVER_INFO_PLAYERS: "0" });
  joinLegacy(quiet.server, "Bob", BOB);
  const info = query(quiet.server, quiet.socket, BROWSER);
  assert.strictEqual(info.players, 1);
  assert.deepStrictEqual(info.list, []);
});

test("SERVER_NAME is validated: Cyrillic is UTF-8 on the wire, control characters go, over 63 bytes is refused", () => {
  const { load, ConfigError } = require("../src/config");
  assert.strictEqual(load({}).serverName, "Ghosting server");
  const cyr = load({ SERVER_NAME: "Сервер №1" }).serverName;
  assert.strictEqual(Buffer.from(cyr, "latin1").toString("utf8"), "Сервер №1");
  assert.strictEqual(load({ SERVER_NAME: "a\tb\u0007c‮d" }).serverName, "a b cd");
  assert.throws(() => load({ SERVER_NAME: "Ж".repeat(32) }), ConfigError);
  assert.throws(() => load({ SERVER_NAME: "   " }), ConfigError);
  assert.doesNotThrow(() => load({ SERVER_NAME: "Ж".repeat(31) + "x" }));
});

test("the info budgets are live-tunable limits, and status counts the queries", () => {
  const { server, socket } = h.makeServer();
  const printed = [];
  const consoleHandle = attach(server, { input: Readable.from([]), print: (line) => printed.push(line) });
  const names = server.limitSnapshot().rows.map((row) => row.name);
  for (const name of ["info.rate", "info.burst", "info.global"]) assert.ok(names.includes(name), name);
  assert.strictEqual(server.setLimit("info.burst", 3).ok, true);
  query(server, socket, BROWSER);
  consoleHandle.handle("status");
  const joined = printed.join("\n");
  assert.match(joined, /Name: Ghosting server/);
  assert.match(joined, /Server info: 2 queries, 1 challenge\(s\), 1 reply/);
});
