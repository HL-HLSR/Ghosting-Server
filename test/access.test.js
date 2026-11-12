"use strict";

// Bans, the whitelist, operators, and the chat commands an operator gets.
//
// Two things are being pinned here. The first is that a ban is not a kick: it
// has to survive the player reconnecting, the process restarting, and the
// player holding down shift while typing their nickname. The second is the
// honest limit of all of it - a name identifies nobody, so every test that
// looks like "identity" is really testing a string comparison, and the ones
// about the file are testing that the operator is never quietly left with
// empty lists.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { AccessList, AccessError, KIND, parseDuration, MAX_ENTRIES } = require("../src/game/access");

const A = h.from("10.0.0.1", 40001);
const B = h.from("10.0.0.2", 40002);
const A2 = h.from("10.0.0.1", 40002);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
};

const kicksTo = (socket, rinfo, since) =>
  h.sentTo(socket, rinfo.address, rinfo.port, since).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.KICK);

const chatLines = (socket, since = 0) =>
  socket.sent
    .slice(since)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT)
    .map((p) => p.buffer.toString("latin1"));

// A store with no file: nothing in this suite may touch the disk except the
// tests that are explicitly about the file.
const store = (now = () => 1000000) => new AccessList({ maxNameLength: 31, now });

const withTempDir = (body) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghserver-access-"));
  try {
    body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

// ---------------------------------------------------------------------------
// The list itself
// ---------------------------------------------------------------------------

test("a name ban is matched the way the roster matches names, not by exact bytes", () => {
  // Keying a ban by the raw string would make Caps Lock the way around it, in
  // exactly the way it was once the way to impersonate somebody: see
  // nickname.js. The ban list has to fold the same way the roster does.
  const access = store();
  assert.strictEqual(access.ban(KIND.NAME, "Griefer").ok, true);

  assert.ok(access.banFor("Griefer", "10.0.0.1"));
  assert.ok(access.banFor("GRIEFER", "10.0.0.1"));
  assert.ok(access.banFor("  griefer ", "10.0.0.1"));
  assert.strictEqual(access.banFor("Grief", "10.0.0.1"), null);
});

test("a term is only a term when it looks like one", () => {
  assert.strictEqual(parseDuration("30s"), 30000);
  assert.strictEqual(parseDuration("45m"), 2700000);
  assert.strictEqual(parseDuration("2h"), 7200000);
  assert.strictEqual(parseDuration("7d"), 604800000);
  assert.strictEqual(parseDuration("perm"), 0);
  // The word after a nickname is usually the reason, so anything that is not
  // unmistakably a duration has to say so rather than be guessed at.
  assert.strictEqual(parseDuration("spamming"), null);
  assert.strictEqual(parseDuration("30"), null);
  assert.strictEqual(parseDuration("-5m"), null);
  assert.strictEqual(parseDuration("99999999d"), null);
  assert.strictEqual(parseDuration(""), null);
  assert.strictEqual(parseDuration(undefined), null);
});

test("a timed ban lapses on its own and a permanent one does not", () => {
  let clock = 1000000;
  const access = store(() => clock);
  access.ban(KIND.NAME, "Temp", { until: clock + 60000 });
  access.ban(KIND.NAME, "Forever");

  assert.ok(access.banFor("Temp", "10.0.0.1"));
  clock += 59000;
  assert.ok(access.banFor("Temp", "10.0.0.1"));
  clock += 2000;
  assert.strictEqual(access.banFor("Temp", "10.0.0.1"), null);
  assert.ok(access.banFor("Forever", "10.0.0.1"));
  // ...and it stops occupying a row in the list the operator reads.
  assert.deepStrictEqual(
    access.bans().map((record) => record.value),
    ["Forever"]
  );
});

test("an address ban needs an address and a name ban needs a name", () => {
  const access = store();
  // A hostname here would mean a DNS lookup inside the connect path, which is
  // the lookup config.js refuses at bind time for the same reason.
  assert.strictEqual(access.ban(KIND.ADDRESS, "example.com").ok, false);
  assert.strictEqual(access.ban(KIND.ADDRESS, "999.1.1.1").ok, false);
  assert.strictEqual(access.ban(KIND.ADDRESS, "203.0.113.7").ok, true);
  // A name of nothing but invisible marks folds away to an empty key, and an
  // empty key would match every packet that carries no name at all.
  assert.strictEqual(access.ban(KIND.NAME, "   ").ok, false);
});

test("neither list can be grown without end", () => {
  // Both are written by operator commands, and one of those commands can be
  // typed from chat. A file that grows for as long as somebody keeps typing is
  // a way to spend the host's disk.
  const access = store();
  for (let i = 0; i < MAX_ENTRIES; i += 1) {
    assert.strictEqual(access.ban(KIND.NAME, `Player${i}`).ok, true, `entry ${i}`);
  }
  const overflow = access.ban(KIND.NAME, "OneMore");
  assert.strictEqual(overflow.ok, false);
  assert.match(overflow.error, /full/);
  // Re-banning somebody already on the list is an update, not a new row.
  assert.strictEqual(access.ban(KIND.NAME, "Player0", { reason: "again" }).ok, true);
});

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

test("the lists survive a restart, and the write leaves no half-written file behind", () => {
  withTempDir((dir) => {
    const file = path.join(dir, "access.json");
    const first = new AccessList({ maxNameLength: 31, now: () => 1000000, file });
    assert.strictEqual(first.ban(KIND.NAME, "Griefer", { reason: "spawn killing" }).persisted, true);
    first.ban(KIND.ADDRESS, "203.0.113.7", { until: 1000000 + 3600000 });
    first.grantOp("Alice");
    first.setWhitelist(true);
    first.whitelistAdd(KIND.NAME, "Bob");

    // The temporary file is renamed over the real one, so a reader never sees a
    // truncated JSON document - and never finds the leftovers of one either.
    assert.deepStrictEqual(fs.readdirSync(dir), ["access.json"]);

    const second = new AccessList({ maxNameLength: 31, now: () => 1000000, file });
    assert.strictEqual(second.load(), true);
    assert.ok(second.banFor("griefer", "10.0.0.1"));
    assert.ok(second.banFor("Someone", "203.0.113.7"));
    assert.strictEqual(second.isOp("ALICE"), true);
    assert.strictEqual(second.whitelistEnabled, true);
    assert.strictEqual(second.isAllowed("Bob", "10.0.0.1"), true);
    assert.strictEqual(second.isAllowed("Carol", "10.0.0.1"), false);
  });
});

test("a ban that has already lapsed is not carried across a restart", () => {
  withTempDir((dir) => {
    const file = path.join(dir, "access.json");
    const first = new AccessList({ maxNameLength: 31, now: () => 1000000, file });
    first.ban(KIND.NAME, "Temp", { until: 1000000 + 60000 });

    const later = new AccessList({ maxNameLength: 31, now: () => 1000000 + 120000, file });
    later.load();
    assert.deepStrictEqual(later.bans(), []);
  });
});

test("a file the server cannot understand stops the start instead of emptying the lists", () => {
  // Starting with empty lists looks like the forgiving option and is the worst
  // one available: the host comes up, the operator sees a working server, and
  // the people they banned walk back in.
  withTempDir((dir) => {
    const file = path.join(dir, "access.json");

    fs.writeFileSync(file, "{ this is not json");
    assert.throws(() => new AccessList({ file }).load(), AccessError);

    fs.writeFileSync(file, JSON.stringify({ version: 99, whitelistEnabled: false, bans: [], whitelist: [], ops: [] }));
    assert.throws(() => new AccessList({ file }).load(), AccessError);

    fs.writeFileSync(file, JSON.stringify({ version: 1, whitelistEnabled: false, bans: {}, whitelist: [], ops: [] }));
    assert.throws(() => new AccessList({ file }).load(), AccessError);

    // An entry whose kind this build does not know about - a kind written by a
    // later version, say (until 1.4.0 that was a SteamID ban; 1.4.0 knows
    // "steamid", so a made-up kind stands in for the next one). Skipping it
    // silently would be a ban the operator believes in and the server does not
    // enforce.
    fs.writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        whitelistEnabled: false,
        bans: [{ kind: "epicid", value: "76561197960287930", reason: "", until: 0 }],
        whitelist: [],
        ops: [],
      })
    );
    assert.throws(() => new AccessList({ file }).load(), AccessError);
  });
});

test("a hand-edited file is keyed by what it says, not by a key it carries", () => {
  // Operators edit this file. A stored key that disagreed with its own value
  // would be a ban nobody can see in banlist and nobody can lift with unban.
  withTempDir((dir) => {
    const file = path.join(dir, "access.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        whitelistEnabled: false,
        bans: [{ kind: "name", value: "GRIEFER", reason: "by hand", until: 0 }],
        whitelist: [],
        ops: [{ kind: "name", value: "alice", addedBy: "console" }],
      })
    );
    const access = new AccessList({ maxNameLength: 31, now: () => 1000000, file });
    access.load();
    assert.ok(access.banFor("griefer", "10.0.0.1"));
    assert.strictEqual(access.isOp("Alice"), true);
    assert.strictEqual(access.unban(KIND.NAME, "Griefer").ok, true);
  });
});

test("a ban still applies when it could not be written to disk", () => {
  // Full disk, read-only mount, a unit file with ProtectSystem=strict. The ban
  // was asked for and takes effect; what is lost is the next restart, and the
  // console says so at the moment the operator types the command.
  withTempDir((dir) => {
    const access = new AccessList({ maxNameLength: 31, now: () => 1000000, file: path.join(dir, "nope", "a.json") });
    const result = access.ban(KIND.NAME, "Griefer");
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.persisted, false);
    assert.ok(access.lastSaveError);
    assert.ok(access.banFor("Griefer", "10.0.0.1"));
  });
});

// ---------------------------------------------------------------------------
// What a ban does to a connection
// ---------------------------------------------------------------------------

test("a kick lets them back in and a ban does not", () => {
  const { server, clock } = h.makeServer();
  join(server, "Griefer", A);
  clock.advance(100);

  // The old answer to a griefer, and the reason README used to say "a kick is
  // not a ban": nothing stopped the next connect.
  assert.strictEqual(server.kickByName("Griefer"), true);
  assert.strictEqual(server.onDatagram(h.connect("Griefer"), A), true);
  assert.strictEqual(server.users.exists("Griefer"), true);

  server.access.ban(KIND.NAME, "Griefer", { reason: "spawn killing" });
  assert.strictEqual(server.enforceBans(), 1);
  assert.strictEqual(server.users.exists("Griefer"), false);

  clock.advance(100);
  assert.strictEqual(server.onDatagram(h.connect("Griefer"), A), false);
  assert.strictEqual(server.users.exists("Griefer"), false);
});

test("the banned client is told why, in the packet it already understands", () => {
  const { server, socket, clock } = h.makeServer();
  server.access.ban(KIND.NAME, "Griefer", { reason: "spawn killing", until: server.access.now() + 3600000 });
  clock.advance(100);

  const mark = socket.sent.length;
  server.onDatagram(h.connect("Griefer"), A);
  const kicks = kicksTo(socket, A, mark);
  assert.strictEqual(kicks.length, 1);
  const text = kicks[0].buffer.toString("latin1");
  assert.match(text, /spawn killing/);
  assert.match(text, /expires in/);
});

test("a banned address takes every session on it, and only that address", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Second", A2);
  join(server, "Bob", B);
  clock.advance(100);

  server.access.ban(KIND.ADDRESS, "10.0.0.1", { reason: "flooding" });
  assert.strictEqual(server.enforceBans(), 2);
  assert.strictEqual(server.users.exists("Alice"), false);
  assert.strictEqual(server.users.exists("Second"), false);
  assert.strictEqual(server.users.exists("Bob"), true);

  // A new nickname from the same address is the same address.
  assert.strictEqual(server.onDatagram(h.connect("Innocent"), A), false);
});

test("a timed ban lets the player back when it runs out", () => {
  const { server, clock } = h.makeServer();
  server.access.ban(KIND.NAME, "Alice", { until: server.access.now() + 60000 });

  assert.strictEqual(server.onDatagram(h.connect("Alice"), A), false);
  clock.advance(61000);
  assert.strictEqual(server.onDatagram(h.connect("Alice"), A), true);
  assert.strictEqual(server.users.exists("Alice"), true);
});

test("a ban is checked before the roster is touched at all", () => {
  // The duplicate-connect branch re-sends the roster to a session that already
  // exists, and takeover moves a nickname to a new socket. A ban applied after
  // either of those would hand a banned player the player list back.
  const { server, socket, clock } = h.makeServer();
  join(server, "Griefer", A);
  clock.advance(100);

  server.access.ban(KIND.NAME, "Griefer");
  const mark = socket.sent.length;
  // The session is still registered here: the ban was added without a kick.
  assert.strictEqual(server.onDatagram(h.connect("Griefer"), A), false);
  const types = h.typesSent(socket, mark);
  assert.strictEqual(types.includes(packets.TYPE.CONNECT), false, "the roster was re-sent to a banned player");
  assert.strictEqual(types.includes(packets.TYPE.KICK), true);
});

// ---------------------------------------------------------------------------
// Whitelist
// ---------------------------------------------------------------------------

test("the whitelist is off until it is turned on, and then it is exactly a list", () => {
  const { server, clock } = h.makeServer();
  assert.strictEqual(server.onDatagram(h.connect("Alice"), A), true);
  server.kickByName("Alice");
  clock.advance(100);

  server.access.setWhitelist(true);
  // On and empty means nobody, and the console says so when it is switched on.
  assert.strictEqual(server.onDatagram(h.connect("Alice"), A), false);

  server.access.whitelistAdd(KIND.NAME, "Alice");
  assert.strictEqual(server.onDatagram(h.connect("Alice"), A), true);
  assert.strictEqual(server.onDatagram(h.connect("Bob"), B), false);

  // An address entry lets everyone behind it in, which is the honest shape of
  // an address: it is not a person.
  server.access.whitelistAdd(KIND.ADDRESS, "10.0.0.2");
  assert.strictEqual(server.onDatagram(h.connect("Bob"), B), true);
});

test("turning the whitelist on does not empty the server", () => {
  // One word in the console must not throw everybody off a running game. The
  // list is a door policy, not a broom; kick is the broom.
  const { server, clock } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(100);

  server.access.setWhitelist(true);
  assert.strictEqual(server.users.count(), 2);
  assert.strictEqual(server.onDatagram(h.update("Alice"), A), true);
});

// ---------------------------------------------------------------------------
// Slots on the fly
// ---------------------------------------------------------------------------

test("the slot limit changes without a restart and refuses nonsense", () => {
  const { server } = h.makeServer({ MAX_PLAYERS: "2" });
  join(server, "Alice", A);
  join(server, "Bob", B);
  assert.strictEqual(server.onDatagram(h.connect("Carol"), h.from("10.0.0.3", 40003)), false);

  assert.strictEqual(server.setMaxPlayers(3).ok, true);
  assert.strictEqual(server.onDatagram(h.connect("Carol"), h.from("10.0.0.3", 40003)), true);

  for (const bad of [0, -1, 65, 2.5, Number.NaN, "8"]) {
    assert.strictEqual(server.setMaxPlayers(bad).ok, false, `maxplayers ${bad}`);
  }
  assert.strictEqual(server.config.maxPlayers, 3);
});

test("lowering the slot limit below the number of players removes nobody", () => {
  // "maxplayers 1" on a full server is a request to stop letting people in, not
  // a request to throw fifteen of them out mid-game.
  const { server } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Bob", B);

  assert.strictEqual(server.setMaxPlayers(1).ok, true);
  assert.strictEqual(server.users.count(), 2);
  assert.strictEqual(server.onDatagram(h.connect("Carol"), h.from("10.0.0.3", 40003)), false);
});

// ---------------------------------------------------------------------------
// Commands from chat
// ---------------------------------------------------------------------------

test("chat commands do nothing for a player who is not an operator", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(100);

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/kick Bob"), A);
  assert.strictEqual(server.users.exists("Bob"), true);
  assert.match(chatLines(socket, mark).join("\n"), /not an operator/);
});

test("an operator kicks and bans from chat, with no change to the mod", () => {
  // The whole point of doing this over opcode 'm': server.dll is not rebuilt,
  // and the reply is an ordinary type 6 chat line the shipped client already
  // renders.
  const { server, socket, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(100);
  server.grantOp("Alice");

  server.onDatagram(h.chat("Alice", "/kick Bob"), A);
  assert.strictEqual(server.users.exists("Bob"), false);

  clock.advance(1000);
  server.onDatagram(h.connect("Bob"), B);
  assert.strictEqual(server.users.exists("Bob"), true, "a kick is not a ban");

  clock.advance(1000);
  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/ban Bob 30m spamming"), A);
  assert.strictEqual(server.users.exists("Bob"), false);
  assert.match(chatLines(socket, mark).join("\n"), /banned by Alice/);

  clock.advance(1000);
  assert.strictEqual(server.onDatagram(h.connect("Bob"), B), false);
  // ...and the term was read as a term, with the rest kept as the reason.
  const record = server.access.banFor("Bob", "10.0.0.9");
  assert.ok(record.until > 0);
  assert.strictEqual(record.reason, "spamming");
});

test("a word that is not a term is the reason, and the ban is permanent", () => {
  const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(100);
  server.grantOp("Alice");

  server.onDatagram(h.chat("Alice", "/ban Bob spamming the chat"), A);
  const record = server.access.banFor("Bob", "10.0.0.9");
  assert.strictEqual(record.until, 0);
  assert.strictEqual(record.reason, "spamming the chat");
});

test("an operator can lift a ban from chat", () => {
  const { server, socket, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  clock.advance(100);
  server.grantOp("Alice");
  server.access.ban(KIND.NAME, "Bob");

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/unban Bob"), A);
  assert.strictEqual(server.access.banFor("Bob", "10.0.0.9"), null);
  assert.match(chatLines(socket, mark).join("\n"), /no longer banned/);
});

test("/broadcast from an operator speaks as SERVER to everyone", () => {
  const { server, socket, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(100);
  server.grantOp("Alice");

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/broadcast race in five minutes"), A);
  const lines = chatLines(socket, mark);
  assert.strictEqual(lines.length, 2, "everyone hears it once");
  assert.match(lines[0], /SERVER/);
  assert.match(lines[0], /race in five minutes/);
});

test("an address ban is not something chat can do", () => {
  // It would need the operator to see other players' addresses, and the
  // protocol does not put them in chat. Address bans stay at the console.
  const { server, socket, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  clock.advance(100);
  server.grantOp("Alice");

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/banip 10.0.0.2"), A);
  assert.match(chatLines(socket, mark).join("\n"), /Unknown command/);
  assert.strictEqual(server.access.bans().length, 0);
});

test("an operator's commands are charged the same budget as everyone's", () => {
  // A command produces at least one packet, and /broadcast produces one per
  // player. Being an operator must not turn a session into an unmetered packet
  // source aimed at whoever owns that address.
  const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1", COMMAND_BURST: "3", COMMAND_RATE_PER_SECOND: "1" });
  join(server, "Alice", A);
  clock.advance(100);
  server.grantOp("Alice");

  let accepted = 0;
  for (let i = 0; i < 10; i += 1) {
    if (server.onDatagram(h.chat("Alice", "/broadcast spam"), A) === true) accepted += 1;
  }
  assert.strictEqual(accepted, 3);
});

test("a nickname from chat cannot smuggle control bytes into the ban list", () => {
  const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  clock.advance(100);
  server.grantOp("Alice");

  const ESC = String.fromCharCode(0x1b);
  server.onDatagram(h.chat("Alice", `/ban Bo${ESC}[2Jb`), A);
  for (const record of server.access.bans()) {
    assert.strictEqual(record.value.includes(ESC), false, "an escape sequence reached the stored name");
  }
});

test("a replacement nickname holder must receive fresh console approval", () => {
  const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  join(server, "Alice", A);
  server.grantOp("Alice");
  clock.advance(100);
  assert.strictEqual(server.access.isOp("Alice"), true);
  assert.strictEqual(server.access.isOp("ALICE"), true);
  assert.strictEqual(server.access.isOp("Bob"), false);

  // The intent stays on the list; the session approval expires.
  server.kickByName("Alice");
  clock.advance(100);
  join(server, "ALICE", B);
  const mark = server.socket.sent.length;
  server.onDatagram(h.chat("ALICE", "/broadcast I am Alice now"), B);
  assert.doesNotMatch(chatLines(server.socket, mark).join("\n"), /I am Alice now/);
});
