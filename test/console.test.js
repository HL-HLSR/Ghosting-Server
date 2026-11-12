"use strict";

// The operator console.
//
// stdin is not automatically trustworthy: under a supervisor the process may be
// started with its input redirected from a file or a pipe, so whatever arrives
// there is treated like any other untrusted text.

const test = require("node:test");
const assert = require("node:assert");
const { Readable } = require("stream");

const h = require("./helpers/harness");
const { attach, parse } = require("../src/console");
const packets = require("../src/wire/packets");
const { Message } = require("../src/wire/reader");

const A = h.from("10.0.0.1", 40001);

const withConsole = (env) => {
  const rig = h.makeServer(env);
  const printed = [];
  const handle = attach(rig.server, { input: Readable.from([]), print: (line) => printed.push(line) });
  return Object.assign(rig, { printed, run: handle.handle });
};

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
};

test("a line is split into a command and an optionally quoted argument", () => {
  assert.deepStrictEqual(parse("status"), { command: "status", argument: "" });
  assert.deepStrictEqual(parse('kick "Some Body"'), { command: "kick", argument: "Some Body" });
  assert.deepStrictEqual(parse("kick Bob"), { command: "kick", argument: "Bob" });
  assert.deepStrictEqual(parse("KICK Bob"), { command: "kick", argument: "Bob" });
  // An unclosed quote used to fall through to the bare-argument branch, which
  // is fine, but the old code indexed the match with no null guard at all.
  assert.deepStrictEqual(parse('kick "Bob'), { command: "kick", argument: '"Bob' });
});

test("status reports the port it is really listening on", () => {
  const { printed, run } = withConsole({ PORT: "27015" });
  run("status");
  // The old status line printed the literal 22228 whatever the socket said.
  assert.strictEqual(printed.some((line) => /27015/.test(line)), true);
  assert.strictEqual(printed.some((line) => /Players: 0\/16/.test(line)), true);
});

test("status shows what the limiters have been dropping", () => {
  const { server, printed, run } = withConsole();
  for (let i = 0; i < 200; i += 1) server.onDatagram(Buffer.from([0, 0, 0, 0]), h.from("203.0.113.1", 9000));
  run("status");
  const joined = printed.join("\n");
  assert.match(joined, /Dropped by limiter/);
  assert.match(joined, /penalty box/);
});

test("list shows every session and marks the ones that never answered", () => {
  const { server, printed, run } = withConsole();
  join(server, "Alice", A);
  // A connect with no follow-up: possibly a forged source address.
  server.onDatagram(h.connect("Maybe"), h.from("10.0.0.9", 40009));

  run("list");
  const joined = printed.join("\n");
  assert.match(joined, /Alice \(10\.0\.0\.1:40001\)/);
  assert.match(joined, /Maybe.*UNCONFIRMED/);
});

test("kick removes a player and reports an unknown name", () => {
  const { server, printed, run, clock } = withConsole();
  join(server, "Alice", A);
  clock.advance(100);

  run('kick "Alice"');
  assert.strictEqual(server.users.exists("Alice"), false);

  run('kick "Nobody"');
  assert.strictEqual(printed.some((line) => /No user named 'Nobody'/.test(line)), true);
});

test("broadcast reaches every player and is capped like any other chat line", () => {
  const { server, socket, printed, run, clock } = withConsole();
  join(server, "Alice", A);
  clock.advance(100);

  const mark = socket.sent.length;
  run(`broadcast "${"x".repeat(500)}"`);
  const chats = socket.sent.slice(mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT);
  assert.strictEqual(chats.length, 1);

  const message = new Message(chats[0].buffer.subarray(5), {}); // past type and id
  assert.strictEqual(message.readString(), "SERVER");
  // GH_CHAT_MAX_LEN is 128 and the receiving buffer is chatMsg[144].
  assert.strictEqual(message.readString().length, 128);
});

test("control characters from stdin never reach players or the terminal", () => {
  const { server, socket, printed, run, clock } = withConsole();
  join(server, "Alice", A);
  clock.advance(100);

  const ESC = String.fromCharCode(0x1b);
  const mark = socket.sent.length;
  run(`broadcast "hello${ESC}[2Jworld"`);

  const chat = socket.sent.slice(mark).find((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT);
  assert.ok(chat);
  assert.strictEqual(chat.buffer.toString("latin1").includes(ESC), false);

  run(ESC + "[2J");
  assert.strictEqual(printed.join("").includes(ESC), false, "an unknown command was echoed raw");
});

test("race cancel releases the runners and says so when there is no race", () => {
  const { server, printed, run, clock } = withConsole({ RACE_LOBBY_MS: "5000" });
  join(server, "Alice", A);
  clock.advance(1000);

  run("race cancel");
  assert.strictEqual(printed.some((line) => /No race is running/.test(line)), true);

  server.onDatagram(h.chat("Alice", "/race"), A);
  assert.strictEqual(server.race.phase, "lobby");
  run("race cancel");
  assert.strictEqual(server.race.phase, "idle");
});

test("an unknown command is reported without stopping the console", () => {
  const { printed, run } = withConsole();
  run("frobnicate");
  assert.strictEqual(printed.some((line) => /Unknown command 'frobnicate'/.test(line)), true);
  run("help");
  assert.strictEqual(printed.some((line) => /Available commands/.test(line)), true);
});

test("an empty line does nothing", () => {
  const { printed, run } = withConsole();
  run("");
  run("   ");
  assert.deepStrictEqual(printed, []);
});

// ---------------------------------------------------------------------------
// Bans, whitelist, operators, slots
//
// parse() still hands the rest of the line over as one argument, because the
// existing commands take one and the tests above pin that. The commands below
// need a name, a term and a reason, so they re-read the raw line; the quoting
// has to keep working the same way in both places.
// ---------------------------------------------------------------------------

test("a quoted name with a space survives the extra parse the ban commands do", () => {
  const { server, printed, run } = withConsole();
  run('ban "Some Body" 30m being rude');
  const bans = server.access.bans();
  assert.strictEqual(bans.length, 1);
  assert.strictEqual(bans[0].value, "Some Body");
  assert.strictEqual(bans[0].reason, "being rude");
  assert.ok(bans[0].until > 0);
  assert.strictEqual(printed.some((line) => /expires in 30m/.test(line)), true);
});

test("ban removes the player it names and keeps them out", () => {
  const { server, printed, run, clock } = withConsole();
  join(server, "Griefer", A);
  clock.advance(100);

  run('ban "Griefer" perm spawn killing');
  assert.strictEqual(server.users.exists("Griefer"), false);
  assert.strictEqual(printed.some((line) => /Removed 1 session/.test(line)), true);

  clock.advance(100);
  assert.strictEqual(server.onDatagram(h.connect("Griefer"), A), false);
});

test("banip names an address and refuses anything that is not one", () => {
  const { server, printed, run, clock } = withConsole();
  join(server, "Alice", A);
  clock.advance(100);

  run("banip nonsense");
  assert.strictEqual(printed.some((line) => /not an IP address/.test(line)), true);
  assert.strictEqual(server.access.bans().length, 0);

  run("banip 10.0.0.1 flooding");
  assert.strictEqual(server.users.exists("Alice"), false);
  assert.strictEqual(server.access.bans()[0].kind, "address");
});

test("banlist shows what is in force and unban takes it off", () => {
  const { printed, run } = withConsole();
  run("banlist");
  assert.strictEqual(printed.some((line) => /Bans in force: 0/.test(line)), true);

  run('ban "Griefer" spawn killing');
  run("banlist");
  assert.strictEqual(printed.some((line) => /name 'Griefer' - permanent/.test(line)), true);

  // Folded the same way the roster folds it, so the case does not have to match.
  run('unban "GRIEFER"');
  assert.strictEqual(printed.some((line) => /Unbanned/.test(line)), true);
  run('unban "Griefer"');
  assert.strictEqual(printed.some((line) => /is not banned/.test(line)), true);
});

test("whitelist reports that it is on, empty, and therefore a closed door", () => {
  const { server, printed, run } = withConsole();
  run("whitelist");
  assert.strictEqual(printed.some((line) => /Whitelist: off/.test(line)), true);

  run("whitelist on");
  assert.strictEqual(server.access.whitelistEnabled, true);
  const joined = printed.join("\n");
  assert.match(joined, /no new connection will be accepted/);
  // Nobody is thrown off by a switch: that has to be said where it is switched.
  assert.match(joined, /already connected are not removed/);

  run('whitelist add "Alice"');
  run("whitelist addip 10.0.0.9");
  run("whitelist");
  assert.strictEqual(printed.some((line) => /2 entries/.test(line)), true);

  run('whitelist remove "Alice"');
  assert.strictEqual(server.access.whitelist().length, 1);
  run("whitelist frobnicate");
  assert.strictEqual(printed.some((line) => /Usage: whitelist/.test(line)), true);
});

test("op approves only the current connected session", () => {
  const { server, printed, run } = withConsole();
  run('op "Alice" 246810');
  assert.strictEqual(server.access.isOp("Alice"), false);
  join(server, "Alice", A);
  run('op "Alice" 246810');
  assert.strictEqual(server.access.isOp("Alice"), true);
  // The caveat belongs where the decision is made, not only in README.
  assert.strictEqual(printed.some((line) => /this session only/.test(line)), true);

  run("ops");
  assert.strictEqual(printed.some((line) => /Operators: 1/.test(line)), true);

  run('deop "Alice"');
  assert.strictEqual(server.access.isOp("Alice"), false);
  run('deop "Alice"');
  assert.strictEqual(printed.some((line) => /not an operator/.test(line)), true);
});

test("maxplayers changes the limit while the server runs", () => {
  const { server, printed, run } = withConsole({ MAX_PLAYERS: "8" });
  run("maxplayers");
  assert.strictEqual(printed.some((line) => /Slots: 0\/8/.test(line)), true);

  run("maxplayers 24");
  assert.strictEqual(server.config.maxPlayers, 24);
  // The same warning the startup check gives, at the moment it is asked for.
  assert.strictEqual(printed.some((line) => /load tested/.test(line)), true);

  run("maxplayers 0");
  run("maxplayers lots");
  assert.strictEqual(server.config.maxPlayers, 24);
  assert.strictEqual(printed.some((line) => /Usage: maxplayers/.test(line)), true);
});

test("lowering maxplayers under the current head count says nobody is removed", () => {
  const { server, printed, run, clock } = withConsole();
  join(server, "Alice", A);
  join(server, "Bob", h.from("10.0.0.2", 40002));
  clock.advance(100);

  run("maxplayers 1");
  assert.strictEqual(server.users.count(), 2);
  assert.strictEqual(printed.some((line) => /Nobody is removed/.test(line)), true);
});

test("a name from stdin cannot write escape sequences into the operator's terminal", () => {
  // stdin is untrusted for the same reason it always was: under a supervisor
  // the process may be started with its input redirected.
  const { printed, run } = withConsole();
  const ESC = String.fromCharCode(0x1b);

  run(`ban "${ESC}[2J" reason`);
  run("banlist");
  run(`unbanip ${ESC}[2J`);
  assert.strictEqual(printed.join("").includes(ESC), false);
});

test("status counts the lists so an operator can see them without listing them", () => {
  const { printed, run } = withConsole();
  run('ban "Griefer"');
  run('op "Alice" 246810');
  run("whitelist on");
  run("status");
  assert.strictEqual(printed.some((line) => /Access: 1 ban\(s\), whitelist ON/.test(line)), true);
});

test("help describes the ban commands and refuses to oversell them", () => {
  const { printed, run } = withConsole();
  run("help");
  const joined = printed.join("\n");
  assert.match(joined, /ban "Nick"/);
  assert.match(joined, /whitelist/);
  assert.match(joined, /op "Nick"/);
  assert.match(joined, /maxplayers/);
  // The help is where an operator decides what these lists are worth. Since
  // 1.4.0 the client sends a SteamID, and the help says what that is worth.
  assert.match(joined, /SELF-REPORTED/);
  assert.match(joined, /no Steam ticket is checked/);
  assert.match(joined, /None of this is authentication/);
});
