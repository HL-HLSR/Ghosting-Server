"use strict";

// What the server does when the socket, the process or the traffic misbehaves.
//
// Two rules underneath all of it:
//
//   a transient send failure is local to that destination and must never take
//   the host down;
//
//   a fatal socket failure must end the process with a non-zero code, because
//   a live process holding a dead socket is invisible to a supervisor and
//   offline to every player.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { SampledLogger } = require("../src/net/logger");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);
const STRANGER = h.from("203.0.113.9", 6666);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
};

// Send policy ----------------------------------------------------------------

test("every socket send passes a callback", () => {
  // Without one, dgram raises the failure as an 'error' event on the socket,
  // and this server treats a socket error as fatal - so one unreachable client
  // would end the process. The rule is easy to break by accident, so it is
  // checked against the source rather than only against behaviour.
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "server.js"), "utf8");
  const marker = "this.socket.send(";
  let found = 0;
  let index = source.indexOf(marker);
  while (index !== -1) {
    found += 1;
    // The callback is the last argument, so it appears within the call itself.
    const window = source.slice(index, index + 400);
    assert.match(window, /\(error\)\s*=>/, `a socket.send without a callback near offset ${index}`);
    index = source.indexOf(marker, index + marker.length);
  }
  assert.strictEqual(found > 0, true, "no socket sends found - has the code moved?");
});

test("a transient send error is counted, not thrown", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);

  for (const code of ["ENOBUFS", "EPERM", "ENETUNREACH", "EMSGSIZE", "EHOSTUNREACH"]) {
    // Past the chat interval, or the later lines are dropped before they reach
    // the socket and nothing fails at all.
    clock.advance(1000);
    socket.failNext = Object.assign(new Error(code), { code });
    assert.doesNotThrow(() => server.onDatagram(h.chat("Alice", `hello ${code}`), ALICE));
  }

  assert.strictEqual(server.stats.sendErrors, 5);
  assert.strictEqual(socket.closed, false, "a transient error must not close the socket");
  assert.ok(server.users.get("Alice"));
  assert.ok(server.users.get("Bob"));
});

test("the same send error does not become a log flood", () => {
  const printed = [];
  const { server, socket, clock } = h.makeServer();
  server.log = new SampledLogger({ sink: (line) => printed.push(line), now: () => clock.now() });
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);

  for (let i = 0; i < 500; i += 1) {
    // Bob is an active client: his own keepalive keeps him inside the H2
    // liveness window and credited, so Alice's relay is actually attempted at
    // him (and then fails with ENOBUFS). Without it the metered fan-out would
    // correctly skip a silent receiver and there would be no send to fail.
    server.onDatagram(h.update("Bob", { position: [0, i, 0] }), BOB);
    socket.failNext = Object.assign(new Error("no buffer space"), { code: "ENOBUFS" });
    server.onDatagram(h.update("Alice", { position: [i, 0, 0] }), ALICE);
    clock.advance(40);
  }

  const sendLines = printed.filter((line) => /send-failed/.test(line));
  assert.strictEqual(server.stats.sendErrors > 100, true, "the errors were not actually delivered");
  assert.strictEqual(sendLines.length <= 4, true, `${sendLines.length} lines for ${server.stats.sendErrors} failures`);
  assert.match(sendLines[0], /ENOBUFS/, "the first occurrence must name the error");
});

test("a fatal socket error stops the server and reports it", () => {
  const { server, socket } = h.makeServer();
  let fatal = null;
  server.onFatal = (error) => {
    fatal = error;
  };

  socket.emit("error", Object.assign(new Error("socket died"), { code: "ENOTSOCK" }));

  // stop() is async; the important part is that running is already false, so
  // nothing else is accepted, and the callback fires for index.js to exit(1).
  assert.strictEqual(server.running, false);
  assert.strictEqual(server.timers.length, 0, "timers must not survive a fatal error");
  return new Promise((resolve) => {
    setTimeout(() => {
      assert.ok(fatal, "onFatal was never called, so the process would stay alive with a dead socket");
      resolve();
    }, 20);
  });
});

test("the entry point exits non-zero on a fatal socket error", () => {
  // The wiring, not the behaviour: index.js is what turns onFatal into an exit
  // code, and a supervisor restart depends on that code being non-zero.
  const source = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
  assert.match(source, /server\.onFatal\s*=/);
  assert.match(source, /process\.exit\(1\)/);
  assert.match(source, /uncaughtException/);
  assert.match(source, /unhandledRejection/);
  assert.match(source, /SIGINT/);
  assert.match(source, /SIGTERM/);
  // EX_CONFIG, so a supervisor can be told not to restart on a bad unit file.
  assert.match(source, /process\.exit\(78\)/);
});

test("shutdown clears every timer and releases race pauses", () => {
  const { server, clock } = h.makeServer({ RACE_LOBBY_MS: "2000" });
  join(server, "Alice", ALICE);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), ALICE);

  assert.strictEqual(server.timers.length, 3, "sweep, tick and heartbeat");
  server.stop("Server is shutting down.");
  assert.strictEqual(server.timers.length, 0);
  assert.strictEqual(server.race.phase, "idle");
  assert.strictEqual(server.race.paused.size, 0);
  assert.strictEqual(server.users.count(), 0);
});

// Amplification and log flood ------------------------------------------------

test("malformed and unknown traffic gets no network reply at all", () => {
  const { server, socket } = h.makeServer();
  const before = socket.sent.length;

  const cases = [
    Buffer.alloc(0),
    Buffer.from([0]),
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0xff, 0xff, 0xff, 0xff]),
    Buffer.from([0x00, 0x00, 0x00, 0x02, 0x7a, 0x7a]),
    Buffer.alloc(600, 0x41),
  ];
  for (const buffer of cases) server.onDatagram(buffer, STRANGER);

  assert.strictEqual(socket.sent.length, before, "junk earned a reply, which is a reflector");
});

test("four bytes of junk cannot buy a kilobyte of log", () => {
  const printed = [];
  const { server, clock } = h.makeServer();
  server.log = new SampledLogger({ sink: (line) => printed.push(line), now: () => clock.now() });

  const junk = Buffer.from([0, 0, 0, 0]);
  for (let i = 0; i < 5000; i += 1) server.onDatagram(junk, STRANGER);

  const bytes = printed.reduce((total, line) => total + line.length, 0);
  assert.strictEqual(printed.length <= 5, true, `${printed.length} lines for 5000 packets`);
  assert.strictEqual(bytes < 1024, true, `${bytes} bytes of log for 20 000 bytes of junk`);
});

test("sampled logging prints the first event and then a summary with the count", () => {
  const printed = [];
  const clock = { value: 1000 };
  const log = new SampledLogger({ sink: (line) => printed.push(line), now: () => clock.value, intervalMs: 10000 });

  log.event("probe", "first");
  assert.strictEqual(printed.length, 1);
  assert.match(printed[0], /probe/);

  for (let i = 0; i < 999; i += 1) log.event("probe", `hit ${i}`);
  assert.strictEqual(printed.length, 1, "repeats must not print");

  clock.value += 11000;
  log.event("probe", "later");
  assert.strictEqual(printed.length, 2);
  assert.match(printed[1], /1000 more/);
  assert.match(printed[1], /1001 total/);
});

test("a reply to an address that never answered is bounded", () => {
  const { server, socket, clock } = h.makeServer();
  for (let i = 0; i < 15; i += 1) join(server, `Player${i}`, h.from(`10.5.0.${i + 1}`, 40000 + i));

  const spoofed = h.from("198.51.100.7", 33333);
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Reflected"), spoofed);

  const burst = h.sentTo(socket, spoofed.address, spoofed.port, mark);
  const bytes = burst.reduce((total, packet) => total + packet.buffer.length, 0);
  assert.strictEqual(bytes <= server.config.unconfirmedBudgetBytes, true, `${bytes} bytes in one burst`);

  // And nothing further: fan-out skips a session that has not answered.
  const after = socket.sent.length;
  for (let i = 0; i < 100; i += 1) {
    clock.advance(40);
    server.onDatagram(h.update("Player0", { position: [i, 0, 0] }), h.from("10.5.0.1", 40000));
  }
  assert.strictEqual(h.sentTo(socket, spoofed.address, spoofed.port, after).length, 0);
});

// Spectate, the worst amplifier in the protocol -------------------------------

test("spectate is rate limited", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);

  const mark = socket.sent.length;
  // Alternate targets so every packet is a real change, then push far past the
  // allowed rate.
  for (let i = 0; i < 500; i += 1) {
    server.onDatagram(h.spectate("Alice", i % 2 === 0 ? "Bob" : ""), ALICE);
  }
  const relayed = socket.sent.slice(mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPECTATE);
  const burst = server.config.eventBurst;
  assert.strictEqual(relayed.length <= burst * 2 + 2, true, `${relayed.length} spectate packets relayed for 500 requests`);
});

test("repeating the current spectate target costs nothing", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);

  server.onDatagram(h.spectate("Alice", "Bob"), ALICE);
  const mark = socket.sent.length;
  for (let i = 0; i < 50; i += 1) server.onDatagram(h.spectate("Alice", "Bob"), ALICE);
  assert.strictEqual(socket.sent.length, mark, "an unchanged target was relayed anyway");
});

test("a spectate target that is not connected is cleared, never relayed", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);

  const mark = socket.sent.length;
  server.onDatagram(h.spectate("Alice", "x".repeat(200)), ALICE);
  assert.strictEqual(server.users.get("Alice").spectating, "");

  const relayed = socket.sent.slice(mark).filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPECTATE);
  for (const packet of relayed) {
    // Watcher name, then target: the target must be empty, not a 200 byte blob.
    assert.strictEqual(packet.buffer.readUInt32BE(1 + 4 + 5), 0, "an unknown target was relayed as text");
  }
});

test("a spectate target is bounded even when it names a real player", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  const longName = "N".repeat(31);
  join(server, longName, BOB);
  clock.advance(1000);

  server.onDatagram(h.spectate("Alice", longName), ALICE);
  assert.strictEqual(server.users.get("Alice").spectating.length <= 31, true);
});
