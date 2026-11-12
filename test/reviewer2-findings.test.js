"use strict";

// One test per defect the second adversarial review found and this round
// closed. Each one fails against the code as it was before the fix; the point
// of writing them here rather than folding them into the topic files is that a
// finding with no test of its own is a finding that can quietly come back.
//
// Where a fix is partial, the test says so and asserts the part that is real.

const test = require("node:test");
const assert = require("node:assert");
const net = require("net");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { load, ConfigError } = require("../src/config");
const { GlobalLimiter } = require("../src/net/rate-limit");

const junk = (bytes) => Buffer.alloc(bytes, 0x41);
const unknownOpcode = () => {
  const buffer = Buffer.alloc(9);
  buffer.writeUInt32BE(5, 0);
  buffer.write("zzzzz", 4, "latin1");
  return buffer;
};

// ---------------------------------------------------------------------------
// R2-01  punish() was called one argument short on the oversized path
// ---------------------------------------------------------------------------

test("an oversized flood boxes the sender, not a timestamp", () => {
  // The call was punish(address, at, "oversized", detail) against a signature
  // of (address, session, trusted, at, code, detail). `trusted` became the
  // string "oversized" (truthy), so the key became `at` - a number that changed
  // every millisecond. Effects: the sender was never boxed, the malformed store
  // grew one bucket per millisecond, and the event was logged with an undefined
  // code.
  const { server, clock, log } = h.makeServer();
  const rinfo = h.from("10.0.0.1", 40001);

  for (let i = 0; i < 200; i += 1) {
    server.onDatagram(junk(600), rinfo);
    if (i % 2 === 0) clock.advance(1);
  }

  // Not 200: once the box is armed, the datagrams are dropped by the box check
  // before the size check counts them. That ordering is deliberate and is the
  // subject of its own test in reviewer3-findings.test.js - an oversized
  // datagram must not be able to renew the sentence it is serving.
  assert.ok(server.stats.oversized > 20, `only ${server.stats.oversized} were counted before the box closed`);
  assert.ok(server.stats.oversized < 200, "the box never closed, so the flood was parsed to the end");
  assert.strictEqual(server.penalty.has("10.0.0.1"), true, "the address is not in the penalty box");
  assert.deepStrictEqual(Array.from(server.penalty.keys()), ["10.0.0.1"]);
  assert.strictEqual(server.malformed.size, 1, "one address must not create hundreds of buckets");
  assert.deepStrictEqual(Array.from(server.malformed.buckets.keys()), ["10.0.0.1"]);

  const codes = log.lines.filter((line) => line[0] === "event").map((line) => line[1]);
  assert.ok(codes.includes("oversized"), `codes seen: ${JSON.stringify(Array.from(new Set(codes)))}`);
  assert.ok(codes.includes("penalty-box"));
});

test("an oversized flood from a confirmed session is scoped to that endpoint", () => {
  const { server, clock } = h.makeServer();
  const abuser = h.from("10.0.0.1", 40001);
  const neighbour = h.from("10.0.0.1", 40002);
  server.onDatagram(h.connect("Abuser"), abuser);
  server.onDatagram(h.update("Abuser"), abuser);
  server.onDatagram(h.connect("Neighbour"), neighbour);
  server.onDatagram(h.update("Neighbour"), neighbour);

  for (let i = 0; i < 40; i += 1) {
    server.onDatagram(junk(600), abuser);
    clock.advance(1);
  }

  assert.strictEqual(server.penalty.has("10.0.0.1:40001"), true, "the endpoint should be boxed");
  assert.strictEqual(server.penalty.has("10.0.0.1"), false, "the shared address must not be boxed");
  clock.advance(100);
  assert.strictEqual(server.onDatagram(h.update("Neighbour"), neighbour), true, "the neighbour was collateral");
});

// ---------------------------------------------------------------------------
// R2-02  a boxed address was an indefinite lockout bought with 0.7 pps
// ---------------------------------------------------------------------------

test("a boxed address is throttled, not silenced: a real connect still lands", () => {
  // The attack: forge the victim's source address, send 21 malformed datagrams
  // every thirty seconds, and the victim can never join their own server. The
  // box now leaves a one-packet-per-second trickle, which is far more than a
  // five-second connect retry needs and far less than a flood can use.
  const { server, clock } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  const victim = h.from("10.0.0.1", 40001);

  for (let i = 0; i < 25; i += 1) {
    server.onDatagram(unknownOpcode(), spoofed);
    clock.advance(10);
  }
  assert.strictEqual(server.penalty.has("10.0.0.1"), true, "the box did not arm, the test proves nothing");

  // The victim's client retries every five seconds (gh_online_connect has a
  // 5 s cooldown, GhostOnlineEngine.cpp:634). Give it three attempts.
  let joined = false;
  for (let attempt = 0; attempt < 3 && !joined; attempt += 1) {
    clock.advance(5000);
    server.onDatagram(h.connect("Victim"), victim);
    joined = server.users.exists("Victim");
  }
  assert.strictEqual(joined, true, "the victim was locked out of their own server");
  assert.strictEqual(server.penalty.has("10.0.0.1"), true, "and the box is still armed against the flood");
});

test("the trickle a boxed address gets is a trickle", () => {
  // The other half of the same fix: it must not become a way to keep parsing.
  const { server, clock } = h.makeServer();
  const rinfo = h.from("10.0.0.1", 59999);

  for (let i = 0; i < 25; i += 1) {
    server.onDatagram(unknownOpcode(), rinfo);
    clock.advance(10);
  }
  const parsedBefore = server.stats.unknownOpcode;

  // Sixty seconds of flooding at 100 pps against a box that grants ~1 pps.
  for (let second = 0; second < 60; second += 1) {
    for (let i = 0; i < 100; i += 1) server.onDatagram(unknownOpcode(), rinfo);
    clock.advance(1000);
  }
  const parsed = server.stats.unknownOpcode - parsedBefore;
  assert.ok(parsed <= 90, `${parsed} of 6000 datagrams were parsed; the trickle is not a trickle`);
  assert.ok(parsed > 0, "the trickle does not exist at all, which is the lockout again");
});

// ---------------------------------------------------------------------------
// R2-03  the whole-process ceiling was first-come-first-served
// ---------------------------------------------------------------------------

test("the global ceiling reserves capacity for sessions that proved their address", () => {
  const limiter = new GlobalLimiter({ capacity: 1000, refillPerSecond: 1000, reserve: 200, now: () => 0 });
  let untrusted = 0;
  while (limiter.take(1, false)) untrusted += 1;
  assert.strictEqual(untrusted, 800, "untrusted traffic drank the reserve");
  assert.strictEqual(limiter.take(1, true), true, "a confirmed session cannot reach the reserve");
});

test("a flood above the ceiling does not silence a connected player", () => {
  // Measured before the fix: at 200 000 pps of four-byte junk a confirmed
  // player got 2 of 500 updates through and was swept as timed out while their
  // client was still sending.
  const { server, clock } = h.makeServer({ GLOBAL_PACKETS_PER_SECOND: "20000" });
  const victim = h.from("10.0.0.9", 40001);
  server.onDatagram(h.connect("Victim"), victim);
  server.onDatagram(h.update("Victim"), victim);
  assert.strictEqual(server.users.get("Victim").confirmed, true);

  let accepted = 0;
  let attempted = 0;
  // Ten seconds: 50 000 spoofed datagrams a second against the victim's 25.
  for (let second = 0; second < 10; second += 1) {
    for (let i = 0; i < 50000; i += 1) {
      server.onDatagram(junk(4), h.from(`10.1.${(i >> 8) & 255}.${i & 255}`, 30000 + (i & 1023)));
    }
    for (let frame = 0; frame < 25; frame += 1) {
      clock.advance(40);
      attempted += 1;
      if (server.onDatagram(h.update("Victim"), victim)) accepted += 1;
    }
  }

  assert.ok(server.global.dropped > 100000, "the ceiling never engaged, so the test proves nothing");
  assert.ok(
    accepted / attempted > 0.9,
    `only ${accepted} of ${attempted} updates from a connected player got through`
  );
  server.sweep();
  assert.strictEqual(server.users.exists("Victim"), true, "the player was swept during the flood");
});

// ---------------------------------------------------------------------------
// R2-04  a boxed player kept their slot
// ---------------------------------------------------------------------------

test("a confirmed session that gets boxed loses its slot instead of holding it", () => {
  const { server, clock } = h.makeServer();
  const abuser = h.from("10.0.0.1", 40001);
  const other = h.from("10.0.0.2", 40002);
  server.onDatagram(h.connect("Abuser"), abuser);
  server.onDatagram(h.update("Abuser"), abuser);
  server.onDatagram(h.connect("Other"), other);
  server.onDatagram(h.update("Other"), other);

  for (let i = 0; i < 40; i += 1) {
    server.onDatagram(unknownOpcode(), abuser);
    clock.advance(1);
  }

  assert.strictEqual(server.users.exists("Abuser"), false, "the slot is still held by a client we ignore");
  assert.strictEqual(server.users.exists("Other"), true);
  assert.strictEqual(server.penalty.has("10.0.0.1:40001"), true);
});

test("the drop is announced to everyone else, so no ghost is left behind", () => {
  const rig = h.makeServer();
  const abuser = h.from("10.0.0.1", 40001);
  const other = h.from("10.0.0.2", 40002);
  rig.server.onDatagram(h.connect("Abuser"), abuser);
  rig.server.onDatagram(h.update("Abuser"), abuser);
  rig.server.onDatagram(h.connect("Other"), other);
  rig.server.onDatagram(h.update("Other"), other);

  const mark = rig.socket.sent.length;
  for (let i = 0; i < 40; i += 1) {
    rig.server.onDatagram(unknownOpcode(), abuser);
    rig.clock.advance(1);
  }

  const toOther = h.sentTo(rig.socket, "10.0.0.2", 40002, mark).map((p) => p.buffer.readUInt8(0));
  assert.ok(toOther.includes(packets.TYPE.DISCONNECT), `types to the other player: ${JSON.stringify(toOther)}`);
});

// ---------------------------------------------------------------------------
// R2-05  BIND_ADDRESS accepted things that are not addresses
// ---------------------------------------------------------------------------

test("BIND_ADDRESS accepts only real IPv4 literals", () => {
  // The dotted-quad regex passed "999.999.999.999", and dgram then treated it
  // as a hostname - the DNS lookup at bind time the check existed to prevent.
  for (const bad of ["999.999.999.999", "256.1.1.1", "1.2.3.400", "localhost", "1.2.3", "1.2.3.4.5", "::1"]) {
    assert.throws(() => load({ BIND_ADDRESS: bad }), ConfigError, `accepted ${bad}`);
  }
  for (const good of ["0.0.0.0", "127.0.0.1", "10.0.0.1", "255.255.255.255"]) {
    const config = load({ BIND_ADDRESS: good });
    assert.strictEqual(config.bindAddress, good);
    assert.strictEqual(net.isIP(config.bindAddress), 4, good);
  }
});

test("GLOBAL_RESERVE_PERCENT is validated like every other knob", () => {
  assert.strictEqual(load({}).globalReservePercent, 20);
  assert.strictEqual(load({ GLOBAL_RESERVE_PERCENT: "0" }).globalReservePercent, 0);
  assert.strictEqual(load({ GLOBAL_RESERVE_PERCENT: "90" }).globalReservePercent, 90);
  assert.throws(() => load({ GLOBAL_RESERVE_PERCENT: "91" }), ConfigError);
  assert.throws(() => load({ GLOBAL_RESERVE_PERCENT: "-1" }), ConfigError);
  assert.throws(() => load({ GLOBAL_RESERVE_PERCENT: "" }), ConfigError);
  assert.throws(() => load({ GLOBAL_RESERVE_PERCENT: "twenty" }), ConfigError);
});

// ---------------------------------------------------------------------------
// R2-06  a runner leaving during loading stranded the rest in a pause
// ---------------------------------------------------------------------------

const A = h.from("10.0.0.1", 40001);
const B = h.from("10.0.0.2", 40002);

const twoRunnersLoading = (env = {}) => {
  const rig = h.makeServer(Object.assign({ RACE_LOBBY_MS: "2000" }, env));
  const { server, clock } = rig;
  for (const [name, rinfo] of [["Alice", A], ["Bob", B]]) {
    server.onDatagram(h.connect(name), rinfo);
    // Deliberately NOT the race map. A runner already standing on
    // d1_trainstation_01 counts as loaded the moment the phase starts, which
    // makes "still loading" impossible to express, and the machine now also
    // tells apart "has not loaded yet" (same map as before) from "loaded the
    // wrong save" (a third map) - a distinction that needs a starting map.
    server.onDatagram(h.update(name, { map: "d1_eli_01" }), rinfo);
  }
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), A);
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), B);
  clock.advance(1500);
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "loading");
  return rig;
};

test("when the last blocker leaves, the countdown starts instead of the pause outlasting it", () => {
  // Alice loads and stages, Bob never loads, Bob leaves. everyoneReady() is now
  // true, but nothing re-evaluated it: the machine sat in `staging` and Alice
  // stayed frozen behind a server pause for the full 120 s staging timeout.
  const { server, clock } = twoRunnersLoading();
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(100);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true);

  clock.advance(100);
  server.onDatagram(h.disconnect("Bob"), B);
  clock.advance(3000);
  server.resolvePendingDrops();

  assert.strictEqual(server.race.phase, "countdown_start", `phase was ${server.race.phase}`);
  // ...and the countdown really releases her, in seconds rather than minutes.
  clock.advance(5000);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.paused.has("Alice"), false);
});

// ---------------------------------------------------------------------------
// R2-07  a partial load stall held the race lock for the full loading timeout
// ---------------------------------------------------------------------------

test("loading is cancelled a short time after the last load, not after the full timeout", () => {
  // Before: the short fuse only fired when NOBODY had loaded, so one runner who
  // loads and one who never does held the lock for RACE_LOADING_TIMEOUT_MS -
  // measured at 179 s.
  const { server, clock, config } = twoRunnersLoading();
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  assert.strictEqual(server.race.loaded.size, 1);

  clock.advance(config.raceNoProgressMs - 1000);
  assert.strictEqual(server.race.phase, "loading", "cancelled too early");

  clock.advance(2000);
  assert.strictEqual(server.race.phase, "idle", "the stall outlived the fuse");
  assert.ok(config.raceNoProgressMs < config.raceLoadingTimeoutMs);
});

test("a runner who loads keeps the fuse alive for the ones still loading", () => {
  const { server, clock, config } = twoRunnersLoading();
  // Both players stay connected the whole time - Bob is still on the map he
  // started from, i.e. has not loaded - so this measures the fuse and not the
  // stale sweep. The map matters: a THIRD map would mean he loaded a save that
  // is not the start of the game, and he would be taken out of the race.
  const keepAlive = (ms) => {
    for (let elapsed = 0; elapsed < ms; elapsed += 1000) {
      clock.advance(1000);
      server.onDatagram(h.update("Bob", { map: "d1_eli_01" }), B);
    }
  };

  keepAlive(config.raceNoProgressMs - 2000);
  // ...then Alice loads, which is progress and buys everyone another window.
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  assert.strictEqual(server.race.loaded.size, 1);

  keepAlive(config.raceNoProgressMs - 2000);
  assert.strictEqual(server.race.phase, "loading", "a load did not reset the fuse");
  keepAlive(3000);
  assert.strictEqual(server.race.phase, "idle", "and the fuse still burns down from there");
});

// ---------------------------------------------------------------------------
// R2-08  a failed pause release was recorded as a success
// ---------------------------------------------------------------------------

test("a release that did not reach the wire is retried instead of forgotten", () => {
  // race.js documented that the bookkeeping is only updated when the packet
  // went out. It was not: deps.pause swallowed send()'s result, so a failed
  // release removed the name from `paused` and the player stayed behind an
  // overlay they cannot dismiss.
  const rig = twoRunnersLoading();
  const { server, clock } = rig;
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(100);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true);

  // Every send fails from here.
  const realSend = server.send.bind(server);
  server.send = () => false;
  server.race.cancel("test");
  server.send = realSend;

  assert.strictEqual(server.pendingUnpause.has("Alice"), true, "the stuck player was forgotten by reset()");

  const mark = rig.socket.sent.length;
  clock.advance(1000);
  server.sweep();
  const released = h
    .sentTo(rig.socket, "10.0.0.1", 40001, mark)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SERVER_PAUSE && p.buffer.readUInt8(1) === 0);
  assert.strictEqual(released.length, 1, "the sweep did not retry the release");
  assert.strictEqual(server.pendingUnpause.has("Alice"), false);
});

test("a release that fails asynchronously (ENOBUFS) is also retried", () => {
  // The sibling case, and the harder one: dgram reports most failures through
  // the send callback, which runs after send() has already returned true. The
  // machine has been told the packet went out by then, so the retry cannot live
  // in race.paused - it lives on the host's list, fed from the callback.
  const rig = twoRunnersLoading();
  const { server, clock, socket } = rig;
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(100);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true);

  socket.failNext = Object.assign(new Error("no buffer space"), { code: "ENOBUFS" });
  const returned = server.race.pauseRunner("Alice", false, "");
  assert.strictEqual(returned, true, "the packet did reach the socket; the failure came later");
  assert.strictEqual(server.stats.sendErrors, 1);
  assert.strictEqual(server.pendingUnpause.has("Alice"), true, "the failed release was not recorded");

  const mark = socket.sent.length;
  clock.advance(6000);
  server.sweep();
  const released = h
    .sentTo(socket, "10.0.0.1", 40001, mark)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SERVER_PAUSE && p.buffer.readUInt8(1) === 0);
  assert.strictEqual(released.length, 1, "the sweep did not retry the release");
  assert.strictEqual(server.pendingUnpause.size, 0);
});

test("a player who left is dropped from the retry list rather than retried forever", () => {
  const { server, clock } = h.makeServer();
  server.pendingUnpause.add("Ghost");
  clock.advance(1000);
  server.sweep();
  assert.strictEqual(server.pendingUnpause.size, 0);
});

// ---------------------------------------------------------------------------
// R2-09  a claim in the report that the fixtures disproved
// ---------------------------------------------------------------------------

test("a fully parsed packet has a size ceiling, but a padded datagram is still accepted", () => {
  // The report said "the worst accepted 'l' is 351 bytes". 351 is the parse
  // ceiling - the largest packet whose fields the server will actually read -
  // not the largest datagram it accepts. Trailing bytes after the last field
  // are ignored, so a 512 byte datagram carrying a valid short update is
  // handled. That is not an amplifier (the reply is built from the parsed
  // fields, and padding only makes the attacker's own traffic larger) but the
  // wording was wrong, so here is what is actually true.
  const { server, clock } = h.makeServer();
  const rinfo = h.from("10.0.0.1", 40001);
  server.onDatagram(h.connect("Alice"), rinfo);
  clock.advance(100);

  const short = h.update("Alice");
  const padded = Buffer.concat([short, Buffer.alloc(512 - short.length, 0x41)]);
  assert.strictEqual(padded.length, 512);
  assert.strictEqual(server.onDatagram(padded, rinfo), true, "trailing bytes are ignored, as documented");

  clock.advance(100);
  const over = Buffer.concat([short, Buffer.alloc(513 - short.length, 0x41)]);
  assert.strictEqual(server.onDatagram(over, rinfo), false, "one byte over the datagram cap must be refused");
});
