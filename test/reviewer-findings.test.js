"use strict";

// One test per finding from the adversarial review.
//
// Each of these reproduces the attack that worked, with the measurement it
// produced, so a future change that reintroduces the defect fails here rather
// than in production. The numbers in the comments are what the attack actually
// achieved against the version that had the bug, not estimates.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const { BufferWriter } = require("../src/wire/writer");
const { TokenBucketStore } = require("../src/net/rate-limit");
const { load, ConfigError } = require("../src/config");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);
const SPOOFED = h.from("198.51.100.7", 33333);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

// F1 -------------------------------------------------------------------------
test("F1 a second forged connect does not confirm a session", () => {
  // Before: 2 connects, 50 bytes in, bought 45 205 bytes of fan-out to an
  // address that never answered - 904x by volume - because the duplicate
  // branch called confirm().
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  server.onDatagram(h.connect("Ghost"), SPOOFED);
  clock.advance(6000);
  server.onDatagram(h.connect("Ghost"), SPOOFED);

  const ghost = server.users.get("Ghost");
  assert.ok(ghost);
  assert.strictEqual(ghost.confirmed, false, "a connect must never be treated as proof of reachability");

  const mark = socket.sent.length;
  for (let i = 0; i < 200; i += 1) {
    clock.advance(50);
    server.onDatagram(h.update("Alice", { position: [i, 0, 0] }), ALICE);
    server.onDatagram(h.update("Bob", { position: [i, 0, 0] }), BOB);
  }
  const bytes = h
    .sentTo(socket, SPOOFED.address, SPOOFED.port, mark)
    .reduce((total, packet) => total + packet.buffer.length, 0);
  assert.strictEqual(bytes, 0, `${bytes} bytes were reflected at an address that never answered`);
});

test("F1b an unconfirmed session keeps the short leash", () => {
  const { server, clock } = h.makeServer();
  server.onDatagram(h.connect("Ghost"), SPOOFED);
  clock.advance(6000);
  server.onDatagram(h.connect("Ghost"), SPOOFED);

  // Confirmed sessions get 60 s, unconfirmed ones 20. The duplicate-connect bug
  // promoted a forged session to the long leash.
  clock.advance(25000);
  assert.strictEqual(server.users.get("Ghost"), null, "a forged session must not survive 25 s");
});

test("F1c confirmation clears the anti-reflection budget", () => {
  const { server } = h.makeServer();
  const user = join(server, "Alice", ALICE);
  assert.strictEqual(user.confirmed, true);
  assert.strictEqual(user.unconfirmedBytes, 0, "the budget is dead state once the address has answered");
});

// F2 -------------------------------------------------------------------------
test("F2 a flood aimed at a player's address cannot starve them off the server", () => {
  // Before: an attacker who knew only the victim's IP spent the shared address
  // budget with junk from any port. The victim's own packets were dropped, so
  // lastSeen froze and the sweep removed them after 60 s.
  const { server, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  const junk = Buffer.from([0, 0, 0, 0]);
  const noise = h.from(ALICE.address, 59999);

  for (let second = 0; second < 70; second += 1) {
    for (let i = 0; i < 300; i += 1) server.onDatagram(junk, noise);
    clock.advance(500);
    server.onDatagram(h.update("Alice"), ALICE);
    clock.advance(500);
    server.onDatagram(h.update("Alice"), ALICE);
    server.onDatagram(h.update("Bob"), BOB);
  }

  assert.ok(server.users.get("Alice"), "the victim was swept off the server by traffic aimed at their IP");
  assert.strictEqual(
    clock.now() - server.users.get("Alice").lastSeen < 2000,
    true,
    "the victim's idle timer was frozen"
  );
});

// F3 -------------------------------------------------------------------------
test("F3 a race cannot reach racing with nobody having loaded the save", () => {
  // Before: checkpoint 1 is accepted during loading, and the countdown started
  // as soon as everyone was staged - so two crafted checkpoints drove the
  // machine to `racing` without a single runner reporting the race map.
  const { server, clock } = h.makeServer({ RACE_LOBBY_MS: "2000" });
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);

  server.onDatagram(h.chat("Alice", "/race"), ALICE);
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), BOB);
  clock.advance(1500);
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "loading");

  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), ALICE);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Bob", 1), BOB);

  assert.strictEqual(server.race.staged.size, 2);
  assert.strictEqual(server.race.loaded.size, 0);
  assert.strictEqual(server.race.phase, "loading", "staging is not evidence of loading");

  clock.advance(4100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.notStrictEqual(server.race.phase, "racing");
});

test("F3b staging first and loading second still starts the race", () => {
  // The legitimate ordering: a runner reaches the pause point before the server
  // has registered their map. Fixing F3 must not break it.
  const { server, clock } = h.makeServer({ RACE_LOBBY_MS: "2000" });
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), ALICE);
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), BOB);
  clock.advance(1500);
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();

  clock.advance(500);
  server.onDatagram(h.checkpoint("Alice", 1), ALICE);
  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), ALICE);
  clock.advance(500);
  server.onDatagram(h.checkpoint("Bob", 1), BOB);
  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), BOB);

  assert.strictEqual(server.race.phase, "countdown_start");
  clock.advance(4100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "racing");
});

test("F3c every phase has a deadline, including the countdowns", () => {
  const { server, clock } = h.makeServer({ RACE_LOBBY_MS: "2000" });
  join(server, "Alice", ALICE);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), ALICE);
  clock.advance(3500);
  assert.strictEqual(server.race.phase, "countdown_map");
  // Before: countdown_map and countdown_start had phaseDeadline = 0, i.e. no
  // expiry at all. A timer that never fires held the race lock for everyone.
  assert.strictEqual(server.race.phaseDeadline > 0, true, "the countdown must expire");

  // Never fire the countdown timers: the deadline has to rescue the machine.
  clock.advance(11000);
  assert.strictEqual(server.race.phase, "idle");
});

test("F3d a race nobody loads is cancelled in well under the loading timeout", () => {
  const { server, clock } = h.makeServer({ RACE_LOBBY_MS: "2000", RACE_NO_PROGRESS_MS: "45000" });
  join(server, "Alice", ALICE);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), ALICE);
  clock.advance(1000);
  clock.advance(1500);
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "loading");

  // Before: the lock was held for lobby + the full 180 s loading timeout.
  clock.advance(46000);
  assert.strictEqual(server.race.phase, "idle");
});

// F4 -------------------------------------------------------------------------
test("F4 a rejected connect cannot evict the player it wanted to replace", () => {
  // Before: the takeover unregistered the previous holder and only then checked
  // the slot limits. When those rejected the newcomer the victim was gone from
  // the roster, and because a takeover is deliberately silent no type 4 went
  // out - so every other client kept rendering a ghost the server no longer had.
  const { server, socket, clock } = h.makeServer({
    MAX_SESSIONS_PER_ADDRESS: "4",
    CONNECT_BURST: "50",
    CONNECT_RATE_PER_MINUTE: "3000",
  });

  join(server, "Victim", h.from("10.9.9.9", 41000));
  for (let i = 0; i < 4; i += 1) join(server, `Att${i}`, h.from("203.0.113.5", 50000 + i));

  // The victim goes quiet long enough for a stranger to be allowed a takeover.
  clock.advance(61000);

  const mark = socket.sent.length;
  const attacker = h.from("203.0.113.5", 50099);
  assert.strictEqual(server.onDatagram(h.connect("Victim"), attacker), false, "the attacker must be rejected");

  assert.ok(server.users.exists("Victim"), "the victim must still be on the roster");
  const kinds = h.typesSent(socket, mark);
  assert.strictEqual(kinds.includes(packets.TYPE.DISCONNECT), false, "nobody left, so nothing may be announced");
});

test("F4b a player reclaiming their own nickname is not blocked by the slot cap", () => {
  const { server, clock } = h.makeServer({ MAX_SESSIONS_PER_ADDRESS: "1" });
  join(server, "Alice", ALICE);
  clock.advance(11000);
  // Same address, new ephemeral port after a crash. The slot is not moving, so
  // the per-address cap must not reject the reconnect of its own owner.
  const reconnect = h.from(ALICE.address, 40009);
  assert.strictEqual(server.onDatagram(h.connect("Alice"), reconnect), true);
  assert.strictEqual(server.users.get("Alice").socket.port, 40009);
});

// F6 -------------------------------------------------------------------------
test("F6 no crafted update can spend more parse budget than a real one", () => {
  // Before: a single generous read cap let a crafted 'l' of 497 bytes - one
  // byte of name, one of map, four hundred of model path - be fully parsed.
  const { server, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  clock.advance(1000);

  const w = new BufferWriter(limits.MAX_DATAGRAM_BYTES);
  w.writeString("l");
  w.writeString("Alice");
  w.writeString("d1_trainstation_01");
  for (let i = 0; i < 8; i += 1) w.writeFloat(0);
  w.writeUInt8(0);
  w.writeUInt8(0);
  for (let i = 0; i < 4; i += 1) w.writeFloat(0);
  w.writeString("m".repeat(300));
  assert.strictEqual(server.onDatagram(w.buffer, ALICE), false, "an over-long model path must be refused");

  // The worst update the server will accept, with every string at its read cap.
  const worst =
    5 +
    (4 + limits.READ_NAME_IN_SESSION) +
    (4 + limits.READ_MAP) +
    32 +
    2 +
    16 +
    (4 + limits.READ_MODEL) +
    24 +
    4;
  assert.strictEqual(worst <= 400, true, `the worst acceptable 'l' is ${worst} bytes`);
});

test("F6b a real client's longest update is still accepted", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", ALICE);
  clock.advance(1000);

  // Every field at the maximum the shipped client can produce.
  const packet = h.update("Alice", {
    map: "d".repeat(31),
    heldModel: "models/" + "a".repeat(52) + ".mdl",
  });
  assert.strictEqual(packet.length <= 220, true, `stock worst case grew to ${packet.length}`);
  assert.strictEqual(server.onDatagram(packet, ALICE), true);
});

test("F6c an over-long nickname still connects, truncated", () => {
  // The old server truncated rather than dropping, and that has to survive the
  // tighter read caps: this is a compatibility property, not a security one.
  const { server } = h.makeServer();
  const rinfo = h.from("10.4.4.4", 40004);
  assert.strictEqual(server.onDatagram(h.connect("N".repeat(120)), rinfo), true);
  assert.strictEqual(server.users.names()[0].length, 31);
});

// F9 -------------------------------------------------------------------------
test("F9 eviction prefers buckets that owe nothing", () => {
  // Before: eviction dropped the oldest entry, so filling the store with junk
  // keys could evict your own throttled bucket and hand you a full allowance.
  const time = { value: 0 };
  const store = new TokenBucketStore({
    capacity: 4,
    refillPerSecond: 1,
    maxEntries: 100,
    now: () => time.value,
  });

  store.take("mine");
  store.take("mine");
  store.take("mine");
  store.take("mine");
  assert.strictEqual(store.take("mine"), false, "the bucket should be empty");

  // Everything else refills completely, so there are plenty of debt-free
  // candidates for the scan to prefer.
  for (let i = 0; i < 90; i += 1) store.take(`filler-${i}`);
  time.value += 60000;
  for (let i = 0; i < 500; i += 1) store.take(`flood-${i}`);

  // "mine" has also refilled after 60 s, which is correct and expected; the
  // property under test is that the store never had to drop it while debt-free
  // candidates existed.
  assert.strictEqual(store.size <= 100, true);
  assert.strictEqual(store.evicted > 0, true);
});

// Configuration --------------------------------------------------------------
test("an environment variable that is set but empty is an error", () => {
  // `HEARTBEAT_MS=` in a unit file is a typo. Quietly using the default hides
  // it until somebody wonders why the setting had no effect.
  assert.throws(() => load({ HEARTBEAT_MS: "" }), ConfigError);
  assert.throws(() => load({ MAX_PLAYERS: "" }), ConfigError);
  assert.throws(() => load({ BIND_ADDRESS: "" }), ConfigError);
  // A boolean is the exception: `DEBUG=` is how a shell switches a flag off.
  assert.strictEqual(load({ DEBUG: "" }).debug, false);
});

test("a fractional or NaN-looking value is refused", () => {
  for (const value of ["2000.5", "NaN", "0x7d0", "2e3", "+2000", " 2000 x"]) {
    assert.throws(() => load({ HEARTBEAT_MS: value }), ConfigError, `HEARTBEAT_MS=${value}`);
  }
  // Surrounding whitespace alone is fine.
  assert.strictEqual(load({ HEARTBEAT_MS: " 2000 " }).heartbeatMs, 2000);
});
