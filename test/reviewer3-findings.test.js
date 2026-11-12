"use strict";

// The third adversarial review, and the defects it found in the second round's
// own fixes. Same rule as the other two files: one test per finding, each one
// failing against the code as it was.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { load, ConfigError } = require("../src/config");
const { PENALTY_MS } = require("../src/server");
const { canonicalizeNickname, nicknameKey } = require("../src/game/nickname");
const { UserManager } = require("../src/game/user-manager");

const NBSP = String.fromCharCode(0x00a0);
const SOFT = String.fromCharCode(0x00ad);
const oversized = () => Buffer.alloc(600, 0x41);
const junk = () => Buffer.from([0, 0, 0, 0]);

// ---------------------------------------------------------------------------
// H1  the penalty box renewed itself forever on oversized traffic
// ---------------------------------------------------------------------------

test("no single sentence is longer than PENALTY_MS, however long the flood runs", () => {
  // The size check used to run above the box check, so an oversized datagram
  // never reached the box - it went straight to punish() and re-armed it. Each
  // packet bought another PENALTY_MS, so at six a second the deadline moved
  // 300 000 ms over a 300 000 ms window: the sentence was the flood's length,
  // not the constant's.
  //
  // What is asserted here is the bound, not the absence of a second sentence: a
  // flood that keeps going will of course be boxed again after the first one
  // lapses. The difference is that the lockout now ends when the flood does.
  const { server, clock } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);

  let longest = 0;
  let deadline = 0;
  for (let tick = 0; tick < 3000; tick += 1) {
    server.onDatagram(oversized(), spoofed);
    clock.advance(100);
    const current = server.penalty.get("10.0.0.1");
    if (current !== undefined && current !== deadline) {
      deadline = current;
      longest = Math.max(longest, current - clock.now());
    }
  }
  assert.ok(longest > 0, "the box never armed, so the test proves nothing");
  assert.ok(longest <= PENALTY_MS, `a single sentence ran for ${longest} ms against PENALTY_MS = ${PENALTY_MS}`);
});

test("a slow forged drip no longer locks the real owner out of their own address", () => {
  // Six oversized datagrams a second was the reviewer's lockout. Measured after
  // the fix: the client's first five-second retry gets in.
  const { server, clock } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  const victim = h.from("10.0.0.1", 40001);

  let joined = false;
  for (let tick = 0; tick < 1200 && !joined; tick += 1) {
    for (let i = 0; i < 6; i += 1) server.onDatagram(oversized(), spoofed);
    clock.advance(1000);
    if (tick % 5 === 4) {
      server.onDatagram(h.connect("Victim"), victim);
      joined = server.users.exists("Victim");
    }
  }
  assert.strictEqual(joined, true, "the victim never got in");
});

// Traffic spread over 10 ms ticks, with the victim's retry landing at an
// arbitrary offset inside the second rather than immediately after a full
// second of silence. That distinction is not cosmetic: the first version of
// this test sent a whole second of junk in one burst, advanced the clock by a
// second - which refills every bucket - and only then sent the connect, so the
// victim always arrived at the instant of maximum token availability. It passed
// with the fix removed. Mutation testing is how that was found.
const lockoutRun = ({
  junkPps = 0,
  junkShape = "plain",
  oversizedPps = 0,
  seconds = 120,
  retryEveryMs = 5000,
  rotatePorts = false,
}) => {
  const { server, clock } = h.makeServer();
  let nextPort = 50000;
  // A fixed source port is the easy case. Rotating it is what an off-path
  // spoofer actually does, and it is the case that defeats anything keyed by
  // endpoint - the sender picks the key, so a fresh port is a fresh bucket.
  const spoofedFrom = () => (rotatePorts ? h.from("10.0.0.1", 50000 + (nextPort++ % 15000)) : h.from("10.0.0.1", 59999));
  const spoofed = h.from("10.0.0.1", 59999);
  const victim = h.from("10.0.0.1", 40001);
  const shaped = junkShape === "connect" ? Buffer.from([0, 0, 0, 1, 0x63]) : junk();

  // Arm the box first, so every run starts from the same place.
  for (let i = 0; i < 30; i += 1) {
    server.onDatagram(oversized(), spoofed);
    clock.advance(10);
  }

  let junkDebt = 0;
  let oversizedDebt = 0;
  let sinceRetry = 1700; // an arbitrary offset, not a multiple of anything
  let retries = 0;
  const step = 10;
  for (let elapsed = 0; elapsed < seconds * 1000; elapsed += step) {
    junkDebt += (junkPps * step) / 1000;
    oversizedDebt += (oversizedPps * step) / 1000;
    while (junkDebt >= 1) {
      server.onDatagram(shaped, spoofedFrom());
      junkDebt -= 1;
    }
    while (oversizedDebt >= 1) {
      server.onDatagram(oversized(), spoofed);
      oversizedDebt -= 1;
    }
    sinceRetry += step;
    if (sinceRetry >= retryEveryMs) {
      sinceRetry = 0;
      retries += 1;
      server.onDatagram(h.connect("Victim"), victim);
      if (server.users.exists("Victim")) return { joined: true, retries };
    }
    clock.advance(step);
  }
  return { joined: false, retries };
};

test("junk from a boxed address cannot drain the path a connect needs", () => {
  // Ordering alone was not enough. With the box re-armed the moment it lapsed
  // and a parallel stream of junk draining the shared trickle, a real client at
  // the forged address never landed a connect in two minutes of retrying.
  for (const junkPps of [10, 200, 2000]) {
    const result = lockoutRun({ junkPps, oversizedPps: 6 });
    assert.strictEqual(result.joined, true, `locked out at ${junkPps} plain junk datagrams a second`);
  }
});

test("connect-shaped junk cannot drain it either", () => {
  // The second round of review broke the fix above by changing five bytes: a
  // datagram of 00 00 00 01 63 is connect-shaped, so it spent the connect half
  // of the trickle - and, through a fallback that no longer exists, the general
  // half as well. Ten a second locked the address out indefinitely.
  for (const junkPps of [10, 200, 2000]) {
    const result = lockoutRun({ junkPps, junkShape: "connect", oversizedPps: 6 });
    assert.strictEqual(result.joined, true, `locked out at ${junkPps} connect-shaped datagrams a second`);
  }
});

test("a flood of well-formed forged connects cannot hold the address's budget empty", () => {
  // The other half of the same finding, and the one the penalty box cannot
  // reach at all: well-formed connects never reach punish(), so the box is
  // never armed. Ten a second - 224 bytes per second - emptied the per-address
  // connect budget and kept it empty, and the victim's own connect got no reply
  // of any kind, so the client retried silently for ever.
  const { server, clock } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  const victim = h.from("10.0.0.1", 40001);

  let joined = false;
  let debt = 0;
  for (let elapsed = 0; elapsed < 60000 && !joined; elapsed += 10) {
    debt += 10 / 100; // ten forged connects a second
    while (debt >= 1) {
      server.onDatagram(h.connect(`Ghost${elapsed}`), spoofed);
      debt -= 1;
    }
    if (elapsed % 5000 === 1700) {
      server.onDatagram(h.connect("Victim"), victim);
      joined = server.users.exists("Victim");
    }
    clock.advance(10);
  }
  assert.strictEqual(joined, true, "the victim never got a connect through");
  assert.strictEqual(server.penalty.size, 0, "well-formed connects should not arm the box; the test would be moot");
});

test("the two halves of the trickle are spent by their own traffic and nothing else", () => {
  // Asserted on the buckets rather than on an outcome, because the outcome hid
  // it: a mutation restoring the probe -> probeConnect fallback left the whole
  // suite green. A test that only ever floods from one endpoint never empties
  // the connect half, so the fallback is never taken and its absence is
  // invisible.
  const rig = h.makeServer();
  const address = "10.0.0.1";
  const arm = h.from(address, 59000);
  for (let i = 0; i < 30; i += 1) {
    rig.server.onDatagram(oversized(), arm);
    rig.clock.advance(10);
  }
  assert.strictEqual(rig.server.penalty.has(address), true);
  // Let the trickles refill before the measurement: arming the box spends the
  // general half, and reading the baseline at zero would hide any extra drain.
  rig.clock.advance(5000);

  // A handful of endpoints, flooded: few enough that each one's own token runs
  // dry, many enough that the address ceiling does too. Flooding from three
  // thousand endpoints instead would leave the per-endpoint half permanently
  // full - every fresh port is a fresh bucket - so a fallback that only fires
  // on an empty bucket would never be exercised. That was the blind spot that
  // let an earlier version of this test pass with the fallback restored.
  const connectShaped = Buffer.from([0, 0, 0, 1, 0x63]);
  const generalBefore = rig.server.probe.available(address);
  const few = [0, 1, 2, 3, 4].map((i) => h.from(address, 51000 + i));
  for (let i = 0; i < 3000; i += 1) rig.server.onDatagram(connectShaped, few[i % few.length]);
  assert.ok(rig.server.probeConnect.available(`${address}:51000`) < 1, "the per-endpoint half was not spent");
  assert.ok(rig.server.probeConnectAddress.available(address) < 1, "the address ceiling was not spent");
  assert.strictEqual(
    rig.server.probe.available(address),
    generalBefore,
    "connect-shaped traffic spent tokens from the general half"
  );

  // ...and the other way round.
  const rig2 = h.makeServer();
  for (let i = 0; i < 30; i += 1) {
    rig2.server.onDatagram(oversized(), arm);
    rig2.clock.advance(10);
  }
  rig2.clock.advance(5000);
  const connectBefore = rig2.server.probeConnectAddress.available(address);
  const oneJunk = h.from(address, 51000);
  for (let i = 0; i < 3000; i += 1) rig2.server.onDatagram(junk(), oneJunk);
  assert.strictEqual(
    rig2.server.probeConnectAddress.available(address),
    connectBefore,
    "plain junk spent tokens from the connect half"
  );
  assert.ok(rig2.server.probe.available(address) < 1);
});

test("a datagram shaped like a connect but too short costs the malformed budget, not the connect budget", () => {
  // The connect budget is twelve a minute, so spending one on a five byte
  // datagram that cannot possibly be a connect was how an attacker held an
  // address's budget empty for 224 bytes a second. Reading before charging
  // sends it where it belongs. Asserted on the buckets: an outcome test could
  // not see it, because the endpoint reserve covered for the ordering.
  const rig = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  const connectsBefore = rig.server.connects.available("10.0.0.1");
  const malformedBefore = rig.server.malformed.available("10.0.0.1");

  const shapes = [
    Buffer.from([0, 0, 0, 1, 0x63]),
    Buffer.concat([Buffer.from([0, 0, 0, 1, 0x63]), Buffer.from([0xff, 0xff, 0xff, 0xff])]),
    Buffer.concat([Buffer.from([0, 0, 0, 1, 0x63]), Buffer.from([0, 0, 0, 200])]),
    Buffer.concat([Buffer.from([0, 0, 0, 1, 0x63]), Buffer.from([0, 0, 0, 3]), Buffer.from("abc", "latin1")]),
  ];
  for (const shape of shapes) rig.server.onDatagram(shape, spoofed);

  assert.strictEqual(
    rig.server.connects.available("10.0.0.1"),
    connectsBefore,
    "a malformed connect spent a token from the connect budget"
  );
  assert.ok(rig.server.malformed.available("10.0.0.1") < malformedBefore, "the malformed budget was not charged");
  assert.strictEqual(rig.server.stats.malformed, shapes.length);
});

test("a connect that only the reserve admitted is refused in silence", () => {
  // The reserve gives an endpoint one connect even when the address budget is
  // gone. That is only safe because a connect admitted that way and then
  // refused sends nothing: otherwise it would be a reply to a forged address
  // for five bytes, which is the reflection the connect budget exists to stop.
  const rig = h.makeServer({ MAX_PLAYERS: "1" });
  rig.server.onDatagram(h.connect("Real"), h.from("10.0.0.9", 40001));
  rig.server.onDatagram(h.update("Real"), h.from("10.0.0.9", 40001));

  const spoofed = h.from("10.0.0.1", 59999);
  // Empty the address budget with connects that are answered.
  for (let i = 0; i < 8; i += 1) rig.server.onDatagram(h.connect(`Full${i}`), spoofed);
  const mark = rig.socket.sent.length;

  // Every one of these is admitted only by its own endpoint reserve, and every
  // one is refused because the server is full.
  for (let i = 0; i < 300; i += 1) {
    rig.server.onDatagram(h.connect(`Ghost${i}`), h.from("10.0.0.1", 50000 + i));
  }
  const reflected = rig.socket.sent.slice(mark).filter((packet) => packet.address === "10.0.0.1");
  assert.strictEqual(reflected.length, 0, `${reflected.length} datagrams were reflected at a forged address`);
});

test("the connect half of the trickle is a trickle too", () => {
  // It must not become a way to keep the parser busy: an attacker who sends
  // connect-shaped datagrams gets the same one-per-second, and pays the connect
  // budget on top.
  const { server, clock } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  for (let i = 0; i < 30; i += 1) {
    server.onDatagram(oversized(), spoofed);
    clock.advance(10);
  }
  assert.strictEqual(server.penalty.has("10.0.0.1"), true);

  const before = server.stats.accepted;
  const seconds = 30;
  for (let second = 0; second < seconds; second += 1) {
    for (let i = 0; i < 500; i += 1) server.onDatagram(h.connect(`Ghost${i}`), spoofed);
    clock.advance(1000);
  }
  const accepted = server.stats.accepted - before;
  // Two buckets at one token a second each, so two parses a second is the
  // ceiling and 15 000 datagrams buy 60 of them.
  assert.ok(accepted <= 2 * seconds, `${accepted} of 15 000 forged connects were handled in ${seconds} s`);
  // ...and almost none of those become a session: the connect budget is next.
  assert.ok(server.users.count() <= server.config.connectBurst, `${server.users.count()} forged sessions`);
});

test("punish() alone refuses to extend a live sentence", () => {
  // The guard inside punish() and the ordering in onDatagram cover the same
  // property from two directions, and until this test existed only the ordering
  // was held: deleting the guard left the whole suite green. If anyone ever
  // moves the size check back above the box for a performance reason, this is
  // the test that notices.
  const { server, clock } = h.makeServer();
  const owner = null;
  server.malformed.forget("10.0.0.1");
  for (let i = 0; i < 25; i += 1) server.punish("10.0.0.1", "10.0.0.1:1", owner, clock.now(), "test", "");
  const armedUntil = server.penalty.get("10.0.0.1");
  assert.ok(armedUntil > clock.now(), "the box did not arm");

  clock.advance(PENALTY_MS - 1000);
  for (let i = 0; i < 200; i += 1) server.punish("10.0.0.1", "10.0.0.1:1", owner, clock.now(), "test", "");
  assert.strictEqual(server.penalty.get("10.0.0.1"), armedUntil, "punish() extended a sentence that was still running");

  // ...and once it has lapsed, a new sentence is allowed.
  clock.advance(2000);
  server.malformed.forget("10.0.0.1");
  for (let i = 0; i < 25; i += 1) server.punish("10.0.0.1", "10.0.0.1:1", owner, clock.now(), "test", "");
  assert.ok(server.penalty.get("10.0.0.1") > armedUntil, "a lapsed box can no longer be re-armed");
});

test("PENALTY_MS is an upper bound on the sentence, not a rolling one", () => {
  const { server, clock } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  const victim = h.from("10.0.0.1", 40001);

  for (let i = 0; i < 30; i += 1) {
    server.onDatagram(oversized(), spoofed);
    clock.advance(10);
  }
  // The flood keeps going for the whole sentence and then stops.
  for (let tick = 0; tick < 300; tick += 1) {
    server.onDatagram(oversized(), spoofed);
    clock.advance(100);
  }
  clock.advance(2000);
  server.sweep();
  assert.strictEqual(server.penalty.has("10.0.0.1"), false, "the box outlived the flood");
  assert.strictEqual(server.onDatagram(h.connect("Victim"), victim), true);
  assert.strictEqual(server.users.exists("Victim"), true);
});

test("a boxed sender's oversized traffic costs a lookup, not a parse or a log line", () => {
  const { server, clock, log } = h.makeServer();
  const spoofed = h.from("10.0.0.1", 59999);
  for (let i = 0; i < 30; i += 1) {
    server.onDatagram(oversized(), spoofed);
    clock.advance(10);
  }
  const eventsBefore = log.lines.length;
  const countedBefore = server.stats.oversized;
  for (let i = 0; i < 5000; i += 1) server.onDatagram(oversized(), spoofed);
  assert.strictEqual(server.stats.oversized, countedBefore, "boxed traffic still reached the size check");
  assert.strictEqual(log.lines.length, eventsBefore, "boxed traffic still bought log lines");
});

// ---------------------------------------------------------------------------
// H2  NAME_MAX_LENGTH below 31 made long-named players unplayable
// ---------------------------------------------------------------------------

test("a name at the wire limit still works when NAME_MAX_LENGTH is lowered", () => {
  // config.js documents NAME_MAX_LENGTH=28 as the workaround for the HUD
  // defect. canonicalizeNickname truncated the display name and derived the key
  // from it; nicknameKey did not truncate at all. So a 31-character gh_name -
  // exactly what server.dll can send - registered under a 28-character key and
  // then never matched again: accepted, never authorised, swept 20 s later.
  const rig = h.makeServer({ NAME_MAX_LENGTH: "28" });
  const socket = h.from("10.0.0.1", 40001);
  const long = "A".repeat(31);

  assert.strictEqual(rig.server.onDatagram(h.connect(long), socket), true);
  const user = rig.server.users.bySocketKey("10.0.0.1:40001");
  assert.ok(user, "the connect was not registered at all");
  assert.strictEqual(user.name.length, 28);

  // Every later packet carries the client's full 31 characters.
  rig.clock.advance(100);
  assert.strictEqual(rig.server.onDatagram(h.update(long), socket), true, "the update did not authorise");
  assert.strictEqual(user.confirmed, true, "the session never confirmed");

  rig.clock.advance(1000);
  assert.strictEqual(rig.server.onDatagram(h.chat(long, "hello"), socket), true);
  rig.clock.advance(1000);
  assert.strictEqual(rig.server.onDatagram(h.spectate(long, ""), socket), false, "no change is not an error");

  // ...and it is still there after the unconfirmed sweep would have fired.
  rig.clock.advance(rig.config.unconfirmedTimeoutMs + 5000);
  rig.server.onDatagram(h.update(long), socket);
  rig.server.sweep();
  assert.strictEqual(rig.server.users.count(), 1, "the player was swept");
});

test("nicknameKey and canonicalizeNickname agree at every length", () => {
  for (const limit of [3, 10, 28, 31]) {
    for (const length of [1, 2, 5, 27, 28, 29, 31, 40, 64]) {
      const raw = "aB".repeat(64).slice(0, length);
      const verdict = canonicalizeNickname(raw, limit);
      if (!verdict.ok) continue;
      assert.strictEqual(
        nicknameKey(raw, limit),
        verdict.key,
        `limit ${limit}, length ${length}: the two derivations disagree`
      );
      assert.strictEqual(nicknameKey(verdict.display, limit), verdict.key, "the display name does not re-derive");
    }
  }
});

test("the roster applies the configured limit to every key it derives", () => {
  const users = new UserManager({ maxNameLength: 28 });
  const long = "A".repeat(31);
  const user = users.register(canonicalizeNickname(long, 28).display, { address: "1.2.3.4", port: 1 }, {}, 0, "1.2.3.4:1");
  assert.strictEqual(users.get(long), user, "a 31 character lookup missed a 28 character registration");
  assert.strictEqual(users.exists(long.toLowerCase()), true);
  assert.strictEqual(users.count(), 1);
});

// ---------------------------------------------------------------------------
// H3  the release at the start of a race dropped its own verdict
// ---------------------------------------------------------------------------

const A = h.from("10.0.0.1", 40001);
const B = h.from("10.0.0.2", 40002);

const twoRunnersStaged = () => {
  const rig = h.makeServer({ RACE_LOBBY_MS: "2000" });
  const { server, clock } = rig;
  for (const [name, rinfo] of [["Alice", A], ["Bob", B]]) {
    server.onDatagram(h.connect(name), rinfo);
    server.onDatagram(h.update(name), rinfo);
  }
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), A);
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), B);
  clock.advance(1500);
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();
  for (const [name, rinfo] of [["Alice", A], ["Bob", B]]) {
    server.onDatagram(h.update(name, { map: "d1_trainstation_01" }), rinfo);
    clock.advance(100);
    server.onDatagram(h.checkpoint(name, 1), rinfo);
    clock.advance(100);
  }
  assert.strictEqual(server.race.phase, "countdown_start", `phase was ${server.race.phase}`);
  return rig;
};

test("a runner the race start could not release is handed to the retry list", () => {
  // The release loop at the start of `racing` ignored pauseRunner's verdict, so
  // unlike the cancel and end-of-race paths it never reached unpauseLater. A
  // runner left frozen there cannot reach the finish trigger, so nothing ends
  // the race early: they sat behind the overlay for RACE_MAX_DURATION_MS, two
  // hours by default.
  const rig = twoRunnersStaged();
  const { server, clock, socket } = rig;
  assert.strictEqual(server.race.paused.has("Alice"), true);

  const realSend = server.send.bind(server);
  server.send = (buffer, target, options) => {
    const user = target && target.socket ? target : null;
    if (user && user.name === "Alice") return false;
    return realSend(buffer, target, options);
  };
  clock.advance(5000);
  clock.runTimeouts();
  clock.runTimeouts();
  server.send = realSend;

  assert.strictEqual(server.race.phase, "racing");
  assert.strictEqual(server.pendingUnpause.has("Alice"), true, "the frozen runner was forgotten");
  assert.strictEqual(server.pendingUnpause.has("Bob"), false, "Bob was released and must not be on the list");

  const mark = socket.sent.length;
  clock.advance(6000);
  server.sweep();
  const released = h
    .sentTo(socket, "10.0.0.1", 40001, mark)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SERVER_PAUSE && p.buffer.readUInt8(1) === 0);
  assert.strictEqual(released.length, 1, "the sweep did not retry the release");
  assert.strictEqual(server.pendingUnpause.size, 0);
});

// ---------------------------------------------------------------------------
// M1  a no-break space made a second, visually identical roster slot
// ---------------------------------------------------------------------------

test("a no-break space is a space, not a different nickname", () => {
  assert.strictEqual(canonicalizeNickname("Bob" + NBSP + "Smith", 31).key, canonicalizeNickname("Bob Smith", 31).key);
  // ...and the display name keeps whatever the player actually typed.
  assert.strictEqual(canonicalizeNickname("Bob" + NBSP + "Smith", 31).display, "Bob" + NBSP + "Smith");

  const rig = h.makeServer();
  rig.server.onDatagram(h.connect("Bob Smith"), h.from("10.0.0.1", 40001));
  rig.server.onDatagram(h.update("Bob Smith"), h.from("10.0.0.1", 40001));
  const handled = rig.server.onDatagram(h.connect("Bob" + NBSP + "Smith"), h.from("10.0.0.2", 40002));
  assert.strictEqual(handled, false);
  assert.strictEqual(rig.server.users.count(), 1, "two entries that render identically");
  assert.deepStrictEqual(rig.server.users.names(), ["Bob Smith"]);
});

test("folding a no-break space does not merge names that look different", () => {
  // One space and two spaces are visibly different on a fixed width HUD, so
  // they stay separate: this closes an impersonation, it does not start one.
  assert.notStrictEqual(canonicalizeNickname("Bob  Smith", 31).key, canonicalizeNickname("Bob Smith", 31).key);
  assert.notStrictEqual(canonicalizeNickname("BobSmith", 31).key, canonicalizeNickname("Bob Smith", 31).key);
});

// ---------------------------------------------------------------------------
// M2  spectate relayed the sender's spelling of somebody else's name
// ---------------------------------------------------------------------------

test("spectate relays the roster's spelling of the target, never the packet's", () => {
  const rig = h.makeServer();
  const attacker = h.from("10.0.0.1", 40001);
  const bystander = h.from("10.0.0.3", 40003);
  for (const [name, rinfo] of [["Mallory", attacker], ["Aperture", h.from("10.0.0.2", 40002)], ["Watcher", bystander]]) {
    rig.server.onDatagram(h.connect(name), rinfo);
    rig.server.onDatagram(h.update(name), rinfo);
  }

  const spellings = ["aperture", "APERTURE", "A" + SOFT + "perture", "  Aperture  ", "ApErTuRe"];
  const seen = new Set();
  for (const spelling of spellings) {
    rig.clock.advance(400);
    const mark = rig.socket.sent.length;
    rig.server.onDatagram(h.spectate("Mallory", spelling), attacker);
    for (const packet of h.sentTo(rig.socket, "10.0.0.3", 40003, mark)) {
      if (packet.buffer.readUInt8(0) !== packets.TYPE.SPECTATE) continue;
      const watcherLength = packet.buffer.readUInt32BE(1);
      const targetOffset = 5 + watcherLength;
      const targetLength = packet.buffer.readUInt32BE(targetOffset);
      seen.add(packet.buffer.toString("latin1", targetOffset + 4, targetOffset + 4 + targetLength));
    }
  }
  assert.deepStrictEqual(Array.from(seen), ["Aperture"], "a chosen spelling reached other clients");
});

test("re-spelling the current spectate target is still a no-op, so it cannot fan out", () => {
  const rig = h.makeServer();
  const attacker = h.from("10.0.0.1", 40001);
  for (const [name, rinfo] of [["Mallory", attacker], ["Aperture", h.from("10.0.0.2", 40002)]]) {
    rig.server.onDatagram(h.connect(name), rinfo);
    rig.server.onDatagram(h.update(name), rinfo);
  }
  rig.clock.advance(400);
  assert.strictEqual(rig.server.onDatagram(h.spectate("Mallory", "Aperture"), attacker), true);

  let relayed = 0;
  for (const spelling of ["aperture", "APERTURE", "ApErTuRe", "  Aperture "]) {
    rig.clock.advance(400);
    if (rig.server.onDatagram(h.spectate("Mallory", spelling), attacker)) relayed += 1;
  }
  assert.strictEqual(relayed, 0, "case permutations bypassed the no-change check");
});

// ---------------------------------------------------------------------------
// M3  connect paths keyed a pending drop on the newcomer's spelling
// ---------------------------------------------------------------------------

test("a re-announcement in another spelling still cancels its own pending drop", () => {
  const rig = h.makeServer();
  const socket = h.from("10.0.0.1", 40001);
  rig.server.onDatagram(h.connect("Aperture"), socket);
  rig.server.onDatagram(h.update("Aperture"), socket);

  rig.clock.advance(1000);
  rig.server.onDatagram(h.disconnect("Aperture"), socket);
  assert.deepStrictEqual(Array.from(rig.server.pendingDrops.keys()), ["Aperture"]);

  rig.clock.advance(200);
  rig.server.onDatagram(h.connect("APERTURE"), socket);
  assert.strictEqual(rig.server.pendingDrops.size, 0, "the drop stayed armed and will fire in two seconds");

  rig.clock.advance(4000);
  rig.server.resolvePendingDrops();
  assert.strictEqual(rig.server.users.exists("Aperture"), true, "the player was removed after re-announcing");
});

test("a takeover in another spelling is not killed by the old session's pending drop", () => {
  // Reaching the TAKEOVER branch with a pending drop still armed needs care.
  // The first version of this test advanced the clock past TAKEOVER_AFTER_MS,
  // which also fired the 250 ms tick, which resolved the two-second drop and
  // emptied the roster - so the second connect took the REGISTER branch and the
  // fix under test was never executed. Mutation testing caught that: reverting
  // the fix left this test green.
  //
  // TAKEOVER_AFTER_MS below the disconnect grace, and the tick driven by hand,
  // are what make the branch reachable.
  const rig = h.makeServer({ TAKEOVER_AFTER_MS: "1000" });
  const first = h.from("10.0.0.1", 40001);
  rig.server.onDatagram(h.connect("Aperture"), first);
  rig.server.onDatagram(h.update("Aperture"), first);

  rig.clock.advance(1000);
  rig.server.onDatagram(h.disconnect("Aperture"), first);
  assert.strictEqual(rig.server.pendingDrops.size, 1);

  // Silent for longer than TAKEOVER_AFTER_MS but less than DISCONNECT_GRACE_MS,
  // so the drop is still pending when the same address comes back.
  rig.clock.value += 1500;
  const second = h.from("10.0.0.1", 40777);
  const before = rig.server.users.get("Aperture");
  assert.strictEqual(rig.server.onDatagram(h.connect("APERTURE"), second), true);
  assert.notStrictEqual(rig.server.users.get("APERTURE"), before, "this was a re-registration, not a takeover");
  assert.strictEqual(rig.server.pendingDrops.size, 0, "the previous session's drop is still armed");

  rig.clock.advance(4000);
  rig.server.resolvePendingDrops();
  const user = rig.server.users.get("aperture");
  assert.ok(user, "the new session was killed by the old session's pending drop");
  assert.strictEqual(user.socket.port, 40777);
});

// ---------------------------------------------------------------------------
// INFO  a knob that was validated and then never read
// ---------------------------------------------------------------------------

test("a retired setting is refused rather than silently ignored", () => {
  // CONNECT_COOLDOWN_MS was parsed and range-checked and then read by nothing.
  // An operator who set it got a silent no-op, which is the exact failure the
  // config rewrite existed to remove.
  assert.throws(() => load({ CONNECT_COOLDOWN_MS: "5000" }), ConfigError);
  assert.throws(() => load({ CONNECT_COOLDOWN_MS: "0" }), ConfigError);
  assert.strictEqual(load({}).connectCooldownMs, undefined);
  // The replacements still work.
  assert.strictEqual(load({ CONNECT_RATE_PER_MINUTE: "30", CONNECT_BURST: "6" }).connectRatePerMinute, 30);

  // EMOTE_PACK was retired by L9 (the 2026-10-22 client dropped type 14) and is
  // back in 1.3.2 with the client that reads it: accepted, and validated rather
  // than ignored (test/emote-pack.test.js).
  assert.strictEqual(load({ EMOTE_PACK: "set:01FE9DRF000009TR6M9N941CYW" }).emotePack, "set:01FE9DRF000009TR6M9N941CYW");
  assert.throws(() => load({ EMOTE_PACK: "not a pack" }), ConfigError);
  assert.strictEqual(load({}).emotePack, null);
});

test("every setting the config parses has a real call site", () => {
  // Looks for `config.<name>` or `this.config.<name>`, not for the bare word.
  // The first version used source.includes(name), which a mention in a comment
  // or a parameter of the same name satisfied - so a knob added and then never
  // wired up could still pass, which is exactly the failure this test exists to
  // catch.
  const fs = require("fs");
  const path = require("path");
  const ROOT = path.join(__dirname, "..");
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (["node_modules", ".git", "test", "legacy", "scripts"].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) files.push(full);
    }
  };
  walk(ROOT);
  const source = files.map((file) => fs.readFileSync(file, "utf8")).join("\n");

  const config = load({});
  const unread = Object.keys(config)
    .filter((name) => name !== "warnings")
    .filter((name) => !new RegExp(`(?:this\\.)?config\\.${name}\\b`).test(source));
  assert.deepStrictEqual(unread, [], `parsed but never referenced as config.<name>: ${unread.join(", ")}`);

  // ...and the check is not vacuous: a name that is only mentioned in prose
  // must not satisfy it.
  assert.strictEqual(/(?:this\.)?config\.thisKnobDoesNotExist\b/.test(source), false);
});
