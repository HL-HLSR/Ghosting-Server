"use strict";

// H3: a trickle of spoofed packets (about one per fake session per 55 s) held
// every slot, so the server reported "full" forever with nothing traceable to
// the attacker. A newcomer may now evict the session with the lowest inbound
// rate when that rate is far below what any real client sends, and only once a
// session has been around long enough to judge.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");

const fillWithSquatters = (env) => {
  const rig = h.makeServer(Object.assign({ MAX_PLAYERS: "16", MAX_SESSIONS_PER_ADDRESS: "64" }, env));
  const fakes = [];
  for (let i = 0; i < 16; i++) {
    const r = h.from(`192.0.2.${i + 1}`, 1000 + i);
    fakes.push(r);
    rig.server.onDatagram(h.connect(`fake${i}`), r);
    rig.server.onDatagram(h.update(`fake${i}`), r);
  }
  return Object.assign(rig, { fakes });
};

test("a trickle of forged sessions no longer keeps a real player out", () => {
  const { server, clock, fakes } = fillWithSquatters();

  // Ten minutes of one keepalive per fake per 55 s: the audit's squat scenario.
  for (let minute = 0; minute < 11; minute++) {
    clock.advance(55000);
    for (let i = 0; i < 16; i++) {
      server.onDatagram(h.update(`fake${i}`, { position: [minute, 0, 0] }), fakes[i]);
    }
  }
  assert.strictEqual(server.users.count(), 16, "all 16 squatters are registered");

  // A real player arrives and is admitted by evicting exactly one squatter.
  const real = h.from("198.51.100.50", 27005);
  server.onDatagram(h.connect("RealPlayer"), real);
  assert.ok(server.users.get("RealPlayer"), "a real player was turned away from a squatted server");
  assert.strictEqual(server.users.count(), 16, "the roster stays at the cap");
  assert.strictEqual(server.stats.squattersEvicted, 1, "exactly one squatter should be evicted");
});

test("sixteen genuinely active players are never evicted for a newcomer", () => {
  const { server, clock, fakes } = fillWithSquatters();

  // Everyone plays at the real cadence for over a window.
  for (let tick = 0; tick < 1700; tick++) {
    clock.advance(40);
    for (let i = 0; i < 16; i++) {
      server.onDatagram(h.update(`fake${i}`, { position: [i, tick, 0] }), fakes[i]);
    }
  }

  const real = h.from("198.51.100.51", 27006);
  const before = server.socket.sent.length;
  server.onDatagram(h.connect("RealPlayer"), real);
  const reply = server.socket.sent.slice(before).map((p) => p.buffer.toString("latin1"));
  assert.strictEqual(server.users.get("RealPlayer"), null, "a real player displaced an active one");
  assert.strictEqual(server.stats.squattersEvicted, 0, "no active player should be evicted");
  assert.ok(reply.some((s) => s.includes("full")), "the newcomer should be told the server is full");
});

test("a player a few seconds into a level load is not mistaken for a squatter", () => {
  const { server, clock, fakes } = fillWithSquatters();

  // Fifteen play normally for well over a window; one goes quiet for an 8 s
  // level load in the middle of it.
  for (let tick = 0; tick < 1700; tick++) {
    clock.advance(40);
    const loading = tick >= 800 && tick < 1000; // 8 s of silence for fake0
    for (let i = 0; i < 16; i++) {
      if (i === 0 && loading) continue;
      server.onDatagram(h.update(`fake${i}`, { position: [i, tick, 0] }), fakes[i]);
    }
  }

  const real = h.from("198.51.100.52", 27007);
  server.onDatagram(h.connect("RealPlayer"), real);
  // The server is full of real (if briefly quiet) players: the newcomer is
  // refused rather than the mid-load player being evicted.
  assert.strictEqual(server.users.get("RealPlayer"), null);
  assert.ok(server.users.get("fake0"), "a player mid level-load was evicted");
  assert.strictEqual(server.stats.squattersEvicted, 0);
});

// ---------------------------------------------------------------------------
// I3 (review 1): two cheap ways around the eviction
// ---------------------------------------------------------------------------

const { BufferWriter } = require("../src/wire/writer");
const tinyChat = (name) => {
  const w = new BufferWriter();
  w.writeString("m");
  w.writeString(name);
  w.writeString("");
  return w.buffer;
};

test("I3: tiny chat packets no longer keep a squatter above the eviction rate", () => {
  const { server, clock, fakes } = fillWithSquatters();
  // ~3 empty chats a second per slot plus one 'l' per 55 s: 775 B/s for all 16
  // slots, which used to count as "busy" because any packet raised the rate.
  for (let ms = 0; ms < 11 * 60000; ms += 333) {
    for (let i = 0; i < 16; i++) server.onDatagram(tinyChat(`fake${i}`), fakes[i]);
    if (ms % 54945 === 0) for (let i = 0; i < 16; i++) server.onDatagram(h.update(`fake${i}`, { position: [ms, 0, 0] }), fakes[i]);
    clock.advance(333);
  }
  const real = h.from("198.51.100.50", 27005);
  server.onDatagram(h.connect("RealPlayer"), real);
  assert.ok(server.users.get("RealPlayer"), "the real player was refused");
  assert.strictEqual(server.stats.squattersEvicted, 1);
});

test("I3: forged never-confirmed connects cannot hold the slots", () => {
  // The forger re-sends 'c' for every slot once a second from a rotating port,
  // never confirming. A real client retries its announce once a second for 6 s,
  // as the DLL does.
  let admitted = 0;
  const trials = 10;
  for (let trial = 0; trial < trials; trial++) {
    const { server, clock } = h.makeServer({ MAX_PLAYERS: "16" });
    const start = 25000 + trial * 1700;
    const nextForge = Array.from({ length: 16 }, (_, i) => (i * 1000) / 16);
    let port = 6000;
    let realIn = false;
    let realTries = 0;
    let nextReal = start;
    for (let ms = 0; ms < start + 7000; ms += 10) {
      for (let i = 0; i < 16; i++) {
        if (ms >= nextForge[i]) {
          server.onDatagram(h.connect(`sq${i}`), h.from(`192.0.2.${i + 1}`, port++));
          nextForge[i] = ms + 1000;
        }
      }
      if (!realIn && ms >= nextReal && realTries < 6) {
        const r = h.from("198.51.100.60", 27000 + trial);
        server.onDatagram(h.connect("Real"), r);
        if (server.users.get("Real")) {
          realIn = true;
          server.onDatagram(h.update("Real"), r); // the client's first line, ~one frame later
        }
        realTries += 1;
        nextReal = ms + 1000;
      }
      clock.advance(10);
    }
    if (realIn && server.users.get("Real")) admitted += 1;
  }
  assert.strictEqual(admitted, trials, `a real client got in ${admitted}/${trials} times`);
});

test("I3: an unconfirmed takeover keeps the original connect time", () => {
  const { server, clock } = h.makeServer();
  server.onDatagram(h.connect("Ghost"), h.from("192.0.2.9", 6000));
  const first = server.users.get("Ghost").connectedAt;
  clock.advance(11000); // past TAKEOVER_AFTER_MS for an unconfirmed holder
  server.onDatagram(h.connect("Ghost"), h.from("192.0.2.9", 6001));
  const holder = server.users.get("Ghost");
  assert.strictEqual(holder.socket.port, 6001, "the takeover should have happened");
  assert.strictEqual(holder.connectedAt, first, "a forged re-connect reset the unconfirmed age");
  // ...so the unconfirmed sweep still fires on the original schedule: 26 s after
  // the first connect (a reset holder would live until ~31-35 s).
  clock.advance(15000);
  assert.strictEqual(server.users.get("Ghost"), null, "the never-confirmed holder outlived its 20 s");
});
