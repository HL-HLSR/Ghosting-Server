"use strict";

// M2: one player could exhaust every other client's spray storage by publishing
// a new one-chunk "spray" with a fresh crc every 25 ms (400 in 10 s in the
// audit). Completed publications are now a slow bucket plus a hard per-session
// ceiling, separate from the piece rate.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");

const ALICE = h.from("10.0.0.1", 40001);

test("a flood of distinct publications publishes only a few", () => {
  const { server, clock } = h.makeServer({ SPRAY_UPLOAD_BURST: "4000", SPRAY_UPLOAD_RATE_PER_SECOND: "1000" });
  const alice = server.users.get("Alice") || (() => {
    server.onDatagram(h.connect("Alice"), ALICE);
    server.onDatagram(h.update("Alice"), ALICE);
    return server.users.get("Alice");
  })();

  let lastCrc = null;
  let distinctPublished = 0;
  for (let i = 0; i < 400; i++) {
    const { blob, crc } = h.sprayBlob(8, (i % 200) + 1);
    h.uploadSpray(server, ALICE, "Alice", crc, blob);
    if (alice.spray && alice.spray.crc !== lastCrc) {
      distinctPublished += 1;
      lastCrc = alice.spray.crc;
    }
    clock.advance(25); // 10 s total
  }

  // The burst (3) plus whatever the slow bucket refilled in 10 s (2/min ~ 0).
  assert.ok(distinctPublished <= server.config.sprayPublishBurst + 1,
    `${distinctPublished} pictures published in 10 s`);
  assert.ok(alice.sprayPublishCount <= server.config.sprayPublishBurst + 1);
});

test("a session cannot publish past its lifetime ceiling", () => {
  const { server, clock } = h.makeServer({
    SPRAY_UPLOAD_BURST: "4000",
    SPRAY_UPLOAD_RATE_PER_SECOND: "1000",
    SPRAY_PUBLISH_PER_MINUTE: "600", // refill fast so only the hard cap bites
    SPRAY_PUBLISH_BURST: "100",
    SPRAY_REENCODE_BURST: "100", // nor the server-wide re-encode budget (C1)
  });
  server.onDatagram(h.connect("Alice"), ALICE);
  server.onDatagram(h.update("Alice"), ALICE);
  const alice = server.users.get("Alice");

  for (let i = 0; i < 50; i++) {
    const { blob, crc } = h.sprayBlob(8, i + 1);
    h.uploadSpray(server, ALICE, "Alice", crc, blob);
    clock.advance(200);
  }

  assert.strictEqual(alice.sprayPublishCount, server.config.sprayPublishMaxPerSession,
    "the per-session publication ceiling must hold");
});

// ---------------------------------------------------------------------------
// I4 (review 1): session churn from one address bypassed the per-session budget
// ---------------------------------------------------------------------------

const packets = require("../src/wire/packets");
const { Message } = require("../src/wire/reader");

// The reviewer's pattern: one address keeps 4 sessions alive, each publishes a
// burst of 3 tiny valid pictures and leaves; a new port and a new name take its
// place. Returns the distinct (sender, crc) pictures a real receiver was fed.
const churn = (env, seconds, sameName = false) => {
  const { server, socket, clock } = h.makeServer(Object.assign({ SPRAY_REENCODE_BURST: "100", SPRAY_REENCODE_PER_MINUTE: "6000" }, env));
  const rx = h.from("198.51.100.9", 30000);
  server.onDatagram(h.connect("Receiver"), rx);
  server.onDatagram(h.update("Receiver"), rx);
  const ATT = "203.0.113.77";
  let port = 2000;
  let n = 0;
  let fill = 1;
  const t0 = clock.now();
  while (clock.now() - t0 < seconds * 1000) {
    if (server.sessionsFrom(ATT) < 4) {
      const r = h.from(ATT, port++);
      const name = sameName ? "Churner" : `churn${n}`;
      n += 1;
      server.onDatagram(h.connect(name), r);
      server.onDatagram(h.update(name), r);
      for (let k = 0; k < 3; k++) {
        const { blob, crc } = h.sprayBlob(8, (fill++ % 250) + 1);
        h.uploadSpray(server, r, name, crc, blob);
      }
      server.onDatagram(h.disconnect(name), r);
      // Same name: let the 2 s disconnect grace resolve, so the next session
      // really is a fresh one holding the same name (not refused as "in use").
      if (sameName) {
        for (let w = 0; w < 110; w++) {
          clock.advance(20);
          server.onDatagram(h.update("Receiver", { position: [w, 0, 0] }), rx);
        }
      }
    }
    server.onDatagram(h.update("Receiver", { position: [clock.now() % 1000, 0, 0] }), rx);
    clock.advance(20);
  }
  const seen = new Set();
  for (const p of h.sentTo(socket, rx.address, rx.port)) {
    if (p.buffer[0] !== packets.TYPE.SPRAY_CHUNK) continue;
    const m = new Message(p.buffer.subarray(1), {});
    seen.add(`${m.readString()}/${m.readInt32()}`);
  }
  return { server, distinct: seen.size };
};

test("I4: churning sessions from one address is held to the address budget", () => {
  const { server, distinct } = churn({}, 60);
  // A burst of 4 sessions' worth, then 4 sessions' worth of the slow refill.
  const perAddressBurst = server.config.sprayPublishBurst * server.config.maxSessionsPerAddress;
  const perAddressMinute = server.config.sprayPublishPerMinute * server.config.maxSessionsPerAddress;
  assert.ok(distinct <= perAddressBurst + perAddressMinute, `${distinct} pictures from one address in 60 s`);
});

test("I4: reconnecting under the same name does not reset the name's budget", () => {
  const { server, distinct } = churn({}, 60, true);
  assert.ok(distinct <= server.config.sprayPublishBurst + server.config.sprayPublishPerMinute,
    `${distinct} pictures from one name in 60 s`);
});

test("I4: a receiver is fed at most SPRAY_MAX_FED_PER_RECEIVER distinct pictures", () => {
  // Many addresses so the per-address budget is not what stops it. Review 2
  // (m3): the fed cap is its own knob (default 200, below the client's 256
  // written blobs); the 40 is now on pictures whose stamps are relayed
  // (review2.test.js). Set to 40 here so 90 publications exceed it.
  const { server, socket, clock } = h.makeServer({
    MAX_PLAYERS: "64",
    SPRAY_REENCODE_BURST: "100",
    SPRAY_REENCODE_PER_MINUTE: "6000",
    SPRAY_MAX_FED_PER_RECEIVER: "40",
  });
  const rx = h.from("198.51.100.9", 30000);
  server.onDatagram(h.connect("Receiver"), rx);
  server.onDatagram(h.update("Receiver"), rx);
  let fill = 1;
  for (let a = 0; a < 30; a++) {
    const r = h.from(`203.0.${a}.1`, 2000);
    const name = `pub${a}`;
    server.onDatagram(h.connect(name), r);
    server.onDatagram(h.update(name), r);
    for (let k = 0; k < 3; k++) {
      const { blob, crc } = h.sprayBlob(8, (fill++ % 250) + 1);
      h.uploadSpray(server, r, name, crc, blob);
      for (let d = 0; d < 20; d++) {
        clock.advance(20);
        server.onDatagram(h.update("Receiver", { position: [d, a, k] }), rx);
      }
    }
  }
  const seen = new Set();
  for (const p of h.sentTo(socket, rx.address, rx.port)) {
    if (p.buffer[0] !== packets.TYPE.SPRAY_CHUNK) continue;
    const m = new Message(p.buffer.subarray(1), {});
    seen.add(`${m.readString()}/${m.readInt32()}`);
  }
  const cap = server.config.sprayMaxFedPerReceiver;
  assert.ok(cap < 256, "the cap must stay below the client's 256 written remote blobs");
  assert.ok(seen.size <= cap, `${seen.size} distinct pictures fed to one receiver (cap ${cap})`);
  assert.ok(seen.size >= cap - 3, `only ${seen.size} pictures were fed; the cap should be what stops it`);
});
