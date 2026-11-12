"use strict";

// C2 (review 1): boxing wrong-owner traffic did not slow the sweep it targets.
// The box only drops packets aimed at WRONG ports; the one forged datagram that
// matters comes from the victim's real address:port, which is a confirmed
// endpoint, so it skipped the address box. A forged /ban from a PIN-less operator
// landed ~2.4 s into a 5000 pps sweep. Fixes:
//   (a) `op "Nick"` needs a PIN of at least 6 digits unless OP_ALLOW_NO_PIN=1;
//       5 wrong PINs revoke the session's approval;
//   (b) [review 2, N2: replaced] the targeted SESSION is guarded instead of the
//       whole address muted: 20 packets naming it from its own IP but another
//       port within 30 s refuse its endpoint's chat, commands and other actions
//       until 10 minutes after the last one (positions keep relaying). See
//       review2.test.js for the l-oracle, rename and NAT-neighbour cases;
//   (c) only the hijack shape counts as wrong-owner: a packet naming an existing
//       CONFIRMED session from another endpoint. An unknown name - a client still
//       sending after a server restart, a lost connect, a kick - is noise.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");

const VICTIM = "198.51.100.7";
const REAL_PORT = 61234; // inside the Windows ephemeral range swept below

const lobby = (env) => {
  const rig = h.makeServer(env);
  const victim = h.from(VICTIM, REAL_PORT);
  rig.server.onDatagram(h.connect("Alice"), victim);
  rig.server.onDatagram(h.update("Alice"), victim);
  const bob = h.from("203.0.113.9", 50000);
  rig.server.onDatagram(h.connect("Bob"), bob);
  rig.server.onDatagram(h.update("Bob"), bob);
  return Object.assign(rig, { victim, bob });
};

test("C2(b): a 5000 pps sweep that INCLUDES the real port never lands a forged /ban (no PIN)", () => {
  const { server, clock, victim } = lobby({ OP_ALLOW_NO_PIN: "1" });
  assert.strictEqual(server.grantOp("Alice", { addedBy: "console" }).ok, true);

  let landed = false;
  let positionsRelayed = 0;
  const markBob = server.socket.sent.length;
  for (let p = 49152; p <= 65535; p++) {
    server.onDatagram(h.chat("Alice", "/ban Bob perm"), h.from(VICTIM, p));
    if (server.access.banFor("Bob", "203.0.113.9")) landed = true;
    if (p % 5 === 0) {
      clock.advance(1); // 5000 pps
      // The victim keeps playing throughout.
      if (p % 100 === 0) server.onDatagram(h.update("Alice", { position: [p, 0, 0] }), victim);
    }
  }
  assert.strictEqual(landed, false, "a forged /ban from the real port executed");
  assert.ok(server.users.get("Bob"), "Bob was removed");
  positionsRelayed = h.sentTo(server.socket, "203.0.113.9", 50000, markBob)
    .filter((pk) => pk.buffer.readUInt8(0) === packets.TYPE.INFO).length;
  assert.ok(positionsRelayed > 0, "the victim's positions must keep relaying while the session is guarded");
  assert.ok(server.users.get("Alice"), "the victim must stay connected");
});

test("N2: the guard lifts IMPERSONATION_GUARD_MS after the last wrong-port packet, not before", () => {
  const { server, clock, victim, bob } = lobby({ OP_ALLOW_NO_PIN: "1" });
  server.grantOp("Alice", { addedBy: "console" });
  for (let p = 20000; p < 20030; p++) server.onDatagram(h.chat("Alice", "/broadcast x"), h.from(VICTIM, p));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true);
  // Where the review-1 address mute lapsed: the session is still guarded.
  clock.advance(31000);
  server.onDatagram(h.update("Alice"), victim); // still connected and playing
  server.onDatagram(h.chat("Alice", "/kick Bob"), victim);
  assert.ok(server.users.get("Bob"), "a command from a guarded endpoint executed");
  // Past the guard, the real operator can moderate from chat again. Both keep
  // playing meanwhile (the sweep would time them out otherwise).
  for (let t = 0; t < server.config.impersonationGuardMs; t += 20000) {
    clock.advance(20000);
    server.onDatagram(h.update("Alice"), victim);
    server.onDatagram(h.update("Bob"), bob);
  }
  assert.ok(server.users.get("Bob"), "precondition: Bob is still here");
  server.onDatagram(h.chat("Alice", "/kick Bob"), victim);
  assert.ok(!server.users.get("Bob"), "the real operator could not act after the guard lapsed");
});

test("C2(c): a client that keeps sending after a server restart does not get its IP boxed", () => {
  // A fresh server knows nobody; the client sends 'l' at 50 Hz for 10 s before
  // it notices (its own 10 s timeout) and reconnects.
  const { server, clock } = h.makeServer();
  const client = h.from("198.51.100.20", 51000);
  for (let t = 0; t < 10000; t += 20) {
    server.onDatagram(h.update("Returning", { position: [t, 0, 0] }), client);
    clock.advance(20);
  }
  assert.strictEqual(server.penalty.has("198.51.100.20"), false, "an unknown-name client was boxed");
  // ...and its reconnect is answered normally.
  server.onDatagram(h.connect("Returning"), client);
  assert.ok(server.users.get("Returning"), "the reconnect was not admitted");
});

test("C2(a): op without a PIN is refused by default", () => {
  const { server } = lobby();
  const r = server.grantOp("Alice", { addedBy: "console" });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /PIN/);
  assert.strictEqual(server.operatorSessions.size, 0);
  // Too short is refused too.
  assert.strictEqual(server.grantOp("Alice", { addedBy: "console", pin: "12345" }).ok, false);
  assert.strictEqual(server.grantOp("Alice", { addedBy: "console", pin: "123456" }).ok, true);
});

test("C2(a): five wrong PINs revoke the session's operator approval", () => {
  const { server, clock, victim } = lobby({ COMMAND_BURST: "20" });
  server.grantOp("Alice", { addedBy: "console", pin: "482913" });
  for (let i = 0; i < 5; i++) {
    clock.advance(1100);
    server.onDatagram(h.chat("Alice", `/kick 00000${i} Bob`), victim);
  }
  assert.strictEqual(server.operatorSessions.size, 0, "approval survived five wrong PINs");
  clock.advance(1100);
  server.onDatagram(h.chat("Alice", "/kick 482913 Bob"), victim);
  assert.ok(server.users.get("Bob"), "a revoked session still acted");
  // The alert names the player, never the PIN.
  const alert = server.log.lines.find((l) => l[0] === "warn" && /wrong PIN/.test(String(l[1])));
  assert.ok(alert, "no console/journal alert was written");
  assert.ok(!JSON.stringify(server.log.lines).includes("482913"), "the PIN reached the log");
});
