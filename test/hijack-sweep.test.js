"use strict";

// H1: a session (including an operator's) could be hijacked in about a minute
// because wrong-owner packets cost nothing. The attacker forges the victim's
// source address and sweeps their ephemeral ports; the one that owns the
// session executes whatever it carries (chat as them, /ban anyone, ...).
//
// Review 2 (N2): wrong-owner packets no longer box the sender's address - that
// never stopped the packet from the victim's real port (a confirmed endpoint
// skips the box) and muting the address hurt NAT neighbours. Packets naming a
// session from its own IP but another port now put THAT session under an
// impersonation guard (its endpoint may not act for 10 minutes after the last
// one); packets from other IPs never affect it. Operator commands additionally
// require a PIN.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");

const VICTIM_ADDR = "198.51.100.7";
const VICTIM_PORT = 40001;

test("wrong-owner traffic never executes, is counted, and guards the targeted session (not the address)", () => {
  const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  const victim = h.from(VICTIM_ADDR, VICTIM_PORT);
  server.onDatagram(h.connect("OpAlice"), victim);
  server.onDatagram(h.update("OpAlice"), victim);
  assert.strictEqual(server.grantOp("OpAlice", { addedBy: "console" }).ok, true);

  const bob = h.from("203.0.113.9", 50000);
  server.onDatagram(h.connect("Bob"), bob);
  server.onDatagram(h.update("Bob"), bob);

  // A blind sweep of WRONG ports (never the real 40001) carrying a forged op
  // command. None owns the session, so none executes; after 20 the targeted
  // session is guarded.
  let port = 20000;
  for (let batch = 0; batch < 200; batch++) {
    for (let i = 0; i < 100; i++) {
      server.onDatagram(h.chat("OpAlice", "/ban Bob perm pwned"), h.from(VICTIM_ADDR, port++));
    }
    clock.advance(250);
  }

  assert.ok(server.users.get("Bob"), "Bob was removed by a forged /ban from a wrong port");
  assert.strictEqual(server.access.banFor("Bob", "203.0.113.9"), null, "a forged /ban was stored");
  assert.strictEqual(server.penalty.has(VICTIM_ADDR), false, "wrong-owner traffic must not box the address");
  assert.strictEqual(server.isGuarded(server.users.get("OpAlice"), clock.now()), true, "the targeted session is not guarded");
  assert.ok(server.stats.unauthorised >= 20, `only ${server.stats.unauthorised} wrong-owner packets were counted`);
});

test("without a PIN, a datagram from the operator's EXACT 5-tuple still acts as them", () => {
  // The unavoidable "guess the live 5-tuple" case: with NO sweep (so nothing
  // armed the guard) and no PIN, a single forged packet from the operator's own
  // address:port is byte-for-byte what the real operator sends. The test pins
  // the limitation; the PIN (required by default) is what closes it.
  const { server } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
  const victim = h.from(VICTIM_ADDR, VICTIM_PORT);
  server.onDatagram(h.connect("OpAlice"), victim);
  server.onDatagram(h.update("OpAlice"), victim);
  server.grantOp("OpAlice", { addedBy: "console" });
  const bob = h.from("203.0.113.9", 50000);
  server.onDatagram(h.connect("Bob"), bob);
  server.onDatagram(h.update("Bob"), bob);

  server.onDatagram(h.chat("OpAlice", "/ban Bob perm"), victim); // exact owner 5-tuple
  assert.ok(server.access.banFor("Bob", "203.0.113.9"), "the exact-5-tuple case should still execute");
});

test("with an operator PIN, even a 65536-port sweep never lands the command", () => {
  const { server, clock } = h.makeServer();
  const victim = h.from(VICTIM_ADDR, VICTIM_PORT);
  server.onDatagram(h.connect("OpAlice"), victim);
  server.onDatagram(h.update("OpAlice"), victim);
  // Approve WITH a PIN the off-path attacker cannot observe.
  assert.strictEqual(server.grantOp("OpAlice", { addedBy: "console", pin: "857142" }).pinSet, true);

  const bob = h.from("203.0.113.9", 50000);
  server.onDatagram(h.connect("Bob"), bob);
  server.onDatagram(h.update("Bob"), bob);

  // Sweep every port INCLUDING the real one, with the command the attacker would
  // send (no PIN, since they cannot know it).
  for (let p = 0; p <= 65535; p++) {
    server.onDatagram(h.chat("OpAlice", "/ban Bob perm pwned"), h.from(VICTIM_ADDR, p));
    if (p % 1000 === 999) clock.advance(50);
  }
  assert.ok(server.users.get("Bob"), "the PIN did not stop a forged /ban");
  assert.strictEqual(server.access.banFor("Bob", "203.0.113.9"), null, "a forged /ban was stored despite the PIN");

  // The sweep guarded the operator's session (N2), so their own chat commands
  // wait for the guard to lapse (they can use the console meanwhile); after
  // that, with the PIN, they moderate normally.
  clock.advance(31000);
  server.onDatagram(h.chat("OpAlice", "/ban 857142 Bob perm griefing"), victim);
  assert.strictEqual(server.access.banFor("Bob", "203.0.113.9"), null, "the guard should hold for its whole window");
  for (let t = 0; t < server.config.impersonationGuardMs; t += 20000) {
    clock.advance(20000); // both keep playing, or the sweep times them out
    server.onDatagram(h.update("OpAlice"), victim);
    server.onDatagram(h.update("Bob"), bob);
  }
  server.onDatagram(h.chat("OpAlice", "/ban 857142 Bob perm griefing"), victim);
  assert.ok(server.access.banFor("Bob", "203.0.113.9"), "the real operator with the PIN should be able to ban");
});

test("the targeted player and a NAT neighbour on the same address keep playing during a sweep", () => {
  const { server, clock } = h.makeServer();
  const victim = h.from(VICTIM_ADDR, VICTIM_PORT);
  server.onDatagram(h.connect("OpAlice"), victim);
  server.onDatagram(h.update("OpAlice"), victim);

  // A confirmed neighbour on the SAME public address, different port.
  const neighbour = h.from(VICTIM_ADDR, 50002);
  server.onDatagram(h.connect("Neighbour"), neighbour);
  server.onDatagram(h.update("Neighbour"), neighbour);

  // Enough wrong-owner traffic from the address to trip the guard on OpAlice.
  for (let i = 0; i < 40; i++) server.onDatagram(h.chat("OpAlice", "/broadcast x"), h.from(VICTIM_ADDR, 20000 + i));
  assert.strictEqual(server.penalty.has(VICTIM_ADDR), false, "the shared address must not be boxed");
  assert.strictEqual(server.isGuarded(server.users.get("OpAlice"), clock.now()), true);
  assert.strictEqual(server.isGuarded(server.users.get("Neighbour"), clock.now()), false);

  // Both the victim and the neighbour are still accepted and relayed. (Past the
  // per-line throttle, which is the only reason an update is otherwise dropped.)
  clock.advance(50);
  assert.strictEqual(server.onDatagram(h.update("OpAlice", { position: [1, 0, 0] }), victim), true);
  assert.strictEqual(server.onDatagram(h.update("Neighbour", { position: [2, 0, 0] }), neighbour), true);
  assert.strictEqual(server.penalty.has(`${VICTIM_ADDR}:${VICTIM_PORT}`), false, "the victim's endpoint must not be boxed");
  assert.strictEqual(server.penalty.has(`${VICTIM_ADDR}:50002`), false, "the neighbour's endpoint must not be boxed");
});

test("OP_CHAT_COMMANDS=0 removes the admin chat surface entirely", () => {
  const { server } = h.makeServer({ OP_CHAT_COMMANDS: "0", OP_ALLOW_NO_PIN: "1" });
  const op = h.from("10.0.0.5", 3000);
  server.onDatagram(h.connect("Op"), op);
  server.onDatagram(h.update("Op"), op);
  server.grantOp("Op", { addedBy: "console" });
  const bob = h.from("10.0.0.6", 3001);
  server.onDatagram(h.connect("Bob"), bob);
  server.onDatagram(h.update("Bob"), bob);

  server.onDatagram(h.chat("Op", "/ban Bob perm"), op);
  assert.ok(server.users.get("Bob"), "Bob was banned though chat admin is disabled");
  assert.strictEqual(server.access.banFor("Bob", "10.0.0.6"), null);
});
