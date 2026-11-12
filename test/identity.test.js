"use strict";

// Session ownership and nickname takeover.
//
// The protocol carries no token, so ownership is decided entirely by the source
// address of a datagram. These tests pin what that does and does not buy; the
// part it cannot buy is written down in the report as a residual risk, not
// tested away here.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { ACTION, decideConnect, ownsSession } = require("../src/game/identity");

const session = (address, port, extra = {}) =>
  Object.assign({ name: "Alice", socket: { address, port }, lastSeen: 0, connectedAt: 0, confirmed: true }, extra);

const decide = (existing, socket, now) =>
  decideConnect({ existing, socket, now, takeoverAfterMs: 10000, staleTimeoutMs: 60000 });

test("an unused name is registered", () => {
  assert.strictEqual(decide(null, { address: "1.1.1.1", port: 1 }, 0).action, ACTION.REGISTER);
});

test("the same address and port is the owner re-announcing", () => {
  const existing = session("1.1.1.1", 4000);
  assert.strictEqual(decide(existing, { address: "1.1.1.1", port: 4000 }, 5000).action, ACTION.DUPLICATE);
});

test("the same address on a new port waits out the takeover window", () => {
  const existing = session("1.1.1.1", 4000, { lastSeen: 1000 });
  // A crash and reconnect gives the client a new ephemeral port. Before the
  // window it is a collision; after it, the same player.
  assert.strictEqual(decide(existing, { address: "1.1.1.1", port: 4001 }, 6000).action, ACTION.REJECT);
  assert.strictEqual(decide(existing, { address: "1.1.1.1", port: 4001 }, 12000).action, ACTION.TAKEOVER);
});

test("a different address waits out the full stale timeout", () => {
  const existing = session("1.1.1.1", 4000, { lastSeen: 1000 });
  // Ten seconds of silence is enough for the same address and nowhere near
  // enough for a stranger: otherwise a nickname could be stolen from anyone who
  // alt-tabbed during a map load.
  assert.strictEqual(decide(existing, { address: "9.9.9.9", port: 4000 }, 12000).action, ACTION.REJECT);
  assert.strictEqual(decide(existing, { address: "9.9.9.9", port: 4000 }, 62000).action, ACTION.TAKEOVER);
});

test("a session that never answered can be displaced by anyone", () => {
  // A forged connect registers a name against an address that will never reply.
  // Letting it hold the name for a full minute would be a free way to deny a
  // nickname to the player who actually uses it.
  const ghost = session("1.1.1.1", 4000, { confirmed: false, connectedAt: 0, lastSeen: 0 });
  assert.strictEqual(decide(ghost, { address: "9.9.9.9", port: 5000 }, 5000).action, ACTION.REJECT);
  assert.strictEqual(decide(ghost, { address: "9.9.9.9", port: 5000 }, 11000).action, ACTION.TAKEOVER);
});

// 1.3.1 (final review M3): a confirmed v2 session proved its endpoint with S,
// and nothing unsigned may displace it. The player's own IP on another port is
// no evidence: a spoofer or a CGNAT neighbour sends from it too, and a level
// load or the main menu is 10 s of silence. Its name is freed when the session
// is stale - exactly when the sweep would remove it - and not before.
test("a confirmed v2 session is not taken over from its own address before it is stale", () => {
  const v2 = session("1.1.1.1", 4000, { lastSeen: 1000, protocol: 2, v2Confirmed: true });
  const samePlace = { address: "1.1.1.1", port: 4001 };
  assert.strictEqual(decide(v2, samePlace, 12000).action, ACTION.REJECT, "10 s of silence");
  assert.strictEqual(decide(v2, samePlace, 60999).action, ACTION.REJECT, "just under the stale timeout");
  assert.strictEqual(decide(v2, samePlace, 61000).action, ACTION.TAKEOVER, "stale");
  assert.strictEqual(decide(v2, { address: "9.9.9.9", port: 4000 }, 60999).action, ACTION.REJECT);
  assert.strictEqual(decide(v2, { address: "9.9.9.9", port: 4000 }, 61000).action, ACTION.TAKEOVER);
});

test("a v2 session that never confirmed is displaced like any unproven one", () => {
  // It never showed S, so it may be a forged announce squatting on the name.
  const ghost = session("1.1.1.1", 4000, { confirmed: false, protocol: 2, v2Confirmed: false });
  assert.strictEqual(decide(ghost, { address: "9.9.9.9", port: 5000 }, 5000).action, ACTION.REJECT);
  assert.strictEqual(decide(ghost, { address: "9.9.9.9", port: 5000 }, 11000).action, ACTION.TAKEOVER);
  assert.strictEqual(decide(ghost, { address: "1.1.1.1", port: 4001 }, 11000).action, ACTION.TAKEOVER);
});

test("ownership is address and port together", () => {
  const user = session("1.1.1.1", 4000);
  assert.strictEqual(ownsSession(user, { address: "1.1.1.1", port: 4000 }), true);
  assert.strictEqual(ownsSession(user, { address: "1.1.1.1", port: 4001 }), false);
  assert.strictEqual(ownsSession(user, { address: "1.1.1.2", port: 4000 }), false);
  assert.strictEqual(ownsSession(null, { address: "1.1.1.1", port: 4000 }), false);
});

// End to end ----------------------------------------------------------------

test("a crashed client reclaims its name and other players keep the ghost", () => {
  const { server, socket, clock } = h.makeServer();
  const first = h.from("10.0.0.1", 40001);
  const second = h.from("10.0.0.1", 40002); // same machine, new ephemeral port
  const witness = h.from("10.0.0.2", 40003);

  server.onDatagram(h.connect("Alice"), first);
  server.onDatagram(h.update("Alice"), first);
  server.onDatagram(h.connect("Watcher"), witness);
  server.onDatagram(h.update("Watcher"), witness);

  // Alice's game crashes: no more packets. After the takeover window she
  // reconnects from a new port.
  clock.advance(11000);
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Alice"), second);

  assert.strictEqual(server.users.get("Alice").socket.port, 40002);
  // The witness must not see a leave: the ghost is replaced by the same name,
  // so announcing a disconnect would make it vanish and reappear.
  const toWitness = h.sentTo(socket, witness.address, witness.port, mark);
  assert.strictEqual(toWitness.some((p) => p.buffer.readUInt8(0) === packets.TYPE.DISCONNECT), false);
  assert.strictEqual(toWitness.some((p) => p.buffer.readUInt8(0) === packets.TYPE.CONNECT), true);
});

test("a name in use is refused with a reason that fits the client's buffer", () => {
  const { server, socket, clock } = h.makeServer();
  const owner = h.from("10.0.0.1", 40001);
  const thief = h.from("10.0.0.9", 40009);

  const longName = "N".repeat(31);
  server.onDatagram(h.connect(longName), owner);
  server.onDatagram(h.update(longName), owner);
  clock.advance(1000);

  const mark = socket.sent.length;
  server.onDatagram(h.connect(longName), thief);

  const reply = h.sentTo(socket, thief.address, thief.port, mark)[0];
  assert.strictEqual(reply.buffer.readUInt8(0), packets.TYPE.KICK);
  // ev.reason is char[64] in GhostOnlineEngine.h. The old server relied on a
  // comment asking future editors to keep the sentence short.
  assert.strictEqual(reply.buffer.readUInt32BE(1) <= 63, true);
  assert.strictEqual(server.users.get(longName).socket.port, owner.port);
});

test("one socket cannot be two players at once", () => {
  const { server, clock } = h.makeServer();
  const rinfo = h.from("10.0.0.1", 40001);

  server.onDatagram(h.connect("Alice"), rinfo);
  server.onDatagram(h.update("Alice"), rinfo);
  clock.advance(20000);
  server.onDatagram(h.connect("Bob"), rinfo);

  assert.strictEqual(server.users.exists("Bob"), true);
  assert.strictEqual(server.users.exists("Alice"), false, "the previous session on that socket must go");
  assert.strictEqual(server.users.count(), 1);
});

test("a name is only usable by the socket that registered it", () => {
  const { server, clock } = h.makeServer();
  const owner = h.from("10.0.0.1", 40001);
  const neighbour = h.from("10.0.0.1", 40002); // same address, different port

  server.onDatagram(h.connect("Alice"), owner);
  server.onDatagram(h.update("Alice", { position: [1, 1, 1] }), owner);
  clock.advance(100);

  // Same machine, wrong port: still not the owner. Sharing an address is not
  // evidence of anything, and on a NAT it is common.
  server.onDatagram(h.update("Alice", { position: [500, 0, 0] }), neighbour);
  assert.strictEqual(server.users.get("Alice").position.x, 1);
  assert.strictEqual(server.stats.unauthorised, 1);
});
