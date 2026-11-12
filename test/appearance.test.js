"use strict";

// Changing colour mid-session.
//
// Colours used to travel exactly once, inside the connect, and nothing ever
// refreshed them: a player who changed gh_ghost_color kept the old colour on
// every other screen until they reconnected. The 'v' opcode carries the same
// seven bytes again and the host relays them as a roster entry.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const { BufferWriter } = require("../src/wire/writer");
const limits = require("../src/wire/limits");

const ALICE = h.from("10.0.0.1", 40001);
const BOB = h.from("10.0.0.2", 40002);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

// Field order matches onAppearance.
const appearance = (name, colours) =>
  new BufferWriter()
    .writeString("v", limits.MAX_OPCODE_LENGTH)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeUInt8(colours.trailLength)
    .writeUInt8(colours.trailRed)
    .writeUInt8(colours.trailGreen)
    .writeUInt8(colours.trailBlue)
    .writeUInt8(colours.ghostRed)
    .writeUInt8(colours.ghostGreen)
    .writeUInt8(colours.ghostBlue).buffer;

const NEW = {
  trailLength: 9,
  trailRed: 1,
  trailGreen: 2,
  trailBlue: 3,
  ghostRed: 4,
  ghostGreen: 5,
  ghostBlue: 6,
};

test("an appearance packet updates the sender's stored colours", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);

  assert.strictEqual(server.onDatagram(appearance("Alice", NEW), ALICE), true);

  assert.strictEqual(alice.ghostRed, 4);
  assert.strictEqual(alice.ghostGreen, 5);
  assert.strictEqual(alice.ghostBlue, 6);
  assert.strictEqual(alice.trailRed, 1);
  assert.strictEqual(alice.trailLength, 9);
});

test("the change is relayed to everybody else, with the announce byte clear", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  const mark = socket.sent.length;
  server.onDatagram(appearance("Alice", NEW), ALICE);

  const toBob = socket.sent.slice(mark).filter((s) => s.port === BOB.port);
  assert.strictEqual(toBob.length, 1, "Bob should get exactly one packet");

  const b = toBob[0].buffer;
  assert.strictEqual(b[0], 0x00, "relayed as a roster entry");
  // Announce byte is the last one: 0 means "not a fresh join", so no console
  // line and no join sound for a colour change.
  assert.strictEqual(b[b.length - 1], 0, "must not be announced as a join");
});

test("the sender is not sent their own change back", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", ALICE);
  join(server, "Bob", BOB);

  const mark = socket.sent.length;
  server.onDatagram(appearance("Alice", NEW), ALICE);

  const toAlice = socket.sent.slice(mark).filter((s) => s.port === ALICE.port);
  assert.strictEqual(toAlice.length, 0);
});

test("a stranger cannot repaint somebody who is on the roster", () => {
  const { server } = h.makeServer();
  const alice = join(server, "Alice", ALICE);
  const before = alice.ghostRed;

  // Bob's endpoint claiming Alice's name: authorise() is what stops this, and
  // without it a colour change would be a free way to vandalise another player.
  assert.strictEqual(server.onDatagram(appearance("Alice", NEW), BOB), false);
  assert.strictEqual(alice.ghostRed, before);
});

test("an appearance from somebody who never connected is refused", () => {
  const { server } = h.makeServer();
  assert.strictEqual(server.onDatagram(appearance("Nobody", NEW), ALICE), false);
});
