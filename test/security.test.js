"use strict";

// Fifteen attacks, one test each.
//
// Every one of these worked against the server this replaced. The point of the
// file is not that the new code refuses them, it is that a future change which
// re-opens any of them fails here first.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const { BufferWriter } = require("../src/wire/writer");
const { sanitizeForLog } = require("../src/wire/text");
const { SampledLogger } = require("../src/net/logger");

const VICTIM = h.from("10.0.0.1", 40001);
const OTHER = h.from("10.0.0.2", 40002);
const ATTACKER = h.from("203.0.113.9", 6666);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  server.onDatagram(h.update(name), rinfo);
  return server.users.get(name);
};

// 1 --------------------------------------------------------------------------
test("1. an oversized datagram is dropped before it is parsed", () => {
  const { server } = h.makeServer();
  const flood = Buffer.alloc(60000, 0x41);
  assert.strictEqual(server.onDatagram(flood, ATTACKER), false);
  assert.strictEqual(server.stats.oversized, 1);
  // The parser never ran, so nothing was allocated on the attacker's behalf.
  assert.strictEqual(server.stats.malformed, 0);
});

// 2 --------------------------------------------------------------------------
test("2. a four byte probe cannot buy a log line per packet", () => {
  const { server, log } = h.makeServer();
  // An empty opcode string: the cheapest packet that reached console.log in the
  // old server, at roughly four million per second on a gigabit link.
  const probe = Buffer.from([0, 0, 0, 0]);
  for (let i = 0; i < 500; i += 1) server.onDatagram(probe, ATTACKER);

  assert.strictEqual(server.stats.unknownOpcode > 0, true);
  // The address runs out of malformed budget and lands in the penalty box, so
  // most of those packets are never even looked at.
  assert.strictEqual(server.penalty.has(ATTACKER.address), true);
  assert.strictEqual(log.lines.length < 60, true, `logged ${log.lines.length} lines for 500 packets`);
});

test("2a. a flood from one endpoint does not take its NAT neighbours down", () => {
  const { server, socket, clock } = h.makeServer();
  // Several players behind one NAT share a public address. The abuser is a
  // different port on that address, and the innocent player must keep playing.
  join(server, "Alice", VICTIM);
  join(server, "Bob", OTHER);
  clock.advance(1000);

  const abuser = h.from(VICTIM.address, 55555);
  const probe = Buffer.from([0, 0, 0, 0]);
  for (let i = 0; i < 500; i += 1) server.onDatagram(probe, abuser);

  // The address is boxed - the abuser has no session, so there is nothing finer
  // to key on - but a confirmed session on it is exempt from that box.
  assert.strictEqual(server.penalty.has(VICTIM.address), true, "the abusing endpoint must be stopped");

  clock.advance(200);
  const mark = socket.sent.length;
  assert.strictEqual(
    server.onDatagram(h.update("Alice", { position: [42, 0, 0] }), VICTIM),
    true,
    "the innocent player on that address was blocked"
  );
  assert.strictEqual(server.users.get("Alice").position.x, 42);
  assert.strictEqual(h.sentTo(socket, OTHER.address, OTHER.port, mark).length, 1, "their update must still be relayed");

  // And the abuser really is being dropped before the parser runs.
  const before = server.stats.received;
  server.onDatagram(probe, abuser);
  assert.strictEqual(server.stats.received, before + 1);
  assert.strictEqual(server.stats.unknownOpcode < 500, true, "boxed traffic must not be parsed");
});

test("2c. a confirmed session gets no unlimited parse budget", () => {
  const { server, clock } = h.makeServer();
  // Exempting a whole address because it held a confirmed session handed a
  // legitimately connected attacker an unlimited parse allowance: measured at
  // 660 unknown-opcode packets parsed in ten seconds, with the box never
  // closing. The exemption is now for the address level box only; the endpoint
  // itself is still boxed.
  join(server, "Alice", VICTIM);
  clock.advance(1000);

  const probe = Buffer.from([0, 0, 0, 0]);
  let parsed = 0;
  for (let i = 0; i < 1000; i += 1) {
    const before = server.stats.unknownOpcode;
    server.onDatagram(probe, VICTIM);
    if (server.stats.unknownOpcode > before) parsed += 1;
  }

  assert.strictEqual(server.penalty.has(`${VICTIM.address}:${VICTIM.port}`), true, "the endpoint must be boxed");
  assert.strictEqual(parsed <= 25, true, `${parsed} packets were parsed from a confirmed abuser`);
});

test("2b. a forged connect cannot buy an address immunity from the penalty box", () => {
  const { server } = h.makeServer();
  // Registered but never answered: exactly what a spoofed source looks like.
  server.onDatagram(h.connect("Ghost"), ATTACKER);
  assert.strictEqual(server.users.get("Ghost").confirmed, false);

  const probe = Buffer.from([0, 0, 0, 0]);
  for (let i = 0; i < 500; i += 1) server.onDatagram(probe, ATTACKER);
  assert.strictEqual(server.penalty.has(ATTACKER.address), true);
});

// 3 --------------------------------------------------------------------------
test("3. an opcode full of escape sequences cannot reach the terminal", () => {
  // Byte 0x1B is ESC and 0x9B is the single byte CSI, which xterm and VTE act
  // on exactly like ESC[. The old server printed the opcode raw, so a probe
  // could clear the operator's screen or set the window title.
  const ESC = String.fromCharCode(0x1b);
  const CSI = String.fromCharCode(0x9b);
  const nasty = ESC + "[2J" + CSI + "6n";

  const escaped = sanitizeForLog(nasty);
  assert.strictEqual(escaped.includes(ESC), false, "ESC survived");
  assert.strictEqual(escaped.includes(CSI), false, "single byte CSI survived");
  // The escaped form keeps the byte visible to the operator as text.
  assert.strictEqual(escaped.includes(String.raw`\x1b`), true);
  assert.strictEqual(escaped.includes(String.raw`\x9b`), true);

  // Through the real logger, which is what a running host uses.
  const printed = [];
  const logger = new SampledLogger({ sink: (line) => printed.push(line), now: () => 0 });
  const { server } = h.makeServer();
  server.log = logger;

  const w = new BufferWriter();
  w.writeString(nasty);
  server.onDatagram(w.buffer, ATTACKER);

  assert.strictEqual(printed.length > 0, true, "the first occurrence should still be reported");
  const joined = printed.join("\n");
  assert.strictEqual(joined.includes(ESC), false, "an ESC byte reached the terminal");
  assert.strictEqual(joined.includes(CSI), false, "a CSI byte reached the terminal");
  assert.strictEqual(joined.includes(String.raw`\x1b`), true, "the operator should still see what was sent");
});

// 4 --------------------------------------------------------------------------
test("4. a negative string length is refused", () => {
  const { server } = h.makeServer();
  const buffer = Buffer.alloc(8);
  buffer.writeInt32BE(-1, 0);
  assert.strictEqual(server.onDatagram(buffer, ATTACKER), false);
  assert.strictEqual(server.stats.malformed, 1);
});

// 5 --------------------------------------------------------------------------
test("5. a length that overruns the packet is refused", () => {
  const { server } = h.makeServer();
  const buffer = Buffer.alloc(8);
  buffer.writeInt32BE(1000, 0); // claims a kilobyte inside an eight byte packet
  assert.strictEqual(server.onDatagram(buffer, ATTACKER), false);
  assert.strictEqual(server.stats.malformed, 1);
});

// 6 --------------------------------------------------------------------------
test("6. a packet truncated inside a float is refused, not defaulted", () => {
  const { server } = h.makeServer();
  join(server, "Alice", VICTIM);
  const full = h.update("Alice");
  // Cut two bytes off the middle of a mandatory field. A trailing optional
  // field may be absent; half of one may not.
  const cut = full.subarray(0, 50);
  assert.strictEqual(server.onDatagram(cut, VICTIM), false);
  assert.strictEqual(server.stats.malformed, 1);
});

// 7 --------------------------------------------------------------------------
test("7. another socket cannot move, mute or disconnect a registered player", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  join(server, "Bob", OTHER);
  clock.advance(1000);

  const before = server.users.get("Alice").position.x;
  const mark = socket.sent.length;

  // The attacker knows the nickname but sends from its own address.
  server.onDatagram(h.update("Alice", { position: [9999, 0, 0] }), ATTACKER);
  server.onDatagram(h.chat("Alice", "I am quitting"), ATTACKER);
  server.onDatagram(h.disconnect("Alice"), ATTACKER);
  server.onDatagram(h.checkpoint("Alice", 2), ATTACKER);
  server.onDatagram(h.spectate("Alice", "Bob"), ATTACKER);

  assert.strictEqual(server.users.get("Alice").position.x, before);
  assert.ok(server.users.get("Alice"), "Alice must still be connected");
  assert.strictEqual(server.stats.unauthorised, 5);
  assert.strictEqual(socket.sent.length, mark, "nothing may be relayed on a stranger's behalf");
});

// 8 --------------------------------------------------------------------------
test("8. a forged disconnect is undone by the victim's next update", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  clock.advance(1000);

  // Worst case for the owner check: the attacker guessed the exact source port.
  server.onDatagram(h.disconnect("Alice"), VICTIM);
  assert.strictEqual(server.pendingDrops.has("Alice"), true);

  // The real client keeps sending at 25 Hz and never notices.
  clock.advance(100);
  server.onDatagram(h.update("Alice"), VICTIM);
  assert.strictEqual(server.pendingDrops.has("Alice"), false);
  assert.strictEqual(server.stats.disconnectsCancelled, 1);

  clock.advance(5000);
  assert.ok(server.users.get("Alice"), "the victim must still be connected");
});

// 9 --------------------------------------------------------------------------
test("9. a connect flood with rotating source ports is limited by address", () => {
  const { server, socket } = h.makeServer();
  let accepted = 0;
  for (let port = 10000; port < 10200; port += 1) {
    if (server.onDatagram(h.connect(`Ghost${port}`), h.from(ATTACKER.address, port))) accepted += 1;
  }
  // The budget is keyed on the address, so changing port buys nothing. The old
  // server keyed it on address:port, which made the limit free to bypass.
  assert.strictEqual(accepted <= 4, true, `${accepted} connects accepted from one address`);
  assert.strictEqual(server.users.count() <= 4, true);
  // And a rejected connect must not answer, or the flood becomes a reflector.
  assert.strictEqual(socket.sent.length <= 12, true, `${socket.sent.length} packets sent for 200 probes`);
});

// 10 -------------------------------------------------------------------------
test("10. one address cannot take every slot", () => {
  const { server } = h.makeServer({ MAX_PLAYERS: "16", CONNECT_BURST: "1000", CONNECT_RATE_PER_MINUTE: "6000" });
  for (let port = 10000; port < 10100; port += 1) {
    server.onDatagram(h.connect(`Ghost${port}`), h.from(ATTACKER.address, port));
  }
  assert.strictEqual(server.users.count(), 4, "MAX_SESSIONS_PER_ADDRESS caps one host at four slots");
});

// 11 -------------------------------------------------------------------------
test("11. a spoofed registration cannot turn the host into a reflector", () => {
  const { server, socket, clock } = h.makeServer();
  // Two real players generating traffic.
  join(server, "Alice", VICTIM);
  join(server, "Bob", OTHER);

  // The attacker registers a third player whose source address is a victim's.
  // Nothing further ever arrives from that address, because it was never really
  // there.
  const reflected = h.from("198.51.100.7", 33333);
  server.onDatagram(h.connect("Reflected"), reflected);
  const mark = socket.sent.length;

  for (let i = 0; i < 200; i += 1) {
    clock.advance(50);
    server.onDatagram(h.update("Alice", { position: [i, 0, 0] }), VICTIM);
    server.onDatagram(h.update("Bob", { position: [i, 0, 0] }), OTHER);
  }

  const bytes = h
    .sentTo(socket, reflected.address, reflected.port, mark)
    .reduce((total, packet) => total + packet.buffer.length, 0);
  assert.strictEqual(bytes, 0, `${bytes} bytes were fanned out to an address that never answered`);

  // And the squatted nickname is released after the unconfirmed timeout rather
  // than being held for the full minute a real session gets.
  clock.advance(25000);
  assert.strictEqual(server.users.get("Reflected"), null);
});

// 12 -------------------------------------------------------------------------
test("12. slash commands cannot be used as an unlimited packet source", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  clock.advance(1000);

  const mark = socket.sent.length;
  for (let i = 0; i < 100; i += 1) server.onDatagram(h.chat("Alice", "/nope"), VICTIM);

  const replies = h.sentTo(socket, VICTIM.address, VICTIM.port, mark).length;
  assert.strictEqual(replies <= 3, true, `${replies} replies for 100 commands`);
});

// 13 -------------------------------------------------------------------------
test("13. an arbitrary map name is never relayed to other clients", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  join(server, "Bob", OTHER);
  clock.advance(1000);

  // OnlineRunLine::map is char[32] on the receiving side; the old server
  // accepted a kilobyte of arbitrary bytes here and passed it straight on.
  const mark = socket.sent.length;
  server.onDatagram(h.update("Alice", { map: "../../etc/passwd !" }), VICTIM);

  assert.strictEqual(server.users.get("Alice").mapname, "unknown");
  const relayed = h.sentTo(socket, OTHER.address, OTHER.port, mark)[0];
  assert.deepStrictEqual(h.readInfo(relayed.buffer), { name: "Alice", map: "unknown" });
});

// 14 -------------------------------------------------------------------------
test("14. a held model outside models/*.mdl is dropped", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  clock.advance(1000);

  for (const bad of ["/etc/passwd", "models/../../secret.mdl", "cfg/autoexec.cfg", "models/x.cfg", "x".repeat(200)]) {
    clock.advance(100);
    server.onDatagram(h.update("Alice", { heldModel: bad }), VICTIM);
    assert.strictEqual(server.users.get("Alice").heldModel, "", `"${bad}" was relayed`);
  }

  clock.advance(100);
  server.onDatagram(h.update("Alice", { heldModel: "models/props_c17/oildrum001.mdl" }), VICTIM);
  assert.strictEqual(server.users.get("Alice").heldModel, "models/props_c17/oildrum001.mdl");
});

// 15 -------------------------------------------------------------------------
test("15. an invisible character cannot smuggle the reserved name through", () => {
  const { server, socket } = h.makeServer();
  // 0xAD is a soft hyphen: it renders as nothing, survived trim() and the old
  // sanitiser, and made toUpperCase() !== "SERVER" while looking identical in
  // chat.
  const soft = Buffer.from([0xad]).toString("latin1");
  const disguises = [soft + "SERVER", "SERVER" + soft, "S.E.R.V.E.R", "server", " SERVER "];

  disguises.forEach((name, index) => {
    // A separate address each, otherwise the connect budget rejects the later
    // attempts for the wrong reason and the test proves nothing.
    const rinfo = h.from(`10.9.${index}.1`, 5000 + index);
    const mark = socket.sent.length;
    server.onDatagram(h.connect(name), rinfo);

    assert.strictEqual(server.users.exists(name), false, `"${name}" was allowed`);
    const reply = socket.sent.slice(mark)[0];
    assert.ok(reply, `"${name}" got no reply at all`);
    assert.strictEqual(reply.buffer.readUInt8(0), packets.TYPE.KICK);
    assert.match(reply.buffer.toString("latin1"), /reserved/);
  });
});

// Supporting checks ----------------------------------------------------------

test("NaN and infinite coordinates are never relayed", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  join(server, "Bob", OTHER);
  clock.advance(1000);

  const mark = socket.sent.length;
  const clean = h.update("Alice");
  for (const bad of [NaN, Infinity, -Infinity, 1e30]) {
    clock.advance(100);
    // Written straight into the bytes: the outbound writer refuses to encode a
    // non-finite float, so a crafted packet has to be built by hand.
    const crafted = h.pokeUpdateFloat(clean, "Alice", "d1_trainstation_01", "position.x", bad);
    assert.strictEqual(server.onDatagram(crafted, VICTIM), false, `${bad} was accepted`);
  }
  assert.strictEqual(h.sentTo(socket, OTHER.address, OTHER.port, mark).length, 0);
  assert.strictEqual(server.users.get("Alice").position.x, 0);
});

test("an eye height outside the crouch range falls back to standing", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  const clean = h.update("Alice");
  for (const bad of [-1, 1e9, NaN, 129, Infinity]) {
    clock.advance(100);
    const crafted = h.pokeUpdateFloat(clean, "Alice", "d1_trainstation_01", "eyeZ", bad);
    server.onDatagram(crafted, VICTIM);
    assert.strictEqual(server.users.get("Alice").eyeZ, 64, `eyeZ ${bad} was kept`);
  }
});

test("a nickname that is an Object.prototype member is an ordinary name", () => {
  const { server, clock } = h.makeServer({ MAX_SESSIONS_PER_ADDRESS: "8", CONNECT_BURST: "20" });
  for (const name of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    clock.advance(20000);
    const rinfo = h.from("10.5.0.1", 3000 + name.length);
    server.onDatagram(h.connect(name), rinfo);
    assert.strictEqual(server.users.exists(name), true, `"${name}" was not registered`);
    assert.strictEqual(server.users.get(name).name, name);
  }
  assert.strictEqual(({}).polluted, undefined);
});

test("a checkpoint id the mod never sends is ignored", () => {
  const { server, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  clock.advance(1000);
  // The mod sends 1 and 2 and nothing else. Anything else is ignored rather
  // than falling into a branch written for one of those two.
  for (const value of [0, 3, 42, 255]) {
    clock.advance(1000);
    assert.strictEqual(server.onDatagram(h.checkpoint("Alice", value), VICTIM), false, `${value} was acted on`);
    assert.strictEqual(server.race.phase, "idle");
  }
});

test("every rate limit map stops growing under a flood", () => {
  const { server } = h.makeServer({ MAX_TRACKED_ADDRESSES: "200", MAX_TRACKED_SESSIONS: "200" });
  for (let i = 0; i < 5000; i += 1) {
    const rinfo = h.from(`10.${(i >> 8) & 0xff}.${i & 0xff}.1`, 1000 + (i % 500));
    server.onDatagram(h.connect(`N${i}`), rinfo);
  }
  assert.strictEqual(server.byAddress.size <= 200, true, `address store grew to ${server.byAddress.size}`);
  assert.strictEqual(server.bySession.size <= 200, true, `session store grew to ${server.bySession.size}`);
  assert.strictEqual(server.connects.size <= 200, true);
  assert.strictEqual(server.penalty.size <= 200, true);
});

test("the global ceiling drops packets without parsing them", () => {
  const { server } = h.makeServer({ GLOBAL_PACKETS_PER_SECOND: "100" });
  let accepted = 0;
  for (let i = 0; i < 1000; i += 1) {
    if (server.onDatagram(h.connect("X"), h.from(`10.7.${i & 0xff}.1`, 2000))) accepted += 1;
  }
  assert.strictEqual(server.global.dropped >= 900, true);
  assert.strictEqual(accepted <= 100, true);
});

test("a send failure to one client does not stop the others receiving", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  join(server, "Bob", OTHER);
  clock.advance(1000);

  // dgram reports a failed send through the callback; without one it raises an
  // 'error' event on the socket, which this server treats as fatal.
  socket.failNext = Object.assign(new Error("no buffer space"), { code: "ENOBUFS" });
  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "still here"), VICTIM);

  assert.strictEqual(server.stats.sendErrors, 1);
  assert.strictEqual(socket.closed, false, "one failed send must not close the socket");
  assert.strictEqual(socket.sent.length > mark, true);
});

test("a synchronous throw from the socket does not abort a broadcast", () => {
  const { server, socket, clock } = h.makeServer();
  join(server, "Alice", VICTIM);
  clock.advance(1000);
  socket.closed = true; // send() now throws ERR_SOCKET_DGRAM_NOT_RUNNING
  assert.doesNotThrow(() => server.broadcast(packets.heartbeat()));
  assert.strictEqual(server.stats.sendErrors > 0, true);
});

test("a datagram cannot spend more than its string budget", () => {
  const { server } = h.makeServer();
  const w = new BufferWriter(limits.MAX_DATAGRAM_BYTES);
  w.writeString("l");
  for (let i = 0; i < 5; i += 1) w.writeString("y".repeat(90));
  assert.strictEqual(server.onDatagram(w.buffer, ATTACKER), false);
  assert.strictEqual(server.stats.malformed, 1);
});
