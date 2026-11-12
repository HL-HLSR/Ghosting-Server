"use strict";

// Review 2 findings (server side). Each section is the test for one finding of
// review-2; the probes it mirrors are named in the comments.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");

const chunksTo = (server, rinfo, since) =>
  server.socket.sent.slice(since)
    .filter((p) => p.address === rinfo.address && p.port === rinfo.port && p.buffer[0] === packets.TYPE.SPRAY_CHUNK)
    .length;

// Keeps the listed sessions alive (an accepted 'l' every 30 ms) and runs the
// drip the way the 250 ms tick does.
const play = (server, clock, ms, sessions) => {
  for (let t = 0; t < ms; t += 30) {
    clock.advance(30);
    for (const [name, rinfo] of sessions) server.onDatagram(h.update(name), rinfo);
    if (t % 240 === 0) server.dripSprays();
  }
};

// --- N1: a rejoining player's spray must reach the players who saw it before --

test("N1: after a sender leaves (type 4) and rejoins with the same picture, an existing receiver is fed it again", () => {
  const { server, clock } = h.makeServer();
  const R = h.from("203.0.113.10", 50000);
  const S1 = h.from("198.51.100.20", 51000);
  const S2 = h.from("198.51.100.20", 52000); // the same player after a restart: new ephemeral port
  server.onDatagram(h.connect("Recv"), R); server.onDatagram(h.update("Recv"), R);
  server.onDatagram(h.connect("Sender"), S1); server.onDatagram(h.update("Sender"), S1);
  const { blob, crc } = h.sprayBlob(64, 3, true);

  let mark = server.socket.sent.length;
  h.uploadSprayPaced(server, clock, S1, "Sender", crc, blob);
  play(server, clock, 8000, [["Recv", R], ["Sender", S1]]);
  const total = server.users.get("Sender").spray.total;
  assert.strictEqual(chunksTo(server, R, mark), total, "precondition: the first session's picture was delivered in full");

  // Goodbye: the receiver's client forgets the picture on the type-4 leave.
  mark = server.socket.sent.length;
  server.onDatagram(h.disconnect("Sender"), S1);
  play(server, clock, 3000, [["Recv", R]]);
  server.sweep();
  assert.ok(!server.users.get("Sender"), "precondition: the sender is gone");
  const leaves = server.socket.sent.slice(mark)
    .filter((p) => p.address === R.address && p.buffer[0] === packets.TYPE.DISCONNECT).length;
  assert.strictEqual(leaves, 1, "precondition: the receiver was sent the type-4 leave");

  // Rejoin under the same name; the client re-uploads its picture on every session start.
  server.onDatagram(h.connect("Sender"), S2); server.onDatagram(h.update("Sender"), S2);
  mark = server.socket.sent.length;
  h.uploadSprayPaced(server, clock, S2, "Sender", crc, blob);
  play(server, clock, 8000, [["Recv", R], ["Sender", S2]]);
  assert.strictEqual(chunksTo(server, R, mark), total,
    "the receiver must be sent the rejoined player's picture again, or it never draws their stamps");
});

test("N1: a silent same-address takeover (no type 4) does not re-send a picture the receiver still has", () => {
  const { server, clock } = h.makeServer();
  const R = h.from("203.0.113.10", 50000);
  const S1 = h.from("198.51.100.20", 51000);
  const S2 = h.from("198.51.100.20", 52000);
  server.onDatagram(h.connect("Recv"), R); server.onDatagram(h.update("Recv"), R);
  server.onDatagram(h.connect("Sender"), S1); server.onDatagram(h.update("Sender"), S1);
  const { blob, crc } = h.sprayBlob(64, 3, true);
  h.uploadSprayPaced(server, clock, S1, "Sender", crc, blob);
  play(server, clock, 8000, [["Recv", R], ["Sender", S1]]);

  // The old socket goes silent (a crash); the restarted client takes the name
  // over from the same address after TAKEOVER_AFTER_MS. Nothing tells the
  // receiver to forget the picture, so it must not be sent again.
  play(server, clock, server.config.takeoverAfterMs + 500, [["Recv", R]]);
  const mark = server.socket.sent.length;
  server.onDatagram(h.connect("Sender"), S2); server.onDatagram(h.update("Sender"), S2);
  assert.strictEqual(server.users.get("Sender").socket.port, S2.port, "precondition: taken over");
  h.uploadSprayPaced(server, clock, S2, "Sender", crc, blob);
  play(server, clock, 8000, [["Recv", R], ["Sender", S2]]);
  const leaves = server.socket.sent.slice(mark)
    .filter((p) => p.address === R.address && p.buffer[0] === packets.TYPE.DISCONNECT).length;
  assert.strictEqual(leaves, 0, "precondition: a takeover is silent");
  assert.strictEqual(chunksTo(server, R, mark), 0, "a picture the receiver still has was sent again");
});

// --- N2: per-target-session impersonation guard ----------------------------
//
// The review-1 address mute was bypassed with 'l' as a port oracle (probe
// l-oracle.js: port learned in 0.8 s at 15000 pps, forged chat landed at ~32 s)
// and muted NAT neighbours (nat-rebind-mute.js). The ruling replaces it with a
// guard on the TARGETED session: >= 20 packets naming it from its own IP but
// another port within 30 s put it under attack until 10 minutes after the last
// such packet. Its endpoint may then not chat, spectate, change appearance,
// spray, say goodbye or rename itself; positions keep relaying, and a race
// finish is accepted but marked unverified.

const VICTIM_IP = "198.51.100.7";
const REAL_PORT = 61234;

const chatTexts = (server, rinfo, since) =>
  server.socket.sent.slice(since)
    .filter((p) => p.address === rinfo.address && p.port === rinfo.port && p.buffer[0] === packets.TYPE.CHAT)
    .map((p) => {
      let at = 5;
      const nameLength = p.buffer.readUInt32BE(at);
      const from = p.buffer.toString("latin1", at + 4, at + 4 + nameLength);
      at += 4 + nameLength;
      const length = p.buffer.readUInt32BE(at);
      return { from, text: p.buffer.toString("latin1", at + 4, at + 4 + length) };
    });

// type 1 (INFO) packets to `rinfo` about `name`, decoded to position.x.
const relayedX = (server, rinfo, name, since) => {
  const out = [];
  for (const p of server.socket.sent.slice(since)) {
    if (p.address !== rinfo.address || p.port !== rinfo.port || p.buffer[0] !== packets.TYPE.INFO) continue;
    let o = 1;
    const nl = p.buffer.readUInt32BE(o); o += 4;
    if (p.buffer.toString("latin1", o, o + nl) !== name) continue;
    o += nl;
    const ml = p.buffer.readUInt32BE(o); o += 4 + ml + 12;
    out.push(p.buffer.readFloatLE(o));
  }
  return out;
};

const oracleLobby = () => {
  const rig = h.makeServer();
  const victim = h.from(VICTIM_IP, REAL_PORT);
  const mallory = h.from("203.0.113.66", 40000); // the attacker's own, legitimate session
  for (const [n, r] of [["Alice", victim], ["Mallory", mallory]]) {
    rig.server.onDatagram(h.connect(n), r);
    rig.server.onDatagram(h.update(n), r);
  }
  return Object.assign(rig, { victim, mallory });
};

// The reviewer's l-oracle: forged 'l' from every port of the victim's IP with
// the port number in position.x, while the victim plays at ~33 lines/s.
const oracleSweep = ({ server, clock, victim, mallory }, pps) => {
  const perMs = pps / 1000;
  let acc = 0;
  let lastAlice = clock.now();
  let found = null;
  for (let p = 49152; p <= 65535 && found === null; p++) {
    const mark = server.socket.sent.length;
    server.onDatagram(h.update("Alice", { position: [p, 0, 0] }), h.from(VICTIM_IP, p));
    if (relayedX(server, mallory, "Alice", mark).some((x) => x > 1000)) found = p;
    if (++acc >= perMs) {
      acc = 0;
      clock.advance(1);
      if (clock.now() - lastAlice >= 30) {
        lastAlice = clock.now();
        server.onDatagram(h.update("Alice", { position: [1, 2, 3] }), victim);
        server.onDatagram(h.update("Mallory"), mallory);
      }
    }
  }
  return found;
};

const keepPlaying = ({ server, clock, victim, mallory }, ms) => {
  for (let t = 0; t < ms; t += 30) {
    clock.advance(30);
    server.onDatagram(h.update("Alice", { position: [5, 5, 5] }), victim);
    server.onDatagram(h.update("Mallory"), mallory);
  }
};

test("N2: after an 'l'-oracle sweep, forged chat from the learned real port is refused for the whole guard window, and the victim keeps playing", () => {
  const rig = oracleLobby();
  const { server, clock, victim, mallory } = rig;
  const markAll = server.socket.sent.length;
  const found = oracleSweep(rig, 15000);
  // Inherent without a client nonce: a forged position from the real port is
  // indistinguishable from the player's, so the port leaks through the relay.
  assert.strictEqual(found, REAL_PORT, "precondition: the oracle finds the real port");
  const sweepEnded = clock.now();
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, "the targeted session is not guarded");

  // The victim is told once, on their own endpoint, however long the sweep was.
  const told = chatTexts(server, victim, markAll).filter((c) => c.from === "SERVER" && /packets as you/i.test(c.text));
  assert.strictEqual(told.length, 1, `victim notices: ${told.length}`);

  const forgedChatLands = () => {
    const mark = server.socket.sent.length;
    server.onDatagram(h.chat("Alice", "I am Alice, honest"), h.from(VICTIM_IP, found));
    return chatTexts(server, mallory, mark).some((c) => c.from === "Alice");
  };
  // Where the address mute lapsed (~32 s), and late in the guard window.
  keepPlaying(rig, 32000 - (clock.now() - sweepEnded));
  assert.strictEqual(forgedChatLands(), false, "forged chat landed after the 30 s the address mute used to last");
  const markPos = server.socket.sent.length;
  // Review 3 (R4): the guard is 3 minutes by default; late in it.
  keepPlaying(rig, server.config.impersonationGuardMs - 30000 - (clock.now() - sweepEnded));
  assert.ok(relayedX(server, mallory, "Alice", markPos).length > 1000, "the victim's positions must keep relaying");
  assert.strictEqual(forgedChatLands(), false, "forged chat landed inside the guard");
  assert.ok(server.users.get("Alice"), "the victim must stay connected");

  // The guard is a delay and an alarm, not authentication: 10 minutes after the
  // last wrong-port packet, the port the oracle leaked works again. Pinned so
  // the README's numbers stay true.
  keepPlaying(rig, server.config.impersonationGuardMs + 1000 - (clock.now() - sweepEnded));
  assert.strictEqual(forgedChatLands(), true, "the guard should lapse IMPERSONATION_GUARD_MS after the last packet");
});

test("N2: a forged 'c' with another name from a guarded endpoint is refused, silently, and the victim stays", () => {
  const rig = oracleLobby();
  const { server, mallory, victim } = rig;
  const found = oracleSweep(rig, 15000);
  const mark = server.socket.sent.length;
  const handled = server.onDatagram(h.connect("Evil"), h.from(VICTIM_IP, found));
  assert.strictEqual(handled, false);
  assert.ok(server.users.get("Alice"), "the victim was dropped by a forged rename");
  assert.strictEqual(server.users.get("Alice").socket.port, REAL_PORT);
  assert.ok(!server.users.get("Evil"), "the forged name was registered");
  const leaves = server.socket.sent.slice(mark).filter((p) => p.buffer[0] === packets.TYPE.DISCONNECT).length;
  assert.strictEqual(leaves, 0, "a type-4 leave went out for the victim");
  assert.strictEqual(h.sentTo(server.socket, victim.address, victim.port, mark).length, 0,
    "nothing (a kick above all) may be sent to the victim's endpoint for a refused forged connect");
  assert.strictEqual(relayedX(server, mallory, "Evil", mark).length, 0);
});

test("N2: a goodbye, spectate and appearance change from a guarded endpoint are refused; 'l' is relayed", () => {
  const rig = oracleLobby();
  const { server, clock, victim, mallory } = rig;
  oracleSweep(rig, 15000);
  clock.advance(100);
  assert.strictEqual(server.onDatagram(h.disconnect("Alice"), victim), false);
  assert.strictEqual(server.pendingDrops.has("Alice"), false);
  assert.strictEqual(server.onDatagram(h.spectate("Alice", "Mallory"), victim), false);
  const mark = server.socket.sent.length;
  assert.strictEqual(server.onDatagram(h.update("Alice", { position: [9, 9, 9] }), victim), true);
  assert.deepStrictEqual(relayedX(server, mallory, "Alice", mark), [9]);
});

test("N2: a NAT neighbour on the same IP keeps chatting while another session there is targeted", () => {
  const { server, clock } = h.makeServer();
  const alice = h.from(VICTIM_IP, REAL_PORT);
  const carol = h.from(VICTIM_IP, 50002);
  const bob = h.from("203.0.113.9", 40000);
  for (const [n, r] of [["Alice", alice], ["Carol", carol], ["Bob", bob]]) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n), r);
  }
  for (let p = 20000; p < 20100; p++) server.onDatagram(h.chat("Alice", "/broadcast pwned"), h.from(VICTIM_IP, p));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, "precondition: Alice is targeted");
  assert.strictEqual(server.penalty.has(VICTIM_IP), false, "wrong-owner traffic no longer boxes the address");

  clock.advance(1000);
  const mark = server.socket.sent.length;
  assert.strictEqual(server.onDatagram(h.chat("Carol", "gg"), carol), true, "the NAT neighbour's chat was refused");
  assert.ok(chatTexts(server, bob, mark).some((c) => c.from === "Carol" && c.text === "gg"), "Carol's chat did not reach Bob");
  assert.strictEqual(server.onDatagram(h.spectate("Carol", "Bob"), carol), true, "the neighbour's spectate was refused");
  clock.advance(1100);
  assert.strictEqual(server.onDatagram(h.disconnect("Carol"), carol), true, "the neighbour's goodbye was refused");
});

test("N2: packets naming a session from a FOREIGN IP never guard it (nobody can mute a stranger from their own IP)", () => {
  const { server, clock } = h.makeServer();
  const alice = h.from(VICTIM_IP, REAL_PORT);
  const bob = h.from("203.0.113.9", 40000);
  for (const [n, r] of [["Alice", alice], ["Bob", bob]]) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n), r);
  }
  for (let i = 0; i < 5000; i++) {
    server.onDatagram(h.chat("Alice", "x"), h.from("203.0.113.66", 1024 + i));
    if (i % 100 === 0) clock.advance(250);
  }
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false, "a foreign IP guarded someone else's session");
  assert.strictEqual(server.penalty.has("203.0.113.66"), false, "wrong-owner traffic no longer boxes the address");
  clock.advance(2000);
  const mark = server.socket.sent.length;
  server.onDatagram(h.chat("Alice", "still me"), alice);
  assert.ok(chatTexts(server, bob, mark).some((c) => c.from === "Alice"), "the real player's chat was refused");
});

test("N2/R3: a NAT re-bind does not guard the session it left behind, and the player's reconnect is clean", () => {
  const { server, clock } = h.makeServer();
  const alice = h.from(VICTIM_IP, 50001);
  const rebound = h.from(VICTIM_IP, 50099);
  const bob = h.from("203.0.113.9", 40000);
  for (const [n, r] of [["Alice", alice], ["Bob", bob]]) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n), r);
  }
  // Her client keeps sending from the new external port until its own 10 s timeout.
  for (let t = 0; t < 10000; t += 30) {
    clock.advance(30);
    server.onDatagram(h.update("Alice"), rebound);
    server.onDatagram(h.update("Bob"), bob);
  }
  // Review 3 (R3): one new port is not a sweep.
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false, "a NAT re-bind guarded the dead session");
  // She reconnects by hand from the new port; the old socket has been silent.
  clock.advance(1000);
  server.onDatagram(h.connect("Alice"), rebound);
  server.onDatagram(h.update("Alice"), rebound);
  const user = server.users.get("Alice");
  assert.strictEqual(user.socket.port, rebound.port, "precondition: taken over");
  assert.strictEqual(server.isGuarded(user, clock.now()), false, "the new session inherited the guard");
  clock.advance(1000);
  const mark = server.socket.sent.length;
  server.onDatagram(h.chat("Alice", "back"), rebound);
  assert.ok(chatTexts(server, bob, mark).some((c) => c.from === "Alice" && c.text === "back"));
});

test("N2: a race finish from a guarded session is accepted but announced and logged as unverified", () => {
  const rig = h.makeServer({ RACE_LOBBY_MS: "2000" });
  const { server, socket, clock } = rig;
  const A = h.from(VICTIM_IP, REAL_PORT);
  const B = h.from("10.0.0.2", 40002);
  for (const [n, r] of [["Alice", A], ["Bob", B]]) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n, { map: "d1_eli_01" }), r);
  }
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), A);
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), B);
  clock.advance(4600);
  clock.runTimeouts();
  clock.runTimeouts();
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  server.onDatagram(h.checkpoint("Bob", 1), B);
  clock.advance(5000);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "racing", "precondition: racing");

  for (let p = 20000; p < 20030; p++) server.onDatagram(h.update("Alice"), h.from(VICTIM_IP, p));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, "precondition: guarded");

  clock.advance(100);
  const mark = socket.sent.length;
  assert.strictEqual(server.onDatagram(h.checkpoint("Alice", 2, { igt: 61.5, liveSplit: -1 }), A), true, "the finish was refused");
  assert.ok(server.race.finished.includes("Alice"));
  const lines = chatTexts(server, B, mark).filter((c) => c.from === "SERVER").map((c) => c.text);
  const result = lines.find((t) => /Alice finished/.test(t));
  assert.ok(result, "no result line");
  assert.match(result, /unverified/i, `the result line does not say unverified: ${result}`);
  assert.ok(lines.some((t) => /impersonation/i.test(t)), "nobody was told why");
  assert.ok(server.log.lines.some((l) => /unverified/i.test(JSON.stringify(l))), "the race log does not record it");
});

// --- N3: the server-wide re-encode budget is a fair queue, not a refusal -----
//
// Review 2 measured: (a) three attacker addresses within every publish budget
// kept the C1 bucket empty and a real player's spray was never published
// (reencode-dos-eager.js: 0/1 at 500, 100 and 20 ms); (b) the "busy" notice was
// an unsampled log line and a chat packet per attempt (busy-logflood.js: 160
// journal lines a second from one address); (c) the only retry was the
// client's single recovery pass, so an honest mass join lost most sprays
// (reencode-dos.js join 48: 21/48). Now publish budgets are charged first, and a
// validated upload that finds the bucket empty waits in a bounded queue the
// tick drains at the bucket rate, round-robin across source addresses.

const joinAll = (server, list) => {
  for (const [n, r] of list) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n), r);
  }
};

const publishedCrc = (server, name) => {
  const u = server.users.get(name);
  return u && u.spray ? u.spray.crc : null;
};

test("N3: spamming fresh pictures at an empty re-encode budget keeps one waiting and publishes no more than the publish budget allows", () => {
  // Review 3 (R6) changed the accounting, not the bound: a newer validated
  // picture replaces the waiting one IN PLACE and the replaced one's publish
  // tokens are given back (it was never published), so the spam no longer
  // drains the allowance up front - but nothing replaced ever reaches the
  // re-encode budget, and what is actually PUBLISHED still costs the budget.
  const { server, clock } = h.makeServer();
  const fillers = [];
  for (let i = 0; i < 4; i++) fillers.push([`F${i}`, h.from(`10.8.${i}.1`, 41000)]);
  const atk = h.from("203.0.113.5", 42000);
  joinAll(server, fillers.concat([["Atk", atk]]));
  // Empty the re-encode bucket with four legitimate publications.
  fillers.forEach(([n, r], i) => {
    const pic = h.sprayBlob(8, 100 + i);
    h.uploadSpray(server, r, n, pic.crc, pic.blob);
  });
  assert.strictEqual(server.sprayReencode.available("all") < 1, true, "precondition: bucket empty");

  let fill = 1000;
  for (let i = 0; i < 50; i++) {
    const pic = h.sprayBlob(8, fill++);
    server.onDatagram(h.sprayChunk("Atk", pic.crc, pic.blob.length, 1, 0, pic.blob), atk);
  }
  assert.strictEqual(server.reencodeQueued.size, 1, `${server.reencodeQueued.size} pictures queued for one session`);
  assert.strictEqual(server.sprayReencode.available("all") < 1, true, "replaced pictures reached the re-encode budget");

  // A minute of the same spam, one fresh picture every 100 ms.
  for (let t = 0; t < 60000; t += 100) {
    clock.advance(100);
    if (t % 500 === 0) for (const [n, r] of fillers.concat([["Atk", atk]])) server.onDatagram(h.update(n), r);
    const pic = h.sprayBlob(8, fill++);
    server.onDatagram(h.sprayChunk("Atk", pic.crc, pic.blob.length, 1, 0, pic.blob), atk);
  }
  const published = server.log.lines.filter((l) => l[0] === "event" && l[1] === "spray-published" && /'Atk'/.test(l[2])).length;
  const allowed = server.config.sprayPublishBurst + server.config.sprayPublishPerMinute;
  assert.ok(published >= 1, "the spammer's picture was never published at all");
  assert.ok(published <= allowed, `${published} publications in a minute (publish budget allows ${allowed})`);
});

test("N3: completions that find the budget empty are queued, published by the tick at the budget rate, and nobody is sent a busy notice", () => {
  const { server, socket, clock } = h.makeServer({ MAX_PLAYERS: "16" });
  const senders = [];
  for (let i = 0; i < 8; i++) senders.push([`S${i}`, h.from(`10.9.${i}.1`, 41000 + i)]);
  joinAll(server, senders);
  const mark = socket.sent.length;
  const infoBefore = server.log.lines.filter((l) => l[0] === "info").length;
  const pics = senders.map((s, i) => h.sprayBlob(8, i + 1));
  senders.forEach(([n, r], i) => h.uploadSpray(server, r, n, pics[i].crc, pics[i].blob));
  const now = senders.filter(([n]) => publishedCrc(server, n) !== null).length;
  assert.strictEqual(now, server.config.sprayReencodeBurst, `${now} re-encodes ran back to back`);
  assert.strictEqual(server.reencodeQueued.size, 8 - now, "the rest are not waiting in the queue");

  // One re-encode per 60/SPRAY_REENCODE_PER_MINUTE seconds after the burst.
  const per = 60000 / server.config.sprayReencodePerMinute;
  for (let t = 0; t < per * (8 - now) + 500; t += 30) {
    clock.advance(30);
    for (const [n, r] of senders) server.onDatagram(h.update(n), r);
  }
  for (const [n] of senders) assert.ok(publishedCrc(server, n) !== null, `${n} was never published from the queue`);
  const notices = socket.sent.slice(mark).filter((p) => p.buffer[0] === packets.TYPE.CHAT).length;
  assert.strictEqual(notices, 0, `${notices} chat notices were sent about the queue`);
  const infos = server.log.lines.filter((l) => l[0] === "info").slice(infoBefore)
    .filter((l) => !/confirmed from/.test(String(l[1])));
  assert.strictEqual(infos.length, 0, `unsampled log lines on the spray path: ${JSON.stringify(infos)}`);
});

test("N3: attackers on three addresses keeping the queue full cannot keep an honest picture out (round-robin by address)", () => {
  const { server, clock } = h.makeServer({ MAX_PLAYERS: "32" });
  const attackers = [];
  for (let a = 0; a < 3; a++) for (let s = 0; s < 4; s++) attackers.push([`Atk${a}${s}`, h.from(`203.0.113.${10 + a}`, 40000 + s)]);
  const victim = h.from("198.51.100.50", 55555);
  joinAll(server, attackers.concat([["Victim", victim]]));
  const pic = h.sprayBlob(128, 9, true);
  const total = Math.ceil(pic.blob.length / 400);
  let next = 0;
  let fill = 1000;
  let rr = 0;
  let completedAt = null;
  let publishedAt = null;
  for (let t = 0; t < 150000 && publishedAt === null; t += 10) {
    clock.advance(10);
    if (t % 30 === 0) {
      server.onDatagram(h.update("Victim"), victim);
      for (const [n, r] of attackers) server.onDatagram(h.update(n), r);
    }
    // The real client: one piece every 40 ms, starting at 20 s.
    if (t >= 20000 && t % 40 === 0 && next < total) {
      const piece = pic.blob.subarray(next * 400, Math.min((next + 1) * 400, pic.blob.length));
      server.onDatagram(h.sprayChunk("Victim", pic.crc, pic.blob.length, total, next, piece), victim);
      next += 1;
      if (next === total) completedAt = t;
    }
    // A fresh one-piece picture every 20 ms, round-robin over the 12 sessions.
    if (t % 20 === 0) {
      const [n, r] = attackers[rr++ % attackers.length];
      const p = h.sprayBlob(8, fill++);
      server.onDatagram(h.sprayChunk(n, p.crc, p.blob.length, 1, 0, p.blob), r);
    }
    if (publishedCrc(server, "Victim") === pic.crc) publishedAt = t;
  }
  assert.ok(completedAt !== null, "precondition: the upload completed");
  assert.ok(publishedAt !== null, "the honest picture was never published");
  // Four addresses competing: at most 4 drains (3 s each) after it was queued.
  const per = 60000 / server.config.sprayReencodePerMinute;
  assert.ok(publishedAt - completedAt <= 4 * per + 500, `published ${publishedAt - completedAt} ms after completing`);
});

test("N3: one address uploading fresh pictures at the piece rate produces no unsampled log flood and no chat back", () => {
  const { server, clock, log, socket } = h.makeServer();
  const sessions = [];
  for (let s = 0; s < 4; s++) sessions.push([`Flood${s}`, h.from("203.0.113.5", 41000 + s)]);
  joinAll(server, sessions);
  let fill = 1;
  for (const [n, r] of sessions) { const p = h.sprayBlob(8, fill++); server.onDatagram(h.sprayChunk(n, p.crc, p.blob.length, 1, 0, p.blob), r); }
  const infoBefore = log.lines.filter((l) => l[0] === "info").length;
  const sentBefore = socket.sent.length;
  for (let ms = 0; ms < 10000; ms += 25) {
    clock.advance(25);
    for (const [n, r] of sessions) {
      if (ms % 50 === 0) server.onDatagram(h.update(n), r);
      const p = h.sprayBlob(8, fill++);
      server.onDatagram(h.sprayChunk(n, p.crc, p.blob.length, 1, 0, p.blob), r);
    }
  }
  const infos = log.lines.filter((l) => l[0] === "info").slice(infoBefore);
  assert.strictEqual(infos.length, 0, `unsampled lines: ${infos.length}`);
  const chats = socket.sent.slice(sentBefore).filter((p) => p.buffer[0] === packets.TYPE.CHAT && p.address === "203.0.113.5").length;
  assert.strictEqual(chats, 0, `${chats} chat packets sent back`);
});

test("N3: an honest mass join (30 players finishing uploads 0.4 s apart) publishes every spray, in bounded time", () => {
  const { server, clock } = h.makeServer({ MAX_PLAYERS: "64" });
  const N = 30;
  const players = [];
  for (let i = 0; i < N; i++) {
    const r = h.from(`198.51.100.${i + 1}`, 50000 + i);
    const pic = h.sprayBlob(128, 100 + i, true);
    players.push({ n: `R${i}`, r, pic, total: Math.ceil(pic.blob.length / 400), next: 0, start: i * 400 });
  }
  joinAll(server, players.map((p) => [p.n, p.r]));
  let last = 0;
  for (let t = 0; t < 150000; t += 10) {
    clock.advance(10);
    if (t % 30 === 0) for (const p of players) server.onDatagram(h.update(p.n), p.r);
    for (const p of players) {
      if (t < p.start || t % 40 !== 0 || p.next >= p.total) continue;
      const piece = p.pic.blob.subarray(p.next * 400, Math.min((p.next + 1) * 400, p.pic.blob.length));
      server.onDatagram(h.sprayChunk(p.n, p.pic.crc, p.pic.blob.length, p.total, p.next, piece), p.r);
      p.next += 1;
    }
    const done = players.filter((p) => publishedCrc(server, p.n) === p.pic.crc).length;
    if (done === N) { last = t; break; }
  }
  const done = players.filter((p) => publishedCrc(server, p.n) === p.pic.crc).length;
  assert.strictEqual(done, N, `${done}/${N} published after 150 s`);
  const per = 60000 / server.config.sprayReencodePerMinute;
  assert.ok(last <= 20000 + (N - server.config.sprayReencodeBurst) * per, `the last spray went out at ${last} ms`);
});

// --- review 2 minors (server) ------------------------------------------------

test("m1: a speedrunner at updaterate 10 doing heavy save/load spam on a full server is not evicted", () => {
  // loadspam-evict.js: 8 lines/s with a 4 s load every 8 s averages ~4.1 lines/s,
  // which the threshold of 5 evicted. The default is now 3.
  const { server, clock } = h.makeServer();
  const players = [];
  for (let i = 0; i < server.config.maxPlayers - 1; i++) {
    players.push([`P${String(i).padStart(2, "0")}`, h.from(`198.51.100.${i + 1}`, 50000 + i)]);
  }
  const runner = h.from("203.0.113.77", 61000);
  joinAll(server, players.concat([["Runner", runner]]));
  const t0 = clock.now();
  let nextRunner = t0;
  let nextOthers = t0;
  for (let t = 0; t < 120000; t += 5) {
    clock.advance(5);
    const now = clock.now();
    if (now >= nextOthers) { for (const [n, r] of players) server.onDatagram(h.update(n), r); nextOthers = now + 30; }
    const loading = ((now - t0) / 1000) % 8 < 4;
    if (!loading && now >= nextRunner) { server.onDatagram(h.update("Runner"), runner); nextRunner = now + 125; }
  }
  const rate = server.users.get("Runner").inboundRate(clock.now(), server.config.squatWindowMs);
  assert.ok(rate > 3 && rate < 5, `precondition: the runner averages ${rate.toFixed(2)} lines/s`);
  server.onDatagram(h.connect("Newcomer"), h.from("192.0.2.200", 40000));
  assert.ok(server.users.get("Runner"), "the save/load-spamming runner was evicted");
});

test("m3: the per-receiver cap counts pictures whose stamps were relayed; a separate, larger cap bounds pictures fed", () => {
  const { server, clock } = h.makeServer({ MAX_PLAYERS: "64", MAX_SESSIONS_PER_ADDRESS: "64", SPRAY_PUBLISH_BURST: "100", SPRAY_PUBLISH_PER_MINUTE: "600", SPRAY_REENCODE_BURST: "100", SPRAY_REENCODE_PER_MINUTE: "6000", SPRAY_PUBLISH_MAX_PER_SESSION: "1000" });
  const R = h.from("203.0.113.10", 50000);
  joinAll(server, [["Recv", R]]);
  assert.strictEqual(server.config.sprayMaxPicturesPerReceiver, 40);
  assert.strictEqual(server.config.sprayMaxFedPerReceiver, 200);
  // 50 senders publish a picture each; nobody stamps. All 50 are fed: nothing
  // was drawn, so no texture was built on the receiver's client.
  const senders = [];
  for (let i = 0; i < 50; i++) senders.push([`S${i}`, h.from(`198.51.${100 + Math.floor(i / 200)}.${(i % 200) + 1}`, 51000 + i)]);
  joinAll(server, senders);
  const pics = senders.map((s, i) => h.sprayBlob(8, 500 + i));
  senders.forEach(([n, r], i) => h.uploadSpray(server, r, n, pics[i].crc, pics[i].blob));
  assert.strictEqual(server.users.get("Recv").sprayPictures.size, 50, "pictures that were never stamped counted toward the 40");

  // Each sender stamps once: only the first 40 distinct pictures' stamps reach
  // the receiver (the client builds a texture per stamped picture, 48 at most).
  let relayed = 0;
  senders.forEach(([n, r], i) => {
    clock.advance(300);
    const mark = server.socket.sent.length;
    server.onDatagram(h.sprayStamp(n, pics[i].crc, 1, 2, 3), r);
    relayed += server.socket.sent.slice(mark).filter((p) => p.address === R.address && p.buffer[0] === packets.TYPE.SPRAY_STAMP).length;
  });
  assert.strictEqual(relayed, 40, `${relayed} distinct pictures' stamps reached the receiver`);
  // A second stamp of an already-counted picture still gets through.
  clock.advance(300);
  const mark = server.socket.sent.length;
  server.onDatagram(h.sprayStamp("S0", pics[0].crc, 4, 5, 6), senders[0][1]);
  assert.strictEqual(server.socket.sent.slice(mark).filter((p) => p.address === R.address && p.buffer[0] === packets.TYPE.SPRAY_STAMP).length, 1);
});

test("m3: pictures fed to one receiver are capped at SPRAY_MAX_FED_PER_RECEIVER", () => {
  const { server } = h.makeServer({ MAX_PLAYERS: "64", MAX_SESSIONS_PER_ADDRESS: "64", SPRAY_MAX_FED_PER_RECEIVER: "10", SPRAY_REENCODE_BURST: "100" });
  const R = h.from("203.0.113.10", 50000);
  joinAll(server, [["Recv", R]]);
  const senders = [];
  for (let i = 0; i < 12; i++) senders.push([`S${i}`, h.from(`198.51.100.${i + 1}`, 51000 + i)]);
  joinAll(server, senders);
  senders.forEach(([n, r], i) => { const p = h.sprayBlob(8, 700 + i); h.uploadSpray(server, r, n, p.crc, p.blob); });
  assert.strictEqual(server.users.get("Recv").sprayPictures.size, 10);
});

// The same near-cap picture spray-validate.test.js uses for I5: a legal upload
// whose level-6 re-encode comes out past the client's 163840 B receive bound.
const overBound = () => {
  const pixels = Buffer.alloc(256 * 256 * 4);
  let x = 12345;
  for (let i = 0; i < pixels.length; i++) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    const noisy = i < 199936 ? 60 : 59;
    pixels[i] = (i % 100) < noisy ? x & 0xff : (i >> 9) & 0xff;
  }
  return h.sprayBlobFromPixels(256, pixels, 9);
};

test("m6: a picture refused as too large after re-encoding gives its publish tokens back", () => {
  const { server, clock } = h.makeServer();
  const a = h.from("203.0.113.20", 40000);
  joinAll(server, [["Big", a]]);
  const key = `${a.address}:${a.port}`;
  const before = [server.sprayPublish.available(key), server.sprayPublishAddress.available(a.address), server.sprayPublishName.available(server.users.key("Big"))];
  const { blob, crc } = overBound();
  h.uploadSprayPaced(server, clock, a, "Big", crc, blob);
  assert.strictEqual(server.users.get("Big").spray, null, "precondition: refused as too large");
  const after = [server.sprayPublish.available(key), server.sprayPublishAddress.available(a.address), server.sprayPublishName.available(server.users.key("Big"))];
  assert.deepStrictEqual(after, before, "the publish budgets were spent on a picture nobody can see");
  assert.ok(server.sprayReencode.available("all") < server.config.sprayReencodeBurst, "the re-encode token stays spent");
});

test("m7: an unconfirmed takeover from ANOTHER address does not inherit the holder's age", () => {
  const { server, clock } = h.makeServer({ MAX_PLAYERS: "2" });
  const forged = h.from("192.0.2.66", 40000);
  server.onDatagram(h.connect("Alice"), forged); // never confirms
  const other = h.from("203.0.113.9", 40001);
  joinAll(server, [["Other", other]]);
  clock.advance(server.config.takeoverAfterMs + 100);
  server.onDatagram(h.update("Other"), other);
  // The real Alice takes her name over from her own address.
  const real = h.from("198.51.100.30", 50000);
  server.onDatagram(h.connect("Alice"), real);
  const alice = server.users.get("Alice");
  assert.strictEqual(alice.socket.port, real.port, "precondition: taken over");
  assert.strictEqual(alice.connectedAt, clock.now(), "the new holder inherited the forged holder's connect time");
  // A join on the full server a moment later must not evict her as a stale
  // unconfirmed session before her first position update arrives.
  clock.advance(30);
  server.onDatagram(h.connect("Late"), h.from("192.0.2.200", 40000));
  assert.ok(server.users.get("Alice"), "the real player was evicted as a 'stale unconfirmed' session");
});

test("m9: console 'op' usage shows the PIN as required, and a console input error does not end the process", () => {
  const { PassThrough } = require("node:stream");
  const { attach } = require("../src/console");
  const { server } = h.makeServer();
  const lines = [];
  const input = new PassThrough();
  const handle = attach(server, { input, print: (line) => lines.push(line) });
  handle.handle("op");
  assert.ok(lines.some((l) => l === 'Usage: op "Nick" PIN'), lines.join("\n"));
  assert.doesNotThrow(() => input.emit("error", Object.assign(new Error("read EIO"), { code: "EIO" })));
  assert.ok(server.log.lines.some((l) => l[0] === "warn" && /console/i.test(String(l[1]))), "the error was not logged");
  handle.rl.close();
});
