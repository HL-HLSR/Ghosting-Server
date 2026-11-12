"use strict";

// Review 3 findings (R1-R9). Each section is the test for one finding; the probe
// it mirrors in review-tmp\round3 is named in the comments.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");

const VICTIM_IP = "198.51.100.7";
const REAL_PORT = 61234;
const JUNK = Buffer.from([0, 0, 0, 2, 0x7a, 0x7a, 1, 2, 3, 4]); // opcode "zz"

const joinAll = (server, list) => {
  for (const [n, r] of list) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n), r);
  }
};

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

// --- R1: boxing the victim's IP first must not blind the guard ----------------

test("R1: an 'l' sweep diluted 2:1 with junk behind a box armed by junk still trips the guard before the port leaks; forged chat and rename are refused", () => {
  // review-tmp\round3\l-oracle-boxed.js 5000 2: before, 0 wrong-owner packets
  // were ever parsed, the port leaked at 2.4 s and chat/rename landed at once.
  const { server, clock } = h.makeServer();
  const victim = h.from(VICTIM_IP, REAL_PORT);
  const mallory = h.from("203.0.113.66", 40000);
  const bob = h.from("192.0.2.40", 40001);
  joinAll(server, [["Alice", victim], ["Mallory", mallory], ["Bob", bob]]);
  let jp = 1;
  const junk = (n) => { for (let j = 0; j < n; j++) server.onDatagram(JUNK, h.from(VICTIM_IP, 1 + (jp++ % 40000))); };
  junk(21);
  assert.strictEqual(server.penalty.has(VICTIM_IP), true, "precondition: the junk boxed the victim's address");
  let lastPlay = clock.now();
  let found = null;
  let guardedWhenFound = null;
  let acc = 0;
  for (let p = 49152; p <= 65535 && found === null; p++) {
    junk(2);
    const mark = server.socket.sent.length;
    server.onDatagram(h.update("Alice", { position: [p, 0, 0] }), h.from(VICTIM_IP, p));
    if (relayedX(server, mallory, "Alice", mark).some((x) => x > 1000)) {
      found = p;
      guardedWhenFound = server.isGuarded(server.users.get("Alice"), clock.now());
    }
    if (++acc >= 5) {
      acc = 0;
      clock.advance(1);
      if (clock.now() - lastPlay >= 30) {
        lastPlay = clock.now();
        for (const [n, r] of [["Alice", victim], ["Mallory", mallory], ["Bob", bob]]) {
          server.onDatagram(h.update(n, n === "Alice" ? { position: [1, 2, 3] } : {}), r);
        }
      }
    }
  }
  assert.strictEqual(found, REAL_PORT, "precondition: the sweep reaches the real port");
  assert.strictEqual(guardedWhenFound, true, "the guard was not up when the port leaked");
  clock.advance(20);
  let mark = server.socket.sent.length;
  assert.strictEqual(server.onDatagram(h.chat("Alice", "I am Alice, honest"), h.from(VICTIM_IP, found)), false);
  assert.strictEqual(chatTexts(server, bob, mark).filter((c) => c.from === "Alice").length, 0, "forged chat reached Bob");
  clock.advance(40);
  mark = server.socket.sent.length;
  server.onDatagram(h.connect("Evil"), h.from(VICTIM_IP, found));
  assert.ok(server.users.get("Alice"), "a forged rename dropped Alice");
  assert.strictEqual(server.socket.sent.slice(mark).filter((p) => p.buffer[0] === packets.TYPE.DISCONNECT).length, 0);
});

test("R1: names in dropped traffic are only peeked at an address that holds a session, and never for a connect", () => {
  const { server, clock } = h.makeServer();
  const victim = h.from(VICTIM_IP, REAL_PORT);
  joinAll(server, [["Alice", victim]]);
  // Box a stranger's address and send it wrong-owner traffic naming Alice: it
  // is not Alice's IP, so it can never count toward her guard.
  for (let i = 0; i < 21; i++) server.onDatagram(JUNK, h.from("203.0.113.99", 1000 + i));
  for (let p = 0; p < 200; p++) server.onDatagram(h.update("Alice"), h.from("203.0.113.99", 20000 + p));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false);
  assert.strictEqual(server.stats.wrongOwnerPeeked, 0, "dropped traffic from an address with no session was parsed");
});

// --- R2: a guarded victim must not be kicked by junk forged from its port -----

const guardedLobby = () => {
  const rig = h.makeServer();
  const alice = h.from(VICTIM_IP, REAL_PORT);
  const bob = h.from("203.0.113.8", 40000);
  joinAll(rig.server, [["Alice", alice], ["Bob", bob]]);
  const play = (ms) => {
    for (let i = 0; i < ms / 30; i++) {
      rig.clock.advance(30);
      rig.server.onDatagram(h.update("Alice"), alice);
      rig.server.onDatagram(h.update("Bob"), bob);
    }
  };
  play(1000);
  for (let p = 0; p < 40; p++) rig.server.onDatagram(h.update("Alice"), h.from(VICTIM_IP, 30000 + p)); // the sweep
  play(1000);
  assert.strictEqual(rig.server.isGuarded(rig.server.users.get("Alice"), rig.clock.now()), true, "precondition: guarded");
  return Object.assign(rig, { alice, bob, play });
};

test("R2: junk, oversized and malformed datagrams forged from a guarded victim's port do not kick or box it", () => {
  // review-tmp\round3\guarded-malformed-kick.js: before, 21 junk datagrams
  // kicked the guarded victim (type 5 to her, type 4 to everyone).
  const { server, clock, alice, bob, play } = guardedLobby();
  const mark = server.socket.sent.length;
  const truncatedChat = Buffer.from([0, 0, 0, 1, 0x6d, 0, 0, 0, 5, 0x41]); // 'm', name claims 5 bytes, has 1
  for (let i = 0; i < 30; i++) {
    server.onDatagram(JUNK, alice);
    server.onDatagram(Buffer.alloc(600, 0x41), alice);
    server.onDatagram(truncatedChat, alice);
    clock.advance(1);
  }
  assert.ok(server.users.get("Alice"), "the guarded victim was dropped");
  assert.strictEqual(server.socket.sent.slice(mark).filter((p) => p.port === REAL_PORT && p.buffer[0] === packets.TYPE.KICK).length, 0, "a kick was sent");
  assert.strictEqual(server.socket.sent.slice(mark).filter((p) => p.address === bob.address && p.buffer[0] === packets.TYPE.DISCONNECT).length, 0);
  assert.strictEqual(server.penalty.has(`${VICTIM_IP}:${REAL_PORT}`), false, "the victim's endpoint was boxed");
  // ...and she keeps playing.
  const m2 = server.socket.sent.length;
  play(100);
  assert.ok(relayedX(server, bob, "Alice", m2).length > 0, "the victim's positions stopped relaying");
  assert.ok(server.log.lines.some((l) => l[0] === "event" && l[1] === "guarded-junk"), "the junk was not counted");
});

test("R2: an unguarded confirmed endpoint sending junk is still boxed and its slot freed (unchanged)", () => {
  const { server, clock } = h.makeServer();
  const abuser = h.from("10.0.0.1", 40001);
  joinAll(server, [["Abuser", abuser]]);
  for (let i = 0; i < 40; i++) { server.onDatagram(JUNK, abuser); clock.advance(1); }
  assert.strictEqual(server.users.exists("Abuser"), false);
  assert.strictEqual(server.penalty.has("10.0.0.1:40001"), true);
});

// --- R3: trigger on distinct source ports; innocent shapes never trip it ------

// A real client behind the same NAT that is refused the name it asked for
// (review-tmp\round3\ghost-collision.js): it binds a NEW port per connect and
// sends 'l' naming the name from the connect until the type-5 kick arrives
// (one RTT), then retries after the 5 s cooldown. `silent` = the refusal is
// not spoken (the address connect budget is spent), so it keeps sending for
// its 10 s client timeout.
const refusedSameNameClient = (server, clock, nat, attempts, { rate = 66, rttMs = 300, silent = false, play }) => {
  for (let a = 0; a < attempts; a++) {
    const b = h.from(nat, 51000 + a);
    if (silent) for (let d = 0; d < 8; d++) server.connects.take(nat);
    server.onDatagram(h.connect("Ghost"), b);
    const lines = silent ? 10000 : rttMs;
    for (let t = 0; t < lines; t += 1000 / rate) {
      server.onDatagram(h.update("Ghost"), b);
      play(1000 / rate);
    }
    play(5000);
  }
};

test("R3: two players behind one NAT who both kept the default name never trip the guard on each other", () => {
  for (const silent of [false, true]) {
    const { server, clock } = h.makeServer();
    const NAT = "100.64.7.9";
    const a = h.from(NAT, 50000);
    const carol = h.from("203.0.113.5", 40000);
    joinAll(server, [["Ghost", a], ["Carol", carol]]);
    let acc = 0;
    const play = (ms) => {
      acc += ms;
      while (acc >= 20) {
        acc -= 20;
        clock.advance(20);
        server.onDatagram(h.update("Ghost"), a);
        server.onDatagram(h.update("Carol"), carol);
      }
    };
    refusedSameNameClient(server, clock, NAT, 6, { silent, play });
    assert.strictEqual(server.isGuarded(server.users.get("Ghost"), clock.now()), false,
      `${silent ? "a silent refusal" : "six refused connects"} guarded the real player`);
    const mark = server.socket.sent.length;
    server.onDatagram(h.chat("Ghost", "hello"), a);
    assert.ok(chatTexts(server, carol, mark).some((c) => c.from === "Ghost"));
  }
});

test("R3: a NAT re-bind (one new port) never guards the session it left behind", () => {
  const { server, clock } = h.makeServer();
  const alice = h.from(VICTIM_IP, 50001);
  const rebound = h.from(VICTIM_IP, 50099);
  const bob = h.from("203.0.113.9", 40000);
  joinAll(server, [["Alice", alice], ["Bob", bob]]);
  for (let t = 0; t < 10000; t += 30) {
    clock.advance(30);
    server.onDatagram(h.update("Alice"), rebound);
    server.onDatagram(h.update("Bob"), bob);
  }
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false);
});

test("R3: a sweep trips the guard after IMPERSONATION_TRIGGER_PORTS distinct ports, not before", () => {
  const { server, clock } = h.makeServer();
  const alice = h.from(VICTIM_IP, REAL_PORT);
  joinAll(server, [["Alice", alice]]);
  const need = server.config.impersonationTriggerPorts;
  assert.strictEqual(need, 8);
  // Many packets from few ports: no.
  for (let i = 0; i < 200; i++) server.onDatagram(h.update("Alice"), h.from(VICTIM_IP, 30000 + (i % (need - 1))));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false, `${need - 1} ports guarded`);
  server.onDatagram(h.update("Alice"), h.from(VICTIM_IP, 40000));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, `${need} distinct ports did not`);
});

test("R3: ports older than the window do not count", () => {
  const { server, clock } = h.makeServer();
  const alice = h.from(VICTIM_IP, REAL_PORT);
  joinAll(server, [["Alice", alice]]);
  for (let i = 0; i < 20; i++) {
    server.onDatagram(h.update("Alice"), h.from(VICTIM_IP, 30000 + i));
    clock.advance(5000); // one new port every 5 s: at most 6-7 in any 30 s
    server.onDatagram(h.update("Alice"), alice);
  }
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false);
});

test("R3: a neighbour naming another player from its OWN confirmed session is charged, never counted toward a guard", () => {
  // review-tmp\round3\grief-sticky.js (b): Mallory on Alice's CGNAT IP named
  // Alice from her own session 20 times; Alice was guarded, Mallory untouched.
  const { server, clock } = h.makeServer();
  const IP = "100.64.9.9";
  const alice = h.from(IP, 61234);
  const mallory = h.from(IP, 61999);
  const bob = h.from("203.0.113.8", 40000);
  joinAll(server, [["Alice", alice], ["Mallory", mallory], ["Bob", bob]]);
  for (let i = 0; i < 30; i++) {
    clock.advance(50);
    server.onDatagram(h.chat("Alice", "hi"), mallory);
    server.onDatagram(h.update("Alice"), alice);
  }
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false, "Mallory's own session guarded Alice");
  assert.ok(!server.users.get("Mallory"), "the endpoint naming somebody else was not charged as malformed");
  assert.ok(server.users.get("Alice"));
});

// --- R4: recoverable, short, and only renewed by a fresh trigger ------------------

const sweepPorts = (server, ip, n, base = 30000) => {
  for (let p = 0; p < n; p++) server.onDatagram(h.update("Alice"), h.from(ip, base + p));
};

const aliceAndBob = () => {
  const rig = h.makeServer();
  const alice = h.from(VICTIM_IP, REAL_PORT);
  const bob = h.from("203.0.113.8", 40000);
  joinAll(rig.server, [["Alice", alice], ["Bob", bob]]);
  const play = (ms) => {
    for (let i = 0; i < ms / 1000; i++) {
      rig.clock.advance(1000);
      rig.server.onDatagram(h.update("Alice"), alice);
      rig.server.onDatagram(h.update("Bob"), bob);
    }
  };
  return Object.assign(rig, { alice, bob, play });
};

test("R4: the guard lasts 3 minutes by default, and a single packet does not renew it", () => {
  // review-tmp\round3\grief-sticky.js (a): 20 packets, then one every 9.5 min,
  // kept Alice guarded 60 of 60 minutes.
  const { server, clock, play } = aliceAndBob();
  assert.strictEqual(server.config.impersonationGuardMs, 180000);
  sweepPorts(server, VICTIM_IP, 20);
  const started = clock.now();
  for (let m = 0; m < 10; m++) {
    play(60000);
    server.onDatagram(h.update("Alice"), h.from(VICTIM_IP, 31000 + m)); // one stray packet a minute
  }
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false, "single packets kept the guard on");
  assert.ok(clock.now() - started >= 180000);
});

test("R4: a fresh trigger while guarded extends it", () => {
  const { server, clock, play } = aliceAndBob();
  sweepPorts(server, VICTIM_IP, 8);
  play(150000);
  sweepPorts(server, VICTIM_IP, 8, 32000); // the sweep goes on
  play(150000);
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, "a fresh trigger did not extend the guard");
  play(40000);
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false);
});

test("R4: notices say what is paused, for how long and how to get a new port, fit the client's chat buffer, and the end is announced", () => {
  const { server, clock, alice, play } = aliceAndBob();
  const mark = server.socket.sent.length;
  sweepPorts(server, VICTIM_IP, 20);
  const start = chatTexts(server, alice, mark).filter((c) => c.from === "SERVER").map((c) => c.text);
  const all = start.join(" ");
  for (const word of [/packets as you/, /\/race/, /\/ready/, /\/leave/, /spectate/, /sprays/, /~3 min/, /gh_online_disconnect/, /gh_online_connect/]) {
    assert.match(all, word, `the notice does not say ${word}: ${all}`);
  }
  for (const line of start) assert.ok(Buffer.byteLength(line, "latin1") <= 127, `${line.length} bytes: ${line}`);
  const m2 = server.socket.sent.length;
  play(181000);
  const end = chatTexts(server, alice, m2).filter((c) => c.from === "SERVER").map((c) => c.text);
  assert.strictEqual(end.length, 1, `end notices: ${JSON.stringify(end)}`);
  assert.match(end[0], /work again/);
});

test("R4: console 'unguard \"Nick\"' lifts the guard, logs it as [admin], tells the player; list and the log line say how", () => {
  const { attach } = require("../src/console");
  const { server, clock, alice } = aliceAndBob();
  sweepPorts(server, VICTIM_IP, 20);
  // Review 4 (M1): a full warn line per guard; formatted the way the shipped
  // logger formats it.
  const { SampledLogger } = require("../src/net/logger");
  const guardLine = server.log.lines.find((l) => l[0] === "warn" && /impersonation guard on/.test(String(l[1])));
  const formatted = guardLine ? new SampledLogger({ sink() {} }).format(guardLine[1], guardLine.slice(2)) : "";
  assert.match(formatted, /unguard "Alice"/, "the guard log line does not say how to lift it");
  const lines = [];
  const handle = attach(server, { input: new (require("node:stream").PassThrough)(), print: (l) => lines.push(l) });
  handle.handle("list");
  assert.ok(lines.some((l) => /IMPERSONATION/.test(l) && /unguard/.test(l)), lines.join("\n"));
  const mark = server.socket.sent.length;
  handle.handle('unguard "Alice"');
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false);
  assert.ok(server.log.lines.some((l) => l[0] === "info" && /\[admin\]/.test(String(l[1])) && /unguard/.test(JSON.stringify(l))), "no [admin] line");
  assert.ok(chatTexts(server, alice, mark).some((c) => c.from === "SERVER" && /work again/.test(c.text)), "the player was not told");
  clock.advance(1000);
  const m2 = server.socket.sent.length;
  server.onDatagram(h.chat("Alice", "back"), alice);
  assert.ok(server.socket.sent.slice(m2).some((p) => p.buffer[0] === packets.TYPE.CHAT), "chat still refused");
  // A fresh sweep starts a new guard (the hit ring was cleared too).
  sweepPorts(server, VICTIM_IP, 7, 40000);
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false, "old hits survived unguard");
  handle.handle('unguard "Nobody"');
  assert.ok(lines.some((l) => /Nobody/.test(l)));
  handle.rl.close();
});

test("R4: an UNVERIFIED race finish is logged with when the guard started", () => {
  const rig = h.makeServer({ RACE_LOBBY_MS: "2000" });
  const { server, clock } = rig;
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
  assert.strictEqual(server.race.phase, "racing");
  sweepPorts(server, VICTIM_IP, 10);
  clock.advance(42000);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  server.onDatagram(h.checkpoint("Alice", 2, { igt: 61.5, liveSplit: -1 }), A);
  const warn = server.log.lines.find((l) => l[0] === "warn" && /unverified/.test(JSON.stringify(l)));
  assert.ok(warn, "no race log line");
  assert.match(String(warn[1]), /since %d s before the finish/);
  assert.deepStrictEqual(warn.slice(2), ["Alice", 42], "the guard start is not recorded next to the finish");
});

// --- R5: one-shot edges refused while guarded are applied when it ends ------

test("R5: a spectate change refused while guarded is applied (and relayed) when the guard ends, so /race works", () => {
  // review-tmp\round3\guard-spectate-stale.js: before, the host kept
  // spectating='Bob' forever and /race said "Stop spectating first".
  const { server, clock, alice, bob, play } = aliceAndBob();
  server.onDatagram(h.spectate("Alice", "Bob"), alice);
  assert.strictEqual(server.users.get("Alice").spectating, "Bob");
  play(1000);
  sweepPorts(server, VICTIM_IP, 10);
  play(1000);
  assert.strictEqual(server.onDatagram(h.spectate("Alice", ""), alice), false, "precondition: refused while guarded");
  const mark = server.socket.sent.length;
  play(server.config.impersonationGuardMs + 2000);
  const user = server.users.get("Alice");
  assert.strictEqual(user.spectating, "", "the stopped-spectating edge was lost");
  const spect = server.socket.sent.slice(mark).filter((p) => p.address === bob.address && p.buffer[0] === packets.TYPE.SPECTATE);
  assert.strictEqual(spect.length, 1, "the other clients were not told she stopped spectating");
  server.onDatagram(h.chat("Alice", "/race"), alice);
  assert.notStrictEqual(server.race.phase, "idle", "/race was refused after the guard");
  assert.ok(!server.log.lines.some((l) => l[1] === "race-denied"), "told to stop spectating");
});

test("R5: an appearance change refused while guarded is relayed when the guard ends (or when the console lifts it)", () => {
  const { server, alice, bob, play } = aliceAndBob();
  sweepPorts(server, VICTIM_IP, 10);
  play(1000);
  const colour = (r, g, b) => {
    const buffer = h.connect("Alice", { ghostRed: r, ghostGreen: g, ghostBlue: b });
    buffer[4] = 0x76; // 'c' -> 'v': same fields after the opcode
    return buffer;
  };
  assert.strictEqual(server.onDatagram(colour(1, 2, 3), alice), false, "precondition: refused while guarded");
  assert.strictEqual(server.onDatagram(colour(200, 100, 50), alice), false);
  const mark = server.socket.sent.length;
  assert.strictEqual(server.unguard("Alice", "console").ok, true);
  const user = server.users.get("Alice");
  assert.deepStrictEqual([user.ghostRed, user.ghostGreen, user.ghostBlue], [200, 100, 50], "the last colour was not applied");
  const roster = server.socket.sent.slice(mark).filter((p) => p.address === bob.address && p.buffer[0] === packets.TYPE.CONNECT);
  assert.strictEqual(roster.length, 1, "the new colour was not relayed");
  // Applied once: nothing left over for the next guard.
  assert.strictEqual(user.guardedAppearance, null);
  assert.strictEqual(user.guardedSpectate, null);
});

// --- R6: a waiting picture is replaced only by a newer one that made it -------

// Me publishes P1 (the re-encode burst is free), eight fillers on other
// addresses empty the re-encode budget, then Me's P2 waits in the queue.
const queuedP2 = (env = {}) => {
  const rig = h.makeServer(Object.assign({ MAX_PLAYERS: "16" }, env));
  const { server, clock } = rig;
  const fill = [];
  for (let i = 0; i < 8; i++) fill.push([`F${i}`, h.from(`10.30.${i}.1`, 41000)]);
  const me = h.from("10.31.0.1", 42000);
  joinAll(server, fill.concat([["Me", me]]));
  const P = [1, 2, 3, 4].map((k) => h.sprayBlob(8, 200 + k));
  h.uploadSpray(server, me, "Me", P[0].crc, P[0].blob);
  fill.forEach(([n, r], i) => { const p = h.sprayBlob(8, 300 + i); h.uploadSpray(server, r, n, p.crc, p.blob); });
  clock.advance(500);
  h.uploadSpray(server, me, "Me", P[1].crc, P[1].blob);
  const entry = server.reencodeQueued.get(`${me.address}:${me.port}`);
  assert.ok(entry && entry.pending.crc === P[1].crc, "precondition: P2 is waiting in the queue");
  const drain = () => {
    for (let t = 0; t < 60000; t += 30) {
      clock.advance(30);
      if (t % 60 === 0) for (const [n, r] of fill.concat([["Me", me]])) server.onDatagram(h.update(n), r);
    }
  };
  const live = () => {
    const spray = server.users.get("Me").spray;
    return spray ? ["P1", "P2", "P3", "P4"][P.findIndex((p) => p.crc === spray.crc)] || "other" : "none";
  };
  return Object.assign(rig, { me, P, drain, live });
};

test("R6: a newer upload that never completes (its last piece lost) does not cost the waiting picture", () => {
  // review-tmp\round3\queue-supersede.js lostpiece: before, the lobby kept P1.
  const { server, me, drain, live } = queuedP2();
  const big = h.sprayBlob(32, 999, true);
  const total = Math.ceil(big.blob.length / 400);
  for (let i = 0; i < total - 1; i++) {
    server.onDatagram(h.sprayChunk("Me", big.crc, big.blob.length, total, i, big.blob.subarray(i * 400, (i + 1) * 400)), me);
  }
  drain();
  assert.strictEqual(live(), "P2");
});

test("R6: a newer upload refused (invalid, or over a publish budget) leaves the waiting picture queued", () => {
  {
    const { server, me, P, drain, live } = queuedP2();
    // A picture whose pixels do not match its crc fails validation.
    server.onDatagram(h.sprayChunk("Me", P[2].crc ^ 0x5a5a, P[2].blob.length, 1, 0, P[2].blob), me);
    drain();
    assert.strictEqual(live(), "P2", "an invalid newer picture discarded the waiting one");
  }
  {
    // Burst 2: P1 and P2 spend it, so P3 is refused by the session budget.
    const { server, me, P, drain, live } = queuedP2({ SPRAY_PUBLISH_BURST: "2" });
    h.uploadSpray(server, me, "Me", P[2].crc, P[2].blob);
    assert.ok(server.log.lines.some((l) => l[1] === "spray-publish-limit"), "precondition: P3 was refused by a budget");
    drain();
    assert.strictEqual(live(), "P2", "a budget-refused newer picture discarded the waiting one");
  }
});

test("R6: a newer validated picture replaces the waiting one in place and its publish tokens are given back", () => {
  // review-tmp\round3\queue-supersede.js budget: before, P2-P4 were all lost.
  const { server, me, P, drain, live } = queuedP2();
  const key = `${me.address}:${me.port}`;
  const before = server.sprayPublish.available(key);
  h.uploadSpray(server, me, "Me", P[2].crc, P[2].blob);
  assert.strictEqual(server.reencodeQueued.get(key).pending.crc, P[2].crc, "P3 did not take P2's place");
  assert.ok(Math.abs(server.sprayPublish.available(key) - before) < 0.01, "P2's tokens were not given back when P3 replaced it");
  h.uploadSpray(server, me, "Me", P[3].crc, P[3].blob);
  drain();
  assert.strictEqual(live(), "P4");
});

// --- R8: no silent same-address takeover of a guarded session during a load --

test("R8: while guarded, a same-address takeover needs STALE_TIMEOUT_MS of silence, not TAKEOVER_AFTER_MS", () => {
  const { server, clock, alice, bob } = aliceAndBob();
  sweepPorts(server, VICTIM_IP, 10);
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true);
  // Alice loads a level: 15 s of silence (the attacker reads it off the relay).
  for (let t = 0; t < 15000; t += 1000) { clock.advance(1000); server.onDatagram(h.update("Bob"), bob); }
  const forged = h.from(VICTIM_IP, 45000);
  server.onDatagram(h.connect("Alice"), forged);
  assert.strictEqual(server.users.get("Alice").socket.port, REAL_PORT, "a guarded session was taken over after a 15 s load");
  // ...and the notice tells the player to wait that long for a new port.
  assert.ok(server.guardNotice().some((l) => l.includes(`wait ${server.config.staleTimeoutMs / 1000} s`)), server.guardNotice().join(" | "));
  // Past the stale timeout the name can be reclaimed (the real player
  // reconnecting from a new port after gh_online_disconnect).
  for (let t = 0; t < 47000; t += 1000) { clock.advance(1000); server.onDatagram(h.update("Bob"), bob); }
  const fresh = h.from(VICTIM_IP, 45001);
  server.onDatagram(h.connect("Alice"), fresh);
  server.onDatagram(h.update("Alice"), fresh);
  assert.ok(server.users.get("Alice"), "the name could not be reclaimed");
  assert.strictEqual(server.users.get("Alice").socket.port, fresh.port);
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), false);
  void alice;
});

test("R8: an unguarded session is still taken over from the same address after TAKEOVER_AFTER_MS (a crash and restart)", () => {
  const { server, clock, bob } = aliceAndBob();
  for (let t = 0; t < server.config.takeoverAfterMs + 1000; t += 1000) { clock.advance(1000); server.onDatagram(h.update("Bob"), bob); }
  const restarted = h.from(VICTIM_IP, 45002);
  server.onDatagram(h.connect("Alice"), restarted);
  assert.strictEqual(server.users.get("Alice").socket.port, restarted.port);
});

// --- R9: visibility of the re-encode queue; the FIFO stream's error listener --

test("R9: status and sprays show how many pictures wait for a re-encode", () => {
  const { attach } = require("../src/console");
  const { server } = h.makeServer({ MAX_PLAYERS: "16" });
  const senders = [];
  for (let i = 0; i < 7; i++) senders.push([`S${i}`, h.from(`10.9.${i}.1`, 41000 + i)]);
  joinAll(server, senders);
  senders.forEach(([n, r], i) => { const p = h.sprayBlob(8, 900 + i); h.uploadSpray(server, r, n, p.crc, p.blob); });
  assert.strictEqual(server.reencodeQueued.size, 3, "precondition: 3 waiting");
  assert.strictEqual(server.status().sprays.reencodeQueued, 3);
  assert.strictEqual(server.spraySnapshot().reencodeQueued, 3);
  const lines = [];
  const handle = attach(server, { input: new (require("node:stream").PassThrough)(), print: (l) => lines.push(l) });
  handle.handle("status");
  assert.ok(lines.some((l) => /waiting for a re-encode: 3/.test(l)), lines.join("\n"));
  lines.length = 0;
  handle.handle("sprays");
  assert.ok(lines.some((l) => /waiting for a re-encode: 3/.test(l)), lines.join("\n"));
  handle.rl.close();
});

test("R9: a read error on the console FIFO stream is logged and does not end the process", () => {
  // Windows has no FIFO; a regular file opened the same way exercises the same
  // code path (openConsoleInput falls back to a read stream on that fd).
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const { openConsoleInput } = require("../index");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghs-fifo-"));
  const file = path.join(dir, "console");
  fs.writeFileSync(file, "");
  const warnings = [];
  const stream = openConsoleInput(file, { warn: (...a) => warnings.push(a) });
  try {
    assert.ok(stream, "the input was not opened");
    assert.doesNotThrow(() => stream.emit("error", Object.assign(new Error("read EIO"), { code: "EIO" })));
    assert.strictEqual(warnings.length, 1, "the read error was not logged");
    assert.match(String(warnings[0][0]), /console FIFO/);
  } finally {
    stream.destroy();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
