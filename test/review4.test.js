"use strict";

// Review 4 findings (F1, M1, M2). The probes these mirror are in
// review-tmp\round4.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");

const joinAll = (server, list) => {
  for (const [n, r] of list) {
    server.onDatagram(h.connect(n), r);
    server.onDatagram(h.update(n), r);
  }
};

// --- F1: a group of same-name players behind one NAT ---------------------------

// review-tmp\round4\lan-default-names.js, as a function. A plays as "Ghost";
// nB neighbours behind the same NAT also kept the default name and press
// connect. Each attempt binds a new port, re-sends 'c' once a second (up to 6)
// until answered, and sends 'l' naming "Ghost" at the update rate until the
// type-5 kick is processed (RTT + a frame) - or for its 10 s timeout if the
// refusal was silent. A new attempt needs the 5 s cooldown plus `think` ms.
const lanParty = (nB, think, attemptsPerB, { rate = 50, rtt = 60, stagger = 700 } = {}) => {
  const { server, socket, clock } = h.makeServer({ RACE_LOBBY_MS: "2000" });
  const NAT = "100.64.7.9";
  const A = h.from(NAT, 50000);
  const C = h.from("203.0.113.5", 40000);
  joinAll(server, [["Ghost", A], ["Carol", C]]);
  for (let i = 0; i < 60; i++) {
    clock.advance(1000);
    server.onDatagram(h.update("Ghost"), A);
    server.onDatagram(h.update("Carol"), C);
  }
  let port = 51000;
  const L = 1000 / rate;
  const Bs = [];
  for (let b = 0; b < nB; b++) {
    Bs.push({ attempts: 0, state: "idle", nextStart: b * stagger, sock: null, lNext: 0, cNext: 0, cTries: 0, stopAt: 0, lastAttempt: -1e9 });
  }
  let t = 0;
  let aNext = 0;
  let cNext = 0;
  let guardedAt = null;
  const kickedNow = (sock, mark) => socket.sent.slice(mark).some((s) => s.address === NAT && s.port === sock.port && s.buffer[0] === 5);
  while (t < 5 * 60000) {
    t += 1;
    clock.advance(1);
    if (t >= aNext) { server.onDatagram(h.update("Ghost"), A); aNext = t + 20; }
    if (t >= cNext) { server.onDatagram(h.update("Carol"), C); cNext = t + 20; }
    for (const B of Bs) {
      if (B.state === "idle" && B.attempts < attemptsPerB && t >= B.nextStart && t - B.lastAttempt >= 5000) {
        B.state = "trying"; B.attempts += 1; B.sock = h.from(NAT, port++); B.lastAttempt = t;
        B.cTries = 0; B.cNext = t; B.lNext = t; B.stopAt = t + 10000;
      }
      if (B.state !== "trying") continue;
      if (t >= B.cNext && B.cTries < 6) {
        const mark = socket.sent.length;
        server.onDatagram(h.connect("Ghost"), B.sock);
        B.cTries += 1; B.cNext = t + 1000;
        if (kickedNow(B.sock, mark)) { B.stopAt = Math.min(B.stopAt, t + rtt + Math.ceil(L)); B.cTries = 99; }
      }
      if (t >= B.lNext) { server.onDatagram(h.update("Ghost"), B.sock); B.lNext = t + L; }
      if (t >= B.stopAt) { B.state = "idle"; B.nextStart = t + think; }
    }
    if (guardedAt === null && server.isGuarded(server.users.get("Ghost"), clock.now())) guardedAt = t;
  }
  return { server, guardedAt, ports: port - 51000 };
};

test("F1: three same-name players behind one NAT retrying three times never guard the one who got in", () => {
  // Before: guarded at 10.7 s (think 0 and 3 s) and 16.9 s (think 8 s).
  for (const think of [0, 3000, 8000]) {
    const { guardedAt, ports } = lanParty(3, think, 3);
    assert.ok(ports >= 9, `precondition: ${ports} ports`);
    assert.strictEqual(guardedAt, null, `guarded at ${guardedAt} ms (think ${think} ms)`);
  }
});

test("F1: two same-name players retrying at the 5 s cooldown never guard the one who got in", () => {
  // Before: guarded at 15.7 s.
  for (const think of [0, 3000]) {
    const { guardedAt } = lanParty(2, think, 6);
    assert.strictEqual(guardedAt, null, `guarded at ${guardedAt} ms (think ${think} ms)`);
  }
});

test("F1: the exemption covers only the refused endpoint, only for the name it was refused, only for a while", () => {
  const { server, clock } = h.makeServer();
  const IP = "100.64.7.9";
  const alice = h.from(IP, 50000);
  const ghost = h.from(IP, 50001);
  joinAll(server, [["Alice", alice], ["Ghost", ghost]]);
  const idle = (ms) => {
    for (let t = 0; t < ms; t += 1000) {
      clock.advance(1000);
      server.onDatagram(h.update("Alice"), alice);
      server.onDatagram(h.update("Ghost"), ghost);
    }
  };
  idle(60000); // the address connect budget is full again (burst 4)
  const refuse = (base) => { for (let p = 0; p < 4; p++) server.onDatagram(h.connect("Ghost"), h.from(IP, base + p)); };
  const name = (who, base) => { for (let p = 0; p < 4; p++) server.onDatagram(h.update(who), h.from(IP, base + p)); };

  // Four ports refused "Ghost" (spoken), then naming Alice: not the name they
  // were refused, so they count - with four more ports, Alice is guarded.
  refuse(52000);
  name("Alice", 52000);
  name("Alice", 52100);
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, "a port refused another name was exempt for Alice");

  // Four more refused "Ghost", naming Ghost within the window: exempt, so even
  // with four other ports Ghost is not guarded.
  idle(30000);
  refuse(53000);
  name("Ghost", 53000);
  name("Ghost", 53100);
  assert.strictEqual(server.isGuarded(server.users.get("Ghost"), clock.now()), false, "the refused ports counted for the name they were refused");

  // Past the window they count again.
  idle(server.config.impersonationRefusedPortMs + 1000);
  name("Ghost", 53000);
  name("Ghost", 53200);
  assert.strictEqual(server.isGuarded(server.users.get("Ghost"), clock.now()), true, "the exemption outlived its window");
});

test("F1: a silent refusal (connect budget spent) buys no exemption, so forged connects cannot hide a sweep", () => {
  const { server, clock } = h.makeServer();
  const IP = "198.51.100.7";
  const alice = h.from(IP, 61234);
  joinAll(server, [["Alice", alice]]);
  // The attacker forges connects naming Alice from fresh ports of her IP: the
  // first few are spoken refusals (budget), the rest silent (reserve tokens).
  for (let p = 0; p < 30; p++) server.onDatagram(h.connect("Alice"), h.from(IP, 40000 + p));
  for (let p = 0; p < 30; p++) server.onDatagram(h.update("Alice"), h.from(IP, 40000 + p));
  assert.strictEqual(server.isGuarded(server.users.get("Alice"), clock.now()), true, "a sweep hid behind forged connects");
});

// --- M1: what the operator sees in the real log ------------------------------

// The shipped SampledLogger (it escapes, truncates details to 120 characters
// and samples every event code), not the harness's raw recorder.
const withRealLog = (env) => {
  const { SampledLogger } = require("../src/net/logger");
  const rig = h.makeServer(env);
  const printed = [];
  const real = new SampledLogger({ intervalMs: 10000, now: () => rig.clock.now(), sink: (line) => printed.push(line) });
  rig.server.log = real;
  rig.server.race.deps.log = real;
  return Object.assign(rig, { printed });
};

const guardVictims = (server, n, firstOctet = 10) => {
  const victims = [];
  for (let v = 0; v < n; v++) {
    const ip = `198.51.${100 + Math.floor(v / 200)}.${firstOctet + (v % 200)}`;
    const name = `Victim${v}`;
    const r = h.from(ip, 61000);
    server.onDatagram(h.connect(name), r);
    server.onDatagram(h.update(name), r);
    victims.push({ ip, name, r });
  }
  return victims;
};
const sweepVictim = (server, v, base = 30000) => {
  for (let p = 0; p < 8; p++) server.onDatagram(h.update(v.name), h.from(v.ip, base + p));
};

test("M1: every guard start is printed by the real logger, with who, for how long and the full unguard command", () => {
  // review-tmp\round4\real-log-guard.js: before, 3 guards in 5 s printed ONE
  // line, cut at 120 characters before the unguard hint.
  const { server, clock, printed } = withRealLog();
  const victims = guardVictims(server, 3);
  for (const v of victims) { clock.advance(1500); sweepVictim(server, v); }
  for (const v of victims) {
    const line = printed.find((l) => l.includes(`'${v.name}'`) && /impersonation guard/i.test(l));
    assert.ok(line, `no log line for ${v.name}:\n${printed.join("\n")}`);
    assert.ok(line.includes(`unguard "${v.name}"`), `the unguard command is missing or cut: ${line}`);
    assert.match(line, /~3 min/);
  }
  // ...and its end.
  for (let t = 0; t < 181000; t += 1000) {
    clock.advance(1000);
    for (const v of victims) server.onDatagram(h.update(v.name), v.r);
  }
  for (const v of victims) {
    assert.ok(printed.some((l) => l.includes(`'${v.name}'`) && /guard .*ended/i.test(l)), `no end line for ${v.name}`);
  }
});

test("M1: guard log lines stay bounded however many guards an attacker starts", () => {
  const { attach } = require("../src/console");
  const { server, clock, printed } = withRealLog({ MAX_PLAYERS: "64" });
  const victims = guardVictims(server, 64);
  const handle = attach(server, { input: new (require("node:stream").PassThrough)(), print: () => {} });
  const guardLines = () => printed.filter((l) => /impersonation guard on/i.test(l)).length;
  // Three rounds inside one minute: guard all 64, lift all, guard all again.
  for (let round = 0; round < 3; round++) {
    for (const v of victims) sweepVictim(server, v, 30000 + round * 100);
    for (const v of victims) handle.handle(`unguard "${v.name}"`);
    clock.advance(1000);
  }
  handle.rl.close();
  const { GUARD_LOG_BURST } = require("../src/server");
  assert.ok(guardLines() <= GUARD_LOG_BURST + 5, `${guardLines()} guard lines in a few seconds (burst ${GUARD_LOG_BURST})`);
  assert.ok(printed.some((l) => /impersonation-guard/.test(l)), "the excess was not summarised by the sampled logger");
});

// --- M2: console commands find non-ASCII players as `list` shows them ----------

// The client sends nicknames as UTF-8 bytes; the host keeps them as that byte
// string; `list` prints them decoded; the operator types what `list` printed.
const wireName = (text) => Buffer.from(text, "utf8").toString("latin1");

const consoleFor = (server) => {
  const { attach } = require("../src/console");
  const out = [];
  const handle = attach(server, { input: new (require("node:stream").PassThrough)(), print: (l) => out.push(l) });
  return { out, handle };
};

test("M2: every console command that takes a nickname finds a Cyrillic or accented player typed as `list` shows it", () => {
  // review-tmp\round4\console-utf8-name.js: before, `unguard "Призрак"` and
  // `kick "Призрак"` answered "no such player".
  for (const shown of ["Призрак", "Renée"]) {
    const { server, clock } = h.makeServer({ OP_ALLOW_NO_PIN: "1" });
    const name = wireName(shown);
    const r = h.from("198.51.100.9", 61000);
    joinAll(server, [[name, r]]);
    const { out, handle } = consoleFor(server);

    handle.handle("list");
    assert.ok(out.some((l) => l.includes(`  ${shown} (`)), `list does not show ${shown}: ${out.join("\n")}`);

    for (let p = 0; p < 8; p++) server.onDatagram(h.update(name), h.from("198.51.100.9", 30000 + p));
    assert.strictEqual(server.isGuarded(server.users.get(name), clock.now()), true, "precondition: guarded");
    handle.handle("list");
    assert.ok(out.some((l) => l.includes(`unguard "${shown}"`)), "list's hint does not show the name as typed");
    handle.handle(`unguard "${shown}"`);
    assert.strictEqual(server.isGuarded(server.users.get(name), clock.now()), false, `unguard "${shown}" did not find the player`);

    handle.handle(`op "${shown}"`);
    assert.strictEqual(server.operatorSessions.size, 1, `op "${shown}" did not find the player`);
    handle.handle(`deop "${shown}"`);
    assert.strictEqual(server.operatorSessions.size, 0, `deop "${shown}" did not find the player`);

    handle.handle(`sprayban "${shown}" 1h`);
    assert.strictEqual(server.access.maySpray(name), false, `sprayban "${shown}" did not match the player`);
    handle.handle(`unsprayban "${shown}"`);
    assert.strictEqual(server.access.maySpray(name), true, `unsprayban "${shown}" did not match`);

    handle.handle(`whitelist add "${shown}"`);
    assert.strictEqual(server.access.isAllowed(name, "203.0.113.1"), true);
    handle.handle("whitelist on");
    assert.strictEqual(server.access.isAllowed(name, "203.0.113.1"), true, `whitelist add "${shown}" did not match the player`);
    handle.handle("whitelist off");

    handle.handle(`ban "${shown}" 1h`);
    assert.ok(server.access.banFor(name, "203.0.113.1"), `ban "${shown}" did not match the player`);
    assert.ok(!server.users.get(name), `ban "${shown}" did not remove the player`);
    handle.handle(`unban "${shown}"`);
    assert.strictEqual(server.access.banFor(name, "203.0.113.1"), null, `unban "${shown}" did not match`);

    joinAll(server, [[name, h.from("198.51.100.9", 61001)]]);
    handle.handle(`kick "${shown}"`);
    assert.ok(!server.users.get(name), `kick "${shown}" did not find the player`);
    // Replies print the name readably, not as escaped bytes.
    handle.handle(`kick "${shown}"`);
    assert.ok(out[out.length - 1].includes(shown), out[out.length - 1]);
    handle.rl.close();
  }
});

test("M2: a console broadcast in Cyrillic reaches players as the UTF-8 the client expects", () => {
  const { server, socket, clock } = h.makeServer();
  const r = h.from("203.0.113.4", 40000);
  joinAll(server, [["Alice", r]]);
  clock.advance(100);
  const { handle } = consoleFor(server);
  const mark = socket.sent.length;
  handle.handle('broadcast "Привет"');
  const chat = socket.sent.slice(mark).find((p) => p.buffer[0] === 6);
  assert.ok(chat, "no chat sent");
  assert.ok(chat.buffer.includes(Buffer.from("Привет", "utf8")), "the text is not the UTF-8 bytes of what was typed");
  handle.rl.close();
});

test("M2: list's unguard hint for a name containing a quote is one the console can parse", () => {
  const { server, clock } = h.makeServer();
  const name = 'Bo"b';
  const r = h.from("198.51.100.9", 61000);
  joinAll(server, [[name, r]]);
  for (let p = 0; p < 8; p++) server.onDatagram(h.update(name), h.from("198.51.100.9", 30000 + p));
  const { out, handle } = consoleFor(server);
  handle.handle("list");
  const hint = out.join("\n").match(/lift with: (unguard [^)]*)\)/);
  assert.ok(hint, out.join("\n"));
  handle.handle(hint[1]);
  assert.strictEqual(server.isGuarded(server.users.get(name), clock.now()), false, `"${hint[1]}" did not lift the guard`);
  handle.rl.close();
});
