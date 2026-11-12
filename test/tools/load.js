#!/usr/bin/env node
"use strict";

// Load harness. Real UDP sockets, loopback only.
//
//   node test/tools/load.js [seconds] [clients]
//
// Phases, in order:
//   1. sustained play    N clients at 50 updates/s, the real client cadence
//   2. chat and a race   the paths that fan out to everyone
//   3. connect storm     rotating source ports from one address
//   4. log flood         the cheapest packet that used to buy a log line
//   5. recovery          a fresh client must still be able to join
//
// What it reports is throughput, loss, event loop lag and resident memory. What
// it cannot tell you is how the host behaves on a real network: this is one
// machine talking to itself, with no packet loss, no reordering and no MTU.

const dgram = require("dgram");
const os = require("os");

const { load } = require("../../src/config");
const { GhostingServer } = require("../../src/server");
const { SampledLogger } = require("../../src/net/logger");
const h = require("../helpers/harness");
const packets = require("../../src/wire/packets");

const SECONDS = Number.parseInt(process.argv[2], 10) || 60;
const CLIENTS = Number.parseInt(process.argv[3], 10) || 16;
const PORT = 22998;
const HOST = "127.0.0.1";
const UPDATE_HZ = 50;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Event loop lag: how late a timer fires. This is the number that matters for a
// game server, because a stalled loop is a stalled relay.
class LagMeter {
  constructor() {
    this.samples = [];
    this.timer = null;
  }
  start() {
    let expected = Date.now() + 20;
    this.timer = setInterval(() => {
      const now = Date.now();
      this.samples.push(Math.max(0, now - expected));
      expected = now + 20;
    }, 20);
  }
  stop() {
    clearInterval(this.timer);
    const sorted = this.samples.slice().sort((a, b) => a - b);
    const at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] || 0;
    return { samples: sorted.length, p50: at(0.5), p95: at(0.95), p99: at(0.99), max: sorted[sorted.length - 1] || 0 };
  }
}

const makeClient = (name) =>
  new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const state = { name, socket, received: 0, bytes: 0, types: new Map(), sent: 0 };
    socket.on("message", (buffer) => {
      state.received += 1;
      state.bytes += buffer.length;
      const type = buffer.readUInt8(0);
      state.types.set(type, (state.types.get(type) || 0) + 1);
    });
    socket.once("error", reject);
    socket.bind(0, HOST, () => resolve(state));
  });

const send = (client, buffer) => {
  client.sent += 1;
  client.socket.send(buffer, PORT, HOST, () => {});
};

const main = async () => {
  const config = load({
    PORT: String(PORT),
    BIND_ADDRESS: HOST,
    MAX_PLAYERS: String(Math.max(16, CLIENTS)),
    MAX_SESSIONS_PER_ADDRESS: String(CLIENTS + 8),
    CONNECT_BURST: String(CLIENTS + 8),
    CONNECT_RATE_PER_MINUTE: "600",
    RACE_LOBBY_MS: "5000",
  });

  const logLines = [];
  const log = new SampledLogger({
    intervalMs: config.logSampleIntervalMs,
    sink: (line) => logLines.push(line),
  });
  const server = new GhostingServer({ config, log });

  const failures = [];
  process.on("uncaughtException", (error) => failures.push(`uncaughtException: ${error.message}`));
  process.on("unhandledRejection", (reason) => failures.push(`unhandledRejection: ${reason}`));

  await server.start();
  console.log(`server on ${HOST}:${PORT}, ${CLIENTS} clients, ${SECONDS}s, node ${process.version} on ${os.platform()}`);

  const clients = [];
  for (let i = 0; i < CLIENTS; i += 1) clients.push(await makeClient(`Runner${i}`));

  // --- phase 1 and 2: sustained play ---------------------------------------
  for (const client of clients) send(client, h.connect(client.name));
  await sleep(300);

  // Idle baseline first. On Windows a 20 ms timer is already 10-15 ms late
  // because of the scheduler's tick, so reporting raw lag under load without it
  // would credit the platform's granularity to the server.
  const idle = new LagMeter();
  idle.start();
  await sleep(1000);
  const idleLag = idle.stop();

  const lag = new LagMeter();
  lag.start();
  const startedAt = Date.now();
  const cpuBefore = process.cpuUsage();

  const tick = setInterval(() => {
    const t = (Date.now() - startedAt) / 1000;
    for (let i = 0; i < clients.length; i += 1) {
      const client = clients[i];
      send(
        client,
        h.update(client.name, {
          map: "d1_trainstation_01",
          position: [Math.sin(t + i) * 500, Math.cos(t + i) * 500, 64],
          velocity: [i * 3, t * 2, 0],
          heldModel: i % 4 === 0 ? "models/props_c17/oildrum001.mdl" : "",
        })
      );
    }
  }, Math.round(1000 / UPDATE_HZ));

  // Chat every two seconds from a rotating sender, plus one race in the middle.
  let chatTurn = 0;
  const chatter = setInterval(() => {
    const client = clients[chatTurn++ % clients.length];
    send(client, h.chat(client.name, `tick ${chatTurn}`));
  }, 2000);

  let raced = false;
  const racer = setInterval(() => {
    if (raced || Date.now() - startedAt < (SECONDS * 1000) / 3) return;
    raced = true;
    send(clients[0], h.chat(clients[0].name, "/race"));
    for (let i = 1; i < Math.min(4, clients.length); i += 1) {
      setTimeout(() => send(clients[i], h.chat(clients[i].name, "/ready")), 500 * i);
    }
    // Everyone reports the race map and reaches the start point.
    setTimeout(() => {
      for (let i = 0; i < Math.min(4, clients.length); i += 1) send(clients[i], h.checkpoint(clients[i].name, 1));
    }, 12000);
  }, 1000);

  await sleep(SECONDS * 1000);
  clearInterval(tick);
  clearInterval(chatter);
  clearInterval(racer);

  const cpu = process.cpuUsage(cpuBefore);
  const lagStats = lag.stop();
  const elapsed = (Date.now() - startedAt) / 1000;
  await sleep(500);

  const sustained = Object.assign({}, server.stats);

  // --- phase 3: connect storm ----------------------------------------------
  const storm = await makeClient("storm");
  const stormMark = server.stats.received;
  for (let i = 0; i < 2000; i += 1) storm.socket.send(h.connect(`Storm${i}`), PORT, HOST, () => {});
  await sleep(1500);
  const stormAccepted = server.users.count();
  const stormPacketsSeen = server.stats.received - stormMark;

  // --- phase 3b: spectate flood --------------------------------------------
  // The cheapest amplifier in the protocol: a tiny payload that used to fan out
  // to every player with no limit at all.
  // Counted as packets that actually carried a spectate relay, not as total
  // sends: heartbeats and ordinary updates keep flowing throughout and would
  // otherwise be credited to the flood.
  const spectateSeenBefore = clients.reduce((sum, c) => sum + (c.types.get(packets.TYPE.SPECTATE) || 0), 0);
  const spectateLinesBefore = logLines.length;
  for (let i = 0; i < 20000; i += 1) {
    const target = i % 2 === 0 ? clients[1].name : "";
    clients[0].socket.send(h.spectate(clients[0].name, target), PORT, HOST, () => {});
  }
  await sleep(2000);
  const spectateFanOut =
    clients.reduce((sum, c) => sum + (c.types.get(packets.TYPE.SPECTATE) || 0), 0) - spectateSeenBefore;
  const spectateLines = logLines.length - spectateLinesBefore;

  // --- phase 3c: unknown opcode flood --------------------------------------
  // Fan-out here means "did the junk earn a reply to the sender", so it is
  // measured at the sender's own socket rather than from the server's counters.
  const unknownReceivedBefore = storm.received;
  const unknownLinesBefore = logLines.length;
  const weird = (() => {
    const w = new (require("../../src/wire/writer").BufferWriter)(64);
    w.writeString("ZZZ");
    return w.buffer;
  })();
  for (let i = 0; i < 20000; i += 1) storm.socket.send(weird, PORT, HOST, () => {});
  await sleep(2000);
  const unknownFanOut = storm.received - unknownReceivedBefore;
  const unknownLines = logLines.length - unknownLinesBefore;

  // --- phase 4: log flood ---------------------------------------------------
  const linesBefore = logLines.length;
  const probe = Buffer.from([0, 0, 0, 0]);
  const floodStart = Date.now();
  for (let i = 0; i < 20000; i += 1) storm.socket.send(probe, PORT, HOST, () => {});
  await sleep(2000);
  const floodLines = logLines.length - linesBefore;
  const floodSeconds = (Date.now() - floodStart) / 1000;

  // --- phase 4b: do the rate-limit tables come back to baseline? ------------
  // Every bucket refills completely after its own idle window, at which point
  // it holds no information and should be pruned. If they do not shrink, a
  // flood leaves residue that accumulates across attacks.
  const tablesAfterFlood = {
    address: server.byAddress.size,
    session: server.bySession.size,
    connect: server.connects.size,
    malformed: server.malformed.size,
    penalty: server.penalty.size,
  };
  await sleep(Math.max(6000, server.config.sweepIntervalMs * 2));
  const tablesAfterTtl = {
    address: server.byAddress.size,
    session: server.bySession.size,
    connect: server.connects.size,
    malformed: server.malformed.size,
    penalty: server.penalty.size,
  };

  // --- phase 5: recovery ----------------------------------------------------
  // One of the original players leaves, which frees the slot a new player needs
  // on a full server and exercises the confirmed-disconnect path at the same
  // time.
  send(clients[0], h.disconnect(clients[0].name));
  await sleep(3000);

  // Everything in this harness shares one address, because loopback has only
  // one. The flooding endpoint has no session of its own, so the penalty falls
  // on the address - which on a real network is the right answer for a stranger
  // and here also covers the QA's own new client.
  //
  // This used to assert that a new client is blocked outright while the box
  // stands. That was the behaviour, and it was a defect: 21 malformed datagrams
  // every thirty seconds, from a source address anyone can forge, locked the
  // real owner of that address out indefinitely. A boxed address now gets a
  // trickle instead of silence, so both halves are measured here: a real client
  // gets in within a few of the DLL's five-second retries, and the flood does
  // not get in at all.
  const earlyJoiner = await makeClient("EarlyJoiner");
  let admittedDuringPenalty = false;
  let attempts = 0;
  while (attempts < 4 && !admittedDuringPenalty) {
    attempts += 1;
    send(earlyJoiner, h.connect("EarlyJoiner"));
    await sleep(1200);
    admittedDuringPenalty = server.users.exists("EarlyJoiner");
  }
  const penaltyStillArmed = server.penalty.size > 0;
  const parsedBefore = server.stats.unknownOpcode;
  // Three seconds of flooding from the boxed endpoint against a ~1 pps trickle.
  for (let i = 0; i < 30000; i += 1) storm.socket.send(probe, PORT, HOST, () => {});
  await sleep(3000);
  const trickleParsed = server.stats.unknownOpcode - parsedBefore;

  send(earlyJoiner, h.disconnect("EarlyJoiner"));
  await sleep(3000);
  earlyJoiner.socket.close();

  const penaltyRemaining = Math.max(...Array.from(server.penalty.values()).map((until) => until - Date.now()), 0);
  console.log(`waiting ${Math.ceil(penaltyRemaining / 1000)}s for the penalty box to lapse...`);
  await sleep(penaltyRemaining + 2000);

  const late = await makeClient("LateJoiner");
  send(late, h.connect("LateJoiner"));
  await sleep(400);
  send(late, h.update("LateJoiner"));
  await sleep(400);
  const recovered = server.users.exists("LateJoiner");

  // --- results --------------------------------------------------------------
  const totalReceived = clients.reduce((sum, c) => sum + c.received, 0);
  const totalBytes = clients.reduce((sum, c) => sum + c.bytes, 0);
  const totalSent = clients.reduce((sum, c) => sum + c.sent, 0);
  const expectedUpdates = Math.round(elapsed * UPDATE_HZ) * CLIENTS;

  const report = {
    node: process.version,
    platform: `${os.platform()} ${os.arch()}`,
    clients: CLIENTS,
    seconds: Number(elapsed.toFixed(1)),
    updatesSentByClients: totalSent,
    expectedUpdatesApprox: expectedUpdates,
    serverReceived: sustained.received,
    serverAccepted: sustained.accepted,
    serverSent: sustained.sent,
    serverBytesOut: sustained.bytesOut,
    clientPacketsReceived: totalReceived,
    clientBytesReceived: totalBytes,
    outboundPacketsPerSecond: Math.round(sustained.sent / elapsed),
    outboundMbitPerSecond: Number(((sustained.bytesOut * 8) / elapsed / 1e6).toFixed(2)),
    deliveryRatio: Number((totalReceived / Math.max(1, sustained.sent)).toFixed(4)),
    cpuUserMs: Math.round(cpu.user / 1000),
    cpuSystemMs: Math.round(cpu.system / 1000),
    cpuPercentOfOneCore: Number((((cpu.user + cpu.system) / 1000 / (elapsed * 1000)) * 100).toFixed(1)),
    rssMb: Number((process.memoryUsage().rss / 1048576).toFixed(1)),
    heapMb: Number((process.memoryUsage().heapUsed / 1048576).toFixed(1)),
    eventLoopLagMs: lagStats,
    eventLoopLagIdleBaselineMs: idleLag,
    raceRan: raced,
    stormPacketsSeen,
    stormSessionsAccepted: stormAccepted,
    slotFreedByDisconnect: !server.users.exists(clients[0].name),
    logFlood: { packets: 20000, seconds: Number(floodSeconds.toFixed(1)), linesWritten: floodLines },
    spectateFlood: { packets: 20000, packetsFannedOut: spectateFanOut, linesWritten: spectateLines },
    unknownOpcodeFlood: { packets: 20000, packetsFannedOut: unknownFanOut, linesWritten: unknownLines },
    rateLimitTables: { afterFlood: tablesAfterFlood, afterTtl: tablesAfterTtl },
    penaltyBox: server.penalty.size,
    trackedAddresses: server.byAddress.size,
    trackedSessions: server.bySession.size,
    boxedAddress: {
      admittedARealClient: admittedDuringPenalty,
      connectAttemptsNeeded: attempts,
      boxStillArmedAfterwards: penaltyStillArmed,
      floodDatagramsSent: 30000,
      floodDatagramsParsed: trickleParsed,
    },
    recoveredAfterPenaltyLapsed: recovered,
    malformed: server.stats.malformed,
    unknownOpcode: server.stats.unknownOpcode,
    oversized: server.stats.oversized,
    sendErrors: server.stats.sendErrors,
    reflectionBlocked: server.stats.reflectionBlocked,
    failures,
  };

  console.log(JSON.stringify(report, null, 2));

  for (const client of clients) client.socket.close();
  storm.socket.close();
  late.socket.close();
  await server.stop();

  // A clean restart on the same port, which is what a supervisor does.
  const again = new GhostingServer({ config, log: new SampledLogger({ sink: () => {} }) });
  await again.start();
  await again.stop();
  console.log("rebind after shutdown: ok");

  const healthy =
    failures.length === 0 &&
    recovered &&
    // A boxed address must let a real client in...
    admittedDuringPenalty &&
    // ...without the box becoming a way to keep parsing: 30 000 datagrams
    // against a two-token, one-per-second trickle.
    trickleParsed <= 20 &&
    report.deliveryRatio > 0.95 &&
    lagStats.p99 < 250 &&
    floodLines < 200 &&
    spectateLines < 200 &&
    unknownLines < 200 &&
    // 20 000 spectate requests must not become 20 000 fan-outs.
    spectateFanOut < 20000 * CLIENTS * 0.02 &&
    // An unknown opcode earns no network reply whatsoever.
    unknownFanOut === 0 &&
    tablesAfterTtl.address <= tablesAfterFlood.address &&
    tablesAfterTtl.penalty <= tablesAfterFlood.penalty &&
    stormAccepted <= CLIENTS + 8;
  console.log(healthy ? "LOAD TEST PASS" : "LOAD TEST FAIL");
  process.exit(healthy ? 0 : 1);
};

main().catch((error) => {
  console.error("load harness failed:", error);
  process.exit(1);
});
