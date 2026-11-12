"use strict";

// Real sockets, on the loopback interface only.
//
// The fake socket used everywhere else proves the logic; this file proves the
// process behaves: it binds, it answers, it shuts down without leaving the port
// held, and it can be started again immediately afterwards - which is what a
// supervisor does on every restart.

const test = require("node:test");
const assert = require("node:assert");
const dgram = require("dgram");

const { load } = require("../src/config");
const { GhostingServer } = require("../src/server");
const { SampledLogger } = require("../src/net/logger");
const h = require("./helpers/harness");
const packets = require("../src/wire/packets");

const PORT = 22999;
const HOST = "127.0.0.1";

const quiet = () => new SampledLogger({ sink: () => {} });

const startServer = async (env = {}) => {
  const config = load(Object.assign({ PORT: String(PORT), BIND_ADDRESS: HOST }, env));
  const server = new GhostingServer({ config, log: quiet() });
  await server.start();
  return server;
};

// A minimal client: send a datagram, collect whatever comes back.
const makeClient = () =>
  new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const received = [];
    socket.on("message", (buffer) => received.push(Buffer.from(buffer)));
    socket.once("error", reject);
    socket.bind(0, HOST, () => resolve({ socket, received, port: socket.address().port }));
  });

const send = (client, buffer) =>
  new Promise((resolve, reject) => {
    client.socket.send(buffer, PORT, HOST, (error) => (error ? reject(error) : resolve()));
  });

const settle = (ms = 120) => new Promise((resolve) => setTimeout(resolve, ms));

test("the server binds, answers a connect and shuts down cleanly", async () => {
  const server = await startServer();
  const client = await makeClient();

  await send(client, h.connect("Alice"));
  await settle();

  assert.strictEqual(server.users.exists("Alice"), true);
  assert.strictEqual(client.received.length >= 1, true, "the client got no accept");
  assert.strictEqual(client.received[0].readUInt8(0), packets.TYPE.CONNECT_ACCEPTED);

  const stopped = await server.stop("Server is shutting down.");
  assert.strictEqual(stopped, true);
  await settle();

  // Players are told before the socket goes away, so a client tears down at
  // once instead of sitting through its ten second timeout.
  const kicks = client.received.filter((b) => b.readUInt8(0) === packets.TYPE.KICK);
  assert.strictEqual(kicks.length, 1);
  assert.match(kicks[0].toString("latin1"), /shutting down/);

  client.socket.close();
});

test("the port is free immediately after a shutdown", async () => {
  const first = await startServer();
  await first.stop();
  await settle();

  // The old server left three intervals running and never called close() on a
  // clean exit, so a restart could race with the previous process for the port.
  const second = await startServer();
  const client = await makeClient();
  await send(client, h.connect("Bob"));
  await settle();

  assert.strictEqual(second.users.exists("Bob"), true, "the restarted server is not accepting connects");

  await second.stop();
  client.socket.close();
});

test("binding a port that is already taken fails instead of half starting", async () => {
  const first = await startServer();

  const config = load({ PORT: String(PORT), BIND_ADDRESS: HOST });
  const second = new GhostingServer({ config, log: quiet() });
  await assert.rejects(() => second.start(), (error) => error.code === "EADDRINUSE");

  // The failed instance must not have installed timers or claimed to be running.
  assert.strictEqual(second.running, false);
  assert.strictEqual(second.timers.length, 0);

  await first.stop();
});

test("a second stop is a no-op rather than a second teardown", async () => {
  const server = await startServer();
  assert.strictEqual(await server.stop(), true);
  assert.strictEqual(await server.stop(), false);
});

test("all timers are cleared on shutdown", async () => {
  const server = await startServer();
  assert.strictEqual(server.timers.length, 3, "sweep, tick and heartbeat");
  await server.stop();
  assert.strictEqual(server.timers.length, 0);
});

test("a full session over real sockets: connect, update, chat, disconnect", async () => {
  const server = await startServer();
  const alice = await makeClient();
  const bob = await makeClient();

  await send(alice, h.connect("Alice"));
  await send(bob, h.connect("Bob"));
  await settle();

  await send(alice, h.update("Alice", { position: [1, 2, 3] }));
  await send(bob, h.update("Bob", { position: [4, 5, 6] }));
  await settle();

  assert.strictEqual(server.users.get("Alice").position.z, 3);
  assert.strictEqual(server.users.get("Bob").position.x, 4);

  await send(alice, h.chat("Alice", "hello"));
  await settle();
  const chats = bob.received.filter((b) => b.readUInt8(0) === packets.TYPE.CHAT);
  assert.strictEqual(chats.length, 1);
  assert.match(chats[0].toString("latin1"), /hello/);

  await send(alice, h.disconnect("Alice"));
  await settle(2600);
  assert.strictEqual(server.users.exists("Alice"), false);
  assert.strictEqual(server.users.exists("Bob"), true);

  await server.stop();
  alice.socket.close();
  bob.socket.close();
});

test("garbage on the wire does not stop the server serving real clients", async () => {
  const server = await startServer();
  const attacker = await makeClient();
  const player = await makeClient();

  // Everything the fuzzers found interesting, over a real socket.
  const garbage = [
    Buffer.alloc(0),
    Buffer.from([0]),
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0xff, 0xff, 0xff, 0xff]),
    Buffer.alloc(600, 0x41),
    Buffer.alloc(1500, 0),
  ];
  for (const buffer of garbage) await send(attacker, buffer);
  await settle();

  await send(player, h.connect("Survivor"));
  await settle();
  assert.strictEqual(server.users.exists("Survivor"), true, "the server stopped answering after garbage");

  await server.stop();
  attacker.socket.close();
  player.socket.close();
});

test("no unhandled error or rejection escapes during a full lifecycle", async () => {
  const seen = [];
  const onError = (error) => seen.push(error);
  process.on("uncaughtException", onError);
  process.on("unhandledRejection", onError);

  try {
    const server = await startServer();
    const client = await makeClient();

    await send(client, h.connect("Alice"));
    await settle();
    // Send to a port nothing is listening on: on Windows this comes back as
    // ICMP port unreachable, which dgram surfaces as a send error. Without a
    // send callback it would be raised on the socket itself, and this server
    // treats a socket error as fatal.
    server.send(packets.heartbeat(), { address: HOST, port: 1 });
    await settle();

    await server.stop("Server is shutting down.");
    await settle();
    client.socket.close();
  } finally {
    process.removeListener("uncaughtException", onError);
    process.removeListener("unhandledRejection", onError);
  }

  assert.deepStrictEqual(seen, []);
});
