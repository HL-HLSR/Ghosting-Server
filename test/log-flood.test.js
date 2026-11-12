"use strict";

// M4: two per-packet log lines were not sampled, so one session could fill the
// log (and, under journald, push out genuine lines). A 'd' every 10 ms wrote
// one info line each - about 120 a second - and every completed publication
// wrote one too. Both are now sampled events and the 'd' path is charged to the
// events budget.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const { SampledLogger } = require("../src/net/logger");

const ALICE = h.from("10.0.0.1", 40001);

test("a thousand disconnect packets produce at most a few log lines", () => {
  const printed = [];
  const { server, clock } = h.makeServer();
  server.log = new SampledLogger({ sink: (line) => printed.push(line), now: () => clock.now(), intervalMs: 10000 });
  server.onDatagram(h.connect("Alice"), ALICE);
  server.onDatagram(h.update("Alice"), ALICE);

  const mark = printed.length;
  for (let t = 0; t < 10000; t += 10) {
    server.onDatagram(h.disconnect("Alice"), ALICE);
    if (t % 1000 === 0) server.onDatagram(h.update("Alice", { position: [t, 0, 0] }), ALICE);
    clock.advance(10);
  }

  const lines = printed.slice(mark).filter((l) => /disconnect-requested/.test(l));
  assert.ok(lines.length <= 3, `${lines.length} disconnect log lines in 10 s`);
  assert.ok(server.users.get("Alice"), "the keepalive updates kept Alice connected");
});

test("a flood of one-chunk publications produces at most a few log lines", () => {
  const printed = [];
  const { server, clock } = h.makeServer({ SPRAY_UPLOAD_BURST: "4000", SPRAY_UPLOAD_RATE_PER_SECOND: "1000" });
  server.log = new SampledLogger({ sink: (line) => printed.push(line), now: () => clock.now(), intervalMs: 10000 });
  server.onDatagram(h.connect("Alice"), ALICE);
  server.onDatagram(h.update("Alice"), ALICE);

  const mark = printed.length;
  // 400 distinct valid one-chunk pictures in 10 s, each with its own crc.
  for (let i = 0; i < 400; i++) {
    const { blob, crc } = h.sprayBlob(8, (i % 200) + 1);
    h.uploadSpray(server, ALICE, "Alice", crc, blob);
    clock.advance(25);
  }

  const published = printed.slice(mark).filter((l) => /spray-published/.test(l));
  assert.ok(published.length <= 3, `${published.length} spray-published log lines in 10 s`);
});
