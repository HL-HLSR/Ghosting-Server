"use strict";

// Defensive protocol probe. FakeSocket only; sends no real network packets.
const assert = require("node:assert/strict");
const h = require("../helpers/harness");
const { server, clock } = h.makeServer();
const claimedEndpoint = h.from("192.0.2.17", 40001);
server.onDatagram(h.connect("ClaimedEndpoint"), claimedEndpoint);
assert.equal(server.users.get("ClaimedEndpoint").confirmed, false);
clock.advance(100);
// The simulated sender never reads an accept, token or challenge response.
server.onDatagram(h.update("ClaimedEndpoint"), claimedEndpoint);
assert.equal(server.users.get("ClaimedEndpoint").confirmed, true);
console.log(JSON.stringify({
  transport: "FakeSocket (no network)",
  readServerResponse: false,
  suppliedSessionToken: false,
  confirmedAfterConnectAndUpdate: true,
  conclusion: "Legacy confirmed is activity, not proof of return routability; nonce handshake required.",
}, null, 2));
