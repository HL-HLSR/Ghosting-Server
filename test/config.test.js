"use strict";

// Environment validation.
//
// Every case here is one the old server got wrong silently. A public host is
// started from a unit file nobody reads twice, so "quietly ran with something
// else" is the failure mode worth testing.

const test = require("node:test");
const assert = require("node:assert");

const { load, ConfigError } = require("../src/config");

test("an empty environment gives the values the host has been running with", () => {
  const config = load({});
  assert.strictEqual(config.port, 22228);
  assert.strictEqual(config.maxPlayers, 16);
  assert.strictEqual(config.debug, false);
  assert.strictEqual(config.staleTimeoutMs, 60000);
  assert.strictEqual(config.takeoverAfterMs, 10000);
  assert.strictEqual(config.chatMinIntervalMs, 600);
  assert.strictEqual(config.minLineIntervalMs, 15);
  assert.strictEqual(config.ratePerSession, 120);
  assert.strictEqual(config.ratePerAddress, 480);
  assert.strictEqual(config.raceLobbyMs, 60000);
  assert.strictEqual(config.heartbeatMs, 2000);
  assert.strictEqual(config.warnings.length, 0);
});

test("DEBUG=0 means false", () => {
  // The old check was `!!process.env.DEBUG`, so the string "0" was truthy and
  // the only way to turn debug off was to unset the variable entirely. An
  // operator who wrote DEBUG=0 got a log line for every position update.
  for (const value of ["0", "false", "no", "off", ""]) {
    assert.strictEqual(load({ DEBUG: value }).debug, false, `DEBUG=${value}`);
  }
  for (const value of ["1", "true", "yes", "on"]) {
    assert.strictEqual(load({ DEBUG: value }).debug, true, `DEBUG=${value}`);
  }
  assert.throws(() => load({ DEBUG: "maybe" }), ConfigError);
});

test("DEBUG=1 is called out as unsuitable for a public host", () => {
  const config = load({ DEBUG: "1" });
  assert.strictEqual(config.debug, true);
  assert.strictEqual(config.warnings.some((w) => /public host/.test(w)), true);
});

test("a MAX_PLAYERS that is not a whole number is refused", () => {
  // parseInt("16abc") is 16 and parseInt("1e9") is 1. Both used to be accepted.
  for (const value of ["lots", "16abc", "1e9", "16.5", " ", "-"]) {
    assert.throws(() => load({ MAX_PLAYERS: value }), ConfigError, `MAX_PLAYERS=${value}`);
  }
});

test("MAX_PLAYERS=0 and MAX_PLAYERS=-1 are refused rather than reinterpreted", () => {
  // `parseInt(...) || 16` turned 0 into 16, and -1 passed through to make
  // `count() >= -1` always true, so every connect was rejected as "full".
  assert.throws(() => load({ MAX_PLAYERS: "0" }), ConfigError);
  assert.throws(() => load({ MAX_PLAYERS: "-1" }), ConfigError);
  assert.throws(() => load({ MAX_PLAYERS: "1000000000" }), ConfigError);
});

test("more than sixteen slots is allowed but flagged as untested", () => {
  const config = load({ MAX_PLAYERS: "32" });
  assert.strictEqual(config.maxPlayers, 32);
  assert.strictEqual(config.warnings.some((w) => /load tested/.test(w)), true);
});

test("the port is configurable, as gh_online_port is on the client", () => {
  assert.strictEqual(load({ PORT: "27015" }).port, 27015);
  assert.throws(() => load({ PORT: "0" }), ConfigError);
  assert.throws(() => load({ PORT: "65536" }), ConfigError);
  assert.throws(() => load({ PORT: "http" }), ConfigError);
});

test("the listener address must be an IPv4 literal", () => {
  assert.strictEqual(load({ BIND_ADDRESS: "127.0.0.1" }).bindAddress, "127.0.0.1");
  // A hostname would mean a DNS lookup at bind time: one more thing to fail or
  // be poisoned, for no benefit.
  assert.throws(() => load({ BIND_ADDRESS: "localhost" }), ConfigError);
  assert.throws(() => load({ BIND_ADDRESS: "::1" }), ConfigError);
});

test("RACE_LOBBY_MS is bounded", () => {
  assert.strictEqual(load({ RACE_LOBBY_MS: "5000" }).raceLobbyMs, 5000);
  assert.throws(() => load({ RACE_LOBBY_MS: "0" }), ConfigError);
  assert.throws(() => load({ RACE_LOBBY_MS: "-60000" }), ConfigError);
});

test("a burst smaller than its sustained rate is refused", () => {
  // A token bucket whose capacity is below its refill rate cannot behave the
  // way the name suggests, so the mistake is caught at startup.
  assert.throws(() => load({ RATE_PER_ADDRESS: "100", BURST_PER_ADDRESS: "50" }), ConfigError);
  assert.throws(() => load({ RATE_PER_SESSION: "100", BURST_PER_SESSION: "50" }), ConfigError);
});

test("the heartbeat cannot be set slower than the client's own timeout", () => {
  // GH_CLIENT_TIMEOUT is 10 seconds (GhostOnlineEngine.cpp:28): the client
  // tears down its session after that long without hearing anything. A
  // heartbeat of 30 seconds would disconnect every player on the server and
  // look like a network fault rather than a setting, and the old range allowed
  // a whole minute.
  assert.strictEqual(load({ HEARTBEAT_MS: "4000" }).heartbeatMs, 4000);
  assert.throws(() => load({ HEARTBEAT_MS: "10000" }), ConfigError);
  assert.throws(() => load({ HEARTBEAT_MS: "30000" }), ConfigError);

  // Still allowed, but flagged: one lost datagram is then close to a drop.
  assert.strictEqual(load({ HEARTBEAT_MS: "5000" }).warnings.some((w) => /10s of silence/.test(w)), true);
});

test("the relay throttle cannot be turned into a slideshow", () => {
  assert.strictEqual(load({ MIN_LINE_INTERVAL_MS: "20" }).minLineIntervalMs, 20);
  // Клиент шлёт каждые 20 мс, поэтому порог предупреждения идёт от него
  assert.strictEqual(load({ MIN_LINE_INTERVAL_MS: "40" }).warnings.some((w) => /stutter/.test(w)), true);
  assert.strictEqual(load({ MIN_LINE_INTERVAL_MS: "100" }).warnings.some((w) => /stutter/.test(w)), true);
  assert.throws(() => load({ MIN_LINE_INTERVAL_MS: "5000" }), ConfigError);
});

test("the unconfirmed timeout cannot exceed the stale timeout", () => {
  assert.throws(() => load({ UNCONFIRMED_TIMEOUT_MS: "120000", STALE_TIMEOUT_MS: "60000" }), ConfigError);
});

test("the name limit can be lowered to work around the client HUD defect", () => {
  assert.strictEqual(load({}).maxNameLength, 31);
  assert.strictEqual(load({ NAME_MAX_LENGTH: "28" }).maxNameLength, 28);
  assert.throws(() => load({ NAME_MAX_LENGTH: "40" }), ConfigError);
});

test("the access file has a default and refuses a path that is not one", () => {
  assert.strictEqual(load({}).accessFile, "access.json");
  assert.strictEqual(load({ ACCESS_FILE: "/var/lib/ghosting/access.json" }).accessFile, "/var/lib/ghosting/access.json");
  // An empty value is a typo, exactly as it is for every other setting.
  assert.throws(() => load({ ACCESS_FILE: "" }), ConfigError);
  // A NUL ends the path at the system call, so what the operator wrote and what
  // would be opened are two different files.
  assert.throws(() => load({ ACCESS_FILE: "access\0.json" }), ConfigError);
});

test("turning off persistence is allowed and said out loud", () => {
  // Bans that quietly stop surviving a restart are worse than no bans at all,
  // so this is one of the settings that has to announce itself.
  assert.strictEqual(load({}).accessPersist, true);
  const config = load({ ACCESS_PERSIST: "0" });
  assert.strictEqual(config.accessPersist, false);
  assert.strictEqual(config.warnings.some((w) => /gone at the next restart/.test(w)), true);
  assert.throws(() => load({ ACCESS_PERSIST: "maybe" }), ConfigError);
});

test("every error message names the variable that was wrong", () => {
  for (const [key, value] of [
    ["MAX_PLAYERS", "x"],
    ["PORT", "x"],
    ["DEBUG", "x"],
    ["RACE_LOBBY_MS", "x"],
    ["STALE_TIMEOUT_MS", "x"],
    ["CONNECT_RATE_PER_MINUTE", "x"],
  ]) {
    try {
      load({ [key]: value });
      assert.fail(`${key} was accepted`);
    } catch (error) {
      assert.strictEqual(error instanceof ConfigError, true);
      assert.match(error.message, new RegExp(key));
    }
  }
});
