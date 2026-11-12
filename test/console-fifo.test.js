"use strict";

// Review 1, minor 6: with Requires= + StandardInput=socket the game server could
// not start without the console socket unit, stopping or restarting the socket
// stopped or bounced the server, and any write to the FIFO started a stopped
// server. The server now opens the FIFO itself (CONSOLE_FIFO), O_RDWR so it never
// sees EOF, and runs without a console when it is absent; the unit has no socket
// dependency and gains ExecReload.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const { openConsoleInput } = require("../index");

const ROOT = path.join(__dirname, "..");
const unit = fs.readFileSync(path.join(ROOT, "deploy", "ghserver.service"), "utf8");
const live = (text) => text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");

test("minor 6: a missing console FIFO is reported, not fatal", () => {
  const warnings = [];
  const input = openConsoleInput(path.join(ROOT, "no-such-dir", "console"), { warn: (...a) => warnings.push(a) });
  assert.strictEqual(input, null);
  assert.strictEqual(warnings.length, 1, "the operator should be told the console is unavailable");
});

test("minor 6: without CONSOLE_FIFO the console reads stdin (development)", () => {
  assert.strictEqual(openConsoleInput(undefined, { warn() {} }), process.stdin);
});

test("minor 6: the unit does not depend on a console socket and supports reload", () => {
  const body = live(unit);
  assert.doesNotMatch(body, /Requires=ghserver-console\.socket/);
  assert.doesNotMatch(body, /^Sockets=/m);
  assert.doesNotMatch(body, /StandardInput=socket/);
  assert.match(body, /^StandardInput=null$/m);
  assert.match(body, /^Environment=CONSOLE_FIFO=\/run\/ghserver\/console$/m);
  assert.match(body, /^RuntimeDirectory=ghserver$/m);
  // The FIFO is created as root before start, and a failure (say the ghsadmin
  // group is missing) must not stop the server from starting.
  assert.match(body, /^ExecStartPre=-\+/m);
  assert.match(body, /^ExecReload=\/bin\/kill -HUP \$MAINPID$/m);
  assert.strictEqual(fs.existsSync(path.join(ROOT, "deploy", "ghserver-console.socket")), false,
    "the socket unit (which activated the server on a write) should be gone");
});

// --- m9 (review 2): the FIFO's ExecStartPre --------------------------------

const execStartPre = () => {
  const line = live(unit).split("\n").find((l) => l.startsWith("ExecStartPre=-+/bin/sh -c '"));
  assert.ok(line, "no ExecStartPre=-+/bin/sh -c '...' line");
  return line.slice("ExecStartPre=-+/bin/sh -c '".length, -1);
};

test("m9: the FIFO is never chown'ed through a symlink, and owner and group are set in one -h call", () => {
  const script = execStartPre();
  assert.doesNotMatch(script, /chown (?!-h)/, script);
  assert.doesNotMatch(script, /chgrp (?!-h)/, script);
  assert.match(script, /chown -h ghserver:ghsadmin /, script);
});

const { spawnSync } = require("node:child_process");
const hasBash = (() => {
  try { return spawnSync("bash", ["-c", "echo ok"], { encoding: "utf8" }).stdout.trim() === "ok"; } catch (e) { return false; }
})();

test("m9: with the ghsadmin group missing there is no FIFO left behind (not even group root) and the journal is told", { skip: !hasBash && "no bash" }, () => {
  const dir = `.tmp-fifo-${process.pid}`;
  fs.mkdirSync(path.join(ROOT, dir, "bin"), { recursive: true });
  try {
    // getent finds no such group.
    fs.writeFileSync(path.join(ROOT, dir, "bin", "getent"), "#!/usr/bin/env bash\nexit 2\n");
    fs.chmodSync(path.join(ROOT, dir, "bin", "getent"), 0o755);
    const fifo = `${dir}/console`;
    fs.writeFileSync(path.join(ROOT, fifo), "stale"); // a leftover from an earlier start
    const script = execStartPre().split("/run/ghserver/console").join(fifo);
    const r = spawnSync("bash", ["-c", 'PATH="$STUBS:$PATH"; exec sh -c "$1"', "x", script],
      { cwd: ROOT, env: Object.assign({}, process.env, { STUBS: `${dir}/bin` }), encoding: "utf8" });
    assert.strictEqual(fs.existsSync(path.join(ROOT, fifo)), false, "a console FIFO (or the stale file) was left in place");
    assert.match(r.stderr, /ghsadmin/, `nothing said why: ${r.stderr}`);
    assert.match(r.stderr, /without a console/, r.stderr);
  } finally {
    fs.rmSync(path.join(ROOT, dir), { recursive: true, force: true });
  }
});
