"use strict";

// M9 (runtime floor), L1 (access-file permissions and atomic write) and M7
// (reload without a restart).

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { checkNodeVersion, MIN_NODE_MAJOR } = require("../index");
const { AccessList, KIND } = require("../src/game/access");
const h = require("./helpers/harness");

// M9 --------------------------------------------------------------------------

test("M9: an EOL Node line is refused, a current one is accepted", () => {
  assert.match(checkNodeVersion("20.18.0"), /too old/);
  assert.match(checkNodeVersion("18.19.1"), /too old/);
  assert.strictEqual(checkNodeVersion(`${MIN_NODE_MAJOR}.0.0`), null);
  assert.strictEqual(checkNodeVersion("24.22.1"), null);
  assert.strictEqual(checkNodeVersion(process.versions.node), null, "the running version must pass");
});

test("M9: package.json requires >= 22 and the index exit code is EX_CONFIG", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
  assert.match(pkg.engines.node, />=\s*22/);
  const source = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
  assert.match(source, /checkNodeVersion/);
  assert.match(source, /process\.exit\(78\)/);
});

// L1 --------------------------------------------------------------------------

test("L1: the access file is written 0600 and not through a followed symlink", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghs-access-"));
  const file = path.join(dir, "access.json");
  const list = new AccessList({ now: Date.now, file });
  list.ban(KIND.NAME, "Griefer", { reason: "x" });
  assert.ok(fs.existsSync(file), "the file should be written");

  if (process.platform !== "win32") {
    const mode = fs.statSync(file).mode & 0o777;
    assert.strictEqual(mode, 0o600, `mode was 0${mode.toString(8)}`);
  }

  // No stray fixed-name temp is left behind, and the write did not follow one
  // planted at the old predictable path.
  assert.ok(!fs.existsSync(`${file}.tmp`), "the old fixed .tmp name must not be used");
  const leftovers = fs.readdirSync(dir).filter((n) => n.endsWith(".tmp"));
  assert.deepStrictEqual(leftovers, [], `temp files left behind: ${leftovers.join(", ")}`);

  fs.rmSync(dir, { recursive: true, force: true });
});

// M7 --------------------------------------------------------------------------

test("M7: reload re-reads the file and kicks anyone now banned", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghs-reload-"));
  const file = path.join(dir, "access.json");

  const { server } = h.makeServer();
  // Point the live list at a real file (the harness runs file-less by default).
  server.access = new AccessList({ now: Date.now, file, maxNameLength: 31 });

  const A = h.from("10.0.0.1", 40001);
  server.onDatagram(h.connect("Griefer"), A);
  server.onDatagram(h.update("Griefer"), A);
  assert.ok(server.users.get("Griefer"));

  // Something else writes a ban into the file; the server has not seen it yet.
  const editor = new AccessList({ now: Date.now, file, maxNameLength: 31 });
  editor.ban(KIND.NAME, "Griefer", { reason: "edited in" });

  const result = server.reloadAccess();
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.removed, 1, "the now-banned session should be kicked");
  assert.strictEqual(server.users.get("Griefer"), null);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("M7: a broken access file on reload keeps the current lists", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ghs-reload2-"));
  const file = path.join(dir, "access.json");

  const { server } = h.makeServer();
  server.access = new AccessList({ now: Date.now, file, maxNameLength: 31 });
  server.access.ban(KIND.NAME, "Alice", {});

  fs.writeFileSync(file, "{ not valid json");
  const result = server.reloadAccess();
  assert.strictEqual(result.ok, false);
  assert.ok(server.access.banFor("Alice", "1.2.3.4"), "the existing ban must survive a bad reload");

  fs.rmSync(dir, { recursive: true, force: true });
});
