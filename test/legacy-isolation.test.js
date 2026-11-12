"use strict";

// legacy/ is a frozen reference, not a second server.
//
// It exists so the compatibility tests can compare against the bytes the
// previous version really produced, executed rather than retyped. That is only
// worth anything if it never runs in production and never changes, so both are
// checked here rather than left to discipline.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const legacy = require("./helpers/legacy");

const ROOT = path.join(__dirname, "..");
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), "utf8");

// Collect every .js file that a production start can reach.
const productionFiles = () => {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      // deploy/ and scripts/ are build/ops tooling, not part of what a running
      // server reaches; dist/ is release output.
      if (["node_modules", ".git", "test", "legacy", "scripts", "deploy", "dist"].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) files.push(full);
    }
  };
  walk(ROOT);
  return files;
};

test("nothing on the production path mentions legacy", () => {
  for (const file of productionFiles()) {
    const source = fs.readFileSync(file, "utf8");
    const relative = path.relative(ROOT, file).replace(/\\/g, "/");
    assert.strictEqual(/require\(["'][^"']*legacy/.test(source), false, `${relative} requires legacy`);
    assert.strictEqual(/legacy\//.test(source), false, `${relative} refers to legacy/`);
  }
});

test("the entry point starts exactly one server", () => {
  const source = read("index.js");
  assert.match(source, /require\("\.\/src\/server"\)/);
  const constructions = source.match(/new GhostingServer\(/g) || [];
  assert.strictEqual(constructions.length, 1, `${constructions.length} servers constructed in index.js`);
  assert.strictEqual(/dgram/.test(source), false, "the entry point must not open a socket of its own");
});

test("the package manifest does not ship legacy", () => {
  const manifest = JSON.parse(read("package.json"));
  assert.strictEqual(manifest.main, "index.js");
  assert.strictEqual(manifest.scripts.start, "node index.js");
  const scripts = JSON.stringify(manifest.scripts);
  assert.strictEqual(/legacy/.test(scripts), false, "a script runs legacy");
  // `files` is what npm would pack. It is absent here (this is a private
  // project deployed by copying the directory), so the README has to say what
  // legacy is for instead - checked below.
  if (manifest.files) {
    assert.strictEqual(manifest.files.some((entry) => /legacy/.test(entry)), false);
  }
});

test("the README explains that legacy is a reference and a rollback, not a service", () => {
  const readme = read("README.en.md");
  assert.match(readme, /legacy\//);
  assert.match(readme, /not loaded at runtime|kept for comparison/i);
});

test("the frozen copy is byte for byte the server that was replaced", () => {
  const bytes = fs.readFileSync(path.join(ROOT, "legacy", "index.js"));
  assert.strictEqual(bytes.length, 40570);
  assert.strictEqual(
    crypto.createHash("sha256").update(bytes).digest("hex"),
    "95fbdd03f3c6871dea79575c4c7f1c5948cbde127d0373cae7033a59b2c84a0e"
  );
});

test("the checksum is enforced by the loader, not only by this test", () => {
  // A reference nobody verifies is a reference that can drift into agreeing
  // with whatever the current code does.
  const loader = read("test/helpers/legacy.js");
  assert.match(loader, /95fbdd03f3c6871dea79575c4c7f1c5948cbde127d0373cae7033a59b2c84a0e/);
  assert.match(loader, /has changed/);

  const checker = read("scripts/check.js");
  assert.match(checker, /95fbdd03f3c6871dea79575c4c7f1c5948cbde127d0373cae7033a59b2c84a0e/);
});

test("the reference runs in a sandbox with no socket, no console and no timers", () => {
  const { api } = legacy.load();
  // It loaded, which means its dgram and readline requires were satisfied by
  // stubs; anything else would have thrown from the loader's require hook.
  assert.strictEqual(typeof api.BufferWriter, "function");
  assert.strictEqual(typeof api.User, "function");

  const loader = read("test/helpers/legacy.js");
  assert.match(loader, /vm\.createContext/);
  assert.match(loader, /unexpected module/);

  // The sandbox's own timer stubs, so the legacy setIntervals cannot run.
  assert.match(loader, /setInterval: \(\) => 0/);
  assert.match(loader, /setTimeout: \(\) => 0/);
});

test("loading the reference does not bind a port", () => {
  // The legacy file ends with server.bind(22228). If that reached a real
  // socket, running the test suite would fight the production host for the
  // port - and on a machine where the host is running, the tests would fail
  // for a reason that has nothing to do with the code.
  const { api } = legacy.load();
  assert.ok(api);
  const loader = read("test/helpers/legacy.js");
  assert.match(loader, /bind\(\)\s*\{\}/);
});

test("the reference and the current server disagree about nothing on the wire", () => {
  // A short restatement of the golden test, here so that "legacy is isolated"
  // and "legacy is still the yardstick" are asserted in the same place.
  const packets = require("../src/wire/packets");
  const { api } = legacy.load();

  const old = new api.User("Bob", { address: "1.2.3.4", port: 5000 }, 12, 255, 0, 0, 10, 20, 30);
  const fresh = {
    name: "Bob",
    trailLength: 12,
    trailRed: 255,
    trailGreen: 0,
    trailBlue: 0,
    ghostRed: 10,
    ghostGreen: 20,
    ghostBlue: 30,
  };
  assert.strictEqual(
    old.createConnectBuffer(true).toString("hex"),
    packets.connect(fresh, true).toString("hex")
  );
});
