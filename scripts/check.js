#!/usr/bin/env node
"use strict";

// Parse check over every JavaScript file in the project.
//
// `node --check` catches a syntax error before it reaches a running host, which
// matters here because the entry point is a long-lived process an operator
// starts from a unit file: a typo would otherwise surface as a restart loop.
//
// legacy/index.js is included: it is the frozen "before" copy the compatibility
// tests execute, so it has to stay parseable.

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const SKIP = new Set(["node_modules", ".git"]);

const collect = (dir, out = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collect(full, out);
    else if (entry.name.endsWith(".js")) out.push(full);
  }
  return out;
};

const files = collect(ROOT).sort();
let failed = 0;

for (const file of files) {
  const relative = path.relative(ROOT, file).replace(/\\/g, "/");
  try {
    execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
    console.log(`ok    ${relative}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  ${relative}`);
    console.error(String(error.stderr || error.message).trim());
  }
}

// The legacy copy is the reference the wire tests compare against. If it moves,
// those tests are comparing against something other than what shipped.
const LEGACY = path.join(ROOT, "legacy", "index.js");
const EXPECTED = "95fbdd03f3c6871dea79575c4c7f1c5948cbde127d0373cae7033a59b2c84a0e";
if (fs.existsSync(LEGACY)) {
  const digest = crypto.createHash("sha256").update(fs.readFileSync(LEGACY)).digest("hex");
  if (digest === EXPECTED) {
    console.log("ok    legacy/index.js is unchanged");
  } else {
    failed += 1;
    console.error(`FAIL  legacy/index.js changed (sha256 ${digest})`);
  }
} else {
  failed += 1;
  console.error("FAIL  legacy/index.js is missing");
}

console.log(`\n${files.length} files checked, ${failed} problem(s)`);
process.exit(failed ? 1 : 0);
