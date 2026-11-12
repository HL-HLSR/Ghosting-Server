#!/usr/bin/env node
"use strict";

// Collects test files and hands them to node --test as an explicit list.
//
// `node --test <dir>` behaves differently across Node versions and does not
// expand a glob on Windows, where npm runs scripts through cmd. An explicit
// list works the same everywhere, and it keeps test/tools (the fuzz and load
// harnesses, which are not tests) out of the run.

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const TEST_DIR = path.join(ROOT, "test");

const files = fs
  .readdirSync(TEST_DIR)
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => path.join("test", name));

if (files.length === 0) {
  console.error("no test files found in test/");
  process.exit(1);
}

// A per-test timeout so a test that leaves a socket or an interval behind
// fails loudly instead of hanging the run.
const args = ["--test", "--test-timeout=30000"].concat(process.argv.slice(2)).concat(files);
try {
  execFileSync(process.execPath, args, { cwd: ROOT, stdio: "inherit" });
} catch (error) {
  process.exit(error.status === undefined ? 1 : error.status);
}
