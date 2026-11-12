#!/usr/bin/env node
"use strict";

// Builds a deployable release tarball and prints its SHA-256.
//
// What ships: the entry point, src/, package.json, the docs and deploy/. What
// does NOT ship is the development surface the audit flagged (L8): legacy/ (the
// unprotected old single-file server, pinned only for the byte-compatibility
// tests), test/ and scripts/. The systemd unit runs node /opt/ghserver/index.js,
// which needs only index.js and src/, so none of the excluded trees are used at
// runtime - leaving them out keeps the old server off the box entirely.
//
// Uses the system `tar` (present on the Ubuntu build host and in Git Bash on
// Windows). It is a build-time dev tool, never run by the service.

const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const DIST = path.join(ROOT, "dist");

const INCLUDE = ["index.js", "src", "package.json", "README.md", "CHANGELOG.md", "deploy"];

const main = () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const version = pkg.version;

  for (const entry of INCLUDE) {
    if (!fs.existsSync(path.join(ROOT, entry))) {
      console.error(`missing ${entry}: refusing to build an incomplete release`);
      process.exit(1);
    }
  }

  fs.mkdirSync(DIST, { recursive: true });
  const name = `ghserver-${version}.tar.gz`;
  const out = path.join(DIST, name);

  // --sort=name + a fixed mtime/owner make the tarball reproducible, so the
  // SHA-256 printed below is the same for the same source on any build host.
  const args = [
    "--create",
    "--gzip",
    // A Windows build path contains a drive-letter colon, which GNU tar would
    // otherwise read as a remote host; harmless on Linux.
    "--force-local",
    `--file=${out}`,
    "--sort=name",
    "--mtime=@0",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "--mode=go-w",
    "-C",
    ROOT,
  ].concat(INCLUDE);

  try {
    execFileSync("tar", args, { stdio: ["ignore", "ignore", "inherit"] });
  } catch (error) {
    console.error("tar failed. Install GNU tar (it ships on Ubuntu and in Git Bash).");
    process.exit(1);
  }

  const bytes = fs.readFileSync(out);
  const sha = crypto.createHash("sha256").update(bytes).digest("hex");
  fs.writeFileSync(`${out}.sha256`, `${sha}  ${name}\n`);

  console.log(`release:   ${out}`);
  console.log(`size:      ${(bytes.length / 1024).toFixed(1)} KiB`);
  console.log(`sha256:    ${sha}`);
  console.log(`excluded:  legacy/ test/ scripts/ (dev only)`);
};

main();
