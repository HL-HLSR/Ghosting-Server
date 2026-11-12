"use strict";

// I6 (review 1): the old guard in firewall-apply.sh grepped for "dport 22", which
// matched the shipped COMMENT and also "tcp dport 22 drop", and knew nothing of
// sshd on another port. It now strips comments, requires a real accept rule for
// every port sshd listens on, refuses "flush ruleset" (which wiped ufw/Docker/
// fail2ban tables), refuses an unrendered template, and requires the game port.
// Driven through the script's --check mode, so the shell code itself is tested.
// Skipped where no bash is available.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const hasBash = (() => {
  try {
    const r = spawnSync("bash", ["-c", "echo ok"], { cwd: ROOT, encoding: "utf8" });
    return r.status === 0 && r.stdout.trim() === "ok";
  } catch (error) {
    return false;
  }
})();

// Temporary files live inside the repo and are passed as relative paths, so the
// same test works with Git Bash and with WSL's bash.
const TMP = `.tmp-fw-${process.pid}`;
const write = (name, text) => {
  fs.mkdirSync(path.join(ROOT, TMP), { recursive: true });
  fs.writeFileSync(path.join(ROOT, TMP, name), text);
  return `${TMP}/${name}`;
};

const template = fs.readFileSync(path.join(ROOT, "deploy", "nftables-ghserver.conf"), "utf8");
const render = (game, ssh) => template.replace(/@GAME_PORT@/g, String(game)).replace(/@SSH_PORTS@/g, ssh);

const check = (file, { ssh = "22", envPort } = {}) => {
  const env = Object.assign({}, process.env, { SSH_PORTS: ssh });
  env.GHS_ENV_FILE = envPort ? write(`env-${envPort}`, `PORT=${envPort}\n`) : `${TMP}/no-such-env`;
  const r = spawnSync("bash", ["deploy/firewall-apply.sh", "--check", file], { cwd: ROOT, env, encoding: "utf8" });
  return { ok: r.status === 0, out: `${r.stdout}${r.stderr}` };
};

test.after(() => fs.rmSync(path.join(ROOT, TMP), { recursive: true, force: true }));

test("I6: every deploy shell script parses", { skip: !hasBash && "no bash" }, () => {
  for (const name of fs.readdirSync(path.join(ROOT, "deploy"))) {
    if (!name.endsWith(".sh") && name !== "ghserver-console") continue;
    const r = spawnSync("bash", ["-n", `deploy/${name}`], { cwd: ROOT, encoding: "utf8" });
    assert.strictEqual(r.status, 0, `${name}: ${r.stderr}`);
  }
});

test("I6: the rendered shipped ruleset passes", { skip: !hasBash && "no bash" }, () => {
  const r = check(write("ok.conf", render(22228, "22")));
  assert.ok(r.ok, r.out);
});

test("I6: an SSH rule that drops, or only a comment mentioning port 22, is refused", { skip: !hasBash && "no bash" }, () => {
  // Anchored to the rule line ("    tcp dport"): the template's comment carries
  // the same words and must not be what the test edits.
  const RULE = "\n    tcp dport { 22 } accept\n";
  const drop = render(22228, "22").replace(RULE, "\n    tcp dport { 22 } drop\n");
  const r1 = check(write("drop.conf", drop));
  assert.strictEqual(r1.ok, false, "tcp dport 22 drop passed the guard");
  assert.match(r1.out, /no 'tcp dport 22 accept' rule/, r1.out);
  const removed = render(22228, "22").replace("    tcp dport { 22 } accept\n", "");
  assert.ok(/dport \{ 22 \}/.test(removed), "the comment still mentions the port");
  const r2 = check(write("nossh.conf", removed));
  assert.strictEqual(r2.ok, false, "a ruleset with only a comment passed");
  assert.match(r2.out, /no 'tcp dport 22 accept' rule/, r2.out);
});

test("I6: sshd on another port must be opened too", { skip: !hasBash && "no bash" }, () => {
  const r1 = check(write("only22.conf", render(22228, "22")), { ssh: "22 2222" });
  assert.strictEqual(r1.ok, false, "port 2222 was not required");
  assert.match(r1.out, /2222/);
  const r2 = check(write("both.conf", render(22228, "22, 2222")), { ssh: "22 2222" });
  assert.ok(r2.ok, r2.out);
});

test("I6: flush ruleset, an unrendered template and a wrong game port are refused", { skip: !hasBash && "no bash" }, () => {
  // Review 2 (m8b): these also failed against a script with no --check mode at
  // all, so each refusal is now pinned to its reason.
  const flush = check(write("flush.conf", `flush ruleset\n${render(22228, "22")}`));
  assert.strictEqual(flush.ok, false);
  assert.match(flush.out, /flushes the whole ruleset/, flush.out);
  const raw = check("deploy/nftables-ghserver.conf");
  assert.strictEqual(raw.ok, false, "the raw template passed");
  assert.match(raw.out, /unrendered @PLACEHOLDERS@/, raw.out);
  const r = check(write("port.conf", render(22228, "22")), { envPort: 23000 });
  assert.strictEqual(r.ok, false, "a ruleset for the wrong game port passed");
  assert.match(r.out, /no 'udp dport 23000 accept' rule for the game port/, r.out);
});

test("I6: the reviewer's lock-out rulesets are refused", { skip: !hasBash && "no bash" }, () => {
  // Built from the old shipped file the way review 1 did: the SSH rule turned to
  // drop, and the SSH rule deleted (only the comment left).
  const old = render(22228, "22")
    .replace("table inet ghserver\ndelete table inet ghserver\n", "")
    .replace("\n    tcp dport { 22 } accept\n", "\n    tcp dport 22 accept\n");
  for (const [name, text] of [
    ["rev1.conf", old.replace("tcp dport 22 accept", "tcp dport 22 drop")],
    ["rev2.conf", old.replace("    tcp dport 22 accept\n", "")],
  ]) {
    const r = check(write(name, text));
    assert.strictEqual(r.ok, false, `${name} passed`);
    assert.match(r.out, /no 'tcp dport 22 accept' rule - sshd listens on 22 and would be locked out/, r.out);
  }
});

// --- N4 (review 2): confirm persists only what was applied ------------------
//
// The apply / confirm / rollback paths need root, nft and systemd. They are
// driven here with stubs on PATH (nft, systemd-run, systemctl, logger, id) and
// the script's GHS_* state paths pointed into a temp directory, so the shell
// logic itself is exercised; the real thing is smoke-tested on the VDS.

const STUBS = {
  nft: `#!/usr/bin/env bash
echo "nft $*" >> "$STUB_DIR/log"
if [ "$1" = "-c" ]; then exit 0; fi
if [ "$1" = "-f" ]; then
  if [ -f "$GHS_FW_PENDING" ]; then echo "pending-at-load=yes" >> "$STUB_DIR/log"; else echo "pending-at-load=no" >> "$STUB_DIR/log"; fi
  if grep -q NFT_STUB_FAIL "$2"; then echo "nft: stub failure" >&2; exit 1; fi
  cp "$2" "$STUB_DIR/live.conf"; exit 0
fi
if [ "$1" = "list" ]; then
  if [ -f "$STUB_DIR/list-error" ]; then echo "Error: Operation not permitted" >&2; exit 1; fi
  if [ -f "$STUB_DIR/live.conf" ]; then exit 0; fi
  echo "Error: No such file or directory; did you mean table 'ghserver' in family ip?" >&2; exit 1
fi
if [ "$1" = "delete" ]; then
  if [ -f "$STUB_DIR/delete-fails" ]; then echo "nft: delete failed" >&2; exit 1; fi
  rm -f "$STUB_DIR/live.conf"; exit 0
fi
exit 0
`,
  "systemd-run": `#!/usr/bin/env bash
echo "systemd-run $*" >> "$STUB_DIR/log"
touch "$STUB_DIR/timer"
`,
  systemctl: `#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_DIR/log"
case "$1" in
  is-active) [ -f "$STUB_DIR/timer" ] ;;
  stop) rm -f "$STUB_DIR/timer" ;;
  *) exit 0 ;;
esac
`,
  logger: `#!/usr/bin/env bash
echo "logger $*" >> "$STUB_DIR/log"
`,
  id: `#!/usr/bin/env bash
if [ "$1" = "-u" ]; then echo 0; else echo "uid=0(root)"; fi
`,
};

let rigs = 0;
const fwRig = () => {
  const dir = `${TMP}/fw${rigs++}`;
  fs.mkdirSync(path.join(ROOT, dir, "bin"), { recursive: true });
  for (const [name, body] of Object.entries(STUBS)) {
    const file = path.join(ROOT, dir, "bin", name);
    fs.writeFileSync(file, body);
    fs.chmodSync(file, 0o755);
  }
  const ruleset = `${dir}/nftables-ghserver.conf`;
  fs.writeFileSync(path.join(ROOT, ruleset), render(22228, "22"));
  const session = `${dir}/sessionid`;
  const run = (args, sessionId) => {
    fs.writeFileSync(path.join(ROOT, session), `${sessionId}\n`);
    const env = Object.assign({}, process.env, {
      SSH_PORTS: "22",
      GHS_ENV_FILE: `${dir}/no-such-env`,
      GHS_FW_STATE_DIR: `${dir}/state`,
      GHS_FW_PENDING: `${dir}/pending`,
      GHS_NFT_MAIN_CONF: `${dir}/nftables.conf`,
      GHS_FW_SESSION_FILE: session,
      STUB_DIR: dir,
      STUBS_BIN: `${dir}/bin`,
    });
    const r = spawnSync("bash", ["-c", 'PATH="$STUBS_BIN:$PATH"; exec bash deploy/firewall-apply.sh "$@"', "fw", ...args],
      { cwd: ROOT, env, encoding: "utf8" });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  };
  const read = (name) => {
    try { return fs.readFileSync(path.join(ROOT, dir, name), "utf8"); } catch (error) { return null; }
  };
  const edit = (text) => fs.writeFileSync(path.join(ROOT, ruleset), text);
  return { dir, ruleset, run, read, edit };
};

test("N4: confirm persists the ruleset that was applied, never a later edit of the file", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  const applied = render(22228, "22");
  const a = fw.run([fw.ruleset], 1);
  assert.strictEqual(a.status, 0, a.out);
  assert.strictEqual(fw.read("live.conf"), applied, "the live rules are not the file as it was at apply");

  // In the new session (as instructed) the admin edits the file, then confirms.
  fw.edit(applied.replace("tcp dport { 22 } accept", "tcp dport { 22 } ip saddr 192.0.2.1 accept"));
  const c = fw.run(["--confirm"], 2);
  assert.notStrictEqual(c.status, 0, "an edited, never-loaded file was confirmed");
  assert.match(c.out, /changed since it was applied/, c.out);
  assert.strictEqual(fw.read("state/applied.conf"), null, "the edited file became the boot ruleset");

  // Putting the file back as it was lets the applied copy be confirmed.
  fw.edit(applied);
  const ok = fw.run(["--confirm"], 2);
  assert.strictEqual(ok.status, 0, ok.out);
  assert.strictEqual(fw.read("state/applied.conf"), applied, "the boot ruleset is not what was applied");
  assert.match(fw.read("nftables.conf"), /include ".*state\/applied\.conf"/);
});

test("N4: the copy taken at apply is what is checked and loaded", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  const a = fw.run([fw.ruleset], 1);
  assert.strictEqual(a.status, 0, a.out);
  const log = fw.read("log");
  assert.match(log, /nft -c -f .*state\/pending\.conf/, log);
  assert.match(log, /nft -f .*state\/pending\.conf/, log);
  assert.doesNotMatch(log, /nft -f .*nftables-ghserver\.conf/, "the editable file itself was loaded");
});

test("N4: a rollback whose restore fails removes the unconfirmed table and says so", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  // A confirmed ruleset that nft can no longer load (a kernel without a feature
  // it uses, say): it becomes the rollback target of the next apply.
  fs.mkdirSync(path.join(ROOT, fw.dir, "state"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, fw.dir, "state", "applied.conf"), "# NFT_STUB_FAIL\n");
  const a = fw.run([fw.ruleset], 1);
  assert.strictEqual(a.status, 0, a.out);
  assert.ok(fw.read("live.conf"), "precondition: the new table is live");

  const r = fw.run(["--rollback-from-timer"], 1);
  assert.strictEqual(fw.read("live.conf"), null, "the unconfirmed table was left live after a failed restore");
  const log = fw.read("log");
  assert.match(log, /nft delete table inet ghserver/, log);
  assert.match(log, /logger .*restor/i, log);
  assert.match(r.out, /removed the ghserver table/i, r.out);
});

// --- m5 (review 2): an old shipped ruleset left in /etc is re-rendered ------
//
// The 13aa81f installer always installed a ruleset with "flush ruleset" and a
// plain "inet filter" table; the new installer used to keep any existing file,
// which firewall-apply.sh then refused with no hint. It now recognises that
// file (ghs_firewall_is_old_shipped), moves it to .bak and renders the template.

const isOld = (file) =>
  spawnSync("bash", ["-c", '. deploy/lib-ghserver.sh; ghs_firewall_is_old_shipped "$1"', "x", file], { cwd: ROOT, encoding: "utf8" }).status === 0;

test("m5: the old shipped ruleset is recognised; a rendered or customised new one is kept", { skip: !hasBash && "no bash" }, () => {
  const old13 = spawnSync("git", ["show", "13aa81f:deploy/nftables-ghserver.conf"], { cwd: ROOT, encoding: "utf8" });
  const oldText = old13.status === 0 ? old13.stdout
    : "flush ruleset\ntable inet filter {\n  chain input { type filter hook input priority filter; policy drop; tcp dport 22 accept }\n}\n";
  assert.strictEqual(isOld(write("old.conf", oldText)), true, "the 13aa81f file was not recognised");
  assert.strictEqual(isOld(write("new.conf", render(22228, "22"))), false, "a rendered new ruleset would be replaced");
  const custom = render(22228, "22").replace("tcp dport { 22 } accept", "tcp dport { 22 } ip saddr 192.0.2.0/24 accept");
  assert.strictEqual(isOld(write("custom.conf", `# not flush ruleset, says the admin\n${custom}`)), false,
    "an admin's edited new ruleset (flush only in a comment) would be replaced");
  assert.strictEqual(isOld(write("foreign.conf", "table inet filter {\n}\n")), true, "a file without the ghserver table is not ours");
});

test("m5: the installer moves an old shipped ruleset aside and re-renders it", () => {
  const body = fs.readFileSync(path.join(ROOT, "deploy", "install-ubuntu.sh"), "utf8");
  const fn = body.slice(body.indexOf("install_firewall_file() {"), body.indexOf("\n}\n", body.indexOf("install_firewall_file() {")));
  assert.match(fn, /ghs_firewall_is_old_shipped "\$out"/);
  assert.match(fn, /mv -f "\$out" "\$\{out\}\.bak/);
  assert.match(fn, /log "/);
});

// --- R9 (review 3): firewall nits -------------------------------------------

test("R9: --rollback with nothing pending says so and changes nothing (live stays the boot ruleset)", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  const a = fw.run([fw.ruleset], 1);
  assert.strictEqual(a.status, 0, a.out);
  const c = fw.run(["--confirm"], 2);
  assert.strictEqual(c.status, 0, c.out);
  const liveBefore = fw.read("live.conf");
  const logBefore = fw.read("log");
  const r = fw.run(["--rollback"], 3);
  assert.match(r.out, /nothing to roll back/i, r.out);
  assert.strictEqual(fw.read("live.conf"), liveBefore, "the live rules changed");
  assert.strictEqual(fw.read("state/applied.conf"), liveBefore, "the boot rules changed");
  assert.doesNotMatch(fw.read("log").slice(logBefore.length), /nft -f|nft delete/, "nft was asked to change something");
});

test("R9: the rollback only says it removed the table when the delete succeeded", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  const a = fw.run([fw.ruleset], 1); // nothing confirmed before: rollback deletes the table
  assert.strictEqual(a.status, 0, a.out);
  fs.writeFileSync(path.join(ROOT, fw.dir, "delete-fails"), "");
  const r = fw.run(["--rollback"], 1);
  assert.doesNotMatch(r.out, /^Removed the ghserver table/m, r.out);
  assert.match(r.out, /could not remove/i, r.out);
  assert.notStrictEqual(r.status, 0, "a rollback that left the rules live reported success");
});

// --- M4 (review 4): the pending record exists before the rules are live -----

test("M4: apply writes the pending record BEFORE nft loads the rules", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  const a = fw.run([fw.ruleset], 1);
  assert.strictEqual(a.status, 0, a.out);
  assert.match(fw.read("log"), /pending-at-load=yes/, "nft -f ran before the pending record existed");
  assert.ok(fw.read("pending"), "no pending record after a successful apply");
});

test("M4: a load nft refuses leaves nothing pending, no timer, and says nothing was changed", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  fw.edit(`${render(22228, "22")}\n# NFT_STUB_FAIL\n`);
  const a = fw.run([fw.ruleset], 1);
  assert.notStrictEqual(a.status, 0, "a refused load reported success");
  assert.strictEqual(fw.read("live.conf"), null, "rules went live");
  assert.strictEqual(fw.read("pending"), null, "a pending record was left for a change that never loaded");
  assert.strictEqual(fw.read("timer"), null, "the rollback timer was left running");
  assert.match(a.out, /nothing was changed/i, a.out);
});

test("M4 nit: a failing 'nft list' is not taken to mean the table is gone", { skip: !hasBash && "no bash" }, () => {
  const fw = fwRig();
  const a = fw.run([fw.ruleset], 1); // nothing confirmed before: a rollback removes the table
  assert.strictEqual(a.status, 0, a.out);
  fs.writeFileSync(path.join(ROOT, fw.dir, "list-error"), "");
  const r = fw.run(["--rollback"], 1);
  assert.notStrictEqual(r.status, 0, r.out);
  assert.doesNotMatch(r.out, /^Removed the ghserver table/m, r.out);
  assert.ok(fw.read("live.conf"), "precondition: the stub still has the table");
});
