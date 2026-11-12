"use strict";

// Ghosting dedicated host. Start it with:
//
//   node index.js
//
// Everything that used to live in this file is now under src/, but the entry
// point and the command have not changed. This file does three things a module
// should not do: it reads the environment, it owns the process signals, and it
// decides the exit code.

const { load, ConfigError } = require("./src/config");
const { SampledLogger } = require("./src/net/logger");
const { GhostingServer } = require("./src/server");
const { AccessList, AccessError } = require("./src/game/access");
const { attach } = require("./src/console");
const { monotonicNow } = require("./src/clock");

// M9: the oldest Node line this parser of unauthenticated network input is
// allowed to run on. `engines` in package.json is advisory for npm only -
// `node index.js` runs on anything new enough to parse the file, and Ubuntu
// 24.04's apt ships Node 18.19 (EOL). Node 20 reached end of life 2026-04-30,
// so 22 is the floor and 24 LTS is recommended. zlib.crc32 (used by the spray
// validator) also needs >= 22.2. Returns an error string when the running
// version is too old, or null when it is fine. Exported so it can be tested
// without stubbing process.exit.
const MIN_NODE_MAJOR = 22;
const checkNodeVersion = (version) => {
  const major = Number.parseInt(String(version).split(".")[0], 10);
  if (!Number.isFinite(major)) return `could not parse the Node.js version "${version}"`;
  if (major < MIN_NODE_MAJOR) {
    return (
      `Node.js ${version} is too old: this server needs >= ${MIN_NODE_MAJOR} ` +
      "(24 LTS recommended). Install it from the NodeSource node_24.x repository " +
      "or the official tarball - NOT from Ubuntu's apt, which ships an EOL 18.x."
    );
  }
  return null;
};

// Where the operator console reads from (review 1, minor 6).
//
// Under the deploy unit the console is a FIFO the unit creates in the runtime
// directory (CONSOLE_FIFO, /run/ghserver/console), and the server opens it
// ITSELF rather than having systemd pass it as stdin from a socket unit. That
// coupling meant the game server could not start without the console unit, that
// stopping or restarting the console stopped or bounced the server, and that any
// write to the FIFO started a stopped server. Opened O_RDWR, so the read side
// never sees EOF between writers; O_NONBLOCK so the open itself cannot hang.
// A missing or unusable FIFO is reported and the server runs without a console.
// Without CONSOLE_FIFO (running by hand, tmux, development) the console is
// stdin, as before.
const openConsoleInput = (fifoPath, log) => {
  if (!fifoPath) return process.stdin;
  const fs = require("fs");
  const net = require("net");
  let fd;
  try {
    fd = fs.openSync(fifoPath, fs.constants.O_RDWR | (fs.constants.O_NONBLOCK || 0));
  } catch (error) {
    log.warn("console FIFO %s unavailable (%s); running without a console", fifoPath, error.code || error.message);
    return null;
  }
  let stream;
  try {
    // A FIFO fd is a pipe to libuv, so net.Socket reads it on the event loop.
    stream = new net.Socket({ fd, readable: true, writable: false });
  } catch (error) {
    stream = fs.createReadStream(null, { fd });
  }
  // Review 2 (m9): a read error on the FIFO is logged and the server keeps
  // running (an unhandled stream 'error' would end the process).
  stream.on("error", (error) => {
    log.warn("console FIFO %s read error (%s); the server keeps running", fifoPath, error.code || error.message);
  });
  return stream;
};

const main = () => {
  const versionError = checkNodeVersion(process.versions.node);
  if (versionError) {
    console.error(`Runtime error. ${versionError}`);
    process.exit(78); // EX_CONFIG
  }

  let config;
  try {
    config = load(process.env);
  } catch (error) {
    if (error instanceof ConfigError) {
      // A typo in a unit file used to be silent: MAX_PLAYERS=lots fell through
      // parseInt(...) || 16 and the operator got a server they did not ask for.
      console.error(`Configuration error. ${error.message}`);
      console.error("Refusing to start with a configuration nobody wrote.");
      process.exit(78); // EX_CONFIG
    }
    throw error;
  }

  const log = new SampledLogger({ intervalMs: config.logSampleIntervalMs, now: monotonicNow });

  // Списки читаются до первого пакета, и испорченный файл останавливает старт.
  //
  // Альтернатива - стартовать с пустыми списками - выглядит мягче и работает
  // хуже всего: сервер поднимется, оператор увидит рабочий хост и решит, что
  // баны на месте, а забаненные в это время зайдут. Это тот же принцип, по
  // которому config.js отказывается стартовать с непонятой переменной.
  //
  // Часы здесь настенные (Date.now), а не монотонные, как у всего остального:
  // срок бана должен пережить перезапуск. См. access.js.
  const access = new AccessList({
    maxNameLength: config.maxNameLength,
    now: Date.now,
    file: config.accessPersist ? config.accessFile : null,
    log,
  });
  try {
    const loaded = access.load();
    if (config.accessPersist) {
      log.info(
        "Access lists: %s (%d bans, %d whitelist, %d operators)",
        loaded ? config.accessFile : `${config.accessFile} (new)`,
        access.bans().length,
        access.whitelist().length,
        access.ops().length
      );
    }
  } catch (error) {
    if (error instanceof AccessError) {
      console.error(`Access file error. ${error.message}`);
      console.error("Refusing to start with bans the operator cannot see.");
      process.exit(78); // EX_CONFIG
    }
    throw error;
  }

  const server = new GhostingServer({ config, log, now: monotonicNow, access });

  // A socket error after a successful bind leaves the process with nothing to
  // do. Exiting non-zero is what tells the supervisor to restart it; the old
  // server closed the socket and stayed alive, which looked healthy to systemd
  // and dead to every player.
  server.onFatal = () => {
    log.error("the listening socket is gone; exiting so the supervisor can restart us");
    process.exit(1);
  };

  const consoleInput = openConsoleInput(process.env.CONSOLE_FIFO, log);
  const consoleHandle = consoleInput ? attach(server, { input: consoleInput }) : null;

  let stopping = false;
  const shutdown = (signal) => {
    if (stopping) return;
    stopping = true;
    log.info("%s received, shutting down", signal);
    if (consoleHandle) consoleHandle.rl.close();
    if (consoleInput && consoleInput !== process.stdin && typeof consoleInput.destroy === "function") consoleInput.destroy();
    // Players are told, and anyone frozen behind a race pause is released,
    // before the socket goes away.
    server.stop("Server is shutting down.").then(() => {
      log.info("stopped cleanly");
      process.exit(0);
    });
    // If close() hangs, leave anyway rather than sitting through the
    // supervisor's kill timeout.
    setTimeout(() => {
      log.error("shutdown timed out; exiting anyway");
      process.exit(0);
    }, 5000).unref();
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // M7: reload the access lists without a restart. The documented production
  // setup runs the console over a FIFO, but an operator who edited access.json
  // directly (or a deploy that replaced it) still needs the running server to
  // pick it up without dropping every player. A bad file is reported and the
  // old lists are kept, exactly as at startup. SIGHUP was previously unhandled
  // and killed the process.
  process.on("SIGHUP", () => {
    const result = server.reloadAccess();
    if (result.ok) {
      log.info(
        "SIGHUP: reloaded access lists (%d ban(s), %d whitelist, %d operator(s); %d session(s) removed)",
        access.bans().length,
        access.whitelist().length,
        access.ops().length,
        result.removed
      );
    } else {
      log.error("SIGHUP: access file not reloaded, keeping the current lists: %s", result.error);
    }
  });

  // Last line of defence. Anything that reaches here is a bug, and the honest
  // response is to log it and let the supervisor restart a known-good process
  // rather than keep running in an unknown state.
  process.on("uncaughtException", (error) => {
    log.error("uncaught exception: %s", error && error.stack);
    log.flush();
    process.exit(1);
  });
  process.on("unhandledRejection", (reason) => {
    log.error("unhandled rejection: %s", reason && (reason.stack || reason.message || reason));
    log.flush();
    process.exit(1);
  });

  server.start().catch((error) => {
    if (error && error.code === "EADDRINUSE") {
      log.error("UDP port %d is already in use", config.port);
    } else if (error && error.code === "EACCES") {
      log.error("no permission to bind UDP port %d", config.port);
    } else {
      log.error("could not bind: %s", error && error.message);
    }
    process.exit(1);
  });
};

if (require.main === module) main();

module.exports = { main, checkNodeVersion, MIN_NODE_MAJOR, openConsoleInput };
