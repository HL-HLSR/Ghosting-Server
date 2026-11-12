"use strict";

// Operator console on stdin.
//
// Kept as a separate module so the server can be exercised in tests without a
// readline interface attached, and so `node index.js < /dev/null` under a
// supervisor does not end up feeding a file into the command parser.

const readline = require("readline");
const { sanitizeForLog, sanitizeChat, truncateBytes, tokenizeCommand } = require("./wire/text");
const { KIND, parseDuration } = require("./game/access");
const limits = require("./wire/limits");

const HELP = [
  "Available commands:",
  "  help                     - show this help",
  "  status                   - show server status and limiter counters",
  "  list                     - list connected users",
  '  gh_online_kick "Nick"    - kick a user by name',
  '  kick "Nick"              - alias for gh_online_kick',
  '  unguard "Nick"           - lift an impersonation guard (see list) once you',
  "                             are satisfied it was not a real attack",
  '  broadcast "message"      - send a chat message to everyone as SERVER',
  "  race cancel              - cancel the current race and unpause everyone",
  "  maxplayers [n]           - show or change the slot limit (1-64), no restart",
  "  limits                   - show every rate limit and what it has dropped",
  "  limits <name> <n>        - change one while the server runs, e.g.",
  "                             limits chat.interval 0",
  "",
  "Bans (a kick only disconnects; a ban keeps them out):",
  '  ban "Nick" [term] [why]  - ban a nickname and remove whoever holds it',
  "  banip ADDRESS [term] [why] - ban an address",
  '  bansteam SteamID|"Nick" [term] [why] - ban a SteamID (a connected player\'s',
  "                             nick means the SteamID they announced)",
  '  unban "Nick" / unbanip ADDRESS / unbansteam SteamID',
  "  banlist                  - show the bans that are in force",
  "  term is 30s, 45m, 2h, 7d or perm (default). A bare word after the name is",
  "  the reason, not the term.",
  "",
  "Sprays (they stay on the server and keep playing; only the picture goes):",
  "  sprays - who has published a picture, and who is still being sent one",
  '  sprayban "Nick" [term] [why] - refuse their spray and drop the one they',
  "                             published; what is already on a wall clears with",
  "                             the map",
  '  unsprayban "Nick"',
  "",
  "Whitelist (checked when someone connects; nobody already playing is removed):",
  "  reload                   - re-read the access file (bans/whitelist/ops)",
  "                             without a restart, then kick anyone now banned",
  "",
  "  whitelist                - show the mode and the list",
  "  whitelist on | off",
  '  whitelist add "Nick" | whitelist addip ADDRESS | whitelist addsteam SteamID',
  '  whitelist remove "Nick" | whitelist removeip ADDRESS | whitelist removesteam SteamID',
  "",
  "Operators (may use /kick, /ban, /unban, /sprayban, /unsprayban and",
  "/broadcast in chat):",
  '  op "Nick" PIN | deop "Nick" | ops',
  "  The PIN (6-12 digits) is required and must come first in every admin chat",
  "  command (/ban PIN Nick). It is never relayed or printed, so a datagram",
  "  forged from the operator's address cannot issue commands; five wrong PINs",
  "  revoke the approval. OP_ALLOW_NO_PIN=1 allows op without one;",
  "  OP_CHAT_COMMANDS=0 disables chat moderation entirely.",
  '  opsteam SteamID|"Nick" PIN | deopsteam SteamID - a standing operator entry:',
  "  every protocol v2 session announcing that SteamID is approved when it",
  "  confirms, also after reconnects and restarts (the PIN is kept as a hash).",
  "",
  "What these lists can and cannot do: a name identifies nobody - it belongs to",
  "whoever typed it first. A SteamID (mod 1.4.0 and later) is SELF-REPORTED by",
  "the client: no Steam ticket is checked, a modified client can claim any",
  "SteamID or none, and SteamIDs are public - for an operator the PIN is the",
  "credential, and a SteamID ban stops only a client that tells the truth. An",
  "address ban stops the connection but also everyone else behind the same NAT.",
  "OP by name is approved for the currently connected session only; verify the",
  "player and approve again after reconnect or restart.",
  "None of this is authentication. See the security model in README.md.",
];

// command ["quoted arg" | bare rest]
const LINE = /^(\S+)\s*(?:"([^"]*)"|(.*))?$/;

const parse = (line) => {
  const match = LINE.exec(line);
  // Unreachable for a non-empty trimmed line, but the old code indexed
  // match[1] with no guard, and a TypeError inside a readline callback ends the
  // process.
  if (!match) return null;
  const argument = match[2] !== undefined ? match[2] : (match[3] || "").trim();
  return { command: match[1].toLowerCase(), argument };
};

// The console command that lifts a guard, as the operator should type it. A
// name containing a double quote cannot be quoted (the parser has no escapes),
// so it is given bare - the rest of the line is the argument.
const unguardHint = (name) => {
  const shown = sanitizeForLog(name, 40);
  return name.includes('"') ? `unguard ${shown}` : `unguard "${shown}"`;
};

const attach = (server, options) => {
  const opts = options || {};
  const out = opts.print || ((line) => console.log(line));

  const status = () => {
    const s = server.status();
    out(`Ghosting dedicated host on ${s.listening}`);
    out(`Name: ${sanitizeForLog(s.serverName, 80)}`);
    out(`Players: ${s.players}/${s.maxPlayers}`);
    out(`Protocol: ${s.protocol.v2} v2, ${s.protocol.legacy} legacy session(s)`);
    out(
      `Launcher: ${s.launcher.hlsr} from HLSR, ${s.launcher.other} not, ${s.launcher.unknown} unknown; ` +
        `${s.launcher.steamIds} with a SteamID (all self-reported)`
    );
    out(
      `Server info: ${s.info.queries} queries, ${s.info.challenges} challenge(s), ${s.info.replies} reply(ies), ` +
        `${s.info.dropped} over budget${s.info.enabled ? "" : " (SERVER_INFO=0: none answered)"}`
    );
    out(`Uptime: ${s.uptimeSeconds} seconds`);
    out(
      `Traffic: ${s.traffic.received} in / ${s.traffic.sent} out, ` +
        `${s.traffic.accepted} accepted, ${s.traffic.malformed} malformed, ` +
        `${s.traffic.unknownOpcode} unknown, ${s.traffic.oversized} oversized`
    );
    out(
      `Dropped by limiter: global ${s.limiters.global.dropped}, ` +
        `address ${s.limiters.address.dropped}, session ${s.limiters.session.dropped}, ` +
        `connect ${s.limiters.connect.dropped}, command ${s.limiters.command.dropped}, ` +
        `event ${s.limiters.event.dropped}`
    );
    out(
      `Tracked: ${s.limiters.address.size} addresses, ${s.limiters.session.size} sessions, ` +
        `${s.limiters.penaltyBox} in the penalty box`
    );
    out(
      `Blocked: ${s.traffic.unauthorised} wrong-owner, ` +
        `${s.traffic.impersonationGuards} impersonation guard(s) started, ` +
        `${s.traffic.mutedUnderAttack} refused from guarded sessions, ` +
        `${s.traffic.reflectionBlocked} reflection, ` +
        `${s.traffic.badToken} without the v2 token, ` +
        `${s.traffic.disconnectsCancelled} disconnects cancelled, ` +
        `${s.traffic.sendErrors} send errors`
    );
    out(
      `Access: ${s.access.bans} ban(s), whitelist ${s.access.whitelistEnabled ? "ON" : "off"} ` +
        `(${s.access.whitelist} entries), ${s.access.ops} operator(s)`
    );
    out(`Sprays waiting for a re-encode: ${s.sprays.reencodeQueued}`);
    if (s.access.saveError) out(`Access file NOT saved: ${sanitizeForLog(s.access.saveError, 120)}`);
    if (s.race.phase !== "idle") {
      out(`Race: ${s.race.phase}, runners ${s.race.runners.length}, finished ${s.race.finished.length}`);
    }
  };

  const list = () => {
    const users = server.list();
    out(`Connected users: ${users.length}/${server.config.maxPlayers}`);
    for (const user of users) {
      out(
        `  ${sanitizeForLog(user.name, 40)} (${user.address}) - map: ${sanitizeForLog(user.map, 40)}, ` +
          `last seen ${user.lastSeenSeconds}s ago${user.confirmed ? "" : ", UNCONFIRMED"}` +
          // 1.4.0: what the client says about itself.
          `, ${user.protocol === 2 ? "v2" : "legacy"}, ${user.launcherText}` +
          (user.launcher === null ? "" : user.steamId ? `, steam ${user.steamId}` : ", no SteamID") +
          (user.operator ? `, operator (${user.operator})` : "") +
          (user.guardedSeconds > 0
            ? `, UNDER IMPERSONATION GUARD (${user.guardedSeconds}s more; lift with: ${unguardHint(user.name)})`
            : "")
      );
    }
  };

  // Всё, что печатает оператор, экранируется на выходе: под супервизором stdin
  // может быть перенаправлен из файла, и это ровно та причина, по которой
  // console.js вообще отделён от сервера.
  const show = (value, width = 40) => sanitizeForLog(value, width);

  // Запись в файл могла не пройти (права, полный диск). Список при этом уже
  // изменён в памяти, и молчать об этом нельзя: оператор узнал бы о потере при
  // следующем старте, то есть когда забаненный уже зашёл.
  const reportSave = (result) => {
    if (result.persisted !== false) return;
    out(`Warning: '${show(server.access.file, 120)}' was NOT written: ${show(server.access.lastSaveError, 120)}`);
    out("The change is in force until the server restarts.");
  };

  const usage = {
    ban: (kind) =>
      kind === KIND.ADDRESS
        ? "Usage: banip 203.0.113.7 [30m|2h|7d|perm] [reason]"
        : kind === KIND.STEAMID
          ? 'Usage: bansteam <SteamID64|STEAM_0:Y:Z|[U:1:N]|"Nick"> [30m|2h|7d|perm] [reason]'
          : 'Usage: ban "Nick" [30m|2h|7d|perm] [reason]',
    unban: (kind) =>
      kind === KIND.ADDRESS
        ? "Usage: unbanip 203.0.113.7"
        : kind === KIND.STEAMID
          ? "Usage: unbansteam <SteamID>"
          : 'Usage: unban "Nick"',
  };

  // 1.4.0: a SteamID argument may also be the nickname of a connected player
  // who announced one (server.resolveSteamTarget). Returns the SteamID64, or
  // null after printing why not.
  const steamTarget = (value, verb) => {
    const resolved = server.resolveSteamTarget(value);
    if (resolved.ok) return resolved.id;
    out(`Cannot ${verb} '${show(value)}': ${resolved.error}.`);
    return null;
  };

  const describe = (record) =>
    `${record.kind} '${show(record.value)}' - ${server.access.term(record)}, by ${show(record.addedBy, 32)}` +
    (record.reason ? `, reason: ${show(record.reason, 80)}` : "");

  const ban = (kind, args) => {
    let value = args[0];
    if (!value) {
      out(usage.ban(kind));
      return;
    }
    if (kind === KIND.STEAMID) {
      value = steamTarget(value, "ban");
      if (value === null) return;
    }
    // Срок - только тот токен, который идёт сразу за именем, и только если он и
    // правда срок. Иначе `ban Bob spamming` попыталось бы понять "spamming" как
    // длительность и молча забанило бы навсегда с пустой причиной.
    const duration = parseDuration(args[1]);
    const rest = duration === null ? args.slice(1) : args.slice(2);
    const result = server.access.ban(kind, value, {
      reason: rest.join(" "),
      until: duration ? server.access.now() + duration : 0,
      addedBy: "console",
    });
    if (!result.ok) {
      out(`Cannot ban '${show(value)}': ${result.error}.`);
      return;
    }
    const kicked = server.enforceBans();
    out(`Banned ${describe(result.record)}.`);
    if (kicked > 0) out(`Removed ${kicked} session(s) that the ban now covers.`);
    else if (kind === KIND.NAME) out("Nobody by that name is here; the ban applies when they connect.");
    reportSave(result);
  };

  const unban = (kind, args) => {
    const value = args[0];
    if (!value) {
      out(usage.unban(kind));
      return;
    }
    const result = server.access.unban(kind, value);
    if (!result.ok) {
      out(`'${show(value)}' is ${result.error}.`);
      return;
    }
    out(`Unbanned ${describe(result.record)}.`);
    reportSave(result);
  };

  // Запрет на спрей. Не бан: человек остаётся на сервере и играет, у него лишь
  // отбирают картинку. Отдельная команда именно потому, что снимать с сервера
  // за спрей - слишком грубая мера, а другой у оператора до сих пор не было.
  const sprayban = (args) => {
    const value = args[0];
    if (!value) {
      out('Usage: sprayban "Nick" [30m|2h|7d|perm] [reason]');
      return;
    }
    const duration = parseDuration(args[1]);
    const rest = duration === null ? args.slice(1) : args.slice(2);
    const result = server.access.ban(KIND.SPRAY, value, {
      reason: rest.join(" "),
      until: duration ? server.access.now() + duration : 0,
      addedBy: "console",
    });
    if (!result.ok) {
      out(`Cannot spray-ban '${show(value)}': ${result.error}.`);
      return;
    }
    // Снятое со стен - половина смысла команды: повод для запрета обычно висит
    // прямо сейчас.
    server.revokeSpray(result.record.key, value);
    out(`Spray-banned ${describe(result.record)}.`);
    out("They stay on the server; only spraying is refused.");
    reportSave(result);
  };

  const unsprayban = (args) => {
    const value = args[0];
    if (!value) {
      out('Usage: unsprayban "Nick"');
      return;
    }
    const result = server.access.unban(KIND.SPRAY, value);
    if (!result.ok) {
      out(`'${show(value)}' is not spray-banned.`);
      return;
    }
    out(`'${show(result.record.value)}' may spray again.`);
    reportSave(result);
  };

  const banlist = () => {
    const records = server.access.bans();
    out(`Bans in force: ${records.length}`);
    for (const record of records) out(`  ${describe(record)}`);
    if (records.length === 0) out("  (none)");
  };

  const whitelist = (args) => {
    const sub = (args[0] || "").toLowerCase();
    const value = args[1];
    const entries = server.access.whitelist();

    if (!sub) {
      out(`Whitelist: ${server.access.whitelistEnabled ? "ON" : "off"}, ${entries.length} entries`);
      for (const record of entries) out(`  ${record.kind} '${show(record.value)}'`);
      if (server.access.whitelistEnabled && entries.length === 0) {
        out("  (empty and ON: nobody can connect)");
      }
      return;
    }

    if (sub === "on" || sub === "off") {
      const result = server.access.setWhitelist(sub === "on");
      out(`Whitelist is now ${result.enabled ? "ON" : "off"}.`);
      if (result.enabled) {
        if (result.empty) out("The list is empty, so no new connection will be accepted.");
        // Никого не выгоняем. Одно слово в консоли не должно снимать с сервера
        // всех, кто уже играет; кому надо выйти - тому kick.
        out("Players already connected are not removed; use kick for that.");
      }
      reportSave(result);
      return;
    }

    const kind = sub.endsWith("ip") ? KIND.ADDRESS : sub.endsWith("steam") ? KIND.STEAMID : KIND.NAME;
    const adding = sub === "add" || sub === "addip" || sub === "addsteam";
    const removing = sub === "remove" || sub === "removeip" || sub === "removesteam";
    if (!adding && !removing) {
      out(
        'Usage: whitelist [on|off|add "Nick"|addip ADDRESS|addsteam SteamID|remove "Nick"|removeip ADDRESS|' +
          "removesteam SteamID]"
      );
      return;
    }
    if (!value) {
      out(`Usage: whitelist ${sub} ${kind === KIND.ADDRESS ? "203.0.113.7" : kind === KIND.STEAMID ? "<SteamID>" : '"Nick"'}`);
      return;
    }
    let target = value;
    if (kind === KIND.STEAMID && adding) {
      target = steamTarget(value, "add");
      if (target === null) return;
    }

    const result = adding
      ? server.access.whitelistAdd(kind, target, { addedBy: "console" })
      : server.access.whitelistRemove(kind, target);
    if (!result.ok) {
      out(`Cannot ${adding ? "add" : "remove"} '${show(value)}': ${result.error}.`);
      return;
    }
    out(`${adding ? "Added" : "Removed"} ${result.record.kind} '${show(result.record.value)}'.`);
    if (adding && !server.access.whitelistEnabled) out("The whitelist is off, so this has no effect yet.");
    reportSave(result);
  };

  const op = (args, granting) => {
    const name = args[0];
    if (!name) {
      out(granting ? 'Usage: op "Nick" PIN' : 'Usage: deop "Nick"');
      return;
    }
    // C2(a): the PIN the operator must carry on every admin chat command, so a
    // datagram forged from their address:port cannot issue commands. Required
    // (6-12 digits) unless the host set OP_ALLOW_NO_PIN=1. It is NEVER printed:
    // under the systemd unit stdout is the journal, readable by more accounts
    // than the operator's.
    const pin = granting ? args[1] : undefined;
    const result = granting
      ? server.grantOp(name, { addedBy: "console", pin })
      : server.revokeOp(name);
    if (!result.ok) {
      out(`Cannot ${granting ? "op" : "deop"} '${show(name)}': ${result.error}.`);
      return;
    }
    if (granting) {
      out(`'${show(result.record.value)}' may now use /kick, /ban, /unban, /sprayban and /broadcast in chat.`);
      if (result.pinSet) {
        out("A PIN is set: they must type it first, e.g.  /ban <PIN> Nick  - only in a '/' command, never as plain chat,");
        out("and not on a live stream. Five wrong PINs in a row revoke the approval.");
      } else {
        out("No PIN (OP_ALLOW_NO_PIN=1): a datagram forged from their address:port can use these commands.");
      }
      // Сказано здесь, а не только в README: команду набирают в тот момент,
      // когда решение принимается.
      out("Approved for this session only. After reconnect or server restart, use op again after verifying the player.");
    } else {
      out(`'${show(result.record.value)}' is no longer an operator.`);
    }
    reportSave(result);
  };

  // 1.4.0: operators by SteamID. Unlike `op "Nick" PIN` the entry is kept in the
  // access file and approves whoever announces that SteamID on a protocol v2
  // session, now and after every reconnect and restart - so it is exactly as
  // strong as its PIN: the SteamID is the client's word, and SteamIDs are public.
  const opsteam = (args, granting) => {
    const value = args[0];
    if (!value) {
      out(granting ? 'Usage: opsteam <SteamID64|STEAM_0:Y:Z|[U:1:N]|"Nick"> PIN' : "Usage: deopsteam <SteamID|\"Nick\">");
      return;
    }
    // The PIN is never printed (see op above).
    const result = granting
      ? server.grantOpSteam(value, { addedBy: "console", pin: args[1] })
      : server.revokeOpSteam(value);
    if (!result.ok) {
      out(`Cannot ${granting ? "opsteam" : "deopsteam"} '${show(value)}': ${result.error}.`);
      return;
    }
    if (granting) {
      out(`SteamID ${result.record.value} is an operator: a protocol v2 session that announces it is approved when it confirms.`);
      if (result.pinSet) {
        out("A PIN is set (kept only as a salted hash): every admin chat command must start with it, e.g. /ban <PIN> Nick.");
      } else {
        out("No PIN (OP_ALLOW_NO_PIN=1): ANYONE whose client announces this SteamID gets these commands.");
      }
      out("The SteamID is self-reported by the client (no Steam ticket check) and SteamIDs are public: the PIN is the");
      out("real credential. Five wrong PINs in a row revoke the session's approval until it reconnects.");
      if (result.approved.length > 0) out(`Approved now: ${result.approved.map((name) => show(name)).join(", ")}.`);
    } else {
      out(`SteamID ${result.record.value} is no longer an operator; any session it approved has lost the approval.`);
    }
    reportSave(result);
  };

  // Who has published a picture and who is still receiving one.
  //
  // The log already says a spray arrived; it said nothing about it leaving
  // again, and "did my friend get it" was unanswerable without adding print
  // statements. Delivery is a drip - a few pieces per tick - so a queue that is
  // shrinking is the thing to look for, not a single yes or no.
  const sprays = () => {
    const snap = server.spraySnapshot();
    if (snap.rows.length === 0) {
      out("Nobody is connected.");
      return;
    }

    const kb = (n) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);
    // L2: every other command escapes the names it prints; `sprays` used to
    // print them raw, so a nickname carrying a C1/CSI byte reached the operator's
    // terminal unescaped. Names here go through show() too, and the column width
    // is measured on the escaped form so the table still lines up.
    const width = Math.max(4, ...snap.rows.map((r) => show(r.name).length));

    out("Sprays");
    out("");
    out(`  ${"Nick".padEnd(width)}  published            receiving      still to send`);
    for (const row of snap.rows) {
      const published = row.published
        ? `${kb(row.published.bytes)} / ${row.published.total} pcs`
        : row.banned
          ? "(spray-banned)"
          : "-";
      const receiving = row.incoming ? `${row.incoming.have}/${row.incoming.total} pcs` : "-";
      let pending = "-";
      if (row.pending > 0) {
        const who = row.pendingFrom.map((f) => `${f.count} from ${show(f.name)}`).join(", ");
        pending = `${row.pending} pcs (${who})`;
      }
      const flag = row.confirmed ? " " : "?";
      out(`  ${show(row.name).padEnd(width)}${flag} ${published.padEnd(20)} ${receiving.padEnd(14)} ${pending}`);
    }
    out("");
    out(`Pieces are ${snap.chunkBytes} bytes and go out ${snap.perTick} per ${snap.tickMs} ms per player,`);
    out("so a full picture takes a few seconds to reach somebody. Run this twice:");
    out("a 'still to send' column that is going down is delivery working.");
    out("A '?' after a nick means that session is not confirmed yet.");
    out(`Sprays waiting for a re-encode: ${snap.reencodeQueued} (published at ${snap.reencodePerMinute} a minute,`);
    out("taking turns by address; the player's own client shows theirs at once).");
  };

  // Rate limits, live.
  //
  // Printed with the drop counter for each family beside it, because the
  // question an operator is actually asking is not "what is this set to" but
  // "is this the thing that is biting". A limit whose counter never moves is
  // not the one to change.
  const limits = (argument) => {
    const snap = server.limitSnapshot();

    if (!argument) {
      out("Rate limits (change with: limits <name> <value>; takes effect immediately)");
      out("");
      const width = Math.max(...snap.rows.map((r) => r.name.length));
      for (const row of snap.rows) {
        out(`  ${row.name.padEnd(width)}  ${String(row.value).padStart(9)}   ${row.help}`);
      }
      out("");
      out("Dropped since start (a counter that stays at 0 means that limit is not biting):");
      const d = snap.dropped;
      out(`  address ${d.address}   session ${d.session}   command ${d.command}   event ${d.event}`);
      out(`  spray ${d.spray}   malformed ${d.malformed}   connect ${d.connect}`);
      out(`  global ${d.global} (of which unconfirmed sessions: ${d.globalUntrusted})`);
      out("");
      out("Nothing here is written to disk: a restart brings back the values from the");
      out("environment. Make a change permanent by setting the matching variable.");
      return;
    }

    const parts = argument.split(/\s+/);
    if (parts.length !== 2) {
      out("Usage: limits              - show everything");
      out("       limits <name> <n>   - set one, e.g. limits chat.interval 0");
      return;
    }

    const value = Number(parts[1]);
    const result = server.setLimit(parts[0].toLowerCase(), value);
    if (!result.ok) {
      out(`Cannot set that: ${result.error}.`);
      if (result.names) out(`Known limits: ${result.names.join(", ")}`);
      return;
    }
    out(`${result.name} is now ${result.value} (was ${result.previous}). In force from the next packet.`);
    out("Not saved - a restart returns it to the environment's value.");
  };

  const maxplayers = (argument) => {
    if (!argument) {
      out(`Slots: ${server.users.count()}/${server.config.maxPlayers}`);
      return;
    }
    if (!/^[0-9]{1,3}$/.test(argument)) {
      out("Usage: maxplayers 16");
      return;
    }
    const result = server.setMaxPlayers(Number(argument));
    if (!result.ok) {
      out(`Cannot set the slot limit: ${result.error}.`);
      return;
    }
    out(`Slot limit is now ${result.value} (was ${result.previous}). ${result.players} player(s) online.`);
    if (result.value > 16) {
      out("Only 16 slots have been load tested; fan-out traffic grows with the square of the count.");
    }
    if (result.players > result.value) {
      out(`Nobody is removed: the server stays full until it drops below ${result.value}.`);
    }
  };

  const handle = (raw) => {
    // Review 4 (M2): one place where the console's text meets the wire's bytes.
    // Nicknames (and chat) live in this host as the byte string the client sent
    // - UTF-8 bytes, one character per byte - and `list` prints them decoded.
    // The operator types what `list` printed, which readline hands over as
    // decoded text, so "Призрак" or "Renée" never matched anybody (and a
    // Cyrillic `broadcast` went out mangled). The line is turned back into the
    // wire's byte form here, before any command sees it; ASCII is unchanged.
    const line = Buffer.from(String(raw), "utf8").toString("latin1").trim();
    if (line.length === 0) return;
    const parsed = parse(line);
    if (!parsed) return;
    const { command, argument } = parsed;
    // parse() отдаёт ровно один аргумент - этого хватало, пока команды были
    // `kick "Ник"`. Бану нужны ещё срок и причина, поэтому строка разбирается
    // ещё раз, целиком и с кавычками. Сам parse() не тронут: он часть контракта
    // и на нём висят тесты.
    const args = tokenizeCommand(line).slice(1);

    switch (command) {
      case "help":
        for (const help of HELP) out(help);
        break;
      case "status":
        status();
        break;
      case "list":
        list();
        break;
      case "gh_online_kick":
      case "kick":
        if (!argument) {
          out('Usage: gh_online_kick "Nick"');
          break;
        }
        if (!server.kickByName(argument)) {
          out(`No user named '${sanitizeForLog(argument, 40)}' is connected. Use 'list' to see who is online.`);
        }
        break;
      case "broadcast": {
        // stdin is untrusted when the process runs under a supervisor with its
        // input redirected, and this text is relayed to every player.
        const text = truncateBytes(sanitizeChat(argument), limits.MAX_CHAT_LENGTH);
        if (!text) {
          out('Usage: broadcast "message"');
          break;
        }
        server.serverSay(text);
        break;
      }
      case "race":
        if (argument.toLowerCase() === "cancel") {
          if (!server.race.cancel("Race cancelled by the server operator.")) out("No race is running.");
        } else {
          out("Usage: race cancel");
        }
        break;
      case "ban":
        ban(KIND.NAME, args);
        break;
      case "banip":
        ban(KIND.ADDRESS, args);
        break;
      case "unban":
        unban(KIND.NAME, args);
        break;
      case "unbanip":
        unban(KIND.ADDRESS, args);
        break;
      case "bansteam":
        ban(KIND.STEAMID, args);
        break;
      case "unbansteam":
        unban(KIND.STEAMID, args);
        break;
      case "sprays":
        sprays();
        break;
      case "sprayban":
        sprayban(args);
        break;
      case "unsprayban":
        unsprayban(args);
        break;
      case "banlist":
        banlist();
        break;
      case "whitelist":
        whitelist(args);
        break;
      case "unguard": {
        // Review 3 (R4): a guard can be tripped by somebody spoofing the
        // player's IP just to pause their chat and races; the operator lifts it.
        if (!argument) {
          out('Usage: unguard "Nick"');
          break;
        }
        const result = server.unguard(argument, "console");
        if (result.ok) out(`Impersonation guard on '${show(result.name)}' lifted; they have been told.`);
        else out(`Cannot unguard '${show(argument)}': ${result.error}.`);
        break;
      }
      case "op":
        op(args, true);
        break;
      case "deop":
        op(args, false);
        break;
      case "opsteam":
        opsteam(args, true);
        break;
      case "deopsteam":
        opsteam(args, false);
        break;
      case "ops": {
        const operators = server.access.ops();
        out(`Operators: ${operators.length}`);
        for (const record of operators) {
          if (record.kind === KIND.STEAMID) {
            out(`  steamid '${show(record.value)}' - by ${show(record.addedBy, 32)}, ${record.pin ? "PIN set" : "NO PIN"}`);
          } else {
            out(`  '${show(record.value)}' - by ${show(record.addedBy, 32)}`);
          }
        }
        if (operators.length === 0) out("  (none)");
        break;
      }
      case "reload": {
        const result = server.reloadAccess();
        if (!result.ok) {
          out(`Reload failed, keeping the current lists: ${show(result.error, 160)}`);
          break;
        }
        out(
          `Reloaded: ${server.access.bans().length} ban(s), ` +
            `whitelist ${server.access.whitelistEnabled ? "ON" : "off"} (${server.access.whitelist().length}), ` +
            `${server.access.ops().length} operator(s).`
        );
        if (result.removed > 0) out(`Removed ${result.removed} session(s) the new bans cover.`);
        break;
      }
      case "maxplayers":
        maxplayers(argument);
        break;
      case "limits":
        limits(argument);
        break;
      default:
        // The token is echoed, so it goes through the same escaping as any
        // other untrusted text: stdin is untrusted too when the process is
        // started with its input redirected.
        out(`Unknown command '${sanitizeForLog(command, 32)}'. Type 'help' for a list of commands.`);
    }
  };

  const rl = readline.createInterface({ input: opts.input || process.stdin, terminal: false });
  // Review 2 (m9): readline re-emits an error of its input stream on the
  // interface, and an 'error' nobody listens to ends the process. A broken
  // console must never take the game server with it.
  rl.on("error", (error) => {
    server.log.warn("console input failed (%s); the server keeps running without a console", (error && (error.code || error.message)) || "error");
  });
  rl.on("line", (line) => {
    try {
      handle(line);
    } catch (error) {
      out(`Command failed: ${error && error.message}`);
    }
  });

  return { rl, handle, parse };
};

module.exports = { attach, parse, HELP };
