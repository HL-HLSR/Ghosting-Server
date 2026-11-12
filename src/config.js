"use strict";

// Environment parsing.
//
// Every knob is validated here and nowhere else. A public host is usually
// started by a supervisor from a unit file, and a typo in that unit file used
// to be silent: `MAX_PLAYERS=lots` fell through `parseInt(...) || 16` back to
// the default, and `DEBUG=0` was truthy because only the presence of the
// variable was checked. Both now stop the process with a readable message
// instead of running a server the operator did not ask for.

const net = require("net");

class ConfigError extends Error {}

const isSet = (raw) => raw !== undefined && raw !== null;

// Integer in [min, max]. Rejects floats, whitespace-only and trailing junk:
// parseInt("16abc") is 16, which is exactly the kind of surprise we don't want.
//
// An empty value is an error rather than "use the default". `HEARTBEAT_MS=` in
// a unit file is a typo, and silently running with 2000 hides it until someone
// wonders why the setting had no effect. Not setting the variable at all is the
// way to ask for the default.
const integer = (env, name, fallback, min, max) => {
  const raw = env[name];
  if (!isSet(raw)) return fallback;
  if (String(raw).trim() === "") {
    throw new ConfigError(`${name}: set but empty. Remove it entirely to use the default (${fallback}).`);
  }
  if (!/^-?\d+$/.test(String(raw).trim())) {
    throw new ConfigError(`${name}: expected an integer, got "${raw}"`);
  }
  const value = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(value)) throw new ConfigError(`${name}: value out of range ("${raw}")`);
  if (value < min || value > max) {
    throw new ConfigError(`${name}: expected ${min}..${max}, got ${value}`);
  }
  return value;
};

// Boolean where "0"/"false"/"no"/"off" mean false. Anything unrecognised is an
// error rather than a guess.
const boolean = (env, name, fallback) => {
  const raw = env[name];
  if (!isSet(raw)) return fallback;
  const value = String(raw).trim().toLowerCase();
  // `DEBUG=` is the conventional way to switch a flag off in a shell, so unlike
  // the numeric variables an empty boolean is accepted and means false.
  if (value === "") return false;
  if (["1", "true", "yes", "on"].includes(value)) return true;
  if (["0", "false", "no", "off"].includes(value)) return false;
  throw new ConfigError(`${name}: expected 0/1 (or false/true), got "${raw}"`);
};

const string = (env, name, fallback, pattern) => {
  const raw = env[name];
  if (!isSet(raw)) return fallback;
  const value = String(raw).trim();
  if (value === "") {
    throw new ConfigError(`${name}: set but empty. Remove it entirely to use the default (${fallback}).`);
  }
  if (pattern && !pattern.test(value)) {
    throw new ConfigError(`${name}: value "${raw}" is not allowed`);
  }
  return value;
};

// Settings that existed and no longer do. Ignoring them silently is the exact
// failure this file was rewritten to eliminate: an operator puts the line in a
// unit file, the value is parsed and range-checked, and then nothing in the
// server ever reads it. CONNECT_COOLDOWN_MS was that: a per-address connect
// cooldown from the old server, replaced by CONNECT_RATE_PER_MINUTE and
// CONNECT_BURST, but still validated as if it did something.
const RETIRED = new Map([
  ["CONNECT_COOLDOWN_MS", "the connect budget replaced it: use CONNECT_RATE_PER_MINUTE and CONNECT_BURST"],
  // EMOTE_PACK was here from L9 (the 2026-10-22 client dropped type 14) until
  // 1.3.2, which brings it back for the client that reads it again.
  // Pre-release names from the first cut of the H2 credit; the credit is now
  // derived from the live lobby (OUTBOUND_RECEIVER_FLOOR_PPS).
  ["OUTBOUND_CREDIT_PER_PACKET", "the credit is now computed from the lobby; tune OUTBOUND_RECEIVER_FLOOR_PPS"],
  ["OUTBOUND_CREDIT_MAX", "the credit is now computed from the lobby; tune OUTBOUND_RECEIVER_FLOOR_PPS"],
  // Review 3 (R3): the guard counts distinct source ports, not packets.
  ["IMPERSONATION_TRIGGER_PACKETS", "the guard now counts distinct ports; use IMPERSONATION_TRIGGER_PORTS"],
]);

const refuseRetired = (env) => {
  for (const [name, advice] of RETIRED) {
    if (isSet(env[name])) throw new ConfigError(`${name}: no longer used - ${advice}`);
  }
};

const ipv4 = (env, name, fallback) => {
  const value = string(env, name, fallback);
  if (net.isIP(value) !== 4) {
    throw new ConfigError(`${name}: expected an IPv4 literal, got "${value}"`);
  }
  return value;
};

// --- 7TV emote pack ---
//
// One identifier, relayed and nothing else. The server does not resolve it: the
// launcher already owns every 7TV request and the host allowlist that goes with
// it, and giving a UDP relay an outbound HTTP client would be a new way for the
// host to hang for no benefit. So this validates the SHAPE and stops. A
// well-formed id naming nothing is a 404 in the launcher, which is the only
// place it could be reported anyway.
//
// Three spellings resolve and they resolve DIFFERENTLY, so the tag has to
// survive the trip to the client:
//   https://7tv.app/emote-sets/<id>  -> GET /v3/emote-sets/<id>
//   https://7tv.app/users/<id>       -> GET /v3/users/<id>, then the
//                                       emote_set_id of a connection
//   a numeric Twitch channel id      -> GET /v3/users/twitch/<id>
//
// A bare 7TV id is read as an emote set: it is the form the site puts in front
// of an operator and the only one that resolves in a single request. Write
// `user:<id>` for the other. The tagged forms are accepted as INPUT precisely so
// that the value this file prints can be pasted back into a unit file and mean
// the same thing.
//
// A 7TV id is either a 26 character ULID (Crockford base32: 0-9 and A-Z without
// I, L, O and U) or one of the 24 character hex ObjectIDs from before the
// migration. Both are accepted because refusing a link that works is a startup
// failure, and the two lengths cannot be confused with each other or with a
// Twitch id, which is decimal - that is what makes a bare id unambiguous.
// Case insensitive but deliberately not /u: with the unicode flag a range like
// A-Z also matches the Kelvin sign, and an id is ASCII.
const EMOTE_ID = "(?:[0-9A-HJKMNP-TV-Z]{26}|[0-9A-F]{24})";
const EMOTE_URL = new RegExp(`^https?://(?:www\\.)?7tv\\.app/(emote-sets|users)/(${EMOTE_ID})/?(?:[?#].*)?$`, "i");
const EMOTE_TAGGED = new RegExp(`^(set|user):(${EMOTE_ID})$`, "i");
const EMOTE_BARE = new RegExp(`^${EMOTE_ID}$`, "i");
const EMOTE_TWITCH = /^(?:twitch:)?([1-9][0-9]{0,14})$/;

// ULIDs are canonically upper case, ObjectIDs lower. Normalising both means two
// operators who pasted the same link in different cases get the same string on
// the wire, and the client's "same set, already asked for" check is not defeated
// by capitalisation.
const canonicalEmoteId = (id) => (id.length === 26 ? id.toUpperCase() : id.toLowerCase());

// The tagged string, or null if it is none of the accepted spellings.
const normaliseEmotePack = (value) => {
  const url = EMOTE_URL.exec(value);
  if (url) return `${url[1].toLowerCase() === "emote-sets" ? "set" : "user"}:${canonicalEmoteId(url[2])}`;
  const tagged = EMOTE_TAGGED.exec(value);
  if (tagged) return `${tagged[1].toLowerCase()}:${canonicalEmoteId(tagged[2])}`;
  const twitch = EMOTE_TWITCH.exec(value);
  if (twitch) return `twitch:${twitch[1]}`;
  if (EMOTE_BARE.test(value)) return `set:${canonicalEmoteId(value)}`;
  return null;
};

// 1.3.2: "0" and "off" switch the pack off as explicitly as leaving the
// variable out does. Neither could ever name a pack (a Twitch id never starts
// with 0), so no value that was valid in 0.3.2 changes meaning; before, they
// stopped startup.
const EMOTE_PACK_OFF = new Set(["0", "off"]);

const emotePack = (env, name, fallback) => {
  const raw = env[name];
  if (raw === undefined || raw === null || String(raw).trim() === "") {
    if (raw !== undefined && raw !== null && String(raw).trim() === "") {
      throw new ConfigError(`${name}: set but empty. Remove it entirely (or set 0) to run without an emote pack.`);
    }
    return fallback;
  }
  const value = String(raw).trim();
  if (EMOTE_PACK_OFF.has(value.toLowerCase())) return null;
  const pack = normaliseEmotePack(value);
  if (!pack) {
    throw new ConfigError(
      `${name}: expected a 7tv.app emote-set or user link, a 7TV id, ` +
        `a numeric Twitch channel id, or 0 for none, got "${raw}"`
    );
  }
  return pack;
};

// --- server browser name (1.4.0) ---
//
// What the mod's "Servers" dialog shows for this host. The environment hands
// Node decoded text; the wire carries UTF-8 bytes in the latin1 costume every
// other string here wears (wire/text.js), so it is re-encoded, then cleaned the
// way chat is (control characters and bidi marks out, whitespace collapsed).
// Too long is refused rather than cut: the client reads it into char[64], and a
// name the operator typed should not be shortened behind their back.
const SERVER_NAME_DEFAULT = "Ghosting server";

const serverName = (env, name) => {
  const raw = env[name];
  if (!isSet(raw)) return SERVER_NAME_DEFAULT;
  // Lazy: text.js is the wire's, and config.js is loaded before anything else.
  const { sanitizeChat } = require("./wire/text");
  const { MAX_SERVER_NAME_LENGTH } = require("./wire/limits");
  const wire = sanitizeChat(Buffer.from(String(raw), "utf8").toString("latin1"));
  if (wire === "") {
    throw new ConfigError(`${name}: set but empty. Remove it entirely to use the default (${SERVER_NAME_DEFAULT}).`);
  }
  if (wire.length > MAX_SERVER_NAME_LENGTH) {
    throw new ConfigError(
      `${name}: ${wire.length} bytes as UTF-8, the limit is ${MAX_SERVER_NAME_LENGTH} (a Cyrillic letter is two bytes)`
    );
  }
  return wire;
};

// Defaults are the values the current public host has been running with, so an
// operator who sets nothing gets the same server they had before.
const load = (env = process.env) => {
  refuseRetired(env);
  const config = {
    // --- listener ---
    port: integer(env, "PORT", 22228, 1, 65535),
    // 0.0.0.0 by default; an operator behind a reverse proxy or on a multi-homed
    // box can pin the listener. Hostnames are rejected: a DNS lookup at bind
    // time is one more thing that can fail or be poisoned.
    //
    // The first version tested this with /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/, which
    // is dotted-quad shaped but not an address: "999.999.999.999" passed, and
    // dgram then treated it as a name to resolve - the exact DNS lookup the
    // check was written to prevent. net.isIP() is the real predicate.
    bindAddress: ipv4(env, "BIND_ADDRESS", "0.0.0.0"),

    // --- slots ---
    // The load evidence in the report covers 16 slots. Higher values are
    // permitted but warned about, because fan-out cost grows as N^2.
    maxPlayers: integer(env, "MAX_PLAYERS", 16, 1, 64),
    // Slots one address may hold. Without a cap, a single host rotating its
    // source port fills the server in seconds and keeps it full.
    maxSessionsPerAddress: integer(env, "MAX_SESSIONS_PER_ADDRESS", 4, 1, 64),

    // Player name length, in BYTES - that is the size of the char[] the name
    // lands in on the client. A Russian nickname is two bytes a letter, so 31
    // bytes is about fifteen letters. Truncation lands on a character boundary
    // (see wire/text.js), never through the middle of one.
    //
    // 31 is what the mod's own buffer allows. The HUD in client.dll used to
    // break the race status column and the spectate label for names longer than
    // 28 characters, because it prefixed "OL " into a 32 byte buffer and then
    // looked the player up by substring; the mod now stores the plain nickname
    // and compares it exactly. Lowering this to 28 is the workaround for an
    // older build of the mod, at the cost of shortening long nicknames.
    maxNameLength: integer(env, "NAME_MAX_LENGTH", 31, 3, 31),

    debug: boolean(env, "DEBUG", false),

    // --- access control ---
    // Баны, whitelist и список OP переживают перезапуск, а значит лежат в
    // файле. Путь берётся ТОЛЬКО отсюда: ни ник, ни чат, ни какая-либо другая
    // строка из сети до имени файла не дотягивается.
    //
    // Значение по умолчанию относительное, то есть считается от рабочего
    // каталога процесса. Под systemd это WorkingDirectory, и каталог должен
    // быть доступен на запись - см. ReadWritePaths в README.
    accessFile: string(env, "ACCESS_FILE", "access.json"),
    // Для хоста, которому диск трогать нечем. Списки продолжают работать, но
    // живут до конца процесса.
    accessPersist: boolean(env, "ACCESS_PERSIST", true),
    // H1 hardening: whether players may use the admin chat commands (/kick,
    // /ban, ...) at all. An operator session is bound only to a forgeable
    // address:port, so on a network that allows spoofing an attacker who knows
    // an op's nickname and IP can reach these commands by sweeping the op's
    // ports (now slow - see authorise - but not impossible). A host that does
    // its moderation from the console does not need the chat surface at all and
    // can turn it off here; the console `op`/`/kick` path is unaffected. On by
    // default so existing hosts behave as before.
    opChatCommands: boolean(env, "OP_CHAT_COMMANDS", true),
    // C2: an operator approved WITHOUT a PIN can be impersonated by anyone who
    // finds their address:port (seconds on a spoofing network), so `op "Nick"`
    // requires a PIN of at least 6 digits. A host that accepts that risk (a LAN
    // party, a box behind a strict firewall) can set this to 1.
    opAllowNoPin: boolean(env, "OP_ALLOW_NO_PIN", false),

    // --- session lifetime ---
    staleTimeoutMs: integer(env, "STALE_TIMEOUT_MS", 60000, 5000, 3600000),
    sweepIntervalMs: integer(env, "SWEEP_INTERVAL_MS", 5000, 250, 60000),
    // A name may move to another port of the same address after this much
    // silence (crash + reconnect); a different address has to wait out the full
    // stale timeout. See docs in identity.js.
    takeoverAfterMs: integer(env, "TAKEOVER_AFTER_MS", 10000, 1000, 3600000),

    // --- chat and updates ---
    chatMinIntervalMs: integer(env, "CHAT_MIN_INTERVAL_MS", 600, 0, 60000),
    // How often one player's position may be relayed.
    //
    // The mod now sends a position every 20 ms (gh_online_updaterate, 50 Hz by
    // default; it used to be 40 ms and ghosts visibly stepped between frames).
    // A throttle at or above the send interval turns every other packet into a
    // dropped one, which is worse than a lower send rate: the gaps are uneven.
    // 15 ms leaves the fastest supported cadence untouched and still refuses a
    // client that sends far faster than any build of the mod does.
    //
    // Throttling relays to slower than five a second stops being rate limiting
    // and starts being a broken game, so the range refuses values that would
    // look like a working server and play like a slideshow.
    minLineIntervalMs: integer(env, "MIN_LINE_INTERVAL_MS", 15, 0, 200),

    // --- emotes ---
    // The one thing the lobby agrees on that is not gameplay. The server carries
    // the identifier, never the artwork: chat stays plain text and every client
    // fetches its own images through its own launcher. So a shared vocabulary
    // costs one string and no Twitch connection - which is also why nobody
    // else's chat lines appear on anyone's screen.
    //
    // Unset (or 0) means the server says nothing at all and every launcher
    // keeps whatever it already had.
    emotePack: emotePack(env, "EMOTE_PACK", null),

    // --- race ---
    // Whether a spectator may start or join a race.
    //
    // A player watching somebody else is not in the game: the mod hides their
    // ghost, and during a race it puts non-participants into spectate itself.
    // Letting one type /race means a bystander can seize the race lock for the
    // whole lobby, which is the cheapest possible troll and needs no bad intent
    // to happen by accident. Off by default; a host that wants the old
    // free-for-all sets RACE_SPECTATORS=1.
    //
    // Not applied to the admin commands: those already need the operator list,
    // and kicking somebody is moderation, not gameplay - an operator watching a
    // ghost must still be able to do it.
    raceSpectators: boolean(env, "RACE_SPECTATORS", false),

    raceLobbyMs: integer(env, "RACE_LOBBY_MS", 60000, 1000, 3600000),
    // The old server could park a runner in a server-driven pause forever if
    // another runner never finished loading. Each waiting phase now expires.
    raceLoadingTimeoutMs: integer(env, "RACE_LOADING_TIMEOUT_MS", 180000, 5000, 3600000),
    raceStagingTimeoutMs: integer(env, "RACE_STAGING_TIMEOUT_MS", 120000, 5000, 3600000),
    raceMaxDurationMs: integer(env, "RACE_MAX_DURATION_MS", 7200000, 60000, 86400000),
    // Cancel much sooner when loading stops making progress. The usual way to
    // hold the race lock is to join a race and never load the save, and waiting
    // out the full loading timeout for that costs everyone else three minutes.
    //
    // This used to fire only when NOBODY had loaded, which left the obvious
    // variant open: two of three runners load, the third never does, and the
    // race sits in `loading` for the full RACE_LOADING_TIMEOUT_MS. Measured at
    // 179 s. The fuse now runs from the last load, so a stalled race is
    // cancelled 45 s after the last runner who was actually going to load did.
    raceNoProgressMs: integer(env, "RACE_NO_PROGRESS_MS", 45000, 5000, 600000),
    // The client tears down its session after ten seconds without a single
    // packet from the host (GH_CLIENT_TIMEOUT, GhostOnlineEngine.cpp:28). A
    // heartbeat slower than half of that leaves no margin for a lost datagram,
    // and one slower than ten seconds disconnects every player on the server -
    // which would look like a network fault rather than a setting. The old
    // range allowed a minute.
    heartbeatMs: integer(env, "HEARTBEAT_MS", 2000, 250, 5000),

    // --- rate limiting ---
    // Sustained packets per second accepted from one address, and from one
    // address:port.
    //
    // A legitimate client sends 50 position updates per second (it used to be
    // 25) plus the occasional chat or checkpoint. The session budget keeps the
    // same margin over that as before, roughly two and a half times the
    // legitimate rate, so a player who briefly sends a burst is not cut off
    // while a flood still is. The address budget is four sessions' worth, for
    // several players behind one NAT.
    //
    // These are the numbers that moved when the send rate doubled. Leaving
    // them at the old values would have been the quiet failure mode: a player
    // at 50 Hz sits just under the old sustained budget and loses packets the
    // moment they also type in chat.
    ratePerAddress: integer(env, "RATE_PER_ADDRESS", 480, 10, 100000),
    burstPerAddress: integer(env, "BURST_PER_ADDRESS", 960, 10, 200000),
    ratePerSession: integer(env, "RATE_PER_SESSION", 120, 5, 100000),
    burstPerSession: integer(env, "BURST_PER_SESSION", 240, 5, 200000),
    // Connect attempts per address. Deliberately small: a connect is the only
    // packet that makes the server send a burst to an address it has never
    // heard from, which is the reflection surface.
    connectRatePerMinute: integer(env, "CONNECT_RATE_PER_MINUTE", 12, 1, 6000),
    connectBurst: integer(env, "CONNECT_BURST", 4, 1, 1000),
    // Malformed or unknown traffic from one address before it is ignored
    // outright for a while.
    malformedRatePerSecond: integer(env, "MALFORMED_RATE_PER_SECOND", 5, 1, 10000),
    malformedBurst: integer(env, "MALFORMED_BURST", 20, 1, 100000),
    // Slash commands ("/race", "/ready") each produce a reply packet, so they
    // need their own budget separate from chat.
    commandRatePerSecond: integer(env, "COMMAND_RATE_PER_SECOND", 1, 1, 1000),
    commandBurst: integer(env, "COMMAND_BURST", 3, 1, 1000),
    // Race checkpoints and spectate changes. Both were completely unlimited,
    // and a spectate change fans out to every player, which made it the
    // cheapest amplifier in the protocol.
    eventRatePerSecond: integer(env, "EVENT_RATE_PER_SECOND", 4, 1, 1000),
    eventBurst: integer(env, "EVENT_BURST", 10, 1, 1000),
    // Spray upload pieces, which arrive dozens at a time and would empty a
    // budget sized for the odd checkpoint. 40 a second finishes the largest
    // allowed spray in about a second and a half; the burst covers a client
    // that sends the whole thing at once. What an upload can actually cost the
    // server is bounded by MAX_SPRAY_BYTES in limits.js, not by this.
    sprayUploadRatePerSecond: integer(env, "SPRAY_UPLOAD_RATE_PER_SECOND", 40, 1, 1000),
    sprayUploadBurst: integer(env, "SPRAY_UPLOAD_BURST", 80, 1, 4000),
    // Pieces handed to each player per 250 ms tick when they are owed somebody
    // else's spray. 16 is 64 a second, so a full 160 KB picture lands in about
    // six seconds - still a trickle rather than a burst at the client least
    // able to absorb it, but MAX_SPRAY_BYTES went up by a factor of six and at
    // the old rate of 4 the same picture would have taken half a minute.
    sprayChunksPerTick: integer(env, "SPRAY_CHUNKS_PER_TICK", 16, 1, 64),
    // Whole-process ceiling. Above this the socket drops datagrams without
    // parsing them, so a flood costs a counter increment instead of a parse.
    globalPacketsPerSecond: integer(env, "GLOBAL_PACKETS_PER_SECOND", 20000, 100, 5000000),
    // Share of that ceiling that only confirmed sessions may spend.
    //
    // Without it the ceiling is first-come-first-served, and a spoofed flood
    // above the ceiling is served first simply because there is more of it:
    // measured at 200 000 pps of four-byte junk, a connected player got 2 of
    // 500 position updates through and was swept as timed out while their
    // client was still sending. The reserve does not make the host survive a
    // volumetric attack - that needs filtering upstream - but it stops the
    // ceiling itself from being the thing that disconnects everyone.
    globalReservePercent: integer(env, "GLOBAL_RESERVE_PERCENT", 20, 0, 90),
    // Upper bound on tracked addresses. Reached only under a spoofed flood;
    // the oldest entries are evicted first.
    maxTrackedAddresses: integer(env, "MAX_TRACKED_ADDRESSES", 20000, 100, 1000000),
    maxTrackedSessions: integer(env, "MAX_TRACKED_SESSIONS", 40000, 100, 2000000),

    // --- H2: outbound credit (anti-reflection for confirmed sessions) ---
    //
    // A confirmed session receives the high-volume fan-out (positions and the
    // spray drip) only against credit it EARNS with its own accepted position
    // updates - never with chat or any other opcode (review 1, I2: 15-byte empty
    // chats used to earn the same as a position). The credit per accepted line is
    // computed at use time from the number of confirmed players and the largest
    // info packet seen recently, sized so a receiver sending only this many lines
    // a second is still fully served against senders at the protocol maximum
    // (~66/s, the 15 ms throttle). The client's floor is gh_online_updaterate 10,
    // which is 7.5-8.6 lines a second once frames quantise it, hence 8.
    //
    // The cost is honest and inherent: whatever a real client at this rate is
    // entitled to, a forged session sending lines at this rate gets too. The
    // worst-case amplification toward a forged confirmed session is therefore
    // about (players - 1) x 66.7 / FLOOR x (largest info packet / 100 B) - see
    // README.
    outboundFloorPps: integer(env, "OUTBOUND_RECEIVER_FLOOR_PPS", 8, 1, 66),
    // --- H2: liveness gate ---
    //
    // The metered fan-out skips a session we have not heard from in this long: a
    // forged endpoint that stops sending stops receiving. A shipped client sends
    // a position every 20 ms and keeps doing so on wall-clock time even while
    // paused, alt-tabbed or in the menu (gameinterface.cpp drives the cadence off
    // Plat_FloatTime, not game time), so the only time it is quiet is a level
    // transition of a few seconds - during which its ghosts are not drawn anyway
    // and heartbeats still reach it, so it is never timed out. 3 s is five missed
    // position packets past the longest normal gap.
    livenessMs: integer(env, "LIVENESS_MS", 3000, 500, 60000),
    // --- H3: slot-squat eviction ---
    //
    // When the server is full, a newcomer may evict the confirmed session with
    // the lowest rate of ACCEPTED position updates, but only if that rate is
    // below this. A shipped client sends 7.5-50 a second (gh_online_updaterate
    // 10-50, frame-quantised) even while paused or unfocused, and goes quiet only
    // during a level load. Review 2 (m1): at 5, a runner at updaterate 10 doing
    // save/load spam (8 lines/s, a 4 s load every 8 s = 4.1 lines/s) was evicted.
    // At 3 that runner stays; at updaterate 10 a player is a candidate only when
    // more than ~60 % of its last minute was loading. A forged keepalive trickle
    // (about 0.02 a second) always is. Without a client nonce this only raises
    // the cost of squatting (a forger has to stream 3 lines a second per slot).
    squatEvictPps: integer(env, "SQUAT_EVICT_PPS", 3, 1, 1000),
    // Window the inbound rate is averaged over for the eviction decision.
    squatWindowMs: integer(env, "SQUAT_WINDOW_MS", 60000, 5000, 600000),

    // --- N2 + review 3: per-session impersonation guard (server.noteWrongOwner) ---
    //
    // A confirmed session is guarded once datagrams naming it arrive from this
    // many DISTINCT PORTS of its own IP within the window - a port sweep. A real
    // client refused a name already taken behind the same NAT uses one new port
    // per attempt (5 s apart), a NAT re-bind one port, so neither trips it; an
    // endpoint holding its own confirmed session is never counted. While guarded
    // (IMPERSONATION_GUARD_MS after the trigger; only a fresh trigger extends it)
    // that session's endpoint may not chat or use commands, spectate, change
    // appearance, spray, say goodbye or rename itself, and its race finish is
    // marked unverified. The console command `unguard "Nick"` lifts it.
    impersonationTriggerPorts: integer(env, "IMPERSONATION_TRIGGER_PORTS", 8, 2, 1000),
    impersonationTriggerWindowMs: integer(env, "IMPERSONATION_TRIGGER_WINDOW_MS", 30000, 1000, 600000),
    impersonationGuardMs: integer(env, "IMPERSONATION_GUARD_MS", 180000, 10000, 86400000),
    // Review 4 (F1): an endpoint the host itself refused a name to - and TOLD
    // ("Nickname ... is already in use") - is not counted toward that name's
    // guard for this long. Its client keeps naming the name until the refusal
    // arrives, and a group of players behind one NAT who all kept the default
    // name used to add up to a sweep's worth of ports.
    impersonationRefusedPortMs: integer(env, "IMPERSONATION_REFUSED_PORT_MS", 60000, 1000, 600000),

    // --- M2: spray publish budget ---
    //
    // How many DISTINCT sprays one session may publish. A completed one-chunk
    // "spray" with a fresh crc every 25 ms used to let one player fill every
    // other client's 256-blob remote cache in about a minute and leave junk files
    // on their disks. Publishing is now a slow bucket (a couple a minute, a small
    // burst) with a hard per-session ceiling.
    sprayPublishPerMinute: integer(env, "SPRAY_PUBLISH_PER_MINUTE", 2, 1, 600),
    sprayPublishBurst: integer(env, "SPRAY_PUBLISH_BURST", 3, 1, 100),
    sprayPublishMaxPerSession: integer(env, "SPRAY_PUBLISH_MAX_PER_SESSION", 10, 1, 1000),
    // I4 + review 2 (m3): two per-receiver ceilings matching the client's two.
    // The shipped client builds a remote spray TEXTURE lazily, when a picture's
    // first stamp is drawn, and at most 48 per game run (gh_spray.cpp
    // GH_SPRAY_MAX_REMOTE_ASSETS); past that it shows nobody's spray until it is
    // restarted. So a (sender, crc) pair counts toward SPRAY_MAX_PICTURES_PER_
    // RECEIVER (40, headroom under 48) when its first stamp is relayed to that
    // receiver; stamps of further pictures are not relayed to it. It also writes
    // at most 256 new remote blobs (gh_spraynet.cpp), so the pictures FED to one
    // receiver session are capped separately (SPRAY_MAX_FED_PER_RECEIVER, 200).
    sprayMaxPicturesPerReceiver: integer(env, "SPRAY_MAX_PICTURES_PER_RECEIVER", 40, 1, 47),
    sprayMaxFedPerReceiver: integer(env, "SPRAY_MAX_FED_PER_RECEIVER", 200, 1, 255),
    // C1: a SERVER-WIDE budget on spray re-encodes. Each one is a synchronous
    // deflate (level 6, ~25 ms worst case on a fast core, more on a VDS vCPU),
    // so the total event-loop time spent re-encoding has to be bounded however
    // many sessions or addresses publish at once. A burst of 4, then one every
    // 3 s. N3: a validated picture that finds it empty waits in a fair queue
    // (at most one per session, SPRAY_REENCODE_QUEUE_MAX in all, round-robin by
    // source address) that the tick drains at this rate, one per tick at most.
    sprayReencodeBurst: integer(env, "SPRAY_REENCODE_BURST", 4, 1, 100),
    sprayReencodePerMinute: integer(env, "SPRAY_REENCODE_PER_MINUTE", 20, 1, 6000),
    sprayReencodeQueueMax: integer(env, "SPRAY_REENCODE_QUEUE_MAX", 64, 1, 1024),

    // --- protocol v2 (session secrets) ---
    // A client built for protocol v2 appends u8(2) + an 8-byte nonce to its
    // connect and is then authenticated both ways (server.js, onConnect); an
    // older build cannot be and keeps the 1.2.0 protections. Once players have
    // updated, a host may refuse legacy connects outright. Off by default:
    // turning it on locks every older build of the mod out.
    requireProtocolV2: boolean(env, "REQUIRE_PROTOCOL_V2", false),

    // --- server browser (1.4.0) ---
    // The mod's "Servers" dialog asks with the connectionless query 'i' (see
    // server.onInfoQuery). SERVER_INFO=0 leaves every query unanswered, as a
    // host before 1.4.0 would (it would also count it as an unknown opcode);
    // SERVER_INFO_PLAYERS=0 keeps the count and drops the names from the reply.
    serverName: serverName(env, "SERVER_NAME"),
    serverInfo: boolean(env, "SERVER_INFO", true),
    serverInfoPlayers: boolean(env, "SERVER_INFO_PLAYERS", true),
    // Queries one address may make, and how many may arrive at once. A browser
    // refresh is two packets per server (the query, then the query with its
    // challenge), so 8 covers a few refreshes in a row and a handful of players
    // behind one NAT.
    infoRatePerSecond: integer(env, "INFO_RATE_PER_SECOND", 2, 1, 1000),
    infoBurst: integer(env, "INFO_BURST", 8, 2, 10000),
    // Queries answered per second from every address together - the bound on
    // what the browser can cost the host, spoofed sources included (each answer
    // is an HMAC and at most 512 bytes).
    infoGlobalPerSecond: integer(env, "INFO_GLOBAL_PER_SECOND", 200, 1, 100000),

    // --- anti-reflection ---
    // A registered socket that has not yet said anything beyond its connect is
    // "unconfirmed": it may be a spoofed source address, in which case every
    // byte we fan out to it is a reflected attack on a third party. Until it
    // speaks again it gets at most this many bytes.
    unconfirmedBudgetBytes: integer(env, "UNCONFIRMED_BUDGET_BYTES", 8192, 512, 1048576),
    // ...and it is swept sooner than a confirmed session.
    unconfirmedTimeoutMs: integer(env, "UNCONFIRMED_TIMEOUT_MS", 20000, 2000, 600000),

    // --- logging ---
    logSampleIntervalMs: integer(env, "LOG_SAMPLE_INTERVAL_MS", 10000, 1000, 3600000),
  };

  if (config.burstPerAddress < config.ratePerAddress) {
    throw new ConfigError("BURST_PER_ADDRESS must be >= RATE_PER_ADDRESS");
  }
  if (config.burstPerSession < config.ratePerSession) {
    throw new ConfigError("BURST_PER_SESSION must be >= RATE_PER_SESSION");
  }
  if (config.unconfirmedTimeoutMs > config.staleTimeoutMs) {
    throw new ConfigError("UNCONFIRMED_TIMEOUT_MS must be <= STALE_TIMEOUT_MS");
  }
  // NUL обрывает имя файла в любом системном вызове, так что путь с ним - это
  // не тот путь, который написал оператор.
  if (config.accessFile.includes("\0")) {
    throw new ConfigError("ACCESS_FILE: a path may not contain a NUL byte");
  }

  config.warnings = [];
  if (config.maxPlayers > 16) {
    config.warnings.push(
      `MAX_PLAYERS=${config.maxPlayers}: only 16 slots have been load tested; ` +
        "fan-out traffic grows with the square of the player count."
    );
  }
  if (config.debug) {
    config.warnings.push("DEBUG=1: every position update is logged. Do not run a public host like this.");
  }
  if (!config.accessPersist) {
    config.warnings.push(
      "ACCESS_PERSIST=0: bans, the whitelist and the operator list are kept in memory only " +
        "and are gone at the next restart."
    );
  }
  if (config.heartbeatMs > 4000) {
    config.warnings.push(
      `HEARTBEAT_MS=${config.heartbeatMs}: the client gives up after 10s of silence, ` +
        "so a single lost heartbeat is now close to a disconnect."
    );
  }
  if (config.minLineIntervalMs > 20) {
    config.warnings.push(
      `MIN_LINE_INTERVAL_MS=${config.minLineIntervalMs}: clients send every 20 ms, ` +
        "so ghosts will visibly stutter."
    );
  }

  // 50 updates a second plus chat and checkpoints. A budget under that is not
  // rate limiting, it is a player losing position packets at random.
  if (config.ratePerSession < 60) {
    config.warnings.push(
      `RATE_PER_SESSION=${config.ratePerSession}: a playing client sends about 50 packets ` +
        "a second, so this will drop position updates from ordinary players."
    );
  }

  if (config.emotePack && config.emotePack.startsWith("user:")) {
    config.warnings.push(
      `EMOTE_PACK=${config.emotePack}: a user link resolves to whichever emote set the ` +
        "launcher picks from that account's connections. Link the emote set itself if the " +
        "account has more than one."
    );
  }

  return config;
};

module.exports = { load, ConfigError, integer, boolean, string, normaliseEmotePack, SERVER_NAME_DEFAULT };
