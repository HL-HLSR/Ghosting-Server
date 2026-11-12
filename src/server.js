"use strict";

// The dedicated host.
//
// Everything an unauthenticated datagram touches is in here, so the order of
// the checks matters as much as the checks themselves. From cheapest to most
// expensive:
//
//   1. v2 token (S)               eight bytes compared in place, and only from
//                                 the endpoint of a protocol v2 session
//   2. global packet budget       one counter, no allocation
//   3. penalty box                one map lookup, set by earlier bad traffic
//   4. datagram size              one comparison
//   5. per address budget         one map lookup
//   6. per session budget         one map lookup
//   7. parse                      allocates, so it goes last
//
// A flood therefore costs a few integer operations per packet instead of a
// parse, a roster walk and a log line. The old server parsed first and logged
// unconditionally, which meant a four byte datagram bought a kilobyte of log.

const crypto = require("crypto");
const dgram = require("dgram");

const { Message, BufferReadError } = require("./wire/reader");
const packets = require("./wire/packets");
const limits = require("./wire/limits");
const spray = require("./wire/spray");
const { sanitizeText, sanitizeChat, truncateBytes, tokenizeCommand, isSaneNumber } = require("./wire/text");
const { TokenBucketStore, GlobalLimiter } = require("./net/rate-limit");
const { SampledLogger } = require("./net/logger");
const { UserManager } = require("./game/user-manager");
const { AccessList, KIND, parseDuration, normalizeSteamId } = require("./game/access");
const { Vector3 } = require("./game/user");
const { ACTION, decideConnect, ownsSession, socketKey, addressKey } = require("./game/identity");
const { canonicalizeNickname, nicknameKey, REASON: NICKNAME } = require("./game/nickname");
const { RaceManager, RS, RACE_MAP } = require("./game/race");

// How long an address is ignored outright after it exhausts its malformed
// traffic budget. Long enough to make probing pointless, short enough that a
// player behind a broken NAT recovers on their own.
const PENALTY_MS = 30000;

// The first five bytes of a connect: an sf::Packet string of length one holding
// "c". Compared as bytes, so a boxed address can be given a path for the one
// packet a locked-out player actually needs without parsing anything.
const CONNECT_PREFIX = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x63]);

const looksLikeConnect = (buffer) =>
  buffer.length >= CONNECT_PREFIX.length && CONNECT_PREFIX.compare(buffer, 0, CONNECT_PREFIX.length) === 0;

// A disconnect is not applied immediately; see onDisconnect.
const DISCONNECT_GRACE_MS = 2000;

// Protocol v2 (session secrets). A v2 client ends its connect with the version
// byte and C, its 8-byte nonce for this connect; the host answers "07 C S" with
// S, 8 random bytes of its own. Then C goes between the type byte and the
// payload of everything sent to that session, and S right after the opcode of
// everything it sends. An off-path attacker forging the player's address sees
// neither: without C it cannot forge the host's packets to the player, and
// without S it cannot speak as the player. Both are 64-bit and never all zero
// (zero is what a client that failed to fill them would send).
const PROTOCOL_V2 = 2;
const SECRET_BYTES = 8;

const isAllZero = (bytes) => bytes.every((byte) => byte === 0);

// The fields every connect starts with: the nickname as sent, the seven
// appearance bytes, and protocol v2's optional tail, u8(2) + C, after them.
// onConnect and the lost-accept check (isLostAcceptReannounce) both read a
// connect through this, so its layout lives in one place. Every server version
// stops reading after the appearance, so older hosts ignore the tail and the
// new client still gets in there (as legacy). Anything else in that place -
// another version, a C cut short, an all-zero C - is a legacy connect, not an
// error: the tail is optional and its absence is the norm. `nonce` is C, or
// null for a legacy connect. Throws BufferReadError, like any read.
const readConnectHead = (message) => {
  const name = message.readString(limits.READ_NAME_ON_CONNECT);
  const appearance = {
    trailLength: message.readUInt8(),
    trailRed: message.readUInt8(),
    trailGreen: message.readUInt8(),
    trailBlue: message.readUInt8(),
    ghostRed: message.readUInt8(),
    ghostGreen: message.readUInt8(),
    ghostBlue: message.readUInt8(),
  };
  let nonce = null;
  if (message.readOptionalUInt8(1) === PROTOCOL_V2 && message.remaining >= SECRET_BYTES) {
    const bytes = message.readFixed(SECRET_BYTES);
    if (!isAllZero(bytes)) nonce = bytes;
  }
  // 1.4.0: the identity block, only after a valid v2 tail (a legacy connect
  // has no place for it, so the same bytes there are read as nothing). Like
  // the tail, it is optional and anything else in its place - another tag, a
  // block cut short - is no identity, not an error. null = the client sent
  // none (every build before 1.4.0).
  let identity = null;
  if (nonce && message.remaining >= IDENTITY_BYTES && message.buffer[message.offset] === IDENTITY_TAG) {
    message.skip(1);
    const flags = message.readUInt8();
    const raw = message.readFixed(SECRET_BYTES);
    const steamId = flags & IDENTITY_FLAG_STEAMID ? normalizeSteamId(raw.readBigUInt64BE(0).toString()) : null;
    identity = {
      launcher: flags & IDENTITY_FLAG_HLSR ? "hlsr" : "other",
      steamId,
      steamIdRefused: !!(flags & IDENTITY_FLAG_STEAMID) && steamId === null,
    };
  }
  return { name, appearance, nonce, identity };
};

// The 1.4.0 identity block after C: u8 tag (1), u8 flags, SteamID64 (8 bytes,
// big endian, zero when there is none). Flag bits: launched from the HLSR
// launcher; a SteamID follows. Self-reported, both of them: see access.js KIND.
const IDENTITY_TAG = 1;
const IDENTITY_BYTES = 10;
const IDENTITY_FLAG_HLSR = 1;
const IDENTITY_FLAG_STEAMID = 2;

// How a session's launcher reads in the log and the console.
const launcherText = (user) =>
  user.launcher === "hlsr" ? "HLSR" : user.launcher === "other" ? "not HLSR" : "launcher unknown";

// The server browser (1.4.0). A challenge belongs to one address:port and one
// window of INFO_CHALLENGE_WINDOW_MS, and is accepted in that window and the
// next, so it lives 15 to 30 s: long enough for the browser's second packet,
// short enough that a leaked one is soon worthless.
const INFO_QUERY_VERSION = 1;
const INFO_CHALLENGE_WINDOW_MS = 15000;
const PACKAGE_VERSION = require("../package.json").version;

const newServerToken = () => {
  let token;
  do {
    token = crypto.randomBytes(SECRET_BYTES);
  } while (isAllZero(token));
  return token;
};

// What a legacy connect is told when REQUIRE_PROTOCOL_V2 is on (50 bytes, well
// inside the client's 64-byte reason buffer).
const NEEDS_V2_REASON = "This server needs the updated Ghosting Mod Renewed";

// L4: smallest gap between two relayed held-prop MODEL changes for one player.
// Each change churns an entity on every receiver, and 50 Hz churn on an
// edict-heavy map can approach "no free edicts"; 250 ms is far below any human
// prop swap and leaves normal play untouched.
const HELD_MODEL_MIN_INTERVAL_MS = 250;

// C2: an operator PIN is 6 to 12 digits, and this many consecutive wrong PINs
// revoke the session's approval (the operator approves again from the console).
const OP_PIN = /^[0-9]{6,12}$/;
const OP_PIN_MAX_FAILURES = 5;

// N2 (review 2): opcodes refused from the endpoint of a session that is under an
// impersonation guard (see noteWrongOwner): chat and commands, goodbye,
// spectate and appearance (both held and applied when the guard ends - review
// 3, R5), spray upload and stamp. A forged datagram from the victim's real
// address:port is indistinguishable from the victim, so while someone is
// demonstrably sweeping for that port nothing from it may speak for the player. Not in the list: 'l' (the player keeps playing; their ghost keeps
// moving), 'r' (a race finish is accepted but marked unverified - refusing it
// would let the attacker cancel the real runner's finish), and 'c' (a connect
// from that endpoint naming ANOTHER nickname is refused in onConnect; the same
// nickname is a harmless duplicate). Legacy sessions only: a v2 session is never
// guarded (noteWrongOwner), since a datagram from its endpoint needs its S.
const GUARDED_OPCODES = new Set(["m", "d", "s", "v", "p", "q"]);

// I1: line-credit sizing (see lineCredit). The most position updates a second
// one sender can have relayed (the 15 ms throttle; the client caps itself at 66),
// the smallest 'l' the shipped client sends (opcode, a 1-byte name, an empty map
// and every trailing field: 100 bytes), a typical info packet (an 8-byte name on
// a typical map, no prop), and the size of one relayed spray chunk packet.
const SENDER_MAX_PPS = 1000 / 15;
const REAL_LINE_MIN_BYTES = 100;
const INFO_BYTES_FLOOR = 128;
const SPRAY_CHUNK_PACKET_BYTES = 460;

// Review 4 (M1): guard start/end lines are written in full (who, how long, the
// unguard command) - one per session per guard, which a guard's own duration
// already bounds - under a global ceiling of this many a minute, past which
// they fall back to the sampled logger.
const GUARD_LOG_BURST = 64;

// I3: an unconfirmed session older than this is the first choice to evict when
// the server is full. A real client confirms one frame after its connect.
const UNCONFIRMED_EVICT_AFTER_MS = 3000;

// The emote pack's per-session bound (sendEmotePack). The copy with the roster
// and the second one (a legacy session's at confirmation, a v2 session's with
// the next heartbeat) go out whenever they come - they are a moment apart by
// design - and any copy after those at most this often. Today only a duplicate
// connect re-sends a roster, and it is throttled to the same 5 s, so this
// changes nothing for a real client; it makes the pack's own cost a property of
// the pack rather than of whoever calls sendRoster next.
const EMOTE_PACK_FREE_SENDS = 2;
const EMOTE_PACK_RESEND_MS = 5000;

// Команды, которые игрок с OP может дать прямо из чата. Набор перечисляет ровно
// те же слова, что и switch в onAdminCommand, и служит его воротами.
//
// Ничего нового на проводе: опкод 'm' уже есть, ответ уходит обычным системным
// сообщением (тип 6). Мод не пересобирается, старый клиент ничего не замечает.
//
// Бана по адресу здесь нет сознательно: чтобы им пользоваться, надо видеть
// адреса игроков, а адресов в чате нет и заводить их там - утечка. Выдача OP
// тоже только из консоли: это единственное, что не должно быть доступно
// сессии, у которой из доказательств один подделываемый адрес отправителя.
const ADMIN_COMMANDS = new Set(["kick", "ban", "unban", "broadcast", "sprayban", "unsprayban"]);

// Идентификатор картинки в логах. Тот же CRC32, что мод использует как имя
// файла, поэтому печатается так же - восемью шестнадцатеричными цифрами, а не
// знаковым десятичным числом, которое приезжает с провода.
const crcText = (crc) => (crc >>> 0).toString(16).padStart(8, "0");

// Map names in Source are identifiers. A client that reports anything else is
// either broken or crafting a string to push through the relay into everyone
// else's client.
const MAP_NAME = /^[a-zA-Z0-9_\-.]+$/;

// Carried prop paths. The mod only ever reports the model of a physics prop,
// which in Source is always models/<something>.mdl. Accepting a leading slash
// or an arbitrary extension, as the old whitelist did, let a crafted packet ask
// every other client to load a path of the attacker's choosing.
const MODEL_PATH = /^models\/[a-zA-Z0-9_\-./]+\.mdl$/;


class GhostingServer {
  constructor(options) {
    const opts = options || {};
    this.config = opts.config;
    this.now = opts.now || (() => Date.now());
    this.setTimer = opts.setInterval || setInterval;
    this.clearTimer = opts.clearInterval || clearInterval;

    this.log =
      opts.log || new SampledLogger({ intervalMs: this.config.logSampleIntervalMs, now: this.now });

    this.socket = opts.socket || dgram.createSocket({ type: "udp4", reuseAddr: false });
    this.users = new UserManager({ maxNameLength: this.config.maxNameLength });
    // The lobby's 7TV emote pack, built once: the operator's setting is the only
    // source of it (no opcode sets or relays one), and it does not change while
    // the process runs. null = no pack, and then nothing is ever sent.
    this.emotePackPacket = this.config.emotePack ? packets.emotePack(this.config.emotePack) : null;
    // A stored nickname is not a credential. Console approval applies only to
    // this User object and expires when the session is replaced or removed.
    this.operatorSessions = new Map();

    // Баны, whitelist и OP. Готовый список передаёт index.js - он же читает
    // файл и он же имеет право упасть, если файл испорчен. Без него получается
    // список без диска: ровно то, что нужно тестам, которым нечего писать.
    this.access =
      opts.access ||
      new AccessList({ maxNameLength: this.config.maxNameLength, now: opts.wallNow || Date.now, log: this.log });

    this.running = false;
    this.timers = [];
    this.nextChatMessageId = 1;
    // Datagrams handed to the socket that have not been written yet. Only used
    // on shutdown, so the goodbye packets are not thrown away by close().
    this.inFlight = 0;

    this.stats = {
      startedAt: 0,
      received: 0,
      accepted: 0,
      sent: 0,
      bytesIn: 0,
      bytesOut: 0,
      oversized: 0,
      malformed: 0,
      unknownOpcode: 0,
      unauthorised: 0,
      reflectionBlocked: 0,
      meteredBlocked: 0,
      squattersEvicted: 0,
      // N2: packets refused from a guarded endpoint, and guards started.
      mutedUnderAttack: 0,
      impersonationGuards: 0,
      // R1 (review 3): wrong-owner names read from datagrams dropped unparsed.
      wrongOwnerPeeked: 0,
      // Protocol v2: packets from a v2 session's endpoint without its S (or
      // with a wrong one), dropped unparsed and never punished.
      badToken: 0,
      sendErrors: 0,
      disconnectsCancelled: 0,
      // 1.4.0 server browser: queries parsed, answered with a challenge, answered
      // with the info, and dropped by the info budgets.
      infoQueries: 0,
      infoChallenges: 0,
      infoReplies: 0,
      infoDropped: 0,
    };

    const now = this.now;
    const store = (capacity, refillPerSecond, maxEntries) =>
      new TokenBucketStore({ capacity, refillPerSecond, maxEntries, now });

    this.byAddress = store(
      this.config.burstPerAddress,
      this.config.ratePerAddress,
      this.config.maxTrackedAddresses
    );
    this.bySession = store(
      this.config.burstPerSession,
      this.config.ratePerSession,
      this.config.maxTrackedSessions
    );
    this.connects = store(
      this.config.connectBurst,
      this.config.connectRatePerMinute / 60,
      this.config.maxTrackedAddresses
    );
    this.malformed = store(
      this.config.malformedBurst,
      this.config.malformedRatePerSecond,
      this.config.maxTrackedAddresses
    );
    this.commands = store(
      this.config.commandBurst,
      this.config.commandRatePerSecond,
      this.config.maxTrackedSessions
    );
    // Checkpoints and spectate changes. Neither had any limit at all, and
    // spectate is the worst amplifier in the protocol: a 14 byte payload made
    // the host send a packet to every player.
    this.events = store(this.config.eventBurst, this.config.eventRatePerSecond, this.config.maxTrackedSessions);
    // Minor 2 (review 1): the client sends its goodbye 'd' exactly once, so it
    // must never lose to the events bucket a player just spent on stamps or
    // spectate toggles (their frozen ghost would stay on every screen for a
    // minute). Its own small bucket still stops a 'd' flood (M4).
    this.disconnects = store(3, 1, this.config.maxTrackedSessions);
    // Spray upload pieces. Its own bucket rather than the event one, because a
    // spray is legitimately dozens of datagrams back to back and would empty a
    // budget sized for the odd checkpoint. Generous per second, but the real
    // ceiling on what an upload can cost the server is MAX_SPRAY_BYTES, which
    // it cannot talk its way past however many packets it is allowed.
    this.sprayUploads = store(
      this.config.sprayUploadBurst,
      this.config.sprayUploadRatePerSecond,
      this.config.maxTrackedSessions
    );
    // M2: how often a session may PUBLISH a distinct spray (a completed upload),
    // as opposed to how fast its pieces may arrive (sprayUploads above). A
    // one-chunk spray with a fresh crc every 25 ms used to let one player fill
    // every other client's 256-blob cache in about a minute; publication is now
    // a slow bucket plus a hard per-session ceiling (see onSprayChunk).
    this.sprayPublish = store(
      this.config.sprayPublishBurst,
      this.config.sprayPublishPerMinute / 60,
      this.config.maxTrackedSessions
    );
    // C1: one bucket for the whole process (a single key), so the event-loop
    // time spent re-encoding sprays is bounded regardless of how many sessions or
    // addresses publish. See onSprayChunk.
    this.sprayReencode = store(this.config.sprayReencodeBurst, this.config.sprayReencodePerMinute / 60, 4);
    // Review 4 (F1): endpoint -> { key, until } for connects refused (and told)
    // because the name was taken. See noteRefusedName.
    this.refusedNamePorts = new Map();
    // N3: validated uploads waiting for that budget - address -> FIFO of
    // entries, served round-robin by address - and session key -> its one
    // entry. See enqueueReencode.
    this.reencodeQueue = new Map();
    this.reencodeQueued = new Map();
    // M1: the global ceiling on full guard start/end log lines.
    this.guardLog = store(GUARD_LOG_BURST, GUARD_LOG_BURST / 60, 4);
    // I4: the per-session publish budget reset with every new session, so one
    // address churning sessions (rotated port, new name, publish, leave) fed a
    // receiver 120 distinct pictures a minute. Publications are now also
    // budgeted per ADDRESS (four sessions' worth, MAX_SESSIONS_PER_ADDRESS, so a
    // NAT of real players is not squeezed) and per NAME KEY (a reconnect under
    // the same name does not get a fresh allowance).
    this.sprayPublishAddress = store(
      this.config.sprayPublishBurst * this.config.maxSessionsPerAddress,
      (this.config.sprayPublishPerMinute * this.config.maxSessionsPerAddress) / 60,
      this.config.maxTrackedAddresses
    );
    this.sprayPublishName = store(
      this.config.sprayPublishBurst,
      this.config.sprayPublishPerMinute / 60,
      this.config.maxTrackedSessions
    );
    // The trickle a boxed address still gets. One packet a second, two in hand:
    // enough for a real client's five-second connect retry to land, far too
    // little to be worth anything to a flood. See onDatagram.
    this.probe = store(2, 1, this.config.maxTrackedAddresses);
    // ...and the half of it reserved for datagrams that look like a connect, so
    // that ordinary junk cannot drain the path a locked-out player needs.
    // Keyed by ENDPOINT, not by address, and that is the whole point. Keyed by
    // address it was one token a second for the whole address, so an attacker
    // forging that address at two hundred connect-shaped datagrams a second took
    // every token and the real owner still never got in. An endpoint the
    // attacker does not control - the victim's ephemeral port - now has its own.
    // An attacker rotating ports gets one each, which costs a parse the address
    // budget already caps and produces no outbound at all, because a connect
    // admitted this way and then refused is refused in silence.
    this.probeConnect = store(1, this.config.connectRatePerMinute / 60, this.config.maxTrackedSessions);
    // ...and a ceiling on the whole address, because a per-endpoint token is
    // minted by whoever picks the source port. Endpoint-keyed alone, an
    // attacker rotating ports had a full bucket for every packet: measured at
    // 248 parses a second against an intended 0.20, which then drained the
    // shared address budget and took the victim's connect with it. Both are
    // required now. The address ceiling is what stops a rotating flood; the
    // endpoint token is what stops a fixed-port one from taking the ceiling.
    this.probeConnectAddress = store(2, 1, this.config.maxTrackedAddresses);
    // One connect per endpoint that has never spent one, for when the address's
    // own connect budget has been emptied by somebody forging that address.
    // See onConnect for why this cannot be used to reflect anything.
    this.connectReserve = store(1, this.config.connectRatePerMinute / 60, this.config.maxTrackedSessions);
    // 1.4.0 server browser: queries per address, and answers from the whole
    // process per second (one key). Both are charged only after the ordinary
    // checks above have let the datagram through, so a query is never cheaper
    // to send than any other packet.
    this.infoQueries = store(this.config.infoBurst, this.config.infoRatePerSecond, this.config.maxTrackedAddresses);
    this.infoGlobal = store(this.config.infoGlobalPerSecond, this.config.infoGlobalPerSecond, 4);
    // The challenge key. Fresh per process: a restart invalidates every
    // challenge out there, which costs a browser one more round trip.
    this.infoSecret = crypto.randomBytes(32);
    this.infoChallengeLifeMs = 2 * INFO_CHALLENGE_WINDOW_MS;

    this.global = new GlobalLimiter({
      capacity: this.config.globalPacketsPerSecond,
      refillPerSecond: this.config.globalPacketsPerSecond,
      reserve: Math.floor((this.config.globalPacketsPerSecond * this.config.globalReservePercent) / 100),
      now,
    });

    // address -> timestamp until which everything from it is dropped unparsed.
    this.penalty = new Map();
    // I1: the largest info packet relayed recently (see largestInfoBytes).
    this.infoWindow = { startedAt: 0, current: 0, previous: 0 };
    // name -> timestamp at which a requested disconnect becomes final.
    this.pendingDrops = new Map();
    // Players the race machine could not release. A server-driven pause is an
    // overlay the player cannot dismiss, so "we tried once and the send failed"
    // is not an acceptable end state; the sweep keeps trying.
    this.pendingUnpause = new Set();

    this.race = new RaceManager({
      config: this.config,
      log: this.log,
      now: this.now,
      say: (text) => this.serverSay(text),
      sayTo: (name, text) => this.serverSayTo(name, text),
      sound: (path) => this.broadcast(packets.playSound(path)),
      getUser: (name) => this.users.get(name),
      // Returns whether the packet was handed to the socket. The race machine
      // uses that to decide whether its bookkeeping may be updated: an earlier
      // version claimed to do this in a comment but swallowed the result, so a
      // failed release cleared the name from `paused` and the player stayed
      // frozen behind an overlay nobody was tracking any more.
      pause: (name, on, label) => {
        const user = this.users.get(name);
        if (!user) return true;
        // A release also has to survive an error that only shows up in the
        // socket callback - ENOBUFS is the realistic one - because by then the
        // machine has already been told the packet went out. Anything that
        // fails asynchronously goes back on the retry list.
        const options = on ? undefined : { onError: () => this.pendingUnpause.add(user.name) };
        return this.send(packets.serverPause(on, label), user, options);
      },
      unpauseLater: (names) => {
        for (const name of names) this.pendingUnpause.add(name);
      },
      forceMap: (name, mapname) => {
        const user = this.users.get(name);
        if (user) this.send(packets.forceMap(mapname), user);
      },
      status: (name, code, isRunner, underway) =>
        this.broadcast(packets.raceStatus(name, code, isRunner, underway)),
    });

    this.handlers = new Map([
      ["c", (message) => this.onConnect(message)],
      ["v", (message) => this.onAppearance(message)],
      ["l", (message) => this.onUpdate(message)],
      ["d", (message) => this.onDisconnect(message)],
      ["m", (message) => this.onChat(message)],
      ["r", (message) => this.onCheckpoint(message)],
      ["s", (message) => this.onSpectate(message)],
      ["p", (message) => this.onSprayChunk(message)],
      ["q", (message) => this.onSprayStamp(message)],
      ["i", (message) => this.onInfoQuery(message)],
    ]);
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  start() {
    return new Promise((resolve, reject) => {
      const onError = (error) => {
        this.socket.removeListener("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        this.socket.removeListener("error", onError);
        this.afterBind();
        resolve(this.socket.address());
      };

      this.socket.once("error", onError);
      this.socket.once("listening", onListening);
      this.socket.on("message", (buffer, rinfo) => this.onDatagram(buffer, rinfo));
      this.socket.bind(this.config.port, this.config.bindAddress);
    });
  }

  afterBind() {
    this.running = true;
    this.stats.startedAt = this.now();

    // Errors after a successful bind are the dangerous ones. The old server
    // logged them and called close(), which left a process with no socket, no
    // players and an exit code of zero: systemd saw a healthy unit and the
    // players saw a dead server. Now it is fatal and the process exits non-zero
    // so the supervisor restarts it.
    this.socket.on("error", (error) => this.onSocketError(error));

    const every = (ms, fn) => {
      const timer = this.setTimer(fn, ms);
      this.timers.push(timer);
      return timer;
    };

    every(this.config.sweepIntervalMs, () => this.guard("sweep", () => this.sweep()));
    every(250, () =>
      this.guard("tick", () => {
        this.race.tick(this.now());
        // Confirmed disconnects are resolved on this tick, not on the sweep:
        // the grace window is two seconds, and a five second sweep would make
        // a leaving player's ghost linger for up to seven.
        this.resolvePendingDrops();
        this.endExpiredGuards(this.now());
        this.drainReencodeQueue();
        this.dripSprays();
      })
    );
    every(this.config.heartbeatMs, () =>
      this.guard("heartbeat", () => {
        this.broadcast(packets.heartbeat());
        this.sendDueEmotePacks();
      })
    );

    const address = this.socket.address();
    this.log.info("Ghosting dedicated host listening on %s:%d/udp", address.address, address.port);
    this.log.info("Slots: %d. Type 'help' for a list of console commands.", this.config.maxPlayers);
    this.log.info(
      "Server name: %s (server browser %s)",
      this.config.serverName,
      this.config.serverInfo ? (this.config.serverInfoPlayers ? "on" : "on, no player names") : "off"
    );
    // So the journal says which pack the lobby is being handed (EMOTE_PACK).
    if (this.config.emotePack) this.log.info("Emote pack: %s, sent to every joining player.", this.config.emotePack);
    for (const warning of this.config.warnings) this.log.warn(warning);
  }

  // A throw inside an interval callback is an uncaught exception, and an
  // uncaught exception in Node ends the process. A bug in the sweep is not a
  // reason to disconnect everybody.
  guard(what, fn) {
    try {
      fn();
    } catch (error) {
      this.log.error("%s failed: %s", what, error && error.stack);
    }
  }

  // Idempotent: a second SIGINT during shutdown must not start another one.
  stop(reason) {
    if (!this.running) return Promise.resolve(false);
    this.running = false;

    for (const timer of this.timers) this.clearTimer(timer);
    this.timers = [];

    // Cancelling the race releases anyone frozen behind a server-driven pause.
    // Without this, "systemctl stop" left every staged runner stuck behind an
    // overlay they cannot dismiss until their own client times out.
    this.race.cancel(null);
    this.race.clearTimers();

    if (reason) {
      for (const user of this.users.values()) {
        this.send(packets.serverPause(false, ""), user, { force: true });
        this.send(packets.kick(reason), user, { force: true });
      }
    }

    this.users.clear();
    this.operatorSessions.clear();
    this.log.flush();

    return new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        resolve(true);
      };

      const closeSocket = () => {
        try {
          this.socket.close(done);
        } catch (error) {
          done();
        }
        // close() never calls back if the socket was never bound.
        setTimeout(done, 1000).unref();
      };

      // Give the goodbye packets a moment to reach the wire. dgram writes are
      // asynchronous, so closing immediately after queueing them would discard
      // exactly the packets that tell players why the server went away.
      const deadline = Date.now() + 500;
      const waitForFlush = () => {
        if (this.inFlight <= 0 || Date.now() >= deadline) {
          closeSocket();
          return;
        }
        setTimeout(waitForFlush, 10).unref();
      };
      waitForFlush();
    });
  }

  onSocketError(error) {
    this.log.error("socket error: %s", error && error.message);
    this.stop().then(() => {
      if (typeof this.onFatal === "function") this.onFatal(error);
    });
  }

  // -------------------------------------------------------------------------
  // Sending
  // -------------------------------------------------------------------------

  // `target` is either a user (preferred: enables the anti-reflection budget)
  // or a bare address record for replies to sockets we have no session for.
  // `force` bypasses the budget for the packets a possibly spoofed source is
  // allowed to receive, namely a rejection or a shutdown notice.
  //
  // Protocol v2: this is the one place C goes on the wire. Every packet to a
  // user - direct, broadcast, metered, the spray drip, roster resends, kicks -
  // comes through here, and a v2 receiver gets [type][C][payload] gathered by
  // the socket, so a broadcast still shares one payload buffer and nothing is
  // copied per receiver. `opts.nonce` is C for a bare-address target: the
  // refusal of a v2 announce, which has no session to carry it.
  send(buffer, target, options) {
    const opts = options || {};
    const user = target && target.socket ? target : null;
    const socket = user ? user.socket : target;
    const nonce = user ? (user.protocol === PROTOCOL_V2 ? user.clientNonce : null) : opts.nonce || null;
    const bytes = nonce ? buffer.length + nonce.length : buffer.length;

    if (user && !user.confirmed && !opts.force) {
      // Until this address answers for itself, everything we send it might be
      // landing on a victim who never asked for it.
      if (user.unconfirmedBytes + bytes > this.config.unconfirmedBudgetBytes) {
        this.stats.reflectionBlocked += 1;
        this.log.event("reflection-budget", `${socketKey(socket)} (${user.name})`);
        return false;
      }
      user.unconfirmedBytes += bytes;
    }

    this.stats.sent += 1;
    this.stats.bytesOut += bytes;
    this.inFlight += 1;
    const datagram = nonce ? [buffer.subarray(0, 1), nonce, buffer.subarray(1)] : buffer;

    // The callback is not optional. Without one, dgram raises send failures as
    // an 'error' event on the socket, and a socket error is fatal here - so a
    // single unreachable client, or one nftables REJECT on the way out, would
    // take the host down. With it, the failure is delivered here and stays
    // local to that destination. The try/catch covers the synchronous throw
    // from a socket that is already closing.
    try {
      this.socket.send(datagram, socket.port, socket.address, (error) => {
        this.inFlight -= 1;
        if (!error) return;
        this.stats.sendErrors += 1;
        this.log.event("send-failed", `${socketKey(socket)} ${error.code || error.message}`);
        // Most packets are a frame of a ghost's position and are not worth
        // resending: by the time the callback runs there is a newer one. A few
        // are not like that - releasing a server-driven pause is the standing
        // example - so a caller can ask to hear about it.
        if (typeof opts.onError === "function") {
          try {
            opts.onError(error);
          } catch (nested) {
            this.log.error("send error handler failed: %s", nested && nested.message);
          }
        }
      });
    } catch (error) {
      this.inFlight -= 1;
      this.stats.sendErrors += 1;
      this.log.event("send-threw", `${socketKey(socket)} ${error.code || error.message}`);
      return false;
    }
    return true;
  }

  // An unconfirmed session is skipped entirely: fan-out is the reflection
  // surface, and a real client confirms on its first position update about 40 ms
  // after connecting, so it misses at most one frame of ghosts.
  broadcast(buffer, exceptName) {
    for (const user of this.users.values()) {
      if (user.name === exceptName) continue;
      if (!user.confirmed) continue;
      this.send(buffer, user);
    }
  }

  // The metered fan-out: the same as broadcast, but a receiver is skipped unless
  // it is live and has earned the bytes (H2). Used for the high-volume streams -
  // the 50 Hz position relay and the spray drip - which are the entire measured
  // reflection amplification; rare control packets (join/leave, chat, race
  // status, sound) go through the plain broadcast so a brief silence never drops
  // a line a real client must see, and those cannot amplify. `size` lets the drip
  // charge per chunk while reusing the same gate.
  //
  // Liveness is the time since the session's last ACCEPTED position update (not
  // any packet: a chat keeps nothing alive here). A real client sends one at its
  // update rate even while paused, alt-tabbed or in the menu, so this is always
  // fresh for it; a forged confirmed session that stops sending lines stops
  // receiving within livenessMs, and even inside that window is capped by the
  // credit its lines earned. Heartbeats never come through here, so a client that
  // is merely loading keeps its slot.
  //
  // Protocol v2 (ruling 9): a confirmed v2 receiver (v2Confirmed) is not
  // charged credit, here or in the spray drip. Its first packet with S proved
  // the address asked for what it is sent (authorise), so nothing sent to it
  // lands on a victim, and a v2 player at a low update rate gets every frame.
  // The liveness gate stays, for it as for everyone: a v2 client that crashed
  // or went quiet stops being sent the 50 Hz stream after livenessMs instead of
  // getting it at a dead port until the stale timeout.
  isLive(user, at) {
    return at - user.lastLineTime <= this.config.livenessMs;
  }

  shouldMeter(user, bytes, at) {
    if (!this.isLive(user, at)) return false;
    if (user.spendCredit(bytes)) return true;
    // The lobby may have grown since this receiver's last line sized its credit
    // (it confirmed while alone, then fifteen players joined): re-size the
    // entitlement of that SAME line to the lobby as it is now, once per line. The
    // per-line ceiling - and so the amplification bound - is unchanged; only a
    // receiver that would otherwise wait a whole update interval for its next
    // line is spared the gap.
    if (user.creditResizedFor !== user.lastLineTime) {
      user.creditResizedFor = user.lastLineTime;
      const fresh = this.lineCredit(user, user.lastLineBytes);
      if (fresh > user.lastLineEarned) {
        user.earnCredit(fresh - user.lastLineEarned, fresh * 4);
        user.lastLineEarned = fresh;
        if (user.spendCredit(bytes)) return true;
      }
    }
    return false;
  }

  // I1/I2: the outbound credit one accepted position update from `user` earns,
  // computed now from the live lobby rather than from MAX_PLAYERS at startup (a
  // live `maxplayers` raise used to leave every receiver under-credited).
  //
  // Sized so a receiver sending only OUTBOUND_RECEIVER_FLOOR_PPS lines a second
  // is fully served by senders at the protocol maximum: per line it may receive
  // (others x SENDER_MAX_PPS x largest info packet) / floor bytes, plus the spray
  // drip's share while it is owed pictures. A line shorter than the smallest the
  // shipped client sends earns proportionally less, so truncated lines do not buy
  // a better ratio than real ones.
  lineCredit(user, lineBytes) {
    let others = 0;
    for (const other of this.users.values()) {
      if (other !== user && other.confirmed) others += 1;
    }
    const floor = this.config.outboundFloorPps;
    const senderMax = this.config.minLineIntervalMs > 0 ? Math.min(SENDER_MAX_PPS, 1000 / this.config.minLineIntervalMs) : SENDER_MAX_PPS;
    const positions = Math.max(1, others) * senderMax * this.largestInfoBytes();
    const drip = user.sprayFeeds.size > 0 ? this.config.sprayChunksPerTick * 4 * SPRAY_CHUNK_PACKET_BYTES : 0;
    const share = Math.min(1, lineBytes / REAL_LINE_MIN_BYTES);
    return ((positions + drip) / floor) * share;
  }

  // The largest info (type 1) packet relayed in the last two 10 s windows, never
  // below a typical one. Used to size line credit for the packets receivers are
  // really being sent (a carried prop makes them ~171 B instead of ~121 B).
  noteInfoBytes(bytes, at) {
    if (at - this.infoWindow.startedAt >= 10000) {
      this.infoWindow.previous = this.infoWindow.current;
      this.infoWindow.current = 0;
      this.infoWindow.startedAt = at;
    }
    if (bytes > this.infoWindow.current) this.infoWindow.current = bytes;
  }

  largestInfoBytes() {
    return Math.max(INFO_BYTES_FLOOR, this.infoWindow.current, this.infoWindow.previous);
  }

  broadcastMetered(buffer, exceptName) {
    const at = this.now();
    for (const user of this.users.values()) {
      if (user.name === exceptName) continue;
      if (!user.confirmed) continue;
      const served = user.v2Confirmed ? this.isLive(user, at) : this.shouldMeter(user, buffer.length, at);
      if (!served) {
        this.stats.meteredBlocked += 1;
        continue;
      }
      this.send(buffer, user);
    }
  }

  chatBuffer(name, text) {
    // Wraps so the int32 on the wire stays positive. Clients only use the id to
    // spot duplicates, so wrapping is invisible; overflowing it threw
    // ERR_OUT_OF_RANGE from inside an interval callback, which ended the
    // process.
    if (this.nextChatMessageId >= 0x7ffffffe) this.nextChatMessageId = 1;
    return packets.chat(this.nextChatMessageId++, name, text);
  }

  serverSay(text) {
    this.log.info("[SERVER] %s", text);
    this.broadcast(this.chatBuffer("SERVER", text));
  }

  // N3 (review 2): a reply to one player is logged as a SAMPLED event. Many of
  // these are automatic (refusals, notices) and a player - or someone forging
  // one - can ask for them at the rate of whatever triggers them; an unsampled
  // line each was a journal flood (160 a second measured). What an operator did
  // is logged separately ([admin]); the reply text itself goes to the player.
  serverSayTo(name, text) {
    const user = this.users.get(name);
    if (!user) return;
    this.log.event("say-to", `'${name}': ${text}`);
    this.send(this.chatBuffer("SERVER", text), user);
  }

  // -------------------------------------------------------------------------
  // Inbound
  // -------------------------------------------------------------------------

  onDatagram(buffer, rinfo) {
    this.stats.received += 1;
    this.stats.bytesIn += buffer.length;

    const address = addressKey(rinfo);
    const session = socketKey(rinfo);
    const at = this.now();

    // Does this exact endpoint own a session that has answered for itself?
    // Everything below treats those two cases differently, and the lookup is a
    // single Map hit, which is why it can afford to come first.
    const owner = this.users.bySocketKey(session);

    // 1. Protocol v2's S, before every budget, the global ceiling included.
    // From the endpoint of a v2 session S follows the opcode of every packet, a
    // 'c' included. Missing or wrong, the packet is not from the player - only
    // the endpoint the accept went to ever saw S - so it is dropped here,
    // unparsed, uncharged and never punished, and it never counts as trusted
    // traffic anywhere. Charged, it would let anyone forging the player's
    // address:port empty the player's own session budget, or the global
    // ceiling's share reserved for real players, and have real lines dropped;
    // punished, it would let them box or kick the player. Compared in place on
    // the raw datagram (hasToken): a Map hit and eight bytes, as cheap as the
    // ceiling it goes in front of.
    //
    // The one unsigned packet that goes on is a connect to a session that is
    // not confirmed yet: it may be the client whose "07 C S" was lost, which
    // never learned S and so cannot send it (ruling 5). Its owner is
    // unconfirmed, so it is untrusted traffic; it pays the budgets and is
    // checked in full once it is parsed (isLostAcceptReannounce, below).
    let signed = false;
    if (owner && owner.protocol === PROTOCOL_V2) {
      signed = this.hasToken(buffer, owner);
      if (!signed && (owner.confirmed || !looksLikeConnect(buffer))) {
        this.stats.badToken += 1;
        this.log.event("bad-token", session);
        return false;
      }
    }
    // From here an owner's packet is either a legacy one or carried S. A packet
    // with the right S is trusted even before its session confirms (final
    // review M5): S went only to this endpoint, in the accept, so it proves the
    // endpoint is real exactly as confirmation does - and the first signed line
    // is the very packet that confirms it. Treated as a stranger's, it competed
    // for a boxed address's one-a-second trickle and for the shared address
    // budget, which junk from any other port of the player's IP drains, and a
    // sustained flood kept the session from ever confirming.
    const trusted = !!owner && (owner.confirmed || signed);

    // 2. Whole process ceiling, with a share of it reserved for players who are
    // really here. The lookup above is what makes that possible: the earlier
    // version took the ceiling first and so had no idea who it was refusing.
    if (!this.global.take(1, trusted)) {
      this.log.event("global-limit", `${this.global.dropped} dropped so far`);
      return false;
    }

    // 3. Penalty box.
    //
    // Ahead of the size check, and that ordering is the whole point. The
    // earlier version checked the size first, so an oversized datagram never
    // reached the box - it went straight to punish(), which re-armed the box
    // for another PENALTY_MS. Six oversized datagrams a second from a forged
    // source address therefore held that address locked out forever: measured
    // at a box deadline that moved 300 000 ms in a 300 000 ms window. The box
    // now short-circuits everything, including the size check, so traffic from
    // a boxed sender costs one map lookup and cannot extend its own sentence.
    //
    // Scoped to the endpoint for a player who is really there, and to the whole
    // address for anyone who is not. A confirmed session (and a packet carrying
    // a v2 session's S, confirmed or not) is exempt from an address level box -
    // that is what keeps one bad client from taking its NAT neighbours down -
    // but it is NOT exempt from being boxed itself.
    if (this.penalty.has(session)) {
      if (at < this.penalty.get(session)) return false;
      this.penalty.delete(session);
    }
    if (!trusted && this.penalty.has(address)) {
      if (at < this.penalty.get(address)) {
        // A boxed ADDRESS is throttled, not silenced.
        //
        // Blocking an address outright turns 21 datagrams per thirty seconds -
        // 0.7 packets a second, from a source address anyone can forge - into
        // a lockout of whoever really owns that address. They cannot connect,
        // and neither can anyone behind the same NAT, because an address that
        // has never had a session here is never trusted.
        //
        // The trickle is deliberately tiny (see `probe`): it costs at most one
        // parse per second per boxed address, which is a 240x saving against
        // the ordinary address budget and a rounding error against a flood,
        // while leaving a genuine client's connect - retried every five
        // seconds by the DLL - a real chance of landing.
        //
        // The trickle is split in two, and the second half only accepts a
        // datagram that begins with a connect opcode. Without that, any junk at
        // all drains the one thing a locked-out player actually needs: measured
        // at ten small datagrams a second from the forged address, a real
        // client never landed a connect in two minutes of retrying. Junk now
        // drains the general half and leaves the connect half alone, so an
        // attacker who wants to block the victim's path has to send connects -
        // which are additionally charged the connect budget.
        //
        // It still does NOT make the victim reachable under a sustained flood
        // of *connects* from their own address: there the attacker competes for
        // the same tokens and wins on volume. What is bounded is the sentence,
        // not the outcome - PENALTY_MS is now a real ceiling, so the lockout
        // ends when the flood does rather than outliving it. The rest is a
        // property of an unauthenticated UDP protocol and needs filtering
        // upstream.
        // Each half is spent by its own kind of traffic and nothing else. The
        // first version let a connect-shaped datagram fall back to the general
        // half when the connect half was empty, which handed an attacker both
        // halves for the price of five bytes: measured at 2.00 parses a second
        // against 0.97 for anything else.
        if (looksLikeConnect(buffer)) {
          if (!this.probeConnect.take(session)) return false;
          if (!this.probeConnectAddress.take(address)) return false;
        } else if (!this.probe.take(address)) {
          // R1 (review 3): the evidence is counted before it is dropped.
          this.peekWrongOwner(buffer, rinfo, address, session, at);
          return false;
        }
      } else {
        this.penalty.delete(address);
      }
    }

    // 4. Size. The largest legitimate inbound packet is a spray chunk, about
    // 465 bytes (a position update is about 224); the cap is 512.
    if (buffer.length > limits.MAX_DATAGRAM_BYTES) {
      this.stats.oversized += 1;
      this.punishUnverified(address, session, owner, at, "oversized", `${session} sent ${buffer.length} bytes`);
      return false;
    }

    // 5/6. Budgets.
    //
    // A confirmed session, and a packet with a v2 session's S, is charged only
    // to its own endpoint. The version that charged the shared address budget
    // first had a nasty consequence: an attacker who knew nothing but a
    // player's IP could spend that player's budget with junk from any port,
    // freeze their lastSeen, and have the sweep remove them after sixty
    // seconds. Measured: the victim was gone, and the attacker never needed
    // their port.
    //
    // Unregistered traffic still pays the address budget first, so a flooder
    // rotating source ports cannot buy a fresh session bucket per packet.
    if (!trusted && !this.byAddress.take(address)) {
      this.log.event("address-limit", address);
      this.peekWrongOwner(buffer, rinfo, address, session, at);
      return false;
    }
    if (!this.bySession.take(session)) {
      this.log.event("session-limit", session);
      return false;
    }

    // 7. Parse.
    let message;
    let opcode;
    let afterOpcode;
    try {
      message = new Message(buffer, rinfo);
      opcode = message.readString(limits.MAX_OPCODE_LENGTH);
      afterOpcode = message.offset;
    } catch (error) {
      this.stats.malformed += 1;
      this.punishUnverified(address, session, owner, at, "malformed", `${session}: ${error.message}`);
      return false;
    }

    // Protocol v2, continued. When S is right (step 1), it is stripped, and
    // the handler reads the packet exactly as a legacy one. The unsigned
    // connect let through there is a lost-accept re-announce only with the
    // session's own nickname and C (isLostAcceptReannounce); it then goes to
    // onConnect like any duplicate connect - charged the connect budget - and
    // gets the same "07 C S" back. Anything else is a bad token after all.
    if (owner && owner.protocol === PROTOCOL_V2) {
      if (signed) {
        message.skip(SECRET_BYTES);
      } else if (!this.isLostAcceptReannounce(buffer, afterOpcode, owner)) {
        this.stats.badToken += 1;
        this.log.event("bad-token", session);
        return false;
      }
    }

    const handler = this.handlers.get(opcode);
    if (!handler) {
      this.stats.unknownOpcode += 1;
      // The opcode is attacker chosen text and used to be printed raw; the
      // logger escapes it and the sampler stops it from becoming a flood.
      this.punish(address, session, owner, at, "unknown-opcode", `${session} sent '${opcode}'`);
      return false;
    }

    // N2: the endpoint of a session under an impersonation attempt may not act
    // for it (GUARDED_OPCODES). Only that one session is affected: its NAT
    // neighbours on the same IP are other endpoints and keep full use of the
    // server. The player keeps playing - positions relay, heartbeats arrive.
    if (owner && GUARDED_OPCODES.has(opcode) && this.isGuarded(owner, at)) {
      this.stats.mutedUnderAttack += 1;
      this.log.event("guarded-session", `${session} '${opcode}'`);
      if (opcode === "s" || opcode === "v") this.keepGuardedEdge(opcode, message, owner);
      return false;
    }

    let handled;
    try {
      handled = handler(message);
    } catch (error) {
      if (error instanceof BufferReadError) {
        // Ruling 6: a v2 client still talking to a host that forgot it - the
        // host restarted, or swept or kicked the session - keeps sending S at
        // 50 Hz until its own timeout. With no session on the endpoint the
        // packet is read as legacy, S lands where the name length belongs, and
        // the address used to be boxed within two seconds. When it does read as
        // opcode + 8 bytes + name, it is the legacy "name nobody holds" case
        // (authorise): a sampled event, no malformed charge, nothing boxed. One
        // extra bounded read, on this failure path only.
        if (!owner && this.isOrphanV2(buffer, afterOpcode, opcode)) {
          this.stats.unauthorised += 1;
          this.log.event("orphan-v2", `${session} '${opcode}'`);
          return false;
        }
        this.stats.malformed += 1;
        this.punish(address, session, owner, at, "malformed", `${session} '${opcode}': ${error.message}`);
        return false;
      }
      // A bug in a handler is not a malformed packet and must not be reported
      // as one; conflating the two is how a real defect hides for months.
      this.log.error("handler '%s' failed: %s", opcode, error && error.stack);
      return false;
    }

    this.stats.accepted += 1;
    // The handler's own verdict: parsed and dispatched is not the same as
    // acted upon, and callers (tests included) care about the second one.
    return handled === true;
  }

  // Bad traffic costs a malformed-traffic budget; when that runs out the sender
  // goes into the penalty box and stops being parsed at all.
  //
  // Which sender, though, is the whole question. Blocking a whole address is
  // right for a stranger and wrong for a shared one: several players behind one
  // NAT arrive from the same public address, so boxing it would knock the
  // innocent ones offline for thirty seconds. The first attempt at this simply
  // exempted any address with a confirmed session, which then handed a
  // legitimately connected attacker an unlimited parse budget - measured at 660
  // unknown-opcode packets parsed in ten seconds with the box never closing.
  //
  // So the scope follows the evidence:
  //
  //   confirmed session on this exact endpoint -> box the endpoint
  //   anything else                            -> box the address
  //
  // A player behind the NAT keeps playing because their endpoint is exempt from
  // the address level box, and the abuser is stopped either way.
  // `owner` is the session on this exact endpoint, or null. Passing the user
  // rather than a boolean is not decoration: the oversized branch used to call
  // this as punish(address, at, "oversized", detail), one argument short, so
  // `trusted` was the string "oversized" (truthy) and `session` was a
  // timestamp. Every oversized datagram was then filed under a key that changed
  // every millisecond: the penalty box never boxed the sender, the malformed
  // store grew a bucket per millisecond (501 of them in a 500 ms flood), and
  // the event was logged with an undefined code. A boolean parameter would have
  // taken the wrong value just as quietly; a user object would not.
  punish(address, session, owner, at, code, detail) {
    const trusted = !!owner && owner.confirmed;
    this.log.event(code, detail);
    // R2 (review 3): never box or kick a session that is under an impersonation
    // attempt because of junk from its endpoint. The shipped client never sends
    // malformed, oversized or unknown datagrams, and while somebody is known to
    // be forging this player's address:port, junk "from" it is presumed forged -
    // 21 of them used to kick the victim, the very forced disconnect the guard
    // exists to stop. The datagram is dropped and counted; the session budget
    // still bounds how many are parsed.
    if (trusted && this.isGuarded(owner, at)) {
      this.log.event("guarded-junk", `${session} '${owner.name}' (${code})`);
      return;
    }
    const key = trusted ? session : address;
    if (this.malformed.take(key)) return;

    // A box that is already running is not extended. PENALTY_MS is meant to be
    // an upper bound on how long a forgeable source address can be silenced,
    // and a sentence that renews itself is not a bound at all - it is an
    // indefinite lockout with extra steps. The check above (onDatagram) means
    // a boxed sender should not reach this line anyway; this makes the property
    // true rather than merely likely.
    if (this.penalty.has(key) && at < this.penalty.get(key)) return;

    this.penalty.set(key, at + PENALTY_MS);
    // The penalty map is attacker sized, so it is bounded like every other
    // per-address structure.
    if (this.penalty.size > this.config.maxTrackedAddresses) {
      const oldest = this.penalty.keys().next();
      if (!oldest.done) this.penalty.delete(oldest.value);
    }
    this.log.event(trusted ? "penalty-box-session" : "penalty-box", key);

    // A confirmed session that has just been boxed is done talking to us for
    // the next thirty seconds, so it is not a player any more - it is a slot
    // nobody can use. The shipped client cannot produce twenty malformed or
    // unknown datagrams, so whatever is on the other end is not it. Freeing the
    // slot now, instead of waiting out the sixty second stale timeout, is the
    // difference between a full server and a playable one.
    if (trusted && owner && this.users.get(owner.name) === owner) {
      this.send(packets.kick("Your client sent malformed packets."), owner, { force: true });
      this.dropUser(owner, "boxed for malformed traffic", "kick");
    }
  }

  // Protocol v2: a datagram from a v2 session's endpoint that is too large to
  // parse, or whose opcode does not read, is counted and logged like any other,
  // but not punished. Without S it never gets this far (onDatagram, step 1);
  // what does is signed, or a connect-shaped datagram to a session not yet
  // confirmed, which anyone forging that address:port can send. Boxing the
  // endpoint (which also kicks a confirmed session) on that evidence is the
  // lever S exists to remove, so these two size and opcode checks stay
  // lenient for v2. Junk that came WITH the right S and fails in a handler is
  // the real client's and is punished as before.
  punishUnverified(address, session, owner, at, code, detail) {
    if (owner && owner.protocol === PROTOCOL_V2) {
      this.log.event(code, detail);
      return;
    }
    this.punish(address, session, owner, at, code, detail);
  }

  // Does the session's S follow the opcode? The opcode is an sf::Packet string,
  // a big-endian uint32 length and then the bytes, so S sits at 4 + length.
  // Read in place on the raw datagram, because this runs before every budget,
  // the global ceiling included, for every datagram from a v2 session's
  // endpoint, forged floods included: no Message, no copy, no allocation. The
  // compare has no early exit, so its time does not depend on how much of S a
  // guess got right; the early returns depend only on the datagram's own
  // length fields. A datagram too short to
  // hold S fails without throwing: a missing S is a bad token, not a malformed
  // packet to be punished.
  hasToken(buffer, owner) {
    if (buffer.length < 4) return false;
    const length = buffer.readUInt32BE(0);
    if (length > limits.MAX_OPCODE_LENGTH) return false;
    const at = 4 + length;
    if (buffer.length < at + SECRET_BYTES) return false;
    const token = owner.serverToken;
    let difference = 0;
    for (let i = 0; i < SECRET_BYTES; i += 1) difference |= buffer[at + i] ^ token[i];
    return difference === 0;
  }

  // Ruling 5: a 'c' without S from the endpoint of a v2 session that is still
  // UNCONFIRMED, announcing the same nickname with the same C. That is the
  // client whose "07 C S" was lost: it never learned S, and before this it was
  // dropped until the session was swept (25 s measured). An off-path attacker
  // cannot produce it, since C was chosen by the client and seen only here;
  // whoever forged the session itself only gets the same 17-byte accept sent
  // again to the address it forged, inside the unconfirmed budget and the
  // connect budget. A different C or another name is still a bad token, and
  // once a packet with S has arrived nothing unsigned is accepted at all.
  isLostAcceptReannounce(buffer, afterOpcode, owner) {
    try {
      const head = readConnectHead(new Message(buffer.subarray(afterOpcode), null));
      if (!head.nonce) return false;
      const verdict = canonicalizeNickname(head.name, this.config.maxNameLength);
      return crypto.timingSafeEqual(head.nonce, owner.clientNonce) && verdict.ok && verdict.key === this.users.key(owner.name);
    } catch (error) {
      if (error instanceof BufferReadError) return false;
      throw error;
    }
  }

  // Ruling 6: does the datagram read as opcode + 8 bytes + name, the shape of
  // a v2 client's packet? The name cap is the one the opcode's handler uses.
  isOrphanV2(buffer, afterOpcode, opcode) {
    if (buffer.length - afterOpcode < SECRET_BYTES) return false;
    try {
      const peek = new Message(buffer.subarray(afterOpcode + SECRET_BYTES), null);
      peek.readString(opcode === "c" ? limits.READ_NAME_ON_CONNECT : limits.READ_NAME_IN_SESSION);
      return true;
    } catch (error) {
      if (error instanceof BufferReadError) return false;
      throw error;
    }
  }

  // N2 + review 3: the per-session impersonation guard.
  //
  // What an attacker can and cannot do. Without a client nonce the only evidence
  // of who sent a datagram is its source address:port, and a forged 'l' from the
  // victim's real port is relayed like the victim's own, so a sweep of the
  // victim's IP learns the port in about a second from the position relay.
  // Nothing can stop that. What can be seen is the sweep: datagrams naming a
  // confirmed session from ITS OWN IP but from many other ports.
  //
  // The trigger counts DISTINCT SOURCE PORTS (review 3, R3): IMPERSONATION_
  // TRIGGER_PORTS of them within IMPERSONATION_TRIGGER_WINDOW_MS. A sweep uses a
  // port per datagram and trips it at once; one real client that asks for a name
  // already taken behind the same NAT uses one new port per attempt (5 s apart),
  // and a NAT re-bind uses one, so neither trips it by itself. A datagram from an
  // endpoint that holds its OWN confirmed session is not counted - a stock
  // client never names anybody else (its session name is pinned), so it is
  // charged as malformed traffic instead (a CGNAT neighbour used to be able to
  // guard someone for free from their own session). Datagrams from any other IP
  // are not counted: they cannot be the real 5-tuple. Someone who shares the
  // player's IP can still trip it by sending from several ports of their own.
  //
  // While guarded, for IMPERSONATION_GUARD_MS (3 min) after the trigger, the
  // session's endpoint may not chat or use commands, spray, say goodbye or
  // rename itself (GUARDED_OPCODES, onConnect); its spectate and appearance
  // changes are held until the guard ends (keepGuardedEdge); junk from it no
  // longer kicks it (punish); the same address cannot take the name over before
  // the stale timeout (onConnect); positions keep relaying; a race finish is
  // accepted but marked unverified. Only a FRESH
  // trigger (the port count met again) extends it, so holding a guard costs a
  // griefer a sweep's worth of ports per window rather than one datagram per
  // window. The player is told when it starts and when it ends, the log names
  // the console command that lifts it (unguard), and `list` shows it.
  //
  // What it is not: authentication. It is an alarm plus a short containment. An
  // attacker who can spoof the victim's IP and has learned the port can wait out
  // the guard in silence and then act as that (non-operator) player; a slow
  // sweep under the port threshold is not seen at all; and the guard itself can
  // be tripped on purpose to pause a player's chat and races (the console
  // `unguard` lifts it). The operator PIN closes the operator case. Protocol
  // v2 closes the rest for the clients that speak it, so all of this applies to
  // legacy sessions only: the guard is never armed for a v2 session (below).
  noteWrongOwner(user, socket, at) {
    if (addressKey(socket) !== addressKey(user.socket)) {
      this.log.event("wrong-owner-foreign", `${socketKey(socket)} acting as '${user.name}'`);
      return;
    }
    // R3: the sender's own confirmed session is charged, never counted.
    const senderKey = socketKey(socket);
    const sender = this.users.bySocketKey(senderKey);
    if (sender && sender.confirmed && sender !== user) {
      this.punish(addressKey(socket), senderKey, sender, at, "wrong-owner-own-session",
        `${senderKey} ('${sender.name}') acting as '${user.name}'`);
      return;
    }
    // Protocol v2: nothing can speak for a v2 session - a datagram from its own
    // endpoint needs S, and these came from other ports and were refused
    // (authorise) - so the guard has nothing to contain, and arming it would
    // only hand a sweeper a way to pause the player's chat and races. It is
    // never armed for one; the sweep is still logged, sampled.
    if (user.protocol === PROTOCOL_V2) {
      this.log.event("wrong-owner-v2", `${senderKey} acting as '${user.name}'`);
      return;
    }
    // F1: an endpoint the host just refused this very name to (and told).
    const refused = this.refusedNamePorts.get(senderKey);
    if (refused && refused.until > at && refused.key === this.users.key(user.name)) {
      this.log.event("wrong-owner-refused-name", `${senderKey} still naming '${user.name}' after being refused it`);
      return;
    }
    this.log.event("hijack-attempt", `'${user.name}' targeted from ${senderKey}`);

    // Distinct ports seen in the window, oldest first (a re-hit moves to the end).
    const port = Number(socket.port);
    if (!user.guardPorts) user.guardPorts = new Map();
    const ports = user.guardPorts;
    ports.delete(port);
    ports.set(port, at);
    const windowStart = at - this.config.impersonationTriggerWindowMs;
    for (const [p, seen] of ports) {
      if (seen >= windowStart) break;
      ports.delete(p);
    }
    if (ports.size < this.config.impersonationTriggerPorts) return;

    // A fresh trigger: the condition met (again). The window starts over.
    ports.clear();
    const guarded = this.isGuarded(user, at);
    user.guardUntil = at + this.config.impersonationGuardMs;
    if (guarded) {
      this.log.event("impersonation-guard-extended", `'${user.name}' by a fresh sweep`);
      return;
    }
    user.guardStartedAt = at;
    this.stats.impersonationGuards += 1;
    // M1: the operator must see who, for how long and how to lift it. The
    // sampled event used to print one line per 10 s across ALL players, cut at
    // 120 characters before the unguard hint; now each guard gets its own line,
    // the hint first.
    this.guardLogLine(
      "warn",
      "impersonation guard on '%s' (%s) for %s - lift with: unguard \"%s\" (%d other ports of its address named it " +
        "within %d s; chat, commands, spectate, appearance, sprays and goodbye paused)",
      [user.name, socketKey(user.socket), this.guardMinutesText(), user.name, this.config.impersonationTriggerPorts,
        Math.round(this.config.impersonationTriggerWindowMs / 1000)],
      `unguard "${user.name}" lifts it: '${user.name}' guarded for ${this.guardMinutesText()}`
    );
    for (const line of this.guardNotice()) this.serverSayTo(user.name, line);
  }

  // Review 4 (F1): the client whose connect was refused because the name is
  // taken keeps sending 'l' naming it - from the new port it bound - until the
  // refusal arrives. One player does that from one port per 5 s attempt; a
  // group behind one NAT who all kept the default name "Ghost" added up to 8
  // ports in 30 s and guarded the one who got in. So that endpoint is not
  // counted toward that name's guard for IMPERSONATION_REFUSED_PORT_MS. Bounded
  // like the other per-endpoint maps, pruned in the sweep.
  noteRefusedName(endpoint, nameKey, at) {
    this.refusedNamePorts.delete(endpoint);
    if (this.refusedNamePorts.size >= this.config.maxTrackedSessions) {
      const oldest = this.refusedNamePorts.keys().next();
      if (!oldest.done) this.refusedNamePorts.delete(oldest.value);
    }
    this.refusedNamePorts.set(endpoint, { key: nameKey, until: at + this.config.impersonationRefusedPortMs });
  }

  // Writes a guard start/end line in full while the global ceiling allows (one
  // per session per guard is the normal rate), else a sampled event whose
  // short detail keeps the essential part inside its 120 characters.
  guardLogLine(level, format, args, shortDetail) {
    if (this.guardLog.take("all")) {
      this.log[level](format, ...args);
    } else {
      this.log.event("impersonation-guard", shortDetail);
    }
  }

  guardMinutesText() {
    const ms = this.config.impersonationGuardMs;
    return ms >= 60000 ? `~${Math.max(1, Math.round(ms / 60000))} min` : `~${Math.round(ms / 1000)} s`;
  }

  // What the player is told (each line within the client's 128-byte chat buffer).
  guardNotice() {
    const wait = Math.ceil(this.guardTakeoverMs() / 1000);
    return [
      `Someone is sending packets as you from your IP: your chat, /race /ready /leave, spectate and sprays are paused for ${this.guardMinutesText()}.`,
      `To get a new port: gh_online_disconnect, wait ${wait} s, then gh_online_connect.`,
    ];
  }

  // How long a guarded session's address:port must be silent before the same
  // address may take its name over (R8, onConnect): the stale timeout. The
  // player's own goodbye is refused while guarded, so "get a new port" means
  // waiting that long before reconnecting.
  guardTakeoverMs() {
    return this.config.staleTimeoutMs;
  }

  // Review 3 (R5): the client sends spectate ('s') and appearance ('v') only
  // when they CHANGE (GhostOnlineEngine.cpp syncSpectateState), so one refused
  // while guarded is never sent again - a player who stopped spectating during
  // the guard was still "spectating" afterwards and /race told them to stop.
  // The last refused one of each is kept and applied when the guard ends.
  keepGuardedEdge(opcode, message, owner) {
    try {
      const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
      if (this.users.key(name) !== this.users.key(owner.name)) return;
      if (opcode === "s") {
        let target = sanitizeText(message.readString(limits.READ_TARGET));
        if (target.length > limits.MAX_SPECTATE_LENGTH) target = truncateBytes(target, limits.MAX_SPECTATE_LENGTH);
        owner.guardedSpectate = target;
      } else {
        owner.guardedAppearance = {
          trailLength: message.readUInt8(),
          trailRed: message.readUInt8(),
          trailGreen: message.readUInt8(),
          trailBlue: message.readUInt8(),
          ghostRed: message.readUInt8(),
          ghostGreen: message.readUInt8(),
          ghostBlue: message.readUInt8(),
        };
      }
    } catch (error) {
      // A truncated one is not a change the client made; nothing to keep.
    }
  }

  applyGuardedEdges(user) {
    if (user.guardedSpectate !== null) {
      const watched = user.guardedSpectate ? this.users.get(user.guardedSpectate) : null;
      const target = watched && watched !== user && watched.announced ? watched.name : "";
      user.guardedSpectate = null;
      if (user.spectating !== target) {
        user.spectating = target;
        this.broadcast(packets.spectate(user.name, target));
      }
    }
    if (user.guardedAppearance !== null) {
      Object.assign(user, user.guardedAppearance);
      user.guardedAppearance = null;
      this.broadcast(packets.connect(user, false), user.name);
    }
  }

  // Ends a guard (it ran out, or the console lifted it) and tells the player.
  endGuard(user, why) {
    user.guardUntil = 0;
    user.guardStartedAt = 0;
    if (user.guardPorts) user.guardPorts.clear();
    this.guardLogLine("info", "impersonation guard on '%s' ended (%s)", [user.name, why], `'${user.name}' ended: ${why}`);
    if (this.users.get(user.name) === user) {
      this.applyGuardedEdges(user);
      this.serverSayTo(user.name, "Your chat, race commands, spectate and sprays work again.");
    }
  }

  // Called from the tick: guards whose time is up are ended (and announced).
  endExpiredGuards(at) {
    for (const user of this.users.values()) {
      if (user.guardUntil > 0 && at >= user.guardUntil) this.endGuard(user, "expired");
    }
  }

  // Console: lift a guard by hand (review 3, R4).
  unguard(name, by) {
    const user = this.users.get(name);
    if (!user) return { ok: false, error: "no such player is connected" };
    if (!this.isGuarded(user, this.now())) {
      if (user.guardPorts) user.guardPorts.clear();
      return { ok: false, error: "not under an impersonation guard" };
    }
    this.log.info("[admin] %s: unguard %s", by || "console", user.name);
    this.endGuard(user, `lifted by ${by || "console"}`);
    return { ok: true, name: user.name };
  }

  // R1 (review 3): a datagram from an untrusted endpoint that is about to be
  // dropped unparsed - by the boxed address's trickle or by the address budget -
  // may still be a swept packet naming a player at that address. An attacker
  // used to box the victim's IP with junk first and dilute the trickle, so the
  // guard never saw a single wrong-owner packet while the one swept datagram
  // from the real (trusted) port leaked it. So the opcode and name are read -
  // two bounded strings every non-connect opcode starts with - but only when
  // the source IP holds a session here at all (one Map lookup; an unconfirmed
  // one suffices to look, the name must still be a CONFIRMED session at that
  // address to count), and after the global limiter, which bounds the cost:
  // review 4 measured ~9 us for a crafted 160-byte name, below a full parse.
  // Datagrams the global limiter itself drops are not seen (README, residual
  // risk 1).
  peekWrongOwner(buffer, rinfo, address, session, at) {
    if (!this.users.hasAddress(address)) return;
    let name;
    try {
      const message = new Message(buffer, rinfo);
      const opcode = message.readString(limits.MAX_OPCODE_LENGTH);
      // 'i' (the server browser) names nobody.
      if (opcode === "c" || opcode === "i" || !this.handlers.has(opcode)) return;
      name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    } catch (error) {
      return;
    }
    const user = this.users.get(name);
    if (!user || !user.confirmed) return;
    if (addressKey(user.socket) !== address || socketKey(user.socket) === session) return;
    this.stats.wrongOwnerPeeked += 1;
    this.noteWrongOwner(user, rinfo, at);
  }

  isGuarded(user, at) {
    return !!user && user.guardUntil > at;
  }

  // Every handler except connect starts here: find the session and prove the
  // packet came from the address that owns it.
  //
  // Deliberately does NOT refresh the idle timer. The old server called touch()
  // on every owned packet, including ones it was about to throw away, so a
  // session could be kept alive forever by traffic that did nothing. Each
  // handler now refreshes the timer only when the packet was actually useful.
  authorise(message, name) {
    const user = this.users.get(name);
    const socket = message.socket;
    if (!user || !ownsSession(user, socket)) {
      this.stats.unauthorised += 1;
      // C2(c): only the HIJACK SHAPE is punished - a packet naming an existing,
      // confirmed session from some other endpoint. A name nobody holds is
      // ordinary client behaviour: every client keeps sending 'l' for up to 10 s
      // after a server restart, after a lost connect, after a kick or a stale
      // sweep. Boxing the player's public IP for that (and every NAT neighbour
      // with it) would punish the real player, so it is a sampled event only.
      if (!user || !user.confirmed) {
        this.log.event("unknown-session", `${socketKey(socket)} as '${name}'`);
        return null;
      }
      // N2 (review 2): the hijack shape no longer boxes or mutes the sender's
      // address. Boxing it never stopped the one packet that matters (the
      // victim's real address:port is a confirmed endpoint and skips the box),
      // muting the whole address was bypassed in about a second through the
      // position relay and silenced NAT neighbours. The evidence is recorded
      // against the TARGETED session instead - see noteWrongOwner.
      this.noteWrongOwner(user, socket, this.now());
      return null;
    }
    // The H3 inbound rate is NOT sampled here either: only an accepted position
    // update counts (onUpdate). Empty chats at 3/s used to keep a squatter above
    // the eviction threshold (review 1, I3).
    // Outbound credit (H2) is NOT earned here: only an accepted position update
    // earns it (onUpdate -> creditLine). A chat, a stamp or an empty packet used
    // to earn as much as a position, which let a forger farm it (review 1, I2).
    // Confirmation. For a legacy session it is an activity marker only: there
    // is no unpredictable response challenge, so a spoofed connect + update can
    // self-confirm without receiving our replies. For a v2 session it is the
    // real thing: every packet from its endpoint that gets this far carried S
    // (onDatagram), which only the endpoint the accept went to has seen, so the
    // first one proves the address asked for what it is sent (confirmV2).
    if (user.confirm(this.now())) {
      this.log.info("'%s' confirmed from %s", user.name, socketKey(socket));
      if (user.protocol === PROTOCOL_V2) {
        this.confirmV2(user);
      } else {
        // Second and last automatic delivery of the emote pack to a legacy
        // session (the first went with its roster, inside the accept burst).
        // The mod announces exactly once per session, so a pack lost in that
        // burst would never be asked for again. A v2 session's roster, pack
        // first, waits for this moment (confirmV2), and its second copy for
        // the next heartbeat (sendDueEmotePacks).
        this.sendEmotePack(user);
      }
    }
    // Hearing from a session cancels a disconnect it did not ask for. Keyed by
    // the roster's display name: the packet carried whatever the sender typed.
    this.cancelPendingDrop(user.name);
    return user;
  }

  // A v2 session's first packet with S. From here it is return-routable: its
  // fan-out is not charged credit (broadcastMetered, dripSprays) and the guard
  // is never armed for it (noteWrongOwner). Two things wait for this moment
  // rather than going out with the accept (onConnect): the lobby is told it
  // joined (ruling 11), and it is sent its roster. So a forged v2 announce,
  // which never gets here, is answered with 17 bytes and nothing else, and
  // nobody else ever hears of it. The duplicate-connect throttle runs from here.
  confirmV2(user) {
    user.v2Confirmed = true;
    user.announced = true;
    this.broadcast(packets.connect(user, true), user.name);
    user.lastRosterResendAt = this.now();
    this.sendRoster(user);
    // The roster above carried the first copy of the emote pack; the second
    // rides the next heartbeat (sendDueEmotePacks), as 0.3.2 always sent two.
    if (this.emotePackPacket) user.emotePackSecondDue = true;
    // 1.4.0: an operator entry for the SteamID it announced applies now, not at
    // the connect: a forged announce never gets here (it has no S).
    this.applySteamOp(user);
  }

  // ---- 'v' appearance -------------------------------------------------------
  //
  // The same seven colour bytes a connect carries, from somebody already on the
  // roster. They used to arrive once and never again, so a player who changed
  // their ghost or trail colour mid-session kept the old one on every other
  // screen until they reconnected - and on their own screen it changed at once,
  // which made it look like everyone else's client was wrong.
  //
  // Relayed as an ordinary roster entry with the announce byte clear: a client
  // that already knows this name recolours it in place, and nobody's console
  // says "X is connecting" because somebody picked a new colour.
  onAppearance(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    const appearance = {
      trailLength: message.readUInt8(),
      trailRed: message.readUInt8(),
      trailGreen: message.readUInt8(),
      trailBlue: message.readUInt8(),
      ghostRed: message.readUInt8(),
      ghostGreen: message.readUInt8(),
      ghostBlue: message.readUInt8(),
    };

    const user = this.authorise(message, name);
    if (!user) return false;

    // Shares the event budget with chat and sprays: a colour is a thing a
    // person changes now and then, not something a client should be able to
    // stream at the lobby.
    if (!this.events.take(socketKey(message.socket))) {
      this.log.event("event-limit", `'${user.name}' appearance`);
      return false;
    }

    user.touch(this.now());
    user.trailLength = appearance.trailLength;
    user.trailRed = appearance.trailRed;
    user.trailGreen = appearance.trailGreen;
    user.trailBlue = appearance.trailBlue;
    user.ghostRed = appearance.ghostRed;
    user.ghostGreen = appearance.ghostGreen;
    user.ghostBlue = appearance.ghostBlue;

    this.broadcast(packets.connect(user, false), user.name);
    return true;
  }

  // ---- 'c' connect ----------------------------------------------------------

  onConnect(message) {
    const socket = message.socket;
    const address = addressKey(socket);
    const key = socketKey(socket);
    const at = this.now();

    // Read first, charge second.
    //
    // The budget used to be taken before the fields were read, which meant a
    // five byte datagram carrying nothing but the opcode - not a connect at
    // all, just something shaped like the start of one - spent a token from a
    // budget of twelve a minute and then threw. Ten of those a second from a
    // forged source address held that address's connect budget permanently
    // empty for 224 bytes per second, and the real owner of the address got no
    // reply to anything, ever. Reading first costs a bounded parse (a 160 byte
    // cap plus seven bytes) and sends the malformed ones where they belong:
    // the BufferReadError lands in onDatagram, which charges the malformed
    // budget and arms the penalty box. A protocol v2 announce carries C after
    // the appearance (readConnectHead); clientNonce is null for a legacy one.
    const { name: raw, appearance, nonce: clientNonce, identity } = readConnectHead(message);
    // 1.4.0: what the client says about itself. Used for the SteamID bans and
    // whitelist below, and kept on the session only if this connect registers
    // one (a duplicate announce never changes an existing session's identity).
    const steamId = identity ? identity.steamId : null;
    if (identity && identity.steamIdRefused) this.log.event("identity-steamid-invalid", key);

    // Connect budget, in two tiers.
    //
    // The per-address bucket is the anti-reflection control: a connect is the
    // one packet that makes the host answer an address it has never heard from.
    // But an address is forgeable, so a per-address budget alone means anyone
    // can hold anyone else's budget empty - and the victim shares that address,
    // so they are locked out by the very control that protects them.
    //
    // So an endpoint that has not spent a connect token of its own gets one,
    // even when the address budget is gone. An attacker rotating source ports
    // gets one each too - which is why the second tier comes with a rule: a
    // connect admitted only by the reserve, and then refused, is answered with
    // silence. Nothing is reflected at the forged address; the real client,
    // whose connect is accepted rather than refused, still gets its roster.
    const budgeted = this.connects.take(address);
    if (!budgeted && !this.connectReserve.take(key)) {
      this.log.event("connect-limit", key);
      return false;
    }
    // Rejections are only spoken aloud for a connect that paid the ordinary
    // budget. See above. A refused v2 announce gets its refusal with its own C
    // in front, like anything else the host sends a v2 client.
    const refuse = (buffer) => {
      if (budgeted) this.send(buffer, socket, { nonce: clientNonce });
      return false;
    };

    // Once players have updated, the operator may close the door on legacy
    // clients (REQUIRE_PROTOCOL_V2): they are the only sessions an off-path
    // attacker can still impersonate.
    if (!clientNonce && this.config.requireProtocolV2) {
      this.log.event("connect-legacy-refused", key);
      return refuse(packets.kick(NEEDS_V2_REASON));
    }

    // One place decides what a nickname is: the display string that goes on the
    // wire, and the key the roster is indexed by. See nickname.js for why the
    // key folds case but not accents, and why "SERVER" is refused.
    const verdict = canonicalizeNickname(raw, this.config.maxNameLength);
    if (!verdict.ok && verdict.reason === NICKNAME.EMPTY) {
      this.log.event("connect-empty-name", key);
      return refuse(packets.kick("Invalid name. Set gh_name before connecting."));
    }
    if (!verdict.ok && verdict.reason === NICKNAME.RESERVED) {
      this.log.event("connect-reserved-name", key);
      return refuse(packets.kick("The name 'SERVER' is reserved."));
    }
    const name = verdict.display;

    // N2: a connect from the endpoint of a session under an impersonation
    // attempt that names a DIFFERENT nickname would drop that session below
    // ("one socket cannot be two players") - an instant forged disconnect of the
    // victim by renaming (review 2, c-during-mute.js). Refused here, before any
    // admission work (a full server would otherwise evict a squatter for it), and
    // in silence: the endpoint is the real player's, and a kick sent to it would
    // disconnect them. The same nickname is an ordinary duplicate connect.
    const holder = this.users.bySocketKey(key);
    if (holder && this.users.key(holder.name) !== verdict.key && this.isGuarded(holder, at)) {
      this.stats.mutedUnderAttack += 1;
      this.log.event("guarded-session", `${key} 'c' as '${name}' (rename refused)`);
      return false;
    }

    // Бан и whitelist - раньше всего, что трогает ростер.
    //
    // Именно раньше: ниже есть ветка DUPLICATE, которая переотправляет ростер
    // уже зарегистрированной сессии, и ветка TAKEOVER, которая перевешивает
    // чужой ник. Забаненный, чью сессию только что сняли командой, попал бы в
    // первую из них и получил бы список игроков обратно.
    //
    // Отказ уходит через refuse(), то есть молчанием для коннекта, который
    // пролез по резерву: сказать "ты забанен" по подделанному адресу - значит
    // отправить пакет тому, кто ничего не спрашивал.
    // Бан и whitelist - раньше всего, что трогает ростер.
    //
    // Именно раньше: ниже есть ветка DUPLICATE, которая переотправляет ростер
    // уже зарегистрированной сессии, и ветка TAKEOVER, которая перевешивает
    // чужой ник. Забаненный, чью сессию ещё не сняли, попал бы в первую из них
    // и получил бы список игроков обратно.
    //
    // Отказ уходит через refuse(), то есть молчанием для коннекта, который
    // пролез по резерву: сказать "ты забанен" по подделанному адресу - значит
    // отправить пакет тому, кто ничего не спрашивал.
    const ban = this.access.banFor(name, address, steamId);
    if (ban) {
      this.log.event("connect-banned", `${key} ('${name}') by ${ban.kind}`);
      return refuse(packets.kick(this.access.banNotice(ban)));
    }
    if (!this.access.isAllowed(name, address, steamId)) {
      this.log.event("connect-not-whitelisted", `${key} ('${name}')`);
      return refuse(packets.kick("This server is whitelisted. Ask the operator for access."));
    }

    const existing = this.users.get(name);
    const decision = decideConnect({
      existing,
      socket,
      now: at,
      // Review 3 (R8): a guarded session is not handed over to "the same
      // address" after a mere 10 s of silence - an attacker spoofing that
      // address reads a level load off the relay and takes the name. It waits
      // for the stale timeout, like a takeover from anywhere else. A confirmed
      // v2 session waits for it too, guard or not (decideConnect, final review
      // M3): no connect from another endpoint carries its S.
      takeoverAfterMs: existing && this.isGuarded(existing, at) ? this.config.staleTimeoutMs : this.config.takeoverAfterMs,
      staleTimeoutMs: this.config.staleTimeoutMs,
    });

    if (decision.action === ACTION.DUPLICATE) {
      // The client re-announced. Resend the roster - but do NOT treat this as
      // proof that the address is real.
      //
      // A connect is the one packet an attacker can forge for free, so
      // confirming a session because a second connect arrived from the same
      // forged address defeats the whole point of the flag. Measured on the
      // version that did: two forged connects, 50 bytes in, bought 45 205 bytes
      // of fan-out to the victim over ten seconds - 904x by volume - plus a
      // sixty second leash instead of twenty and immunity from the penalty box.
      // Confirmation now happens only in authorise(), i.e. only for an opcode
      // that requires an already registered session.
      // H2(c): a connect is forgeable, so a duplicate connect must buy nothing.
      // It no longer touch()es the session (which extended a forged session's
      // leash from 20 s to 60 s), the roster resend is rate-limited to one every
      // 5 s per session (a forged duplicate-connect flood used to re-send the
      // whole roster every time), and the spray re-queue inside sendRoster only
      // ever queues chunks a receiver has not already been sent - see queueSpray,
      // which keeps each receiver's per-sender cursor rather than refilling it.
      // Keyed by the roster's display name, not the spelling in this packet.
      this.cancelPendingDrop(existing.name);
      // Protocol v2: the same accept again, same C and S, for a client whose
      // first one was lost. A 'c' from a v2 session's endpoint gets here only
      // with S, or - while the session is unconfirmed - with the same name and
      // the same C (onDatagram, isLostAcceptReannounce), which only the client
      // or whoever forged the session knows, so this is not a free packet for
      // anyone else. A duplicate never changes a session's protocol
      // either way: a forgeable v2 tail on a legacy session's endpoint would
      // otherwise have the host prefix every packet to a client that cannot
      // read them. Not confirmed yet, a v2 session gets the accept and nothing
      // else, as with its first announce: its roster follows its first packet
      // with S (confirmV2).
      if (existing.protocol === PROTOCOL_V2) {
        this.send(this.acceptPacket(existing), existing);
        if (!existing.v2Confirmed) return true;
      }
      if (at - existing.lastRosterResendAt >= 5000) {
        existing.lastRosterResendAt = at;
        this.sendRoster(existing);
        this.log.info("Re-sent roster to '%s' (duplicate connect).", name);
      } else {
        this.log.event("duplicate-connect-throttled", key);
      }
      return true;
    }

    if (decision.action === ACTION.REJECT) {
      this.log.event("connect-name-in-use", `${key} wanted '${name}'`);
      // F1: only a SPOKEN refusal exempts the endpoint. A silent one (admitted
      // by the per-endpoint reserve) is free for anyone who picks a fresh port,
      // so exempting it would let a sweep hide behind forged connects; a spoken
      // one is capped by the address connect budget.
      if (budgeted) this.noteRefusedName(key, verdict.key, at);
      // The client reads this into char[64]; packets.js truncates to fit, and
      // "Nickname '" + 31 + "' is already in use." is 61 characters plus the
      // terminator, so at the configured name limit it never has to.
      //
      // The rejected newcomer is told nothing else and, more importantly,
      // nothing about the existing player changes: no unregister, no socket
      // rebind, no announcement. A refused connect must not be a way to touch
      // somebody else's session.
      return refuse(packets.kick(`Nickname '${name}' is already in use.`));
    }

    // Admission is decided BEFORE anyone is removed.
    //
    // The first version unregistered the previous holder and only then checked
    // the slot limits. When those rejected the newcomer, the old player was
    // already gone from the roster - and because a takeover is deliberately
    // silent, no type 4 went out either, so every other client kept rendering a
    // ghost for a player the server no longer had. Two attackers holding the
    // per-address slots could evict any player they knew the nickname of.
    //
    // A takeover replaces a slot rather than adding one, so it is exempt from
    // the count checks it would otherwise fail against itself.
    const takingOver = decision.action === ACTION.TAKEOVER;
    // A takeover from the same address moves nothing: the slot was already
    // counted against that address, so checking the cap would reject the
    // reconnect of the very player who owns it. From a different address the
    // slot really does move, and the cap applies.
    const reclaimingOwnSlot = takingOver && existing && addressKey(existing.socket) === address;

    if (!takingOver && this.users.count() >= this.config.maxPlayers) {
      // H3: before turning a real player away, try to reclaim a slot a squatter
      // is holding. A forged trickle of keepalives (about one packet per session
      // per 55 s) used to keep every slot indefinitely with nothing traceable to
      // the attacker. The lowest-inbound-rate session is evicted, but only if its
      // rate is far below what any real client sends.
      if (!this.evictSquatter(at)) {
        this.log.event("server-full", `${key} ('${name}')`);
        return refuse(packets.kick("Ghost server is full."));
      }
    }

    // Slots per address. Without this, one host rotating its source port fills
    // every slot in seconds and keeps them, and the connect budget does not
    // help because it is spent on accepted connects too.
    if (!reclaimingOwnSlot && this.sessionsFrom(address) >= this.config.maxSessionsPerAddress) {
      this.log.event("address-slot-limit", `${key} ('${name}')`);
      return refuse(packets.kick("Too many connections from your address."));
    }

    if (takingOver) {
      this.log.info("'%s' taken over by %s (%s).", name, key, decision.reason);
      // Silent: the ghost is immediately replaced by the same name, so other
      // clients keep it rather than seeing a leave and a join.
      this.users.unregister(existing.name, socketKey(existing.socket));
      this.operatorSessions.delete(this.users.key(existing.name));
      // Same reason as the duplicate branch: the drop was filed under the
      // previous holder's spelling, and leaving it armed killed the session
      // that had just taken the name over.
      this.pendingDrops.delete(existing.name);
    }

    // A second session from the same address:port replaces the first: one
    // socket cannot be two players. Compared on the canonical key, so
    // reconnecting as "ALICE" from Alice's socket is a rename of one session
    // and not a second registration.
    const previous = this.users.bySocketKey(key);
    if (previous && this.users.key(previous.name) !== verdict.key) {
      this.dropUser(previous, "replaced by a new connect from the same socket", "left");
    }

    const user = this.users.register(name, socket, appearance, at, key);
    // I3: taking over a holder that never confirmed must not reset its clock. A
    // forger re-sending 'c' from a rotated port every 10 s used to get a fresh
    // connectedAt (and a fresh 20 s unconfirmed leash) each time, so the slot
    // was never swept and never looked old enough to evict. The new holder keeps
    // the original connect time; a real client confirms within a frame anyway.
    // Review 2 (m7): only from the SAME address - the forger's pattern. A real
    // player taking the name over from their own address must not inherit a
    // forged holder's 20 s-old clock and be swept or evicted as a stale
    // unconfirmed session before their first position update arrives.
    if (takingOver && existing && !existing.confirmed && addressKey(existing.socket) === address) {
      user.connectedAt = Math.min(user.connectedAt, existing.connectedAt);
      user.lastSeen = Math.min(user.lastSeen, existing.lastSeen);
    }
    // Protocol v2: C as announced, S fresh for this session. A reconnect from
    // a new port is a new session and gets a new S.
    if (clientNonce) {
      user.protocol = PROTOCOL_V2;
      user.clientNonce = clientNonce;
      user.serverToken = newServerToken();
    }
    if (identity) {
      user.launcher = identity.launcher;
      user.steamId = identity.steamId;
    }
    this.log.info(
      "Registered '%s' (%s%s, %s%s).",
      name,
      key,
      user.protocol === PROTOCOL_V2 ? ", v2" : "",
      launcherText(user),
      user.steamId ? `, steam ${user.steamId}` : ""
    );

    this.send(this.acceptPacket(user), user);
    // Protocol v2: the join announcement and the roster wait for the session's
    // first packet with S (confirmV2). Until then an address that has not shown
    // it asked gets the 17-byte accept and nothing more, less than the announce
    // it answers, so a forged v2 announce is no reflector, and the lobby is not
    // told about a player who may not exist (ruling 11). If it took over a name
    // the lobby already knows (silently, above), it inherits that: the lobby
    // still has that ghost and must be told when this session goes. A legacy
    // session can never show it asked, so it is announced and sent the roster
    // now, inside the unconfirmed budget, as in 1.2.0.
    if (user.protocol === PROTOCOL_V2) {
      user.announced = takingOver && !!existing && existing.announced;
    } else {
      this.broadcast(packets.connect(user, true), name);
      user.announced = true;
      this.sendRoster(user);
    }
    return true;
  }

  // Type 7. Legacy: the bare type byte (packets.js). v2: S after it, and send()
  // puts C in between, so the client reads "07 C S".
  acceptPacket(user) {
    const accept = packets.connectAccepted();
    return user.protocol === PROTOCOL_V2 ? Buffer.concat([accept, user.serverToken]) : accept;
  }

  sessionsFrom(address) {
    let count = 0;
    for (const user of this.users.values()) {
      if (addressKey(user.socket) === address) count += 1;
    }
    return count;
  }

  // H3: reclaim a slot held by a squatter when the server is full.
  //
  // The session with the lowest inbound packet rate over squatWindowMs is a
  // candidate only if that rate is below squatEvictPps - well under the 50 pps a
  // shipped client sends even while paused or alt-tabbed, and still well under
  // what the worst real case (a few seconds of silence during a level load)
  // leaves on a 60 s average. So a real player is never evicted to admit
  // another, while a forged keepalive trickle (about 0.02 pps) always loses its
  // slot. The evictee is sent a type 5 kick and a type 4 leave is broadcast
  // (dropUser), exactly like any other removal, so every other client's roster
  // stays correct. Returns true when a slot was freed.
  evictSquatter(at) {
    // I3, first choice: a session that has never confirmed for more than a few
    // seconds. A real client confirms with its first position update about one
    // frame after its connect, so an old unconfirmed session is a forged connect
    // holding a slot (review 1 measured 16 of them, re-sent once a second,
    // keeping a real client out 40 times out of 40). Oldest first.
    let stale = null;
    for (const user of this.users.values()) {
      if (user.confirmed || at - user.connectedAt < UNCONFIRMED_EVICT_AFTER_MS) continue;
      if (!stale || user.connectedAt < stale.connectedAt) stale = user;
    }
    if (stale) {
      this.stats.squattersEvicted += 1;
      this.log.event("squatter-evicted", `'${stale.name}' (never confirmed) ${socketKey(stale.socket)}`);
      // Silent: an unconfirmed session has given no evidence its address is
      // real, so nothing is sent to it (see the unconfirmed reflection budget).
      this.dropUser(stale, "evicted: never confirmed its address", "timeout");
      return true;
    }

    // Ruling 14 (final review M4): a confirmed v2 session is never a candidate.
    // This tier exists against forged sessions that keep a slot with a trickle
    // of position updates, and a v2 session confirmed with S cannot be forged;
    // the only v2 player it could ever pick is a real runner who is loading or
    // idle. Such a player still leaves with the stale sweep once silent for
    // STALE_TIMEOUT_MS, so the cost is that an idle real v2 player can hold a
    // slot on a full server until then.
    let worst = null;
    let worstRate = Infinity;
    for (const user of this.users.values()) {
      if (!user.confirmed || user.v2Confirmed) continue;
      // A session younger than the averaging window has not been here long
      // enough to judge: a real client that joined a second ago has only sent a
      // packet or two, so its measured rate is low through no fault of its own.
      // Waiting a full window before a session can be called a squatter also
      // means a brand-new player is never evicted to admit another - only a
      // session that has had a minute to prove it sends like a client, and did
      // not, loses its slot.
      if (at - user.confirmedAt < this.config.squatWindowMs) continue;
      const rate = user.inboundRate(at, this.config.squatWindowMs);
      if (rate < worstRate) {
        worstRate = rate;
        worst = user;
      }
    }
    if (!worst || worstRate >= this.config.squatEvictPps) return false;
    this.stats.squattersEvicted += 1;
    this.log.event("squatter-evicted", `'${worst.name}' (${worstRate.toFixed(3)} pps) ${socketKey(worst.socket)}`);
    this.send(packets.kick("Disconnected to make room for a returning player."), worst, { force: true });
    this.dropUser(worst, `evicted as a slot squatter (${worstRate.toFixed(3)} pps)`, "kick");
    return true;
  }

  confirmedSessionsFrom(address) {
    let count = 0;
    for (const user of this.users.values()) {
      if (user.confirmed && addressKey(user.socket) === address) count += 1;
    }
    return count;
  }

  // The roster a joining client needs: everyone already here, announced
  // silently so the newcomer doesn't see a wall of join lines.
  //
  // Spectate state goes with it. Clients announce it edge-triggered - only
  // when it changes - so a player who was already watching somebody when the
  // newcomer joined would stay unaccounted for until they stopped. That was
  // merely a missing line in the player list; now the mod also hides a
  // watching player's ghost, so the newcomer would have seen a body standing
  // in somebody else's shoes with nothing to explain it.
  sendRoster(user) {
    // Ahead of the roster fan-out on purpose: it is the setting the whole lobby
    // has to agree on, and going first means it is charged first against the
    // unconfirmed reflection budget rather than being the packet that trips it.
    this.sendEmotePack(user);

    for (const other of this.users.values()) {
      if (other.name === user.name) continue;
      // A v2 session the lobby has not been told about yet (not confirmed:
      // confirmV2) is not in anyone's roster either. A roster entry is an
      // announcement in all but the chat line, and such a session leaves
      // without a type 4, so the receiver would keep its ghost for good. It is
      // announced to this receiver, like to everyone, when it confirms.
      if (!other.announced) continue;
      this.send(packets.connect(other, false), user);
      if (other.spectating) this.send(packets.spectate(other.name, other.spectating), user);
      // Queued, not sent: this is potentially every player's picture, and the
      // tick hands them over a few pieces at a time. See queueSpray.
      this.queueSpray(user, other);
    }

    // Состояние гонки - по той же причине. Статусы уходят в момент изменения,
    // поэтому вошедший посреди гонки не знал бы, что она идёт: у него не было
    // бы ни колонки статуса, ни повода уйти в наблюдение вместо того, чтобы
    // бегать по карте среди участников.
    for (const row of this.race.statusSnapshot())
      this.send(packets.raceStatus(row.name, row.code, row.isRunner, row.underway), user);
  }

  // The lobby's shared emote vocabulary (type 14): one identifier, no artwork.
  // The host never talks to 7tv.io - each client hands this to its own
  // launcher, which owns every 7TV request and the allowlist that goes with it.
  // Nobody joins a Twitch chat for it, so no foreign chat line ever reaches
  // anyone's screen.
  //
  // Who sends it: only the operator, through EMOTE_PACK. No opcode carries a
  // pack - the mod never had one - so nothing a datagram says can change it or
  // make the host relay one. Who gets it: the session that joins, and only it,
  // twice, as in 0.3.2, so one lost datagram cannot lose it for the session: a
  // legacy session with its roster (sendRoster) and once more when it confirms
  // (authorise); a v2 session with its roster at confirmation (confirmV2) and
  // once more with the next heartbeat (sendDueEmotePacks). The lobby is not
  // told again when somebody joins. A refused connect gets its refusal and
  // nothing else; a v2 session gets nothing before its first packet with S.
  // Framing is send()'s: [14][C][payload] to a v2 session, the 0.3.2 bytes to a
  // legacy one. Nothing here bypasses the unconfirmed budget.
  //
  // Bounded per session (EMOTE_PACK_RESEND_MS): two copies free, then one per
  // 5 s however often the roster is re-sent. The count lives on the User and
  // goes with it, so a rejoin is a newcomer and is fed again - and the client
  // drops the lobby's pack itself when it leaves (clearEmotePack in the mod's
  // disconnect). Nothing else is kept: the packet is built once, at startup.
  //
  // A host with no pack configured sends nothing, so the connect path is
  // byte-for-byte what it was before this existed.
  sendEmotePack(user) {
    if (!this.emotePackPacket) return false;
    const at = this.now();
    if (user.emotePackSends >= EMOTE_PACK_FREE_SENDS && at - user.emotePackSentAt < EMOTE_PACK_RESEND_MS) {
      this.log.event("emote-pack-throttled", `'${user.name}'`);
      return false;
    }
    if (!this.send(this.emotePackPacket, user)) return false;
    user.emotePackSends += 1;
    user.emotePackSentAt = at;
    return true;
  }

  // The v2 second copy, on the heartbeat tick after confirmV2: 0 to
  // HEARTBEAT_MS after the first, on a datagram of its own. Due once; inside
  // the same per-session bound, so a roster re-sent in between (which already
  // spent the second free copy) leaves it nothing to send. One flag per User,
  // walked only when a pack is configured.
  sendDueEmotePacks() {
    if (!this.emotePackPacket) return;
    for (const user of this.users.values()) {
      if (!user.emotePackSecondDue) continue;
      user.emotePackSecondDue = false;
      this.sendEmotePack(user);
    }
  }

  // ---- 'i' server browser query (1.4.0) ------------------------------------
  //
  // The mod's "Servers" dialog asks for the name, version, player count and
  // lobby of a host it has not joined: a connectionless request from an
  // address nobody verified, which is the shape of a reflection attack. So it
  // works like A2S:
  //
  //   query  "i" u8(1) u32 request id u32 challenge      14 bytes
  //   a challenge that is 0, wrong or stale  -> type 17, 9 bytes: a fresh one
  //   the challenge this host gave that same address:port -> type 18, <= 512
  //
  // A forged source never sees its challenge (it went to the victim), so it
  // never gets more back than it sent; whoever does see the challenge is the
  // address that asked. Before any of this the datagram has passed the
  // ordinary checks in onDatagram, and here it pays a per-address and a
  // whole-process info budget. Over budget, unknown version or SERVER_INFO=0:
  // dropped in silence and never punished. Nothing about a query touches the
  // roster.
  onInfoQuery(message) {
    const socket = message.socket;
    const version = message.readUInt8();
    const requestId = message.readInt32() >>> 0;
    const challenge = message.readInt32() >>> 0;
    this.stats.infoQueries += 1;

    if (!this.config.serverInfo) {
      this.log.event("info-off", socketKey(socket));
      return false;
    }
    // A later browser may ask in a format this host does not speak; it then
    // shows the host as not answering, which is the truth.
    if (version !== INFO_QUERY_VERSION) {
      this.log.event("info-version", `${socketKey(socket)} asked in format ${version}`);
      return false;
    }
    if (!this.infoQueries.take(addressKey(socket)) || !this.infoGlobal.take("all")) {
      this.stats.infoDropped += 1;
      this.log.event("info-limit", socketKey(socket));
      return false;
    }

    const at = this.now();
    if (challenge === 0 || !this.infoChallengeValid(socket, challenge, at)) {
      this.stats.infoChallenges += 1;
      this.send(packets.infoChallenge(requestId, this.infoChallengeFor(socket, Math.floor(at / INFO_CHALLENGE_WINDOW_MS))), socket);
      return true;
    }
    this.stats.infoReplies += 1;
    this.send(this.serverInfoPacket(requestId), socket);
    return true;
  }

  // HMAC-SHA256 of the endpoint and the window under a per-process key, cut to
  // 32 bits (never 0, which means "none"). Nothing is stored per asker, so a
  // flood of queries costs no memory.
  infoChallengeFor(socket, window) {
    const digest = crypto
      .createHmac("sha256", this.infoSecret)
      .update(`${socket.address}|${socket.port}|${window}`)
      .digest();
    return digest.readUInt32BE(0) || 1;
  }

  infoChallengeValid(socket, challenge, at) {
    const window = Math.floor(at / INFO_CHALLENGE_WINDOW_MS);
    return challenge === this.infoChallengeFor(socket, window) || challenge === this.infoChallengeFor(socket, window - 1);
  }

  // What type 18 says. Players are the confirmed sessions - an announce that
  // never answered is not somebody in the lobby - and the list says only what
  // the lobby itself could see (name, spectating, racing, operator) plus what
  // the client said about itself (HLSR). Never an address or a SteamID.
  serverInfoPacket(requestId) {
    const F = packets.INFO_PLAYER_FLAG;
    const S = packets.INFO_SERVER_FLAG;
    const players = [];
    const maps = new Map();
    for (const user of this.users.values()) {
      if (!user.confirmed) continue;
      let flags = 0;
      if (user.launcher === "hlsr") flags |= F.HLSR;
      if (user.launcher !== null) flags |= F.IDENTIFIED;
      if (this.operatorSessions.get(this.users.key(user.name)) === user) flags |= F.OP;
      if (user.spectating) flags |= F.SPECTATING;
      if (this.race.isRunner(user.name)) flags |= F.RUNNER;
      if (user.protocol === PROTOCOL_V2) flags |= F.V2;
      players.push({ name: user.name, flags });
      if (user.mapname && user.mapname !== "unknown") maps.set(user.mapname, (maps.get(user.mapname) || 0) + 1);
    }
    let map = "";
    let most = 0;
    for (const [name, count] of maps) {
      if (count > most) {
        most = count;
        map = name;
      }
    }
    let flags = S.STEAM_IDENTITY;
    if (this.config.requireProtocolV2) flags |= S.REQUIRE_V2;
    if (this.access.whitelistEnabled) flags |= S.WHITELIST;
    if (this.config.opChatCommands) flags |= S.OP_CHAT;
    const phase = this.race.phase;
    return packets.serverInfo(
      requestId,
      {
        name: this.config.serverName,
        version: PACKAGE_VERSION,
        protocol: PROTOCOL_V2,
        flags,
        players: players.length,
        maxPlayers: this.config.maxPlayers,
        race: Object.hasOwn(packets.RACE_PHASE, phase) ? packets.RACE_PHASE[phase] : 0,
        map,
      },
      this.config.serverInfoPlayers ? players : []
    );
  }

  // ---- 'l' position update --------------------------------------------------

  onUpdate(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    let mapname = sanitizeText(message.readString(limits.READ_MAP));

    const velocity = new Vector3(message.readFloat(), message.readFloat(), message.readFloat());
    const position = new Vector3(message.readFloat(), message.readFloat(), message.readFloat());
    const pitch = message.readFloat();
    const yaw = message.readFloat();

    // Everything from here is a trailing optional field: a client built before
    // it was added simply stops, and the packet ends.
    const paused = message.readOptionalUInt8(0);
    const weapon = message.readOptionalUInt8(0);
    let hp = message.readOptionalFloat(-1);
    let armor = message.readOptionalFloat(-1);
    let clip = message.readOptionalFloat(-1);
    let ammo = message.readOptionalFloat(-1);

    // Carried prop. Anything that is not a model path is treated as holding
    // nothing: this string is relayed to every other client, which hands it to
    // the engine.
    let heldModel = sanitizeText(message.readOptionalString(limits.READ_MODEL, ""));
    if (heldModel.length > limits.MAX_MODEL_LENGTH || heldModel.includes("..") || !MODEL_PATH.test(heldModel)) {
      heldModel = "";
    }

    let heldPos = new Vector3(
      message.readOptionalFloat(0),
      message.readOptionalFloat(0),
      message.readOptionalFloat(0)
    );
    let heldAng = new Vector3(
      message.readOptionalFloat(0),
      message.readOptionalFloat(0),
      message.readOptionalFloat(0)
    );
    if (
      ![heldPos.x, heldPos.y, heldPos.z, heldAng.x, heldAng.y, heldAng.z].every((n) =>
        isSaneNumber(n, limits.MAX_COORDINATE)
      )
    ) {
      heldModel = "";
      heldPos = new Vector3(0, 0, 0);
      heldAng = new Vector3(0, 0, 0);
    }

    let eyeZ = message.readOptionalFloat(64);
    if (!isSaneNumber(eyeZ, limits.MAX_COORDINATE) || eyeZ < 0 || eyeZ > limits.MAX_EYE_HEIGHT) eyeZ = 64;

    // Keys held, a bitmask the client packs (GhostKeyBit_t in the mod's
    // game/shared/ghost_keys.h). Relayed so a first-person spectator sees the
    // runner's own keys instead of their own. Anything that is not a plain
    // integer inside the mask becomes 0: it is drawn as pressed keys, and a
    // stray high bit would light a cell that does not exist.
    let keys = message.readOptionalFloat(0);
    if (!Number.isInteger(keys) || keys < 0 || keys > limits.MAX_KEY_MASK) keys = 0;

    const user = this.authorise(message, name);
    if (!user) return false;

    // Garbage numbers are dropped rather than relayed: a NaN position puts
    // another player's ghost nowhere and the client follows it there.
    const coordinates = [velocity.x, velocity.y, velocity.z, position.x, position.y, position.z, pitch, yaw];
    if (!coordinates.every((n) => isSaneNumber(n, limits.MAX_COORDINATE))) {
      this.log.event("insane-coordinates", user.name);
      return false;
    }

    // The map name is relayed verbatim into every other client's
    // OnlineRunLine::map[32]. The old server accepted a kilobyte of arbitrary
    // bytes here while carefully validating the model path two fields later.
    if (mapname.length > limits.MAX_MAP_LENGTH || !MAP_NAME.test(mapname)) mapname = "unknown";

    // Per user throttle, at the legitimate ~25/s cadence. A client that sends
    // faster stays connected but does not get its traffic multiplied by the
    // player count.
    const at = this.now();
    if (at - user.lastLineTime < this.config.minLineIntervalMs) return false;
    user.lastLineTime = at;
    user.touch(at);

    if (!isSaneNumber(hp, limits.MAX_COORDINATE)) hp = -1;
    if (!isSaneNumber(armor, limits.MAX_COORDINATE)) armor = -1;
    if (!isSaneNumber(clip, limits.MAX_COORDINATE)) clip = -1;
    if (!isSaneNumber(ammo, limits.MAX_COORDINATE)) ammo = -1;

    // L4: the receiving server.dll creates and removes an entity on every
    // heldModel change (GhostEntity.cpp), and freed edicts are not reused for
    // about a second, so a peer alternating two precached models every 20 ms
    // could churn an edict 50 times a second on every client on the map. Relay
    // a model CHANGE at most every HELD_MODEL_MIN_INTERVAL_MS per user, keeping
    // the previous model in between. Clearing the prop (back to "") is never
    // throttled - dropping a prop must look instant.
    if (heldModel !== user.heldModel && heldModel !== "") {
      if (at - user.lastHeldModelChangeAt < HELD_MODEL_MIN_INTERVAL_MS) {
        heldModel = user.heldModel;
        heldPos = user.heldPos;
        heldAng = user.heldAng;
      } else {
        user.lastHeldModelChangeAt = at;
      }
    } else if (heldModel !== user.heldModel) {
      // A genuine change (to empty) still resets the clock so the next pick-up
      // is immediate.
      user.lastHeldModelChangeAt = at;
    }

    user.updateInfo({
      mapname,
      position,
      velocity,
      pitch,
      yaw,
      paused,
      weapon,
      hp,
      armor,
      clip,
      ammo,
      heldModel,
      heldPos,
      heldAng,
      eyeZ,
      keys,
    });

    // Load detection for the race: a runner reporting the race map has arrived.
    this.race.onMapUpdate(user.name, mapname);

    if (this.config.debug) this.log.info("update from '%s' on %s", user.name, mapname);

    // I1/I2: an ACCEPTED position update (it passed the throttle above) is the
    // only thing that earns outbound credit. The cap is a few lines' worth, so a
    // burst-then-quiet session cannot bank an allowance to reflect later.
    const info = packets.info(user);
    this.noteInfoBytes(info.length, at);
    // I3: the squat-eviction rate counts accepted position updates only.
    user.recordInbound(at);

    const earn = this.lineCredit(user, message.buffer.length);
    user.earnCredit(earn, earn * 4);
    user.lastLineEarned = earn;
    user.lastLineBytes = message.buffer.length;

    // Metered: the position stream is the reflection amplifier (H2). A real
    // peer receives every frame; a forged endpoint that went silent or ran out
    // of earned credit does not.
    this.broadcastMetered(info, user.name);
    return true;
  }

  // ---- 'd' disconnect -------------------------------------------------------

  onDisconnect(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    const user = this.authorise(message, name);
    if (!user) return false;

    // Not applied immediately.
    //
    // A single forged datagram used to remove any player from the server, and
    // the victim was never told: they kept sending updates into a session that
    // no longer existed. The client sends its disconnect and then goes quiet,
    // so holding the request for two seconds costs a leaving player nothing.
    // A spoofed one, on the other hand, is cancelled by the victim's very next
    // position update about 40 ms later.
    //
    // M4: 'd' used to print one info line per packet and had no budget of its
    // own, so a session sending 'd' every 10 ms produced ~120 log lines a second
    // while staying connected (each 'd' cancels and re-arms the pending drop).
    // It is now charged to the events bucket and logged as a SAMPLED event, so a
    // probe cannot fill the disk through this path - which is what the README
    // claimed but was not true.
    if (!this.disconnects.take(socketKey(message.socket))) {
      this.log.event("event-limit", `'${user.name}' disconnect`);
      return false;
    }

    // authorise() above already cancelled the pending drop this packet might
    // have re-armed, so set it afterwards.
    this.pendingDrops.set(user.name, this.now() + DISCONNECT_GRACE_MS);
    user.touch(this.now());
    this.log.event("disconnect-requested", user.name);
    return true;
  }

  cancelPendingDrop(name) {
    if (!this.pendingDrops.has(name)) return false;
    this.pendingDrops.delete(name);
    this.stats.disconnectsCancelled += 1;
    this.log.event("disconnect-cancelled", name);
    return true;
  }

  // ---- 'm' chat -------------------------------------------------------------

  onChat(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    let text = message.readString(limits.READ_CHAT);

    const user = this.authorise(message, name);
    if (!user) return false;

    text = sanitizeChat(text);
    if (text.length === 0) return false;
    if (text.length > limits.MAX_CHAT_LENGTH) text = truncateBytes(text, limits.MAX_CHAT_LENGTH);

    // Slash commands are consumed here and never echoed as chat.
    if (text[0] === "/") {
      // Commands used to skip the chat interval entirely, and every command
      // produces at least one reply addressed to this session. Since the
      // session address may be forged, an unlimited command rate was an
      // unlimited packet source aimed at whoever owns that address.
      if (!this.commands.take(socketKey(message.socket))) {
        this.log.event("command-limit", user.name);
        return false;
      }
      user.touch(this.now());
      // Первый токен - сама команда, остальные её аргументы. Почему разбор
      // именно такой (и почему не через \s) - см. tokenizeCommand в wire/text.
      const parts = tokenizeCommand(text.slice(1));
      const command = (parts[0] || "").toLowerCase();
      // Race commands are gameplay, so they need a player who is actually in the
      // game. A spectator typing /race would take the race lock away from the
      // whole lobby without ever running. The admin commands below are NOT
      // gated this way: they already need the operator list, and moderation is
      // not gameplay.
      // Leaving is deliberately outside the spectator gate below. That gate
      // exists to stop a spectator claiming the race; it must never stand
      // between a runner and the exit. A runner who started spectating mid-race
      // would otherwise be told to stop spectating in order to leave a race they
      // are still frozen in.
      if (command === "leave") {
        this.race.cmdLeave(user.name);
      }
      else if (command === "race" || command === "ready") {
        if (!this.config.raceSpectators && user.spectating) {
          this.log.event("race-denied", `'${user.name}' tried /${command} while spectating`);
          this.serverSayTo(user.name, "Stop spectating first - a race is for players in the game.");
          return true;
        }
        if (command === "race") this.race.cmdRace(user.name);
        else this.race.cmdReady(user.name);
      }
      else if (ADMIN_COMMANDS.has(command)) {
        // H1 hardening: a host that moderates from the console can switch the
        // chat-admin surface off entirely (OP_CHAT_COMMANDS=0), so an operator's
        // forgeable address:port is not a path to /ban anyone.
        if (!this.config.opChatCommands) {
          this.log.event("admin-disabled", `'${user.name}' tried /${command}`);
          this.serverSayTo(user.name, "Admin chat commands are disabled on this server.");
          return true;
        }
        this.onAdminCommand(user, command, parts.slice(1));
      }
      // The echo is clamped: reflecting 127 characters of the sender's own text
      // back at them made the server exceed its own chat length limit.
      else this.serverSayTo(user.name, `Unknown command '/${command.slice(0, 24)}'.`);
      return true;
    }

    const at = this.now();
    if (at - user.lastChatTime < this.config.chatMinIntervalMs) return false;
    user.lastChatTime = at;
    user.touch(at);

    this.log.info("[chat] %s: %s", user.name, text);
    // Delivered to everyone including the sender: the client displays a message
    // only when it comes back, which keeps ordering the same for everyone.
    this.broadcast(this.chatBuffer(user.name, text));
    return true;
  }

  // ---- команды администратора из чата ---------------------------------------

  // Всё, что сюда приходит, - строка от игрока, то есть враждебная. Ник цели
  // проходит ровно тот же nicknameKey, что и ростер (иначе "alice" и "ALICE"
  // были бы разными людьми), причина сокращается в access.js, а в лог всё
  // уходит только через %s, то есть через sanitizeForLog: собранная руками
  // строка пронесла бы в терминал оператора управляющие байты.
  //
  // Бюджет команд уже списан в onChat (COMMAND_RATE_PER_SECOND, по умолчанию
  // одна в секунду с запасом на три), и это тот же бюджет, что у /race. Иначе
  // /broadcast был бы бесплатным способом разослать пакет всему серверу.
  onAdminCommand(user, command, args) {
    // 1.4.0: a session approved by a SteamID entry (applySteamOp) answers to
    // that entry, read now, so a deopsteam or a reload takes effect at once.
    const steamRecord = user.opBySteam ? this.access.opForSteam(user.steamId) : null;
    const listed = user.opBySteam ? !!steamRecord : this.access.isOp(user.name);
    if (!listed || this.operatorSessions.get(this.users.key(user.name)) !== user) {
      // Отказ стоит отправителю токен команды и один пакет ему же, так что
      // перебор команд в надежде на права ничем не дешевле обычного чата.
      this.log.event("admin-denied", `'${user.name}' tried /${command}`);
      this.serverSayTo(user.name, "You are not an operator.");
      return true;
    }

    // H1 op hardening: an operator session is bound only to a forgeable
    // address:port, and nothing can stop a datagram forged from the operator's
    // EXACT live 5-tuple (it is indistinguishable from the real operator; the
    // port leaks through the position relay in about a second of sweeping, and
    // the impersonation guard only delays use of it). When the
    // operator was approved WITH a PIN, every admin command must carry it as its
    // first token. The PIN travels only in the operator's own inbound chat
    // packet and is consumed here - never relayed, never logged - so an OFF-PATH
    // attacker spoofing the operator's address cannot observe or forge it. This
    // closes the op-hijack even for a guessed 5-tuple; without a PIN (or
    // OP_CHAT_COMMANDS=0) that escalation stays open, which the README documents.
    // A SteamID operator's PIN is checked against the entry's hash (scrypt)
    // until it was right once; then it is cached on the session like a console
    // operator's (opPin), and compared as that is.
    if (user.opPin || (steamRecord && steamRecord.pin)) {
      const given = args[0] || "";
      const right = user.opPin ? given === user.opPin : this.access.checkPin(steamRecord, given);
      if (!right) {
        user.opPinFailures += 1;
        this.log.event("admin-pin", `'${user.name}' wrong PIN for /${command}`);
        // C2(a): a run of wrong PINs from the operator's endpoint is either a
        // mistyping operator or someone guessing from a forged copy of it. Either
        // way the approval is revoked and the console is told (never the PIN).
        if (user.opPinFailures >= OP_PIN_MAX_FAILURES) {
          this.operatorSessions.delete(this.users.key(user.name));
          user.opPin = null;
          user.opPinFailures = 0;
          // A SteamID entry would approve the same session again on the next
          // reload; this session has used up its chances.
          if (user.opBySteam) user.opSteamRevoked = true;
          user.opBySteam = false;
          this.log.warn(
            "operator '%s': %d wrong PINs in a row - chat operator approval revoked for this session; " +
              "check who it is, then approve again from the console with op",
            user.name,
            OP_PIN_MAX_FAILURES
          );
          this.serverSayTo(user.name, "Operator approval revoked after repeated wrong PINs. Ask the host to approve you again.");
          return true;
        }
        this.serverSayTo(user.name, "Operator PIN required: /" + command + " <PIN> ...");
        return true;
      }
      user.opPinFailures = 0;
      if (!user.opPin) user.opPin = given; // a SteamID operator's, now verified
      args = args.slice(1); // strip the PIN before anything logs or acts on it
    }

    this.log.info("[admin] %s: /%s %s", user.name, command, args.join(" "));

    const target = args[0] || "";
    const reply = (line) => this.serverSayTo(user.name, line);
    // Ник в ответе - это то, что напечатал отправитель. Обрезаем, чтобы ответ
    // не выпихнул сам себя за лимит чата.
    const shown = () => truncateBytes(target, this.config.maxNameLength);

    switch (command) {
      case "kick": {
        if (!target) return reply("Usage: /kick Nick");
        // Кикнуть себя можно: это не дыра, а способ проверить, что права есть.
        if (!this.kickByName(target, `Kicked by ${user.name}.`)) {
          return reply(`No player named '${shown()}' is here.`);
        }
        this.serverSay(`${shown()} was kicked by ${user.name}.`);
        return true;
      }

      case "ban": {
        if (!target) return reply("Usage: /ban Nick [30m|2h|perm] [reason]");
        // Срок - только следующий за ником токен, и только если он выглядит
        // сроком. Иначе "/ban Nick spamming" забанил бы на "spamming" минут.
        const duration = parseDuration(args[1]);
        const rest = duration === null ? args.slice(1) : args.slice(2);
        const result = this.access.ban(KIND.NAME, target, {
          reason: rest.join(" "),
          until: duration ? this.access.now() + duration : 0,
          addedBy: user.name,
        });
        if (!result.ok) return reply(`Cannot ban '${shown()}': ${result.error}.`);
        this.enforceBans();
        this.warnIfUnsaved(reply);
        this.serverSay(`${result.record.value} was banned by ${user.name} (${this.access.term(result.record)}).`);
        return true;
      }

      case "unban": {
        if (!target) return reply("Usage: /unban Nick");
        const result = this.access.unban(KIND.NAME, target);
        if (!result.ok) return reply(`'${shown()}' is ${result.error}.`);
        this.warnIfUnsaved(reply);
        return reply(`'${result.record.value}' is no longer banned.`);
      }

      // Запрет на спрей. Отдельная команда, а не бан: за картинку снимать
      // человека с сервера целиком - слишком грубо, пусть играет молча.
      case "sprayban": {
        if (!target) return reply("Usage: /sprayban Nick [30m|2h|perm] [reason]");
        const duration = parseDuration(args[1]);
        const rest = duration === null ? args.slice(1) : args.slice(2);
        const result = this.access.ban(KIND.SPRAY, target, {
          reason: rest.join(" "),
          until: duration ? this.access.now() + duration : 0,
          addedBy: user.name,
        });
        if (!result.ok) return reply(`Cannot spray-ban '${shown()}': ${result.error}.`);
        this.warnIfUnsaved(reply);

        // Снимаем со стен то, что уже висит: запретить ставить новое и оставить
        // висеть старое - это половина решения, а поводом для запрета обычно
        // служит ровно то, что уже висит.
        this.revokeSpray(result.record.key, target);
        this.serverSay(`${result.record.value} may no longer spray (${this.access.term(result.record)}).`);
        return true;
      }

      case "unsprayban": {
        if (!target) return reply("Usage: /unsprayban Nick");
        const result = this.access.unban(KIND.SPRAY, target);
        if (!result.ok) return reply(`'${shown()}' is not spray-banned.`);
        this.warnIfUnsaved(reply);
        return reply(`'${result.record.value}' may spray again.`);
      }

      case "broadcast": {
        const message = args.join(" ");
        if (!message) return reply("Usage: /broadcast message");
        // Уже прошло sanitizeChat в onChat, а длину обрежет packets.chat по
        // буферу клиента.
        this.serverSay(message);
        return true;
      }

      // default не нужен: сюда попадают только команды из ADMIN_COMMANDS, и
      // этот набор перечисляет ровно ветки ниже.
    }
    return true;
  }

  grantOp(name, options) {
    const opts = options || {};
    const pin = opts.pin === undefined || opts.pin === null || opts.pin === "" ? null : String(opts.pin);
    // C2(a): an operator without a PIN can be impersonated by anyone who finds
    // their address:port, so a PIN is required unless the host opted out.
    if (pin === null && !this.config.opAllowNoPin) {
      return {
        ok: false,
        error: 'an operator PIN of 6-12 digits is required: op "Nick" <PIN> (or set OP_ALLOW_NO_PIN=1)',
      };
    }
    if (pin !== null && !OP_PIN.test(pin)) {
      return { ok: false, error: "the operator PIN must be 6 to 12 digits" };
    }
    const user = this.users.get(name);
    if (!user) return { ok: false, error: "player must be connected; approve their current session from the console" };
    const result = this.access.grantOp(user.name, opts);
    if (result.ok) {
      this.operatorSessions.set(this.users.key(user.name), user);
      // The PIN lives on the live session only (never persisted), so it is gone
      // on reconnect exactly like the approval itself.
      user.opPin = pin;
      user.opPinFailures = 0;
      // From now on this session answers to the console's approval, not to a
      // SteamID entry it may also have.
      user.opBySteam = false;
    }
    // Whether a PIN is set - never the PIN itself (callers print this).
    return Object.assign({}, result, { pinSet: !!user.opPin });
  }

  revokeOp(name) {
    const user = this.users.get(name);
    if (user) user.opPin = null;
    this.operatorSessions.delete(this.users.key(name));
    return this.access.revokeOp(name);
  }

  // ---- 1.4.0: operators, bans and the whitelist by SteamID ------------------
  //
  // The SteamID is the client's word (see access.js, KIND). An entry here is
  // as strong as the PIN that goes with it: anyone whose client announces the
  // SteamID gets the approval, and SteamIDs are public.

  // A console argument: a SteamID in any form normalizeSteamId reads, or the
  // nickname of a connected player who announced one.
  resolveSteamTarget(target) {
    const id = normalizeSteamId(typeof target === "string" ? target : "");
    if (id) return { ok: true, id };
    const user = typeof target === "string" && target ? this.users.get(target) : null;
    if (!user) return { ok: false, error: "not a SteamID, and no player by that name is connected" };
    if (!user.steamId) return { ok: false, error: `'${user.name}' reported no SteamID` };
    return { ok: true, id: user.steamId, name: user.name };
  }

  grantOpSteam(target, options) {
    const opts = options || {};
    const pin = opts.pin === undefined || opts.pin === null || opts.pin === "" ? null : String(opts.pin);
    if (pin === null && !this.config.opAllowNoPin) {
      return {
        ok: false,
        error: "an operator PIN of 6-12 digits is required: opsteam <SteamID> <PIN> (or set OP_ALLOW_NO_PIN=1)",
      };
    }
    if (pin !== null && !OP_PIN.test(pin)) {
      return { ok: false, error: "the operator PIN must be 6 to 12 digits" };
    }
    const resolved = this.resolveSteamTarget(target);
    if (!resolved.ok) return resolved;
    const result = this.access.grantOpSteam(resolved.id, { addedBy: opts.addedBy || "console", pin });
    if (!result.ok) return result;
    const approved = this.applySteamOps();
    return Object.assign({}, result, { pinSet: pin !== null, steamId: resolved.id, approved });
  }

  revokeOpSteam(target) {
    const resolved = this.resolveSteamTarget(target);
    if (!resolved.ok) return resolved;
    const result = this.access.revokeOpSteam(resolved.id);
    if (result.ok) this.applySteamOps();
    return result;
  }

  // Approves one confirmed v2 session whose announced SteamID has an operator
  // entry. Called when it confirms (confirmV2) and from applySteamOps. A legacy
  // session never has a SteamID (the block follows the v2 tail), and a v2
  // session that has not signed a packet yet is not approved: a forged announce
  // could name any SteamID. Returns whether it approved.
  applySteamOp(user) {
    if (!user.steamId || !user.v2Confirmed || user.opSteamRevoked) return false;
    if (this.users.get(user.name) !== user) return false;
    const key = this.users.key(user.name);
    if (this.operatorSessions.get(key) === user) return false; // already approved
    const record = this.access.opForSteam(user.steamId);
    if (!record) return false;
    if (!record.pin && !this.config.opAllowNoPin) {
      this.log.event("steam-op-no-pin", `SteamID ${user.steamId} ('${user.name}'): the entry has no PIN, not applied`);
      return false;
    }
    this.operatorSessions.set(key, user);
    user.opBySteam = true;
    user.opPin = null;
    user.opPinFailures = 0;
    this.log.info(
      "'%s' approved as an operator by SteamID %s (the client's word; %s).",
      user.name,
      user.steamId,
      record.pin ? "commands need the PIN" : "no PIN"
    );
    this.serverSayTo(
      user.name,
      record.pin
        ? "You are an operator here (by SteamID). Admin commands need your PIN first: /kick <PIN> Nick"
        : "You are an operator here (by SteamID)."
    );
    return true;
  }

  // After the SteamID operator entries changed (opsteam, deopsteam, reload):
  // sessions whose entry is gone (or lost its PIN) lose the approval, sessions
  // whose entry is new get it, and every cached PIN is checked again. Returns
  // the names approved now.
  applySteamOps() {
    const approved = [];
    for (const user of Array.from(this.users.values())) {
      const key = this.users.key(user.name);
      if (user.opBySteam) {
        const record = this.access.opForSteam(user.steamId);
        if (!record || (!record.pin && !this.config.opAllowNoPin)) {
          if (this.operatorSessions.get(key) === user) this.operatorSessions.delete(key);
          user.opBySteam = false;
          user.opPin = null;
          this.log.info("'%s' is no longer an operator (SteamID entry removed).", user.name);
          continue;
        }
        user.opPin = null;
      } else if (this.applySteamOp(user)) {
        approved.push(user.name);
      }
    }
    return approved;
  }

  // Запись на диск могла не пройти. Бан при этом действует, но переживёт только
  // до перезапуска, и узнать об этом лучше сразу, а не тогда, когда забаненный
  // вернётся после рестарта.
  warnIfUnsaved(reply) {
    if (this.access.lastSaveError) reply("Warning: the access file could not be written; see the server log.");
  }

  // ---- 'r' race checkpoint --------------------------------------------------

  onCheckpoint(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    const checkpoint = message.readUInt8();

    // Trailing optional fields: the finisher's own run time in seconds, and
    // LiveSplit's if they are mirroring it (-1 when they are not). A client
    // built before these existed simply stops here and the packet ends.
    const igt = message.readOptionalFloat(-1);
    const liveSplit = message.readOptionalFloat(-1);

    const user = this.authorise(message, name);
    if (!user) return false;
    if (!this.events.take(socketKey(message.socket))) {
      this.log.event("event-limit", `'${user.name}' checkpoint`);
      return false;
    }
    const at = this.now();
    user.touch(at);
    // N2: accepted from a guarded session, but the result is marked unverified.
    const unverified = this.isGuarded(user, at);
    return this.race.onCheckpoint(user.name, checkpoint, {
      igt,
      liveSplit,
      unverified,
      guardedForMs: unverified ? at - user.guardStartedAt : 0,
    });
  }

  // ---- 's' spectate ---------------------------------------------------------

  onSpectate(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    let target = sanitizeText(message.readString(limits.READ_TARGET));
    const user = this.authorise(message, name);
    if (!user) return false;

    if (target.length > limits.MAX_SPECTATE_LENGTH) target = truncateBytes(target, limits.MAX_SPECTATE_LENGTH);
    // Spectating somebody who is not here is meaningless and would let a client
    // push an arbitrary string through the relay into everyone's HUD.
    // Relayed to every client, so it has to be the roster's spelling and not
    // the one in this packet. Sending the raw string let a confirmed session
    // put any latin1 spelling of another player's name into everyone's HUD,
    // and defeated the "repeating the current target costs nothing" check
    // below, because 32 case permutations are 32 different strings.
    // A v2 session nobody has been told about (confirmV2) is nobody to watch.
    const watched = target ? this.users.get(target) : null;
    target = watched && watched.announced ? watched.name : "";

    // Repeating the current target changes nothing, so it must not cost a
    // packet to every player. This was the cheapest amplifier in the protocol:
    // a 14 byte payload, no rate limit, and a fan-out to the whole server.
    if (user.spectating === target) return false;
    if (!this.events.take(socketKey(message.socket))) {
      this.log.event("event-limit", `'${user.name}' spectate`);
      return false;
    }

    user.touch(this.now());
    user.spectating = target;
    this.broadcast(packets.spectate(user.name, target));
    return true;
  }

  // ---- 'p' spray upload -----------------------------------------------------

  // A spray arrives in pieces and is stored as pieces. Nothing here parses the
  // payload: it is a deflated VTF, and the only end that can safely decide
  // whether it is really a texture is the client that has to render it. What
  // this does check is everything about the *shape* of the upload, because that
  // is what costs the server memory.
  onSprayChunk(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    const crc = message.readInt32();
    const rawBytes = message.readInt32();
    const total = message.readInt32();
    const index = message.readInt32();
    const payload = message.readBytes(limits.SPRAY_CHUNK_BYTES);

    const user = this.authorise(message, name);
    if (!user) return false;

    if (!this.sprayUploads.take(socketKey(message.socket))) {
      this.log.event("spray-limit", `'${user.name}' upload`);
      return false;
    }

    user.touch(this.now());

    // Silently dropped rather than answered. Telling a banned player their
    // spray was refused invites them to keep trying with a different picture,
    // and the refusal costs a packet each time.
    if (!this.access.maySpray(user.name)) {
      this.log.event("spray-denied", `'${user.name}' is spray-banned`);
      return false;
    }

    if (total < 1 || total > limits.MAX_SPRAY_CHUNKS) return false;
    if (index < 0 || index >= total) return false;
    if (rawBytes < 1 || rawBytes > limits.MAX_SPRAY_RAW_BYTES) return false;
    // Clients place chunks at index * 400, so intermediate gaps are invalid.
    if (payload.length === 0 || (index < total - 1 && payload.length !== limits.SPRAY_CHUNK_BYTES)) return false;

    // A new crc, or a restarted upload, replaces whatever was half-arrived.
    let pending = user.sprayIn;
    if (!pending || pending.crc !== crc || pending.total !== total || pending.rawBytes !== rawBytes) {
      pending = { crc, rawBytes, total, chunks: new Array(total).fill(null), have: 0, bytes: 0 };
      user.sprayIn = pending;
    }
    // N3: a completed upload already waiting in the re-encode queue is accepted;
    // the client's recovery pass re-sending its pieces changes nothing.
    if (pending.queued) return true;

    // Re-sending a piece is not an error - it is what a client does when a
    // datagram is lost - but it must not be charged twice against the budget.
    if (pending.chunks[index] === null) {
      if (pending.bytes + payload.length > limits.MAX_SPRAY_BYTES) {
        this.log.event("spray-oversize", `'${user.name}' past ${limits.MAX_SPRAY_BYTES} bytes`);
        user.sprayIn = null;
        return false;
      }
      pending.chunks[index] = payload;
      pending.have += 1;
      pending.bytes += payload.length;
    }

    if (pending.have < pending.total) return true;

    // L5: the client sends the full blob byte count in rawBytes and the chunk
    // count that matches it, so require them to agree with what actually
    // arrived. A sender that lies about either is dropped rather than published.
    if (pending.bytes !== rawBytes || total !== Math.ceil(rawBytes / limits.SPRAY_CHUNK_BYTES)) {
      this.log.event("spray-mismatch", `'${user.name}' declared ${rawBytes}/${total}, got ${pending.bytes}`);
      user.sprayIn = null;
      return false;
    }

    // M2: a completed upload is a publication, and publications are budgeted
    // separately from pieces. A fresh picture every 25 ms used to fill every
    // other client's remote-blob cache; now a session may publish only a couple
    // a minute, a small burst, and at most a fixed number for the whole session.
    if (user.sprayPublishCount >= this.config.sprayPublishMaxPerSession) {
      this.log.event("spray-publish-cap", `'${user.name}' past ${this.config.sprayPublishMaxPerSession} this session`);
      user.sprayIn = null;
      return false;
    }

    // M3: inspect the blob before it is fanned out. A stranger's bytes are
    // parsed as a deflated VTF, bounded on inflate, matched field-for-field
    // against what the client's own writer produces, and the pixels checked
    // against the announced crc (cheap: one bounded inflate and a CRC). Junk is
    // dropped with no fan-out and one sampled line.
    const assembled = Buffer.concat(pending.chunks, pending.bytes);
    const verdict = spray.validate(assembled, crc);
    if (!verdict.ok) {
      this.log.event("spray-invalid", `'${user.name}' id ${crcText(crc)}: ${verdict.reason}`);
      user.sprayIn = null;
      return false;
    }

    // M2 + I4: the session, its address and its name must all have a token;
    // none is spent unless all three do. N3 (review 2): charged BEFORE anything
    // touches the server-wide re-encode budget, so an attempt over any of them
    // never reaches it - a fresh picture aimed at an empty re-encode budget used
    // to cost its sender nothing, which is how three addresses kept it empty.
    const publishKeys = [
      [this.sprayPublish, socketKey(message.socket), "session"],
      [this.sprayPublishAddress, addressKey(message.socket), "address"],
      [this.sprayPublishName, this.users.key(user.name), "name"],
    ];
    const short = publishKeys.find(([store, key]) => store.available(key) < 1);
    if (short) {
      short[0].dropped += 1;
      this.log.event("spray-publish-limit", `'${user.name}' (${short[2]} budget)`);
      user.sprayIn = null;
      return false;
    }
    for (const [store, key] of publishKeys) store.take(key);

    // C1 + N3: the re-encode is a synchronous deflate (level 6, bounded per
    // picture), so the total time spent on it is bounded server-wide by one
    // budget. With the budget free and nobody waiting, the picture goes out now;
    // otherwise it waits its turn in a fair queue the tick drains at the
    // budget's rate (drainReencodeQueue). Nobody is told: the player sees their
    // own spray at once, everybody else gets it within a few seconds, and a
    // notice per attempt was a chat packet and an unsampled log line an attacker
    // could ask for 160 times a second (review 2, N3b).
    if (this.reencodeQueued.size === 0 && this.sprayReencode.available("all") >= 1) {
      return this.publishSpray(user, crc, verdict, publishKeys, pending);
    }
    return this.enqueueReencode(user, pending, assembled, message.socket, publishKeys);
  }

  // N3: queue a validated, budgeted upload for the re-encode budget.
  //
  // Bounded twice: one entry per session (a newer picture from the same
  // session replaces the older one in its place), and SPRAY_REENCODE_QUEUE_MAX
  // entries in all. Entries are kept per source ADDRESS and served round-robin
  // across addresses, so N addresses publishing as fast as their budgets allow
  // get at most N/(N+1) of the re-encodes and every other player's picture is
  // published within a bounded number of turns - without depending on the
  // client's one recovery pass, which is all the C1 version had (review 2
  // measured 21 of 48 sprays published after an honest mass join).
  //
  // The entry keeps the deflated upload (at most MAX_SPRAY_BYTES, already held
  // per session) rather than the inflated VTF, and is validated again when its
  // turn comes, which is one bounded inflate per re-encode.
  enqueueReencode(user, pending, assembled, socket, publishKeys) {
    const key = socketKey(socket);
    const address = addressKey(socket);
    let entry = this.reencodeQueued.get(key);
    if (entry) {
      // Review 3 (R6): replaced in place by a newer picture that validated and
      // was budgeted; the one it replaces was never published, so its publish
      // tokens are given back.
      this.refundPublish(entry.publishKeys);
      entry.user = user;
      entry.pending = pending;
      entry.publishKeys = publishKeys;
    } else {
      if (this.reencodeQueued.size >= this.config.sprayReencodeQueueMax) {
        this.log.event("spray-queue-full", `'${user.name}' id ${crcText(pending.crc)}`);
        this.refundPublish(publishKeys);
        user.sprayIn = null;
        return false;
      }
      entry = { key, address, user, pending, publishKeys };
      this.reencodeQueued.set(key, entry);
      const list = this.reencodeQueue.get(address);
      if (list) list.push(entry);
      else this.reencodeQueue.set(address, [entry]);
    }
    pending.queued = true;
    pending.assembled = assembled;
    pending.chunks = null;
    this.log.event("spray-queued", `'${user.name}' id ${crcText(pending.crc)} (${this.reencodeQueued.size} waiting)`);
    return true;
  }

  // Removes a session's queue entry, if it has one.
  dequeueReencode(key) {
    const entry = this.reencodeQueued.get(key);
    if (!entry) return;
    this.reencodeQueued.delete(key);
    const list = this.reencodeQueue.get(entry.address);
    if (!list) return;
    const at = list.indexOf(entry);
    if (at >= 0) list.splice(at, 1);
    if (list.length === 0) this.reencodeQueue.delete(entry.address);
  }

  // Called from the tick: at most ONE re-encode per call (so one tick never
  // runs a burst of deflates back to back), and only when the server-wide
  // budget has a token. The address served goes to the back of the line.
  drainReencodeQueue() {
    while (this.reencodeQueue.size > 0 && this.sprayReencode.available("all") >= 1) {
      const [address, list] = this.reencodeQueue.entries().next().value;
      const entry = list.shift();
      this.reencodeQueue.delete(address);
      if (list.length > 0) this.reencodeQueue.set(address, list);
      this.reencodeQueued.delete(entry.key);
      const { user, pending } = entry;
      // Stale only when the session is gone (left, or replaced by a takeover).
      // Review 3 (R6): a newer upload that merely STARTED, never completed, or
      // was refused does not cost the waiting picture - only a newer one that
      // validated and was budgeted replaces it, in place (enqueueReencode). A
      // spray ban while waiting skips it. Neither spends the re-encode budget.
      if (this.users.get(user.name) !== user) continue;
      if (!this.access.maySpray(user.name)) continue;
      const verdict = spray.validate(pending.assembled, pending.crc);
      if (!verdict.ok) {
        this.log.event("spray-invalid", `'${user.name}' id ${crcText(pending.crc)}: ${verdict.reason}`);
        continue;
      }
      this.publishSpray(user, pending.crc, verdict, entry.publishKeys, pending);
      return;
    }
  }

  // Review 2 (m6): the publish budgets charged for a picture that was then not
  // published (too large after re-encoding, or no room in the queue) are given
  // back. The re-encode budget, if spent, stays spent: the work was done.
  refundPublish(publishKeys) {
    for (const [store, key] of publishKeys || []) store.refund(key);
  }

  // Re-encodes a validated picture (spending the server-wide budget) and
  // publishes it to the lobby.
  // `pending` is the upload being published; it is cleared from the session
  // only if it is still the session's current one (a newer upload may be under
  // way while this one came out of the queue).
  publishSpray(user, crc, verdict, publishKeys, pending) {
    const done = () => {
      if (user.sprayIn === pending) user.sprayIn = null;
    };
    this.sprayReencode.take("all");
    const encoded = spray.reencode(verdict.vtf, verdict.declaredVtf);
    if (!encoded.ok) {
      this.refundPublish(publishKeys);
      // I5: a photo-like picture within ~2 % of the cap can come out of the
      // re-encode larger than a receiving client accepts. It is refused rather
      // than relayed in its original encoding, and the sender is told, since a
      // silent refusal looked like a spray nobody else could see for no reason.
      this.log.event("spray-too-large", `'${user.name}' id ${crcText(crc)}: ${encoded.length} B after re-encoding`);
      this.serverSayTo(user.name, "Your spray is too large after re-encoding, so nobody else will see it - use a smaller or flatter picture.");
      done();
      return false;
    }

    // M1: build the relay chunk packets ONCE from the re-encoded blob. Every
    // receiver shares this one immutable array through a cursor, instead of each
    // getting its own copy of every chunk.
    const blob = encoded.blob;
    const relayTotal = Math.ceil(blob.length / limits.SPRAY_CHUNK_BYTES);
    const relayPackets = new Array(relayTotal);
    for (let i = 0; i < relayTotal; i++) {
      const start = i * limits.SPRAY_CHUNK_BYTES;
      const piece = blob.subarray(start, Math.min(start + limits.SPRAY_CHUNK_BYTES, blob.length));
      relayPackets[i] = packets.sprayChunk(user.name, crc, blob.length, relayTotal, i, piece);
    }
    user.spray = { crc, rawBytes: blob.length, total: relayTotal, bytes: blob.length, packets: relayPackets };
    done();
    user.sprayPublishCount += 1;
    this.log.event(
      "spray-published",
      `'${user.name}' ${blob.length} bytes, ${relayTotal} pieces, id ${crcText(crc)}`
    );

    // Everyone else gets it now, a piece at a time, through a per-receiver cursor.
    for (const other of this.users.values()) {
      if (other.name === user.name || !other.confirmed) continue;
      this.queueSpray(other, user);
    }
    return true;
  }

  // ---- 'q' spray stamp ------------------------------------------------------

  onSprayStamp(message) {
    const name = sanitizeText(message.readString(limits.READ_NAME_IN_SESSION));
    const crc = message.readInt32();
    const x = message.readFloat();
    const y = message.readFloat();
    const z = message.readFloat();

    const user = this.authorise(message, name);
    if (!user) return false;
    if (!this.events.take(socketKey(message.socket))) {
      this.log.event("event-limit", `'${user.name}' spray`);
      return false;
    }

    user.touch(this.now());

    if (!this.access.maySpray(user.name)) return false;

    // A stamp for a picture nobody has is a fan-out that buys the sender
    // nothing but costs everyone a packet, so it is refused rather than
    // relayed and left for the receivers to ignore.
    if (!user.spray || user.spray.crc !== crc) return false;

    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) return false;
    const far = limits.MAX_COORDINATE;
    if (Math.abs(x) > far || Math.abs(y) > far || Math.abs(z) > far) return false;

    // Review 2 (m3): the receiving client builds a texture for a picture when
    // its first stamp is drawn, at most 48 per game run, and past that shows
    // nobody's spray until restarted. So a picture counts against a receiver's
    // SPRAY_MAX_PICTURES_PER_RECEIVER when its first stamp is relayed there,
    // and stamps of further pictures are not relayed to that receiver. A stamp
    // goes only to receivers that were fed the picture: nobody else can draw it.
    const buffer = packets.sprayStamp(user.name, crc, x, y, z);
    const pair = this.sprayPair(user.name, crc);
    for (const other of this.users.values()) {
      if (other.name === user.name || !other.confirmed) continue;
      if (!other.sprayPictures.has(pair)) continue;
      if (!other.sprayStamped.has(pair)) {
        if (other.sprayStamped.size >= this.config.sprayMaxPicturesPerReceiver) {
          this.log.event("spray-stamp-cap", `'${other.name}' has drawn ${other.sprayStamped.size} pictures`);
          continue;
        }
        other.sprayStamped.add(pair);
      }
      this.send(buffer, other);
    }
    return true;
  }

  // ---- spray relay ----------------------------------------------------------

  sprayPair(name, crc) {
    return `${this.users.key(name)}:${crc >>> 0}`;
  }

  // Queues one player's spray for delivery to another. Nothing is sent here:
  // the pieces go out on the tick, a few at a time, so a join into a lobby
  // where everybody has a spray does not arrive as a burst of hundreds of
  // datagrams at the client least able to absorb it.
  queueSpray(to, from) {
    if (!from.spray) return;

    const existing = to.sprayFeeds.get(from.name);
    // Already being sent THIS picture: keep the cursor where it is, so a
    // duplicate connect (H2) or a late roster resend does not restart delivery
    // and re-send chunks this receiver already has. Only a genuinely new picture
    // (a different crc) rewinds the feed to the start.
    if (existing && existing.crc === from.spray.crc) return;
    // Minor 10 (review 1): a picture this receiver has already been sent in full
    // is not fed again. The finished feed is deleted, so without this a duplicate
    // connect (allowed every 5 s) re-queued the whole picture from chunk 0.
    if (to.sprayDelivered.get(from.name) === from.spray.crc) return;

    // I4 + m3: a per-receiver ceiling on DISTINCT pictures fed, whoever sends
    // them, below the 256 remote blobs the client writes. (The client's tighter
    // limit, 48 textures, is on pictures it DRAWS; see onSprayStamp.)
    const pair = this.sprayPair(from.name, from.spray.crc);
    if (!to.sprayPictures.has(pair)) {
      if (to.sprayPictures.size >= this.config.sprayMaxFedPerReceiver) {
        this.log.event("spray-receiver-cap", `'${to.name}' has been sent ${to.sprayPictures.size} pictures`);
        return;
      }
      to.sprayPictures.add(pair);
    }
    to.sprayFeeds.set(from.name, { crc: from.spray.crc, next: 0 });
  }

  // Forgets a player's published spray and cancels anything still queued from
  // them. Used when they are spray-banned: leaving the picture that earned the
  // ban in everybody's cache, and still sending it to whoever joins next, would
  // make the ban half a measure.
  //
  // What is already on somebody's wall stays there until the map changes - the
  // decals live in each client's engine and this server has no way to reach
  // them. It is the newcomers, and everyone after a map change, who see the
  // difference.
  revokeSpray(bannedKey, displayName) {
    let found = false;
    for (const user of this.users.values()) {
      if (this.access.keyFor(KIND.SPRAY, user.name) === bannedKey) {
        user.spray = null;
        user.sprayIn = null;
        found = true;
      }
    }

    // Drop any receiver's cursor that points at the banned sender, so an
    // in-flight picture stops being delivered the moment the ban lands.
    for (const user of this.users.values()) {
      for (const fromName of user.sprayFeeds.keys()) {
        if (this.access.keyFor(KIND.SPRAY, fromName) === bannedKey) user.sprayFeeds.delete(fromName);
      }
    }

    if (found) this.log.info("Dropped the published spray of '%s'", displayName);
  }

  // Called from the tick. Each player gets a few pieces per pass, which spreads
  // a full spray over a few seconds rather than a frame.
  dripSprays() {
    const perTick = this.config.sprayChunksPerTick;
    const at = this.now();
    for (const user of this.users.values()) {
      if (!user.confirmed || user.sprayFeeds.size === 0) continue;
      // Same liveness + credit gate as the position relay (H2): a forged
      // endpoint that squatted a session cannot be fed somebody else's 160 KB
      // picture over and over as a reflected attack. A confirmed v2 receiver
      // skips the credit, as it does there (broadcastMetered), not liveness.
      const charged = !user.v2Confirmed;
      if (!this.isLive(user, at)) continue;

      let sent = 0;
      for (const [fromName, feed] of user.sprayFeeds) {
        if (sent >= perTick) break;
        const from = this.users.get(fromName);
        // The sender left, was spray-banned, or published a different picture:
        // this feed is stale. Drop it rather than send from a gone array.
        if (!from || !from.spray || from.spray.crc !== feed.crc) {
          user.sprayFeeds.delete(fromName);
          continue;
        }
        while (sent < perTick && feed.next < from.spray.total) {
          const buffer = from.spray.packets[feed.next];
          if (charged && !user.spendCredit(buffer.length)) {
            this.stats.meteredBlocked += 1;
            sent = perTick; // out of credit this tick: stop the whole user
            break;
          }
          feed.next += 1;
          sent += 1;
          this.send(buffer, user);
        }
        if (feed.next >= from.spray.total) {
          user.sprayFeeds.delete(fromName);
          user.sprayDelivered.set(fromName, feed.crc);
        }
      }
    }
  }

  // What the server is holding and handing out, for the `sprays` console
  // command. Publication is in the log, but delivery was invisible: the useful
  // question is not "did a picture arrive" but "has everyone got it yet", and
  // nothing answered that.
  spraySnapshot() {
    const rows = [];
    for (const user of this.users.values()) {
      // Pieces still owed to this receiver, per sender: the sender's total minus
      // where this receiver's cursor has reached.
      const pendingFrom = [];
      let pending = 0;
      for (const [fromName, feed] of user.sprayFeeds) {
        const from = this.users.get(fromName);
        if (!from || !from.spray || from.spray.crc !== feed.crc) continue;
        const remaining = from.spray.total - feed.next;
        if (remaining > 0) {
          pendingFrom.push({ name: fromName, count: remaining });
          pending += remaining;
        }
      }
      rows.push({
        name: user.name,
        confirmed: user.confirmed,
        published: user.spray
          ? { bytes: user.spray.bytes, total: user.spray.total, crc: user.spray.crc }
          : null,
        incoming: user.sprayIn
          ? { have: user.sprayIn.have, total: user.sprayIn.total, bytes: user.sprayIn.bytes }
          : null,
        pending,
        pendingFrom,
        banned: !this.access.maySpray(user.name),
      });
    }
    rows.sort((a, b) => a.name.localeCompare(b.name));
    return {
      rows,
      chunkBytes: limits.SPRAY_CHUNK_BYTES,
      perTick: this.config.sprayChunksPerTick,
      reencodeQueued: this.reencodeQueued.size,
      reencodePerMinute: this.config.sprayReencodePerMinute,
      tickMs: 250,	// the drip rides the general tick, see start()
    };
  }

  // -------------------------------------------------------------------------
  // Housekeeping
  // -------------------------------------------------------------------------

  dropUser(user, logReason, wireReason) {
    this.users.unregister(user.name, socketKey(user.socket));
    const queued = this.reencodeQueued.get(socketKey(user.socket));
    if (queued && queued.user === user) this.dequeueReencode(queued.key);
    this.operatorSessions.delete(this.users.key(user.name));
    this.pendingDrops.delete(user.name);
    // Nobody needs the rest of a leaver's picture. Without this a player who
    // joins and leaves repeatedly can leave a cursor behind them each time.
    // N1 (review 2): the type 4 below makes every receiving client forget this
    // player's picture (GhostOnlineEngine.cpp:520 -> GhSprayNet_Forget ->
    // Unpublish), so "already delivered" must be forgotten with it. Otherwise a
    // player who leaves and rejoins with the same picture - every crash and
    // restart - was never sent it again, and their stamps were relayed to
    // clients that could not draw them. A silent takeover sends no type 4, so it
    // does not come through here and correctly keeps the record.
    for (const other of this.users.values()) {
      if (other.sprayFeeds.has(user.name)) other.sprayFeeds.delete(user.name);
      other.sprayDelivered.delete(user.name);
    }
    // A v2 session the lobby was never told about (it never confirmed:
    // confirmV2) leaves the same way, without a word to anyone.
    if (user.announced) this.broadcast(packets.disconnect(user.name, wireReason || "left"));
    if (logReason) this.log.info("Dropped '%s': %s", user.name, logReason);
    this.race.onPlayerDrop(user.name, wireReason);
  }

  // Disconnects that were requested and not contradicted by a later packet
  // from the same session.
  resolvePendingDrops() {
    const at = this.now();
    for (const [name, deadline] of this.pendingDrops) {
      if (at < deadline) continue;
      this.pendingDrops.delete(name);
      const user = this.users.get(name);
      if (user) this.dropUser(user, "disconnected", "left");
    }
  }

  // Releases the machine could not deliver. Bounded by the roster: a name whose
  // player is gone is forgotten rather than retried forever.
  retryUnpause() {
    for (const name of Array.from(this.pendingUnpause)) {
      const user = this.users.get(name);
      if (!user) {
        this.pendingUnpause.delete(name);
        continue;
      }
      if (this.send(packets.serverPause(false, ""), user, { force: true })) {
        this.pendingUnpause.delete(name);
        this.log.event("unpause-retried", name);
      }
    }
  }

  sweep() {
    const at = this.now();
    this.resolvePendingDrops();

    for (const user of Array.from(this.users.values())) {
      // A session whose address never answered is held to a shorter leash: it
      // may be a forged source squatting on a nickname.
      const timeout = user.confirmed ? this.config.staleTimeoutMs : this.config.unconfirmedTimeoutMs;
      if (at - user.lastSeen <= timeout) continue;
      if (user.confirmed) this.send(packets.kick("Timed out."), user);
      this.dropUser(user, user.confirmed ? "timed out" : "never confirmed its address", "timeout");
    }

    // Every per-address structure is pruned on the same tick, so a flood that
    // stops leaves no residue behind.
    this.byAddress.prune();
    this.bySession.prune();
    this.connects.prune();
    this.malformed.prune();
    this.commands.prune();
    this.events.prune();
    // L5: the spray buckets were never pruned (capped, so residue not a leak,
    // but residue nonetheless). Pruned now like every other per-session store.
    this.disconnects.prune();
    this.sprayUploads.prune();
    this.sprayPublish.prune();
    this.sprayPublishAddress.prune();
    this.sprayPublishName.prune();
    this.probe.prune();
    this.probeConnect.prune();
    this.probeConnectAddress.prune();
    this.connectReserve.prune();
    this.infoQueries.prune();
    this.retryUnpause();
    for (const [address, until] of this.penalty) {
      if (at >= until) this.penalty.delete(address);
    }
    for (const [endpoint, refused] of this.refusedNamePorts) {
      if (at >= refused.until) this.refusedNamePorts.delete(endpoint);
    }
    // N3: queue entries whose session is gone (a silent takeover replaces the
    // session without dropUser). Bounded by SPRAY_REENCODE_QUEUE_MAX.
    for (const [key, entry] of Array.from(this.reencodeQueued)) {
      if (this.users.get(entry.user.name) !== entry.user) {
        this.dequeueReencode(key);
      }
    }
  }

  kickByName(name, reason) {
    const user = this.users.get(name);
    if (!user) return false;
    this.send(packets.kick(reason || "You were kicked from the server."), user, { force: true });
    this.dropUser(user, "kicked by server console", "kick");
    return true;
  }

  // Кик всех, кто под действующим баном. Вызывается сразу после того, как бан
  // добавили: бан, который не выгоняет того, из-за кого его поставили, - это
  // кик, отложенный до его собственного решения выйти.
  //
  // Обратной операции нет специально. Снятие бана никого не возвращает, а
  // истечение срока не требует действия: и то, и другое проверяется на входе.
  enforceBans() {
    let removed = 0;
    for (const user of Array.from(this.users.values())) {
      const ban = this.access.banFor(user.name, addressKey(user.socket), user.steamId);
      if (!ban) continue;
      this.send(packets.kick(this.access.banNotice(ban)), user, { force: true });
      this.dropUser(user, "banned", "kick");
      removed += 1;
    }
    return removed;
  }

  // M7: re-read the access file into the live lists, then kick anyone the new
  // bans now cover. A broken file throws before the maps are replaced (see
  // access.load / fromJSON), so the current lists are kept and the error is
  // reported rather than the server coming up with no bans. Called by the
  // console `reload` command and the SIGHUP handler.
  reloadAccess() {
    try {
      const loaded = this.access.load();
      const removed = this.enforceBans();
      // 1.4.0: SteamID operator entries may have come or gone with the file.
      this.applySteamOps();
      return { ok: true, loaded, removed };
    } catch (error) {
      return { ok: false, error: error && error.message };
    }
  }

  // Слоты на лету. config.maxPlayers читается при каждом коннекте и в status(),
  // поэтому присвоения достаточно - кэша нет.
  //
  // Диапазон тот же, что у MAX_PLAYERS в config.js, и по той же причине: 64 -
  // это потолок, до которого разлёт трафика ещё считается терпимым.
  //
  // Уменьшение НИКОГО не выгоняет. Оператор, который набирает "maxplayers 4" на
  // полном сервере, просит "больше не пускать", а не "выкинуть двенадцать
  // человек посреди игры"; вторая трактовка стоила бы дороже и была бы
  // необратимой. Сервер просто стоит полным, пока люди не разойдутся сами.
  setMaxPlayers(value) {
    if (!Number.isInteger(value) || value < 1 || value > 64) {
      return { ok: false, error: "expected a whole number from 1 to 64" };
    }
    const previous = this.config.maxPlayers;
    this.config.maxPlayers = value;
    this.log.info("Slot limit changed from %d to %d.", previous, value);
    return { ok: true, previous, value, players: this.users.count() };
  }

  // -------------------------------------------------------------------------
  // Runtime rate-limit tuning
  //
  // Every one of these was fixed at startup from the environment, which meant
  // finding out a limit was wrong cost everybody their session. They are all
  // plain fields on live objects - TokenBucketStore reads this.capacity and
  // this.refillPerSecond on each take() - so changing one takes effect on the
  // next packet with no restart and no reconnect.
  //
  // Buckets already in flight keep the tokens they have. Lowering a limit
  // therefore tightens from now on rather than retroactively punishing someone
  // mid-burst, which is the behaviour an operator reaching for this actually
  // wants: they are reacting to something happening right now.
  //
  // The table is the single source of truth for the console command, its help
  // text and its validation, so a knob cannot be added in one place and
  // forgotten in another.
  // -------------------------------------------------------------------------

  limitTable() {
    const bucket = (store, what) => ({
      rate: {
        get: () => store.refillPerSecond,
        set: (v) => { store.refillPerSecond = v; },
        min: 0.01, max: 10000,
        help: `${what}: sustained rate, per second`,
      },
      burst: {
        get: () => store.capacity,
        set: (v) => { store.capacity = v; },
        min: 1, max: 100000, integer: true,
        help: `${what}: how many may arrive at once`,
      },
    });

    const address = bucket(this.byAddress, "any traffic from one address");
    const session = bucket(this.bySession, "any traffic from one session");
    const command = bucket(this.commands, "slash commands");
    const event = bucket(this.events, "checkpoints and spectate changes");
    const spray = bucket(this.sprayUploads, "spray upload pieces");
    const malformed = bucket(this.malformed, "malformed packets before the penalty box");
    const connect = bucket(this.connects, "connects from one address");
    const info = bucket(this.infoQueries, "server browser queries from one address");

    return {
      // The one that is not a bucket: a flat minimum gap between chat lines.
      "chat.interval": {
        get: () => this.config.chatMinIntervalMs,
        set: (v) => { this.config.chatMinIntervalMs = v; },
        min: 0, max: 60000, integer: true,
        help: "minimum milliseconds between one player's chat lines (0 = no limit)",
      },

      "address.rate": address.rate,
      "address.burst": address.burst,
      "session.rate": session.rate,
      "session.burst": session.burst,
      "command.rate": command.rate,
      "command.burst": command.burst,
      "event.rate": event.rate,
      "event.burst": event.burst,
      "spray.rate": spray.rate,
      "spray.burst": spray.burst,
      "malformed.rate": malformed.rate,
      "malformed.burst": malformed.burst,
      "connect.rate": connect.rate,
      "connect.burst": connect.burst,
      "info.rate": info.rate,
      "info.burst": info.burst,
      // One budget for the whole process, a second's worth at a time.
      "info.global": {
        get: () => this.infoGlobal.refillPerSecond,
        set: (v) => {
          this.infoGlobal.refillPerSecond = v;
          this.infoGlobal.capacity = v;
        },
        min: 1, max: 100000, integer: true,
        help: "server browser queries answered per second, from all addresses together",
      },

      // Whole-process ceiling. Capacity and refill move together: this one is a
      // rate, and a burst above it would let a flood through the door it exists
      // to hold shut.
      "global.rate": {
        get: () => this.global.refillPerSecond,
        set: (v) => {
          this.global.refillPerSecond = v;
          this.global.capacity = v;
          this.global.reserve = Math.min(
            Math.floor((v * this.config.globalReservePercent) / 100),
            v
          );
        },
        min: 100, max: 5000000, integer: true,
        help: "packets per second for the whole process, before parsing",
      },
      "global.reserve": {
        get: () => this.config.globalReservePercent,
        set: (v) => {
          this.config.globalReservePercent = v;
          this.global.reserve = Math.min(
            Math.floor((this.global.capacity * v) / 100),
            this.global.capacity
          );
        },
        min: 0, max: 100, integer: true,
        help: "percent of global.rate only confirmed sessions may spend",
      },

      "spray.chunksPerTick": {
        get: () => this.config.sprayChunksPerTick,
        set: (v) => { this.config.sprayChunksPerTick = v; },
        min: 1, max: 64, integer: true,
        help: "spray pieces handed to each player per 250 ms tick",
      },
    };
  }

  // Current values plus the counters that say whether a limit is biting. A
  // drop count that never moves means the limit is not the thing to change.
  limitSnapshot() {
    const table = this.limitTable();
    const rows = Object.keys(table).map((name) => ({
      name,
      value: table[name].get(),
      help: table[name].help,
    }));
    return {
      rows,
      dropped: {
        address: this.byAddress.dropped,
        session: this.bySession.dropped,
        command: this.commands.dropped,
        event: this.events.dropped,
        spray: this.sprayUploads.dropped,
        malformed: this.malformed.dropped,
        connect: this.connects.dropped,
        info: this.stats.infoDropped,
        global: this.global.dropped,
        globalUntrusted: this.global.droppedUntrusted,
      },
    };
  }

  setLimit(name, value) {
    const table = this.limitTable();
    // L3: `limits __proto__ 1` used to look an attacker-free but console-chosen
    // key up in a plain object, so table["__proto__"] was Object.prototype
    // (truthy) and knob.get threw. Own-property only.
    if (!Object.hasOwn(table, name)) {
      return { ok: false, error: `no such limit '${name}'`, names: Object.keys(table) };
    }
    const knob = table[name];
    if (!Number.isFinite(value)) {
      return { ok: false, error: "expected a number" };
    }
    if (knob.integer && !Number.isInteger(value)) {
      return { ok: false, error: `${name} must be a whole number` };
    }
    if (value < knob.min || value > knob.max) {
      return { ok: false, error: `${name} must be between ${knob.min} and ${knob.max}` };
    }

    const previous = knob.get();
    knob.set(value);
    this.log.info("Limit '%s' changed from %s to %s.", name, String(previous), String(value));
    return { ok: true, name, previous, value };
  }

  status() {
    const address = this.running ? this.socket.address() : null;
    // Protocol v2: how many sessions are authenticated, and how many are legacy
    // clients that still depend on the 1.2.0 protections (REQUIRE_PROTOCOL_V2).
    let v2 = 0;
    const launcher = { hlsr: 0, other: 0, unknown: 0, steamIds: 0 };
    for (const user of this.users.values()) {
      if (user.protocol === PROTOCOL_V2) v2 += 1;
      if (user.launcher === "hlsr") launcher.hlsr += 1;
      else if (user.launcher === "other") launcher.other += 1;
      else launcher.unknown += 1;
      if (user.steamId) launcher.steamIds += 1;
    }
    return {
      listening: address ? `${address.address}:${address.port}` : "not listening",
      serverName: this.config.serverName,
      players: this.users.count(),
      maxPlayers: this.config.maxPlayers,
      protocol: { v2, legacy: this.users.count() - v2 },
      // 1.4.0: what the clients said about themselves (self-reported).
      launcher,
      info: {
        enabled: this.config.serverInfo,
        queries: this.stats.infoQueries,
        challenges: this.stats.infoChallenges,
        replies: this.stats.infoReplies,
        dropped: this.stats.infoDropped,
      },
      uptimeSeconds: Math.floor((this.now() - this.stats.startedAt) / 1000),
      race: this.race.snapshot(),
      // Review 3 (R9): why sprays take minutes in a mass join.
      sprays: { reencodeQueued: this.reencodeQueued.size },
      access: {
        bans: this.access.bans().length,
        whitelistEnabled: this.access.whitelistEnabled,
        whitelist: this.access.whitelist().length,
        ops: this.access.ops().length,
        saveError: this.access.lastSaveError,
      },
      traffic: Object.assign({}, this.stats),
      limiters: {
        global: this.global.stats(),
        address: this.byAddress.stats(),
        session: this.bySession.stats(),
        connect: this.connects.stats(),
        malformed: this.malformed.stats(),
        command: this.commands.stats(),
        event: this.events.stats(),
        probe: this.probe.stats(),
        probeConnect: this.probeConnect.stats(),
        probeConnectAddress: this.probeConnectAddress.stats(),
        connectReserve: this.connectReserve.stats(),
        penaltyBox: this.penalty.size,
        pendingUnpause: this.pendingUnpause.size,
      },
      events: this.log.counts(),
    };
  }

  list() {
    const at = this.now();
    return Array.from(this.users.values()).map((user) => ({
      name: user.name,
      address: socketKey(user.socket),
      map: user.mapname,
      confirmed: user.confirmed,
      lastSeenSeconds: Math.floor((at - user.lastSeen) / 1000),
      // N2: seconds left on an impersonation guard, 0 when none.
      guardedSeconds: user.guardUntil > at ? Math.ceil((user.guardUntil - at) / 1000) : 0,
      // 1.4.0: "hlsr", "other" or null (no identity block), and the SteamID the
      // client announced (or null). Both are the client's word.
      launcher: user.launcher,
      launcherText: launcherText(user),
      steamId: user.steamId,
      protocol: user.protocol,
      operator: this.operatorSessions.get(this.users.key(user.name)) === user ? (user.opBySteam ? "steamid" : "console") : null,
    }));
  }
}

module.exports = {
  GhostingServer,
  RS,
  RACE_MAP,
  PENALTY_MS,
  DISCONNECT_GRACE_MS,
  GUARD_LOG_BURST,
  RESERVED_NAMES: require("./game/nickname").RESERVED,
  MAP_NAME,
  MODEL_PATH,
};
