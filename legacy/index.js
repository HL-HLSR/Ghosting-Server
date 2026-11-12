const dgram = require("dgram");
const readline = require("readline");

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

// ScriptedSnark: it was additional workaround to not crash the server,
// but it's just useless, can only protect players from getting edicts alloc error (can't)
const MAX_PLAYERS = parseInt(process.env.MAX_PLAYERS, 10) || 16;

// Minimum seconds between connect attempts from the same address:port.
// Mirrors the client-side hard cooldown of gh_online_connect (5s).
const CONNECT_COOLDOWN_MS = 5000;

// A user whose last packet is older than this is considered gone (crashed or
// lost connectivity) and gets swept. Kept generous so slow map loads survive.
const STALE_TIMEOUT_MS = 60000;

// How often the stale sweep runs.
const SWEEP_INTERVAL_MS = 5000;

// A registered name may be taken over by a new socket only if the old socket
// went silent for at least this long (crash + reconnect case).
const TAKEOVER_AFTER_MS = 10000;

// Chat limits.
const CHAT_MAX_LENGTH = 128;

// Minimum interval between accepted position updates ('l') from one user. The
// client sends every ~40ms (25/s); 30ms leaves margin for jitter while capping
// a flooder that would otherwise be fanned out to every other client.
const MIN_LINE_INTERVAL_MS = 30;
const CHAT_MIN_INTERVAL_MS = 600;

// --- Speedrun race ---
// Save everyone loads to start from, the map it lives on (for load detection),
// and the map whose finish trigger ends the race.
const RACE_SAVE = "start";
const RACE_MAP = "d1_trainstation_01";
const FINISH_MAP = "d3_breen_01";
// Lobby window after /race (env-overridable so tests don't wait a full minute).
const RACE_LOBBY_MS = parseInt(process.env.RACE_LOBBY_MS, 10) || 60000;
// How often the host pings every client so clients can detect a dropped link.
const HEARTBEAT_MS = 2000;

// Per-player race status shown in the HUD table (packet type 10).
const RS = { NONE: 0, READY: 1, LOADING: 2, INRACE: 3, DONE: 4 };

const MAX_NAME_LENGTH = 31;

// Set DEBUG=1 to log every line/update packet (very spammy).
const DEBUG = !!process.env.DEBUG;

// ---------------------------------------------------------------------------
// Packet reading
// ---------------------------------------------------------------------------

// Thrown when a packet is too short for the field being read
class BufferReadError extends Error {}

class Message {
  constructor(buffer, info) {
    this.buffer = buffer;
    this.socket = info;
    this.offset = 0;
  }

  // making sure there are at least `n` more bytes to read
  ensure(n) {
    if (this.offset + n > this.buffer.length) {
      throw new BufferReadError(
        `read past end of packet (need ${n} byte(s) at offset ${this.offset}, length ${this.buffer.length})`);
    }
  }

  readUInt8() {
    this.ensure(1);
    const result = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return result;
  }

  readInt32() {
    this.ensure(4);
    const result = this.buffer.readInt32BE(this.offset);
    this.offset += 4;
    return result;
  }

  readFloat() {
    this.ensure(4);
    const result = this.buffer.readFloatLE(this.offset);
    this.offset += 4;
    return result;
  }

  readString() {
    const size = this.readInt32();
    // Reject bogus lengths (negative or whatever) before touching the buffer
    if (size < 0 || size > 1024) {
      throw new BufferReadError(`bad string length ${size}`);
    }
    this.ensure(size);
    // latin1 is byte-preserving both ways, so whatever ANSI text the game
    // sends (e.g. cyrillic) survives the round trip unmangled.
    const string = this.buffer.toString("latin1", this.offset, this.offset + size);
    this.offset += size;
    return string;
  }
}

class MessageHandler {
  constructor() {
    this.listeners = {};
  }

  onMessage(message) {
    let opcode = message.readString();
    let handled = false;

    for (let listenerName in this.listeners) {
      if (opcode == listenerName) {
        let listener = this.listeners[listenerName];
        listener(message);
        handled = true;
        break;
      }
    }

    if (!handled)
      console.log("Unknown opcode '%s' from %s:%d!", opcode, message.socket.address, message.socket.port);
  }

  addListener(name, callback) {
    if (!(name in this.listeners)) {
      console.log("Successfully added a listener for '%s' message!", name);
      this.listeners[name] = callback;
    } else {
      console.error("Trying to add a listener '%s' that already exists!", name);
    }
  }
}

class Vector3 {
  constructor(x = 0, y = 0, z = 0) {
    this.x = x;
    this.y = y;
    this.z = z;
  }
}

class BufferWriter {
  constructor() {
    this.buffer = null;
  }

  addBuffer(buffer) {
    if (this.buffer) this.buffer = Buffer.concat([this.buffer, buffer]);
    else this.buffer = buffer;
  }

  writeInt8(value) {
    let buffer = Buffer.alloc(1);
    buffer.writeInt8(value);
    this.addBuffer(buffer);
  }

  writeUInt8(value) {
    let buffer = Buffer.alloc(1);
    buffer.writeUInt8(value);
    this.addBuffer(buffer);
  }

  writeInt32(value) {
    let buffer = Buffer.alloc(4);
    buffer.writeInt32BE(value);
    this.addBuffer(buffer);
  }

  writeFloat(value) {
    let buffer = Buffer.alloc(4);
    buffer.writeFloatLE(value);
    this.addBuffer(buffer);
  }

  writeString(value) {
    const payload = Buffer.from(value, "latin1");
    let buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(payload.length);
    this.addBuffer(buffer);
    this.addBuffer(payload);
  }
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

const socketKey = (socket) => `${socket.address}:${socket.port}`;

// Remove control bytes (0x00-0x1F, 0x7F) from untrusted text. These would
// otherwise let a client inject terminal escape sequences into the server
// operator's console, or in-game chat color-code bytes into other clients.
const sanitizeText = (s) => s.replace(/[\x00-\x1F\x7F]/g, "");

// Reject non-finite (NaN/Infinity) or absurdly large numbers before we store
// and rebroadcast them - otherwise clients get NaN positions/velocities.
const isSaneNumber = (n) => Number.isFinite(n) && Math.abs(n) < 1e6;

class User {
  constructor(name, socket, trailLength, trailRed, trailGreen, trailBlue, ghostRed, ghostGreen, ghostBlue) {
    this.name = name;
    this.socket = socket;
    this.mapname = "unknown";
    this.trailLength = trailLength;
    this.trailRed = trailRed;
    this.trailGreen = trailGreen;
    this.trailBlue = trailBlue;
    this.ghostRed = ghostRed;
    this.ghostGreen = ghostGreen;
    this.ghostBlue = ghostBlue;
    this.position = new Vector3(0, 0, 0);
    this.velocity = new Vector3(0, 0, 0);
    this.pitch = 0;
    this.yaw = 0;
    this.paused = 0;
    this.weapon = 0;
    // Sender stats for first-person spectators (-1 = unknown/none).
    this.hp = -1;
    this.armor = -1;
    this.clip = -1;
    this.ammo = -1;
    // Prop carried with +use ("" = nothing) + its world position/angles.
    this.heldModel = "";
    this.heldPos = new Vector3(0, 0, 0);
    this.heldAng = new Vector3(0, 0, 0);
    // Eye height over the origin (crouch state); 64 = standing.
    this.eyeZ = 64;
    this.lastSeen = Date.now();
    this.lastChatTime = 0;
    this.lastLineTime = 0;
  }

  touch() {
    this.lastSeen = Date.now();
  }

  updateInfo(mapname, position, velocity, pitch, yaw, paused, weapon, hp, armor, clip, ammo, heldModel, heldPos, heldAng, eyeZ) {
    this.mapname = mapname;
    this.position = position;
    this.velocity = velocity;
    this.pitch = pitch;
    this.yaw = yaw;
    this.paused = paused;
    this.weapon = weapon;
    this.hp = hp;
    this.armor = armor;
    this.clip = clip;
    this.ammo = ammo;
    this.heldModel = heldModel;
    this.heldPos = heldPos;
    this.heldAng = heldAng;
    this.eyeZ = eyeZ;
  }

  // announce = true  -> a fresh join the receiver should show in chat
  // announce = false -> a silent roster entry (sent to a user on their own connect)
  createConnectBuffer(announce) {
    let writer = new BufferWriter();

    writer.writeInt8(0);
    writer.writeString(this.name);
    writer.writeUInt8(this.trailLength);
    writer.writeUInt8(this.trailRed);
    writer.writeUInt8(this.trailGreen);
    writer.writeUInt8(this.trailBlue);
    writer.writeUInt8(this.ghostRed);
    writer.writeUInt8(this.ghostGreen);
    writer.writeUInt8(this.ghostBlue);
    writer.writeUInt8(announce ? 1 : 0);

    return writer.buffer;
  }

  // reason is a short code the client turns into a chat line: "left"/"kick"/"timeout"
  createDisconnectBuffer(reason) {
    let writer = new BufferWriter();

    writer.writeInt8(4);
    writer.writeString(this.name);
    writer.writeString(reason || "left");

    return writer.buffer;
  }

  createInfoBuffer() {
    let writer = new BufferWriter();

    writer.writeInt8(1);
    writer.writeString(this.name);
    writer.writeString(this.mapname);
    writer.writeFloat(this.velocity.x);
    writer.writeFloat(this.velocity.y);
    writer.writeFloat(this.velocity.z);
    writer.writeFloat(this.position.x);
    writer.writeFloat(this.position.y);
    writer.writeFloat(this.position.z);
    writer.writeFloat(this.pitch);
    writer.writeFloat(this.yaw);
    writer.writeUInt8(this.paused ? 1 : 0);
    // Weapon id the sender is holding (see ghost_weapons.h in the mod); trailing
    // optional byte so older clients simply never read it.
    writer.writeUInt8(this.weapon & 0xFF);
    // Sender stats for first-person spectators (trailing optional floats).
    writer.writeFloat(this.hp);
    writer.writeFloat(this.armor);
    writer.writeFloat(this.clip);
    writer.writeFloat(this.ammo);
    // Carried prop mirror ("" = holding nothing).
    writer.writeString(this.heldModel || "");
    writer.writeFloat(this.heldPos.x);
    writer.writeFloat(this.heldPos.y);
    writer.writeFloat(this.heldPos.z);
    writer.writeFloat(this.heldAng.x);
    writer.writeFloat(this.heldAng.y);
    writer.writeFloat(this.heldAng.z);
    // Eye height (crouch state) for first-person spectators.
    writer.writeFloat(this.eyeZ);

    return writer.buffer;
  }
}

class UserManager {
  constructor() {
    // Object.create(null): a prototype-less map so nicknames like "__proto__",
    // "constructor" or "toString" can't collide with Object.prototype members
    // (which would make userExists()/getUser() misbehave and corrupt state).
    this.users = Object.create(null);
  }

  registerUser(name, socket, trailLength, trailRed, trailGreen, trailBlue, ghostRed, ghostGreen, ghostBlue) {
    if (!this.userExists(name)) {
      this.users[name] = new User(name, socket, trailLength, trailRed, trailGreen, trailBlue, ghostRed, ghostGreen, ghostBlue);
      console.log("Successfully registered user '%s' (%s)!", name, socketKey(socket));
    } else {
      console.log("Trying to register an already existing user '%s'!", name);
    }

    return this.users[name];
  }

  unregisterUser(name) {
    if (this.userExists(name)) {
      delete this.users[name];
      console.log("Successfully unregistered user '%s'!", name);
    } else {
      console.log("Trying to unregister user '%s' that doesn't exist!", name);
    }
  }

  getUser(name) {
    // Own-property only: never walk a prototype chain (there is none now, but
    // this stays correct even if the map type changes later).
    return Object.prototype.hasOwnProperty.call(this.users, name) ? this.users[name] : null;
  }

  userExists(name) {
    return Object.prototype.hasOwnProperty.call(this.users, name);
  }

  count() {
    return Object.keys(this.users).length;
  }
}

const userManager = new UserManager();
const messageHandler = new MessageHandler();
const server = dgram.createSocket("udp4");

// ---------------------------------------------------------------------------
// Send helpers
// ---------------------------------------------------------------------------

// Tell a client it was rejected/removed (packet type 5 = kick, with a reason string).
const sendKick = (socket, reason) => {
  let writer = new BufferWriter();
  writer.writeInt8(5);
  writer.writeString(reason);
  server.send(writer.buffer, socket.port, socket.address);
};

// Confirm to a client that its connect was accepted (packet type 7, no payload).
const sendConnectAccepted = (socket) => {
  let writer = new BufferWriter();
  writer.writeInt8(7);
  server.send(writer.buffer, socket.port, socket.address);
};

// Chat messages get an incrementing id so clients can drop UDP duplicates
// and keep a consistent order (packet type 6).
let nextChatMessageId = 1;

const createChatBuffer = (name, text) => {
  let writer = new BufferWriter();
  writer.writeInt8(6);
  writer.writeInt32(nextChatMessageId++);
  writer.writeString(name);
  writer.writeString(text);
  return writer.buffer;
};

// Send a raw buffer to every registered user; `exceptName` skips one of them.
const broadcast = (buffer, exceptName = null) => {
  for (let name in userManager.users) {
    if (name === exceptName) continue;
    let user = userManager.users[name];
    server.send(buffer, user.socket.port, user.socket.address);
  }
};

// Chat as the (reserved) "SERVER" nick - shown red on clients.
const serverSay = (text) => {
  console.log("[SERVER] %s", text);
  broadcast(createChatBuffer("SERVER", text));
};

// Private SERVER line to a single user.
const serverSayTo = (user, text) => {
  if (!user) return;
  console.log("[SERVER->%s] %s", user.name, text);
  server.send(createChatBuffer("SERVER", text), user.socket.port, user.socket.address);
};

// packet type 8 = force the client to load a map (map <name>).
const sendForceMap = (socket, mapname) => {
  let w = new BufferWriter();
  w.writeInt8(8);
  w.writeString(mapname);
  server.send(w.buffer, socket.port, socket.address);
};

// packet type 9 = server-driven pause the player can't lift (on/off + overlay label).
const sendServerPause = (socket, on, label) => {
  let w = new BufferWriter();
  w.writeInt8(9);
  w.writeUInt8(on ? 1 : 0);
  w.writeString(label || "");
  server.send(w.buffer, socket.port, socket.address);
};

// packet type 10 = per-player race status for the HUD table (name, status, isRunner).
const broadcastRaceStatus = (name, statusCode, isRunner) => {
  let w = new BufferWriter();
  w.writeInt8(10);
  w.writeString(name);
  w.writeUInt8(statusCode);
  w.writeUInt8(isRunner ? 1 : 0);
  broadcast(w.buffer);
};

// packet type 12 = play a 2D sound on every client (path relative to sound/).
// Used for the 3/2/1 countdown beeps and the race-announcement hint, so the whole
// server hears them on the same beat.
const broadcastPlaySound = (soundPath) => {
  let w = new BufferWriter();
  w.writeInt8(12);
  w.writeString(soundPath);
  broadcast(w.buffer);
};

// Sound paths (relative to the game's sound/ folder). Change here if you move them.
const SND_COUNTDOWN = { 3: "server/three.wav", 2: "server/two.wav", 1: "server/one.wav" };
const SND_RACE_HINT = "server/hint.wav";

// Remove a user and tell everyone else they left (packet type 4).
// wireReason ("left"/"kick"/"timeout") drives the chat line other clients show.
const dropUser = (user, logReason, wireReason) => {
  userManager.unregisterUser(user.name);
  broadcast(user.createDisconnectBuffer(wireReason || "left"));
  if (logReason) console.log("Dropped '%s': %s", user.name, logReason);
  // Pull them out of any race and clean up its state.
  race.onPlayerDrop(user.name, wireReason);
};

// ---------------------------------------------------------------------------
// Speedrun race state machine
//
// Phases: idle -> lobby -> countdown_map -> loading -> staging ->
//         countdown_start -> racing -> (all finished) -> idle
//
// All player-facing chat is from SERVER, in English. Durations are driven by
// setTimeout chains for the fixed countdowns and by tick() for the lobby window.
// ---------------------------------------------------------------------------
class RaceManager {
  constructor() { this.reset(); }

  reset() {
    this.phase = "idle";
    this.creator = null;
    this.runners = new Set();   // participant names
    this.loaded = new Set();    // runners who loaded RACE_MAP
    this.staged = new Set();    // runners frozen at the pre-teleport pause point
    this.finished = [];         // names in finish order
    this.lobbyEndsAt = 0;
    this.warned30 = false;
    this.warned10 = false;
    this.clearTimers();
  }

  clearTimers() {
    if (this._timers) for (const t of this._timers) clearTimeout(t);
    this._timers = [];
  }

  after(ms, fn) {
    const t = setTimeout(() => { try { fn(); } catch (e) { console.log("race timer error: %s", e.message); } }, ms);
    this._timers.push(t);
  }

  active() { return this.phase !== "idle"; }
  isRunner(name) { return this.runners.has(name); }

  setStatus(name, code) { broadcastRaceStatus(name, code, this.runners.has(name)); }

  // ---- Chat commands (routed from the 'm' handler) ----
  cmdRace(name) {
    if (this.phase !== "idle") {
      serverSayTo(userManager.getUser(name), "A race is already in progress. Please wait until it finishes.");
      return;
    }
    this.reset();
    this.phase = "lobby";
    this.creator = name;
    this.runners.add(name);
    this.setStatus(name, RS.READY);
    this.lobbyEndsAt = Date.now() + RACE_LOBBY_MS;
    // Announce to the whole server + play the hint so nobody misses it.
    broadcastPlaySound(SND_RACE_HINT);
    serverSay(`${name} wants to start a speedrun race! Type /ready to join. The race begins in ${Math.round(RACE_LOBBY_MS / 1000)} seconds.`);
    serverSay(`Every racer MUST have a save named '${RACE_SAVE}' (${RACE_SAVE}.sav) - the race loads it. Create it before you join!`);
  }

  cmdReady(name) {
    if (this.phase !== "lobby") {
      serverSayTo(userManager.getUser(name),
        this.phase === "idle" ? "There is no race to join. Type /race to start one."
                              : "The race lobby is closed - you can't join anymore.");
      return;
    }
    if (this.runners.has(name)) return;
    this.runners.add(name);
    this.setStatus(name, RS.READY);
    serverSay(`${name} is ready for the race!`);
  }

  // ---- Lobby timer + warnings ----
  tick(now) {
    if (this.phase !== "lobby") return;
    const remain = this.lobbyEndsAt - now;
    if (!this.warned30 && remain <= 30000 && RACE_LOBBY_MS > 30000) {
      this.warned30 = true;
      serverSay("30 seconds left. Type /ready to join the race!");
    }
    if (!this.warned10 && remain <= 10000 && RACE_LOBBY_MS > 10000) {
      this.warned10 = true;
      serverSay("The race begins in 10 seconds!");
    }
    if (remain <= 0) this.startMapCountdown();
  }

  startMapCountdown() {
    this.phase = "countdown_map";
    serverSay("3...");            broadcastPlaySound(SND_COUNTDOWN[3]);
    this.after(1000, () => { serverSay("2..."); broadcastPlaySound(SND_COUNTDOWN[2]); });
    this.after(2000, () => { serverSay("1..."); broadcastPlaySound(SND_COUNTDOWN[1]); });
    this.after(3000, () => { serverSay(`Loading the race save '${RACE_SAVE}'...`); this.beginLoading(); });
  }

  beginLoading() {
    this.phase = "loading";
    this.loaded.clear();
    for (const name of this.runners) {
      const user = userManager.getUser(name);
      if (user) { sendForceMap(user.socket, RACE_SAVE); this.setStatus(name, RS.LOADING); }
    }
  }

  // Driven by the 'l' map field: a runner reporting RACE_MAP has finished loading.
  onMapUpdate(name, mapname) {
    if (this.phase !== "loading" || !this.runners.has(name) || this.loaded.has(name)) return;
    if (mapname !== RACE_MAP) return;
    this.loaded.add(name);
    this.setStatus(name, RS.READY);
    serverSay(`${name} has loaded in!`);
    if (this.loaded.size === this.runners.size && this.runners.size > 0) {
      this.phase = "staging";
    }
  }

  // Client checkpoints: 1 = reached the pre-teleport pause point, 2 = finished.
  onCheckpoint(name, cp) {
    if (cp === 1) {
      if (this.phase !== "staging" && this.phase !== "loading") return;
      if (!this.runners.has(name) || this.staged.has(name)) return;
      this.staged.add(name);
      const user = userManager.getUser(name);
      if (user) sendServerPause(user.socket, true, "PAUSED BY SERVER");
      this.setStatus(name, RS.READY);
      serverSay(`${name} is ready to start! Waiting for the others...`);
      if (this.staged.size === this.runners.size && this.runners.size > 0) this.startRaceCountdown();
    } else if (cp === 2) {
      if (this.phase !== "racing" || !this.runners.has(name) || this.finished.includes(name)) return;
      this.finished.push(name);
      this.setStatus(name, RS.DONE);
      const place = this.finished.length;
      const ord = place === 1 ? "first" : place === 2 ? "second" : place === 3 ? "third" : null;
      serverSay(ord ? `${name} finished the speedrun ${ord}!` : `${name} finished the speedrun!`);
      if (this.finished.length === this.runners.size && this.runners.size > 0) {
        serverSay("Race over! GG!");
        this.endRace();
      }
    }
  }

  startRaceCountdown() {
    this.phase = "countdown_start";
    serverSay("All players are ready, starting the race!");
    serverSay("3...");            broadcastPlaySound(SND_COUNTDOWN[3]);
    this.after(1000, () => { serverSay("2..."); broadcastPlaySound(SND_COUNTDOWN[2]); });
    this.after(2000, () => { serverSay("1..."); broadcastPlaySound(SND_COUNTDOWN[1]); });
    // One extra second after "1..." so everyone releases on the same beat.
    this.after(4000, () => {
      this.phase = "racing";
      for (const name of this.runners) {
        const user = userManager.getUser(name);
        if (user) sendServerPause(user.socket, false, "");
        this.setStatus(name, RS.INRACE);
      }
    });
  }

  endRace() {
    for (const name of this.runners) {
      const user = userManager.getUser(name);
      if (user) sendServerPause(user.socket, false, "");
      this.setStatus(name, RS.NONE);
    }
    this.reset();
  }

  onPlayerDrop(name, wireReason) {
    if (!this.runners.has(name)) return;
    this.runners.delete(name);
    this.loaded.delete(name);
    this.staged.delete(name);
    const reason = wireReason === "timeout" ? "TIMED OUT" : wireReason === "kick" ? "KICKED" : "LEFT";
    serverSay(`${name} was removed from the race. Reason: ${reason}`);
    broadcastRaceStatus(name, RS.NONE, false);

    if (this.runners.size === 0) {
      serverSay("Race cancelled - no players left.");
      this.endRace();
      return;
    }
    // The player we were waiting on may have been the last blocker.
    if (this.phase === "loading" && this.loaded.size === this.runners.size) {
      this.phase = "staging";
      serverSay("Before the race starts, the game will pause automatically. Please wait for it to end.");
    } else if (this.phase === "staging" && this.staged.size === this.runners.size) {
      this.startRaceCountdown();
    } else if (this.phase === "racing" && this.finished.length === this.runners.size) {
      serverSay("Race over! GG!");
      this.endRace();
    }
  }
}

const race = new RaceManager();

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------

// address:port -> timestamp of the last connect attempt (for rate limiting)
const connectAttempts = new Map();

const registerUser = (username, socket, trailLength, trailRed, trailGreen, trailBlue, ghostRed, ghostGreen, ghostBlue) => {
  const connectedUser = userManager.registerUser(username, socket, trailLength, trailRed, trailGreen, trailBlue, ghostRed, ghostGreen, ghostBlue);

  // Confirm the accept to the joining client (it shows "Connected..." only now).
  sendConnectAccepted(connectedUser.socket);

  // Announce the fresh join to everyone else (they show it in chat).
  broadcast(connectedUser.createConnectBuffer(true), username);

  // Send the existing roster to the newly connected user - silently (announce=false),
  // so they don't get a "joined" spam line for everyone already on the server.
  for (let name in userManager.users) {
    if (name == username) continue;

    let otherUser = userManager.users[name];
    server.send(otherUser.createConnectBuffer(false), connectedUser.socket.port, connectedUser.socket.address);
  }
}

messageHandler.addListener('c', (message) => {
  // Connect command
  let username = sanitizeText(message.readString()).trim();
  let trailLength = message.readUInt8();
  let trailRed = message.readUInt8();
  let trailGreen = message.readUInt8();
  let trailBlue = message.readUInt8();
  let ghostRed = message.readUInt8();
  let ghostGreen = message.readUInt8();
  let ghostBlue = message.readUInt8();

  if (username.length === 0) {
    console.log("Rejecting connect with an empty name from %s.", socketKey(message.socket));
    sendKick(message.socket, "Invalid name. Set gh_name before connecting.");
    return;
  }
  if (username.length > MAX_NAME_LENGTH) username = username.substring(0, MAX_NAME_LENGTH);

  // "SERVER" is reserved for host/broadcast messages (shown in red on clients),
  // so no player may impersonate it.
  if (username.toUpperCase() === "SERVER") {
    console.log("Rejecting reserved name 'SERVER' from %s.", socketKey(message.socket));
    sendKick(message.socket, "The name 'SERVER' is reserved.");
    return;
  }

  const now = Date.now();
  const key = socketKey(message.socket);
  const existing = userManager.getUser(username);

  // A duplicate connect from the exact same socket is harmless (the client
  // may re-announce after confusion) - just resend the roster, rate-limited.
  if (existing && socketKey(existing.socket) === key) {
    if (now - (connectAttempts.get(key) ?? 0) < CONNECT_COOLDOWN_MS) return;
    connectAttempts.set(key, now);
    existing.touch();
    for (let name in userManager.users) {
      if (name == username) continue;
      server.send(userManager.users[name].createConnectBuffer(false), existing.socket.port, existing.socket.address);
    }
    console.log("Re-sent roster to '%s' (duplicate connect).", username);
    return;
  }

  // Server-side connect rate limit per address:port. Don't punish registered
  // users (handled above); everyone else gets told to slow down.
  const lastAttempt = connectAttempts.get(key) ?? 0;
  connectAttempts.set(key, now);
  if (now - lastAttempt < CONNECT_COOLDOWN_MS) {
    console.log("Connect spam from %s ('%s'); ignoring.", key, username);
    sendKick(message.socket, "Connect cooldown active. Try again later.");
    return;
  }

  if (existing) {
    // Same name from a different socket: allow the takeover only if the old
    // socket looks dead (crash + reconnect), otherwise it's a name collision.
    if (now - existing.lastSeen >= TAKEOVER_AFTER_MS) {
      console.log("'%s' reconnected from %s (old socket %s was stale).", username, key, socketKey(existing.socket));
      // Drop the old registration silently (no disconnect broadcast: the ghost
      // is immediately replaced by the same name, so other clients keep it).
      userManager.unregisterUser(username);
    } else {
      console.log("Rejecting '%s' from %s: name is already in use by %s.", username, key, socketKey(existing.socket));
      // Keep this under ~63 chars incl. the nick: the client stores the reason
      // in a 64-byte buffer (name is already capped to 31 above).
      sendKick(message.socket, "Nickname '" + username + "' is already in use.");
      return;
    }
  }

  if (userManager.count() >= MAX_PLAYERS) {
    console.log("Server full (%d/%d); rejecting '%s'.", userManager.count(), MAX_PLAYERS, username);
    sendKick(message.socket, "Ghost server is full.");
    return;
  }

  registerUser(username, message.socket, trailLength, trailRed, trailGreen, trailBlue, ghostRed, ghostGreen, ghostBlue);
});

// ---------------------------------------------------------------------------
// Line/update
// ---------------------------------------------------------------------------

messageHandler.addListener('l', (message) => {
  // Line command
  let username = sanitizeText(message.readString());
  let mapname = sanitizeText(message.readString());
  let velocity = new Vector3(message.readFloat(), message.readFloat(), message.readFloat());
  let position = new Vector3(message.readFloat(), message.readFloat(), message.readFloat());
  let pitch = message.readFloat();
  let yaw = message.readFloat();
  // Paused flag is optional (absent from older clients) -> default to not paused.
  let paused = (message.offset < message.buffer.length) ? message.readUInt8() : 0;
  // Weapon id is optional too (added after paused) -> default to 0 = unknown.
  let weapon = (message.offset < message.buffer.length) ? message.readUInt8() : 0;
  // Stats are optional trailing floats (added after weapon) -> default -1 = unknown.
  const readOptFloat = () => (message.offset + 4 <= message.buffer.length) ? message.readFloat() : -1;
  let hp = readOptFloat();
  let armor = readOptFloat();
  let clip = readOptFloat();
  let ammo = readOptFloat();
  // Carried prop (optional trailing string + 6 floats; "" = holding nothing).
  // Model paths only ever contain [a-z0-9_\-./]; anything else (or a path
  // traversal) is treated as empty so we never relay garbage.
  let heldModel = "";
  if (message.offset + 4 <= message.buffer.length) {
    heldModel = sanitizeText(message.readString());
    if (heldModel.length > 96 || heldModel.includes("..") || !/^[a-zA-Z0-9_\-./]*$/.test(heldModel)) {
      heldModel = "";
    }
  }
  const readOptFloat0 = () => (message.offset + 4 <= message.buffer.length) ? message.readFloat() : 0;
  let heldPos = new Vector3(readOptFloat0(), readOptFloat0(), readOptFloat0());
  let heldAng = new Vector3(readOptFloat0(), readOptFloat0(), readOptFloat0());
  if (![heldPos.x, heldPos.y, heldPos.z, heldAng.x, heldAng.y, heldAng.z].every(isSaneNumber)) {
    heldModel = "";
    heldPos = new Vector3(0, 0, 0);
    heldAng = new Vector3(0, 0, 0);
  }
  // Eye height (optional trailing float; crouch state). 64 = standing default.
  let eyeZ = (message.offset + 4 <= message.buffer.length) ? message.readFloat() : 64;
  if (!isSaneNumber(eyeZ) || eyeZ < 0 || eyeZ > 128) eyeZ = 64;

  let updatedUser = userManager.getUser(username);
  if (!updatedUser) return;

  // Only the socket that registered the name may drive its ghost.
  if (socketKey(updatedUser.socket) !== socketKey(message.socket)) return;

  // Drop garbage numbers (NaN/Infinity/absurd) so we never rebroadcast a
  // ghost to an impossible position/velocity.
  if (![velocity.x, velocity.y, velocity.z, position.x, position.y, position.z, pitch, yaw].every(isSaneNumber)) {
    return;
  }

  // Per-user throttle: keep the fresh timeout alive (touch) but don't rebroadcast
  // faster than the legitimate ~25/s cadence, capping amplification from a flooder.
  const nowLine = Date.now();
  updatedUser.touch();
  if (nowLine - updatedUser.lastLineTime < MIN_LINE_INTERVAL_MS) return;
  updatedUser.lastLineTime = nowLine;

  // Sanitize stats too (they're rebroadcast as-is).
  if (!isSaneNumber(hp)) hp = -1;
  if (!isSaneNumber(armor)) armor = -1;
  if (!isSaneNumber(clip)) clip = -1;
  if (!isSaneNumber(ammo)) ammo = -1;

  updatedUser.updateInfo(mapname, position, velocity, pitch, yaw, paused, weapon, hp, armor, clip, ammo, heldModel, heldPos, heldAng, eyeZ);
  // Loading-progress detection for the race (runner reporting the race map).
  race.onMapUpdate(username, mapname);

  if (DEBUG) console.log(`Updated user ${username}`, updatedUser);

  // Send info about the update to other users
  broadcast(updatedUser.createInfoBuffer(), username);
});

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

messageHandler.addListener('d', (message) => {
  // Disconnect command
  let username = sanitizeText(message.readString());

  const disconnectedUser = userManager.getUser(username);
  if (!disconnectedUser) return;

  // Only the owning socket may disconnect the name.
  if (socketKey(disconnectedUser.socket) !== socketKey(message.socket)) return;

  dropUser(disconnectedUser, "disconnected", "left");
});

// ---------------------------------------------------------------------------
// Chat (opcode 'm' in, packet type 6 out)
// ---------------------------------------------------------------------------

messageHandler.addListener('m', (message) => {
  let username = sanitizeText(message.readString());
  let text = message.readString();

  const user = userManager.getUser(username);
  if (!user) return; // not registered (or already kicked/dropped)

  // Only the socket that owns the name may chat as it.
  if (socketKey(user.socket) !== socketKey(message.socket)) return;

  // Strip control characters, collapse to a trimmed line.
  text = text.replace(/[\x00-\x1F\x7F]/g, " ").trim();
  if (text.length === 0) return;
  if (text.length > CHAT_MAX_LENGTH) text = text.substring(0, CHAT_MAX_LENGTH);

  // Slash-commands are consumed here (never echoed as chat).
  if (text[0] === "/") {
    const cmd = text.slice(1).split(/\s+/)[0].toLowerCase();
    user.touch();
    if (cmd === "race") race.cmdRace(username);
    else if (cmd === "ready") race.cmdReady(username);
    else serverSayTo(user, `Unknown command '/${cmd}'.`);
    return;
  }

  const now = Date.now();
  if (now - user.lastChatTime < CHAT_MIN_INTERVAL_MS) return; // chat spam, drop
  user.lastChatTime = now;
  user.touch();

  console.log("[chat] %s: %s", username, text);

  // Broadcast to everyone INCLUDING the sender: the sender displays the
  // message only when it comes back, so there are no local duplicates.
  broadcast(createChatBuffer(username, text));
});

// ---------------------------------------------------------------------------
// Race checkpoint (opcode 'r' in): the client reached a scripted race moment.
// checkpoint: 1 = pre-teleport pause point on the start map, 2 = finish trigger.
// ---------------------------------------------------------------------------

messageHandler.addListener('r', (message) => {
  let username = sanitizeText(message.readString());
  let checkpoint = message.readUInt8();

  const user = userManager.getUser(username);
  if (!user) return;
  if (socketKey(user.socket) !== socketKey(message.socket)) return;

  user.touch();
  race.onCheckpoint(username, checkpoint);
});

// ---------------------------------------------------------------------------
// Spectate state (opcode 's' in, packet type 13 out)
// ---------------------------------------------------------------------------

const broadcastSpectate = (name, target) => {
  let w = new BufferWriter();
  w.writeInt8(13); w.writeString(name); w.writeString(target || "");
  broadcast(w.buffer);
};
messageHandler.addListener('s', (message) => {
  let username = sanitizeText(message.readString());
  let target = sanitizeText(message.readString());
  const user = userManager.getUser(username);
  if (!user) return;
  if (socketKey(user.socket) !== socketKey(message.socket)) return;
  user.touch(); user.spectating = target || "";
  broadcastSpectate(username, user.spectating);
});

// ---------------------------------------------------------------------------
// Stale client sweep
// ---------------------------------------------------------------------------

setInterval(() => {
  const now = Date.now();
  for (let name of Object.keys(userManager.users)) {
    const user = userManager.users[name];
    if (now - user.lastSeen > STALE_TIMEOUT_MS) {
      sendKick(user.socket, "Timed out.");
      dropUser(user, "timed out", "timeout");
    }
  }
  // Keep the connect rate-limit map from growing forever.
  for (let [key, time] of connectAttempts) {
    if (now - time > CONNECT_COOLDOWN_MS * 4) connectAttempts.delete(key);
  }
}, SWEEP_INTERVAL_MS);

// Race lobby timer / warnings.
setInterval(() => race.tick(Date.now()), 250);

// Heartbeat: ping every client so a client whose link drops (and therefore stops
// hearing us) can notice and tear down locally - crucial so a race pause never
// leaves a disconnected player frozen. Packet type 11, no payload.
setInterval(() => {
  const w = new BufferWriter();
  w.writeInt8(11);
  broadcast(w.buffer);
}, HEARTBEAT_MS);

// ---------------------------------------------------------------------------
// Server console (stdin) commands
// ---------------------------------------------------------------------------

const consoleHelp = () => {
  console.log("Available commands:");
  console.log('  help                     - show this help');
  console.log('  status                   - show server status');
  console.log('  list                     - list connected users');
  console.log('  gh_online_kick "Nick"    - kick a user by name');
  console.log('  kick "Nick"              - alias for gh_online_kick');
  console.log('  broadcast "message"      - send a chat message to everyone as SERVER');
};

const consoleStatus = () => {
  console.log("Ghosting dedicated host on UDP port %d", 22228);
  console.log("Players: %d/%d", userManager.count(), MAX_PLAYERS);
  console.log("Uptime: %d seconds", Math.floor(process.uptime()));
};

const consoleList = () => {
  const count = userManager.count();
  console.log("Connected users: %d/%d", count, MAX_PLAYERS);
  const now = Date.now();
  for (let name in userManager.users) {
    const user = userManager.users[name];
    console.log("  %s (%s) - map: %s, last seen %ds ago",
      name, socketKey(user.socket), user.mapname, Math.floor((now - user.lastSeen) / 1000));
  }
};

const consoleKick = (nick) => {
  if (!nick) {
    console.log('Usage: gh_online_kick "Nick"');
    return;
  }
  const user = userManager.getUser(nick);
  if (!user) {
    console.log("No user named '%s' is connected. Use 'list' to see who is online.", nick);
    return;
  }
  sendKick(user.socket, "You were kicked from the server.");
  dropUser(user, "kicked by server console", "kick");
};

const consoleBroadcast = (text) => {
  if (!text) {
    console.log('Usage: broadcast "message"');
    return;
  }
  text = text.trim();
  if (text.length === 0) return;
  if (text.length > CHAT_MAX_LENGTH) text = text.substring(0, CHAT_MAX_LENGTH);
  console.log("[chat] SERVER: %s", text);
  broadcast(createChatBuffer("SERVER", text));
};

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.on("line", (line) => {
  line = line.trim();
  if (line.length === 0) return;

  // command ["quoted arg" | bare rest]
  const match = line.match(/^(\S+)\s*(?:"([^"]*)"|(.*))?$/);
  const command = match[1].toLowerCase();
  const arg = (match[2] !== undefined ? match[2] : match[3] ?? "").trim();

  switch (command) {
    case "help": consoleHelp(); break;
    case "status": consoleStatus(); break;
    case "list": consoleList(); break;
    case "gh_online_kick":
    case "kick": consoleKick(arg); break;
    case "broadcast": consoleBroadcast(arg); break;
    default:
      console.log("Unknown command '%s'. Type 'help' for a list of commands.", command);
  }
});

// ---------------------------------------------------------------------------
// Socket events
// ---------------------------------------------------------------------------

server.on("message", function (buffer, socket) {
  try {
    let message = new Message(buffer, socket);
    messageHandler.onMessage(message);
  } catch (e) {
    // Never let one malformed datagram crash everything
    console.log("Dropped malformed packet from %s:%d - %s", socket.address, socket.port, e.message);
  }
});

//emits when socket is ready and listening for datagram msgs
server.on("listening", function () {
  var address = server.address();
  var port = address.port;
  var family = address.family;
  var ipaddr = address.address;
  console.log("Server is listening at port " + port);
  console.log("Server ip: " + ipaddr);
  console.log("Server is IP4/IP6: " + family);
  console.log("Type 'help' for a list of console commands.");
});

// emits when any error occurs
server.on("error", function (error) {
  console.log("Error: " + error);
  server.close();
});

//emits after the socket is closed using socket.close();
server.on("close", function () {
  console.log("Socket is closed !");
});

server.bind(22228);
