"use strict";

// Every packet the server emits, in one place.
//
// The byte layout is frozen: the clients that read these packets are already
// compiled and shipped, so a field added, removed or reordered here is a broken
// player, not a failing test. test/wire-golden.test.js pins each function
// against a fixture captured from the pre-hardening server.
//
// Strings are truncated to the size of the buffer the client reads them into.
// The old server relied on a comment ("keep this under ~63 chars") to stay
// inside the client's 64 byte reason buffer; a nickname long enough could push
// past it. Truncation is now enforced by the writer.

const { BufferWriter } = require("./writer");
const limits = require("./limits");
const { truncateBytes } = require("./text");

const TYPE = {
  CONNECT: 0,
  INFO: 1,
  DISCONNECT: 4,
  KICK: 5,
  CHAT: 6,
  CONNECT_ACCEPTED: 7,
  FORCE_MAP: 8,
  SERVER_PAUSE: 9,
  RACE_STATUS: 10,
  HEARTBEAT: 11,
  PLAY_SOUND: 12,
  SPECTATE: 13,
  // The lobby's 7TV emote pack. Retired in L9 when the 2026-10-22 client
  // dropped it, back in 1.3.2 with the client that reads it again; sent only
  // when the operator names a pack (EMOTE_PACK).
  EMOTE_PACK: 14,
  SPRAY_CHUNK: 15,
  SPRAY_STAMP: 16,
  // The server browser (1.4.0). Never sent to a session: they answer the
  // connectionless query 'i' from whatever address asked, so neither carries C.
  // A game client that is sent one by a forged query (the address it was forged
  // from) has no case for 17 or 18 and drops it; a v2 client drops it for
  // lacking C before that.
  INFO_CHALLENGE: 17,
  SERVER_INFO: 18,
};

// Type 18, per player listed.
const INFO_PLAYER_FLAG = {
  HLSR: 1, // the client says the game was started from the HLSR launcher
  OP: 2, // an approved operator session (console op, or opsteam at confirmation)
  SPECTATING: 4, // watching somebody
  RUNNER: 8, // in the current race
  IDENTIFIED: 16, // a 1.4.0 client: it sent the identity block (else HLSR is unknown)
  V2: 32, // a protocol v2 session
};

// Type 18, about the host.
const INFO_SERVER_FLAG = {
  REQUIRE_V2: 1, // REQUIRE_PROTOCOL_V2=1: an older build of the mod is refused
  WHITELIST: 2, // the whitelist is on
  STEAM_IDENTITY: 4, // 1.4.0: reads the identity block (SteamID and HLSR flag)
  OP_CHAT: 8, // operator chat commands are enabled
};

// Type 18's race byte: race.js's phases, in the order a race goes through them.
const RACE_PHASE = {
  idle: 0,
  lobby: 1,
  countdown_map: 2,
  loading: 3,
  staging: 4,
  countdown_start: 5,
  racing: 6,
};

// announce = 1 for a fresh join the receiver should show in chat,
// 0 for the silent roster entries a client gets about players already present.
const connect = (user, announce) =>
  new BufferWriter()
    .writeInt8(TYPE.CONNECT)
    .writeString(user.name, limits.MAX_NAME_LENGTH)
    .writeUInt8(user.trailLength)
    .writeUInt8(user.trailRed)
    .writeUInt8(user.trailGreen)
    .writeUInt8(user.trailBlue)
    .writeUInt8(user.ghostRed)
    .writeUInt8(user.ghostGreen)
    .writeUInt8(user.ghostBlue)
    .writeUInt8(announce ? 1 : 0).buffer;

const info = (user) => {
  const w = new BufferWriter();
  w.writeInt8(TYPE.INFO);
  w.writeString(user.name, limits.MAX_NAME_LENGTH);
  w.writeString(user.mapname, limits.MAX_MAP_LENGTH);
  w.writeFloat(user.velocity.x);
  w.writeFloat(user.velocity.y);
  w.writeFloat(user.velocity.z);
  w.writeFloat(user.position.x);
  w.writeFloat(user.position.y);
  w.writeFloat(user.position.z);
  w.writeFloat(user.pitch);
  w.writeFloat(user.yaw);
  w.writeUInt8(user.paused ? 1 : 0);
  // Weapon id (see ghost_weapons.h in the mod). Everything from here on is a
  // trailing optional field: older clients stop reading and never see it.
  w.writeUInt8(user.weapon & 0xff);
  // Sender stats for first person spectators.
  w.writeFloat(user.hp);
  w.writeFloat(user.armor);
  w.writeFloat(user.clip);
  w.writeFloat(user.ammo);
  // Carried prop mirror ("" = holding nothing).
  w.writeString(user.heldModel || "", limits.MAX_MODEL_LENGTH);
  w.writeFloat(user.heldPos.x);
  w.writeFloat(user.heldPos.y);
  w.writeFloat(user.heldPos.z);
  w.writeFloat(user.heldAng.x);
  w.writeFloat(user.heldAng.y);
  w.writeFloat(user.heldAng.z);
  // Eye height over the origin (crouch state); 64 = standing.
  w.writeFloat(user.eyeZ);
  // Keys held (GhostKeyBit_t bitmask), for first person spectators' key panel.
  w.writeFloat(user.keys || 0);
  return w.buffer;
};

// reason is a short code the client turns into a chat line: left/kick/timeout.
const disconnect = (name, reason) =>
  new BufferWriter()
    .writeInt8(TYPE.DISCONNECT)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeString(reason || "left", limits.MAX_REASON_LENGTH).buffer;

const kick = (reason) =>
  new BufferWriter().writeInt8(TYPE.KICK).writeString(reason, limits.MAX_REASON_LENGTH).buffer;

const connectAccepted = () => new BufferWriter().writeInt8(TYPE.CONNECT_ACCEPTED).buffer;

const chat = (id, name, text) =>
  new BufferWriter()
    .writeInt8(TYPE.CHAT)
    .writeInt32(id)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeString(text, limits.MAX_CHAT_LENGTH).buffer;

const forceMap = (mapname) =>
  new BufferWriter().writeInt8(TYPE.FORCE_MAP).writeString(mapname, limits.MAX_MAP_LENGTH).buffer;

const serverPause = (on, label) =>
  new BufferWriter()
    .writeInt8(TYPE.SERVER_PAUSE)
    .writeUInt8(on ? 1 : 0)
    .writeString(label || "", limits.MAX_REASON_LENGTH).buffer;

// `underway` says whether the race has moved past the lobby. It is a property
// of the race, not of the player, but it rides along with every status change
// so a client never has to work it out from the codes - and it cannot, because
// runners go back to READY while staging, so "somebody is LOADING" is true only
// part of the time a race is running.
//
// A trailing optional field: a client built before it existed stops reading
// after isRunner.
const raceStatus = (name, statusCode, isRunner, underway) =>
  new BufferWriter()
    .writeInt8(TYPE.RACE_STATUS)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeUInt8(statusCode)
    .writeUInt8(isRunner ? 1 : 0)
    .writeUInt8(underway ? 1 : 0).buffer;

const heartbeat = () => new BufferWriter().writeInt8(TYPE.HEARTBEAT).buffer;

const playSound = (soundPath) =>
  new BufferWriter().writeInt8(TYPE.PLAY_SOUND).writeString(soundPath, limits.MAX_MODEL_LENGTH).buffer;

const spectate = (name, target) =>
  new BufferWriter()
    .writeInt8(TYPE.SPECTATE)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeString(target || "", limits.MAX_SPECTATE_LENGTH).buffer;

// The lobby's shared emote vocabulary, as one already-tagged identifier:
// "set:<id>", "user:<id>" or "twitch:<id>". The tag is not decoration - the
// three resolve through three different 7TV endpoints, and the client is not
// allowed to guess which. No artwork crosses this wire for emotes: each client
// fetches its own through its own launcher.
//
// Sprays are the exception, and the only one - see the note in limits.js for
// why they cannot work the same way.
const emotePack = (identifier) =>
  new BufferWriter().writeInt8(TYPE.EMOTE_PACK).writeString(identifier || "", limits.MAX_EMOTE_PACK_LENGTH).buffer;

// One piece of somebody's spray.
//
// crc identifies the picture and is what the receiving client names the file
// it assembles, exactly as the sender did - same picture, same name, on every
// machine. rawBytes is the uncompressed size, sent so the receiver can bound
// its inflate instead of trusting the blob.
//
// The server never inspects the payload. It is deflated VTF, and the only end
// that can safely decide whether it is really a texture is the one that has to
// render it.
const sprayChunk = (name, crc, rawBytes, total, index, payload) =>
  new BufferWriter()
    .writeInt8(TYPE.SPRAY_CHUNK)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeInt32(crc)
    .writeInt32(rawBytes)
    .writeInt32(total)
    .writeInt32(index)
    .writeBytes(payload, limits.SPRAY_CHUNK_BYTES).buffer;

// Somebody put their spray on a wall, here.
//
// The position is world space and the surface is worked out by the receiving
// client's own trace - entity indices mean nothing across machines, and a
// spray only ever lands on world brushes anyway (the server traces it with
// MASK_SOLID_BRUSHONLY).
const sprayStamp = (name, crc, x, y, z) =>
  new BufferWriter()
    .writeInt8(TYPE.SPRAY_STAMP)
    .writeString(name, limits.MAX_NAME_LENGTH)
    .writeInt32(crc)
    .writeFloat(x)
    .writeFloat(y)
    .writeFloat(z).buffer;

// Type 17: the answer to a query that carried no valid challenge. u32 request id
// (echoed, so the browser can tell its queries apart), u32 challenge. 9 bytes,
// always fewer than the 14-byte query it answers (limits.INFO_QUERY_BYTES).
const infoChallenge = (requestId, challenge) =>
  new BufferWriter().writeInt8(TYPE.INFO_CHALLENGE).writeInt32(requestId | 0).writeInt32(challenge | 0).buffer;

// Type 18: the server info, sent only for a query carrying the challenge this
// host issued to the same address:port.
//
//   u8  18
//   u32 request id (echoed)
//   u8  format (1)
//   str server name (<= 63 bytes, UTF-8)
//   str ghserver version (<= 15)
//   u8  protocol (2: speaks protocol v2 and legacy)
//   u8  INFO_SERVER_FLAG bits
//   u8  players online (confirmed sessions, the whole lobby)
//   u8  slot limit
//   u8  RACE_PHASE
//   str the map most players are on (<= 31, "" for none)
//   u8  n players listed
//   n x { str name (<= 31), u8 INFO_PLAYER_FLAG bits }
//
// Capped at limits.MAX_INFO_REPLY_BYTES: the list stops at the first entry that
// would not fit, or at INFO_MAX_LISTED. No SteamID and no address is ever in it.
const serverInfo = (requestId, head, players) => {
  const w = new BufferWriter(limits.MAX_INFO_REPLY_BYTES);
  w.writeInt8(TYPE.SERVER_INFO);
  w.writeInt32(requestId | 0);
  w.writeUInt8(1);
  w.writeString(head.name, limits.MAX_SERVER_NAME_LENGTH);
  w.writeString(head.version, limits.MAX_VERSION_LENGTH);
  w.writeUInt8(head.protocol);
  w.writeUInt8(head.flags);
  w.writeUInt8(Math.min(255, head.players));
  w.writeUInt8(Math.min(255, head.maxPlayers));
  w.writeUInt8(head.race);
  w.writeString(head.map || "", limits.MAX_MAP_LENGTH);
  const countAt = w.length;
  w.writeUInt8(0);
  let listed = 0;
  for (const player of players || []) {
    if (listed >= limits.INFO_MAX_LISTED) break;
    const name = truncateBytes(player.name, limits.MAX_NAME_LENGTH);
    const entry = 4 + Buffer.byteLength(name, "latin1") + 1;
    if (w.length + entry > limits.MAX_INFO_REPLY_BYTES) break;
    w.writeString(name, limits.MAX_NAME_LENGTH);
    w.writeUInt8(player.flags);
    listed += 1;
  }
  w.scratch.writeUInt8(listed, countAt);
  return w.buffer;
};

module.exports = {
  TYPE,
  INFO_PLAYER_FLAG,
  INFO_SERVER_FLAG,
  RACE_PHASE,
  infoChallenge,
  serverInfo,
  connect,
  info,
  disconnect,
  kick,
  connectAccepted,
  chat,
  forceMap,
  serverPause,
  raceStatus,
  heartbeat,
  playSound,
  spectate,
  emotePack,
  sprayChunk,
  sprayStamp,
};
