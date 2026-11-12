"use strict";

// Wire limits.
//
// Every number here is the size of a buffer in the shipped mod, not a round
// number that felt safe. The clients are already compiled: a limit that is too
// tight silently breaks players, and a limit that is too loose is the attack
// surface. Sources are given as file:line in the matching game source tree.
//
// The whole online protocol lives in the mod's server.dll
// (sp/src/game/server/GhostOnlineEngine.cpp); client.dll only renders what
// server.dll forwards to it over usermessages. That means a string has to
// survive two buffers, and the smaller of the two is what is written here.

// Longest opcode the client sends is one character (GhostOnlineEngine.cpp:758,
// 770, 719, 780, 550, 560). Anything longer is a probe.
const MAX_OPCODE_LENGTH = 8;

// Player name.
//
// server.dll sanitises into char cleanName[MAX_PLAYER_NAME_LENGTH] where
// MAX_PLAYER_NAME_LENGTH is 32 (public/const.h:41), so 31 usable bytes, and
// OnlineRunLine::name is char[32] (runline.h:350).
//
// There used to be a client defect worth working around here: the HUD built
// "OL " + name into GhostData::name[32] and then looked players up by substring,
// so a name longer than 28 characters no longer matched itself after that
// truncation and lost its race status column and spectate label. The mod now
// stores the plain nickname and compares it exactly, so the full 31 bytes are
// usable again. NAME_MAX_LENGTH still exists for an operator running an older
// build of the mod.
const MAX_NAME_LENGTH = 31;

// Map name. OnlineRunLine::map is char[32] (runline.h:349).
const MAX_MAP_LENGTH = 31;

// Chat text. GH_CHAT_MAX_LEN is 128 (GhostOnlineEngine.h:10) and the receiving
// buffer is char chatMsg[144] (GhostOnlineEngine.h:31).
const MAX_CHAT_LENGTH = 128;

// Model path of a carried prop. OnlineRunLine::heldModel is char[64]
// (runline.h:368), and CGhostAnimating::m_szHeldModel is char[64] too
// (GhostAnimating.h:58). The old server accepted 96, which the client then
// truncated.
const MAX_MODEL_LENGTH = 63;

// Spectate target. OnlineEvent::specTarget is char[64], but client.dll narrows
// it to char target[32] (client/GhostHud.cpp:226), so the smaller wins.
const MAX_SPECTATE_LENGTH = 31;

// Kick and disconnect reasons: OnlineEvent::reason is char[64]
// (GhostOnlineEngine.h), so 63 usable bytes.
const MAX_REASON_LENGTH = 63;

// Labels the client copies into OnlineEvent::label[64]: the pause overlay text
// (packet 9), the force-map save name (packet 8) and the sound path
// (packet 12).
const MAX_LABEL_LENGTH = 63;

// The lobby's 7TV emote pack (packet 14).
//
// The client that reads it is the one 51a8d1fb took the feature out of and the
// 2026-10-30 build puts back. server.dll copies the string into
// OnlineEvent::label[64] (GhostOnlineEngine.cpp, case 0x0E) and forwards it to
// client.dll, which reads it into char szPack[40] and keeps it in
// s_szEmotePack[40] (client/gh_presence.cpp, GhPresence_MsgEmotePack), so the
// smaller wins: 39. Builds between 2026-10-22 and that restore have no case for
// 0x0E and drop the packet in parsePacket's default. The longest value the
// config parser can produce is "user:" plus a 26 character 7TV id = 31 bytes,
// so a value that passed validation is never truncated here; the margin is so a
// future tag does not quietly turn a working setting into a chopped one.
const MAX_EMOTE_PACK_LENGTH = 39;

// The server browser's query (1.4.0, opcode 'i', reply types 17 and 18). These
// are client.dll's own buffers in the mod's "Servers" dialog
// (client/gh_serverlist_proto.h), which reads the reply without the server.dll
// relay, so there is only one buffer per field.
//
//   SERVER_NAME   char szName[64]       the operator's SERVER_NAME, UTF-8
//   VERSION       char szVersion[16]    package.json's version
//   INFO_QUERY    the query is opcode (5) + u8 version + u32 request id + u32
//                 challenge = 14 bytes, and the challenge reply is 9: a bare
//                 query can never be answered with more than it sent.
//   INFO_REPLY    the full reply is capped at the host's own outbound ceiling;
//                 the player list stops when the next entry would not fit, and
//                 at INFO_MAX_LISTED entries in any case. The count before it
//                 is the whole lobby, so the browser still shows "40/64".
const MAX_SERVER_NAME_LENGTH = 63;
const MAX_VERSION_LENGTH = 15;
const INFO_QUERY_BYTES = 14;
const INFO_CHALLENGE_BYTES = 9;
const MAX_INFO_REPLY_BYTES = 512;
const INFO_MAX_LISTED = 32;

// Read caps, applied while parsing rather than after it.
//
// The field limits above say how long a value may be once stored or relayed.
// These say how many bytes the parser will even look at, and they exist because
// the two are not the same thing: with a single generous cap for every string,
// a crafted 'l' of 497 bytes - one byte of name, one of map, four hundred of
// model path - passed the datagram gate and was fully parsed before the field
// limits threw the contents away.
//
// Each cap is comfortably above what the shipped client can produce, so the old
// behaviour of truncating an over-long value rather than dropping the packet is
// preserved, and none of them is anywhere near the datagram limit.
//
//   NAME_ON_CONNECT  gh_name is capped at 31 client side; 160 leaves room for a
//                    build that somehow sends more, and it still truncates.
//   NAME_IN_SESSION  a name that does not match a registered session is useless
//                    however long it is, so twice the maximum is generous.
//   CHAT             GH_CHAT_MAX_LEN is 128.
//   MAP              OnlineRunLine::map is char[32].
//   MODEL            OnlineRunLine::heldModel is char[64].
//   TARGET           client.dll narrows the spectate target to char[32].
const READ_NAME_ON_CONNECT = 160;
const READ_NAME_IN_SESSION = 64;
const READ_CHAT = 160;
const READ_MAP = 64;
const READ_MODEL = 128;
const READ_TARGET = 64;

// Hard ceiling for any single read, whatever cap the caller asks for.
const MAX_STRING_LENGTH = 160;

// ---------------------------------------------------------------------------
// Sprays.
//
// This is the first thing that puts artwork on this wire, and packets.js used
// to say that would never happen. It says so no longer, and the reason the
// rule changed is worth writing down: emotes are fetched by each client's
// launcher, so the host only ever had to name one. A spray has no launcher
// behind it - it has to work in singleplayer with nothing else running, which
// is the whole point of it being a local file - so the bytes have nowhere to
// travel except here.
//
// A spray is a VTF the sending client already wrote to disk, deflated. Nothing
// on the server understands the format: it stores the pieces, hands them on,
// and never looks inside. Deciding what is a valid texture is the receiving
// client's job, and it is the only end that can do it safely anyway.

// Payload bytes in one chunk. The datagram budget:
//   opcode      4 + 1  =   5
//   name        4 + 31 =  35
//   crc                =   4
//   raw size           =   4
//   total              =   4
//   index              =   4
//   payload     4 + N  = 4 + N
//                      = 60 + N, and MAX_DATAGRAM_BYTES is 512
// 400 leaves 52 bytes of headroom for a future trailing field.
const SPRAY_CHUNK_BYTES = 400;

// Hard ceiling on any byte field, whatever the caller asks for - the sibling of
// MAX_STRING_LENGTH.
const MAX_BYTES_FIELD = 448;

// Largest spray, compressed.
//
// This was 24 KB, which fits flat artwork and refuses photographs: the texture
// on the wire is raw BGRA, and deflate only takes a 256x256 photo down to
// 60-135 KB. Measured on real pictures, not guessed - four of them came out at
// 59, 77, 121 and 134 KB, so 24 KB rejected all but the smallest and 3x would
// still have rejected three of the four.
//
// 160 KB covers them with margin. At 400 bytes a chunk that is 410 datagrams,
// which is why sprayChunksPerTick went up to match: at the old drip rate a
// picture this size would take half a minute to reach one player.
const MAX_SPRAY_BYTES = 163840;

// The largest spray blob a RECEIVING client accepts, which bounds what the host
// may relay after re-encoding (review 1, I5). server.dll assembles into a fixed
// unsigned char pData[GH_SPRAY_MAX_BYTES] (gh_spraynet.cpp:43), refuses a
// rawBytes or an offset+length past it (:303, :308) and a stored size past it
// (:620); client.dll reads the file with the same bound and refuses a larger
// blob (gh_spray.cpp:617, :662, GH_SPRAY_MAX_BLOB_BYTES = 163840). It equals the
// upload cap, so there is no headroom for a re-encode that comes out larger.
const CLIENT_RECEIVE_MAX_BYTES = 163840;

// Chunks per spray. Derived from the two numbers above, with one spare, and
// checked separately so a sender cannot claim a small total and a huge index.
const MAX_SPRAY_CHUNKS = Math.ceil(MAX_SPRAY_BYTES / SPRAY_CHUNK_BYTES) + 1;

// Uncompressed size the sender declares. The receiving client bounds its
// inflate with it, so a 24 KB blob cannot ask anyone to allocate a gigabyte.
// 256x256 BGRA plus a VTF header is the largest picture the mod will build.
const MAX_SPRAY_RAW_BYTES = 256 * 256 * 4 + 1024;

// How many strings one datagram may contain. The busiest legitimate packet is
// 'l' with four: opcode, name, map, held model.
const MAX_STRINGS_PER_DATAGRAM = 6;

// Total string bytes per datagram, so six short strings cannot become six long
// ones.
const MAX_STRING_BYTES_PER_DATAGRAM = 448;

// Largest datagram the server will parse.
//
// Worst case legitimate 'l', with every field at its client side maximum:
//   opcode             4 + 1  =   5
//   name               4 + 31 =  35
//   map                4 + 31 =  35
//   velocity xyz       3 * 4  =  12
//   position xyz       3 * 4  =  12
//   pitch, yaw         2 * 4  =   8
//   paused, weapon     1 + 1  =   2
//   hp/armor/clip/ammo 4 * 4  =  16
//   held model         4 + 63 =  67
//   held pos/ang       6 * 4  =  24
//   eye height             4  =   4
//   keys held              4  =   4
//                             = 224 bytes
//
// 512 leaves room for a future trailing field and for the oversized-but-legal
// names the old server used to truncate, while cutting the parse surface by a
// factor of 128 against the 65507 a UDP datagram may carry. Larger datagrams
// are counted and dropped before the parser runs.
const MAX_DATAGRAM_BYTES = 512;

// Largest datagram the server will emit. The client's receive buffer is
// sf::UdpSocket::MaxDatagramSize = 65507 (SFML/UdpSocket.hpp:54), so this is
// our own ceiling rather than the client's: the biggest thing we send is a
// type 1 update, which is the inbound 'l' minus the opcode.
const MAX_OUTBOUND_BYTES = 512;

// Coordinates and velocities outside this range are not reachable in a Source
// map (the engine's own world limit is 16384 units) and are almost always a
// corrupted or hand-crafted packet.
const MAX_COORDINATE = 1e6;

// Largest key bitmask the mod can produce: GhostKeyBit_t currently ends at
// 1 << 22 (the weapon slot keys), so every valid mask fits in 23 bits. Anything
// above this is not a key combination, it is a malformed or hand-made packet.
const MAX_KEY_MASK = (1 << 23) - 1;

// Eye height above the origin: 64 standing, ~28 crouched. The client validates
// the same 0..128 range (GhostOnlineEngine.cpp:146-148).
const MAX_EYE_HEIGHT = 128;

// The only two checkpoint ids the mod sends: 1 from the pre-teleport pause
// point (logicrelay.cpp:162) and 2 from the finish trigger (player.cpp:7613).
const CHECKPOINT_STAGE = 1;
const CHECKPOINT_FINISH = 2;

module.exports = {
  MAX_OPCODE_LENGTH,
  MAX_NAME_LENGTH,
  MAX_MAP_LENGTH,
  MAX_CHAT_LENGTH,
  MAX_MODEL_LENGTH,
  MAX_SPECTATE_LENGTH,
  MAX_REASON_LENGTH,
  MAX_LABEL_LENGTH,
  MAX_EMOTE_PACK_LENGTH,
  MAX_SERVER_NAME_LENGTH,
  MAX_VERSION_LENGTH,
  INFO_QUERY_BYTES,
  INFO_CHALLENGE_BYTES,
  MAX_INFO_REPLY_BYTES,
  INFO_MAX_LISTED,
  MAX_STRING_LENGTH,
  MAX_BYTES_FIELD,
  SPRAY_CHUNK_BYTES,
  MAX_SPRAY_BYTES,
  CLIENT_RECEIVE_MAX_BYTES,
  MAX_SPRAY_CHUNKS,
  MAX_SPRAY_RAW_BYTES,
  READ_NAME_ON_CONNECT,
  READ_NAME_IN_SESSION,
  READ_CHAT,
  READ_MAP,
  READ_MODEL,
  READ_TARGET,
  MAX_STRINGS_PER_DATAGRAM,
  MAX_STRING_BYTES_PER_DATAGRAM,
  MAX_DATAGRAM_BYTES,
  MAX_OUTBOUND_BYTES,
  MAX_COORDINATE,
  MAX_KEY_MASK,
  MAX_EYE_HEIGHT,
  CHECKPOINT_STAGE,
  CHECKPOINT_FINISH,
};
