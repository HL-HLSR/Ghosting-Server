"use strict";

// One connected player.
//
// A user is identified by a nickname and owned by exactly one address:port. A
// legacy client's protocol carries no token, so for its session that
// address:port is the only evidence of ownership the server has; see
// identity.js for what that does and does not buy us. A protocol v2 session
// also has S, which every packet from its endpoint must carry (server.js).

class Vector3 {
  constructor(x = 0, y = 0, z = 0) {
    this.x = x;
    this.y = y;
    this.z = z;
  }
}

class User {
  constructor(name, socket, appearance, now) {
    const at = now === undefined ? Date.now() : now;

    this.name = name;
    this.socket = socket;
    this.mapname = "unknown";

    this.trailLength = appearance.trailLength;
    this.trailRed = appearance.trailRed;
    this.trailGreen = appearance.trailGreen;
    this.trailBlue = appearance.trailBlue;
    this.ghostRed = appearance.ghostRed;
    this.ghostGreen = appearance.ghostGreen;
    this.ghostBlue = appearance.ghostBlue;

    this.position = new Vector3(0, 0, 0);
    this.velocity = new Vector3(0, 0, 0);
    this.pitch = 0;
    this.yaw = 0;
    this.paused = 0;
    this.weapon = 0;

    // Sender stats for first person spectators (-1 = unknown).
    this.hp = -1;
    this.armor = -1;
    this.clip = -1;
    this.ammo = -1;

    // Prop carried with +use ("" = nothing) and its world transform.
    this.heldModel = "";
    this.heldPos = new Vector3(0, 0, 0);
    this.heldAng = new Vector3(0, 0, 0);
    // When the relayed held model last CHANGED (L4 throttle).
    this.lastHeldModelChangeAt = 0;

    // Eye height over the origin (crouch state); 64 = standing.
    this.eyeZ = 64;

    // Keys held, as a bitmask the mod packs (GhostKeyBit_t). Relayed untouched;
    // the server never looks inside it.
    this.keys = 0;

    this.spectating = "";

    // Sprays.
    //
    // `spray` is the finished picture this player has published, AFTER the host
    // validated and canonically re-encoded it (see wire/spray.js). It now holds
    // the per-chunk relay packets BUILT ONCE and shared by every receiver:
    // `{ crc, rawBytes, total, bytes, packets: [Buffer, ...] }`. The old code
    // built a fresh copy of every chunk for every receiver, so relay memory grew
    // as players^2 * 160 KB (measured 674 MB queued at 64 players, M1). One
    // immutable copy per publisher makes it N * 160 KB instead.
    //
    // `sprayIn` is a half-arrived upload. It is dropped whole if anything about
    // it stops adding up, rather than being repaired: a spray is cheap to send
    // again and a partially trusted one is not worth having.
    //
    // `sprayFeeds` is what this player still has to be sent: a cursor per sender
    // (`fromName -> { crc, next }`) into that sender's shared `packets` array,
    // not a queue of buffers. A join into a full lobby costs one small cursor per
    // other player instead of a burst of hundreds of copied datagrams, and a
    // duplicate connect cannot re-queue a picture a receiver already has (H2).
    this.spray = null;
    this.sprayIn = null;
    this.sprayFeeds = new Map();
    // I4: distinct (sender key, crc) pictures this receiver session was fed
    // (capped at SPRAY_MAX_FED_PER_RECEIVER).
    this.sprayPictures = new Set();
    // Review 2 (m3): distinct pictures whose stamps were relayed to this receiver,
    // i.e. remote textures its client may have built (SPRAY_MAX_PICTURES_PER_RECEIVER).
    this.sprayStamped = new Set();
    // Minor 10: sender name -> crc of the picture this receiver has in full.
    this.sprayDelivered = new Map();
    // How many DISTINCT sprays this session has published (M2 per-session cap).
    this.sprayPublishCount = 0;
    this.lastSprayChunkTime = 0;
    this.lastSprayStampTime = 0;

    this.connectedAt = at;
    this.lastSeen = at;
    this.lastChatTime = 0;
    this.lastLineTime = 0;
    // Rate-limit a duplicate-connect roster resend (H2): a forged duplicate
    // connect used to re-send the whole roster (and re-queue every spray) for
    // free. 0 = never resent yet.
    this.lastRosterResendAt = 0;
    // The emote pack's per-session bound (server.sendEmotePack): copies sent to
    // this session and when the last one went. Kept here so it ends with the
    // session; the pack itself is the operator's and lives in the config.
    this.emotePackSends = 0;
    this.emotePackSentAt = 0;
    // A v2 session's second copy, due on the next heartbeat (server.confirmV2).
    this.emotePackSecondDue = false;

    // --- H2: proportional outbound credit ---
    //
    // The reflection weakness is that a confirmed session (which a spoofed
    // source address can become with two forged datagrams) receives every other
    // player's 50 Hz position stream: 263 attacker bytes bought 2.83 MB to the
    // victim in the audit, about 10 765x. A session now has to EARN the bytes it
    // is sent: each accepted inbound packet adds a fixed credit, and the metered
    // fan-out (positions, spray drip) spends it. A real client at 50 Hz earns far
    // more than it is ever sent, so it never notices; a forged session that sends
    // one keepalive a minute earns almost nothing, which caps the multiplier at
    // roughly the inherent fan-out ratio instead of 10^4.
    this.outCredit = 0;
    // What the last accepted line earned and its size, so a receiver whose lobby
    // grew since that line can have the same line re-sized once (shouldMeter).
    this.lastLineEarned = 0;
    this.lastLineBytes = 0;
    this.creditResizedFor = -1;

    // --- H3: sliding inbound packet rate ---
    //
    // A trickle of forged keepalives (about one packet per session per 55 s) used
    // to hold every slot forever, so the whole server reported "full" with
    // nothing traceable to the attacker. A newcomer may now evict the session
    // with the lowest inbound rate when that rate is far below what any real
    // client sends (a shipped client sends 50 pps even in the pause menu). The
    // rate is sampled in one-second buckets over a sliding minute.
    this._rateBuckets = null; // lazily created in recordInbound
    this._rateLastSec = 0;

    // Anti reflection state.
    //
    // A connect packet carries no proof that its source address is real. If it
    // is spoofed, everything the server fans out to this "player" is an attack
    // on whoever actually owns that address. A session stays unconfirmed until
    // a second packet arrives from the same address:port. An off-path attacker
    // forging the source address CAN produce that second packet (it carries no
    // unpredictable challenge - see identity.js and README), which is why
    // confirmation alone is not enough and the metered fan-out (H2) and the
    // slot-squat eviction (H3) exist. A protocol v2 session is the exception:
    // it confirms only with S, which such an attacker never sees (v2Confirmed).
    // Until a session confirms it may receive only a small fixed budget of
    // bytes; a real client confirms within about 40 ms, on its first position
    // update, so nobody notices.
    this.confirmed = false;
    this.confirmedAt = 0;
    this.unconfirmedBytes = 0;

    // Protocol v2 (session secrets; set by onConnect). 1 = a legacy client,
    // which carries no secret, so everything above about forgeable sessions
    // applies to it. 2 = the connect carried u8(2) + C: `clientNonce` (C, the
    // client's 8 bytes) goes in front of every packet sent to this session, and
    // `serverToken` (S, 8 random bytes chosen here and sent only in the accept)
    // must follow the opcode of every packet from its endpoint. Neither is ever
    // logged.
    this.protocol = 1;
    this.clientNonce = null;
    this.serverToken = null;
    // A v2 session confirmed by its first packet carrying S (server.confirmV2),
    // set together with `confirmed`. Unlike a legacy confirmation it proves the
    // address is the one the accept reached, so the session's fan-out is not
    // charged credit (the liveness gate still applies) and the impersonation
    // guard is never armed for it.
    this.v2Confirmed = false;
    // Whether the rest of the lobby has been told this name is here (a type 0
    // join), so that it must be told when it goes (a type 4). Set by
    // server.onConnect for a legacy session; a v2 session is announced only
    // when it confirms (confirmV2), unless it silently took over a name the
    // lobby already knew.
    this.announced = false;

    // 1.4.0 identity block (server.readConnectHead), from the v2 announce that
    // registered this session; a duplicate announce never changes it. Both are
    // the client's word - nothing checks a Steam ticket.
    //   launcher  "hlsr" (the game says it was started from HLSR), "other", or
    //             null when the client sent no block (a legacy or 1.3 build)
    //   steamId   SteamID64 as a decimal string (access.normalizeSteamId), or null
    this.launcher = null;
    this.steamId = null;
    // Approved as an operator by a SteamID entry (server.applySteamOp) rather
    // than by the console's `op "Nick" PIN`. Its PIN is checked against that
    // entry's hash; opPin below then caches the PIN once it was right.
    this.opBySteam = false;
    // Five wrong PINs ended this session's SteamID approval for good: a reload
    // of the access file does not hand it back (a reconnect does).
    this.opSteamRevoked = false;

    // H1: optional operator PIN for admin chat commands, set when the console
    // approves this session with one. Lives on the session only; never stored.
    this.opPin = null;
    // C2: consecutive wrong PINs; at OP_PIN_MAX_FAILURES the approval is revoked.
    this.opPinFailures = 0;

    // N2 + review 3: impersonation guard (server.noteWrongOwner). `guardPorts`
    // maps the distinct source ports that named this session from its own IP in
    // the trigger window to when each was last seen (allocated on the first);
    // while `guardUntil` is in the future the session is guarded, since
    // `guardStartedAt`. Per session object: a reconnect that replaces the
    // session starts clean.
    this.guardPorts = null;
    this.guardUntil = 0;
    this.guardStartedAt = 0;
    // Review 3 (R5): the last spectate target / appearance refused while
    // guarded (null = none), applied when the guard ends.
    this.guardedSpectate = null;
    this.guardedAppearance = null;
  }

  touch(now) {
    this.lastSeen = now === undefined ? Date.now() : now;
  }

  // --- H2 credit ---
  earnCredit(perPacket, max) {
    this.outCredit = Math.min(max, this.outCredit + perPacket);
  }

  // Returns false (and spends nothing) when the session has not earned these
  // bytes. Used only by the metered fan-out, never by a direct reply.
  spendCredit(bytes) {
    if (this.outCredit < bytes) return false;
    this.outCredit -= bytes;
    return true;
  }

  // --- H3 inbound rate ---
  _rateAdvance(now) {
    const sec = Math.floor(now / 1000);
    if (this._rateBuckets === null) {
      this._rateBuckets = new Array(60).fill(0);
      this._rateLastSec = sec;
      return;
    }
    const gap = sec - this._rateLastSec;
    if (gap <= 0) return;
    if (gap >= 60) {
      this._rateBuckets.fill(0);
    } else {
      for (let i = 1; i <= gap; i++) this._rateBuckets[(this._rateLastSec + i) % 60] = 0;
    }
    this._rateLastSec = sec;
  }

  recordInbound(now) {
    this._rateAdvance(now);
    this._rateBuckets[this._rateLastSec % 60] += 1;
  }

  // Packets per second over the trailing window, averaged over the time the
  // session has actually existed (never over a full minute it was not here for,
  // which would make a newcomer sending 50 pps look like a 2 pps squatter).
  inboundRate(now, windowMs) {
    if (this._rateBuckets === null) return 0;
    this._rateAdvance(now);
    const windowSec = Math.max(1, Math.min(60, Math.ceil(windowMs / 1000)));
    let sum = 0;
    for (let i = 0; i < windowSec; i++) sum += this._rateBuckets[(this._rateLastSec - i + 60) % 60];
    const aliveSec = Math.max(1, Math.floor((now - (this.confirmed ? this.confirmedAt : this.connectedAt)) / 1000));
    return sum / Math.min(windowSec, aliveSec);
  }

  // Any packet other than the initial connect proves the address is reachable.
  //
  // A connect does not, and must never be allowed to: it is the one packet an
  // attacker can forge without knowing anything about an existing session.
  confirm(now) {
    if (this.confirmed) return false;
    this.confirmed = true;
    // I3: the eviction grace and the inbound rate run from here, not from the
    // connect (which an unconfirmed takeover may have inherited).
    this.confirmedAt = now === undefined ? Date.now() : now;
    // The budget has done its job and the number is now dead state; leaving it
    // set would make the diagnostics read as if a live session were still being
    // rationed.
    this.unconfirmedBytes = 0;
    return true;
  }

  updateInfo(fields) {
    this.mapname = fields.mapname;
    this.position = fields.position;
    this.velocity = fields.velocity;
    this.pitch = fields.pitch;
    this.yaw = fields.yaw;
    this.paused = fields.paused;
    this.weapon = fields.weapon;
    this.hp = fields.hp;
    this.armor = fields.armor;
    this.clip = fields.clip;
    this.ammo = fields.ammo;
    this.heldModel = fields.heldModel;
    this.heldPos = fields.heldPos;
    this.heldAng = fields.heldAng;
    this.eyeZ = fields.eyeZ;
    this.keys = fields.keys;
  }
}

module.exports = { User, Vector3 };
