"use strict";

// Who owns a nickname.
//
// THE HONEST VERSION FIRST. A legacy client (every build before protocol v2)
// sends no session token, no shared secret and no signature. For its session
// the server's only evidence that a packet came from the player who registered
// a name is the source address:port of the datagram, and UDP source addresses
// are trivially forged. Someone who knows such a player's nickname, address and
// current ephemeral port can chat as them, move their ghost and disconnect
// them, and no amount of server side work changes that. What follows raises
// the cost of the attacks that do not require guessing a live 5-tuple; it is
// not authentication and the report says so.
//
// A protocol v2 client is different: every packet from its endpoint must carry
// S, a secret the server sent only to that endpoint (server.js). Against an
// off-path attacker that is authentication; the policy below still decides who
// may hold a name, for both kinds of session.
//
// The policy, in order of how much evidence each case has:
//
//   same address:port   the registered owner. Full trust, such as it is.
//   same address        almost certainly the same player after a crash or a
//                       router assigning a new ephemeral port. Allowed to take
//                       the name over once the old socket has been silent for
//                       `takeoverAfterMs`.
//   different address   could be anyone. Has to wait out the full
//                       `staleTimeoutMs`, i.e. until the sweep would have
//                       removed the old session anyway.
//   unconfirmed owner   a registration whose address has never answered may be
//                       a spoofed source squatting on the nickname. Anyone may
//                       displace it after `takeoverAfterMs`.
//   confirmed v2 owner  its endpoint proved itself with S, and a connect from
//                       anywhere else carries no S for it. The same address on
//                       another port is no evidence - a spoofer or a CGNAT
//                       neighbour sends from it too, and a level load or the
//                       main menu is ten seconds of silence - so it waits for
//                       `staleTimeoutMs` like a different address: the name is
//                       freed when the session is stale, exactly when the sweep
//                       would remove it, and not before (final review M3).

const ACTION = {
  REGISTER: "register",
  DUPLICATE: "duplicate",
  TAKEOVER: "takeover",
  REJECT: "reject",
};

const socketKey = (socket) => `${socket.address}:${socket.port}`;
const addressKey = (socket) => String(socket.address);

const decideConnect = (options) => {
  const { existing, socket, now, takeoverAfterMs, staleTimeoutMs } = options;

  if (!existing) return { action: ACTION.REGISTER };

  const incoming = socketKey(socket);
  const owner = socketKey(existing.socket);

  // The client re-announces after a reconnect or a lost accept; that is not a
  // collision, it is the same player asking again.
  if (owner === incoming) return { action: ACTION.DUPLICATE };

  const silentFor = now - existing.lastSeen;

  // A registration that never answered from its own address proves nothing.
  // Letting it hold a nickname for a full minute would hand anyone a cheap way
  // to deny a specific name to its real owner.
  if (!existing.confirmed && now - existing.connectedAt >= takeoverAfterMs) {
    return { action: ACTION.TAKEOVER, reason: "previous session never confirmed its address" };
  }

  if (addressKey(existing.socket) === addressKey(socket)) {
    const sameAddressAfterMs = existing.v2Confirmed ? staleTimeoutMs : takeoverAfterMs;
    if (silentFor >= sameAddressAfterMs) {
      return { action: ACTION.TAKEOVER, reason: `same address, silent for ${Math.round(silentFor / 1000)}s` };
    }
    return { action: ACTION.REJECT, reason: "name in use from this address" };
  }

  if (silentFor >= staleTimeoutMs) {
    return { action: ACTION.TAKEOVER, reason: `different address, silent for ${Math.round(silentFor / 1000)}s` };
  }

  return { action: ACTION.REJECT, reason: "name in use" };
};

// Only the address:port that registered a name may act as it. Every handler
// except connect goes through this.
const ownsSession = (user, socket) => !!user && socketKey(user.socket) === socketKey(socket);

module.exports = { ACTION, decideConnect, ownsSession, socketKey, addressKey };
