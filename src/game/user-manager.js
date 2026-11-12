"use strict";

// The roster.
//
// Nicknames are attacker chosen strings used as map keys, so the store is a
// Map rather than a plain object: "__proto__", "constructor" and "toString" are
// ordinary keys to a Map and cannot reach Object.prototype. The old server used
// Object.create(null) with hasOwnProperty guards, which was correct but had to
// stay correct in every future call site; a Map cannot be got wrong.
//
// The key is the canonical form of the nickname, never the nickname itself.
// Keying by the raw string made "Aperture", "aperture" and "APERTURE" three
// different players, which in a chat window is indistinguishable from one. The
// display name - the exact string the first player connected with - lives on
// the user record and is what goes out on the wire, so folding the key changes
// who may join and changes nothing about what anyone sees.
//
// Every lookup canonicalises, because the name in an inbound packet is whatever
// the sender put there: a client that connects as "Alice" and then sends
// updates as "ALICE" has to resolve to the same user rather than create a
// second one.

const { User } = require("./user");
const { nicknameKey } = require("./nickname");

class UserManager {
  // The name limit has to live here because every key derivation must apply it.
  // See nickname.js: a key built from a truncated display name and a key built
  // from an untruncated packet name are different keys, and the session that
  // falls between them can never be found again.
  constructor(options) {
    this.maxNameLength = (options && options.maxNameLength) || 31;
    // canonical key -> User
    this.users = new Map();
    // Reverse index address:port -> canonical key. The old server scanned the
    // whole roster to answer "who owns this socket"; every inbound packet needs
    // that answer, so it is maintained here instead.
    this.bySocket = new Map();
    // address -> number of registered sessions from it. Review 3 (R1): lets the
    // host decide in one lookup whether a dropped datagram's source IP holds a
    // player at all before it spends a parse on it.
    this.addressCounts = new Map();
  }

  hasAddress(address) {
    return this.addressCounts.has(String(address));
  }

  get size() {
    return this.users.size;
  }

  count() {
    return this.users.size;
  }

  // Display names, in join order. Callers put these on the wire, so this must
  // never return the folded keys.
  names() {
    const out = [];
    for (const user of this.users.values()) out.push(user.name);
    return out;
  }

  keys() {
    return Array.from(this.users.keys());
  }

  values() {
    return this.users.values();
  }

  key(name) {
    return nicknameKey(name, this.maxNameLength);
  }

  get(name) {
    return this.users.get(this.key(name)) || null;
  }

  exists(name) {
    return this.users.has(this.key(name));
  }

  bySocketKey(key) {
    const owner = this.bySocket.get(key);
    return owner === undefined ? null : this.users.get(owner) || null;
  }

  register(name, socket, appearance, now, socketKey) {
    const user = new User(name, socket, appearance, now);
    const key = this.key(name);
    this.users.set(key, user);
    this.bySocket.set(socketKey, key);
    const address = String(socket.address);
    this.addressCounts.set(address, (this.addressCounts.get(address) || 0) + 1);
    return user;
  }

  unregister(name, socketKey) {
    const key = this.key(name);
    const user = this.users.get(key);
    if (!user) return null;
    this.users.delete(key);
    const address = String(user.socket.address);
    const left = (this.addressCounts.get(address) || 1) - 1;
    if (left > 0) this.addressCounts.set(address, left);
    else this.addressCounts.delete(address);
    // Only clear the reverse index if it still points at this user: a takeover
    // rebinds the key before the old registration is removed.
    if (this.bySocket.get(socketKey) === key) this.bySocket.delete(socketKey);
    return user;
  }

  clear() {
    this.users.clear();
    this.bySocket.clear();
    this.addressCounts.clear();
  }
}

module.exports = { UserManager };
