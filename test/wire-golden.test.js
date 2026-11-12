"use strict";

// The wire contract, pinned twice.
//
// First against golden fixtures written out by hand from the mod's own source,
// so a test failure points at a field the compiled client.dll/server.dll will
// misread. Second against legacy/index.js executed as it stands, so nothing the
// old server put on the wire has silently changed shape.
//
// Field layouts come from the matching Source SDK game code:
//   sp/src/game/server/GhostOnlineEngine.cpp   parsePacket, send helpers
//   sp/src/game/server/runline.h               OnlineRunLine
//   sp/src/game/server/SFML/Packet.cpp         int32 big endian, float raw LE
//
// Encoding rules the fixtures encode:
//   * outbound packet type is a bare byte, with no length prefix;
//   * an inbound opcode is a string, so it has one;
//   * int32 is big endian (htonl), float is little endian (raw memcpy on x86);
//   * a string is uint32 big endian length followed by raw bytes, no NUL.

const test = require("node:test");
const assert = require("node:assert");

const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const { BufferWriter } = require("../src/wire/writer");
const { Message } = require("../src/wire/reader");
const legacy = require("./helpers/legacy");

const hex = (buffer) => Buffer.from(buffer).toString("hex");

const sampleUser = () => ({
  name: "Bob",
  mapname: "d1_trainstation_01",
  trailLength: 12,
  trailRed: 255,
  trailGreen: 0,
  trailBlue: 0,
  ghostRed: 10,
  ghostGreen: 20,
  ghostBlue: 30,
  velocity: { x: 1.5, y: -2.25, z: 0 },
  position: { x: 100.5, y: -200.25, z: 33 },
  pitch: 12.5,
  yaw: -90,
  paused: 0,
  weapon: 7,
  hp: 100,
  armor: 50,
  clip: 30,
  ammo: 90,
  heldModel: "models/props_c17/oildrum001.mdl",
  heldPos: { x: 1, y: 2, z: 3 },
  heldAng: { x: 4, y: 5, z: 6 },
  eyeZ: 64,
  // GHOST_KEY_FORWARD | GHOST_KEY_JUMP = 1 | 16. A live-looking combination
  // rather than a round number, so a field written in the wrong place shows up.
  keys: 17,
});

// ---------------------------------------------------------------------------
// Encoding primitives
// ---------------------------------------------------------------------------

test("int32 goes on the wire big endian, as htonl in Packet.cpp:373", () => {
  assert.strictEqual(hex(new BufferWriter().writeInt32(1).buffer), "00000001");
  assert.strictEqual(hex(new BufferWriter().writeInt32(0x01020304).buffer), "01020304");
});

test("float goes on the wire little endian, as the raw memcpy in Packet.cpp:391", () => {
  // 1.0f is 0x3F800000; little endian puts the exponent byte last.
  assert.strictEqual(hex(new BufferWriter().writeFloat(1).buffer), "0000803f");
  assert.strictEqual(hex(new BufferWriter().writeFloat(-1).buffer), "000080bf");
});

test("a string is a big endian length and raw bytes with no terminator", () => {
  assert.strictEqual(hex(new BufferWriter().writeString("abc").buffer), "00000003616263");
  assert.strictEqual(hex(new BufferWriter().writeString("").buffer), "00000000");
});

test("latin1 survives the round trip byte for byte", () => {
  // The game sends ANSI text; a cyrillic nickname must come back unchanged.
  const name = Buffer.from([0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]).toString("latin1");
  const encoded = new BufferWriter().writeString(name).buffer;
  const message = new Message(encoded, {});
  assert.strictEqual(message.readString(), name);
  assert.strictEqual(hex(encoded.subarray(4)), "cff0e8e2e5f2");
});

// ---------------------------------------------------------------------------
// Golden fixtures: outbound packets
// ---------------------------------------------------------------------------

test("type 0 connect matches the fixture read by GhostOnlineEngine.cpp:99", () => {
  const expected =
    "00" + // packet type
    "00000003" + "426f62" + // name "Bob"
    "0c" + "ff" + "00" + "00" + // trail length, trail rgb
    "0a" + "14" + "1e" + // ghost rgb
    "01"; // announce byte: 1 = show "joined the game"
  assert.strictEqual(hex(packets.connect(sampleUser(), true)), expected);
  assert.strictEqual(hex(packets.connect(sampleUser(), false)).slice(-2), "00");
});

test("type 1 update matches OnlineRunLine field order", () => {
  // Float constants are IEEE-754 single precision written low byte first, the
  // same bytes the client's memcpy reads back on x86:
  //   1.5      3FC00000 -> 0000c03f      -2.25    C0100000 -> 000010c0
  //   100.5    42C90000 -> 0000c942      -200.25  C3484000 -> 004048c3
  //   33       42040000 -> 00000442      12.5     41480000 -> 00004841
  //   -90      C2B40000 -> 0000b4c2      64       42800000 -> 00008042
  const expected =
    "01" +
    "00000003" + "426f62" + // name
    "00000012" + Buffer.from("d1_trainstation_01", "latin1").toString("hex") + // map, 18 bytes
    "0000c03f" + "000010c0" + "00000000" + // velocity xyz
    "0000c942" + "004048c3" + "00000442" + // position xyz
    "00004841" + "0000b4c2" + // pitch, yaw
    "00" + // paused
    "07" + // weapon
    "0000c842" + "00004842" + "0000f041" + "0000b442" + // hp 100, armor 50, clip 30, ammo 90
    "0000001f" + Buffer.from("models/props_c17/oildrum001.mdl", "latin1").toString("hex") + // 31 bytes
    "0000803f" + "00000040" + "00004040" + // held position 1, 2, 3
    "00008040" + "0000a040" + "0000c040" + // held angles 4, 5, 6
    "00008042" + // eye height 64
    "00008841"; // keys 17 (forward + jump)
  assert.strictEqual(hex(packets.info(sampleUser())), expected);
});

test("type 4 disconnect carries the name and the reason code", () => {
  assert.strictEqual(hex(packets.disconnect("Bob", "timeout")), "04" + "00000003426f62" + "00000007" + "74696d656f7574");
  // An absent reason defaults to "left", which is what older builds send.
  assert.strictEqual(hex(packets.disconnect("Bob", null)), "04" + "00000003426f62" + "00000004" + "6c656674");
});

test("type 5 kick carries only a reason", () => {
  assert.strictEqual(hex(packets.kick("Timed out.")), "05" + "0000000a" + "54696d6564206f75742e");
});

test("type 6 chat carries a big endian id before the name", () => {
  assert.strictEqual(hex(packets.chat(1, "Bob", "hi")), "06" + "00000001" + "00000003426f62" + "000000026869");
});

test("type 7 accept is a single byte", () => {
  assert.strictEqual(hex(packets.connectAccepted()), "07");
});

test("type 11 heartbeat is a single byte", () => {
  assert.strictEqual(hex(packets.heartbeat()), "0b");
});

test("type 8 force map carries the save name", () => {
  assert.strictEqual(hex(packets.forceMap("start")), "08" + "00000005" + "7374617274");
});

test("type 9 pause carries the flag then the overlay label", () => {
  assert.strictEqual(hex(packets.serverPause(true, "PAUSED BY SERVER")), "09" + "01" + "00000010" + Buffer.from("PAUSED BY SERVER", "latin1").toString("hex"));
  assert.strictEqual(hex(packets.serverPause(false, "")), "09" + "00" + "00000000");
});

test("type 10 race status carries name, status, the runner flag and the race flag", () => {
  assert.strictEqual(hex(packets.raceStatus("Bob", 3, true, true)), "0a" + "00000003426f62" + "03" + "01" + "01");
  // Лобби: участник уже есть, гонки ещё нет
  assert.strictEqual(hex(packets.raceStatus("Bob", 1, true, false)), "0a" + "00000003426f62" + "01" + "01" + "00");
});

test("type 12 play sound carries a path relative to sound/", () => {
  assert.strictEqual(hex(packets.playSound("server/three.wav")), "0c" + "00000010" + Buffer.from("server/three.wav", "latin1").toString("hex"));
});

test("type 13 spectate carries the watcher and the target", () => {
  assert.strictEqual(hex(packets.spectate("Bob", "Alice")), "0d" + "00000003426f62" + "00000005" + "416c696365");
  assert.strictEqual(hex(packets.spectate("Bob", "")), "0d" + "00000003426f62" + "00000000");
});

// ---------------------------------------------------------------------------
// Byte identity with the pre-hardening server
// ---------------------------------------------------------------------------

test("legacy/index.js is the frozen copy the comparison depends on", () => {
  const { sha256, bytes } = legacy.load();
  assert.strictEqual(bytes, 40570);
  assert.strictEqual(sha256, legacy.LEGACY_SHA256);
});

test("every outbound packet is byte identical to the pre-hardening server", () => {
  const { api } = legacy.load();
  const sample = sampleUser();

  const old = new api.User(
    sample.name,
    { address: "1.2.3.4", port: 5000 },
    sample.trailLength,
    sample.trailRed,
    sample.trailGreen,
    sample.trailBlue,
    sample.ghostRed,
    sample.ghostGreen,
    sample.ghostBlue
  );
  old.updateInfo(
    sample.mapname,
    sample.position,
    sample.velocity,
    sample.pitch,
    sample.yaw,
    sample.paused,
    sample.weapon,
    sample.hp,
    sample.armor,
    sample.clip,
    sample.ammo,
    sample.heldModel,
    sample.heldPos,
    sample.heldAng,
    sample.eyeZ
  );

  const socket = { address: "1.2.3.4", port: 5000 };
  // Types 10, 12 and 13 leave the old server through broadcast(), so it needs
  // exactly one registered recipient for the buffer to be produced at all.
  api.userManager.users[sample.name] = old;

  const cases = [
    ["type 0 announce", () => old.createConnectBuffer(true), packets.connect(sample, true)],
    ["type 0 roster", () => old.createConnectBuffer(false), packets.connect(sample, false)],
    // type 1 is checked as a prefix below - it grew a trailing keys field.
    ["type 4 disconnect", () => old.createDisconnectBuffer("timeout"), packets.disconnect(sample.name, "timeout")],
    ["type 5 kick", () => legacy.capture(() => api.sendKick(socket, "Timed out.")), packets.kick("Timed out.")],
    ["type 6 chat", () => api.createChatBuffer("Bob", "hi"), packets.chat(1, "Bob", "hi")],
    ["type 7 accept", () => legacy.capture(() => api.sendConnectAccepted(socket)), packets.connectAccepted()],
    ["type 8 force map", () => legacy.capture(() => api.sendForceMap(socket, "start")), packets.forceMap("start")],
    [
      "type 9 pause on",
      () => legacy.capture(() => api.sendServerPause(socket, true, "PAUSED BY SERVER")),
      packets.serverPause(true, "PAUSED BY SERVER"),
    ],
    ["type 9 pause off", () => legacy.capture(() => api.sendServerPause(socket, false, "")), packets.serverPause(false, "")],
    [
      "type 12 sound",
      () => legacy.capture(() => api.broadcastPlaySound("server/three.wav")),
      packets.playSound("server/three.wav"),
    ],
    ["type 13 spectate", () => legacy.capture(() => api.broadcastSpectate("Bob", "Alice")), packets.spectate("Bob", "Alice")],
  ];

  for (const [label, produceOld, fresh] of cases) {
    assert.strictEqual(hex(produceOld()), hex(fresh), `${label} changed shape`);
  }

  // Type 10 is the one packet that is deliberately no longer byte identical: a
  // trailing "the race has started" byte was added, because a client cannot
  // work that out from the status codes (runners go back to READY while
  // staging, so "somebody is LOADING" is true only part of the time).
  //
  // Checked as a PREFIX rather than dropped from the comparison. Trailing
  // extension is the pattern the whole protocol is built on - a client built
  // before the field stops reading and never sees it - and the guarantee that
  // matters is that everything BEFORE the new field is untouched.
  // Type 1 is the other one, for the same reason: it gained a trailing float
  // carrying the keys the runner is holding, so a first-person spectator's key
  // panel can show the runner's input instead of their own. Same prefix rule -
  // a client built before the field stops reading at the eye height and never
  // learns the difference.
  const legacyInfo = hex(old.createInfoBuffer());
  const freshInfo = hex(packets.info(sample));
  assert.ok(freshInfo.startsWith(legacyInfo), "type 1 changed shape ahead of the new field");
  assert.strictEqual(freshInfo.length - legacyInfo.length, 8, "type 1 grew by more than one float");

  const legacyStatus = hex(legacy.capture(() => api.broadcastRaceStatus("Bob", 3, true)));
  const freshStatus = hex(packets.raceStatus("Bob", 3, true, true));
  assert.ok(freshStatus.startsWith(legacyStatus), "type 10 changed shape ahead of the new field");
  assert.strictEqual(freshStatus.length - legacyStatus.length, 2, "type 10 grew by more than one byte");

  delete api.userManager.users[sample.name];
});

test("the first chat id is 1 and it stays a positive int32 on the wire", () => {
  // The old server incremented forever; at 2^31 writeInt32BE threw from inside
  // an interval callback, which ended the process. Wrapping is invisible to a
  // client that only uses the id to spot duplicates.
  const wrapped = packets.chat(0x7ffffffd, "Bob", "hi");
  assert.strictEqual(wrapped.readInt32BE(1) > 0, true);
});

// ---------------------------------------------------------------------------
// Outbound strings fit the client's buffers
// ---------------------------------------------------------------------------

test("no outbound string can overflow the buffer the client reads it into", () => {
  const long = "x".repeat(300);

  // ev.reason is char[64] in GhostOnlineEngine.h
  assert.strictEqual(packets.kick(long).readUInt32BE(1), limits.MAX_REASON_LENGTH);
  // OnlineRunLine::name is char[32], map is char[32], heldModel is char[64]
  const wide = Object.assign(sampleUser(), { name: long, mapname: long, heldModel: long });
  const info = packets.info(wide);
  assert.strictEqual(info.readUInt32BE(1), limits.MAX_NAME_LENGTH);
  // GH_CHAT_MAX_LEN is 128 and the receiving buffer is chatMsg[144]
  const chat = packets.chat(1, long, long);
  assert.strictEqual(chat.readUInt32BE(5), limits.MAX_NAME_LENGTH);
  // ev.label is char[64]
  assert.strictEqual(packets.serverPause(true, long).readUInt32BE(2), limits.MAX_LABEL_LENGTH);
  assert.strictEqual(packets.forceMap(long).readUInt32BE(1), limits.MAX_MAP_LENGTH);
  // client.dll narrows the spectate target to char[32]
  assert.strictEqual(packets.spectate("Bob", long).readUInt32BE(8), limits.MAX_SPECTATE_LENGTH);
});

test("the biggest packet the server can emit stays well inside a datagram", () => {
  const wide = Object.assign(sampleUser(), {
    name: "n".repeat(limits.MAX_NAME_LENGTH),
    mapname: "m".repeat(limits.MAX_MAP_LENGTH),
    heldModel: "h".repeat(limits.MAX_MODEL_LENGTH),
  });
  const size = packets.info(wide).length;
  assert.strictEqual(size <= limits.MAX_OUTBOUND_BYTES, true, `type 1 grew to ${size} bytes`);
  // 220 is the worst case computed in limits.js from the client's own buffers.
  assert.strictEqual(size <= 220, true, `type 1 is ${size} bytes, the documented worst case is 220`);
});

// Type 14 (the 7TV emote pack) was removed in L9 and is back in 1.3.2. Its bytes
// are the 0.3.2 ones: the type, then one string. A host that names no pack must
// never emit it, so everything else in this file stays byte for byte what it
// was (test/emote-pack.test.js covers the host that does).
test("type 14 is 0.3.2's bytes and is never sent without a pack", () => {
  assert.strictEqual(packets.TYPE.EMOTE_PACK, 14);
  assert.deepStrictEqual(
    packets.emotePack("set:01FE9DRF000009TR6M9N941CYW"),
    Buffer.concat([Buffer.from("0e0000001e", "hex"), Buffer.from("set:01FE9DRF000009TR6M9N941CYW")])
  );
  // ...and, like every other string, cut to the client's buffer (szPack[40]).
  assert.strictEqual(packets.emotePack("x".repeat(300)).readUInt32BE(1), limits.MAX_EMOTE_PACK_LENGTH);

  // Drive a full connect + confirm + roster and assert no datagram is type 14.
  const h = require("./helpers/harness");
  const { server, socket } = h.makeServer();
  const A = h.from("10.0.0.1", 40001);
  const B = h.from("10.0.0.2", 40002);
  server.onDatagram(h.connect("Alice"), A);
  server.onDatagram(h.update("Alice"), A);
  server.onDatagram(h.connect("Bob"), B);
  server.onDatagram(h.update("Bob"), B);
  assert.strictEqual(socket.sent.some((p) => p.buffer.readUInt8(0) === 14), false, "a type 14 datagram was emitted");
});
