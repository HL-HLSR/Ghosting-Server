"use strict";

// The race state machine.
//
// The bug worth remembering: a runner who reached the pre-teleport point got a
// server-driven pause they could not lift, and if any other runner never
// finished loading, nothing in the machine ever timed that out. The only escape
// was to quit the game. Every waiting phase now has a deadline, and every exit
// path releases everyone it paused.

const test = require("node:test");
const assert = require("node:assert");

const h = require("./helpers/harness");
const packets = require("../src/wire/packets");
const { RS } = require("../src/game/race");

const A = h.from("10.0.0.1", 40001);
const B = h.from("10.0.0.2", 40002);

const join = (server, name, rinfo) => {
  server.onDatagram(h.connect(name), rinfo);
  // Заведомо НЕ карта гонки: игрок, уже стоящий на d1_trainstation_01,
  // считается загрузившимся сразу, и «ещё грузится» тогда не выразить.
  server.onDatagram(h.update(name, { map: "d1_eli_01" }), rinfo);
};

// Get two runners as far as the loading phase.
const toLoading = (env = {}) => {
  const rig = h.makeServer(Object.assign({ RACE_LOBBY_MS: "2000" }, env));
  const { server, clock } = rig;
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(1000);

  server.onDatagram(h.chat("Alice", "/race"), A);
  clock.advance(1000);
  server.onDatagram(h.chat("Bob", "/ready"), B);
  clock.advance(1500);
  clock.advance(3100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "loading");
  return rig;
};

const pauseState = (socket, rinfo, since = 0) =>
  h
    .sentTo(socket, rinfo.address, rinfo.port, since)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SERVER_PAUSE)
    .map((p) => p.buffer.readUInt8(1));

test("a second /race while one is running is refused", () => {
  const { server, clock } = h.makeServer({ RACE_LOBBY_MS: "10000" });
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(1000);

  server.onDatagram(h.chat("Alice", "/race"), A);
  assert.strictEqual(server.race.phase, "lobby");
  clock.advance(3000);
  server.onDatagram(h.chat("Bob", "/race"), B);
  assert.strictEqual(server.race.runners.size, 1, "the second /race must not restart the lobby");
});

test("/ready after the lobby closes is refused", () => {
  const { server, clock } = toLoading();
  clock.advance(2000);
  const before = server.race.runners.size;
  server.onDatagram(h.chat("Bob", "/ready"), B);
  assert.strictEqual(server.race.runners.size, before);
});

test("a runner who never finishes loading cannot freeze the others forever", () => {
  const { server, socket, clock } = toLoading({ RACE_LOADING_TIMEOUT_MS: "20000" });

  // Alice reaches the pre-teleport point and is frozen waiting for Bob.
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true);

  const mark = socket.sent.length;
  // Bob's game hangs on the load. He keeps sending updates from the map he
  // started on, so he never times out as a player, and the old machine waited
  // for ever. The map matters: a THIRD map would now mean he loaded the wrong
  // save, and he would be taken out of the race instead of stalling it.
  for (let i = 0; i < 25; i += 1) {
    clock.advance(1000);
    server.onDatagram(h.update("Bob", { map: "d1_eli_01" }), B);
    server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  }

  assert.strictEqual(server.race.phase, "idle", "the loading phase must expire");
  assert.strictEqual(server.race.paused.size, 0);
  assert.deepStrictEqual(pauseState(socket, A, mark).slice(-1), [0], "Alice must be released");
});

test("a runner who never reaches the start cannot freeze the others forever", () => {
  const { server, socket, clock } = toLoading({ RACE_STAGING_TIMEOUT_MS: "15000" });

  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);
  assert.strictEqual(server.race.phase, "staging");

  const mark = socket.sent.length;
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true);

  clock.advance(20000);
  assert.strictEqual(server.race.phase, "idle");
  assert.deepStrictEqual(pauseState(socket, A, mark), [1, 0], "paused, then released");
});

test("a race that runs too long is ended so the next one can start", () => {
  const { server, clock } = toLoading({ RACE_MAX_DURATION_MS: "60000" });
  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Bob", 1), B);
  clock.advance(4100);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "racing");

  clock.advance(61000);
  assert.strictEqual(server.race.phase, "idle");
});

test("a finish is only counted from a runner who is racing", () => {
  const { server, clock } = toLoading();
  // Still loading: a finish here is either a stray packet or a crafted one.
  clock.advance(1000);
  assert.strictEqual(server.onDatagram(h.checkpoint("Alice", 2), A), false);
  assert.deepStrictEqual(server.race.finished, []);
});

test("the same checkpoint twice does not change the result", () => {
  const { server, clock } = toLoading();
  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);

  clock.advance(1000);
  assert.strictEqual(server.onDatagram(h.checkpoint("Alice", 1), A), true);
  clock.advance(1000);
  assert.strictEqual(server.onDatagram(h.checkpoint("Alice", 1), A), false, "a repeat must be ignored");
  assert.strictEqual(server.race.staged.size, 1);

  clock.advance(1000);
  server.onDatagram(h.checkpoint("Bob", 1), B);
  clock.advance(4100);
  clock.runTimeouts();
  clock.runTimeouts();

  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 2), A);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 2), A);
  assert.deepStrictEqual(server.race.finished, ["Alice"], "finishing twice must not double count");
});

test("a runner who drops is removed and the rest continue", () => {
  const { server, clock } = toLoading();
  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);

  // Bob times out while still loading. Alice was the only other runner and is
  // already staged, so the race must move on rather than wait for a ghost.
  for (let i = 0; i < 70; i += 1) {
    clock.advance(1000);
    server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  }
  assert.strictEqual(server.race.runners.has("Bob"), false);
});

test("the last runner leaving cancels the race", () => {
  const { server, clock } = toLoading();
  clock.advance(1000);
  server.onDatagram(h.disconnect("Alice"), A);
  clock.advance(3000);
  server.onDatagram(h.disconnect("Bob"), B);
  clock.advance(3000);
  assert.strictEqual(server.race.phase, "idle");
  assert.strictEqual(server.race.paused.size, 0);
});

test("a failed release is remembered and retried, not forgotten", () => {
  const { server, socket, clock } = toLoading();
  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Bob", 1), B);
  assert.strictEqual(server.race.phase, "countdown_start");

  // The old machine set phase = "racing" first and then released runners one by
  // one, with nothing catching a failure: a throw partway through left every
  // runner after it in the list frozen, and the machine believed they were free.
  const realPause = server.race.pause.bind(server.race);
  server.race.pause = () => {
    throw new Error("send failed");
  };
  clock.advance(4100);
  clock.runTimeouts();
  clock.runTimeouts();

  // The race goes on: one undeliverable packet is not a reason to cancel it.
  assert.strictEqual(server.race.phase, "racing");
  // But nobody is quietly written off as released.
  assert.deepStrictEqual([...server.race.paused].sort(), ["Alice", "Bob"]);

  // When the link recovers, the next release actually reaches them.
  server.race.pause = realPause;
  const mark = socket.sent.length;
  server.race.cancel("Race cancelled.");
  assert.strictEqual(server.race.paused.size, 0);
  assert.deepStrictEqual(pauseState(socket, A, mark).slice(-1), [0]);
  assert.deepStrictEqual(pauseState(socket, B, mark).slice(-1), [0]);
});

test("shutting the server down releases everyone it paused", () => {
  const { server, socket, clock } = toLoading();
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true);

  const mark = socket.sent.length;
  server.stop("Server is shutting down.");

  // systemctl stop used to leave a staged runner behind an overlay until their
  // own client timed out.
  assert.deepStrictEqual(pauseState(socket, A, mark).slice(-1), [0]);
});

test("the operator can cancel a race from the console", () => {
  const { server, socket, clock } = toLoading();
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  const mark = socket.sent.length;

  assert.strictEqual(server.race.cancel("Race cancelled by the server operator."), true);
  assert.strictEqual(server.race.phase, "idle");
  assert.deepStrictEqual(pauseState(socket, A, mark).slice(-1), [0]);
  assert.strictEqual(server.race.cancel("again"), false, "cancelling twice is a no-op");
});

test("race status codes are the ones the HUD table knows", () => {
  assert.deepStrictEqual(RS, { NONE: 0, READY: 1, LOADING: 2, INRACE: 3, DONE: 4 });
});

// ---------------------------------------------------------------------------
// Наличие сейва и его содержимое — разные вещи
// ---------------------------------------------------------------------------

// Текст всех сообщений от сервера (тип 6, отправитель SERVER), пришедших
// на указанный адрес после отметки.
const serverLines = (socket, rinfo, since = 0) =>
  h
    .sentTo(socket, rinfo.address, rinfo.port, since)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.CHAT)
    .map((p) => {
      let at = 5; // тип + идентификатор
      at += 4 + p.buffer.readUInt32BE(at); // имя
      const length = p.buffer.readUInt32BE(at);
      return p.buffer.toString("latin1", at + 4, at + 4 + length);
    });

test("сейв, который грузит не ту карту, выводит игрока из гонки с объяснением", () => {
  // Клиент проверяет только, что файл start.sav существует. Сейв, сделанный
  // посреди прохождения, грузится прекрасно — и оставляет игрока не там.
  // Раньше гонка просто ждала карту, которая никогда не придёт, и умирала по
  // таймауту с сообщением, никого не называющим.
  const { server, socket, clock } = toLoading();
  const mark = socket.sent.length;

  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d2_coast_01" }), B);

  assert.strictEqual(server.race.runners.has("Bob"), false, "Боб должен выйти из гонки");

  const toBob = serverLines(socket, B, mark).join("\n");
  assert.match(toBob, /d2_coast_01/, "игроку не сказали, что именно он загрузил");
  assert.match(toBob, /d1_trainstation_01/, "игроку не сказали, что должно было загрузиться");
});

test("та же карта, с которой начали, значит «ещё грузится», а не «не тот сейв»", () => {
  const { server, clock } = toLoading();

  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_eli_01" }), B);

  assert.strictEqual(server.race.runners.has("Bob"), true);
  assert.strictEqual(server.race.phase, "loading");
});

test("выход одного участника не ломает гонку остальным", () => {
  const { server, clock } = toLoading();

  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  // Боб грузит не тот сейв — Алиса остаётся одна и гонка идёт дальше
  server.onDatagram(h.update("Bob", { map: "d2_coast_01" }), B);

  assert.strictEqual(server.race.runners.size, 1);
  assert.strictEqual(server.race.phase, "countdown_start");
});

// ---------------------------------------------------------------------------
// Время на финише
// ---------------------------------------------------------------------------

const finish = (server, clock) => {
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  server.onDatagram(h.checkpoint("Bob", 1), B);
  clock.advance(5000);
  clock.runTimeouts();
  clock.runTimeouts();
  assert.strictEqual(server.race.phase, "racing");
};

test("финиш объявляется вместе с игровым временем", () => {
  const { server, socket, clock } = toLoading();
  finish(server, clock);

  const mark = socket.sent.length;
  server.onDatagram(h.checkpoint("Alice", 2, { igt: 3661.5, liveSplit: -1 }), A);

  const line = serverLines(socket, B, mark).find((text) => text.includes("finished"));
  assert.ok(line, "объявления о финише нет");
  assert.match(line, /IGT: 01:01:01\.500/);
  assert.doesNotMatch(line, /LiveSplit/, "лайвсплита не было — и упоминать его нечего");
});

test("время лайвсплита показывается рядом со своим, когда бежали с зеркалом", () => {
  const { server, socket, clock } = toLoading();
  finish(server, clock);

  const mark = socket.sent.length;
  server.onDatagram(h.checkpoint("Alice", 2, { igt: 65.25, liveSplit: 65.29 }), A);

  const line = serverLines(socket, B, mark).find((text) => text.includes("finished"));
  assert.match(line, /IGT: 00:01:05\.250/);
  assert.match(line, /LiveSplit: 00:01:05\.290/);
});

test("клиент без полей времени объявляется по-старому", () => {
  const { server, socket, clock } = toLoading();
  finish(server, clock);

  const mark = socket.sent.length;
  server.onDatagram(h.checkpoint("Alice", 2), A);

  const line = serverLines(socket, B, mark).find((text) => text.includes("finished"));
  assert.ok(line, "объявления о финише нет");
  assert.doesNotMatch(line, /IGT/, "числа взяться неоткуда — и выдумывать его нельзя");
});

test("бессмысленное время не попадает в объявление", () => {
  const { server, socket, clock } = toLoading();
  finish(server, clock);

  const mark = socket.sent.length;
  server.onDatagram(h.checkpoint("Alice", 2, { igt: -5, liveSplit: 1e9 }), A);

  const line = serverLines(socket, B, mark).find((text) => text.includes("finished"));
  assert.doesNotMatch(line, /IGT|LiveSplit|NaN/);
});

// ---------------------------------------------------------------------------
// Состояние наблюдения в списке при входе
// ---------------------------------------------------------------------------

test("вошедшему сразу сообщают, кто за кем наблюдает", () => {
  // Клиенты объявляют наблюдение по изменению, поэтому тот, кто уже смотрел,
  // для нового игрока оставался бы обычным бегуном. Мод теперь по этому же
  // признаку прячет призрак наблюдателя, так что вошедший видел бы тело,
  // стоящее в чужих ботинках, без всякого объяснения.
  const { server, socket } = h.makeServer();

  server.onDatagram(h.connect("Alice"), A);
  server.onDatagram(h.update("Alice"), A);
  server.onDatagram(h.connect("Bob"), B);
  server.onDatagram(h.update("Bob"), B);
  server.onDatagram(h.spectate("Bob", "Alice"), B);

  const C = h.from("10.0.0.3", 40003);
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Carol"), C);

  const spectatePackets = h
    .sentTo(socket, C.address, C.port, mark)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPECTATE);

  assert.strictEqual(spectatePackets.length, 1, "состояние наблюдения не отправлено");

  const buffer = spectatePackets[0].buffer;
  const nameLength = buffer.readUInt32BE(1);
  assert.strictEqual(buffer.toString("latin1", 5, 5 + nameLength), "Bob");
});

test("тем, кто ни за кем не наблюдает, лишнего пакета не шлют", () => {
  const { server, socket } = h.makeServer();

  server.onDatagram(h.connect("Alice"), A);
  server.onDatagram(h.update("Alice"), A);

  const mark = socket.sent.length;
  server.onDatagram(h.connect("Bob"), B);

  const spectatePackets = h
    .sentTo(socket, B.address, B.port, mark)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.SPECTATE);

  assert.strictEqual(spectatePackets.length, 0);
});

// ---------------------------------------------------------------------------
// Кто не бежит - тот смотрит
// ---------------------------------------------------------------------------

// Пакеты статуса гонки, пришедшие на адрес после отметки, в виде
// { name, code, isRunner, underway }.
const statusPackets = (socket, rinfo, since = 0) =>
  h
    .sentTo(socket, rinfo.address, rinfo.port, since)
    .filter((p) => p.buffer.readUInt8(0) === packets.TYPE.RACE_STATUS)
    .map((p) => {
      const length = p.buffer.readUInt32BE(1);
      return {
        name: p.buffer.toString("latin1", 5, 5 + length),
        code: p.buffer.readUInt8(5 + length),
        isRunner: p.buffer.readUInt8(6 + length),
        underway: p.buffer.readUInt8(7 + length),
      };
    });

test("пока открыто лобби, гонка ещё не идёт", () => {
  // У не-участника есть минута, чтобы передумать и написать /ready. Увести его
  // в наблюдение в этот момент значило бы отнять у него эту минуту.
  const { server, socket, clock } = h.makeServer({ RACE_LOBBY_MS: "10000" });
  join(server, "Alice", A);
  join(server, "Bob", B);
  clock.advance(1000);

  const mark = socket.sent.length;
  server.onDatagram(h.chat("Alice", "/race"), A);

  const rows = statusPackets(socket, B, mark);
  assert.ok(rows.length > 0, "статус не разослан");
  assert.strictEqual(rows[0].isRunner, 1);
  assert.strictEqual(rows[0].underway, 0, "лобби - это ещё не гонка");
});

test("после обратного отсчёта гонка объявляется идущей", () => {
  const { server, socket } = toLoading();

  const rows = statusPackets(socket, B).filter((r) => r.underway === 1);
  assert.ok(rows.length > 0, "признак идущей гонки не выставлен ни разу");
});

test("вошедший посреди гонки сразу узнаёт, что она идёт", () => {
  // Статусы рассылаются в момент изменения. Без снимка при входе новый игрок
  // не знал бы ни о гонке, ни о том, что ему в ней делать нечего, и бегал бы
  // по той же карте среди участников.
  const { server, socket } = toLoading();

  const C = h.from("10.0.0.3", 40003);
  const mark = socket.sent.length;
  server.onDatagram(h.connect("Carol"), C);

  const rows = statusPackets(socket, C, mark);
  assert.strictEqual(rows.length, 2, "должны прийти статусы обоих участников");
  for (const row of rows) {
    assert.strictEqual(row.isRunner, 1);
    assert.strictEqual(row.underway, 1);
  }
});

test("в спокойное время вошедшему статусы не шлют", () => {
  const { server, socket } = h.makeServer();
  join(server, "Alice", A);

  const mark = socket.sent.length;
  server.onDatagram(h.connect("Bob"), B);

  assert.deepStrictEqual(statusPackets(socket, B, mark), []);
});

test("конец гонки снимает и признак участника, и признак гонки", () => {
  // Клиент считает гонку идущей, пока хоть у кого-то стоит признак участника.
  // Раньше последний статус уходил при ещё не очищенном списке участников,
  // то есть с признаком включённым, и гонка на клиенте не кончалась никогда.
  const { server, socket, clock } = toLoading();
  finish(server, clock);

  const mark = socket.sent.length;
  server.onDatagram(h.checkpoint("Alice", 2), A);
  server.onDatagram(h.checkpoint("Bob", 2), B);

  assert.strictEqual(server.race.phase, "idle");

  const last = statusPackets(socket, B, mark).slice(-2);
  assert.strictEqual(last.length, 2);
  for (const row of last) {
    assert.strictEqual(row.code, RS.NONE);
    assert.strictEqual(row.isRunner, 0, "признак участника должен сняться");
    assert.strictEqual(row.underway, 0, "признак гонки должен сняться");
  }
});

test("отмена гонки снимает признаки так же, как обычный конец", () => {
  const { server, socket, clock } = toLoading();
  clock.advance(1000);

  const mark = socket.sent.length;
  server.race.cancel("Race cancelled by the server operator.");

  const rows = statusPackets(socket, B, mark);
  assert.ok(rows.length > 0);
  for (const row of rows) {
    assert.strictEqual(row.isRunner, 0);
    assert.strictEqual(row.underway, 0);
  }
});

// --- a race is for players who are in the game --------------------------------
//
// The mod hides a spectator's ghost, and during a race it puts non-participants
// into spectate itself. So a spectator typing /race is a bystander taking the
// race lock away from the whole lobby - the cheapest possible troll, and one
// that happens by accident just as easily.

test("a spectator cannot start a race", () => {
  const { server } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Bob", B);

  server.onDatagram(h.spectate("Alice", "Bob"), A);
  server.onDatagram(h.chat("Alice", "/race"), A);

  assert.strictEqual(server.race.phase, "idle", "a spectator must not hold the race lock");
});

test("a spectator cannot join a race either", () => {
  const { server } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Bob", B);

  server.onDatagram(h.chat("Alice", "/race"), A);
  assert.strictEqual(server.race.phase, "lobby");

  server.onDatagram(h.spectate("Bob", "Alice"), B);
  server.onDatagram(h.chat("Bob", "/ready"), B);

  assert.ok(!server.race.runners.has("Bob"), "a spectator must not become a runner");
});

test("stopping spectating gives the commands back", () => {
  const { server } = h.makeServer();
  join(server, "Alice", A);
  join(server, "Bob", B);		// the target has to exist or the spectate is refused

  server.onDatagram(h.spectate("Alice", "Bob"), A);
  server.onDatagram(h.chat("Alice", "/race"), A);
  assert.strictEqual(server.race.phase, "idle");

  // "" is how the mod says it stopped watching.
  server.onDatagram(h.spectate("Alice", ""), A);
  server.onDatagram(h.chat("Alice", "/race"), A);
  assert.strictEqual(server.race.phase, "lobby", "a player back in the game may race");
});

test("RACE_SPECTATORS=1 restores the old free-for-all", () => {
  const { server } = h.makeServer({ RACE_SPECTATORS: "1" });
  join(server, "Alice", A);
  join(server, "Bob", B);		// as above - otherwise nobody is really spectating

  server.onDatagram(h.spectate("Alice", "Bob"), A);
  assert.strictEqual(server.users.get("Alice").spectating, "Bob", "the test must actually spectate");
  server.onDatagram(h.chat("Alice", "/race"), A);

  assert.strictEqual(server.race.phase, "lobby");
});

// ---- /leave ----------------------------------------------------------------
//
// Quitting on purpose is not the same as dropping out, and the difference is
// the pause. A player who disconnects has no session left to unfreeze; a player
// who types /leave is still sitting there, and the race froze them at the start
// line. Getting this wrong tells someone they are out of the race and then
// leaves them staring at PAUSED BY SERVER with no way to move.

const C = h.from("10.0.0.3", 40003);

test("/leave lifts the pause the race put on the runner", () => {
  const { server, socket, clock } = toLoading();

  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);
  clock.advance(500);
  server.onDatagram(h.update("Bob", { map: "d1_trainstation_01" }), B);
  assert.strictEqual(server.race.phase, "staging");

  // Alice reaches the start line and is frozen waiting for Bob.
  const mark = socket.sent.length;
  clock.advance(1000);
  server.onDatagram(h.checkpoint("Alice", 1), A);
  assert.strictEqual(server.race.paused.has("Alice"), true, "the test must actually freeze her");

  server.onDatagram(h.chat("Alice", "/leave"), A);

  assert.strictEqual(server.race.runners.has("Alice"), false, "she must be out of the race");
  assert.strictEqual(server.race.paused.has("Alice"), false, "and out of the pause");
  assert.deepStrictEqual(pauseState(socket, A, mark), [1, 0], "frozen, then released");
});

test("/leave from someone who is not racing changes nothing", () => {
  const { server, clock } = toLoading();
  clock.advance(500);
  server.onDatagram(h.update("Alice", { map: "d1_trainstation_01" }), A);

  const phase = server.race.phase;
  const runners = server.race.runners.size;
  // Carol never joined, so there is nothing for her to leave.
  server.onDatagram(h.connect("Carol"), C);
  server.onDatagram(h.chat("Carol", "/leave"), C);

  assert.strictEqual(server.race.phase, phase);
  assert.strictEqual(server.race.runners.size, runners);
});

test("the last runner typing /leave cancels the race", () => {
  const { server, clock } = toLoading();
  clock.advance(500);
  server.onDatagram(h.chat("Alice", "/leave"), A);
  assert.strictEqual(server.race.phase, "loading", "one runner is still in it");
  clock.advance(500);
  server.onDatagram(h.chat("Bob", "/leave"), B);
  assert.strictEqual(server.race.phase, "idle", "nobody left, so the race is over");
});

test("a finisher leaving does not end the race for the runners still going", () => {
  // Three runners, two of them home. If a finisher who leaves stays on the
  // finished list, "everyone is done" counts two against two remaining runners
  // and the race ends under the third, who is still on the course.
  const rig = h.makeServer({ RACE_LOBBY_MS: "2000" });
  const { server, clock } = rig;
  join(server, "Alice", A);
  join(server, "Bob", B);
  join(server, "Carol", C);
  clock.advance(1000);
  server.onDatagram(h.chat("Alice", "/race"), A);
  server.onDatagram(h.chat("Bob", "/ready"), B);
  server.onDatagram(h.chat("Carol", "/ready"), C);
  // The map countdown is a chain of timers a second apart, so the clock has to
  // be pumped rather than jumped: one advance past the lobby fires only the
  // first link.
  clock.advance(2100);
  for (let i = 0; i < 6; i += 1) {
    clock.advance(1000);
    clock.runTimeouts();
  }
  assert.strictEqual(server.race.phase, "loading");

  for (const [name, at] of [["Alice", A], ["Bob", B], ["Carol", C]]) {
    clock.advance(200);
    server.onDatagram(h.update(name, { map: "d1_trainstation_01" }), at);
  }
  for (const [name, at] of [["Alice", A], ["Bob", B], ["Carol", C]]) {
    server.onDatagram(h.checkpoint(name, 1), at);
  }
  // Same again for the start countdown: 3, 2, 1 and one beat more.
  for (let i = 0; i < 6; i += 1) {
    clock.advance(1000);
    clock.runTimeouts();
  }
  assert.strictEqual(server.race.phase, "racing", "the test must actually start the race");

  server.onDatagram(h.checkpoint("Alice", 2), A);
  server.onDatagram(h.checkpoint("Bob", 2), B);
  assert.strictEqual(server.race.phase, "racing", "Carol is still running");

  server.onDatagram(h.chat("Alice", "/leave"), A);
  assert.strictEqual(server.race.phase, "racing", "Carol is STILL running");
  assert.strictEqual(server.race.runners.has("Carol"), true);

  // And the race still ends properly once she is home.
  server.onDatagram(h.checkpoint("Carol", 2), C);
  assert.strictEqual(server.race.phase, "idle");
});
