"use strict";

// Speedrun race state machine.
//
//   idle -> lobby -> countdown_map -> loading -> staging -> countdown_start
//        -> racing -> idle
//
// Behaviour on the wire is unchanged: the same chat lines, the same countdown
// sounds, the same force-map, pause and status packets in the same order.
//
// Two things are new.
//
// Every waiting phase has a deadline. The old machine could park a player in a
// server-driven pause forever: a runner who reached the pre-teleport point sent
// checkpoint 1, got `pause on`, and then waited for a runner who never finished
// loading. Nothing in the machine ever timed that out, and the pause is one the
// player cannot lift, so the only way out was to quit the game. Each phase now
// expires and cancels the race, which unpauses everyone.
//
// Every transition validates the sequence. A finish is only accepted from a
// runner in `racing`; a checkpoint is only accepted once; a checkpoint id
// outside the two the client sends is ignored rather than falling through.
//
// This is not anticheat. The client still reports its own checkpoints, so a
// modified client can report a finish it did not earn. The sequence checks stop
// a *stray or replayed* packet from corrupting the machine, which is a
// different problem.

// Per-player race status shown in the HUD table (packet type 10).
const RS = { NONE: 0, READY: 1, LOADING: 2, INRACE: 3, DONE: 4 };

// The save every racer loads from, the map it lives on (for load detection),
// and the map whose finish trigger ends the race.
const RACE_SAVE = "start";
const RACE_MAP = "d1_trainstation_01";
const FINISH_MAP = "d3_breen_01";

// Sound paths relative to the game's sound/ folder.
const SND_COUNTDOWN = { 3: "server/three.wav", 2: "server/two.wav", 1: "server/one.wav" };
const SND_RACE_HINT = "server/hint.wav";

const CHECKPOINT_STAGE = 1;
const CHECKPOINT_FINISH = 2;

// Run time as the mod's own HUD writes it: HH:MM:SS.mmm. Returns null for
// anything that is not a real time, so a client that reports nothing (or
// garbage) simply gets the old announcement without a number in it - better
// than a race result reading "IGT: NaN".
const formatTime = (seconds) => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return null;
  // A single run past a day is not a run, it is a stuck timer.
  if (seconds >= 86400) return null;

  const whole = Math.floor(seconds);
  const millis = Math.round((seconds - whole) * 1000);
  const pad = (value, width) => String(value).padStart(width, "0");

  return (
    pad(Math.floor(whole / 3600), 2) +
    ":" +
    pad(Math.floor(whole / 60) % 60, 2) +
    ":" +
    pad(whole % 60, 2) +
    "." +
    pad(millis, 3)
  );
};

class RaceManager {
  constructor(deps) {
    this.deps = deps;
    this.config = deps.config;
    this.now = deps.now || (() => Date.now());
    this.setTimer = deps.setTimeout || setTimeout;
    this.clearTimer = deps.clearTimeout || clearTimeout;
    this._timers = [];
    this.reset();
  }

  // ---- helpers bound to the server ----
  say(text) {
    this.deps.say(text);
  }
  sayTo(name, text) {
    this.deps.sayTo(name, text);
  }
  sound(path) {
    this.deps.sound(path);
  }
  getUser(name) {
    return this.deps.getUser(name);
  }
  // The host returns whether the packet reached the socket. Anything that is
  // not an explicit false is treated as delivered, so a test double that
  // returns nothing keeps the old behaviour.
  pause(name, on, label) {
    return this.deps.pause(name, on, label) !== false;
  }
  forceMap(name, mapname) {
    this.deps.forceMap(name, mapname);
  }
  setStatus(name, code) {
    // Запомнено, чтобы вошедшего посреди гонки можно было ввести в курс дела:
    // статусы рассылаются в момент изменения, и тот, кто подключился позже,
    // иначе не узнал бы, что гонка вообще идёт.
    if (code === RS.NONE) this.statuses.delete(name);
    else this.statuses.set(name, code);
    this.deps.status(name, code, this.runners.has(name), this.underway());
  }

  // Набор участников закончился и началась собственно гонка.
  //
  // Различие важно клиенту: пока идёт лобби, у не-участника ещё есть минута,
  // чтобы написать /ready, и уводить его в наблюдение рано. По одним кодам
  // статуса это не вычислить - на этапе выхода к старту участники снова
  // становятся READY, ровно как в лобби.
  underway() {
    return this.phase !== "idle" && this.phase !== "lobby";
  }

  // Состояние гонки для того, кто только что вошёл: имя, код и признак
  // участника по каждому, о ком есть что сказать.
  statusSnapshot() {
    const rows = [];
    const underway = this.underway();
    for (const [name, code] of this.statuses)
      rows.push({ name, code, isRunner: this.runners.has(name), underway });
    return rows;
  }

  reset() {
    this.phase = "idle";
    this.creator = null;
    this.runners = new Set();
    this.loaded = new Set();
    this.staged = new Set();
    this.paused = new Set(); // who currently holds a server-driven pause
    this.statuses = new Map(); // имя -> последний разосланный код статуса
    // Map each runner was standing on when the load was ordered. A runner who
    // moves to a THIRD map has loaded a save that is not the start of the game.
    this.mapBeforeLoad = new Map();
    this.finished = [];
    this.lobbyEndsAt = 0;
    this.phaseDeadline = 0;
    this.loadingStartedAt = 0;
    // When loading last made progress: the phase start, or the last runner to
    // report the race map. The stall fuse in tick() runs from here.
    this.loadProgressAt = 0;
    this.warned30 = false;
    this.warned10 = false;
    this.clearTimers();
  }

  clearTimers() {
    if (this._timers) for (const timer of this._timers) this.clearTimer(timer);
    this._timers = [];
  }

  // A throw inside a countdown callback used to be caught but left the machine
  // in whatever half-applied state it had reached. The catch stays (a race is
  // never worth taking the server down for) and the machine is cancelled, which
  // is a defined state with everyone unpaused.
  after(ms, fn) {
    const timer = this.setTimer(() => {
      try {
        fn();
      } catch (error) {
        this.deps.log.error("race timer failed: %s", error && error.message);
        this.cancel("an internal error ended the race");
      }
    }, ms);
    this._timers.push(timer);
    return timer;
  }

  active() {
    return this.phase !== "idle";
  }

  isRunner(name) {
    return this.runners.has(name);
  }

  setPhase(phase, timeoutMs) {
    this.phase = phase;
    this.phaseDeadline = timeoutMs ? this.now() + timeoutMs : 0;
  }

  // ---- chat commands ----
  cmdRace(name) {
    if (this.phase !== "idle") {
      this.sayTo(name, "A race is already in progress. Please wait until it finishes.");
      return false;
    }
    this.reset();
    this.phase = "lobby";
    this.creator = name;
    this.runners.add(name);
    this.setStatus(name, RS.READY);
    this.lobbyEndsAt = this.now() + this.config.raceLobbyMs;
    this.sound(SND_RACE_HINT);
    this.say(
      `${name} wants to start a speedrun race! Type /ready to join. ` +
        `The race begins in ${Math.round(this.config.raceLobbyMs / 1000)} seconds.`
    );
    this.say(
      `Every racer MUST have a save named '${RACE_SAVE}' (${RACE_SAVE}.sav) - the race loads it. ` +
        "Create it before you join!"
    );
    return true;
  }

  cmdReady(name) {
    if (this.phase !== "lobby") {
      this.sayTo(
        name,
        this.phase === "idle"
          ? "There is no race to join. Type /race to start one."
          : "The race lobby is closed - you can't join anymore."
      );
      return false;
    }
    if (this.runners.has(name)) return false;
    this.runners.add(name);
    this.setStatus(name, RS.READY);
    this.say(`${name} is ready for the race!`);
    return true;
  }

  // Quitting on purpose, which is not the same thing as dropping out.
  //
  // onPlayerDrop cannot be reused here. It deliberately leaves the pause alone,
  // because a disconnected player has no session left to unpause - but whoever
  // types /leave is still sitting in the game, and a race freezes its runners at
  // the start line. Without lifting that by hand they would be told they are out
  // of the race and then left staring at PAUSED BY SERVER with no way to move.
  cmdLeave(name) {
    if (!this.runners.has(name)) {
      this.sayTo(
        name,
        this.phase === "idle"
          ? "There is no race to leave."
          : "You are not in this race."
      );
      return false;
    }

    // The pause goes first: everything after this can end the race, and endRace
    // releases `paused` plus `runners` - a set this name is about to leave. If
    // the packet fails to go out the name stays in `paused` on purpose, so those
    // later sweeps try again rather than forgetting somebody who is still frozen.
    this.pauseRunner(name, false, "");

    this.runners.delete(name);
    this.loaded.delete(name);
    this.staged.delete(name);
    this.mapBeforeLoad.delete(name);
    this.dropFinished(name);
    this.setStatus(name, RS.NONE);
    this.say(`${name} left the race.`);

    if (this.runners.size === 0) {
      this.cancel("Race cancelled - no players left.");
      return true;
    }
    this.settleAfterRunnerLeft();
    return true;
  }

  // A runner who is no longer racing must not be counted as one who is done,
  // or the "everyone has finished" test below ends the race under the players
  // still on the course: three runners, two home, one of the two leaves, and
  // finished.length === runners.size becomes true with a runner mid-run.
  dropFinished(name) {
    const at = this.finished.indexOf(name);
    if (at >= 0) this.finished.splice(at, 1);
  }

  // The runner who just left may have been the one everybody was waiting on.
  // Shared by /leave and by dropping out, because the machine does not care why
  // the name went away - only that the counts it blocks on have changed.
  settleAfterRunnerLeft() {
    if (this.phase === "loading" && this.loaded.size === this.runners.size) {
      this.setPhase("staging", this.config.raceStagingTimeoutMs);
      this.say("Before the race starts, the game will pause automatically. Please wait for it to end.");
      // The runners who are left may already be staged, in which case there is
      // nothing to wait for. Without this check the machine sat in `staging`
      // with everyoneReady() true and every remaining runner frozen behind a
      // server pause until the staging timeout expired two minutes later.
      if (this.everyoneReady()) this.startRaceCountdown();
    } else if (this.phase === "staging" && this.everyoneReady()) {
      this.startRaceCountdown();
    } else if (this.phase === "racing" && this.finished.length === this.runners.size) {
      this.say("Race over! GG!");
      this.endRace();
    }
  }

  // ---- lobby timer, warnings and phase deadlines ----
  tick(now) {
    if (this.phase === "lobby") {
      const remain = this.lobbyEndsAt - now;
      if (!this.warned30 && remain <= 30000 && this.config.raceLobbyMs > 30000) {
        this.warned30 = true;
        this.say("30 seconds left. Type /ready to join the race!");
      }
      if (!this.warned10 && remain <= 10000 && this.config.raceLobbyMs > 10000) {
        this.warned10 = true;
        this.say("The race begins in 10 seconds!");
      }
      if (remain <= 0) this.startMapCountdown();
      return;
    }

    // Loading has stopped making progress. The common way to hold the race lock
    // is to join a race and never load, so that case gets a much shorter fuse
    // than the full loading timeout.
    //
    // The fuse runs from the last load, not from the start of the phase. The
    // first version only fired when NOBODY had loaded, which left the obvious
    // variant open: two of three runners load, the third never does, and the
    // race sits in `loading` for the full RACE_LOADING_TIMEOUT_MS - measured at
    // 179 s with everyone else locked out of starting one.
    if (
      this.phase === "loading" &&
      this.loadProgressAt &&
      now - this.loadProgressAt >= this.config.raceNoProgressMs
    ) {
      this.cancel(
        this.loaded.size === 0
          ? "Race cancelled - nobody loaded the save."
          : "Race cancelled - not everyone loaded the save."
      );
      return;
    }

    if (this.phaseDeadline && now >= this.phaseDeadline) {
      const stuck = this.phase;
      this.cancel(
        stuck === "loading"
          ? "Race cancelled - not everyone finished loading in time."
          : stuck === "staging"
            ? "Race cancelled - not everyone reached the start in time."
            : stuck === "countdown_map" || stuck === "countdown_start"
              ? "Race cancelled - the countdown did not finish."
              : "Race cancelled - it ran for too long."
      );
    }
  }

  startMapCountdown() {
    // Deadline on the countdown too. It is driven by setTimeout chains, and a
    // timer that never fires - a bug, or a process suspended mid-countdown -
    // used to leave the machine in a phase with no expiry, holding the race
    // lock for everyone. Ten seconds is three times the countdown itself.
    this.setPhase("countdown_map", 10000);
    this.say("3...");
    this.sound(SND_COUNTDOWN[3]);
    this.after(1000, () => {
      this.say("2...");
      this.sound(SND_COUNTDOWN[2]);
    });
    this.after(2000, () => {
      this.say("1...");
      this.sound(SND_COUNTDOWN[1]);
    });
    this.after(3000, () => {
      this.say(`Loading the race save '${RACE_SAVE}'...`);
      this.beginLoading();
    });
  }

  beginLoading() {
    this.setPhase("loading", this.config.raceLoadingTimeoutMs);
    this.loadingStartedAt = this.now();
    this.loadProgressAt = this.loadingStartedAt;
    this.loaded.clear();
    this.mapBeforeLoad.clear();
    for (const name of this.runners) {
      const user = this.getUser(name);
      if (!user) continue;
      // Remembered before the load is ordered, so the map the runner ends up
      // on can be told apart from the one they were already standing on.
      this.mapBeforeLoad.set(name, user.mapname || "");
      this.forceMap(name, RACE_SAVE);
      this.setStatus(name, RS.LOADING);
    }
  }

  // Driven by the map field of a position update: a runner reporting RACE_MAP
  // has finished loading.
  //
  // The save existing is not the same thing as the save being the start of the
  // game. The client checks that a file named 'start.sav' is there and loads
  // it; nothing checked where it PUT the player. A runner whose 'start' save
  // was made in the middle of a run therefore loaded fine, landed on some other
  // map, and the whole race sat in `loading` waiting for a map report that was
  // never coming - until a timeout cancelled it for everybody with a message
  // that named nobody.
  onMapUpdate(name, mapname) {
    if (this.phase !== "loading") return;
    if (!this.runners.has(name) || this.loaded.has(name)) return;

    if (mapname === RACE_MAP) {
      this.loaded.add(name);
      this.loadProgressAt = this.now();
      this.setStatus(name, RS.READY);
      this.say(`${name} has loaded in!`);
      if (this.loaded.size === this.runners.size && this.runners.size > 0) {
        this.setPhase("staging", this.config.raceStagingTimeoutMs);
        // Runners who reached the pause point while others were still loading
        // are already staged; with the last load in, the race can start.
        if (this.everyoneReady()) this.startRaceCountdown();
      }
      return;
    }

    // Still on the map they started from: the load has not happened yet.
    if (mapname === this.mapBeforeLoad.get(name)) return;

    // A third map. They loaded something, and it was not the start of the game.
    this.sayTo(
      name,
      `Your '${RACE_SAVE}' save loads ${mapname}, not ${RACE_MAP}. ` +
        "Start a new game, make the save at the very beginning, and join the next race."
    );
    this.say(`${name} loaded ${mapname} instead of ${RACE_MAP} and is out of the race.`);
    this.dropRunner(name);
  }

  // Take one runner out of a race that is still forming, and let the machine
  // move on without them. Same bookkeeping as a player leaving, minus the
  // "was removed, reason: LEFT" line, because they are still connected.
  dropRunner(name) {
    this.runners.delete(name);
    this.loaded.delete(name);
    this.staged.delete(name);
    this.mapBeforeLoad.delete(name);
    this.pauseRunner(name, false, "");
    this.setStatus(name, RS.NONE);

    if (this.runners.size === 0) {
      this.cancel("Race cancelled - no players left.");
      return;
    }

    // They may have been the last one everybody was waiting for.
    if (this.phase === "loading" && this.loaded.size === this.runners.size) {
      this.setPhase("staging", this.config.raceStagingTimeoutMs);
      if (this.everyoneReady()) this.startRaceCountdown();
    }
  }

  // Client checkpoints: 1 = reached the pre-teleport pause point, 2 = finished.
  // `times` carries the finisher's own clocks and is absent from older clients.
  onCheckpoint(name, checkpoint, times) {
    if (checkpoint === CHECKPOINT_STAGE) return this.onStaged(name);
    if (checkpoint === CHECKPOINT_FINISH) return this.onFinished(name, times);
    // Any other id is a client we don't speak to or a crafted packet. Ignoring
    // it beats falling through into a branch that was written for 1 or 2.
    return false;
  }

  onStaged(name) {
    if (this.phase !== "staging" && this.phase !== "loading") return false;
    if (!this.runners.has(name) || this.staged.has(name)) return false;

    // A runner can legitimately reach the pause point before the server has
    // registered their map, so checkpoint 1 is accepted during loading. But
    // reaching it is not evidence of having loaded, and the first version let
    // the countdown start as soon as everyone was staged - so two crafted
    // checkpoints drove the machine all the way to `racing` with nobody having
    // loaded the save at all. Staging counts; loading still has to finish.
    this.staged.add(name);
    this.pauseRunner(name, true, "PAUSED BY SERVER");
    this.setStatus(name, RS.READY);
    this.say(`${name} is ready to start! Waiting for the others...`);
    if (this.everyoneReady()) this.startRaceCountdown();
    return true;
  }

  everyoneReady() {
    if (this.runners.size === 0) return false;
    if (this.staged.size !== this.runners.size) return false;
    // Every runner must have reported the race map, not merely a checkpoint.
    return this.loaded.size === this.runners.size;
  }

  onFinished(name, times) {
    // A finish only counts from a runner who is actually racing, and only once.
    if (this.phase !== "racing") return false;
    if (!this.runners.has(name) || this.finished.includes(name)) return false;

    this.finished.push(name);
    this.setStatus(name, RS.DONE);
    const place = this.finished.length;
    const ordinal = place === 1 ? "first" : place === 2 ? "second" : place === 3 ? "third" : null;

    // The finisher's own clocks, reported with the checkpoint.
    //
    // This is the runner's word, exactly like the checkpoint itself: the
    // client owns the timer, so a modified one can report anything. The race
    // was never an anticheat, and a time nobody can read is worse than a time
    // that has to be trusted.
    //
    // LiveSplit's number is shown next to ours only when the runner is
    // actually mirroring it (gh_timer_mirror 1). It is the community's
    // official time and it will not match ours to the millisecond - they are
    // two clocks - so both are printed rather than one being picked.
    const igt = formatTime(times && times.igt);
    const liveSplit = formatTime(times && times.liveSplit);

    // N2 (review 2): a finish from a session that was under an impersonation
    // attempt is accepted - refusing it would let an attacker cancel the real
    // runner's finish - but it may have been forged from the runner's own
    // address:port, so it is marked where everybody reads it and in the log.
    const unverified = !!(times && times.unverified);
    let line = ordinal ? `${name} finished the speedrun ${ordinal}` : `${name} finished the speedrun`;
    line += unverified ? " (UNVERIFIED)!" : "!";
    if (igt) line += ` IGT: ${igt}`;
    if (igt && liveSplit) line += ` | LiveSplit: ${liveSplit}`;
    this.say(line);
    if (unverified) {
      this.say(`${name}'s result is unverified: the session was under an impersonation attempt.`);
      if (this.deps.log) {
        // When the guard started, so an operator can tell a griefer who tripped
        // it seconds before the finish from a sweep that ran for minutes.
        const since = Math.round(((times && times.guardedForMs) || 0) / 1000);
        this.deps.log.warn(
          "race: '%s' finish is unverified (session under an impersonation guard since %d s before the finish)",
          name,
          since
        );
      }
    }

    if (this.finished.length === this.runners.size && this.runners.size > 0) {
      this.say("Race over! GG!");
      this.endRace();
    }
    return true;
  }

  startRaceCountdown() {
    this.setPhase("countdown_start", 12000);
    this.say("All players are ready, starting the race!");
    this.say("3...");
    this.sound(SND_COUNTDOWN[3]);
    this.after(1000, () => {
      this.say("2...");
      this.sound(SND_COUNTDOWN[2]);
    });
    this.after(2000, () => {
      this.say("1...");
      this.sound(SND_COUNTDOWN[1]);
    });
    // One extra second after "1..." so everyone releases on the same beat.
    this.after(4000, () => {
      this.setPhase("racing", this.config.raceMaxDurationMs);
      // The release at the start of a race is the one that matters most: a
      // runner who is not released here cannot reach the finish trigger, so
      // nothing ends the race early and they sit behind the overlay until
      // RACE_MAX_DURATION_MS - two hours by default. This loop used to drop
      // pauseRunner's verdict on the floor, which meant only the cancel and
      // end-of-race paths ever handed a failure to the host.
      const stuck = [];
      for (const name of this.runners) {
        if (!this.pauseRunner(name, false, "")) stuck.push(name);
        this.setStatus(name, RS.INRACE);
      }
      if (stuck.length && typeof this.deps.unpauseLater === "function") this.deps.unpauseLater(stuck);
    });
  }

  // Pause bookkeeping lives here so that "everyone we paused gets unpaused" is
  // a property of the machine rather than of each exit path remembering to do
  // it. A player who is gone is simply skipped; a player still connected is
  // always released.
  pauseRunner(name, on, label) {
    // A player who is gone is not frozen, whatever the bookkeeping says.
    if (!this.getUser(name)) {
      this.paused.delete(name);
      return true;
    }

    // Delivery is best effort and must never decide the machine's state: the
    // old release loop sent to each runner in turn with nothing catching a
    // failure, so one bad send left every runner after it in the list frozen.
    //
    // The bookkeeping is only updated when the packet actually went out. A
    // release that failed leaves the name in `paused`, so the next attempt -
    // the end of the race, a cancel, or shutdown - tries again instead of
    // quietly forgetting somebody who is still staring at an overlay.
    let delivered;
    try {
      delivered = this.pause(name, on, label);
    } catch (error) {
      this.deps.log.error("could not send pause to '%s': %s", name, error && error.message);
      return false;
    }
    if (!delivered) {
      this.deps.log.error("pause packet for '%s' was not sent", name);
      return false;
    }

    if (on) this.paused.add(name);
    else this.paused.delete(name);
    return true;
  }

  // Returns the names it could not release, so the caller can keep trying.
  releaseEveryone() {
    // Everyone we ever paused, plus every current runner: a runner who was
    // about to be paused when the race was cancelled costs one extra packet,
    // and one extra packet is cheaper than a player stuck behind an overlay.
    const release = new Set([...this.paused, ...this.runners]);
    const stuck = [];
    for (const name of release) {
      if (!this.pauseRunner(name, false, "")) stuck.push(name);
    }
    return stuck;
  }

  endRace() {
    // reset() clears `paused`, so anyone the release could not reach has to be
    // handed to the host before that happens or the overlay they are staring at
    // becomes nobody's problem.
    const stuck = this.releaseEveryone();
    if (stuck.length && typeof this.deps.unpauseLater === "function") this.deps.unpauseLater(stuck);

    // Последние статусы уходят ПОСЛЕ сброса, и это принципиально: они обязаны
    // сказать и «не участник», и «гонки нет».
    //
    // Клиент считает гонку идущей, пока хоть у кого-то стоит признак
    // участника. Раньше финальный статус рассылался при ещё не очищенном
    // списке участников, то есть с этим признаком включённым, и гонка на
    // клиенте не заканчивалась никогда: у бегунов навсегда оставались скрыты
    // призраки зрителей.
    const names = Array.from(this.runners);
    this.reset();
    for (const name of names) this.setStatus(name, RS.NONE);
  }

  // Any abnormal end: a deadline, an internal error, or the operator.
  cancel(reason) {
    if (this.phase === "idle") return false;
    if (reason) this.say(reason);
    this.endRace();
    return true;
  }

  onPlayerDrop(name, wireReason) {
    // A player who leaves must not stay in `paused`: they are gone, and if they
    // come back it is as a new session with no pause.
    this.paused.delete(name);
    if (!this.runners.has(name)) return;

    this.runners.delete(name);
    this.loaded.delete(name);
    this.staged.delete(name);
    this.mapBeforeLoad.delete(name);
    this.dropFinished(name);
    const reason = wireReason === "timeout" ? "TIMED OUT" : wireReason === "kick" ? "KICKED" : "LEFT";
    this.say(`${name} was removed from the race. Reason: ${reason}`);
    // Участник уже вычеркнут выше, поэтому статус уйдёт с признаком «не
    // участник» сам собой.
    this.setStatus(name, RS.NONE);

    if (this.runners.size === 0) {
      this.say("Race cancelled - no players left.");
      this.endRace();
      return;
    }

    // The player we were waiting on may have been the last blocker.
    this.settleAfterRunnerLeft();
  }

  snapshot() {
    return {
      phase: this.phase,
      creator: this.creator,
      runners: Array.from(this.runners),
      loaded: Array.from(this.loaded),
      staged: Array.from(this.staged),
      paused: Array.from(this.paused),
      finished: this.finished.slice(),
    };
  }
}

module.exports = {
  RaceManager,
  RS,
  formatTime,
  RACE_SAVE,
  RACE_MAP,
  FINISH_MAP,
  SND_COUNTDOWN,
  SND_RACE_HINT,
  CHECKPOINT_STAGE,
  CHECKPOINT_FINISH,
};
