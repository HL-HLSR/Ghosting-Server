"use strict";

// Кого не пускать, кого пускать только по списку и кому можно больше остальных.
//
// ЧЕСТНАЯ ЧАСТЬ ПЕРВОЙ, как в identity.js. В протоколе нет ни SteamID, ни
// токена, ни подписи, и мод пересобирать не будут. Значит опознать человека
// нечем: есть ник, который никому не принадлежит, и адрес источника, который
// подделывается. Отсюда два признака, и они РАЗНОЙ прочности:
//
//   name      удобство, не безопасность. Ник занимает тот, кто успел; см.
//             nickname.js. Бан по нику держит того, кому лень сменить ник, и
//             больше никого. OP по нику - та же слабость обратной стороной:
//             права получит любой, кто займёт ник, пока настоящий владелец не
//             на сервере. Выдаётся поэтому только из консоли.
//   address   доказательства ровно те же (адрес отправителя подделывается), но
//             чтобы ИГРАТЬ с чужого адреса, ответы должны до него доходить, и
//             вот это уже не бесплатно. Зато адрес общий: за одним NAT сидят
//             посторонние, и бан по адресу выключает их всех.
//
// Ни то, ни другое не аутентификация, и справка с README говорят это прямым
// текстом. Здесь это сказано, чтобы следующий читатель не принял список за
// систему прав.
//
// Вид идентичности лежит в записи отдельным полем `kind`. С 1.4.0 мод
// присылает SteamID - и это ровно ещё одно значение kind (STEAMID ниже) и одна
// строчка в keyFor, не новый формат файла. Что SteamID стоит как
// доказательство (не больше ника: его присылает сам клиент), сказано у KIND.

const fs = require("fs");
const net = require("net");
const path = require("path");
const crypto = require("crypto");

const { nicknameKey } = require("./nickname");
const { sanitizeText, truncateBytes } = require("../wire/text");

class AccessError extends Error {}

// Виды идентичности. STEAMID появится здесь же, когда его начнёт присылать мод.
//
// SPRAY - это не отдельный список, а тот же бан по нику, только запрещающий не
// вход, а спрей. Смысл в том, что порнографию в лобби вешает человек, а не
// адрес, и снимать его с сервера целиком за картинку - слишком грубо: пусть
// играет молча. Записи лежат в том же файле и в той же карте `banned`, ключ
// разведён префиксом, а isBanned спрашивает только NAME и ADDRESS - поэтому
// запрет на спрей никого не выкидывает. Ровно тот случай, который описан выше:
// новое значение kind и одна строчка в keyFor, без нового формата файла.
//
// STEAMID (1.4.0) - тот самый обещанный вид. Мод 1.4.0 присылает в конце v2
// коннекта SteamID64 игрока (server.js, readConnectHead). ПРИСЫЛАЕТ САМ: тикета
// Steam за ним нет, сервер ничего не проверяет, и клиент, которому так
// захотелось, пришлёт чужой SteamID или никакой. Поэтому SteamID здесь - ровно
// та же категория, что ник: удобный ярлык, а не доказательство. Чуть лучше ника
// в одном: случайно совпасть он не может, и сменить его стоит правки DLL, а не
// одной строки в консоли. Бан по SteamID обходится тем, что SteamID не прислан;
// OP по SteamID без PIN получает любой, кто его знает (а SteamID публичны).
const KIND = { NAME: "name", ADDRESS: "address", SPRAY: "spray", STEAMID: "steamid" };

// Ключи SteamID лежат в своём пространстве: ник "76561198000000001" - это ник,
// и бан по нему не должен совпасть с баном по SteamID.
const STEAM_KEY_PREFIX = "steam:";

// SteamID64 обычной (individual) учётки публичной вселенной Steam на десктопе:
// вселенная 1, тип 1, инстанс 1 - старшие 32 бита 0x01100001, номер учётки в
// младших. 76561197960265728 - это тот же SteamID с номером 0.
const STEAMID64_BASE = 76561197960265728n;
const STEAMID64_HIGH = 0x01100001n;

// SteamID64, "STEAM_X:Y:Z" или "[U:1:N]" -> SteamID64 строкой, или null.
// Только обычные учётки: группа, игровой сервер, анонимный вход и нулевой
// номер - не игроки. Строки, и только строки: число из JSON уже потеряло бы
// младшие разряды (SteamID64 больше 2^53).
const normalizeSteamId = (value) => {
  if (typeof value !== "string") return null;
  const text = value.trim();
  let account = null;
  let match;
  if (/^[0-9]{17}$/.test(text)) {
    const id = BigInt(text);
    if (id >> 32n !== STEAMID64_HIGH) return null;
    account = id & 0xffffffffn;
  } else if ((match = /^STEAM_[0-5]:([01]):([0-9]{1,10})$/i.exec(text))) {
    account = BigInt(match[2]) * 2n + BigInt(match[1]);
  } else if ((match = /^\[U:1:([0-9]{1,10})\]$/i.exec(text))) {
    account = BigInt(match[1]);
  } else {
    return null;
  }
  if (account <= 0n || account > 0xffffffffn) return null;
  return (STEAMID64_BASE + account).toString();
};

// PIN оператора по SteamID. В отличие от PIN из `op "Nick" PIN` (живёт только
// в памяти, до конца сессии) этот переживает перезапуск, а значит лежит в
// файле - и лежит хэшем: scrypt с солью. 6-12 цифр перебираются офлайн за
// минуты, так что хэш защищает от случайного взгляда в файл, не от того, кто
// его унёс; файл и так 0600. Параметры скромные (N=4096, ~10 мс): проверка
// идёт в цикле событий на каждую команду оператора, пока PIN не подтверждён.
const PIN_FORMAT = /^s1\$([0-9a-f]{32})\$([0-9a-f]{64})$/;
const PIN_SCRYPT = { N: 4096, r: 8, p: 1 };

const hashPin = (pin) => {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pin), salt, 32, PIN_SCRYPT);
  return `s1$${salt.toString("hex")}$${hash.toString("hex")}`;
};

const invalidValue = (kind) => {
  if (kind === KIND.ADDRESS) return "not an IP address";
  if (kind === KIND.STEAMID) return "not a SteamID (SteamID64, STEAM_0:Y:Z or [U:1:N] of a player account)";
  return "not a usable nickname";
};

// Формат файла. Номер проверяется при загрузке: файл, написанный будущей
// версией, лучше не открывать вовсе, чем молча потерять из него половину
// записей - потерянная запись это впущенный обратно забаненный.
const FORMAT_VERSION = 1;

// Потолок на каждый список. Списки правит человек, а не поток пакетов, но
// команды из чата тоже сюда пишут, и файл, растущий без предела, - это способ
// занять диск чужими руками.
const MAX_ENTRIES = 1024;

// Причина едет в кик-пакет, где на всю строку 63 байта (limits.js), и оседает
// в файле. 64 байта хватает на человеческую формулировку и не даёт превратить
// список в хранилище текста.
const MAX_REASON_BYTES = 64;

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

// Год. Всё, что дольше, - это "навсегда", записанное числом, и пусть оно так и
// называется: "ban 3650d" и "ban perm" не должны быть разными вещами.
const MAX_DURATION_MS = 365 * DAY;

// Одна цифровая группа и одна буква. Без вложенных квантификаторов и без
// альтернатив, которые могли бы разойтись на длинном вводе: строка приходит из
// чата, то есть от игрока.
const DURATION = /^([0-9]{1,7})([smhd])$/;
const PERMANENT = new Set(["perm", "permanent", "forever"]);
const SCALE = { s: SECOND, m: MINUTE, h: HOUR, d: DAY };

// L6: IPv4 only. The socket is udp4, so an IPv6 literal or an IPv4-mapped one
// (::ffff:1.2.3.4) in a ban or whitelist would silently never match any real
// client - a ban that does nothing is worse than a refused one. A mapped literal
// is normalised to the IPv4 form the datagram's rinfo actually carries; anything
// that is not a plain IPv4 literal is refused. A hostname would mean a DNS lookup
// in the ban-check path, which config.js refuses for the same reason. Returns the
// canonical IPv4 string, or null.
const normalizeAddress = (value) => {
  let text = String(value == null ? "" : value).trim();
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(text);
  if (mapped) text = mapped[1];
  return net.isIP(text) === 4 ? text : null;
};

// Строка срока -> миллисекунды, 0 = навсегда, null = не срок.
const parseDuration = (token) => {
  if (typeof token !== "string") return null;
  const value = token.trim().toLowerCase();
  if (value === "") return null;
  if (PERMANENT.has(value)) return 0;
  const match = DURATION.exec(value);
  if (!match) return null;
  const ms = Number(match[1]) * SCALE[match[2]];
  if (ms <= 0 || ms > MAX_DURATION_MS) return null;
  return ms;
};

// Две старшие единицы, не больше: "1d 4h" читается, "1d 4h 12m 3s" - уже нет.
//
// Округление вверх до секунды - не косметика. Между "ban 45m" и первым выводом
// списка проходит несколько миллисекунд, и без него оператор видит в ответ на
// свои же 45m строчку "44m 59s" и начинает искать, где потерялась минута.
const formatDuration = (ms) => {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  const parts = [];
  let rest = Math.ceil(ms / SECOND) * SECOND;
  for (const [unit, size] of [["d", DAY], ["h", HOUR], ["m", MINUTE], ["s", SECOND]]) {
    const count = Math.floor(rest / size);
    if (count > 0) {
      parts.push(`${count}${unit}`);
      rest -= count * size;
    }
    if (parts.length === 2) break;
  }
  return parts.length > 0 ? parts.join(" ") : "0s";
};

class AccessList {
  constructor(options) {
    const opts = options || {};
    this.maxNameLength = opts.maxNameLength || 31;

    // Часы здесь НАСТЕННЫЕ, и это единственное место в сервере, где так.
    //
    // Всё остальное меряет интервалы монотонным clock.js, потому что скачок NTP
    // ломает throttle и sweep. Здесь наоборот: срок бана должен пережить
    // перезапуск процесса, а монотонное время после рестарта начинается заново
    // и записанное "истекает в 1000000" не значит уже ничего. Цена честная и
    // маленькая: перевод часов сдвинет момент разбана, и всё.
    this.now = opts.now || Date.now;

    // null = ничего не писать на диск. Так работают тесты и так работает
    // ACCESS_PERSIST=0.
    this.file = opts.file || null;
    this.log = opts.log || null;

    this.whitelistEnabled = false;
    // ключ записи -> запись
    this.banned = new Map();
    this.allowed = new Map();
    this.operators = new Map();

    // Последняя ошибка записи. Консоль показывает её сразу после команды:
    // "забанил, но на диск не легло" операторy надо знать в тот же момент, а не
    // при следующем старте.
    this.lastSaveError = null;
  }

  // -------------------------------------------------------------------------
  // Ключи и записи
  // -------------------------------------------------------------------------

  // Значение -> ключ сравнения, или null, если значение вообще не годится.
  //
  // Ник сворачивается ровно тем же nicknameKey, что и ростер: иначе "alice" в
  // бан-листе и "ALICE" на сервере - два разных человека, а это и есть обход
  // бана нажатием Caps Lock.
  keyFor(kind, value) {
    if (kind === KIND.NAME) {
      const key = nicknameKey(typeof value === "string" ? value : "", this.maxNameLength);
      return key.length > 0 ? key : null;
    }
    if (kind === KIND.SPRAY) {
      // Тот же свёрнутый ник, но в своём пространстве ключей: у одного человека
      // может быть и запрет на спрей, и обычный бан, и это две разные записи.
      const key = nicknameKey(typeof value === "string" ? value : "", this.maxNameLength);
      return key.length > 0 ? `spray:${key}` : null;
    }
    if (kind === KIND.ADDRESS) return normalizeAddress(value);
    if (kind === KIND.STEAMID) {
      const id = normalizeSteamId(value);
      return id === null ? null : `${STEAM_KEY_PREFIX}${id}`;
    }
    return null;
  }

  // Как показывать. Для ника - то, что ввели, без управляющих байтов и по длине
  // ника: строка уходит в чат и в консоль оператора.
  displayFor(kind, value) {
    if (kind === KIND.NAME || kind === KIND.SPRAY) return truncateBytes(sanitizeText(value), this.maxNameLength);
    if (kind === KIND.STEAMID) return normalizeSteamId(value) || "";
    // An address is shown in the same canonical IPv4 form it is keyed by, so a
    // mapped literal does not read back as the thing that would never match.
    return normalizeAddress(value) || String(value == null ? "" : value).trim();
  }

  makeRecord(kind, value, options) {
    const opts = options || {};
    const key = this.keyFor(kind, value);
    if (key === null) return null;
    return {
      kind,
      value: this.displayFor(kind, value),
      key,
      reason: truncateBytes(sanitizeText(opts.reason || ""), MAX_REASON_BYTES),
      // 0 = навсегда, иначе абсолютный момент по настенным часам.
      until: Number.isFinite(opts.until) && opts.until > 0 ? Math.floor(opts.until) : 0,
      addedAt: Math.floor(this.now()),
      addedBy: truncateBytes(sanitizeText(opts.addedBy || "console"), this.maxNameLength),
    };
  }

  expired(record) {
    return record.until > 0 && this.now() >= record.until;
  }

  // -------------------------------------------------------------------------
  // Баны
  // -------------------------------------------------------------------------

  ban(kind, value, options) {
    const record = this.makeRecord(kind, value, options);
    if (!record) {
      return { ok: false, error: invalidValue(kind) };
    }
    // Повторный бан того же ключа - это обновление срока и причины, а не новая
    // строка, поэтому потолок ему не помеха.
    if (!this.banned.has(record.key) && this.banned.size >= MAX_ENTRIES) {
      return { ok: false, error: `the ban list is full (${MAX_ENTRIES} entries)` };
    }
    this.banned.set(record.key, record);
    return { ok: true, record, persisted: this.save() };
  }

  unban(kind, value) {
    const key = this.keyFor(kind, value);
    if (key === null) return { ok: false, error: invalidValue(kind) };
    const record = this.banned.get(key);
    if (!record || this.expired(record)) {
      this.banned.delete(key);
      return { ok: false, error: "not banned" };
    }
    this.banned.delete(key);
    return { ok: true, record, persisted: this.save() };
  }

  // Действующий бан на этого игрока, или null.
  //
  // Адрес проверяется первым: он же и снимается первым в списке, и в логе
  // полезнее видеть именно его. Заодно это чистит истёкшие записи по пути, так
  // что отдельный проход по списку не нужен.
  //
  // SteamID (1.4.0) - вторым: его прислал сам клиент (см. KIND), и клиент без
  // SteamID его просто не проходит.
  banFor(name, address, steamId) {
    return (
      this.lookupBan(KIND.ADDRESS, address) ||
      (steamId ? this.lookupBan(KIND.STEAMID, steamId) : null) ||
      this.lookupBan(KIND.NAME, name)
    );
  }

  // Запрет на спрей, или null. Намеренно не входит в banFor: этот запрет не
  // снимает человека с сервера.
  sprayBanFor(name) {
    return this.lookupBan(KIND.SPRAY, name);
  }

  maySpray(name) {
    return this.sprayBanFor(name) === null;
  }

  lookupBan(kind, value) {
    const key = this.keyFor(kind, value);
    if (key === null) return null;
    const record = this.banned.get(key);
    if (!record) return null;
    if (this.expired(record)) {
      this.banned.delete(key);
      return null;
    }
    return record;
  }

  // Действующие баны, в порядке добавления. Истёкшие выбрасываются здесь же.
  bans() {
    const out = [];
    for (const [key, record] of Array.from(this.banned)) {
      if (this.expired(record)) this.banned.delete(key);
      else out.push(record);
    }
    return out;
  }

  // Срок записи словами: либо "permanent", либо сколько осталось.
  term(record) {
    return record.until > 0 ? `expires in ${formatDuration(record.until - this.now())}` : "permanent";
  }

  // Текст, который увидит забаненный. packets.js обрежет по буферу клиента.
  banNotice(record) {
    const left = this.term(record);
    return record.reason ? `Banned: ${record.reason} (${left})` : `Banned (${left}).`;
  }

  // -------------------------------------------------------------------------
  // Whitelist
  // -------------------------------------------------------------------------

  setWhitelist(on) {
    this.whitelistEnabled = !!on;
    return { ok: true, enabled: this.whitelistEnabled, empty: this.allowed.size === 0, persisted: this.save() };
  }

  whitelistAdd(kind, value, options) {
    const record = this.makeRecord(kind, value, options);
    if (!record) {
      return { ok: false, error: invalidValue(kind) };
    }
    if (!this.allowed.has(record.key) && this.allowed.size >= MAX_ENTRIES) {
      return { ok: false, error: `the whitelist is full (${MAX_ENTRIES} entries)` };
    }
    this.allowed.set(record.key, record);
    return { ok: true, record, persisted: this.save() };
  }

  whitelistRemove(kind, value) {
    const key = this.keyFor(kind, value);
    if (key === null) return { ok: false, error: invalidValue(kind) };
    const record = this.allowed.get(key);
    if (!record) return { ok: false, error: "not on the whitelist" };
    this.allowed.delete(key);
    return { ok: true, record, persisted: this.save() };
  }

  whitelist() {
    return Array.from(this.allowed.values());
  }

  // Выключенный whitelist пускает всех - в том числе и потому, что включённый и
  // пустой не пускает никого, и это должно быть заметным решением оператора, а
  // не побочным эффектом первой же команды.
  isAllowed(name, address, steamId) {
    if (!this.whitelistEnabled) return true;
    const byName = this.keyFor(KIND.NAME, name);
    if (byName !== null && this.allowed.has(byName)) return true;
    const bySteam = steamId ? this.keyFor(KIND.STEAMID, steamId) : null;
    if (bySteam !== null && this.allowed.has(bySteam)) return true;
    const byAddress = this.keyFor(KIND.ADDRESS, address);
    return byAddress !== null && this.allowed.has(byAddress);
  }

  // -------------------------------------------------------------------------
  // OP
  // -------------------------------------------------------------------------

  // Только по нику: address:port живёт до первого переподключения, а адрес без
  // порта - это весь NAT целиком. Слабость ника описана в шапке файла, в help и
  // в README; здесь она не лечится, здесь она названа.
  grantOp(name, options) {
    const record = this.makeRecord(KIND.NAME, name, options);
    if (!record) return { ok: false, error: "not a usable nickname" };
    if (!this.operators.has(record.key) && this.operators.size >= MAX_ENTRIES) {
      return { ok: false, error: `the operator list is full (${MAX_ENTRIES} entries)` };
    }
    this.operators.set(record.key, record);
    return { ok: true, record, persisted: this.save() };
  }

  revokeOp(name) {
    const key = this.keyFor(KIND.NAME, name);
    if (key === null) return { ok: false, error: "not a usable nickname" };
    const record = this.operators.get(key);
    if (!record) return { ok: false, error: "not an operator" };
    this.operators.delete(key);
    return { ok: true, record, persisted: this.save() };
  }

  isOp(name) {
    const key = this.keyFor(KIND.NAME, name);
    return key !== null && this.operators.has(key);
  }

  // OP по SteamID (1.4.0). В отличие от OP по нику запись САМА выдаёт права:
  // сессия с этим SteamID одобряется, когда подтверждает себя как v2
  // (server.applySteamOp), без консоли. Слабость названа в шапке файла: SteamID
  // присылает клиент. Поэтому к записи прилагается PIN (хэшем, см. hashPin), и
  // команды из чата требуют его так же, как у `op "Nick" PIN`. Без PIN запись
  // создаётся только при OP_ALLOW_NO_PIN=1 - это решает server.grantOpSteam.
  grantOpSteam(steamId, options) {
    const opts = options || {};
    const record = this.makeRecord(KIND.STEAMID, steamId, opts);
    if (!record) return { ok: false, error: invalidValue(KIND.STEAMID) };
    if (!this.operators.has(record.key) && this.operators.size >= MAX_ENTRIES) {
      return { ok: false, error: `the operator list is full (${MAX_ENTRIES} entries)` };
    }
    record.pin = opts.pin === undefined || opts.pin === null || opts.pin === "" ? null : hashPin(opts.pin);
    this.operators.set(record.key, record);
    return { ok: true, record, persisted: this.save() };
  }

  revokeOpSteam(steamId) {
    const key = this.keyFor(KIND.STEAMID, steamId);
    if (key === null) return { ok: false, error: invalidValue(KIND.STEAMID) };
    const record = this.operators.get(key);
    if (!record) return { ok: false, error: "not an operator" };
    this.operators.delete(key);
    return { ok: true, record, persisted: this.save() };
  }

  // Запись OP для этого SteamID, или null.
  opForSteam(steamId) {
    if (!steamId) return null;
    const key = this.keyFor(KIND.STEAMID, steamId);
    return key === null ? null : this.operators.get(key) || null;
  }

  // Совпадает ли pin с хэшем записи. Запись без PIN не принимает никакой.
  checkPin(record, pin) {
    const match = record && typeof record.pin === "string" ? PIN_FORMAT.exec(record.pin) : null;
    if (!match || typeof pin !== "string" || pin.length === 0 || pin.length > 64) return false;
    const want = Buffer.from(match[2], "hex");
    const got = crypto.scryptSync(pin, Buffer.from(match[1], "hex"), want.length, PIN_SCRYPT);
    return crypto.timingSafeEqual(want, got);
  }

  ops() {
    return Array.from(this.operators.values());
  }

  // -------------------------------------------------------------------------
  // Файл
  // -------------------------------------------------------------------------

  toJSON() {
    const strip = (record) =>
      Object.assign(
        {
          kind: record.kind,
          value: record.value,
          reason: record.reason,
          until: record.until,
          addedAt: record.addedAt,
          addedBy: record.addedBy,
        },
        // Only a SteamID operator has one, and only as its salted hash.
        record.pin ? { pin: record.pin } : {}
      );
    return {
      version: FORMAT_VERSION,
      whitelistEnabled: this.whitelistEnabled,
      // Истёкшее не сохраняем: файл иначе растёт от каждого получасового бана.
      bans: this.bans().map(strip),
      whitelist: this.whitelist().map(strip),
      ops: this.ops().map(strip),
    };
  }

  // Атомарная запись: временный файл рядом, fsync, переименование поверх.
  //
  // Переименование - единственный шаг, который видит остальной мир, и оно либо
  // случилось целиком, либо не случилось: при обрыве питания посреди
  // writeFileSync прямо в access.json остался бы обрезанный JSON, а обрезанный
  // JSON здесь означает сервер, который отказывается стартовать.
  //
  // Ошибка записи НЕ роняет сервер и не откатывает список: бан уже применён в
  // памяти, и потерять его прямо сейчас хуже, чем потерять при перезапуске.
  save() {
    if (!this.file) return true;
    // L1: the file holds banned and whitelisted player IPs and nicknames, so it
    // is created 0600 (owner only) rather than inheriting 0644 from the umask,
    // and the temporary is opened "wx" (O_EXCL) under a RANDOM name. A fixed
    // ".tmp" opened without O_EXCL meant that, in a directory another account
    // could write, a planted symlink would be followed and the service would
    // overwrite the link's target as itself. A random "wx" name cannot be
    // pre-created to point anywhere.
    const temporary = `${this.file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
      const payload = `${JSON.stringify(this.toJSON(), null, 2)}\n`;
      const fd = fs.openSync(temporary, "wx", 0o600);
      try {
        fs.writeFileSync(fd, payload);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(temporary, this.file);
      // Durability of the rename itself: without a directory fsync the rename
      // can still be lost in a power cut even though the data was fsync'd. Best
      // effort - a directory fd cannot be fsync'd on every platform (Windows) -
      // and that must not turn a successful save into a reported failure.
      try {
        const dir = fs.openSync(path.dirname(path.resolve(this.file)), "r");
        try {
          fs.fsyncSync(dir);
        } finally {
          fs.closeSync(dir);
        }
      } catch (ignored) {
        // Directory fsync unsupported here; the data fsync above still holds.
      }
      this.lastSaveError = null;
      return true;
    } catch (error) {
      this.lastSaveError = error.message;
      if (this.log) this.log.error("could not write the access file %s: %s", this.file, error.message);
      try {
        fs.unlinkSync(temporary);
      } catch (ignored) {
        // Хвост от неудачной записи; имя случайное, так что следующая попытка
        // не споткнётся о него.
      }
      return false;
    }
  }

  // Бросает AccessError на всём, чего не понимает.
  //
  // Молча продолжить с пустым списком нельзя: оператор увидит работающий сервер
  // и решит, что баны на месте, а забаненные в это время зайдут. Отказ на
  // старте - это тот же принцип, по которому config.js отказывается стартовать
  // с непонятой переменной.
  load() {
    if (!this.file) return false;
    let raw;
    try {
      raw = fs.readFileSync(this.file, "utf8");
    } catch (error) {
      // Файла ещё нет - первого бана просто не было.
      if (error.code === "ENOENT") return false;
      throw new AccessError(`${this.file}: ${error.message}`);
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch (error) {
      throw new AccessError(
        `${this.file}: not valid JSON (${error.message}). Move the file aside to start with empty lists.`
      );
    }
    this.fromJSON(data);
    return true;
  }

  fromJSON(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new AccessError(`${this.file}: expected a JSON object`);
    }
    if (data.version !== FORMAT_VERSION) {
      throw new AccessError(
        `${this.file}: format version ${JSON.stringify(data.version)}, expected ${FORMAT_VERSION}`
      );
    }
    if (typeof data.whitelistEnabled !== "boolean") {
      throw new AccessError(`${this.file}: "whitelistEnabled" must be true or false`);
    }

    const read = (field, kinds) => {
      const rows = data[field];
      if (!Array.isArray(rows)) throw new AccessError(`${this.file}: "${field}" must be an array`);
      if (rows.length > MAX_ENTRIES) {
        throw new AccessError(`${this.file}: "${field}" has ${rows.length} entries, the limit is ${MAX_ENTRIES}`);
      }
      const out = new Map();
      for (const row of rows) {
        if (!row || typeof row !== "object" || !kinds.includes(row.kind)) {
          throw new AccessError(`${this.file}: "${field}" has an entry with an unknown kind`);
        }
        // Ключ ПЕРЕСЧИТЫВАЕТСЯ, а не читается из файла. Файл правят руками, и
        // запись, у которой ключ разошёлся со значением, - это бан, которого не
        // видно в списке и который нечем снять.
        const record = this.makeRecord(row.kind, row.value, {
          reason: typeof row.reason === "string" ? row.reason : "",
          until: typeof row.until === "number" ? row.until : 0,
          addedBy: typeof row.addedBy === "string" ? row.addedBy : "console",
        });
        if (!record && row.kind === KIND.ADDRESS) {
          // Minor 4 (review 1): an older build accepted IPv6 and other non-IPv4
          // address entries, which never matched the udp4 socket (L6). Refusing
          // the whole file would keep an upgraded server down (exit 78); the row
          // is dropped with a warning instead, and leaves the file on next save.
          if (this.log) {
            this.log.warn(
              "%s: dropped %s entry %s - not an IPv4 address, so it could never match a client",
              this.file || "access list",
              field,
              String(row.value)
            );
          }
          continue;
        }
        if (!record) {
          throw new AccessError(`${this.file}: "${field}" has an entry whose value is not a usable ${row.kind}`);
        }
        if (typeof row.addedAt === "number" && Number.isFinite(row.addedAt)) record.addedAt = Math.floor(row.addedAt);
        // A SteamID operator's PIN hash; anything that is not one is no PIN
        // (and such an operator is not approved unless OP_ALLOW_NO_PIN=1).
        if (field === "ops" && row.kind === KIND.STEAMID) {
          record.pin = typeof row.pin === "string" && PIN_FORMAT.test(row.pin) ? row.pin : null;
        }
        if (this.expired(record)) continue;
        out.set(record.key, record);
      }
      return out;
    };

    const bans = read("bans", [KIND.NAME, KIND.ADDRESS, KIND.SPRAY, KIND.STEAMID]);
    const allowed = read("whitelist", [KIND.NAME, KIND.ADDRESS, KIND.STEAMID]);
    // OP по нику (grantOp) и по SteamID (grantOpSteam). Сборка до 1.4.0
    // откажется загружать файл с записью steamid ("unknown kind") - так и
    // задумано: молча потерянный бан хуже остановленного старта.
    const operators = read("ops", [KIND.NAME, KIND.STEAMID]);

    this.banned = bans;
    this.allowed = allowed;
    this.operators = operators;
    this.whitelistEnabled = data.whitelistEnabled;
  }
}

module.exports = {
  AccessList,
  AccessError,
  KIND,
  parseDuration,
  formatDuration,
  normalizeSteamId,
  MAX_ENTRIES,
  MAX_REASON_BYTES,
};
