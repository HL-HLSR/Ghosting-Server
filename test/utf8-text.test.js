"use strict";

// Russian text on the wire.
//
// The wire carries bytes and the reader hands them over as latin1, one
// character per byte. Those bytes are UTF-8: the mod converts the chat entry
// with ConvertUnicodeToANSI, which in Source 2013 is
// WideCharToMultiByte(CP_UTF8). Anything on this side that edits the string
// byte by byte is editing halves of letters.
//
// The symptom that started this: the sanitiser treated C1 (0x80-0x9F) as
// control bytes, which is right for a terminal and wrong for UTF-8, where those
// are continuation bytes. Every Cyrillic letter from р to я has its second byte
// in that range, so "привет" arrived as "п? иве?" - the first half of the
// alphabet intact, the second half beheaded.

const test = require("node:test");
const assert = require("node:assert");

const { sanitizeChat, sanitizeText, sanitizeForLog, truncateBytes } = require("../src/wire/text");
const { BufferWriter } = require("../src/wire/writer");
const { canonicalizeNickname, nicknameKey } = require("../src/game/nickname");
const packets = require("../src/wire/packets");
const limits = require("../src/wire/limits");
const { makeServer, connect, update, chat, from } = require("./helpers/harness");

// How a string looks after the mod encodes it: UTF-8 bytes read back as latin1.
const wire = (text) => Buffer.from(text, "utf8").toString("latin1");
const readable = (value) => Buffer.from(value, "latin1").toString("utf8");

// Text of the last chat packet (type 6) the socket sent.
const lastChatText = (socket) => {
  for (let i = socket.sent.length - 1; i >= 0; i -= 1) {
    const buffer = socket.sent[i].buffer;
    if (buffer.readUInt8(0) !== 6) continue;
    let at = 5; // type + id
    const nameLength = buffer.readUInt32BE(at);
    at += 4 + nameLength;
    const textLength = buffer.readUInt32BE(at);
    at += 4;
    return buffer.toString("latin1", at, at + textLength);
  }
  return null;
};

// --- the letters themselves ---

test("каждая буква русского алфавита переживает санитайзер", () => {
  const alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя" + "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

  assert.strictEqual(readable(sanitizeChat(wire(alphabet))), alphabet);
  assert.strictEqual(readable(sanitizeText(wire(alphabet))), alphabet);
});

test("привет остаётся приветом, а не «п? иве?»", () => {
  assert.strictEqual(readable(sanitizeChat(wire("привет"))), "привет");
});

test("управляющие байты по-прежнему вырезаются", () => {
  // Байты 1-8 клиентский рендер чата читает как коды цвета: пропустить их
  // значит отдать игроку раскраску чужих сообщений.
  // Байт 0x03 - код цвета, 0x01 - переход к обычному цвету, 0x7F - DEL.
  const attack =
    String.fromCharCode(0x03) + wire("х красный") + String.fromCharCode(0x01, 0x7f);

  assert.strictEqual(readable(sanitizeChat(attack)), "х красный");
  assert.strictEqual(readable(sanitizeText(attack)), "х красный");
});

test("схлопывание пробелов не трогает байты внутри букв", () => {
  // \s в регулярном выражении покрывает U+00A0, а байт A0 - это вторая
  // половина буквы «Р» (U+0420 = D0 A0). Схлопывание по \s съедало её.
  const text = "Работа  Р";
  assert.strictEqual(readable(sanitizeChat(wire(text))), "Работа Р");
});

// --- обрезка по длине ---

test("обрезка по байтам не рубит букву пополам", () => {
  const long = wire("привет".repeat(10));

  for (let limit = 1; limit <= 24; limit += 1) {
    const cut = truncateBytes(long, limit);
    assert.ok(cut.length <= limit, `обрезка до ${limit} дала ${cut.length} байт`);
    assert.ok(
      Buffer.from(cut, "latin1").toString("utf8").indexOf("�") === -1,
      `обрезка до ${limit} байт оставила половину буквы`
    );
  }
});

test("байты, не являющиеся UTF-8, режутся как байты", () => {
  // Клиент в другой однобайтовой кодировке не должен терять последние буквы
  // из-за догадки о границе символа.
  const cp1251 = String.fromCharCode(0xef, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2);
  assert.strictEqual(truncateBytes(cp1251, 4).length, 4);
});

test("длинный ник в пакете обрезается по границе буквы", () => {
  const name = "Аперчурасайенс".repeat(4); // заведомо длиннее 31 байта
  const buffer = packets.disconnect(wire(name), "left");

  const length = buffer.readUInt32BE(1);
  const sent = buffer.toString("latin1", 5, 5 + length);

  assert.ok(length <= limits.MAX_NAME_LENGTH);
  assert.ok(readable(sent).indexOf("�") === -1, "в имени приехала половина буквы");
});

test("writeString без ограничения ничего не трогает", () => {
  const text = wire("тест");
  const buffer = new BufferWriter().writeString(text).buffer;
  assert.strictEqual(buffer.readUInt32BE(0), text.length);
});

// --- ники ---

test("русский ник принимается и не теряет букв", () => {
  const result = canonicalizeNickname(wire("Пролерт"));
  assert.strictEqual(result.ok, true);
  assert.strictEqual(readable(result.display), "Пролерт");
});

test("русский ник складывается по регистру, как и латинский", () => {
  // Прежняя таблица знала только latin1, поэтому «Пролерт» и «пролерт» были
  // двумя разными записями в списке игроков - ровно та подмена, ради которой
  // складывание регистра и существует.
  assert.strictEqual(nicknameKey(wire("Пролерт")), nicknameKey(wire("пролерт")));
  assert.strictEqual(nicknameKey(wire("ПРОЛЕРТ")), nicknameKey(wire("пролерт")));
});

test("ник, оканчивающийся на «Р», не теряет последний байт", () => {
  // U+0420 - это D0 A0, а A0 для String.prototype.trim() пробел
  const result = canonicalizeNickname(wire("МастеР"));
  assert.strictEqual(readable(result.display), "МастеР");
});

test("невидимые символы не создают второго «того же» ника", () => {
  const zeroWidth = "​";
  assert.strictEqual(nicknameKey(wire(zeroWidth + "Пролерт")), nicknameKey(wire("Пролерт")));
  assert.strictEqual(nicknameKey(wire("Про‍лерт")), nicknameKey(wire("Пролерт")));
});

test("SERVER под невидимым символом по-прежнему отклоняется", () => {
  assert.strictEqual(canonicalizeNickname(wire("​SERVER")).ok, false);
});

// --- журнал ---

test("в журнал русский текст попадает буквами, а не кодами", () => {
  assert.strictEqual(sanitizeForLog(wire("привет")), "привет");
});

test("байт CSI из не-UTF-8 мусора в журнале по-прежнему экранируется", () => {
  // Ради этого C1 когда-то и вырезали: 0x9B в терминале - введение
  // escape-последовательности. Журнал остаётся единственным местом, где это
  // важно, и он это по-прежнему делает.
  const junk = String.fromCharCode(0x9b) + "[2J";
  assert.ok(sanitizeForLog(junk).startsWith("\\x9b"));
});

// --- сквозь сервер ---

test("сообщение с русским текстом доходит до рассылки целиком", () => {
  const { server, socket } = makeServer();

  server.onDatagram(connect("Пролерт"), from("10.0.0.5", 40000));
  server.onDatagram(chat("Пролерт", wire("привет всем")), from("10.0.0.5", 40000));

  assert.strictEqual(readable(lastChatText(socket)), "привет всем");

  server.stop("test");
});

test("русский ник проходит регистрацию и рассылается целиком", () => {
  const { server, socket } = makeServer();

  // Пакет подключения рассылается ОСТАЛЬНЫМ, и только подтверждённым
  // сессиям, поэтому наблюдателю нужно сначала прислать свою позицию
  server.onDatagram(connect("Watcher"), from("10.0.0.6", 40001));
  server.onDatagram(update("Watcher"), from("10.0.0.6", 40001));
  const before = socket.sent.length;
  server.onDatagram(connect(wire("Пролерт")), from("10.0.0.7", 40002));

  const connectPacket = socket.sent
    .slice(before)
    .find((packet) => packet.buffer.readUInt8(0) === 0 && packet.port === 40001);
  assert.ok(connectPacket, "пакет подключения не отправлен");

  const length = connectPacket.buffer.readUInt32BE(1);
  assert.strictEqual(readable(connectPacket.buffer.toString("latin1", 5, 5 + length)), "Пролерт");

  server.stop("test");
});
