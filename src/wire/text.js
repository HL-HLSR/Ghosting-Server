"use strict";

// Text coming off the wire is attacker controlled and ends up in three places:
// the operator's terminal, other players' chat, and the server's own log file.
// Each has a different escaping problem, so each gets its own function.
//
// The wire is bytes, and reader.js hands them over as latin1, one character per
// byte. What those bytes MEAN is UTF-8: the mod converts the chat entry with
// ConvertUnicodeToANSI, which in Source 2013 is WideCharToMultiByte(CP_UTF8),
// and renders incoming text with the matching ConvertANSIToUnicode. So a string
// here is a UTF-8 byte sequence wearing a latin1 costume, and anything that
// edits it byte by byte is editing halves of characters.

const { isUtf8 } = require("node:buffer");

// A byte that must never survive into text handed to another player's client.
//
// C0 (0x00-0x1F) and DEL (0x7F): the chat renderer in client.dll reads bytes
// 1-8 as colour codes, and only the ones the mod puts in the format string may
// be there.
//
// C1 (0x80-0x9F) is deliberately NOT here, and that is the whole fix. Those
// bytes are continuation bytes of multi-byte UTF-8 characters: 'р' is D1 80,
// 'с' is D1 81, and so on for every Cyrillic letter from р to я. Treating them
// as control codes replaced the second half of half the alphabet with a space
// and left the lead byte dangling, which is exactly what players saw:
// "привет" arrived as "п? иве?".
//
// The reason C1 was stripped in the first place stands, but it belongs to a
// different audience: byte 0x9B is CSI, the single-byte escape introducer, and
// a terminal would act on it. Nothing relayed here reaches a terminal without
// going through sanitizeForLog below, which escapes it.
const isGameControlCode = (code) => code < 0x20 || code === 0x7f;

// Everything the terminal must not act on: C0, DEL and C1.
const isControlCode = (code) => code < 0x20 || (code >= 0x7f && code <= 0x9f);

// Characters that are not control codes but still reorder or rewrite a log line
// (L2): the bidi marks, overrides and isolates, the Unicode line/paragraph
// separators, and a BOM/zero-width no-break space. Escaped rather than printed.
const isLineReorderingCode = (code) =>
  code === 0x200e ||
  code === 0x200f ||
  (code >= 0x202a && code <= 0x202e) ||
  (code >= 0x2066 && code <= 0x2069) ||
  code === 0x2028 ||
  code === 0x2029 ||
  code === 0xfeff;

const replaceControl = (value, replacement) => {
  const text = String(value == null ? "" : value);
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    out += isGameControlCode(text.charCodeAt(i)) ? replacement : text[i];
  }
  return out;
};

// Player facing text: control bytes removed entirely.
const sanitizeText = (value) => replaceControl(value, "");

// Chat: control bytes become spaces so words don't get glued together, then the
// line is collapsed and trimmed.
//
// The collapse only touches ASCII whitespace. \s in a JavaScript regular
// expression also matches U+00A0 and other Unicode spaces, and on a latin1
// string those are single bytes that appear inside UTF-8 sequences: A0 is a
// continuation byte, so /\s+/ would eat the tail of 'р' (D1 80) reading the A0
// of an unrelated character. Spelled out as the five ASCII whitespace bytes,
// none of which can occur inside a UTF-8 sequence.
// Bidi controls (M5): they reorder the glyphs around them, so a chat line can
// be made to read back to front or to impersonate "SERVER:". They are multi-byte
// UTF-8, so they are removed on the decoded string and re-encoded to the latin1
// costume the rest of the pipeline expects; bytes that are not valid UTF-8 are
// left as they were rather than mangled by a decode that does not apply.
const BIDI = /[‎‏‪-‮⁦-⁩]/g;
const stripBidi = (value) => {
  const text = String(value == null ? "" : value);
  const bytes = Buffer.from(text, "latin1");
  if (!isUtf8(bytes)) return text;
  return Buffer.from(bytes.toString("utf8").replace(BIDI, ""), "utf8").toString("latin1");
};

const sanitizeChat = (value) =>
  stripBidi(replaceControl(value, " "))
    .replace(/[ \t\n\r\f\v]+/g, " ")
    .replace(/^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g, "");

// Anything printed to the console or a log file.
//
// The old server logged the raw opcode string of an unknown packet
// (`console.log("Unknown opcode '%s'", opcode)`), and the opcode is up to a
// kilobyte of attacker chosen bytes, so a probe could write escape sequences
// straight into the operator's terminal: reposition the cursor, hide earlier
// lines, or in some terminals set the window title. Everything printable is
// kept; everything else becomes a visible \xNN so the operator can still see
// what was sent.
//
// This is the one place C1 still has to go, and the one place it can go without
// breaking anybody: the operator's terminal is not a game client.
//
// Text that is valid UTF-8 is decoded first, so a Russian nickname appears in
// the log as itself rather than as a row of \xNN. Anything that is not valid
// UTF-8 keeps the old byte-wise treatment.
const sanitizeForLog = (value, maxLength = 64) => {
  let text = String(value == null ? "" : value);

  const bytes = Buffer.from(text, "latin1");
  if (isUtf8(bytes)) text = bytes.toString("utf8");

  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    // L2: C0/C1 (a terminal acts on 0x9B CSI), plus the characters that reorder
    // or rewrite a terminal line without being control codes - bidi overrides
    // and isolates, the LRM/RLM marks, the Unicode line/paragraph separators,
    // and a leading BOM/ZWNBSP. Escaped to a visible \uNNNN so the operator sees
    // exactly what was sent.
    if (isControlCode(code) || isLineReorderingCode(code)) {
      out += (code <= 0xff ? "\\x" + code.toString(16).padStart(2, "0") : "\\u" + code.toString(16).padStart(4, "0"));
    } else {
      out += text[i];
    }
    if (out.length >= maxLength) return out.slice(0, maxLength) + "...";
  }
  return out;
};

// Cut a latin1 byte string to at most maxBytes WITHOUT splitting a character.
//
// Every length limit in the protocol counts bytes, because on the other end it
// is the size of a char[] in the compiled client. Cutting to that count with
// slice() lands in the middle of a multi-byte character often enough to be the
// normal case for a Russian nickname, and the client then draws a broken
// character at the end of the string.
//
// Bytes that are not valid UTF-8 are cut as bytes, exactly as before: a client
// sending some other 8-bit encoding must not have its last letters trimmed off
// on the guess that they were a character boundary.
const truncateBytes = (value, maxBytes) => {
  const text = String(value == null ? "" : value);
  if (text.length <= maxBytes) return text;

  const bytes = Buffer.from(text, "latin1");
  if (!isUtf8(bytes)) return text.slice(0, maxBytes);

  // Step back to the nearest character boundary. A prefix of valid UTF-8 is
  // itself valid exactly at a boundary, and a character is at most four bytes,
  // so this gives up after three steps.
  let end = maxBytes;
  while (end > 0 && !isUtf8(bytes.subarray(0, end))) end -= 1;
  return text.slice(0, end);
};

// Reject non-finite (NaN/Infinity) and absurd magnitudes before storing and
// rebroadcasting them: a NaN position puts another player's ghost nowhere and
// the client renders it there.
const isSaneNumber = (value, max) => Number.isFinite(value) && Math.abs(value) < max;

// Разбор командной строки на токены: кавычки склеивают ник с пробелом в один
// аргумент, всё остальное режется по пробелам.
//
// Используется с двух сторон - консолью оператора и командами из чата - и
// поэтому написан под чат, где строка это latin1-костюм на UTF-8 байтах.
// Отсюда `[^ \t]` вместо `\S`: \S в JavaScript знает про Unicode-пробелы, а
// U+00A0 в этой строке - одиночный байт A0, то есть хвост кириллической буквы.
// Ник "Пётр" разошёлся бы по такому "пробелу" пополам. Пробел и табуляция -
// ASCII, внутри UTF-8 последовательности не встречаются, резать по ним
// безопасно.
//
// Квантификаторы не вложены и альтернативы не перекрываются, так что длинная
// строка из чата стоит один проход, а не экспоненту.
const COMMAND_TOKEN = /"([^"]*)"|([^ \t]+)/g;

const tokenizeCommand = (line, maxTokens = 16) => {
  const text = String(line == null ? "" : line);
  const out = [];
  COMMAND_TOKEN.lastIndex = 0;
  let match = COMMAND_TOKEN.exec(text);
  while (match !== null && out.length < maxTokens) {
    out.push(match[1] !== undefined ? match[1] : match[2]);
    match = COMMAND_TOKEN.exec(text);
  }
  return out;
};

module.exports = {
  sanitizeText,
  sanitizeChat,
  sanitizeForLog,
  truncateBytes,
  tokenizeCommand,
  isSaneNumber,
  isControlCode,
  isGameControlCode,
};
