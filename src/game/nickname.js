"use strict";

// Nicknames: display name in, canonical key out.
//
// This is *active collision protection*, not authentication. There is no
// account, no password and no permanent ownership: the protocol carries a
// nickname and nothing else, so all the server can do is refuse to have two
// people wearing the same one at the same time. See identity.js for what the
// source address is and is not evidence of.
//
// The problem this closes: the roster used to be keyed by the nickname exactly
// as it arrived, so "Aperture", "aperture" and "APERTURE" were three separate
// players. In a chat window they are indistinguishable, which makes
// impersonating whoever is already on the server a matter of holding shift.
//
// Two strings therefore map to one key when they differ only in
//
//   - control bytes (already removed by the wire sanitiser),
//   - characters that carry no glyph (soft hyphen, zero-width marks),
//   - leading or trailing whitespace,
//   - letter case.
//
// Nothing else. In particular there is no transliteration and no stripping of
// accents or punctuation: "Renee" and "Renée" are different people, "A.B" and
// "AB" are different people, and merging them would be a denial of service
// dressed up as a security feature. The one deliberate exception is the
// reserved-name test, which does strip punctuation, because "S-E-R-V-E-R" is
// not a person's name, it is an attempt to look like the host.

const { isUtf8 } = require("node:buffer");

const { sanitizeText, truncateBytes } = require("../wire/text");

// The wire is bytes, and reader.js hands them over as latin1: one JavaScript
// character per byte. Those bytes are UTF-8 (see wire/text.js), so everything
// below that reasons about CHARACTERS - case folding, invisible marks,
// trimming - decodes first and encodes back at the end. Doing any of it on the
// latin1 form edits halves of letters: the soft-hyphen test alone matched the
// second byte of U+00AD's UTF-8 form (C2 AD) and left the C2 dangling.
//
// Bytes that are not valid UTF-8 keep the old latin1 treatment rather than
// being mangled by a decode that does not apply to them.
const decode = (value) => {
  const bytes = Buffer.from(value, "latin1");
  return isUtf8(bytes) ? bytes.toString("utf8") : value;
};

const encode = (text, wasUtf8) => (wasUtf8 ? Buffer.from(text, "utf8").toString("latin1") : text);

const looksUtf8 = (value) => isUtf8(Buffer.from(value, "latin1"));

// Case folding, one code point to one code point.
//
// String.prototype.toUpperCase() is applied per character and only kept when it
// stays the same length. It is Unicode-aware, which sounds better than it is:
// "ß" upper-cases to two characters, so "Straße" and "Strasse" would become the
// same key and one player would lock the other out of a name they have every
// right to. Length-preserving folding keeps the mapping predictable, and it now
// covers Cyrillic - which the previous latin1-only table did not, so "Прolert"
// and "прolert" were two roster entries that look alike at a glance.
const NO_BREAK_SPACE = " ";

const foldText = (text, wasUtf8) => {
  let out = "";
  for (const character of text) {
    // A no-break space is a space. It is not invisible - it has a glyph, the
    // same one an ordinary space has - so it cannot simply be dropped the way
    // the soft hyphen is; it has to become the character it looks like.
    // Without this, "Bob Smith" and "Bob Smith" are two roster entries
    // that render identically, which is the whole impersonation class this
    // file exists to close.
    if (character === NO_BREAK_SPACE) {
      out += " ";
      continue;
    }

    const upper = character.toUpperCase();
    let folded = upper.length === character.length ? upper : character;

    // Bytes that are not UTF-8 stay bytes. "ÿ" upper-cases to U+0178, which
    // does not fit in one, and a key holding it would no longer be the same
    // shape as the string it was made from.
    if (!wasUtf8 && folded.charCodeAt(0) > 0xff) folded = character;

    out += folded;
  }
  return out;
};

const fold = (value) => {
  const utf8 = looksUtf8(value);
  return encode(foldText(decode(value), utf8), utf8);
};

// Characters that carry no glyph and must not create a "different" nickname.
// A name built as "­" + "SERVER" prints as "SERVER" and passed a plain
// equality test against it.
//
// The list is longer than the soft hyphen alone because it has to be: while
// strings were treated as latin1 the soft hyphen was the only invisible
// character that fit in one byte, and the zero-width marks were unreachable.
// They are two and three bytes of UTF-8, and UTF-8 is what the wire actually
// carries, so they were reachable all along - just not to this function.
const INVISIBLE = new Set([
  "­", // soft hyphen
  "​", // zero width space
  "‌", // zero width non-joiner
  "‍", // zero width joiner
  "⁠", // word joiner
  "﻿", // zero width no-break space
]);

// Characters that carry no glyph OR reorder the ones around them, by code point
// (M5). Bidi controls (U+200E/200F, U+202A-202E, U+2066-2069) let a name render
// in a different order than its bytes - "SERVER" wearing an RLO looks like the
// host - and the rest are invisibles that create a "different" nickname without
// changing what anyone sees (Hangul fillers, variation selectors, tag
// characters, combining grapheme joiner, the invisible maths operators).
const isStrippable = (code) =>
  code === 0x200e ||
  code === 0x200f ||
  (code >= 0x202a && code <= 0x202e) ||
  (code >= 0x2066 && code <= 0x2069) ||
  (code >= 0x2061 && code <= 0x2064) ||
  code === 0x034f ||
  code === 0x115f ||
  code === 0x1160 ||
  code === 0x3164 ||
  (code >= 0xfe00 && code <= 0xfe0f) ||
  (code >= 0xe0000 && code <= 0xe007f);

const removeInvisible = (value) => {
  const utf8 = looksUtf8(value);
  let out = "";
  for (const character of decode(value)) {
    if (INVISIBLE.has(character)) continue;
    if (isStrippable(character.codePointAt(0))) continue;
    out += character;
  }
  return encode(out, utf8);
};

// Leading and trailing whitespace, ASCII only.
//
// String.prototype.trim() is Unicode-aware and would be the obvious choice, but
// it is applied here to a latin1 byte string: byte 0xA0 is whitespace to trim()
// and a UTF-8 continuation byte to everybody else. A nickname ending in "Р"
// (U+0420, D0 A0) would lose its last byte and arrive as a dangling D0.
const trimAscii = (value) => value.replace(/^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g, "");

// Names the host uses for itself. Chat from the server is rendered in red under
// this name, so a player wearing it can put words in the host's mouth.
const RESERVED = new Set(["SERVER"]);

// Confusable letters that read as Latin A-Z but are not (M5). "SЕRVЕR" with
// Cyrillic Ye, "ЅERVER" with Dze, "SΕRVER" with Greek Epsilon all look exactly
// like the host's name; mapped to their Latin skeleton they are caught. The
// lists are the ones the audit names (Cyrillic and Greek capitals that share a
// glyph with a Latin capital); NFKC above already folds fullwidth and other
// compatibility forms, and toUpperCase folds case (and ß -> SS).
const CONFUSABLES = new Map([
  // Cyrillic
  ["А", "A"], ["В", "B"], ["Е", "E"], ["К", "K"], ["М", "M"], ["Н", "H"],
  ["О", "O"], ["Р", "P"], ["С", "C"], ["Т", "T"], ["Х", "X"], ["Ѕ", "S"],
  ["І", "I"], ["Ј", "J"], ["Ү", "Y"],
  // Greek
  ["Α", "A"], ["Β", "B"], ["Ε", "E"], ["Ζ", "Z"], ["Η", "H"], ["Ι", "I"],
  ["Κ", "K"], ["Μ", "M"], ["Ν", "N"], ["Ο", "O"], ["Ρ", "P"], ["Τ", "T"],
  ["Υ", "Y"], ["Χ", "X"],
  // Cherokee capitals that read as S, E, R, V (review 1, minor 5)
  ["\u13DA", "S"], ["\u13AC", "E"], ["\u13D2", "R"], ["\u13D9", "V"],
  // Latin small capitals (NFKD leaves them alone; ʀ upper-cases to Ʀ)
  ["\uA731", "S"], ["\u1D07", "E"], ["\u0280", "R"], ["\u01A6", "R"], ["\u1D20", "V"],
]);

// Reserved names are compared on a confusable SKELETON, not on the bytes: NFKD
// (fullwidth -> ASCII and every accented letter split into base + mark), the
// combining marks removed, upper case, Cyrillic/Greek/Cherokee/small-capital
// lookalikes mapped to Latin, then only letters and digits kept. NFKC (the first
// version) recomposed "E + dot below" into one letter that was then dropped, so
// "SẸRVẸR" became "SRVR" and passed (review 1, minor 5). That is a coarser
// comparison than the canonical key on purpose - it is not deciding who owns a
// name, it is refusing a small fixed set of impersonations of the host.
const COMBINING_MARK = /\p{M}/gu;
const reservedForm = (value) => {
  const decoded = decode(value).normalize("NFKD").replace(COMBINING_MARK, "").toUpperCase();
  let out = "";
  for (const character of decoded) {
    const mapped = CONFUSABLES.get(character) || character;
    for (let i = 0; i < mapped.length; i += 1) {
      const code = mapped.charCodeAt(i);
      if ((code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a)) out += mapped[i];
    }
  }
  return out;
};

const REASON = {
  OK: null,
  EMPTY: "empty",
  RESERVED: "reserved",
};

// The one function everything else goes through.
//
// `maxLength` is the DLL-compatible limit (31 by default, see config.js), and
// it counts BYTES, because on the other end it is the size of a char[] in the
// compiled client. The display name is truncated to it exactly as the old
// server did, so a player with a long gh_name gets a short name rather than a
// dropped packet - but on a character boundary, so a Russian nickname is not
// cut through the middle of a letter.
//
// The key is derived from the truncated display name, so what the roster shows
// and what the roster is keyed by can never disagree. They did once, and the
// consequence was ugly: the key came from a truncated display name while
// nicknameKey did not truncate at all, so with NAME_MAX_LENGTH=28 - the setting
// config.js itself recommends as a workaround for the HUD defect - a player
// with a 31 character gh_name was registered under a 28 character key, and then
// every packet they sent carried the full 31 characters, folded to a key that
// matched nothing. They were accepted, never authorised again, and swept twenty
// seconds later.
const displayForm = (raw, limit) => {
  let display = trimAscii(removeInvisible(sanitizeText(typeof raw === "string" ? raw : "")));
  if (display.length > limit) display = trimAscii(truncateBytes(display, limit));
  return display;
};

const clamp = (maxLength) => (typeof maxLength === "number" && maxLength > 0 ? maxLength : 31);

const canonicalizeNickname = (raw, maxLength) => {
  const display = displayForm(raw, clamp(maxLength));
  if (display.length === 0) return { ok: false, reason: REASON.EMPTY, display: "", key: "" };

  const key = fold(display);
  if (RESERVED.has(reservedForm(key))) {
    return { ok: false, reason: REASON.RESERVED, display, key };
  }

  return { ok: true, reason: REASON.OK, display, key };
};

// Key for a name that arrived in an in-session packet, or for a roster entry.
// Same pipeline as canonicalizeNickname, including the truncation, and no
// validation: the caller is asking "who is this", not "may this join".
const nicknameKey = (name, maxLength) => fold(displayForm(name, clamp(maxLength)));

module.exports = { canonicalizeNickname, nicknameKey, REASON, RESERVED };
