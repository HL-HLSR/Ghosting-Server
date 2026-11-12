# Changelog

## 1.4.0 - 2026-11-11

For the mod's main-menu "Servers" dialog (the 1.4.0 build of Ghosting Mod
Renewed). Every packet a 1.3.2 host sent is sent byte for byte as before, and
every older client is served as before.

### Server browser query

- **Opcode `i`, types 17 and 18.** A connectionless query in the shape of
  Valve's A2S challenge exchange: a bare query (or one with a wrong or stale
  challenge) gets a 9-byte type 17 challenge for its 14 bytes; only a query
  carrying the challenge this host issued to the same address:port, within 15
  to 30 s, gets the type 18 info, capped at 512 bytes. The challenge is an
  HMAC-SHA256 of address, port and time window under a per-process key, so
  nothing is stored per asker.
- **The info:** `SERVER_NAME`, the ghserver version, the protocol, host flags
  (REQUIRE_PROTOCOL_V2, whitelist, identity block, operator chat), players
  online and the slot limit, the race phase, the map most players are on, and
  up to 32 players (stopping earlier at 512 bytes) with HLSR, operator,
  spectator, runner, identified and v2 flags. Never an address or a SteamID.
- **Bounds:** the ordinary inbound checks first (global ceiling, penalty box,
  size, address and session budgets), then `INFO_RATE_PER_SECOND` /
  `INFO_BURST` per address (2 / 8) and `INFO_GLOBAL_PER_SECOND` (200) for the
  process; live-tunable as `limits info.rate|info.burst|info.global`. Over
  budget, an unknown query version and `SERVER_INFO=0` are dropped in silence,
  a stale challenge is answered with a fresh one; none is punished. A query
  creates no session.
- New settings `SERVER_NAME` (default `Ghosting server`, UTF-8, at most 63
  bytes, cleaned like chat, refused when longer), `SERVER_INFO`,
  `SERVER_INFO_PLAYERS`. `status` shows the name and the query counters; the
  startup log names the server.
- `test/tools/server-info.js` asks a live host over UDP.

### SteamID and HLSR on join

- **The identity block** after a v2 announce's C: `u8(1) u8 flags SteamID64`
  (flags: launched from HLSR, a SteamID follows). Read only after a valid v2
  tail; anything else in its place is no identity, not an error; a SteamID that
  is not a public individual account is dropped. Older hosts stop reading
  before it; a 1.3 client sends none and reads as "launcher unknown".
- The join line in the log and `list` show `HLSR` / `not HLSR` / `launcher
  unknown` and the SteamID; `status` counts them; the server browser carries
  the HLSR flag.
- **Access lists by SteamID:** `bansteam` / `unbansteam`, `whitelist addsteam`
  / `removesteam`, and `opsteam SteamID PIN` / `deopsteam`: a standing
  operator entry that approves every v2 session announcing that SteamID when
  it confirms (never a forged announce, never a legacy session), whose admin
  chat commands then need the PIN (kept as a salted scrypt hash, never
  printed; five wrong PINs revoke that session). SteamID64, `STEAM_0:Y:Z` and
  `[U:1:N]` are accepted; a connected player's `"Nick"` means the SteamID they
  announced. `ops` lists both kinds.
- **Self-reported, and the docs say so** (help, README "What a SteamID is
  worth", residual risk 16): no Steam ticket is checked, so a SteamID ban
  stops only an honest client and a SteamID operator is as strong as its PIN.
- The access file gains `steamid` records (format version unchanged). A host
  before 1.4.0 refuses to start on such a file ("unknown kind"), as it was
  built to; remove them before a downgrade.
- Two tests that pinned the old state were updated: the "unknown kind" check
  in access.test.js now uses a made-up kind (steamid is known), and the help
  test checks the new SteamID caveat instead of "no SteamID". The emote-pack
  test's list of opcodes gained `i`.
- 37 new tests (629 in all: 612 pass, 17 skipped as before, 0 fail).

## 1.3.2 - 2026-10-30

The lobby's 7TV emote pack (type 14) is back, as it was in 0.3.2, for the
2026-10-30 build of the mod, which reads it again. A host that does not set
`EMOTE_PACK` sends exactly what 1.3.1 sent.

### Emote pack

- **`EMOTE_PACK` is accepted again** with its 0.3.2 meaning and validation: a
  `7tv.app/emote-sets/<id>` or `7tv.app/users/<id>` link, a bare 7TV id (ULID
  or the old 24-digit hex ObjectID) or a numeric Twitch channel id, normalised
  to `set:`/`user:`/`twitch:`; a user link is warned about; anything else stops
  startup with a message naming the variable. New: `0` and `off` mean no pack,
  like leaving it out (neither ever named one, so no value valid in 0.3.2
  changes meaning). 1.2.0 had retired it (audit finding L9) when the
  2026-10-22 client dropped type 14.
- **Who sends it:** only the operator. No opcode carries a pack - the mod never
  had one - so a datagram can neither change it nor make the host relay one; a
  pack-shaped datagram from a v2 session's endpoint without its S is a bad
  token, and with S (or from a legacy session) an unknown opcode.
- **Who gets it:** the session that joins, and only it. Right after the accept,
  ahead of the roster (charged first against a legacy session's unconfirmed
  budget), and once more when a legacy session confirms, because the mod
  announces itself once per session. A v2 session gets it with its roster at
  its first packet with S, and a second copy with the next heartbeat, so it
  too gets two and one lost datagram cannot lose the pack for the session.
  The lobby is not sent it again when somebody joins; a refused connect gets
  only its refusal.
- **Framing:** `14 C payload` to a v2 session, the 0.3.2 bytes to a legacy one.
  One string, cut to 39 bytes (client.dll's `char szPack[40]`); the longest the
  config produces is 31.
- **Bounds:** two copies a session, then at most one every 5 s however often its
  roster is re-sent (only a duplicate connect re-sends one, and that is
  throttled to 5 s too). Every copy to an unconfirmed session is charged to its
  unconfirmed budget, and one that does not fit is not sent. The count lives
  on the session and ends with it, so a rejoin is fed again; nothing else is
  kept. The client drops the lobby's pack itself when it leaves.
- **Reflection:** with a pack set, a forged legacy connect to an empty lobby
  gets the accept plus the pack, as in 0.3.2: at most 37 bytes for a 17-byte
  connect. `REQUIRE_PROTOCOL_V2=1` removes it; a v2 announce still gets only
  its 17-byte accept.
- **Older clients:** builds from 2026-10-22 until the 2026-10-30 one have no
  case for type 14 and drop it unread, whether it carries C or not; builds
  before 2026-10-22 read it as in 0.3.2.
- The startup log names the pack. `smoke-remote.js --emote-pack VALUE|none`
  checks what a live host sends.
- README: residual risk 15, a forged pack on a link without C (a legacy client,
  or the updated one in the handshake window of risk 11) swaps the pictures a
  player sees for another 7TV set until they leave the lobby.
- 21 new tests (592 in all: 591 pass, 1 pre-existing Windows skip).

## 1.3.1 - 2026-10-29

Fixes from the final review of protocol v2. No wire change: every packet keeps
its 1.3.0 bytes, and legacy sessions are served exactly as before.

### Protocol v2 sessions

- **An unsigned connect never takes a confirmed v2 session over** (review M3).
  In 1.3.0 a connect naming a v2 player from another port of their own IP took
  the name over once they had been silent for `TAKEOVER_AFTER_MS` (10 s): a
  level load, or the main menu. Anyone who could send from that IP - by
  spoofing, or as a CGNAT neighbour - could do it, the real session was
  dropped without a word, and the player's signed packets became `orphan-v2`
  until their client timed out. That was a forced disconnect, which the
  README said v2 ruled out. Now a confirmed v2 session's name is freed only by
  its own signed goodbye, by the sweep after `STALE_TIMEOUT_MS` (60 s) of
  silence, or by the server (console, or a kick for junk that carried its S).
  An unsigned connect from its own endpoint was already a bad token, so it
  could not rename the session; a test now pins that. The price: a v2 player
  whose game crashed gets their name back after up to 60 s instead of 10 s. A
  v2 session that never confirmed is displaced like any unconfirmed one.
- **The squat eviction's rate rule never picks a confirmed v2 session**
  (review M4, ruling 14). The rule exists against forged sessions that hold a
  slot with a trickle of position updates; a v2 session confirmed with S
  cannot be one, so the only v2 player it could pick was a real runner who was
  loading or idle. The 1.3.0 README already said squat eviction was for legacy
  sessions; now it is true. The price: on a full server, an idle v2 player
  keeps the slot until the sweep.
- **A packet with the right S is trusted traffic from the first one** (review
  M5), before its session confirms: it skips the address-level penalty box and
  the shared address budget. In 1.3.0 the first signed line of a new v2
  session competed with junk from any other port of the player's IP for a
  boxed address's one-a-second trickle (or for the spent address budget), and
  under a sustained flood the session never confirmed. Tested with the address
  boxed and with the address budget spent, 3 s of junk from 64 other ports:
  147 of 147 signed lines accepted, against none in 1.3.0.

### Documentation

- `bad-token` no longer reads as "always forged". The first v2 test builds of
  the mod sent position lines before their accept arrived, so every connect
  logged a few (1 on a LAN, 3-5 over the internet); the released v2 build sends
  nothing but its announce until it has S. Diagnostics now says what each
  build produces and when a stream of them means forgery.
- The security model no longer claims more than holds: v2 rules out a forced
  disconnect through the server since this release, and the connect handshake
  has a one-round-trip window on the client (below).
- New residual risks, all in the updated mod's client (11-14): the handshake
  window, where a forged bare accept that beats the real one makes the client
  believe unprefixed packets until the real accept arrives (a fake kick, or a
  fake race status followed by a fake forced load or pause); the race gate on
  a link without C, which stops only a lone forged force-map or pause; a big
  lobby on a host older than 1.3.0 with the accept lost, where the client's
  32-packet queue can drop some roster entries for the session; and
  `-multirun`, where a second game process deletes the first one's cached
  remote sprays.
- The README no longer says a packet without S is never parsed (a
  connect-shaped one to an unconfirmed session is, to recognise a lost-accept
  re-announce), and the 1.3.0 entry below no longer says every piece of junk
  carrying S is punished.

### Tests

- 10 new tests (571 in all): the takeover and rename rules for v2 sessions,
  the squat rate rule with a slow v2 player and with a full server of them,
  the first signed line under an address box and under a spent address budget,
  and 0-3 byte or truncated-S datagrams from a v2 session's endpoint, which are
  bad tokens and never malformed traffic.

## 1.3.0 - 2026-10-28

Protocol v2: per-session secrets, so a session from the updated mod is
authenticated both ways against an off-path attacker. Compatible both ways: an
older build of the mod is a legacy session here, served the exact bytes 1.2.0
served (wire-golden), with every 1.2.0 protection; the updated mod is a legacy
session on an older host. Design: `docs/superpowers/specs/2026-10-28-online-client-hardening-design.md`
in the mod's repository, section 3.1.

### Rollout, in this order

1. **Deploy ghserver 1.3.0** to the host (`update.sh`). It accepts v1 and v2;
   players on older builds notice nothing.
2. **Publish the mod build with the v2 client.** Players who update are v2
   sessions from their next connect.
3. **Once players have updated, set `REQUIRE_PROTOCOL_V2=1`**, which refuses a
   legacy connect with "This server needs the updated Ghosting Mod Renewed".
   Until then legacy sessions keep the 1.2.0 containment and its residual risks.

### Protocol v2

- **Handshake.** A v2 client ends its connect with `u8(2)` and C, 8 random
  bytes of its own; the host answers `07 C S`, S being 8 bytes from
  `crypto.randomBytes`, sent only to that endpoint. Neither is ever all zero.
  A tail that is not exactly that is a legacy connect, not an error.
- **Framing.** Every packet to a v2 session is `type C payload`, put together
  in one place (`send`) by the socket without copying the payload, so a
  broadcast still shares one buffer. Every packet from its endpoint must carry
  S right after the opcode. The largest packets stay under 512 bytes (a client
  spray piece 468, a relayed one 464).
- **A packet without the right S is dropped before every budget**, the global
  packet ceiling included, so it never counts as trusted traffic. It is
  unparsed, counted (`status`, `bad-token`) and never punished: it cannot be the
  player, and boxing for it would be a griefing lever.
  - Measured with 2000 such packets a second from the player's own
    address:port: their real lines went from 5 of 34 relayed (the forgeries
    emptied the session budget) to 34 of 34.
  - With 5000 a second against `GLOBAL_PACKETS_PER_SECOND=1000`: the player's
    and a neighbour's lines went from 9 of 34 each to 34 of 34, and the ceiling
    dropped nothing.
  - Junk that does carry S is the real client's: an unknown opcode or fields
    that do not parse are punished as before; an oversized datagram, or one
    whose opcode cannot be read, is only logged. (Corrected in 1.3.1; this
    line said all of it was punished.)
- **Confirmed only by a packet carrying S.** Until then the session's address
  gets the accept and nothing else. A forged v2 announce is answered with 17
  bytes: 0.53x for a 32-byte announce, against 3.25x in a 3-player lobby and
  14x in a 15-player one with the roster sent at connect. A forged v2 session
  never confirms, so a full server evicts it first.
- **Announced to the lobby when it confirms.** The type 0 join goes to the
  others once, with the session's first signed packet, and the newcomer gets
  its roster at the same moment. A forged v2 session is never announced - not in
  anyone's roster either - and it leaves without a type 4, unless it silently
  took over a name the lobby already knew. Legacy sessions are announced at
  connect, as before.
- **Confirmed v2 sessions are not charged outbound credit.** They are
  return-routable, so the position relay and the spray drip skip the credit
  for them: a v2 receiver at 10 lines a second against 15 senders at 66 got
  5925 of 5925 positions (5886 under the 1.2.0 metering). The liveness gate
  stays: no accepted line for `LIVENESS_MS`, no fan-out, as for any session.
- **The impersonation guard is never armed for a v2 session.** Nothing can speak
  for it without S, so an 8-port sweep naming it no longer pauses its chat.
- **A lost accept** costs one re-announce: an unsigned `c` with the same
  nickname and C, while the session is unconfirmed, gets the same `07 C S`
  again, charged the connect budget like any duplicate connect.
- **A host restart** does not box the address of a v2 client still sending with
  its old S until it times out (`orphan-v2`, sampled, never punished).
- `status` counts v2 and legacy sessions. C and S are never logged.

### Tools

- `test/tools/smoke-remote.js` and `test/tools/smoke-spray.js`: smoke tests
  against a live host over real UDP, each with `--v2`, which announces v2 and
  handles C and S the way the client does, and fails on a legacy answer or on
  any packet without C. `smoke-spray` takes a real spray from `--spray-dir` /
  `GH_SPRAY_DIR`, or builds a synthetic one. Nicknames get a random per-run
  suffix (`--suffix` overrides it), so a rerun is not refused as "in use".

### Known limits

- An on-path observer (the same Wi-Fi, the ISP) can read C and S and act as the
  session it watched; that needs encryption, which is not proposed.
- A v2 session is not followed to a new NAT port; the client reconnects, as a
  legacy one does.

## 1.2.0 - 2026-10-28

Security update from the October 2026 audit. The wire protocol is unchanged, so
no client rebuild is required; every packet the server sends still parses and
behaves the same in the `gh2013_main` client. Audit ids in brackets.

### High

- **[H1] Session/operator hijack by port sweep.** Without a client nonce the
  port cannot be hidden: a sweep of a player's IP reads it back from the
  position relay in about a second. `op "Nick" PIN` now **requires** a 6-12
  digit PIN that every admin chat command must carry (never relayed or printed;
  five wrong PINs revoke the approval with a log alert), which closes the
  operator case; `OP_ALLOW_NO_PIN=1` opts out, `OP_CHAT_COMMANDS=0` removes the
  admin chat surface entirely. For everyone else the sweep is detected and
  contained per session for a short time: datagrams naming a confirmed session
  from 8 distinct ports of its own IP within 30 s (`IMPERSONATION_*`; counted
  even when they are dropped before parsing, so boxing the address first no
  longer hides a sweep) put **that session** under an impersonation guard for
  3 minutes, extended only by a fresh trigger. Its endpoint may not chat or use
  commands (`/race`, `/ready`, `/leave` included), spray, say goodbye or rename
  itself; spectate and appearance changes are applied when it ends; junk from
  it no longer kicks it; a same-address takeover needs the stale timeout; a race
  finish is accepted but marked unverified (the log says how long the guard had
  been on). The player is told when it starts and ends; the log gets a line
  per guard naming who, for how long and the console command that lifts it
  (`unguard "Nick"`, which - like every console command taking a nickname -
  accepts non-Latin names as `list` prints them); `list` shows it. A port the
  server refused the name to, and told so, is not counted toward that name for
  `IMPERSONATION_REFUSED_PORT_MS`, so a group of players behind one NAT who
  all kept the default name does not trip it. Positions keep relaying. Nothing is boxed or muted
  per address any more: other players behind the same IP keep full use of the
  server, and one player refused a taken name behind that NAT, or a NAT re-bind,
  does not trip it; an endpoint that names someone else from its own session is
  charged as malformed instead. Without a client nonce this is an alarm and a
  short containment, not authentication: an attacker who can spoof the
  player's IP can act as them after waiting it out, someone sharing the IP
  can trip it to pause a player's chat and races, and datagrams the global
  packet ceiling drops are not counted (a large volumetric flood can hide a
  slow sweep; listed in the README's residual risks).
- **[H2] Reflection bounded.** A confirmed session (which a forged address can
  become - confirmation is not return-routability) earns outbound credit only
  with its accepted position updates, sized from the live lobby so a receiver at
  the client's slowest update rate is fully served (`OUTBOUND_RECEIVER_FLOOR_PPS`),
  and the high-volume fan-out (position relay and spray drip) is metered:
  skipped for a session out of credit or without an accepted line for
  `LIVENESS_MS`. Amplification to a forged endpoint drops from ~10765x to ~185x
  worst case in a 16-player lobby (it grows ~12x per other player; 69x for the
  audit's one-packet-per-50-s forger); tiny chat packets earn nothing. Real
  players at 10-20 updates/s, and lobbies whose slots are raised live, receive
  >= 99 % of the fan-out. A duplicate connect no longer refreshes the session,
  re-sends the roster at most once per 5 s, and re-queues no delivered spray
  chunk.
- **[H3] Slot-squat eviction.** A full server first evicts a session that has
  not confirmed for over 3 s, then the confirmed session with the lowest rate of accepted position
  updates when that rate is below `SQUAT_EVICT_PPS` (3) and it has been
  confirmed for `SQUAT_WINDOW_MS`. Chat no longer counts, so neither empty chats
  nor re-sent forged connects keep a real player out (both measured 0 -> 100 %
  admitted), and a runner at the slowest update rate doing save/load spam (a 4 s
  load every 8 s) is not evicted. An unconfirmed takeover keeps the original
  connect time only from the same address. Without a client nonce this raises
  the cost of squatting (3 lines a second per slot) rather than closing it.

### Medium

- **[M1] Spray relay memory is now O(players), not O(players²).** Chunk packets
  are built once per publisher and shared through a per-receiver cursor.
- **[M2] Spray publication budget.** A session may publish only
  `SPRAY_PUBLISH_PER_MINUTE` distinct pictures (burst `SPRAY_PUBLISH_BURST`) and
  at most `SPRAY_PUBLISH_MAX_PER_SESSION`; the same budget applies per nickname
  and (times `MAX_SESSIONS_PER_ADDRESS`) per address, so churning sessions from
  one IP no longer multiplies it (120 -> 17 distinct pictures a minute measured),
  and a receiver session is sent stamps of at most
  `SPRAY_MAX_PICTURES_PER_RECEIVER` (40) distinct pictures, below the 48 remote
  textures the client builds per game run (a picture counts when its first stamp
  is relayed), and is fed at most `SPRAY_MAX_FED_PER_RECEIVER` (200) pictures,
  below its 256 written blobs. A picture refused as too large after re-encoding
  gives its publish budget back.
- **[M3] Sprays are validated before relay and re-encoded.** Strict parse
  (`GHS1` magic, legal VTF size, bounded inflate to exactly that size, VTF
  header matched byte-for-byte against the client's own writer, pixel CRC), then
  the host relays a blob re-encoded with the current zlib. Junk is dropped with
  no fan-out. Proven wire-compatible against the shipped client. The re-encode
  runs at zlib level 6 (a valid 2-colour-noise picture took ~455 ms at level 9,
  ~25 ms at level 6) under a server-wide budget (`SPRAY_REENCODE_BURST` /
  `SPRAY_REENCODE_PER_MINUTE`), so sprays cannot freeze the event loop however
  many sessions publish. The publish budgets are charged first, and a picture
  that finds the re-encode budget busy waits in a bounded queue
  (`SPRAY_REENCODE_QUEUE_MAX`, one per session) drained at the budget's rate,
  round-robin by source address - so attackers cannot keep a real player's
  spray out (measured 0/1 -> published within 8 s against three addresses), an
  honest mass join publishes every spray (48 joiners: 21/48 -> 48/48), and no
  notice or unsampled log line is produced per attempt (160 lines/s from one
  address -> 0). A waiting picture is replaced only by a newer one from the
  same player that validated and was budgeted (in place, its tokens given
  back) - a newer upload that is refused or never completes no longer costs
  it - and `status` and `sprays` show how many wait. Replies to a single
  player (`serverSayTo`) are logged as a sampled event. A picture whose
  re-encode exceeds the receiving
  client's bound (163840 B, equal to the upload cap; roughly originals above
  ~160 KB) is refused, never relayed in its original encoding, and the sender is
  told.
- **[M4] The `d` and spray-publish log lines are sampled** and `d` is charged to
  the events budget, so a probe cannot fill the disk through them.
- **[M5] Homoglyph `SERVER` is refused** on a confusable skeleton (NFKD,
  combining marks removed, Cyrillic/Greek/Cherokee/small-capital lookalikes
  mapped to Latin - so `SẸRVẸR` and `SÉRVÉR` are caught too), and bidi/invisible
  marks are stripped from names and chat.
- **[M6] Firewall ruleset rewritten** (`deploy/nftables-ghserver.conf`): its own
  `inet ghserver` table replaced atomically (never `flush ruleset`), untracked
  game port so the per-IP meter bites, SSH, DHCPv4/DHCPv6 replies and ICMPv6
  kept, oversize UDP dropped; rendered by the installer for the env `PORT` and
  every sshd port. `firewall-apply.sh` guards the file (a real accept for every
  sshd port, comments ignored), schedules the rollback with `systemd-run` so it
  survives a dropped session, and keeps the rules only when confirmed from a
  NEW ssh session. It applies, and on confirm persists, a copy taken at apply
  time (an edit made afterwards is refused, never silently made the boot
  ruleset); the confirmed copy is included from `/etc/nftables.conf`. A
  rollback whose restore fails removes the ghserver table rather than leaving
  unconfirmed rules live; it reports a table removal only when it happened,
  and `--rollback` with nothing pending changes nothing (live stays the boot
  ruleset). The pending record is written before the rules are loaded, so any
  failure after the load is still rolled back; a load nft refuses changes
  nothing and leaves nothing pending.
- **[M7] Hardened systemd unit and FIFO console** in `deploy/`: code read-only
  out of `/opt/ghserver`, `StateDirectory` for state, and a `reload` command /
  `SIGHUP` handler (`systemctl reload ghserver`) to re-read the access file
  without a restart. The server opens the console FIFO itself (`CONSOLE_FIFO`),
  so the console is not a dependency: the server starts without it, and a write
  never starts a stopped server. `ghserver-console` with no arguments reads the
  command without echoing it, so an operator PIN stays out of shell history.
- **Installer:** the NodeSource key fingerprint is pinned, NodeSource updates
  are matched by `site=` (an `origin=` pattern never matched), no automatic
  reboot, a re-run restarts the service, it refuses to run from `/opt/ghserver`,
  the env template has no inline comments, and a ruleset left by the pre-release
  installer (one that flushes everything) is moved to `.bak` and re-rendered.
  Without the `ghsadmin` group no console FIFO is created (none owned by group
  root) and the journal says so; the FIFO is chowned with `-h`. `update.sh` checks the env `PORT`
  and never loses the only copy of the install if a move fails.
- **[M9] Node floor raised to 22** (24 LTS recommended). `index.js` refuses an
  older runtime (exit 78); `engines` is `>=22`.

### Low

- **[L1]** The access file is written `0600` through a random-named `O_EXCL`
  temporary with a directory `fsync`.
- **[L2]** The `sprays` console table escapes names; `sanitizeForLog` escapes
  bidi marks and line separators.
- **[L3]** `limits __proto__` replies "no such limit" instead of throwing.
- **[L4]** Held-prop model changes are relayed at most every 250 ms per player.
- **[L5]** The spray buckets are pruned in the sweep; a completed upload's
  declared size and chunk count must match what arrived.
- **[L6]** Address bans/whitelist entries are IPv4 only (mapped `::ffff:` is
  normalised, pure IPv6 refused). An existing access file with a non-IPv4
  address row still loads: the row is dropped with a warning (it could never
  match), instead of the server refusing to start.
- A goodbye (`d`) has its own small bucket, so a player who just used the
  events budget on stamps or spectate toggles is not left as a frozen ghost.
- A duplicate connect never re-sends a picture the receiver already has in full
  (per-receiver delivered map). The record is forgotten when the sender leaves
  (type 4), because the receiving client forgets the picture then too: a player
  who rejoins with the same picture is sent to everyone again, so their stamps
  are drawn.
- **[L8]** `make-release.js` ships without `legacy/`, `test/` and `scripts/`.
- **[L9]** The dead 7TV emote pack (type 14, `EMOTE_PACK`) is removed; stale
  comments corrected.

### Not done (client follow-ups, require a mod rebuild)

A per-session nonce (closes direct client griefing and makes the H2/H3 defences
return-routable), relinking the client's zlib 1.2.5, validating a spray before
writing it to disk, and ignoring force-map/pause packets outside a race lobby.
