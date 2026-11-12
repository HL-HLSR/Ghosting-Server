# Ghosting server

This is the dedicated host for Ghosting Mod (2013 SDK) online. All ghost
clients connect to this Node.js UDP server; the server validates their
packets and relays state (positions, connects/disconnects, chat) to everyone
else. There is no player-hosted mode - the server is the authority.

## Requirements

Node.js **22 or newer** (24 LTS recommended). Nothing else: no dependencies, no
build step, no database. The process refuses to start on an older line (exit
78): Node 20 reached end of life in April 2026, and Ubuntu's own `apt` still
ships an EOL 18.x, which a parser of unauthenticated network input should not
run on. See "Deploying on Ubuntu 24.04" for how to install a current Node.

    node index.js

UDP port `22228` must be reachable for internet play.

## Layout

    index.js        entry point: environment, signals, exit codes
    src/config.js   every environment variable, validated in one place
    src/server.js   the host: inbound checks, handlers, sweep, shutdown
    src/console.js  operator commands on stdin
    src/clock.js    monotonic time
    src/wire/       the packet format: reader, writer, limits, packet builders
    src/net/        token buckets and sampled logging
    src/game/       users, nickname ownership, bans and operators, the race machine
    test/           node:test suites, plus fuzz and load harnesses
    legacy/         the previous single-file server, kept for comparison

`legacy/index.js` is the version this replaced. It is not loaded at runtime; the
compatibility tests execute it in a sandbox and compare its bytes against the
current packet builders, so a change to the wire format fails the build instead
of reaching players.

## Environment

Every variable is validated at startup. An unparseable value stops the process
with exit code 78 and a message naming the variable, rather than falling back to
a default nobody asked for.

### Basics

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `22228` | UDP port. Must match `gh_online_port` on the clients. |
| `BIND_ADDRESS` | `0.0.0.0` | IPv4 literal to listen on. Hostnames are rejected. |
| `MAX_PLAYERS` | `16` | Slot limit. Above 16 the server warns: fan-out cost grows with the square of the player count and only 16 has been load tested. |
| `MAX_SESSIONS_PER_ADDRESS` | `4` | Slots one address may hold. |
| `NAME_MAX_LENGTH` | `31` | Nickname length in bytes, which is the size of the buffer it lands in on the client. A Russian nickname is two bytes a letter; truncation always lands on a character boundary. Lower it to `28` only for a build of the mod older than the one that dropped the `OL ` prefix. |
| `DEBUG` | `0` | `1` logs every position update. `0`, `false`, `no` and `off` all mean off. |
| `ACCESS_FILE` | `access.json` | Where bans, the whitelist and the operator list are kept. Relative to the working directory, which must be writable. |
| `ACCESS_PERSIST` | `1` | `0` keeps those lists in memory only: they work while the process runs and are gone at the next restart. Warned about at startup. |
| `OP_CHAT_COMMANDS` | `1` | Whether players may use the operator chat commands (`/kick`, `/ban`, ...) at all. An operator session is bound only to a forgeable address:port, so a host that moderates from the console can set `0` and remove that chat surface entirely; the console `op`/`kick` path is unaffected. |
| `OP_ALLOW_NO_PIN` | `0` | `op "Nick"` requires a PIN of 6-12 digits. `1` allows approving an operator without one - then anyone who finds their address:port can use their commands. |
| `REQUIRE_PROTOCOL_V2` | `0` | `1` refuses a legacy connect (any build of the mod older than protocol v2) with "This server needs the updated Ghosting Mod Renewed". Turn it on only once players have updated: it locks every older build out. See "Protocol v2". |

### Server browser (1.4.0)

The mod's main-menu "Servers" dialog (the 1.4.0 build of Ghosting Mod Renewed)
asks a host for its name, version, players and race without joining it; see
"Server browser query" under Protocol for the wire and its reflection bounds.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SERVER_NAME` | `Ghosting server` | The name the dialog shows. UTF-8, at most 63 bytes (a Cyrillic letter is two); control characters and bidi marks are removed, longer is refused at startup. |
| `SERVER_INFO` | `1` | `0` leaves every query unanswered, as a host before 1.4.0 would. |
| `SERVER_INFO_PLAYERS` | `1` | `0` keeps the player count in the reply and leaves the names (and their HLSR / operator / spectator / runner flags) out. |
| `INFO_RATE_PER_SECOND` / `INFO_BURST` | `2` / `8` | Queries one address may make. A refresh is two datagrams per server (the query, then the query with its challenge). |
| `INFO_GLOBAL_PER_SECOND` | `200` | Queries answered per second from all addresses together, spoofed ones included. |

### Timing

| Variable | Default | Meaning |
| --- | --- | --- |
| `STALE_TIMEOUT_MS` | `60000` | Silence after which a session is swept. |
| `UNCONFIRMED_TIMEOUT_MS` | `20000` | Shorter leash for a session that has sent only a connect packet. This does not prove return routability. |
| `TAKEOVER_AFTER_MS` | `10000` | Silence after which the same address may reclaim its nickname on a new port, and the age after which anyone may displace a session that never confirmed. Not for a confirmed protocol v2 session: no connect from another endpoint carries its S, so its name is freed only by its own goodbye, by the sweep after `STALE_TIMEOUT_MS` of silence, or by the server (see "Protocol v2"). |
| `SWEEP_INTERVAL_MS` | `5000` | How often the sweep runs. |
| `HEARTBEAT_MS` | `2000` | Keepalive to every client. Clients drop the session after 10 s of silence, so the accepted range stops at 5000 and anything above 4000 is warned about. |
| `CHAT_MIN_INTERVAL_MS` | `600` | Minimum gap between chat lines from one player. |
| `RACE_SPECTATORS` | `0` | Whether a player who is spectating may use `/race` and `/ready`. Off by default: a bystander should not be able to take the race lock. |
| `EMOTE_PACK` | unset | The lobby's shared 7TV emote pack. Accepts a `7tv.app/emote-sets/<id>` or `7tv.app/users/<id>` link, a bare 7TV id, or a numeric Twitch channel id. Unset (or `0`, or `off`) means the host says nothing and every client keeps whatever it had. A user link is warned about: it resolves to whichever set the launcher picks from that account. See type `14` under "Protocol". |
| `MIN_LINE_INTERVAL_MS` | `15` | Minimum gap between relayed position updates. The client sends every 20 ms (`gh_online_updaterate`), so anything above that makes ghosts stutter and is warned about; the range stops at 200. |

`EMOTE_PACK` was retired in 1.2.0 (audit finding L9), when the 2026-10-22 client
had dropped packet type 14, and is back in 1.3.2 for the client that reads it again.
Its values mean what they meant in 0.3.2; `0` and `off` are new and mean none.

### Race

| Variable | Default | Meaning |
| --- | --- | --- |
| `RACE_LOBBY_MS` | `60000` | Lobby window after `/race`. |
| `RACE_LOADING_TIMEOUT_MS` | `180000` | Cancel the race if not everyone has loaded by then. |
| `RACE_STAGING_TIMEOUT_MS` | `120000` | Cancel the race if not everyone has reached the start by then. |
| `RACE_MAX_DURATION_MS` | `7200000` | Cancel a race that has been running this long. |
| `RACE_NO_PROGRESS_MS` | `45000` | Cancel the race if loading has made no progress for this long. Runs from the last runner to report the race map, not from the start of the phase, so one runner who never loads cannot hold the lock for the full loading timeout. |

### Rate limiting

| Variable | Default | Meaning |
| --- | --- | --- |
| `RATE_PER_ADDRESS` / `BURST_PER_ADDRESS` | `480` / `960` | Packets per second from one address, and the burst it may spend at once. Four sessions' worth, for several players behind one NAT. |
| `RATE_PER_SESSION` / `BURST_PER_SESSION` | `120` / `240` | The same, per address:port. A playing client sends about 50 packets a second, so a value under 60 is warned about. |
| `CONNECT_RATE_PER_MINUTE` / `CONNECT_BURST` | `12` / `4` | Connects per address. An endpoint that has never spent a connect gets one more even when the address budget is empty, so a forged flood cannot lock the real owner of an address out; a connect admitted that way and then refused is answered with silence. |
| `COMMAND_RATE_PER_SECOND` / `COMMAND_BURST` | `1` / `3` | Slash commands per session. |
| `EVENT_RATE_PER_SECOND` / `EVENT_BURST` | `4` / `10` | Race checkpoints and spectate changes per session. |
| `MALFORMED_RATE_PER_SECOND` / `MALFORMED_BURST` | `5` / `20` | Bad packets per address before it is ignored for 30 s. |
| `GLOBAL_PACKETS_PER_SECOND` | `20000` | Whole-process ceiling. |
| `GLOBAL_RESERVE_PERCENT` | `20` | Share of that ceiling only confirmed sessions may spend (from a v2 session's endpoint, only packets carrying its S; the rest are dropped before the ceiling). Without it the ceiling is first-come-first-served, which under a flood means most-packets-wins: the connected players lose to the attacker and the ceiling ends up disconnecting the people it protects. |
| `MAX_TRACKED_ADDRESSES` | `20000` | Ceiling on the per-address bookkeeping. |
| `MAX_TRACKED_SESSIONS` | `40000` | Ceiling on the per-session bookkeeping. |
| `UNCONFIRMED_BUDGET_BYTES` | `8192` | Bytes a session may receive before a follow-up packet marks it active, counted as they go on the wire (a v2 session's C included). |
| `LOG_SAMPLE_INTERVAL_MS` | `10000` | How often a repeated event is summarised. |

### Anti-reflection and slot squatting

A confirmed session (which a forged source address can become - confirmation is
not return-routability) used to receive every player's 50 Hz stream as a
reflected attack, and a trickle of forged keepalives could hold every slot.
These bound both. The credit and the squat eviction's rate rule apply to legacy
sessions only: a protocol v2 session is confirmed only by a packet carrying its
S, which proves the address asked, so its fan-out is not charged credit and,
once confirmed, it is never evicted as a squatter (an unconfirmed one is, first
of all). `LIVENESS_MS` applies to every session (see "Protocol v2").

With `EMOTE_PACK` set, a forged legacy connect to an empty lobby gets the accept
plus the emote pack, as in 0.3.2: at most 37 bytes for a 17-byte connect (2.2x),
inside `UNCONFIRMED_BUDGET_BYTES` like the roster. `REQUIRE_PROTOCOL_V2=1`
removes it (a legacy connect then gets only its refusal); a v2 announce gets
the 17-byte accept alone either way.

| Variable | Default | Meaning |
| --- | --- | --- |
| `OUTBOUND_RECEIVER_FLOOR_PPS` | `8` | The metered fan-out (the position relay and the spray drip) is paid for with credit a session earns **only with accepted position updates** - never chat or other packets. Each accepted line earns what a receiver sending only this many lines a second needs to be fully served by senders at the protocol maximum (~66/s), computed from the live lobby (confirmed players, largest recent info packet), so a low `gh_online_updaterate`, an unfocused window or a live `maxplayers` raise never starves a real player. The client's floor is `updaterate 10`, 7.5-8.6 lines/s once frames quantise it. Lower it and slow players stutter; raise it and the amplification bound below falls proportionally. |
| `LIVENESS_MS` | `3000` | The metered fan-out skips a session that has sent no accepted position update for this long. A real client sends position keepalives on wall-clock even while paused, alt-tabbed or in the menu, and only goes quiet during a level transition of a few seconds; heartbeats still reach it, so it is never timed out. |
| `SQUAT_EVICT_PPS` | `3` | When the server is full, a newcomer first evicts a session that has not confirmed for over 3 s (a real client confirms one frame after connecting), then the confirmed **legacy** session with the lowest rate of **accepted position updates** if that rate is below this. A confirmed protocol v2 session is never a candidate (1.3.1): it cannot be a forged one, so on a full server of them a newcomer is told the server is full. A shipped client sends 7.5-50 a second even while paused or unfocused, and goes quiet only while a level loads. Measured at `gh_online_updaterate 10` (~8 lines/s), the slowest setting: a runner spamming saves with a 4 s load every 8 s averages 4.1/s and stays, 5 s of every 8 s (3.2/s) stays, 7 s of every 10 s (2.4/s) is a candidate - so at the slowest rate a player is at risk only when more than ~60 % of their last minute was loading, and at 20 or more never in practice. Raising it makes squatting dearer for a forger and save/load spam riskier for runners. |
| `SQUAT_WINDOW_MS` | `60000` | Window the inbound rate is averaged over, and the minimum age before a session can be judged a squatter (so a just-joined player is never evicted). |

### Impersonation guard

Legacy sessions only. The guard is never armed for a protocol v2 session:
nothing can speak for one without its S, so there is nothing to contain.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IMPERSONATION_TRIGGER_PORTS` / `IMPERSONATION_TRIGGER_WINDOW_MS` | `8` / `30000` | A confirmed session is guarded once datagrams naming it arrive within the window from this many **distinct ports of its own IP** - the shape of a sweep for its port. A player whose connect the server refuses because the name is taken - and tells so - keeps naming it from the new port until the refusal arrives; that port is not counted toward that name for `IMPERSONATION_REFUSED_PORT_MS`, so a group of players behind one NAT who all kept the default name "Ghost" does not trip it (measured with up to 9 of them pressing connect together). A refusal the server keeps silent (the address's connect budget is spent, about 12 connects at once) is still counted, and a NAT re-bind uses one port. A datagram from an endpoint that holds its own confirmed session is not counted (it is charged as malformed traffic instead), and datagrams from other IPs are not counted. Datagrams dropped before parsing (a boxed address, the address budget) are still counted. |
| `IMPERSONATION_REFUSED_PORT_MS` | `60000` | How long an address:port the server refused a name to (and told) is not counted toward that name's guard. Only spoken refusals count here: those are capped by the address connect budget, so a sweep cannot buy exemptions in bulk. |
| `IMPERSONATION_GUARD_MS` | `180000` | How long the guard holds after it was triggered. Only a fresh trigger (the port count met again) extends it; the console command `unguard "Nick"` lifts it. See "Commands in chat" (under Access control) for exactly what it refuses. `IMPERSONATION_TRIGGER_PACKETS` (an earlier pre-release name) is refused at startup. |

### Sprays

| Variable | Default | Meaning |
| --- | --- | --- |
| `SPRAY_UPLOAD_RATE_PER_SECOND` / `SPRAY_UPLOAD_BURST` | `40` / `80` | How fast one session's spray PIECES may arrive. A full 160 KB picture is about 410 pieces, so the burst covers a client sending it all at once. |
| `SPRAY_CHUNKS_PER_TICK` | `16` | Pieces handed to each receiver per 250 ms tick (64 a second), so a join into a spray-heavy lobby is a trickle, not a burst. |
| `SPRAY_PUBLISH_PER_MINUTE` / `SPRAY_PUBLISH_BURST` | `2` / `3` | How often a session may complete (publish) a DISTINCT picture, separate from the piece rate. The same budget applies per nickname (a reconnect under the same name gets no fresh allowance) and, times `MAX_SESSIONS_PER_ADDRESS`, per address (so churning sessions from one IP cannot multiply it, while a NAT of real players still fits). A fresh one-chunk spray every 25 ms used to fill every other client's cache. |
| `SPRAY_MAX_PICTURES_PER_RECEIVER` | `40` | Distinct pictures whose **stamps** one receiver session is sent, from all senders together. The shipped client builds a remote spray texture when it first draws a picture's stamp, at most 48 per game run, and then shows nobody's spray until restarted; a picture counts here when its first stamp is relayed to that receiver, and stamps of further pictures are not relayed to it. |
| `SPRAY_MAX_FED_PER_RECEIVER` | `200` | Distinct pictures one receiver session is ever fed (sent in full), below the 256 remote blobs the client writes to disk. Pictures nobody stamps cost the receiver no texture, so churn alone no longer stops them from seeing new sprays after 40. |
| `SPRAY_PUBLISH_MAX_PER_SESSION` | `10` | Hard ceiling on distinct pictures one session may publish before it reconnects. |
| `SPRAY_REENCODE_BURST` / `SPRAY_REENCODE_PER_MINUTE` | `4` / `20` | **Server-wide** budget on spray re-encodes (one every 3 s after a burst of 4). Each re-encode is a synchronous level-6 deflate, ~25 ms worst case on a fast core for an attacker-chosen valid picture, so this bounds the event-loop time sprays can take however many sessions publish. The publish budgets above are charged first. A validated picture that finds this budget busy **waits in a queue** the server drains at this rate, one per 250 ms tick at most, taking turns by source address: whoever floods it from N addresses gets at most N/(N+1) of the turns, and every other picture is published without the player doing anything (measured: within 8 s against three attacking addresses; after an honest mass join of 16 / 48 / 64 players, the last spray goes out about 40 s / 2.3 min / 3.1 min after the first). Nobody is sent a notice. Raise the rate on a fast host if mass joins matter more than ~1 % of a core. |
| `SPRAY_REENCODE_QUEUE_MAX` | `64` | Pictures that may wait for a re-encode at once. One per session (a newer picture replaces the session's waiting one), so with up to 64 slots it is never full. |

## Console commands

Type these where `node index.js` is running:

| Command | Description |
| --- | --- |
| `help` | Show the command list |
| `status` | Server name, players, uptime, how many sessions say they came from HLSR or sent a SteamID, server-browser queries, traffic counters, what the limiters have dropped, list sizes |
| `list` | Connected users with address, map, last-seen time, whether the address has answered, protocol (v2/legacy), `HLSR` / `not HLSR` / `launcher unknown` (a client before 1.4.0) and the SteamID it announced, whether it is an approved operator, and any impersonation guard with the time left |
| `gh_online_kick "Nick"` | Kick a user by name |
| `kick "Nick"` | Alias for `gh_online_kick` |
| `unguard "Nick"` | Lift an impersonation guard (`list` shows who is guarded) once you are satisfied it was not a real attack; the player is told their chat is back |
| `broadcast "message"` | Send a chat message to everyone as `SERVER` |
| `race cancel` | End the current race and release anyone it paused |
| `maxplayers [n]` | Show or change the slot limit, `1`..`64`, without a restart |
| `limits` | Every rate limit with its live value and what it has dropped |
| `limits <name> <n>` | Change one while the server runs, e.g. `limits chat.interval 0` |
| `ban "Nick" [term] [reason]` | Ban a nickname and remove whoever is holding it |
| `banip ADDRESS [term] [reason]` | Ban an address and remove every session on it |
| `bansteam SteamID [term] [reason]` | Ban a SteamID (SteamID64, `STEAM_0:Y:Z` or `[U:1:N]`) and remove every session that announced it. `bansteam "Nick"` bans the SteamID that connected player announced. Self-reported: see "What a SteamID is worth" |
| `unban "Nick"` / `unbanip ADDRESS` / `unbansteam SteamID` | Lift a ban. Nobody is invited back; it only stops refusing them |
| `banlist` | The bans that are in force. Lapsed ones are dropped, not listed |
| `sprays` | Who has published a picture, who is half-uploading, who is still being sent one |
| `sprayban "Nick" [term] [reason]` | Refuse a player's spray and drop the one they published; they stay on the server |
| `unsprayban "Nick"` | Let them spray again |
| `reload` | Re-read the access file (bans/whitelist/ops) without a restart, then kick anyone now banned |
| `whitelist` | Show the mode and the entries |
| `whitelist on` / `off` | Switch it, effective for the next connect |
| `whitelist add "Nick"` / `addip ADDRESS` / `addsteam SteamID` | Add an entry (`addsteam "Nick"`: the SteamID that connected player announced) |
| `whitelist remove "Nick"` / `removeip ADDRESS` / `removesteam SteamID` | Remove one |
| `op "Nick" PIN` / `deop "Nick"` / `ops` | Approve a connected session with a 6-12 digit PIN its chat commands must carry, revoke, and list the operators (by name and by SteamID). The PIN is never printed. |
| `opsteam SteamID PIN` / `deopsteam SteamID` | A standing operator entry by SteamID (1.4.0): every protocol v2 session that announces that SteamID is approved when it confirms - after reconnects and restarts too - and its admin chat commands need the PIN, kept in the access file as a salted hash. `opsteam "Nick" PIN` takes the SteamID a connected player announced. Read "What a SteamID is worth" first. |

`reload` also fires on `SIGHUP`, so a deploy that replaces `access.json` can
signal the running server instead of restarting it. A broken file is reported
and the current lists are kept.

Kicked clients receive packet type `5` with the reason; everyone else gets a
type `4` disconnect for that user.

`term` is `30s`, `45m`, `2h`, `7d`, or `perm` - the default. It is only read
from the token immediately after the name, and only when it is unmistakably a
duration, so `ban "Bob" spamming` is a permanent ban with a reason rather than a
ban for "spamming" minutes.

`maxplayers` takes effect on the next connect, because the limit is read live.
Lowering it below the number of players **removes nobody**: it stops new
connections until enough people leave. Throwing twelve players out of a running
game is not what an operator asking for fewer slots meant, and it cannot be
undone.

`whitelist on` likewise removes nobody who is already playing - use `kick` for
that - and an empty whitelist that is switched on refuses everyone, which the
console says out loud at the moment it is switched.

## Access control

### What a name and an address are worth

Read this before deciding what the lists are for. The protocol carries no
account and no signature. (A protocol v2 client carries a per-session secret,
S: it proves a packet came from the endpoint that connected, not who is behind
it.) Since 1.4.0 the mod also **says** which SteamID it runs under - see "What
a SteamID is worth" below: it is the client's word, not a login. That leaves
the server these handles, and they are not equally good:

- **A nickname belongs to nobody.** It is whoever typed it first; `nickname.js`
  refuses two people wearing one at the same time and that is the entire
  guarantee. A name ban stops the player who cannot be bothered to change it and
  nobody else. OP must be approved from the console for a currently connected
  session after verifying the player. Reconnecting or restarting the server
  requires approval again; the persisted name list does not automatically grant
  privileges to whoever next takes a name. This closes offline name takeover,
  but does not authenticate UDP packets or the human using that connection.
- **An address is not a person.** It is forgeable, exactly as the security model
  below says, and it is shared: banning one address bans everybody behind that
  NAT, including people who did nothing.

So this is moderation, not authentication. It ends arguments and it removes
people who are ruining a game; it does not keep out somebody who wants back in
and knows how. Nothing in the code claims otherwise, and the console prints the
caveat when you type `op`.

### What a SteamID is worth

The 1.4.0 build of the mod appends an identity block to its protocol v2
announce: the SteamID64 the game runs under (read from the local Steam client,
left out when there is none, or when the player sets `gh_online_send_steamid
0`) and whether the game was started from the HLSR launcher. **Both are
self-reported. The host checks no Steam ticket** - there is no Steam
authentication anywhere in this protocol - so a modified client can announce
any SteamID, somebody else's included, or none at all. SteamIDs are public (any
Steam profile shows one). So:

- a **SteamID ban** (`bansteam`) stops a player whose client tells the truth -
  which an unmodified client does, and changing that costs editing a DLL rather
  than retyping a nickname - and nobody who leaves the SteamID out;
- a **SteamID whitelist** entry (`whitelist addsteam`) admits anyone who
  announces that SteamID;
- a **SteamID operator** (`opsteam SteamID PIN`) is approved automatically on
  every session that announces that SteamID, which is exactly what makes it
  convenient and exactly why **the PIN is the real credential**: without it
  (`OP_ALLOW_NO_PIN=1`) anyone who looks the operator's SteamID up and claims
  it gets the admin chat commands. With it, a session claiming the SteamID is
  approved but every command still needs the PIN, five wrong ones revoke that
  session's approval (and say so in the log), and the PIN is stored only as a
  salted scrypt hash. Pick 8 or more digits; a 6-digit PIN can be guessed in
  time by somebody reconnecting from many addresses. An approval applies only
  to a protocol v2 session that has confirmed with S, so a forged announce
  cannot become an operator; a legacy client never carries a SteamID at all.
- "**HLSR**" means the game process had the launcher's presence variables in its
  environment when it connected; it is shown in `list`, on the join line and in
  the server browser, and decides nothing.

The stored records carry the kind of identity in a field of their own (`name`,
`address`, `spray`, `steamid`), so the SteamID is one more value rather than a
new file format. A host before 1.4.0 refuses to start on an access file with a
`steamid` record ("unknown kind") - deliberately: a ban silently dropped is a
banned player let back in. Remove those records before downgrading.

### Where it is kept

`ACCESS_FILE` (`access.json` by default; `/var/lib/ghserver/access.json` under
the deploy unit's `StateDirectory`). Written atomically and privately: a
randomly-named `O_EXCL` temporary beside it created `0600`, `fsync`, a rename
over the top, then a directory `fsync` - so a power cut cannot leave a
half-written list behind, and a symlink planted at a predictable temp name
cannot be followed. The file holds player addresses, so it is owner-only. Lapsed
bans are not written back.

A file the server cannot parse **stops the start** with exit code 78. Coming up
with empty lists would be the friendlier-looking failure and the worse one: the
host would look healthy while everyone you banned walked back in. Editing the
file on a running server and then `reload` (or `SIGHUP`) applies it without a
restart; a broken file is reported and the current lists are kept.

A write that fails - full disk, read-only mount - does not fail the command and
does not roll it back. The ban is in force; the console says the file was not
written, and `status` keeps saying so. (Under the deploy unit the state
directory is writable, so this is a disk problem, not a permissions one.)

### Commands in chat

A player approved as an operator for their current session - from the console
with `op "Nick" PIN`, or automatically through an `opsteam` entry for the
SteamID their client announced (they are told so in chat when it happens) - can
type these into the ordinary chat window:

    /kick Nick
    /ban Nick [term] [reason]
    /unban Nick
    /sprayban Nick [term] [reason]
    /unsprayban Nick
    /broadcast message

This needs **no change to the mod**. Chat is opcode `m`, which every shipped
client already sends; the server consumes a line starting with `/` instead of
relaying it, and answers with an ordinary type `6` chat message from `SERVER`.
There is no new packet type and no new build.

They cost the same command budget as `/race` (`COMMAND_RATE_PER_SECOND`), so an
operator is not an unmetered packet source, and a player who is not on the list
gets a refusal and nothing else.

The rest of this section is about operators on a legacy client. An operator
on a protocol v2 session cannot be impersonated by an off-path attacker at all
(a datagram from their endpoint needs their S); the PIN still applies.

Because a legacy operator session is bound only to a forgeable address:port, an
off-path attacker who knows an operator's nickname and IP can forge datagrams
from the operator's address and sweep the source port. **The port is found in
about a second**: a forged position update from the real port is relayed like
the player's own, so the attacker reads the port back from the relay (measured:
0.8 s at 15000 packets a second, 2.4 s at 5000). For a legacy client nothing on
the server can prevent that. Three defences stand in the way of what
comes after it:

- **A PIN is required.** `op "Nick" PIN` (6-12 digits); every admin chat command
  must carry it first (`/ban 482913 Griefer perm`). It travels only in the
  operator's own chat packet and is consumed - never relayed, never printed - so
  an off-path attacker cannot observe or forge it. Type it only in a `/` command,
  never as plain chat, and not on a live stream. Five wrong PINs in a row revoke
  the approval and write an alert to the log. `OP_ALLOW_NO_PIN=1` opts out.
- **The targeted session is guarded - an alarm and a short containment.**
  Datagrams naming a session from 8 distinct ports of its own IP within 30 s -
  the sweep itself, counted even when the address is boxed or over budget - put
  that one session under an impersonation guard for 3 minutes
  (`IMPERSONATION_*`); only a repeat of that trigger extends it. While it holds,
  from that session's address:port:
  - chat and every chat command (`/race`, `/ready`, `/leave`, operator
    commands), sprays and the goodbye are refused;
  - a connect naming another nickname (a rename that would drop the player) is
    refused, and junk datagrams are dropped without kicking the player;
  - spectate and appearance changes are held and the last one is applied when
    the guard ends (a forged one would be applied too - nothing new: it could
    as well be sent after the guard);
  - positions still relay and heartbeats still arrive, so the player keeps
    playing, and a race finish is accepted but announced and logged as
    **unverified**, with how long the guard had been on;
  - the same address cannot take the name over until the stale timeout (60 s
    of silence) instead of 10 s.

  The player is told when it starts (what is paused, for how long, and how to
  get a new port: `gh_online_disconnect`, wait 60 s, `gh_online_connect`) and
  when it ends. The log gets one line per guard - `WARN impersonation guard on
  'Nick' (address:port) for ~3 min - lift with: unguard "Nick" ...` - and one
  when it ends (a ceiling of 64 such lines a minute, past which they are
  summarised), and `list` on the console shows it. An operator under attack
  moderates from the console meanwhile, and `unguard "Nick"` lifts a guard at
  once; console commands take a nickname exactly as `list` prints it,
  non-Latin letters included.

  It is not tripped by players behind the same NAT who all kept the default
  name "Ghost" and keep pressing connect: a port the server refused that name
  to - and told - is not counted toward it for a minute
  (`IMPERSONATION_REFUSED_PORT_MS`). About a dozen of them pressing connect at
  the same moment still can, because once the address's connect budget is
  spent the server stops answering refusals (to avoid reflecting at a forged
  address), and unanswered ones are counted; they could not all play from one
  address anyway (`MAX_SESSIONS_PER_ADDRESS`).

  What it does not do: authenticate anybody. An attacker who can spoof the
  player's IP and has learned the port can wait out the 3 minutes in silence
  and then chat, spray or race as that (non-operator) player; a sweep slow
  enough to stay under the trigger is not seen at all, and how long that takes
  depends on how predictable the player's NAT makes the port, so do not count
  on it. Someone who shares the player's public IP (CGNAT) can trip the guard
  without spoofing, by sending from several ports - and so pause that player's
  chat and races for 3 minutes at a time; the console `unguard` and a ban are
  the remedies. Protocol v2 closes this for players who update: the guard is
  never armed for a v2 session.
- **`OP_CHAT_COMMANDS=0`** removes the admin chat surface entirely, for a host
  that moderates from the console.

There is deliberately no `/banip`: using it would mean showing players' addresses
in chat, and address bans stay at the console. Granting OP is console-only for
the same kind of reason - it is the one thing that should not be reachable from a
session whose only credential is a forgeable source address.

## Protocol

Incoming opcodes (client -> server). Each datagram starts with a
length-prefixed opcode string. `int32` is big endian, `float` is little endian,
and a string is a big endian `uint32` length followed by that many raw bytes.

| Opcode | Meaning | Payload |
| --- | --- | --- |
| `c` | connect | name, trail length, trail RGB, ghost RGB (bytes) |
| `v` | appearance | name, the same seven colour bytes - sent when a player recolours mid-session; relayed as a silent type 0 so the lobby updates in place |
| `l` | line/update | name, map, velocity xyz, position xyz, pitch, yaw, then optional: paused, weapon, hp/armor/clip/ammo, held model + transform, eye height, keys bitmask |
| `d` | disconnect | name |
| `m` | chat message | name, message text (text starting with `/` is a command) |
| `r` | race checkpoint | name, checkpoint byte (1 = pre-teleport pause point, 2 = finish), then optionally the finisher's own run time in seconds and LiveSplit's (-1 when not mirroring) |
| `s` | spectate | name, target name (empty = stopped watching) |
| `p` | spray chunk | name, pixel crc (int32), raw byte count (int32), total chunks (int32), index (int32), up to 400 payload bytes |
| `q` | spray stamp | name, pixel crc (int32), x, y, z (world position of the decal) |
| `i` | server browser query (1.4.0) | u8 query version (1), u32 request id, u32 challenge (0 = none yet); 14 bytes. Connectionless: see "Server browser query" |

Outgoing packet types (server -> client). The first byte is the type, with no
length prefix.

| Type | Meaning | Payload |
| --- | --- | --- |
| `0` | user connect | name, trail length, trail RGB, ghost RGB, announce byte |
| `1` | user info/update | same fields as `l`, minus the opcode |
| `4` | user disconnect | name, reason code (`left`/`kick`/`timeout`) |
| `5` | kick/reject reason | reason string |
| `6` | chat message | message id (int32), name, message text |
| `7` | connect accepted | none |
| `8` | force map load | map name |
| `9` | server pause | on byte (0/1), overlay label |
| `10` | race status | name, status byte (0 none, 1 READY, 2 LOADING, 3 IN RACE, 4 DONE), isRunner byte, then optionally an "the race has started" byte (0 while the lobby is still open) |
| `11` | heartbeat | none |
| `12` | play sound | path relative to `sound/` |
| `13` | spectate | watcher name, target name |
| `14` | emote pack | the lobby's 7TV pack, tagged `set:`/`user:`/`twitch:` (at most 39 bytes) |
| `15` | spray chunk | name, pixel crc, raw byte count, total, index, payload - the re-encoded blob (see Sprays below) |
| `16` | spray stamp | name, pixel crc, x, y, z |
| `17` | server browser challenge (1.4.0) | u32 request id, u32 challenge; 9 bytes, never C |
| `18` | server info (1.4.0) | see "Server browser query"; at most 512 bytes, never C |

### Server browser query

The mod's "Servers" dialog asks a host it has not joined for its name, version,
players and race - a connectionless request from an address nobody has
verified, which is the shape of a reflection attack. So it works like the
challenge exchange of Valve's A2S queries:

    client  "i" u8(1) u32 id u32 0               14 bytes
    host    17  u32 id u32 challenge              9 bytes
    client  "i" u8(1) u32 id u32 challenge       14 bytes
    host    18  ...                              <= 512 bytes

- **A bare query, or one with a wrong or stale challenge, gets only a type 17**,
  9 bytes for the 14 it sent: answering a forged source address with it
  reflects less than the forger sent. The challenge is an HMAC-SHA256 of the
  asker's address, port and a 15 s time window under a key drawn at startup
  (nothing is stored per asker), cut to 32 bits; it is accepted in its window
  and the next, so it lives 15 to 30 s, and only from that address:port. A
  forger never sees the challenge (it went to the victim), so it never gets the
  full reply; whoever does see it is the address that asked.
- **The full reply is at most 512 bytes** and only ever goes to the address:port
  that showed its challenge.
- **Budgets.** A query is an ordinary datagram first: the global packet ceiling,
  the penalty box, the 512-byte size cap and the per-address and per-session
  budgets all apply before it is parsed, and a truncated one is malformed
  traffic like any other. Then it pays `INFO_RATE_PER_SECOND` / `INFO_BURST`
  for its address and `INFO_GLOBAL_PER_SECOND` for the whole process; over
  either it is dropped in silence (`status` counts it). A stale challenge, an
  unknown query version and `SERVER_INFO=0` are never punished. From the
  endpoint of a v2 session a query needs S like anything else (the game's
  dialog asks from a socket of its own).
- **Nothing about a query touches the roster**: it creates no session, and
  nobody in the lobby is told.

Type 18:

    u8  18
    u32 request id (echoed)
    u8  format (1)
    str server name (SERVER_NAME, <= 63 bytes, UTF-8)
    str ghserver version (package.json, <= 15)
    u8  protocol (2: speaks v2, and legacy unless REQUIRE_PROTOCOL_V2)
    u8  host flags: 1 REQUIRE_PROTOCOL_V2, 2 whitelist on, 4 reads the identity
        block, 8 operator chat commands on
    u8  players online (confirmed sessions - the whole lobby, listed or not)
    u8  slot limit (MAX_PLAYERS)
    u8  race: 0 idle, 1 lobby, 2 countdown to the map, 3 loading, 4 staging,
        5 countdown to the start, 6 racing
    str the map most players are on (<= 31; "" when nobody reported one)
    u8  n players listed
    n x { str name (<= 31), u8 flags: 1 HLSR, 2 operator, 4 spectating,
          8 race runner, 16 sent the identity block, 32 protocol v2 }

The list stops at 32 players, or earlier at the first name that would take the
datagram past 512 bytes, so the count above it is the number to show.
`SERVER_INFO_PLAYERS=0` sends an empty list. No address and no SteamID is ever
in the reply; the operator flag does tell anyone who asks which nickname is an
operator. A host before 1.4.0 does not know opcode `i`: it counts it as an
unknown opcode against the asker's malformed budget (5 a second, 20 at once)
and answers nothing, so the dialog shows it as not answering.

`node test/tools/server-info.js <host> [port]` makes the same exchange over
real UDP and prints the reply (`--wrong-challenge`, `--repeat N`,
`--expect-name TEXT`).

Type `14` carries an identifier and never any artwork: each client hands it to
its own HLSR launcher, which fetches the images. The host never talks to 7TV.
It is sent only when the operator sets `EMOTE_PACK`, and that setting is its
only source: no opcode carries a pack (the mod never had one), so a datagram can
neither change it nor make the host relay one.

- **Who gets it:** the session that joins, and only it. It goes right after the
  accept, ahead of the roster (so it is charged first against a legacy session's
  unconfirmed budget), and a legacy session gets it once more when a follow-up
  packet confirms it, because the mod announces itself only once per session
  and a copy lost in the accept burst would never be asked for again. A v2
  session gets nothing but its accept until its first packet with S; its roster,
  pack first, goes at that moment, and the second copy with the next heartbeat
  (0 to `HEARTBEAT_MS` later, on its own datagram), so a v2 session also gets
  two. The rest of the lobby is not sent it again when somebody joins, and a
  refused connect gets only its refusal.
- **Framing:** `14 C payload` to a v2 session, `14 payload` (the 0.3.2 bytes)
  to a legacy one. The payload is one string, cut to 39 bytes - client.dll reads
  it into `char szPack[40]`; the longest value the config produces is 31.
- **Bounds:** per session, the two copies above, then at most one every 5 s
  however often a roster is re-sent (today only a duplicate connect re-sends
  one, and that is throttled to 5 s as well); every copy to an unconfirmed
  legacy session is charged to its unconfirmed budget like any packet, and one
  that does not fit is not sent. Nothing is kept beyond the
  operator's pack and that count, which ends with the session: a rejoin is a
  newcomer and is fed again. Leaving the lobby is the client's business: the
  mod drops the lobby's pack when it disconnects and goes back to the player's
  own channel.
- **Clients:** the 2026-10-30 build reads it. Builds from 2026-10-22 until then
  have no case for type 14 and drop it unread (with C it is still counted as
  hearing from the host); builds before 2026-10-22 read it as in 0.3.2. A host
  with no pack sends exactly what 1.3.1 sent.

### Protocol v2

ghserver 1.3.0 also speaks protocol v2, in which each session has two 64-bit
secrets, never zero:

- **C (client nonce)**, chosen by the client for each connect. The host puts it
  in front of every packet it sends that session, and the v2 client accepts
  only server packets that carry it. An off-path attacker never sees C, so it
  cannot forge the host's packets to the player.
- **S (server token)**, chosen by the host with `crypto.randomBytes` and sent
  only in the accept, to the endpoint that connected. The client puts it right
  after the opcode of every packet it sends. A forged source address never
  receives S, so a packet carrying it proves the endpoint is real.

Both are 8 raw bytes on the wire:

| Packet | Legacy (v1) | v2 |
| --- | --- | --- |
| client `c` | `"c" name 7×u8` | `"c" name 7×u8 u8(2) C` |
| server type 7 | `07` | `07 C S` |
| every other server→client | `type payload` | `type C payload` |
| every other client→server | `"op" name …` | `"op" S name …` |

**The identity block (1.4.0).** The 1.4.0 build of the mod appends, after C:

    u8(1)  u8 flags  SteamID64 (8 bytes, big endian; zero when there is none)

flags bit 0 = launched from the HLSR launcher, bit 1 = a SteamID follows. It is
read only after a valid v2 tail (the same bytes after a legacy connect mean
nothing), and like the tail it is optional: another first byte, a block cut
short, or a SteamID that is not a public individual account is no identity (or
no SteamID), never an error. Every host before 1.4.0 stops reading a connect
after C (1.3.x) or after the colours (1.2.0, 0.3.2), so it costs them nothing;
a 1.3 client sends no block and its launcher reads as "unknown". A duplicate
announce never changes a session's identity. What the host does with it, and
what it is worth: "What a SteamID is worth" under Access control.

It is compatible both ways. A connect without the tail - every build of the mod
before v2 - is a legacy session, sent exactly the bytes 1.2.0 sent (the
wire-golden tests pin them). A tail that is not `u8(2)` followed by 8 bytes
that are not all zero is a legacy connect too, not an error. Hosts before 1.3.0
stop reading a connect after the appearance, so a v2 client is a legacy session
there, and the bare `07` it gets back tells it so. The largest packets stay
under 512 bytes: a client spray piece is 468 bytes, a relayed one 464.

What a v2 session gets, and what it is held to:

- **A packet from its endpoint without its S, or with a wrong one, is dropped
  before every budget**, the global packet ceiling included, so it never counts
  as trusted traffic anywhere. It is never punished, only counted (`status`:
  "without the v2 token"; `bad-token` in the log, see "Diagnostics" for what it
  means). It cannot be the player. Charging it would let anyone forging the
  player's address:port spend the player's own budgets. Measured with 2000 such
  packets a second, the player's real lines went from 5 of 34 relayed to 34 of
  34. With 5000 a second against a ceiling of 1000, the player's and a
  neighbour's lines went from 9 of 34 each to 34 of 34. Punishing it would let
  them box or kick the player. It is not parsed either, with one exception: a
  connect-shaped datagram while the session is not yet confirmed, because the
  client whose accept was lost never learned S. That one pays the budgets as
  untrusted traffic, like anything for an unconfirmed session, and is parsed;
  with the same nickname and the same C it gets the same `07 C S` again, and
  otherwise it is dropped as a bad token after all.
- **A packet with its S is trusted from the first one**, before the session
  confirms (1.3.1): it skips the address-level penalty box and the shared
  address budget, as a confirmed session's packets do. S went only to that
  endpoint, so the packet proves the endpoint is real. Before 1.3.1 the first
  signed line competed with junk from any other port of the player's IP for a
  boxed address's one-datagram-a-second trickle, and under a sustained flood
  the session never confirmed. Junk that carries S is the real client's: an
  unknown opcode or fields that do not parse are punished as for any session;
  an oversized datagram, or one whose opcode cannot be read, is only logged.
- **It is confirmed by its first packet carrying S**, and nothing else. Until
  then its address gets the accept and nothing more: no roster, no fan-out. So a
  forged v2 announce is answered with 17 bytes, fewer than it sent (measured
  with a 32-byte announce: 0.53x; sending the roster with the accept, as 1.2.0
  does, made it 3.25x in a 3-player lobby and 14x in a 15-player one).
- **The lobby hears of it when it confirms**, not when it connects: the type 0
  join (announce byte 1) goes to the others once, with its first signed packet,
  and the newcomer gets its roster at the same moment. A forged v2 session never
  signs, so nobody is ever told it joined: it is in nobody's roster and cannot
  be spectated, and it leaves without a type 4 when it is swept or evicted -
  unless it silently took over a name the lobby already knew, whose ghost must
  then be removed. Forged v2 sessions never confirm, so
  on a full server they are the first evicted (after 3 s). Legacy sessions are
  announced at connect, as in 1.2.0.
- **Once confirmed it is return-routable**, so the position relay and the spray
  drip do not charge it outbound credit. Measured: a v2 receiver at 10 lines a
  second against 15 senders at 66 got 5925 of 5925 positions (1.2.0's
  metering: 5886). The liveness gate stays: a v2 receiver with no accepted line
  for `LIVENESS_MS` gets no position or spray fan-out, like any session, so a
  crashed client's port is not fed until the stale timeout.
- **The impersonation guard is never armed for it.** Packets naming it from
  other endpoints are refused, as for any session.
- **Once confirmed, its name and its slot stay its own while it is live**
  (1.3.1). It is removed only by its own goodbye (a `d` with its S), by the
  sweep once it has been silent for `STALE_TIMEOUT_MS`, or by the server (a
  console `kick` or ban, or junk that carried its S). No connect from another
  endpoint carries its S, so none takes the name over before the session is
  stale - not even from the player's own IP, which a spoofer or a CGNAT
  neighbour can send from too, and which used to need only `TAKEOVER_AFTER_MS`
  (10 s, one level load) of silence. An unsigned connect from its own endpoint
  is a bad token, so it cannot rename the session either. The squat eviction's
  rate rule never picks it: that rule exists against forged sessions, and the
  only v2 player it could pick is a real runner who is loading or idle. The
  price: a v2 player whose game crashed gets the name back
  after up to `STALE_TIMEOUT_MS` (60 s), not 10 s, and an idle v2 player keeps
  a slot on a full server until the sweep. A v2 session that never confirmed
  proved nothing and is displaced, swept and evicted like any unconfirmed one.
- C and S are never logged.

`REQUIRE_PROTOCOL_V2=1` refuses legacy connects. Roll it out in this order:

1. Deploy ghserver 1.3.0 or later, which accepts both v1 and v2 (`update.sh`
   on the host). Players on older builds notice nothing.
2. Publish the mod build with the v2 client. Players who update are v2 sessions
   from their next connect.
3. Once players have updated, set `REQUIRE_PROTOCOL_V2=1`. Until then every
   legacy session keeps the 1.2.0 containment and the 1.2.0 residual risks
   below.

### Sprays

A spray is a deflated VTF the sending client built from a local picture; it is
the only artwork that crosses this wire (emotes are fetched by each client's
launcher, but a spray has to work in singleplayer with nothing else running).
The host now **inspects** every spray before relaying it: the `GHS1` magic, a
declared size that must be one of the sizes the client's own VTF writer
produces, a bounded inflate to exactly that size, the VTF header matched
byte-for-byte against that writer's output, and the pixel CRC. It then relays a
blob it re-encoded with a current zlib (level 6), so shipped clients only ever
inflate a stream the host produced. A picture that fails any check is dropped
with no fan-out and one sampled log line. The re-encode is 1-2 % larger than the
client's own level-9 output, and a receiving client accepts at most 163840 B -
the same as the upload cap, so there is no headroom - which means a photo-like
256x256 spray of more than about 160 KB can come out too large: it is refused
(never relayed in its original encoding) and its sender is told to use a
smaller or flatter picture. The relay packets for a picture are built once
and shared by every receiver through a cursor, so relay memory is bounded by the
number of players, not its square.

Chat messages carry an incrementing id so clients can drop UDP duplicates; the
sender's own message is delivered back by the server, which keeps ordering
consistent for everyone.

The type `0` **announce byte** is `1` for a fresh join and `0` for the silent
roster entries a client receives about players already present. The type `4`
**reason code** tells the client which chat line to show.

Every outgoing string is truncated to the size of the buffer the client reads it
into. Those sizes live in `src/wire/limits.js` with the file and line of the
mod source they come from.

## Speedrun race

Typing `/race` in chat opens a 60-second lobby; other players `/ready` to join.
Warnings fire at 30 s and 10 s; only one race runs at a time. On lobby close the
host counts down, force-loads everyone onto the `start` save (type 8), tracks
loading via the `l` map field, freezes each runner at the pre-teleport point
(type 9) reported via the `r` checkpoint, releases them together, and marks
finishers in order when they hit the `d3_breen_01` end trigger.

`/leave` drops out of a race at any point, and unlike a disconnect it lifts the
server pause on the way out — a runner frozen at the start line would otherwise
be told they are no longer racing and left stuck behind the overlay. The race
carries on for everyone else, and if the leaver was the last one it is cancelled.
Someone who has already finished can leave without ending the race for the
runners still on the course. Unlike `/race` and `/ready`, `/leave` is not gated
by `RACE_SPECTATORS`: that gate stops a bystander taking the race lock, and it
must never stand between a runner and the exit.

A finish announcement carries the runner's own clocks: `IGT:` is the mod's
timer, and `LiveSplit:` is added next to it when that runner is mirroring
LiveSplit (`gh_timer_mirror 1`). Both numbers come from the finisher's client,
exactly like the checkpoint itself, so they are the runner's word - see the
security model below.

A player who is not racing is put into spectator mode by the mod and is not
drawn for the runners. This starts when the lobby closes, not when it opens, so
everyone keeps the full minute to `/ready` in; it ends when the race does. A
client joining mid-race is sent the current statuses along with the roster,
because status packets are only broadcast when they change and a newcomer would
otherwise have no way to know a race was on. The mod leaves a player alone if
their own run timer is going, and `gh_online_race_autospectate 0` turns it off
entirely.

Having a save named `start` is not the same as that save being the start of the
game. The client checks the file exists; the host checks where it actually put
the player. A runner who lands on a third map is told which map their save
loads, taken out of the race, and the others carry on - instead of the race
waiting for a map report that is never coming and expiring for everybody.

Every waiting phase has a deadline. If a runner never finishes loading or never
reaches the start, the race is cancelled and everyone is released, rather than
leaving players behind a pause they cannot lift.

## Security model

There are two kinds of session now, and they are not equally protected.

**Protocol v2 sessions are authenticated both ways against an off-path
attacker, once the client has its accept.** Someone who can forge source
addresses but cannot see the traffic between the player and the host can
neither speak as a v2 player (no S) nor forge the host's packets to them (no
C). That rules out chat, race actions, goodbyes and sprays in the player's
name, reflection off their session, holding slots with forged v2 announces,
and a fake kick, force-map, pause or `SERVER` chat aimed at them. Since 1.3.1
it also rules out disconnecting a confirmed v2 player through the server: no
connect from another endpoint takes their name over while the session is live,
not even one from their own IP, and the squat eviction never picks them (see
"Protocol v2"). Two things are left. **An on-path observer can read C and S** -
anyone on the same Wi-Fi, at the ISP, anywhere the packets pass - and can then
do all of that to the session they watched; stopping that needs encryption,
which the protocol does not have (residual risk 10). And **the connect
handshake itself**: for about one round trip the updated client does not yet
know whether the host speaks v2, and a forged legacy accept that wins that
race makes it believe unprefixed packets until the real accept arrives
(residual risk 11).

**Legacy sessions keep the 1.2.0 containment.** A legacy session is one from a
build of the mod older than protocol v2, and there will be some until the
operator sets `REQUIRE_PROTOCOL_V2=1`. The next three paragraphs, and the guard,
the metering and the squat eviction in the list below, are about them; the rest
of the list applies to every session.

**What the server can prove about a legacy session.** A datagram arrived from a
particular address and port. That is all.

**What it cannot.** Clients older than protocol v2 send no session token, no
shared secret and no signature. So the source address is the only evidence of
ownership, and UDP source addresses are forged trivially.

Concretely, an attacker who knows a player's nickname, address **and** current
ephemeral port can chat as them, move their ghost and report race checkpoints
for them. Guessing the port means finding one value out of 65536. **No amount of
server side work fixes the case where the attacker guesses the live 5-tuple** -
that needs the session secret only protocol v2 carries. And finding the port is
fast: a forged position update from the real port is relayed like the player's
own, so a sweep of the player's IP reads it back in about a second. What the
server does is notice the sweep and contain it to the one session for a short
time: datagrams naming that session from 8 ports of its own IP within 30 s put
it under the impersonation guard (above) for 3 minutes. On a legacy session,
a competent attacker who can spoof the player's IP can still impersonate a
non-operator player after waiting that out; the guard is an alarm and a short
containment, and the operator PIN closes the operator case. Other players
behind the same NAT keep full use of the server while one of them is guarded.

The mitigations that exist:

- every opcode except connect is accepted only from the exact address:port that
  registered the nickname; a sweep of the session's own IP trips the per-session
  impersonation guard (above), which for 3 minutes refuses chat, commands,
  sprays, goodbye and renames from that endpoint (positions still relay, a race
  finish is accepted but marked unverified). A packet from the exact owner
  5-tuple outside a guard is accepted as that owner (unavoidable), which is why
  operator commands require a PIN;
- a disconnect is not applied for two seconds, and any packet from the real
  client in that window cancels it, so a single forged datagram can no longer
  remove a player;
- a connect-only session receives almost nothing and is swept in 20 seconds.
  This is a traffic budget, **not a return-address challenge**: a second forged
  packet can mark that same address:port confirmed without reading a reply. So
  the high-volume fan-out (the 50 Hz position relay and the spray drip) is
  **metered**: a session earns outbound credit by sending, and the fan-out is
  skipped for one that has gone silent (`LIVENESS_MS`) or spent its credit. A
  session's credit comes only from its accepted position updates and is sized so
  a real client at the slowest update rate is still fully served. The price is
  that a forged confirmed session gets what such a slow real client gets: at
  most about (players - 1) x 66.7 / `OUTBOUND_RECEIVER_FLOOR_PPS` x (largest
  info packet / 100 B) bytes out per byte in - measured ~185x in a 16-player
  lobby (69x for the audit's one-packet-a-50-s forger), against 10765x before.
  It scales with the lobby, and the forger must keep sending a position at least
  every 3 s. Protocol v2 closes it for the clients that speak it: a v2 session
  confirms only with S, so it cannot be a forged one, and its fan-out is not
  charged credit (the liveness gate still applies);
- keeping the server "full" with forged sessions is made expensive, not
  impossible: when every slot is taken, a newcomer first evicts a session that
  never confirmed (older than 3 s; an unconfirmed takeover no longer resets its
  age), then the confirmed session with the lowest rate of accepted position
  updates if that rate is below `SQUAT_EVICT_PPS` and it has been confirmed long
  enough to judge. Chat and other packets do not count. With legacy sessions a
  forger can still hold slots by streaming 3 position updates a second per slot
  (~0.3 KB/s each), so this raises the cost rather than closing it - the
  threshold is set for runners doing save/load spam first. A forged v2 session
  never confirms, so it is always the first choice, and a confirmed v2 session
  is never evicted by the rate rule (1.3.1);
- one address may hold at most four slots, so a single host cannot fill the
  server by rotating its source port;
- a ban and the whitelist are checked before anything touches the roster, and a
  refusal to a connect that only got through on the anti-lockout reserve is
  silent, so neither can be used to bounce a packet at a forged address;
- sprays are validated before they are relayed and re-encoded with a current
  zlib (see Protocol) under a server-wide budget with a fair queue, a session,
  its address and its name may publish only a couple of distinct pictures a
  minute and a bounded number per session, and the reserved host name `SERVER`
  is refused on a confusable skeleton (so accented, Cyrillic, Greek, Cherokee,
  small-capital and fullwidth lookalikes and bidi tricks cannot impersonate the
  host in red).

The lists themselves prove nothing about who is on the other end: see access
control above.

**Client-side, which the server cannot fix.** A client older than protocol v2
trusts any datagram whose source IP:port is the configured server's, with no
session secret and no rate limit. An off-path attacker who knows such a
player's IP and spoofs the server's address can force-load their `start` save,
pause them, or feed them fake `SERVER` chat. The v2 client accepts only server
packets that carry its C, which closes this for players who update once their
client has its accept from a v2 host. Before that, and for good on a host older
than 1.3.0, the updated client is a legacy one in this respect, with a race gate
that stops only a lone forged force-map or pause (residual risks 9 and 11).

**What the server does not attempt.** The race is scored from checkpoints the
client reports. A modified `client.dll` can report a finish it did not earn.
This is not anticheat and is not described as one anywhere in the code.

**Traffic that is refused before it is parsed.** Datagrams over 512 bytes, and
anything from an address that has spent its malformed-traffic budget. Everything
else passes a global ceiling, a per-address budget and a per-session budget
first, so a flood costs a few integer operations rather than a parse and a log
line.

**Logging.** Untrusted text is escaped before it reaches the terminal -
including bidi marks and line separators, which could otherwise reorder or
rewrite a log line - and every attacker-triggered event, now including the `d`
path and spray publications, is sampled rather than printed per packet. A probe
cannot fill the disk or write escape sequences into the operator's console.

## Limits of UDP

- **There is no connection.** Every datagram is independent, and a forged source
  address is indistinguishable from a real one at this layer. Ask the upstream
  network for BCP38 / uRPF filtering if it is available.
- **Nothing is encrypted.** Chat, nicknames, map names and positions are on the
  wire in plain text, and anyone on the path can read or alter them. The server
  does not pretend otherwise: there is no "encryption" setting, because adding
  one without changing the clients would be a lie. Protocol v2's C and S travel
  in the clear too: they stop an off-path forger, not someone who can read the
  traffic.
- **Delivery is not guaranteed and order is not preserved.** Position updates
  are sent 50 times a second precisely because losing one does not matter.
- **Amplification is inherent.** One inbound update becomes one outbound packet
  per player. For a confirmed legacy session the metered fan-out caps the
  multiplier at the fan-out ratio of the slowest real client (~185x measured in
  a 16-player lobby, roughly 12x per other player); it cannot remove it, and a
  flood of small packets still arrives on the interface. A confirmed v2 session
  cannot be a forged one, so its fan-out is not charged credit and reflects at
  nobody; an unconfirmed one is sent 17 bytes per announce.

## Residual risks

These are known and unfixed. They are listed so an operator can decide, not to
be reassuring. Risks 1, 3 and 9 are about legacy sessions (clients older than
protocol v2): a v2 session is closed to them against an off-path attacker, and
risk 10 is what is left for it. They stay open for as long as legacy clients
may connect - until `REQUIRE_PROTOCOL_V2=1`, the last step of the rollout under
"Protocol v2". Risks 11 to 14 are in the updated mod's client, not in the
server, and are listed here because operators and players meet them here.

1. **Impersonating a legacy player whose address:port is known.** Unfixable
   without protocol v2: a datagram forged from a player's exact live 5-tuple is
   accepted as them, and a sweep of their IP finds the port in about a second
   through the position relay. The sweep trips the per-session impersonation
   guard: for 3 minutes chat, commands, sprays, goodbye and renames from that
   endpoint are refused, a race finish is marked unverified, the player is told
   and the log is alerted. After that an attacker who kept the port and can
   spoof the player's IP can chat, spray, race or disconnect them as that player,
   and a sweep slow enough to stay under the trigger is not seen at all. A forged
   position always moves the player's ghost. Operator commands also need the
   PIN, which the attacker cannot observe, so the operator case is closed. The
   guard itself can be tripped on purpose - by a spoofer, or by someone sharing
   the player's IP - to pause their chat and races for 3 minutes at a time; the
   console `unguard "Nick"` lifts it. Datagrams the whole-process packet ceiling
   (`GLOBAL_PACKETS_PER_SECOND`) drops are never looked at, so a volumetric
   flood that saturates the share of that ceiling for unconfirmed traffic -
   on the order of 10^5-10^6 packets a second, held for the length of the
   sweep - can hide a slow sweep from the guard; such a flood also stops every
   new player from joining, so it does not go unnoticed.
2. **Race results are client-reported.** A modified client can win instantly.
   This is not anticheat; demo-based verification is the intended future path.
3. **A forged confirmed legacy session can still reflect at the fan-out ratio.**
   The metering brings the multiplier down from ~10000x to ~185x (16 players; it
   grows with the lobby, ~12x per other player) and starves a
   silent forged endpoint, but a forger willing to keep sending at the real rate
   is, by construction, indistinguishable from a real legacy client. A forged v2
   session never confirms. Volumetric floods still need upstream filtering.
4. **A ban is a name and an address, and neither identifies anybody.** A kick
   still only disconnects; the ban list is what keeps somebody out, and what it
   holds is a nickname the player can change and an address they may be sharing
   with innocents or able to change too. It is enough for the ordinary case -
   the person spoiling the game leaves and stays gone - and it is not a
   permission system. Since 1.4.0 a ban can also name the SteamID a client
   announces, which an honest client cannot shed by renaming - but it is
   self-reported (risk 16); the firewall is still the layer that stops somebody
   determined.
5. **Player addresses appear in the log**, and since 1.4.0 the SteamIDs clients
   announce. `list`, connect lines and rate-limit events all include them. If
   that matters for your jurisdiction, rotate and restrict the log.
6. **One player can block races for the whole server** for the length of the
   lobby plus the loading timeout by starting a race and never loading. Lower
   `RACE_LOADING_TIMEOUT_MS` if this is abused, or use `race cancel`.
7. **A determined flood still costs bandwidth.** The server stops parsing early,
   but the packets still arrive on the interface. Rate limiting at the firewall
   is the layer that helps.
8. **Sprays are moderated only by `sprayban`.** The host proves a spray is a
   well-formed VTF whose pixels hash to the id the sender claims, but it does not
   look at what the picture depicts; an operator takes an offensive one down with
   `sprayban`, which also drops the copy already published.
9. **A legacy client trusts the server's address with no secret.** An off-path
   attacker spoofing the server's IP can grief such a player directly
   (force-load, pause, fake chat). Server-unfixable; the v2 client checks C
   once its accept from a v2 host has arrived (see 11 and 12 for before that).
10. **An on-path observer can read C and S.** Protocol v2 authenticates a
    session against an off-path attacker only. Anyone who sees the traffic
    between a player and the host - the same Wi-Fi, the ISP, a router on the
    path - reads C and S in the clear and can then do to that session what an
    off-path attacker can do to a legacy one: speak as the player, forge the
    host's packets to them, hold their slot. Closing that needs encryption,
    which is not proposed. A v2 session is also bound to the address:port it
    connected from: a client whose NAT moves it to a new port mid-session is
    not followed there and has to reconnect, as a legacy one does.
11. **The updated client's connect handshake.** For about one round trip after
    it announces itself, the updated client does not know whether the host
    speaks protocol v2: an old host answers with a bare accept (type 7 alone),
    a v2 host with one that carries C and S. An attacker who spoofs the host's
    address, knows the player's IP and the port their game has just opened, and
    gets a fake bare accept to them before the real one arrives, makes the
    client treat the host as an old one until the real accept comes in (usually
    a round trip later; the client then switches to v2 by itself). In that
    window it believes packets without C: a fake kick disconnects the player,
    and a fake race status naming them a runner, followed by a fake forced map
    load or pause, is obeyed. A flood of packets without C, combined with a
    real accept that got lost, does the same. It needs spoofing, the right port
    and the right moment, which the attacker cannot see; an established v2
    session is not affected. Not fixed: the fix (treat a bare accept as
    provisional for up to a second) would delay every connect to an old host.
12. **The race gate stops only a lone forged packet where there is no C.** The
    updated client ignores a forced map load (type 8) or pause (type 9) unless
    it has seen a race lobby it is in. On a link without C - a host older than
    1.3.0, or the window in risk 11 - that race lobby can be faked too: a fake
    race status naming the player as a runner, sent first, gets a fake forced
    load or pause past the gate. On such a link a fake kick disconnects the
    player anyway (risk 9). With a v2 host every one of these needs C.
13. **A big lobby on a host older than 1.3.0, when the accept is lost.** While
    the updated client waits to learn the host's version it keeps what the host
    sends in a queue of 32 packets. A host older than 1.3.0 sends the whole
    roster (and spray pieces) together with its accept. If that bare accept is
    lost in a big lobby, what does not fit is dropped and is not sent again, so
    a few players stay invisible to that client until it reconnects. A host on
    1.3.0 or later sends a v2 client nothing but its accept until the client
    has answered with S, so it does not happen there.
14. **Two copies of the game on one PC (`-multirun`).** At startup the mod
    deletes the cached copies of other players' sprays from its previous
    session. A second copy started while the first is online deletes the
    first one's cache too, so in the first copy a spray it already received
    may not draw when it is stamped again. Players do not run two copies; it
    matters for testing only.
15. **A forged emote pack where there is no C.** Type 14 names a 7TV set for
    the player's launcher to show. A client that believes packets without C -
    a build older than protocol v2, or the updated one in the window of risk 11
    - can be sent a fake one by an off-path attacker spoofing the host, and
    then shows that set's pictures instead of the lobby's (or the player's own
    channel's) until it leaves the lobby. The client checks only the shape of
    the identifier, so the set itself is the attacker's choice. With a v2 host
    it needs C. The host does not look at what the operator's set contains
    either: 7TV serves whatever is in it today.
16. **The SteamID and the HLSR flag are the client's word.** No Steam ticket is
    checked. A modified client can announce another player's SteamID (they are
    public) or none: a SteamID ban stops only an honest client, a SteamID
    whitelist entry admits whoever claims it, and a SteamID operator entry is
    as strong as its PIN (with `OP_ALLOW_NO_PIN=1`, not at all). Making it a
    login would need Steam session tickets checked against Steam's Web API,
    which this host does not do. See "What a SteamID is worth".
17. **The server browser shows who is on the server to anyone who asks.** The
    type 18 reply lists the nicknames online with their HLSR, operator,
    spectator and runner flags (never an address or a SteamID).
    `SERVER_INFO_PLAYERS=0` keeps only the count; `SERVER_INFO=0` answers
    nothing. Its reflection bound: 9 bytes back for a 14-byte forged query;
    the full reply only to the address:port that showed its challenge.

### Client follow-ups (the protocol v2 mod build, not server work)

- protocol v2 itself: C in front of every server packet, S after the opcode of
  every client packet, and a legacy fallback for older hosts. The server side is
  in ghserver 1.3.0; players who update close risks 1 and 3, and risk 9 once
  their client has its accept from a v2 host (risks 11 and 12 are what is left
  before that);
- relink the client's zlib (1.2.5, 2010) to a current release;
- validate a spray before writing it to disk and keep remote blobs in a cache
  cleaned at start;
- ignore the force-map (type 8) and pause (type 9) packets unless a race lobby
  has been seen (on a link without C this stops a lone forged packet only, risk
  12).

## Deploying on Ubuntu 24.04

Everything below is scripted in `deploy/`. The installer is idempotent, so
re-running it picks up a new release and re-asserts permissions.

**Build a release** (on any box with Node and GNU tar):

    npm run release
    # -> dist/ghserver-<version>.tar.gz and its .sha256
    # the tarball excludes legacy/, test/ and scripts/ (dev only)

**Install** (as root, from the unpacked tarball):

    tar xzf ghserver-1.4.0.tar.gz -C /tmp/ghserver-release
    sudo /tmp/ghserver-release/deploy/install-ubuntu.sh

That installs Node 24 from NodeSource (signed-by keyring whose fingerprint
`6F71F525282841EEDAF851B42F59B5F99B1BE0B4` is checked before it is trusted; no
`curl | bash`), creates the `ghserver` system user (no shell, no home) and the
`ghsadmin` group, copies the code to `/opt/ghserver` **root-owned and read-only to
the service**, puts state under `/var/lib/ghserver` (a systemd `StateDirectory`,
0700) and the config at `/etc/ghserver/ghserver.env` (0640 `root:ghserver`),
installs the hardened unit and the `ghserver-console` helper, enables
`unattended-upgrades` for NodeSource's repository too (matched by
`site=deb.nodesource.com`) with no automatic reboot, and renders the firewall
ruleset **without activating it**. Re-running it from a newly unpacked release
upgrades in place and restarts the service if it was running; it refuses to run
from `/opt/ghserver` itself.

If `/etc/ghserver/nftables-ghserver.conf` is the ruleset an earlier 1.2.0
pre-release installed (it flushes the whole ruleset), a re-run moves it to
`nftables-ghserver.conf.bak.<date>` and renders the new one, and says so.

In `ghserver.env` put one `KEY=value` per line and nothing after the value:
systemd does not strip a trailing `# comment`, it becomes part of the value and
the server refuses to start.

An automatic Node.js security update can restart the server (Ubuntu's
`needrestart` restarts services still running the old binary). That ends a race
in progress and disconnects everyone ("Server is shutting down."): the client
does not reconnect by itself, so players reconnect by hand with
`gh_online_connect` in the game console once the server is back (a few
seconds). To choose the moment yourself, add `"nodejs";` to
`Unattended-Upgrade::Package-Blacklist` and update by hand.

The hardened unit (`deploy/ghserver.service`) runs read-only out of
`/opt/ghserver` - a compromise cannot rewrite the code and survive a restart -
with `StateDirectory`, `UMask=0077` and the full systemd sandbox. Check it with
`systemd-analyze security ghserver` and run `npm run load` against it once.
`systemctl reload ghserver` re-reads the access file (it sends `SIGHUP`).

**The console over SSH.** The unit creates a FIFO, `/run/ghserver/console`
(0620 `ghserver:ghsadmin`), and the server opens it itself (`CONSOLE_FIFO`), so
an operator never needs a shell as the service user. The console is not a
dependency: the server starts and runs without it (a missing `ghsadmin` group
just means no console, said in the journal), and writing to it never starts a
stopped server.

    sudo usermod -aG ghsadmin <you>     # log out and back in
    ghserver-console status
    ghserver-console 'ban "Griefer" 2h spamming'
    ghserver-console reload
    ghserver-console                    # then type: op "Nick" 482913

Approve an operator with **no arguments** and type the command at the prompt (it
is not echoed): as an argument the PIN would sit in your shell history and be
visible in `ps`. Replies go to the journal.

**Logs:**

    journalctl -u ghserver -f
    journalctl -u ghserver | grep -c 'penalty-box'   # how often addresses were boxed

**Firewall.** The server's own limits protect the process, not the link. The
installer renders `/etc/ghserver/nftables-ghserver.conf` for the game `PORT`
from the env file and every port sshd listens on (Ubuntu 24.04 socket-activates
sshd, so `ssh.socket` is read as well as `sshd -T`). Review it - restrict the
SSH rule to your admin networks if you can - and apply it:

    sudo /opt/ghserver/deploy/firewall-apply.sh

That takes a copy of the file (`/var/lib/ghserver-fw/pending.conf`), checks the
copy (comments stripped, a real `tcp dport <port> accept` for every sshd port,
the game port open, no `flush ruleset`), runs `nft -c` on it, then schedules a
rollback with `systemd-run` **before** loading that copy, so the rollback fires
in 120 s even if your SSH session dies. Because the ruleset keeps
established connections, the session you applied from proves nothing about new
logins - so **confirm from a NEW ssh connection**:

    sudo /opt/ghserver/deploy/firewall-apply.sh --confirm

It refuses to confirm from the session that applied the change, and it refuses
if the file was edited after it was applied (the edit was never loaded or
tested - apply again). What is kept is exactly the copy that was applied. If the
new connection cannot get in, do nothing: the previous rules come back on their
own (`--rollback` undoes it at once); if the previous rules cannot be restored,
the ghserver table is removed instead and the journal says so. If even that
fails, the script says so, exits non-zero and keeps the change pending so
`--rollback` can be run again - it never claims a removal that did not happen.
`--rollback` with nothing pending changes nothing (the live rules are the
confirmed ones, the same as at boot). On confirm that copy is included from
`/etc/nftables.conf` and `nftables.service` is enabled, so it loads at boot;
the live ruleset is never dumped (that would bake the meter's dynamic entries
into the file). Check any file without touching the system with
`firewall-apply.sh --check FILE`.

The ruleset owns one table, `inet ghserver`, replaced atomically; it never
flushes the ruleset, so ufw, Docker and fail2ban keep theirs. It keeps loopback,
established/related, SSH, DHCPv4 and DHCPv6 replies, ICMPv6 (neighbour discovery
and router advertisements) and a trickle of ICMPv4, `notrack`s the game port so
the per-IP meter actually bites (the old `ct state established accept` example
let the flood past), and drops UDP longer than 520 bytes. Per-IP limits do
nothing against a flood from random spoofed sources; that needs upstream BCP38
or your provider's DDoS service.

**Update and rollback:**

    sudo /opt/ghserver/deploy/update.sh ghserver-1.2.1.tar.gz

The previous build is kept as `/opt/ghserver.prev`, state and config are left
alone, and a build that does not come up healthy (service active and the UDP
port bound) is rolled back automatically. `systemctl stop` sends SIGTERM: the
server tells every player it is going away, releases anyone frozen by a race
pause, and frees the port for the restart. `deploy/uninstall.sh` removes the
service and code and keeps state unless you pass `--purge`.

**Do not deploy `legacy/index.js`** as a fallback: it binds 22228 with none of
the parser, session, reflection or spray protections here. It is kept only for
the byte-compatibility tests and is excluded from the release tarball.

### PM2 (development only)

    pm2 start index.js --name ghserver --time
    pm2 save

PM2 has no sandbox and runs as whoever started it (often root); use systemd in
production. A memory backstop is reasonable, but size it per lobby:
`MAX_PLAYERS × ~170 KB` of sprays plus the process base, so about 256-384 MB at
16 players - not the old `--max-memory-restart 256M`, which with the pre-fix
per-player² spray memory produced a restart loop.

## Diagnostics

    status                 in the console: counters, limiter drops, race phase,
                           list sizes, and whether the access file is being written
    list                   who is connected and whether a follow-up packet arrived
    banlist                the bans in force, with what is left of each term
    sprays                 who published a picture and who is still being sent one
    journalctl -u ghserver -f            live log
    journalctl -u ghserver | grep -c 'penalty-box'   how often addresses were boxed
    ss -lunp | grep 22228                confirm the socket is bound
    node --check index.js                syntax check before a restart

If players report ghosts freezing, look for `send-failed` in the log: it names
the destination and the errno. If they report being unable to connect, look for
`connect-limit`, `server-full` or `address-slot-limit`. `hijack-attempt`,
`impersonation guard on`, `squatter-evicted` and `spray-invalid` name the
anti-abuse defences firing.

`bad-token` is a packet from a v2 session's endpoint without its S, or with a
wrong one. It is dropped and changes nothing. Whether it is forged depends on
the build of the mod:

- builds older than protocol v2 are legacy sessions and never cause it;
- the first protocol v2 test builds sent position lines in the round trip
  before their accept arrived, so each of their connects logs a few from the
  player's own endpoint: one on a LAN, three to five over the internet;
- the released v2 build sends nothing but its announce until it has S, and
  every packet after that carries S. From it you see `bad-token` only when the
  network delivered a re-announce after the session had already confirmed, or
  when every answer to its announce was lost: the client then gives up and
  talks legacy to a session the host holds as v2, until one side times out.

So one to a few around a player's connect are harmless; a steady stream from
one endpoint means someone is forging that player's address:port.
`wrong-owner-v2` is a datagram from another port naming a v2 session; it does
nothing either. `orphan-v2` is a v2 client still talking to a host that has
forgotten its session (after a restart, a kick or a sweep) until it times out;
it is not punished.
Edit `access.json` and run `reload` (or send `SIGHUP`) to apply bans without a
restart.

## Tests

    npm test        node:test suites, including 50000 fuzz datagrams
    npm run check   node --check over every file, and the legacy checksum
    npm run load    16 clients at 50 updates/s for 60 seconds, on loopback

`npm run load` takes about ninety seconds and prints a JSON report: throughput,
delivery ratio, event loop lag, memory, and what the connect storm and log flood
phases did.

Two smoke tests run against a live host over real UDP - a local one, or the
deployed one after an update - and end with `RESULT: PASS` or `RESULT: FAIL`:

    node test/tools/smoke-remote.js <host> [port] [clients] [seconds] [pps] [--v2] [--suffix TEXT] [--emote-pack VALUE|none]
    node test/tools/smoke-spray.js <host> [port] [spray] [--v2] [--spray-dir DIR] [--suffix TEXT]
    node test/tools/server-info.js <host> [port] [--wrong-challenge] [--repeat N] [--expect-name TEXT]

`server-info` asks the way the mod's "Servers" dialog does and fails when the
challenge is larger than the query, the reply is over 512 bytes, or nothing
answers (a host before 1.4.0 does not).

`smoke-remote` connects fake clients that move, chat and leave, and checks each
one receives at least 95 % of the others' positions. `smoke-spray` uploads a
spray at the client's pace and checks two receivers rebuild it byte for byte
and get its stamp; with `--spray-dir` (or `GH_SPRAY_DIR`) it uses a real
`<spray>.ghs` and `.vtf` the mod wrote, otherwise a synthetic picture. With
`--v2` the clients announce protocol v2 and handle C and S the way the mod's
client does, and the run also fails if the host answered as a legacy host or
sent anything without C or over 512 bytes. Run both with and without `--v2`
after an update: the legacy run is the players who have not updated yet. Each
run adds a random suffix to its nicknames (`SmokeA_3f9c`), so a rerun is not
refused while the host still holds the last run's names; `--suffix TEXT` picks
it, and `--suffix ""` gives the bare names. `smoke-remote` prints the emote pack
(type 14) each client was sent; `--emote-pack set:<id>` (the normalised form the
host logs at startup) fails the run unless every client got exactly that pack,
and `--emote-pack none` fails it if any did. Every client is sent it twice; a v2
client's second copy comes with the next heartbeat.

## Credits

Thanks to:
- [Gocnak](https://github.com/Gocnak) for original server on Java and Ghosting itself.
- [InfiniteC0re](https://github.com/InfiniteC0re) for rewriting server core on JS.
