#!/usr/bin/env bash
# Apply the ghost-host nftables ruleset WITH an automatic rollback, and keep it
# only once you have proved - from a NEW ssh connection - that you can still log
# in.
#
#   sudo /opt/ghserver/deploy/firewall-apply.sh            # apply, rollback in 120 s
#   sudo /opt/ghserver/deploy/firewall-apply.sh --confirm  # from a NEW ssh session: keep it
#   sudo /opt/ghserver/deploy/firewall-apply.sh --rollback # undo now
#        /opt/ghserver/deploy/firewall-apply.sh --check FILE   # guard only, no changes
#
# Why a new session: the ruleset accepts established connections, so the session
# you apply it from survives even when the SSH rule you just edited blocks every
# NEW login. Confirming from the same session would prove nothing; you would
# find out at your next login.
#
# Why systemd-run: a rollback started as a background job of this script dies
# with it when the SSH session drops (SIGHUP to the process group). A transient
# systemd timer does not: if you lose the box, it restores the previous rules
# on its own after ROLLBACK_SECONDS.
#
# What is applied is a COPY of the file taken at apply time (pending.conf): the
# guard and nft's own check run on that copy, nft loads that copy, and --confirm
# persists that copy - never the editable file, which may have been changed
# since (and is refused if it was: apply again).
#
# Only the table "inet ghserver" is touched; the rest of the ruleset (ufw,
# Docker, fail2ban) is never flushed or rewritten.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-ghserver.sh
. "$HERE/lib-ghserver.sh"

RULESET_DEFAULT="/etc/ghserver/nftables-ghserver.conf"
ROLLBACK_SECONDS="${ROLLBACK_SECONDS:-120}"
# The GHS_* overrides exist for the test suite (stubbed nft/systemd); sudo's
# env_reset drops them for a normal run.
STATE_DIR="${GHS_FW_STATE_DIR:-/var/lib/ghserver-fw}"
APPLIED="$STATE_DIR/applied.conf"     # the last CONFIRMED ruleset (what boots)
PREVIOUS="$STATE_DIR/rollback.conf"   # what a rollback restores
APPLYING="$STATE_DIR/pending.conf"    # the copy that was applied, awaiting --confirm
PENDING="${GHS_FW_PENDING:-/run/ghserver-fw.pending}"    # an applied, not yet confirmed, change
NFT_MAIN="${GHS_NFT_MAIN_CONF:-/etc/nftables.conf}"
SESSION_FILE="${GHS_FW_SESSION_FILE:-/proc/self/sessionid}"
UNIT="ghserver-fw-rollback"
SELF="$HERE/firewall-apply.sh"

need_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "run as root (sudo)." >&2
		exit 1
	fi
	if ! command -v nft >/dev/null 2>&1; then
		echo "nft not found. Install nftables: apt-get install -y nftables" >&2
		exit 1
	fi
}

# The audit-login session of whoever runs this. It survives sudo and is new for
# every ssh connection, so it tells "the same session" from "a new one".
# 4294967295 means unset (no pam_loginuid, e.g. some consoles).
session_id() {
	local id
	id="$(cat "$SESSION_FILE" 2>/dev/null || true)"
	if [ -z "$id" ] || [ "$id" = "4294967295" ]; then id="unknown"; fi
	printf '%s\n' "$id"
}

# 0700 state directory. (mkdir + chmod rather than install -d -m, which the
# test suite's Windows bash cannot do; the result on Linux is the same.)
state_dir() {
	( umask 077; mkdir -p "$STATE_DIR" )
	chmod 0700 "$STATE_DIR"
}

sha_of() {
	sha256sum "$1" | cut -d' ' -f1
}

cancel_timer() {
	systemctl stop "$UNIT.timer" "$UNIT.service" >/dev/null 2>&1 || true
	systemctl reset-failed "$UNIT.timer" "$UNIT.service" >/dev/null 2>&1 || true
}

# Never leaves the unconfirmed table live: if the previous ruleset cannot be
# restored (nft refuses it now), the ghserver table is deleted instead, which
# falls back to whatever else the host has (ufw, or nothing) rather than to
# rules nobody confirmed.
# Removes the ghserver table; 0 when it is gone afterwards (or was never there).
remove_table() {
	local err
	if err="$(nft list table inet ghserver 2>&1 >/dev/null)"; then
		nft delete table inet ghserver 2>/dev/null
		return
	fi
	# Review 4 (M4 nit): only "no such table" means gone; any other failure
	# (permissions, a broken nft) says nothing about the table.
	case "$err" in
		*"No such file or directory"*) return 0 ;;
	esac
	echo "nft could not list the ghserver table: $err" >&2
	return 1
}

# Review 3 (R9): only an UNCONFIRMED change is rolled back. With nothing
# pending the live rules are the confirmed ones (what boots), and restoring the
# ruleset from before them would make live and boot differ - so nothing is
# touched. A message about removing the table is printed only when it is gone.
rollback_now() {
	if [ ! -f "$PENDING" ]; then
		echo "Nothing to roll back: no unconfirmed firewall change is pending (the live rules are the confirmed ones)."
		return 0
	fi
	if [ -f "$PREVIOUS" ]; then
		if nft -f "$PREVIOUS"; then
			echo "Restored the previous ghserver ruleset."
		else
			logger -t ghserver-firewall "rollback: restoring $PREVIOUS failed; removing the unconfirmed ghserver table instead" || true
			if remove_table; then
				echo "Restoring the previous ruleset failed - removed the ghserver table instead (no ghserver rules are active)." >&2
			else
				logger -t ghserver-firewall "rollback: could not remove the ghserver table either; the unconfirmed rules are LIVE" || true
				echo "Restoring the previous ruleset failed and the ghserver table could not be removed either:" >&2
				echo "the unconfirmed rules are still live. Check 'nft list ruleset' and run --rollback again." >&2
				return 1
			fi
		fi
	else
		if remove_table; then
			echo "Removed the ghserver table (there was no confirmed ruleset before)."
		else
			logger -t ghserver-firewall "rollback: could not remove the unconfirmed ghserver table; it is LIVE" || true
			echo "Could not remove the ghserver table: the unconfirmed rules are still live." >&2
			echo "Check 'nft list ruleset' and run --rollback again." >&2
			return 1
		fi
	fi
	rm -f "$PENDING" "$APPLYING"
}

do_check() {
	local file="$1"
	ghs_firewall_guard "$file" "$(ghs_game_port)"
}

do_apply() {
	local file="$1"
	need_root
	if [ ! -r "$file" ]; then
		echo "ruleset $file not found or unreadable (install-ubuntu.sh renders it)." >&2
		exit 1
	fi

	# Freeze what is about to be applied: everything below - the guard, nft's
	# check, the load and a later --confirm - uses this copy.
	state_dir
	install -m 0600 "$file" "$APPLYING"
	if ! ghs_firewall_guard "$APPLYING" "$(ghs_game_port)"; then
		rm -f "$APPLYING"
		exit 1
	fi
	# Syntax and semantics check against the live kernel before touching anything.
	if ! nft -c -f "$APPLYING"; then
		rm -f "$APPLYING"
		echo "ruleset failed nft's own check; not applying." >&2
		exit 1
	fi

	# What a rollback restores: the last confirmed ruleset, or no table at all.
	if [ -f "$APPLIED" ]; then cp -f "$APPLIED" "$PREVIOUS"; else rm -f "$PREVIOUS"; fi

	# Schedule the rollback FIRST, so it exists before the new rules can bite.
	cancel_timer
	systemd-run --quiet --unit="$UNIT" --on-active="${ROLLBACK_SECONDS}s" \
		--timer-property=AccuracySec=1s \
		"$SELF" --rollback-from-timer

	# Review 4 (M4): the pending record exists BEFORE the rules can be live, so
	# a failure anywhere after the load still leaves a change that the timer or
	# --rollback undoes (a rollback with nothing pending changes nothing).
	( umask 077; printf 'file=%s\nsha256=%s\nsession=%s\n' "$file" "$(sha_of "$APPLYING")" "$(session_id)" > "$PENDING" )
	chmod 0600 "$PENDING"
	if ! nft -f "$APPLYING"; then
		# nft loads a file as one transaction: refused means nothing changed.
		rm -f "$PENDING" "$APPLYING"
		cancel_timer
		echo "nft refused to load the ruleset; nothing was changed." >&2
		exit 1
	fi

	cat <<EOF

The new ruleset is LIVE and will be rolled back automatically in ${ROLLBACK_SECONDS} s.

Do NOT confirm from this session: it stays connected even if new SSH logins are
blocked. Instead, open a NEW ssh connection to this box now and run there:

    sudo $SELF --confirm

If that new connection cannot get in, do nothing: the previous rules come back
on their own. To undo immediately: sudo $SELF --rollback
EOF
}

do_confirm() {
	need_root
	if [ ! -f "$PENDING" ]; then
		echo "nothing to confirm (no pending firewall change, or it was already rolled back)." >&2
		exit 1
	fi
	if ! systemctl is-active --quiet "$UNIT.timer"; then
		echo "the rollback timer is gone - the change was already rolled back. Apply it again." >&2
		rm -f "$PENDING"
		exit 1
	fi
	local file sum applied_by now
	file="$(sed -n 's/^file=//p' "$PENDING")"
	sum="$(sed -n 's/^sha256=//p' "$PENDING")"
	applied_by="$(sed -n 's/^session=//p' "$PENDING")"
	now="$(session_id)"
	if [ "$now" != "unknown" ] && [ "$now" = "$applied_by" ]; then
		echo "refusing: this is the session that applied the change. Confirm from a NEW ssh connection," >&2
		echo "which proves new logins still get through." >&2
		exit 1
	fi
	if [ "$now" = "unknown" ]; then
		echo "warning: cannot tell this session from the one that applied the change (no login session id);" >&2
		echo "make sure you ran this from a NEW ssh connection." >&2
	fi

	# Only what was applied and tested may be kept. An edit made to the file since
	# (in the new session, say) was never loaded: confirming it would make an
	# untested ruleset the one that boots.
	if [ ! -f "$APPLYING" ] || [ -z "$sum" ] || [ "$(sha_of "$APPLYING")" != "$sum" ]; then
		echo "refusing: the applied copy ($APPLYING) is missing or altered. Apply again." >&2
		exit 1
	fi
	if [ ! -r "$file" ] || [ "$(sha_of "$file")" != "$sum" ]; then
		echo "refusing: $file changed since it was applied, and the changed version was never loaded or tested." >&2
		echo "Apply it again (the live, unconfirmed rules roll back on their own when the timer fires)." >&2
		exit 1
	fi

	cancel_timer
	state_dir
	install -m 0600 "$APPLYING" "$APPLIED"
	rm -f "$PENDING" "$APPLYING"

	# Persist: /etc/nftables.conf includes the CONFIRMED copy - the exact bytes
	# that were applied and tested above, never the editable file - and
	# nftables.service loads it at boot. No dump of the live ruleset (that would
	# bake the meter's dynamic elements into the file).
	local include="include \"$APPLIED\""
	if [ ! -f "$NFT_MAIN" ]; then
		printf '#!/usr/sbin/nft -f\n' > "$NFT_MAIN"
	fi
	if ! grep -qF "$include" "$NFT_MAIN"; then
		printf '\n# ghserver firewall (confirmed copy, see /opt/ghserver/deploy/firewall-apply.sh)\n%s\n' "$include" >> "$NFT_MAIN"
	fi
	systemctl enable nftables >/dev/null 2>&1 || true
	echo "Confirmed. The ruleset is kept and will be loaded at boot (nftables.service)."
	if sed 's/#.*$//' "$NFT_MAIN" | grep -Eq 'flush[[:space:]]+ruleset'; then
		echo "Note: /etc/nftables.conf (Ubuntu's stock file) starts with 'flush ruleset'. At boot that runs before"
		echo "ufw/Docker add their tables, but 'systemctl restart nftables' later would wipe them - remove that"
		echo "line if you use ufw or Docker."
	fi
}

case "${1:-}" in
	--confirm) do_confirm ;;
	--rollback) need_root; cancel_timer; rollback_now ;;
	--rollback-from-timer)
		need_root
		if [ -f "$PENDING" ]; then
			logger -t ghserver-firewall "rollback: the firewall change was not confirmed in time; restoring the previous rules" || true
		fi
		rollback_now ;;
	--check)
		if [ -z "${2:-}" ]; then echo "usage: firewall-apply.sh --check FILE" >&2; exit 2; fi
		do_check "$2" && echo "ok: $2 passes the guard" ;;
	--help|-h) sed -n '2,27p' "$0" ;;
	*) do_apply "${1:-$RULESET_DEFAULT}" ;;
esac
