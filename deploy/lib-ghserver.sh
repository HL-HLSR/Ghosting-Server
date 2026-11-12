# Shared helpers for the deploy scripts. Sourced, never executed:
#   . "$(dirname "$0")/lib-ghserver.sh"
# shellcheck shell=bash

GHS_ENV_FILE="${GHS_ENV_FILE:-/etc/ghserver/ghserver.env}"

# The UDP game port the server will bind: PORT from the env file, else 22228.
# Accepts PORT=22228, PORT="22228" and PORT='22228'; the last assignment wins,
# as it does for systemd's EnvironmentFile.
ghs_game_port() {
	local p=""
	if [ -r "$GHS_ENV_FILE" ]; then
		p="$(sed -n "s/^[[:space:]]*PORT[[:space:]]*=[[:space:]]*[\"']\{0,1\}\([0-9]\{1,5\}\)[\"']\{0,1\}[[:space:]]*\$/\1/p" "$GHS_ENV_FILE" | tail -n 1)"
	fi
	printf '%s\n' "${p:-22228}"
}

# Every TCP port sshd may be listening on, one per line, sorted. Ubuntu 24.04
# socket-activates sshd, so the ports in ssh.socket (ListenStream, honouring an
# empty "ListenStream=" in a drop-in, which resets the list) are what matters;
# `sshd -T` is added as well for a box that runs sshd as a plain service. The
# union is deliberately over-inclusive: an extra accept rule costs nothing, a
# missing one locks the admin out. SSH_PORTS (space-separated) overrides both,
# for tests and unusual setups.
ghs_ssh_ports() {
	if [ -n "${SSH_PORTS:-}" ]; then
		printf '%s\n' $SSH_PORTS | grep -E '^[0-9]+$' | sort -un
		return
	fi
	{
		if command -v sshd >/dev/null 2>&1; then
			sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
		fi
		if command -v systemctl >/dev/null 2>&1; then
			systemctl cat ssh.socket 2>/dev/null | awk '
				/^[[:space:]]*ListenStream[[:space:]]*=/ {
					v = $0; sub(/^[^=]*=[[:space:]]*/, "", v)
					if (v == "") { n = 0; next }
					sub(/.*:/, "", v); sub(/[^0-9].*$/, "", v)
					if (v != "") ports[++n] = v
				}
				END { for (i = 1; i <= n; i++) print ports[i] }'
		fi
	} | grep -E '^[0-9]+$' | sort -un
}

# 0 when FILE is not a ruleset rendered from this release's template - in
# practice the one the 1.2.0 pre-release installer always put in /etc: it
# flushes the whole ruleset and builds a plain "inet filter" table, so
# firewall-apply.sh refuses it. Comments are ignored, so an admin's note that
# mentions "flush ruleset" does not count; an edited new ruleset (it still owns
# "table inet ghserver" and does not flush) is not matched.
ghs_firewall_is_old_shipped() {
	local body
	body="$(sed 's/#.*$//' "$1")"
	if printf '%s\n' "$body" | grep -Eq 'flush[[:space:]]+ruleset'; then return 0; fi
	if ! printf '%s\n' "$body" | grep -Eq 'table[[:space:]]+inet[[:space:]]+ghserver([[:space:]]|$|\{)'; then return 0; fi
	return 1
}

# Render the firewall template: @GAME_PORT@ and @SSH_PORTS@ (comma-separated).
ghs_render_firewall() {
	local template="$1" out="$2" game="$3" ssh="$4"
	sed -e "s/@GAME_PORT@/${game}/g" -e "s/@SSH_PORTS@/${ssh}/g" "$template" > "$out"
}

# 0 when the ruleset (comments stripped) has a real "tcp dport <port> ... accept"
# rule (a bare port or a set containing it) on a line that does not also drop or
# reject. A comment or a "tcp dport 22 drop" does not count.
ghs_has_tcp_accept() {
	local file="$1" port="$2"
	sed 's/#.*$//' "$file" | awk -v p="$port" '
		/tcp[ \t]+dport/ && /[ \t]accept([ \t;]|$)/ && !/(drop|reject)/ {
			line = $0
			sub(/.*tcp[ \t]+dport[ \t]+/, "", line)
			if (line ~ /^\{/) { sub(/\}.*/, "", line); gsub(/[{}, \t]+/, " ", line) }
			else { sub(/[ \t].*/, "", line) }
			n = split(line, a, " ")
			for (i = 1; i <= n; i++) if (a[i] == p) found = 1
		}
		END { exit found ? 0 : 1 }'
}

# Refuse a ruleset that would lock SSH out, is not rendered, flushes the whole
# ruleset, or does not open the game port. Prints the reason; 0 = acceptable.
ghs_firewall_guard() {
	local file="$1" game="$2" port ports ok=0
	if grep -q '@[A-Z_]*@' "$file"; then
		echo "refusing: $file still contains unrendered @PLACEHOLDERS@" >&2
		return 1
	fi
	if sed 's/#.*$//' "$file" | grep -Eq 'flush[[:space:]]+ruleset'; then
		echo "refusing: $file flushes the whole ruleset (it would wipe ufw, Docker and fail2ban tables)" >&2
		return 1
	fi
	ports="$(ghs_ssh_ports)"
	if [ -z "$ports" ]; then
		echo "warning: could not detect sshd's ports; assuming 22" >&2
		ports=22
	fi
	for port in $ports; do
		if ! ghs_has_tcp_accept "$file" "$port"; then
			echo "refusing: no 'tcp dport $port accept' rule - sshd listens on $port and would be locked out" >&2
			ok=1
		fi
	done
	if ! sed 's/#.*$//' "$file" | grep -Eq "udp[[:space:]]+dport[[:space:]]+${game}[[:space:]]+accept"; then
		echo "refusing: no 'udp dport $game accept' rule for the game port (PORT in $GHS_ENV_FILE)" >&2
		ok=1
	fi
	return "$ok"
}
