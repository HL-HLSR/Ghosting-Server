#!/usr/bin/env bash
# Install the Ghosting ghost host on Ubuntu 24.04 LTS. Idempotent: safe to run
# again to pick up a new release or re-assert permissions.
#
#   sudo deploy/install-ubuntu.sh
#
# Run it from an UNPACKED release (deploy/ sits next to index.js and src/):
#   tar xzf ghserver-1.3.2.tar.gz -C /tmp/ghserver-release
#   sudo /tmp/ghserver-release/deploy/install-ubuntu.sh
#
# What it does:
#   * installs Node 24 from the NodeSource apt repo with a signed-by keyring
#     whose fingerprint is pinned (no curl|bash),
#   * creates the system user `ghserver` (no shell, no home login) and the
#     `ghsadmin` group for console access,
#   * installs the code to /opt/ghserver, root-owned and read-only to the
#     service; state to /var/lib/ghserver (StateDirectory); config to
#     /etc/ghserver/ghserver.env (0640 root:ghserver),
#   * installs the hardened systemd unit (the server opens its console FIFO
#     itself) and the ghserver-console helper, and restarts the service if it
#     was running so a new release really takes effect,
#   * enables unattended-upgrades for security, including NodeSource's repo,
#     with no automatic reboot,
#   * installs the firewall ruleset as a FILE but does NOT activate it (use
#     deploy/firewall-apply.sh for that).
set -euo pipefail

NODE_MAJOR=24
# NodeSource's repository signing key, pinned (review 1 addendum): rsa2048,
# uid "NSolid <nsolid-gpg@nodesource.com>". The download is refused if the key
# it serves is anything else.
NODESOURCE_KEY_URL="https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
NODESOURCE_KEY_FPR="6F71F525282841EEDAF851B42F59B5F99B1BE0B4"
PREFIX=/opt/ghserver
STATE=/var/lib/ghserver
CONF_DIR=/etc/ghserver
CONF="${CONF_DIR}/ghserver.env"
UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\n==> %s\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (sudo)." >&2
	exit 1
fi

if [ ! -f "${SRC_DIR}/index.js" ] || [ ! -d "${SRC_DIR}/src" ]; then
	echo "this script must be run from an unpacked release (index.js and src/ next to deploy/)." >&2
	exit 1
fi

# Running it from the installed copy would copy the install onto itself (and,
# without rsync, delete it first). Re-run it from a freshly unpacked release.
if [ "$(realpath "${SRC_DIR}")" = "$(realpath -m "${PREFIX}")" ]; then
	echo "refusing: run this from an unpacked release, not from ${PREFIX} itself." >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# --- Node 24 from NodeSource, pinned signed-by keyring (no curl|bash) --------
# The key is fetched to a FILE, its fingerprint checked against the pinned one,
# and only then dearmored into the keyring apt trusts for that one repository.
install_nodesource_repo() {
	local tmp fprs
	apt-get install -y ca-certificates curl gnupg
	tmp="$(mktemp -d)"
	install -d -m 0700 "${tmp}/gnupg"
	if ! curl -fsSL "${NODESOURCE_KEY_URL}" -o "${tmp}/key.asc"; then
		rm -rf "${tmp}"
		echo "could not download the NodeSource signing key from ${NODESOURCE_KEY_URL}" >&2
		exit 1
	fi
	# Primary-key fingerprints only (the fpr line right after each pub line).
	fprs="$(GNUPGHOME="${tmp}/gnupg" gpg --batch --show-keys --with-colons "${tmp}/key.asc" 2>/dev/null \
		| awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }')"
	if [ "${fprs}" != "${NODESOURCE_KEY_FPR}" ]; then
		rm -rf "${tmp}"
		echo "refusing: the NodeSource key served has fingerprint(s) [${fprs//$'\n'/ }]," >&2
		echo "expected exactly ${NODESOURCE_KEY_FPR}. Not installing an unverified repository." >&2
		exit 1
	fi
	install -d -m 0755 /usr/share/keyrings
	GNUPGHOME="${tmp}/gnupg" gpg --batch --dearmor --yes -o /usr/share/keyrings/nodesource.gpg "${tmp}/key.asc"
	chmod 0644 /usr/share/keyrings/nodesource.gpg
	rm -rf "${tmp}"
	echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
		> /etc/apt/sources.list.d/nodesource.list
}

install_node() {
	log "Configuring the NodeSource node_${NODE_MAJOR}.x repository (pinned key ${NODESOURCE_KEY_FPR})"
	apt-get update -y
	install_nodesource_repo
	apt-get update -y
	if command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]; then
		log "Node $(node -v) already present (>= 22); leaving it (security updates come from the repository)."
		return
	fi
	log "Installing Node ${NODE_MAJOR} from NodeSource"
	apt-get install -y nodejs
	log "Installed $(node -v)"
}

# --- service user and admin group -------------------------------------------
make_accounts() {
	if ! getent group ghsadmin >/dev/null; then
		log "Creating group ghsadmin (console access)"
		groupadd --system ghsadmin
	fi
	if ! id ghserver >/dev/null 2>&1; then
		log "Creating system user ghserver"
		useradd --system --no-create-home --home-dir "${STATE}" \
			--shell /usr/sbin/nologin ghserver
	fi
}

# --- code to /opt/ghserver, root-owned, read-only to the service -------------
install_code() {
	log "Installing code to ${PREFIX}"
	install -d -m 0755 "${PREFIX}"
	# Copy only what the release ships; rsync mirrors so a removed file in a new
	# release is removed here too.
	if command -v rsync >/dev/null 2>&1; then
		rsync -a --delete \
			--exclude 'legacy' --exclude 'test' --exclude 'scripts' \
			--exclude 'node_modules' --exclude '.git' --exclude 'dist' \
			"${SRC_DIR}/" "${PREFIX}/"
	else
		rm -rf "${PREFIX:?}/src" "${PREFIX}/index.js" "${PREFIX}/package.json"
		cp -a "${SRC_DIR}/index.js" "${SRC_DIR}/package.json" "${PREFIX}/"
		cp -a "${SRC_DIR}/src" "${PREFIX}/"
		[ -d "${SRC_DIR}/deploy" ] && cp -a "${SRC_DIR}/deploy" "${PREFIX}/"
		[ -f "${SRC_DIR}/README.md" ] && cp -a "${SRC_DIR}/README.md" "${PREFIX}/"
		[ -f "${SRC_DIR}/CHANGELOG.md" ] && cp -a "${SRC_DIR}/CHANGELOG.md" "${PREFIX}/"
	fi
	# Root owns it; the service can read and execute but not write. A future
	# compromise cannot rewrite index.js or src/ and persist (M7, L8).
	chown -R root:root "${PREFIX}"
	chmod -R u=rwX,go=rX "${PREFIX}"
	install -m 0755 "${PREFIX}/deploy/ghserver-console" /usr/local/bin/ghserver-console
}

# --- state, config -----------------------------------------------------------
install_state_and_config() {
	log "Creating state ${STATE} and config ${CONF}"
	install -d -o ghserver -g ghserver -m 0700 "${STATE}"
	install -d -m 0755 "${CONF_DIR}"
	if [ ! -f "${CONF}" ]; then
		cat > "${CONF}" <<'ENV'
# ghserver configuration. See the README for every variable.
#
# One KEY=value per line, and NOTHING after the value: systemd does not strip a
# trailing "# comment", it becomes part of the value and the server refuses to
# start (exit 78). Remove the leading "#" of a line to set it; leave a setting
# out entirely to use its default.

# UDP port players connect to (gh_online_port on the clients).
#PORT=22228

# Slot limit.
#MAX_PLAYERS=16

# 0 disables the operator chat commands (/kick, /ban, ...) for a host that
# moderates from the console only.
#OP_CHAT_COMMANDS=1

# Distinct sprays one player may publish per minute.
#SPRAY_PUBLISH_PER_MINUTE=2
ENV
	fi
	# Readable by the service, writable only by root. No secrets belong here.
	chown root:ghserver "${CONF}"
	chmod 0640 "${CONF}"
}

# --- systemd unit ------------------------------------------------------------
install_units() {
	log "Installing the systemd unit"
	local node_bin was_active=0
	node_bin="$(command -v node)"
	if systemctl is-active --quiet ghserver.service; then was_active=1; fi
	# Install the unit, pointing ExecStart at the node we actually installed.
	sed "s#^ExecStart=/usr/bin/node#ExecStart=${node_bin}#" \
		"${PREFIX}/deploy/ghserver.service" > "${UNIT_DIR}/ghserver.service"
	chmod 0644 "${UNIT_DIR}/ghserver.service"
	systemctl daemon-reload
	# An earlier release ran the console through a socket unit that the service
	# Required; the new unit has no such dependency, so it can go without
	# stopping the server.
	if [ -f "${UNIT_DIR}/ghserver-console.socket" ]; then
		systemctl disable --now ghserver-console.socket >/dev/null 2>&1 || true
		rm -f "${UNIT_DIR}/ghserver-console.socket"
		systemctl daemon-reload
	fi
	systemctl enable ghserver.service
	if [ "${was_active}" -eq 1 ]; then
		# A re-run that installs a new release must actually run it.
		log "Restarting ghserver so the new code takes effect"
		systemctl restart ghserver.service
	else
		systemctl start ghserver.service
	fi
}

# --- unattended security upgrades, including the NodeSource origin -----------
install_unattended() {
	log "Enabling unattended security upgrades"
	apt-get install -y unattended-upgrades
	cat > /etc/apt/apt.conf.d/51ghserver-nodesource <<'APT'
// Let unattended-upgrades apply NodeSource updates too. Matched by SITE (the
// repository host): NodeSource's Release file for node_24.x/nodistro says
// "Origin: . nodistro", so an origin= pattern never matches and Node would
// never be updated.
Unattended-Upgrade::Origins-Pattern {
    "site=deb.nodesource.com";
};
// Never reboot the game host on its own; a kernel update waits for the admin.
Unattended-Upgrade::Automatic-Reboot "false";
APT
	cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
	systemctl enable --now unattended-upgrades.service 2>/dev/null || true
}

# --- firewall ruleset installed but NOT activated ----------------------------
install_firewall_file() {
	local out="${CONF_DIR}/nftables-ghserver.conf" game ssh
	# shellcheck source=lib-ghserver.sh
	. "${PREFIX}/deploy/lib-ghserver.sh"
	# Review 2 (m5): the pre-release installer always installed a ruleset that
	# flushes everything; firewall-apply.sh refuses it, with no hint to re-render.
	# Such a file (or any without the ghserver table) is moved aside, not kept.
	if [ -f "$out" ] && ghs_firewall_is_old_shipped "$out"; then
		local stamp
		stamp="$(date +%Y%m%d%H%M%S)"
		mv -f "$out" "${out}.bak.${stamp}"
		log "Moved the old ruleset ${out} to ${out}.bak.${stamp} (it flushes the whole ruleset or has no 'inet ghserver' table); rendering the new one"
	fi
	if [ -f "$out" ]; then
		log "Keeping your existing ${out} (not re-rendered)"
	else
		game="$(ghs_game_port)"
		ssh="$(ghs_ssh_ports | paste -sd, - | sed 's/,/, /g')"
		[ -n "$ssh" ] || ssh=22
		log "Rendering the firewall ruleset for UDP ${game} and SSH ${ssh} (NOT activating it)"
		ghs_render_firewall "${PREFIX}/deploy/nftables-ghserver.conf" "$out" "$game" "$ssh"
		chmod 0644 "$out"
	fi
	echo "    review ${out} (restrict SSH to your admin networks if you can), then activate it with"
	echo "    sudo ${PREFIX}/deploy/firewall-apply.sh   and confirm from a NEW ssh session."
}

install_node
make_accounts
install_code
install_state_and_config
install_units
install_unattended
install_firewall_file

log "Done."
echo "    status:   systemctl status ghserver"
echo "    logs:     journalctl -u ghserver -f"
echo "    console:  add yourself to ghsadmin (usermod -aG ghsadmin <you>), then"
echo "              ghserver-console status"
echo "    firewall: review and run ${PREFIX}/deploy/firewall-apply.sh"
