#!/usr/bin/env bash
# Deploy a new release tarball, keeping the previous one, and roll back if the
# new build does not come up healthy.
#
#   sudo /opt/ghserver/deploy/update.sh ghserver-1.2.1.tar.gz
#
# The previous /opt/ghserver is kept as /opt/ghserver.prev, so a rollback is a
# move back. State (/var/lib/ghserver) and config (/etc/ghserver) are never
# touched. A SHA-256 is verified when a matching .sha256 sits next to the
# tarball. The health check looks for the UDP PORT from /etc/ghserver/ghserver.env.
#
# Safe against a failure half way: a staged build is only deleted while a live
# copy exists at /opt/ghserver, and a failed swap puts the previous build back.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-ghserver.sh
. "$HERE/lib-ghserver.sh"

PREFIX=/opt/ghserver
PREV="${PREFIX}.prev"
STAGE="${PREFIX}.new.$$"
UNIT_DIR=/etc/systemd/system
HEALTH_WAIT="${HEALTH_WAIT:-8}"

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (sudo)." >&2
	exit 1
fi

TARBALL="${1:-}"
if [ -z "${TARBALL}" ] || [ ! -r "${TARBALL}" ]; then
	echo "usage: update.sh <release.tar.gz>" >&2
	exit 1
fi

if [ -r "${TARBALL}.sha256" ]; then
	echo "==> Verifying ${TARBALL}.sha256"
	( cd "$(dirname "${TARBALL}")" && sha256sum -c "$(basename "${TARBALL}").sha256" )
fi

# Never delete the staged build unless a live install exists - otherwise a
# failure between the two moves would leave the box with no server at all.
cleanup() {
	if [ -d "${STAGE}" ] && [ -d "${PREFIX}" ]; then rm -rf "${STAGE}"; fi
}
trap cleanup EXIT

echo "==> Unpacking into ${STAGE}"
mkdir -p "${STAGE}"
tar xzf "${TARBALL}" -C "${STAGE}"
if [ ! -f "${STAGE}/index.js" ] || [ ! -d "${STAGE}/src" ]; then
	echo "that tarball does not look like a ghserver release (no index.js/src)." >&2
	exit 1
fi
chown -R root:root "${STAGE}"
chmod -R u=rwX,go=rX "${STAGE}"

node_bin="$(command -v node)"
PORT="$(ghs_game_port)"

install_unit_from() {
	sed "s#^ExecStart=/usr/bin/node#ExecStart=${node_bin}#" \
		"$1/deploy/ghserver.service" > "${UNIT_DIR}/ghserver.service"
	# The console no longer runs through a socket unit (see the unit file).
	if [ -f "${UNIT_DIR}/ghserver-console.socket" ]; then
		systemctl disable --now ghserver-console.socket >/dev/null 2>&1 || true
		rm -f "${UNIT_DIR}/ghserver-console.socket"
	fi
	systemctl daemon-reload
}

healthy() {
	sleep "${HEALTH_WAIT}"
	systemctl is-active --quiet ghserver.service || return 1
	if command -v ss >/dev/null 2>&1; then
		ss -Hlun 2>/dev/null | awk -v p="${PORT}" '{ n = split($4, a, ":"); if (a[n] == p) found = 1 } END { exit found ? 0 : 1 }' || return 1
	fi
	return 0
}

echo "==> Swapping ${PREFIX} (previous kept as ${PREV})"
systemctl stop ghserver.service || true
rm -rf "${PREV}"
if [ -d "${PREFIX}" ]; then
	mv "${PREFIX}" "${PREV}"
fi
if ! mv "${STAGE}" "${PREFIX}"; then
	echo "!! could not move the new build into place - restoring the previous one" >&2
	if [ -d "${PREV}" ] && [ ! -d "${PREFIX}" ]; then mv "${PREV}" "${PREFIX}"; fi
	systemctl start ghserver.service || true
	exit 1
fi
install -m 0755 "${PREFIX}/deploy/ghserver-console" /usr/local/bin/ghserver-console 2>/dev/null || true
install_unit_from "${PREFIX}"

echo "==> Starting the new build"
systemctl start ghserver.service

if healthy; then
	echo "==> Healthy (UDP ${PORT} bound). Previous build kept at ${PREV}; remove it when you are satisfied."
	exit 0
fi

echo "!! The new build did not come up healthy (UDP ${PORT}) - rolling back to ${PREV}" >&2
if [ -d "${PREV}" ]; then
	systemctl stop ghserver.service || true
	FAILED="${PREFIX}.failed.$$"
	mv "${PREFIX}" "${FAILED}"
	if mv "${PREV}" "${PREFIX}"; then
		rm -rf "${FAILED}"
	else
		mv "${FAILED}" "${PREFIX}"
	fi
	install_unit_from "${PREFIX}"
	systemctl start ghserver.service
	echo "rolled back." >&2
fi
exit 1
