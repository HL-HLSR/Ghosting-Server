#!/usr/bin/env bash
# Remove the ghost host. State (bans/whitelist/ops) is KEPT unless you pass
# --purge, so an accidental uninstall does not throw your moderation away.
#
#   sudo deploy/uninstall.sh            # remove code, units, user; keep state
#   sudo deploy/uninstall.sh --purge    # also remove state and config
set -euo pipefail

PREFIX=/opt/ghserver
STATE=/var/lib/ghserver
CONF_DIR=/etc/ghserver
UNIT_DIR=/etc/systemd/system

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (sudo)." >&2
	exit 1
fi

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "==> Stopping and disabling the service and socket"
systemctl disable --now ghserver.service 2>/dev/null || true
systemctl disable --now ghserver-console.socket 2>/dev/null || true

echo "==> Removing units and helper"
rm -f "${UNIT_DIR}/ghserver.service" "${UNIT_DIR}/ghserver-console.socket"
rm -f /usr/local/bin/ghserver-console
systemctl daemon-reload

echo "==> Removing code at ${PREFIX}"
rm -rf "${PREFIX}" "${PREFIX}.prev" "${PREFIX}.new."* 2>/dev/null || true

if [ "${PURGE}" -eq 1 ]; then
	echo "==> Purging state and config"
	rm -rf "${STATE}" "${CONF_DIR}"
	if id ghserver >/dev/null 2>&1; then userdel ghserver 2>/dev/null || true; fi
	if getent group ghsadmin >/dev/null; then groupdel ghsadmin 2>/dev/null || true; fi
	echo "    removed ${STATE}, ${CONF_DIR}, the ghserver user and the ghsadmin group."
else
	echo "==> Kept ${STATE} and ${CONF_DIR} (bans/whitelist/ops and config)."
	echo "    re-run with --purge to remove them, the ghserver user and the ghsadmin group."
fi

echo "==> Note: the NodeSource apt repo and Node itself are left in place."
echo "    If you activated the ghserver firewall: nft delete table inet ghserver, and remove its include line"
echo "    from /etc/nftables.conf (and /var/lib/ghserver-fw)."
echo "Done."
