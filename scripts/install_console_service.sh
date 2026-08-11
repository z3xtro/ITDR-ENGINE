#!/usr/bin/env bash
# install_console_service.sh — install the ITDR console as an always-on
# systemd service, correctly, in one shot. Run it on the Wazuh VM:
#
#   export WAZUH_INDEXER_PASSWORD=admin      # if not already set
#   bash scripts/install_console_service.sh
#
# Run WITHOUT sudo — it invokes sudo only for the privileged steps, so it
# inherits your exported WAZUH_* variables (sudo would strip them).
#
# Written as a script because the VirtualBox text console mangles pasted
# multi-line commands; a committed file runs byte-for-byte.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RUN_USER="$(whoami)"
PORT="${ITDR_CONSOLE_PORT:-8080}"
CURSOR="${REPO}/.wazuh_console_cursor.json"

IDX_URL="${WAZUH_INDEXER_URL:-https://localhost:9200}"
IDX_USER="${WAZUH_INDEXER_USER:-admin}"
IDX_PASS="${WAZUH_INDEXER_PASSWORD:-admin}"

echo "== installing ITDR console service =="
echo "   repo : ${REPO}"
echo "   user : ${RUN_USER}"
echo "   port : ${PORT}"
echo "   idx  : ${IDX_URL}"
echo

PYBIN="$(command -v python3.11 || command -v python3)"
echo "   python: ${PYBIN}"

# 1. credentials file (root-owned, 0600)
sudo tee /etc/itdr-console.env >/dev/null <<EOF
WAZUH_INDEXER_URL=${IDX_URL}
WAZUH_INDEXER_USER=${IDX_USER}
WAZUH_INDEXER_PASSWORD=${IDX_PASS}
WAZUH_VERIFY_TLS=false
WAZUH_CURSOR_FILE=${CURSOR}
EOF
sudo chmod 600 /etc/itdr-console.env
echo "   wrote /etc/itdr-console.env"

# 2. the unit, generated with this host's real paths
sudo tee /etc/systemd/system/itdr-console.service >/dev/null <<EOF
[Unit]
Description=ITDR Console — identity threat detection dashboard
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO}
Environment=HOME=/home/${RUN_USER}
Environment=PYTHONPATH=/home/${RUN_USER}/.local/lib/python3.11/site-packages
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=-/etc/itdr-console.env
ExecStart=${PYBIN} -m itdr.dashboard --live --hours 24 --interval 60 --port ${PORT}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=itdr-console

[Install]
WantedBy=multi-user.target
EOF
echo "   wrote /etc/systemd/system/itdr-console.service"

# 3. fresh cursor so the first poll re-reads the last 24h (incl. any
#    attack you just generated) rather than resuming past it.
rm -f "${CURSOR}"

# 4. start it
sudo systemctl daemon-reload
sudo systemctl enable itdr-console >/dev/null 2>&1 || true
sudo systemctl restart itdr-console

# 5. verify it is actually serving before declaring success
echo
echo "waiting for the console to answer..."
ok=""
for _ in $(seq 1 15); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PORT}" || true)"
    if [ "${code}" = "200" ]; then ok=1; break; fi
    sleep 2
done

echo
if [ -n "${ok}" ]; then
    IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "SUCCESS — console is live and will survive reboot."
    echo "   local : http://localhost:${PORT}"
    [ -n "${IP}" ] && echo "   LAN   : http://${IP}:${PORT}"
    echo
    echo "   manage:  sudo systemctl status itdr-console"
    echo "   logs:    journalctl -u itdr-console -f"
else
    echo "The service did not answer on port ${PORT}. Its log:"
    echo "-------------------------------------------------------"
    sudo journalctl -u itdr-console -n 20 --no-pager || true
    echo "-------------------------------------------------------"
    echo "Paste the above and I'll fix it."
    exit 1
fi
