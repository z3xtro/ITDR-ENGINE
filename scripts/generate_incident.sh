#!/usr/bin/env bash
# generate_incident.sh — stage a believable, MULTI-VECTOR intrusion
# against this host from real telemetry, so the live ITDR console fills
# up like a working SOC rather than showing one lonely alert.
#
#   cd ~/ITDR-ENGINE && git pull && sudo bash scripts/generate_incident.sh
#
# Needs sudo: it creates a couple of throwaway lab accounts to compromise
# (so the "most targeted accounts" panel has real, distinct identities),
# then generates:
#
#   * two account takeovers   — brute force -> success -> sudo
#                               (T1110 credential access + T1548 esc)
#   * a credential-spray scan — failed bursts against accounts that do
#                               not exist (T1078, stays NOTABLE)
#
# Every event is a real sshd/PAM/sudo record that Wazuh decodes and the
# engine consumes. Nothing is injected. Remove the lab accounts anytime
# with:  sudo userdel -r alice ; sudo userdel -r bob
set -uo pipefail

TARGET="${ATTACK_TARGET:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
[ -z "${TARGET}" ] && TARGET="127.0.0.1"
DEMO_PASS="Wazuh-lab-2026"
BURST=11                       # >= 9 clears CRITICAL after the ramp

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5 -o PreferredAuthentications=password
          -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo:  sudo bash scripts/generate_incident.sh"; exit 1
fi
command -v sshpass >/dev/null 2>&1 || dnf install -y sshpass >/dev/null 2>&1
command -v sshpass >/dev/null 2>&1 || { echo "need sshpass"; exit 1; }

echo "== staging multi-vector incident against ${TARGET} =="

# -- lab accounts to compromise (idempotent) --------------------------
for u in alice bob; do
    if ! id "${u}" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "${u}"
        echo "${u}:${DEMO_PASS}" | chpasswd
        usermod -aG wheel "${u}" 2>/dev/null || true
        echo "   created lab account ${u}"
    fi
done

compromise() {   # $1 = username
    local u="$1"
    echo "[*] ${u}: ${BURST} failed attempts, then a break-in + escalation"
    for i in $(seq 1 "${BURST}"); do
        sshpass -p "wrong-${i}" ssh "${SSH_OPTS[@]}" "${u}@${TARGET}" true \
            2>/dev/null
    done
    sshpass -p "${DEMO_PASS}" ssh "${SSH_OPTS[@]}" "${u}@${TARGET}" \
        "echo ${DEMO_PASS} | sudo -S -k id >/dev/null 2>&1; true" 2>/dev/null
}

spray() {        # $1 = username that does not exist
    local u="$1"
    echo "[*] ${u}: credential spray (no such account)"
    for i in $(seq 1 8); do
        sshpass -p "guess-${i}" ssh "${SSH_OPTS[@]}" "${u}@${TARGET}" true \
            2>/dev/null
    done
}

insider() {      # $1 = username — clean login, then straight to root
    local u="$1"
    echo "[*] ${u}: clean login then immediate escalation (no brute force)"
    sshpass -p "${DEMO_PASS}" ssh "${SSH_OPTS[@]}" "${u}@${TARGET}" \
        "echo ${DEMO_PASS} | sudo -S -k id >/dev/null 2>&1; true" 2>/dev/null
}

# -- run the vectors --------------------------------------------------
compromise alice          # brute force -> takeover      (T1110, CRITICAL)
compromise bob            # brute force -> takeover      (T1110, CRITICAL)
insider alice             # login -> instant root        (T1548, escalation)
spray oracle              # spray, no such account       (T1078, NOTABLE)
spray admin
spray postgres

echo
echo "Done. Real events are in Wazuh now. Within ~60s the console should show:"
echo "  * CRITICAL: alice, bob            (ssh_bruteforce_success + escalation)"
echo "  * several accounts under 'most targeted'"
echo "  * detections across T1110 / T1548 / T1078"
echo
echo "Refresh  http://${TARGET}:8080   (or :8081 if running foreground)"
echo "Tidy up later:  sudo userdel -r alice ; sudo userdel -r bob"
