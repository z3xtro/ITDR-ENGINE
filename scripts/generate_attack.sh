#!/usr/bin/env bash
# generate_attack.sh — produce a real brute-force-then-compromise chain
# against this host, so the live ITDR console has a genuine CRITICAL to
# show. Everything the detector needs, from real sshd/sudo events:
#
#   1. a burst of failed SSH password attempts   -> rule 5716
#   2. a successful login from the same IP        -> rule 5715 / 5501
#   3. an immediate privilege escalation          -> rule 5402
#
# Run it ON the Wazuh VM (the console is fine — this never locks you out,
# because it authenticates successfully at the end):
#
#   cd ~/ITDR-ENGINE && git pull && bash scripts/generate_attack.sh
#
# Why a script and not pasted commands: the VirtualBox text console
# mangles pasted quotes and pipes. A file in the repo runs byte-for-byte
# as written.
set -u

# ---- config (override by exporting before running) ------------------
USER_NAME="${ATTACK_USER:-wazuh-user}"
GOOD_PASS="${ATTACK_PASS:-wazuh}"
FAILURES="${ATTACK_FAILURES:-12}"
# Target the host's own LAN IP by default, so the alert carries a real
# source address rather than 127.0.0.1 (which the engine normalises to
# 0.0.0.0). Falls back to loopback if no LAN IP is found.
TARGET="${ATTACK_TARGET:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
[ -z "${TARGET}" ] && TARGET="127.0.0.1"

SSH_OPTS=(-o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5
          -o PreferredAuthentications=password
          -o PubkeyAuthentication=no
          -o NumberOfPasswordPrompts=1)

echo "== ITDR attack chain generator =="
echo "   target   : ${USER_NAME}@${TARGET}"
echo "   failures : ${FAILURES}"
echo

if ! command -v sshpass >/dev/null 2>&1; then
    echo "sshpass is not installed. Install it first:"
    echo "    sudo dnf install -y sshpass"
    exit 1
fi

# ---- 1. the brute-force burst ---------------------------------------
echo "[1/3] sending ${FAILURES} failed password attempts..."
for i in $(seq 1 "${FAILURES}"); do
    sshpass -p "definitely-wrong-${i}" \
        ssh "${SSH_OPTS[@]}" "${USER_NAME}@${TARGET}" true 2>/dev/null
    printf '.'
done
echo " done"

# ---- 2. the successful login ----------------------------------------
echo "[2/3] logging in with the correct password..."
if sshpass -p "${GOOD_PASS}" ssh "${SSH_OPTS[@]}" \
        "${USER_NAME}@${TARGET}" "echo GOT_IN" 2>/dev/null | grep -q GOT_IN
then
    echo "      success — login accepted"
else
    echo "      WARNING: the success login failed. Check that"
    echo "      ATTACK_PASS is correct (currently '${GOOD_PASS}')."
    echo "      Without a success the burst alone is NOT a compromise."
fi

# ---- 3. the privilege escalation ------------------------------------
echo "[3/3] escalating to root over that session..."
# -S reads the sudo password from stdin; -k forces a fresh auth so the
# event always fires rather than riding a cached credential.
sshpass -p "${GOOD_PASS}" ssh "${SSH_OPTS[@]}" "${USER_NAME}@${TARGET}" \
    "echo ${GOOD_PASS} | sudo -S -k id >/dev/null 2>&1 && echo ESCALATED" \
    2>/dev/null | grep -q ESCALATED \
    && echo "      success — ran 'id' as root" \
    || echo "      note: sudo did not succeed (password may differ); the"
echo
echo "Done. Wait ~60s for the next poll, then refresh http://${TARGET}:8080"
echo "Expect: CRITICAL 1, ssh_bruteforce_success + privilege_escalation,"
echo "        source IP ${TARGET} in the alert feed."
