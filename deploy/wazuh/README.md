# Wazuh → ITDR Engine

Connecting the engine to a running Wazuh install, in the order that
actually works. You have Wazuh up; start at step 1.

---

## 1. Prove the engine can read your install

Before changing anything on the manager, run the diagnostic. It is
read-only and safe against production.

```bash
export WAZUH_INDEXER_URL=https://localhost:9200
export WAZUH_INDEXER_USER=admin
export WAZUH_INDEXER_PASSWORD='...'
export WAZUH_API_URL=https://localhost:55000
export WAZUH_API_USER=wazuh-wui
export WAZUH_API_PASSWORD='...'

python -m itdr.wazuh_doctor
```

For the `wazuh-docker` single-node stack those passwords are in
`single-node/docker-compose.yml` as `INDEXER_PASSWORD` and
`API_PASSWORD` (defaults `SecretPassword` and `MyS3cr37P450r.*-`).

The doctor runs seven checks and reports each independently:

| check | what it proves |
|---|---|
| `config` | connection variables are present |
| `indexer` | the Indexer answers and holds alert indices |
| `manager` | the API authenticates; reports the version |
| `agents` | an endpoint is actually enrolled (agent `000` is the manager itself and doesn't count) |
| `alerts` | authentication alerts exist in the last 24h |
| `mapping` | **how many of your real alerts become AuthEvents, and why the rest didn't** |
| `detection` | replays them through the real engine and shows what fired |

The `mapping` check is the one worth reading closely. "Events are
arriving" is easy to believe and usually half true; what matters is
which of *your* alerts survive normalization. The doctor prints the
rule IDs it mapped and the reasons it rejected the others.

If `agents` warns that only the manager is active, enroll an endpoint
before continuing — there is no real telemetry until you do.

If `alerts` warns that none exist, SSH into an enrolled endpoint (get
the password wrong a few times first) and re-run.

---

## 2. Ingest, the easy way — Indexer polling

This needs no manager changes at all. It reads the same
`wazuh-alerts-*` indices the dashboard renders.

```bash
IDP=wazuh-indexer python -m itdr.service
```

The service polls every `POLL_INTERVAL` seconds (default 60) and
persists a cursor to `.wazuh_cursor.json`, so a restart resumes at the
frontier without replaying or dropping events.

Start here. Move to push ingestion only once the pipeline shape is
settled.

---

## 3. Ingest, the low-latency way — push integration

Sub-second instead of up-to-a-minute, at the cost of an ossec.conf edit
and a manager restart.

On the **manager**:

```bash
cp integrations/custom-itdr /var/ossec/integrations/custom-itdr
chmod 750 /var/ossec/integrations/custom-itdr
chown root:wazuh /var/ossec/integrations/custom-itdr
```

Add the block from `ossec-integration.xml` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`, setting `hook_url` to the engine's address
and `api_key` to a token you choose. Then:

```bash
systemctl restart wazuh-manager      # docker: docker compose restart wazuh.manager
```

Run the engine with the matching token:

```bash
IDP=wazuh WAZUH_SHARED_TOKEN='<same token>' python -m itdr.service
```

Verify from the manager side:

```bash
tail -f /var/ossec/logs/integrations.log     # forwarder's own log
curl http://ITDR_HOST:8099/health            # engine's counters
```

`received` climbing as you log in and out of an endpoint is the proof
the path is live. `unmapped` climbing instead means alerts are arriving
but not normalizing — run the doctor to see why.

---

## 4. Containment on the endpoint (Active Response)

This is the part that makes it a response engine rather than a
detection one. On a CRITICAL alert the engine can tell the manager to
firewall-drop the attacker's IP on the affected host, and to lock the
account.

```bash
export WAZUH_API_URL=https://localhost:55000
export WAZUH_API_USER=wazuh-wui
export WAZUH_API_PASSWORD='...'
export ENFORCEMENT_MODE=ACTIVE_ENFORCEMENT      # required; DRY_RUN otherwise
```

### Capability map — what actually happens

| playbook step | on a Wazuh endpoint |
|---|---|
| `revoke_user_sessions` | `firewall-drop` the source IP — severs the attacker's network path |
| `quarantine_account` | `disable-account` — locks the OS account |
| `invalidate_tokens` | **unsupported** — hosts issue no tokens |
| `enforce_mfa_reset` | **unsupported** — PAM here has no enrolled factors |

The unsupported two report failure rather than returning success for
work that never happened, and the transaction records them as skipped.

### Prerequisites

`firewall-drop` ships enabled in the stock ossec.conf.
`disable-account` does **not**, and only works on Linux agents. To
enable it, add to the manager's ossec.conf:

```xml
<command>
  <name>disable-account</name>
  <executable>disable-account</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>disable-account</command>
  <location>local</location>
  <timeout>600</timeout>
</active-response>
```

If a command isn't configured the adapter logs it and returns False —
a partially configured manager degrades, it doesn't break containment.

### Safety

Blocking is destructive and trivially weaponized: anyone who can forge
a source IP can make you firewall your own users off. Three guards, all
on by default:

- **Private and reserved ranges are never blocked.** In a lab the
  "attacker" is usually another VM on the same bridge, and blocking it
  can cut the manager off from its own agents. Override deliberately
  with `WAZUH_BLOCK_PRIVATE_IPS=true`.
- **`WAZUH_NEVER_BLOCK`** — comma-separated addresses that no risk
  score can touch. Put your own management IP here first.
- **Timeouts.** Wazuh reverses `firewall-drop` after the configured
  `<timeout>`, so a false positive self-heals.

The engine's existing interlocks still gate everything upstream:
`ACTIVE_ENFORCEMENT` mode, the risk threshold, and a minimum number of
correlated signals. One detector firing never contains anything.

---

## 5. Environment reference

| variable | default | meaning |
|---|---|---|
| `IDP` | `sim` | `wazuh-indexer` (poll) or `wazuh` (push) |
| `WAZUH_INDEXER_URL` | `https://localhost:9200` | Indexer endpoint |
| `WAZUH_INDEXER_USER` / `_PASSWORD` | `admin` / — | Indexer credentials |
| `WAZUH_API_URL` | `https://localhost:55000` | manager API |
| `WAZUH_API_USER` / `_PASSWORD` | `wazuh-wui` / — | manager credentials |
| `WAZUH_SHARED_TOKEN` | — | push-mode token; must equal `api_key` in ossec.conf |
| `WAZUH_LISTEN_PORT` | `8099` | push listener port |
| `WAZUH_VERIFY_TLS` | `false` | `true`, or a CA bundle path |
| `WAZUH_BLOCK_PRIVATE_IPS` | `false` | allow blocking private/reserved space |
| `WAZUH_NEVER_BLOCK` | — | comma-separated never-block list |
| `WAZUH_FALLBACK_AGENTS` | — | agent ids to act on when the endpoint can't be resolved |

`WAZUH_VERIFY_TLS` defaults to `false` because stock installs ship a
self-signed certificate. That is a real downgrade — it makes the
connection interceptable. Point it at the manager's CA bundle once you
have one.

---

## 6. Exercising it

On an enrolled endpoint, from another machine:

```bash
for i in $(seq 1 8); do sshpass -p wrong ssh alice@ENDPOINT true; done
ssh alice@ENDPOINT          # correct password
sudo -i                     # escalate
```

That sequence trips `ssh_bruteforce_success` (CRITICAL, T1110) and
`privilege_escalation` (HIGH, T1548), which together clear the CRITICAL
threshold and drive the containment playbook.

Offline equivalent, no infrastructure:

```bash
python soar_demo.py
```

---

## 7. Why host telemetry needs its own detections

The engine's original three detections were built for IdP data, and two
of them cannot fire on host logs at all:

- **MFA fatigue** needs MFA challenge events. sshd and PAM never emit
  them — there is no MFA concept in host auth logs.
- **Impossible travel** needs geo coordinates. Wazuh only populates
  `GeoLocation` when GeoIP is configured on the manager (off by
  default), and it never resolves for RFC1918 traffic, which is most of
  a lab.

Mapping Wazuh into the existing pipeline and stopping there gives you a
system that ingests real events and detects almost nothing. So
`itdr/wazuh_detections.py` adds five checkers built for what host
telemetry can actually evidence:

| checker | MITRE | fires on |
|---|---|---|
| `ssh_bruteforce_success` | T1110 | failed-password burst then a success from the same IP |
| `new_source_ip` | T1078 | first authentication for an account from an IP, after a learning period |
| `lateral_movement` | T1021 | one account reaching several endpoints in a short window |
| `privilege_escalation` | T1548 | sudo/su to root soon after a remote login |
| `off_hours_access` | T1078 | interactive auth outside working hours, in the event's own timezone |

The IdP checkers stay in the chain — impossible travel and Tor access
do fire once GeoIP is on and the source is internet-facing. They simply
abstain when the telemetry can't support them.

**Known limitation:** these five correlate across sessions and hosts,
which the shared `UserContext` doesn't model, so each holds its own
bounded in-process state. With multiple engine replicas behind one
manager, each replica sees only its own slice and correlation weakens.
Single-process deployments — every lab and most small SOCs — are
unaffected.
