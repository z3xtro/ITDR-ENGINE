# Wazuh → ITDR → TheHive: the full SOAR pipeline

The engine already contained hijacked sessions. This wires it into a
real SIEM on one end and a real case-management platform on the other,
so a containment action becomes an auditable, analyst-dispositionable
case instead of a line in a log file.

```
endpoint (sshd / Windows Security)
   │  wazuh-agent
   ▼
wazuh-manager ──(custom-itdr integration, auth groups only)──┐
                                                              │ HTTP POST
                                                              ▼
                                                    WazuhListener :8099
                                                              │ map_wazuh_alert
                                                              ▼
                                                       ITDREngine
                                            (impossible travel · session
                                             mutation · MFA fatigue)
                                                              │ ITDRAlert
                                    ┌─────────────────────────┤
                                    ▼                         ▼
                            SOARResponder              TheHiveBridge
                         (containment playbook,      NOTABLE → alert
                          dry-run by default)        CRITICAL → case
                                    │                   + "Automated
                                    └── actions ───────▶  containment" task
                                                          with one log per
                                                          playbook action
```

## Why staged

Wazuh's single-node stack wants ~4 GB. TheHive needs Cassandra and
Elasticsearch alongside it — realistically another 8 GB, and Cortex on
top of that. Bringing all of it up in one session is how you lose an
evening to Docker and have nothing to show.

**Stage 1** ([`deploy/wazuh/README.md`](../deploy/wazuh/README.md)):
Wazuh + one or two agents + the engine. Checkpoint: real login events
from a real endpoint produce a detection.

**Stage 2** ([`deploy/thehive/docker-compose.yml`](../deploy/thehive/docker-compose.yml)):
TheHive (+ Cortex only if RAM allows). Checkpoint: a CRITICAL alert
opens a case with the containment playbook logged on a task.

If a single machine can't hold both, run Stage 2 on a second box (or
pause the Wazuh stack while demoing Stage 2) — the engine talks to both
over HTTP, so they don't need to be co-located.

### Rough RAM budget

| Component | Heap / limit | Notes |
|---|---|---|
| wazuh-indexer | ~2 GB | the OpenSearch node; the hungry one |
| wazuh-manager + dashboard | ~1.5 GB | |
| cassandra | 1 GB heap | TheHive graph store |
| elasticsearch | 1 GB heap | TheHive index |
| thehive | 1 GB heap | |
| cortex | ~1 GB | optional — skip on first run |
| itdr engine + redis | < 300 MB | |

Under 16 GB, don't run both stacks and Cortex at once.

## Wazuh ingestion

`itdr.wazuh.map_wazuh_alert` is a pure function from a Wazuh alert dict
to an `AuthEvent` — the same type the Okta and Entra pollers emit, so
the detection pipeline is untouched by where telemetry came from.

Two things differ from an IdP source, and both are deliberate:

- **Session identity.** Host auth logs have no IdP session id. Events
  are keyed `wazuh:{user}@{agent}` — one logical session per user per
  endpoint. A source-IP or subnet change on that key is exactly the
  shape SessionMutation is looking for.
- **User agent.** There's no browser on an SSH login, so the field
  carries the authenticating program (`sshd`, `su`, `winlogon`). It
  still gives the mutation detector a context dimension: the same
  account authenticating via a different program mid-session is worth
  a signal.

Geo enrichment requires MaxMind GeoIP configured on the manager
(`<geoip_db_path>` in `ossec.conf`). Without it, impossible-travel stays
quiet on Wazuh-sourced events — it needs coordinates, and the mapper
correctly emits `None` rather than inventing them.

### Transport security

The listener refuses to start without `WAZUH_SHARED_TOKEN`, and compares
the `X-ITDR-Token` header constant-time. An unauthenticated ingestion
port is an event-injection primitive: anyone who can reach it can forge
an authentication event and steer the risk score. Bind it to the
management network, not a public interface.

## TheHive case pipeline

Every alert becomes a TheHive alert with observables (source IP, user
agent, identity) and MITRE tags. CRITICAL alerts are promoted to a case
carrying an **Automated containment** task, one task log per action the
responder took — including the dry-run narration, so a passive-mode run
still produces a complete case record.

Dedup rides on TheHive's `(type, source, sourceRef)` uniqueness; a
replayed alert collides and is logged as a no-op rather than opening a
second case.

**Ordering matters:** containment runs first, case creation second. A
TheHive outage must never delay revoking a hijacked session, so the
bridge is strictly downstream and swallows its own failures (counted in
`bridge.stats["errors"]`).

### False-positive disposition

```python
bridge.close_false_positive(alert.id, note="VPN egress change, benign")
await responder.rollback_containment(alert.id)   # itdr.enforcement
```

Closes the case as FalsePositive and reverses what's reversible. Revoked
sessions and reset MFA factors can't be un-revoked — the user simply
re-authenticates — so only the account suspension actually rolls back.
`rollback_containment` says so explicitly rather than implying a clean
undo.

## Configuration

| Variable | Meaning |
|---|---|
| `IDP=wazuh` | push mode: run the listener instead of a poller |
| `WAZUH_SHARED_TOKEN` | required; must equal the integration's `api_key` |
| `WAZUH_LISTEN_PORT` | default 8099 |
| `THEHIVE_URL` | e.g. `http://localhost:9000` |
| `THEHIVE_API_KEY` | service-account key from TheHive |
| `THEHIVE_VERIFY_TLS` | `false` for lab self-signed certs |

TheHive wiring is opt-in: with both variables unset, the bridge isn't
constructed and the engine behaves exactly as before.
