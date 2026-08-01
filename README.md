# ITDR Engine

**Identity Threat Detection & Response — a stateful analytics engine for post-authentication identity attacks.**

[![CI](https://github.com/YOUR_USERNAME/itdr-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/itdr-engine/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> **MFA is not a finish line.** Most identity tooling stops watching once a
> login succeeds. This engine watches what happens *after* — token replay,
> MFA push-bombing, and physically impossible session geography — and
> answers with an automated, auditable containment response.

---

## What it does

ITDR Engine ingests authentication telemetry shaped like Okta or Microsoft
Entra ID events, maintains a live, per-session behavioral fingerprint,
scores each session against three real-time detections, and — when risk
crosses a threshold — drives a SOAR containment playbook against the
identity provider. It ships as a library, a CLI demo, and a container-ready
always-on service.

```
                     ┌─────────────────────────────────────────┐
                     │            DETECTION PIPELINE            │
AuthEvent ──────────▶│  ImpossibleTravel │ SessionMutation │    │
(Okta / Entra /      │                   │      MFAFatigue     │
 simulator)          └──────────┬──────────────────┬───────────┘
                                 │  risk points      │
                                 ▼                   │
                          SessionState  ◀────────────┘
                        (Redis or in-memory)
                                 │
                     risk ≥ threshold?
                                 │
                                 ▼
                            ITDRAlert ───▶ SOARResponder ───▶ IdP API
                                              │                (mock or live)
                                    dry_run=True by default
                                    JSONL audit trail, always
```

## Detections

| Detection | MITRE ATT&CK | Trigger logic |
|---|---|---|
| **Impossible Travel** | [T1078](https://attack.mitre.org/techniques/T1078/) | Haversine distance between a user's consecutive successful logins ÷ elapsed time. Velocity > 800 km/h flags; confidence scales with how extreme the velocity is. Tracked cross-session per user. |
| **Session Context Mutation** | [T1550.004](https://attack.mitre.org/techniques/T1550/004/) | Mid-session change of User-Agent and/or IP /24 on an *already-established* session, without re-authentication — the signature of a replayed stolen token. UA+subnet together escalates to CRITICAL. |
| **MFA Fatigue** | [T1621](https://attack.mitre.org/techniques/T1621/) | ≥5 MFA rejections within 120s followed by an acceptance within 90s — the push-bombing capitulation pattern (the 2022 Uber breach signature). |

Every detection's full writeup — hypothesis, required telemetry, **known
false-positive modes**, and tuning knobs — lives in
[`docs/DETECTIONS.md`](docs/DETECTIONS.md), auto-generated from
[`itdr/catalog.py`](itdr/catalog.py) and kept in sync by a CI drift check.

### Risk & correlation

Each detection contributes `severity × confidence` points to its session.
Signals compound — a stolen-token replay typically trips *both*
impossible-travel and session-mutation, pushing one session past the
CRITICAL line. That correlation is what separates this from three
independent alert scripts:

| Session risk | Tier | Response |
|---|---|---|
| ≥ 40 | `NOTABLE` | SOC notification only |
| ≥ 75 | `CRITICAL` | Notification + automated containment playbook |

## Response

On a CRITICAL alert, `SOARResponder` runs a containment playbook against
the identity provider: revoke all sessions, force MFA re-enrollment, notify
the SOC channel. Guardrails, not optional extras:

- **`dry_run=True` by default** — every action is fully planned and logged
  as `[DRY-RUN] would revoke...`; nothing touches a real account until you
  explicitly disable it.
- **Protected principals** (break-glass admins) can never be
  auto-contained — routed to manual review instead.
- **Every decision is audited** to an append-only JSONL log, including
  decisions *not* to act.

## Production posture

Three deliberate design choices separate this from a single-file demo
script:

**Scale.** Session state sits behind a `SessionStore` interface
([`itdr/state.py`](itdr/state.py)) with two implementations: in-memory
(default, zero dependencies) and `RedisStore`, which lets multiple engine
workers share state with eviction delegated entirely to Redis key TTLs. A
parity test asserts the token-theft attack produces an identical CRITICAL
alert on both backends.

**Live telemetry.** [`itdr/pollers.py`](itdr/pollers.py) implements real
**Okta System Log** and **Microsoft Graph (Entra sign-ins)** clients —
cursor persistence for restart-safety, exponential backoff on rate limits,
and pure mapping functions unit-tested against recorded API response
fixtures. Point it at a free Okta developer org or M365 E5 dev tenant and
the engine consumes real logins with no changes to detection code.

**Attack validation.** [`validate.py`](validate.py) emulates every
catalogued MITRE technique through a fresh engine and asserts the correct
detection fires at the correct tier — plus a negative case asserting
benign traffic stays *silent*. The output is a pass/fail matrix
([`docs/VALIDATION.md`](docs/VALIDATION.md)) enforced in CI: a change that
breaks a detection fails the build.

## Quickstart

**Local:**
```bash
pip install rich pytest requests redis fakeredis
python -m itdr --speed 5              # replay attack scenarios, dry-run
python -m itdr --live                 # same, mock IdP calls marked LIVE
python -m pytest tests/ -v            # 18 tests
python validate.py                    # MITRE technique validation matrix
python benchmark.py                   # throughput measurement
```

**Container (engine + Redis):**
```bash
docker compose up                                              # demo telemetry
IDP=okta OKTA_ORG_URL=https://dev-xxxx.okta.com \
  OKTA_API_TOKEN=*** docker compose up                          # live Okta
```

### Configuration

`itdr/service.py` is configured entirely by environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `IDP` | `sim` | `sim` \| `okta` \| `entra` — telemetry source |
| `POLL_INTERVAL` | `60` | Seconds between polling passes |
| `STATE_BACKEND` | `memory` | `memory` \| `redis` |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `DRY_RUN` | `true` | SOAR containment gate |
| `OKTA_ORG_URL`, `OKTA_API_TOKEN` | — | Required if `IDP=okta` |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` | — | Required if `IDP=entra` |

## Engineering properties

- **Fast** — ~108,000 events/sec sustained single-thread throughput
  (9.2 µs/event) through the full pipeline, measured on a realistic
  500-user traffic mix (`benchmark.py`).
- **Thread-safe** — a single `RLock` guards state; alert callbacks fire
  outside the lock so a slow webhook can't stall ingestion. Verified under
  concurrent 8-thread load.
- **Memory-bounded** — per-session history is a fixed-size deque; idle
  sessions are evicted by TTL (wall-clock in-memory, native in Redis) —
  no unbounded growth, no background threads required.
- **Tested** — 18 pytest cases: detection math, trigger *and*
  non-trigger paths (a slow traveler and one fat-fingered MFA push stay
  quiet), Redis/in-memory parity, poller field-mapping against fixtures,
  pruning, tiering, and both SOAR guardrails. Enforced in CI on every push,
  across Python 3.11 and 3.12.

## Repository structure

```
itdr/
├── models.py       # AuthEvent, SessionState, Detection, ITDRAlert
├── detections.py   # ImpossibleTravel / SessionMutation / MFAFatigue checkers
├── state.py         # SessionStore interface: InMemoryStore, RedisStore
├── engine.py        # thread-safe stateful core, risk tiering
├── respond.py        # SOAR playbooks, MockIdPClient, dry-run + audit log
├── enrichment.py     # TOR/hosting IP reputation
├── metrics.py        # Prometheus /metrics exporter
├── pollers.py        # Okta System Log + Entra Graph API clients
├── service.py        # always-on entry point (env-var configured)
├── catalog.py         # detection-as-code registry → docs/DETECTIONS.md
├── simulator.py        # deterministic benign + attack telemetry generator
└── __main__.py          # CLI demo runner
tests/
├── test_itdr.py           # core engine, detections, guardrails
└── test_scale_and_pollers.py  # Redis parity, poller fixture mapping
docs/
├── DETECTIONS.md   # auto-generated detection catalog
└── VALIDATION.md   # auto-generated attack-validation matrix
benchmark.py   # throughput measurement harness
replay.py      # JSON incident timeline replay
validate.py    # purple-team validation harness (CI-enforced)
Dockerfile
docker-compose.yml
.github/workflows/ci.yml
```

## Extending

- **New detector** — implement `check(event, session, ctx) -> Detection | None`
  and add it to `DEFAULT_CHECKERS` in `detections.py`. Risk aggregation,
  correlation, and alerting all come for free.
- **New IdP source** — add a mapping function (`map_x_event`) and a poller
  class in `pollers.py` following the Okta/Entra pattern; the engine is
  transport-agnostic by construction.
- **Real containment** — swap `MockIdPClient` in `respond.py` for a real
  HTTP client; the playbook logic doesn't change.

## Known limitations

Stated plainly, because a detection engineer's job includes knowing where
the edges are:

- `RedisStore` performs per-key read-modify-write without a distributed
  lock — safe when events are partitioned by user across workers (the
  standard Kafka-keyed deployment shape), but concurrent writers on the
  *same* user session could race. A Lua-script/`WATCH` upgrade closes this.
- Detections are validated against emulated attacks and fixture data, not
  production traffic from a live enterprise tenant — the natural next step
  is a purple-team engagement against a real Okta/Entra org.
- Geo-IP accuracy bounds the Impossible Travel detection; the 50 km
  minimum-distance floor absorbs most jitter but a poor geo-IP source will
  still produce noise.

## License

MIT — see [`LICENSE`](LICENSE).
