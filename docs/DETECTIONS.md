# Detection Catalog

> Auto-generated from `itdr/catalog.py` — regenerate with `python -m itdr.catalog`. The code is the source of truth; this document cannot drift.

## MITRE ATT&CK Coverage

| Detection | Technique | Tactic | Severity |
|---|---|---|---|
| Impossible Travel | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | Initial Access / Defense Evasion | HIGH |
| Session Context Mutation | [T1550.004](https://attack.mitre.org/techniques/T1550/004/) Use Alternate Authentication Material: Web Session Cookie | Lateral Movement / Defense Evasion | HIGH–CRITICAL |
| MFA Fatigue (Push Bombing) | [T1621](https://attack.mitre.org/techniques/T1621/) Multi-Factor Authentication Request Generation | Credential Access | HIGH |
| Failed-Login Burst Preceding Success | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Credential Access | HIGH |
| TOR Exit Access | [T1090.003](https://attack.mitre.org/techniques/T1090/003/) Proxy: Multi-hop Proxy | Command and Control / Defense Evasion | MEDIUM |
| Refresh Token Replay | [T1550.004](https://attack.mitre.org/techniques/T1550/004/) Use Alternate Authentication Material: Web Session Cookie | Defense Evasion / Lateral Movement | HIGH |
| Mass Session Creation | [T1136](https://attack.mitre.org/techniques/T1136/) Create Account (session flooding) | Persistence / Credential Access | HIGH |
| Brute Force Succeeded | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Credential Access | CRITICAL |
| First-Seen Source IP | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | Initial Access / Persistence | LOW |
| Credential Used Across Endpoints | [T1021](https://attack.mitre.org/techniques/T1021/) Remote Services | Lateral Movement | HIGH |
| Escalation After Remote Login | [T1548](https://attack.mitre.org/techniques/T1548/) Abuse Elevation Control Mechanism | Privilege Escalation | HIGH |
| Off-Hours Authentication | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | Initial Access / Defense Evasion | LOW |

## Impossible Travel

**Technique:** T1078 — Valid Accounts  
**Tactic:** Initial Access / Defense Evasion  
**Severity:** HIGH  
**Implementation:** `itdr.detections.ImpossibleTravelChecker`

### Hypothesis
Two successful authentications for the same user from locations that no physical means of travel could connect in the elapsed time indicate credential compromise — the second login is an attacker, not the user.

### Required telemetry
- Successful authentication events with geo-IP resolution (lat/lon)
- Per-user login history (cross-session)

### Detection logic
`velocity = haversine(prev_success_geo, geo) / Δt ; flag if velocity > 800 km/h AND distance > 50 km. Confidence ramps 0.5 → 1.0 between 800 and 4,000 km/h.`

### Known false-positive modes
- VPN/proxy egress switching (user joins corporate VPN mid-session → geo jumps to VPN concentrator). Mitigate by allowlisting known corporate egress ranges upstream.
- Geo-IP database inaccuracy for mobile carriers. The 50 km minimum-distance floor absorbs most of this jitter.
- Shared service accounts used from multiple sites simultaneously — exclude service principals or route them to a separate baseline.

### Tuning guidance
- `max_kmh` (default 800): lower to ~500 for high-security tenants willing to review commercial-flight edge cases.
- `min_distance_km` (default 50): raise to 150+ if your geo-IP source is city-imprecise.

### References
- https://attack.mitre.org/techniques/T1078/

## Session Context Mutation

**Technique:** T1550.004 — Use Alternate Authentication Material: Web Session Cookie  
**Tactic:** Lateral Movement / Defense Evasion  
**Severity:** HIGH–CRITICAL  
**Implementation:** `itdr.detections.SessionMutationChecker`

### Hypothesis
A session token presented mid-session from a different device fingerprint (User-Agent) or network (/24 subnet) without re-authentication indicates the token was stolen and replayed — AiTM phishing kits and infostealers both produce exactly this pattern.

### Required telemetry
- All session-scoped events (token refresh, API access) with client IP + User-Agent
- Stable session identifiers across the session lifetime

### Detection logic
`On established sessions only (never the first event, never at LOGIN/MFA boundaries): UA change ⇒ conf 0.85 HIGH; subnet change ⇒ conf 0.55 MEDIUM; both ⇒ conf 0.95 CRITICAL.`

### Known false-positive modes
- Mobile roaming and CGNAT legitimately rotate IPs — this is why subnet-only mutation is deliberately scored at 0.55, below the alert threshold on its own.
- Browser auto-updates change the UA version string. Consider comparing parsed UA family+OS rather than the raw string for strictness reduction.
- Corporate proxies that rewrite or strip UA headers.

### Tuning guidance
- Compare /16 instead of /24 for carrier-grade-NAT-heavy user bases (reduces subnet-change noise further).
- Add an allowlist of managed-device UA transitions if MDM data is available.

### References
- https://attack.mitre.org/techniques/T1550/004/

## MFA Fatigue (Push Bombing)

**Technique:** T1621 — Multi-Factor Authentication Request Generation  
**Tactic:** Credential Access  
**Severity:** HIGH  
**Implementation:** `itdr.detections.MFAFatigueChecker`

### Hypothesis
An attacker with valid credentials spams MFA push notifications until the victim approves one out of exhaustion or confusion. A rejection burst followed closely by an acceptance is the capitulation signature (the Uber 2022 breach pattern).

### Required telemetry
- MFA challenge events with results (cross-session per user — attacker pushes and victim approval may ride different session IDs)

### Detection logic
`≥ 5 MFA FAILs within 120 s, then a SUCCESS within 90 s of the last failure. The burst is consumed on firing to prevent duplicate alerts. Confidence grows +0.08 per failure beyond the threshold.`

### Known false-positive modes
- A user with a broken authenticator retrying repeatedly, then succeeding after a fix. Rare at ≥5-in-2-min density, but pair the alert with a user-confirmation step (e.g. Slack bot asking 'was this you?') before containment.
- Time-drifted TOTP codes causing repeated soft failures — distinguishable upstream by failure sub-reason if the IdP provides it.

### Tuning guidance
- `fail_count` (default 5) / `fail_window` (default 120 s): tighten to 3/60 for admin accounts.
- `success_grace` (default 90 s): the max gap between the last rejection and the capitulation approval.

### References
- https://attack.mitre.org/techniques/T1621/

## Failed-Login Burst Preceding Success

**Technique:** T1110 — Brute Force  
**Tactic:** Credential Access  
**Severity:** HIGH  
**Implementation:** `itdr.detections.AuthFailureBurstChecker`

### Hypothesis
A dense burst of failed authentications for one account followed promptly by a success means the guessing worked — the successful login is the attacker, not the user. This is the detection host telemetry (Wazuh sshd/PAM/Windows Security) can feed: those sources emit only login success/fail records, with no mid-session or MFA-challenge events for the other checkers to work with.

### Required telemetry
- Failed and successful login events with a user identifier (cross-session per user — a brute-force run may produce a fresh session key per attempt)

### Detection logic
`≥ 8 failed LOGINs within 300 s, then a SUCCESS within 120 s of the last failure. The burst is consumed on firing. Confidence grows +0.05 per failure beyond the threshold, +0.20 when the attempt rate exceeds 0.5/s (machine-speed guessing rather than human fumbling).`

### Known false-positive modes
- A user locked out by a stale cached credential — a mail client or mapped drive retrying an old password in the background — who then logs in correctly. Check whether the failures share the source IP of the success.
- Automated service accounts with rotated secrets retrying against a stale value. Exclude service principals or give them a separate, higher threshold.
- Shared-workstation kiosk accounts where several people mistype before one succeeds.

### Tuning guidance
- `fail_count` (default 8) / `fail_window` (default 300 s): lower to 5/120 for administrative accounts.
- `success_grace` (default 120 s): the maximum gap between the last failure and the successful login that still counts as the same episode.

### References
- https://attack.mitre.org/techniques/T1110/

## TOR Exit Access

**Technique:** T1090.003 — Proxy: Multi-hop Proxy  
**Tactic:** Command and Control / Defense Evasion  
**Severity:** MEDIUM  
**Implementation:** `itdr.detections.TorAccessChecker`

### Hypothesis
Authentication from a known TOR exit node is a strong anonymization signal — legitimate enterprise users rarely reach corporate IdPs over TOR. Enriched, not raw.

### Required telemetry
- Client IP
- TOR exit list (offline seed + optional live refresh from check.torproject.org)

### Detection logic
`IP ∈ TOR exit set on a SUCCESS event ⇒ MEDIUM/conf 0.70. Also adds +0.15 confidence to Impossible Travel.`

### Known false-positive modes
- Privacy-conscious legitimate users on TOR. Scope to workforce IdPs where TOR is out-of-policy to minimize this.
- Stale exit-list entries — refresh periodically.

### Tuning guidance
- Swap the offline seed for a scheduled live refresh in high-security tenants.

### References
- https://attack.mitre.org/techniques/T1090/003/

## Refresh Token Replay

**Technique:** T1550.004 — Use Alternate Authentication Material: Web Session Cookie  
**Tactic:** Defense Evasion / Lateral Movement  
**Severity:** HIGH  
**Implementation:** `itdr.detections.RefreshTokenReplayChecker`

### Hypothesis
A refresh/token event on an established session arriving from a different IP than the session origin indicates a stolen refresh token replayed from attacker infrastructure.

### Required telemetry
- Token refresh events with client IP
- Established session origin IP

### Detection logic
`TOKEN_REFRESH on an established session where refresh IP ≠ session IP ⇒ HIGH; +0.2 confidence if the refresh IP is TOR/hosting.`

### Known false-positive modes
- Legitimate network changes mid-session (roaming). Correlate with geo distance to suppress benign same-city hops.
- Corporate egress IP rotation.

### Tuning guidance
- Require a minimum geo distance between session and refresh IP before firing.

### References
- https://attack.mitre.org/techniques/T1550/004/

## Mass Session Creation

**Technique:** T1136 — Create Account (session flooding)  
**Tactic:** Persistence / Credential Access  
**Severity:** HIGH  
**Implementation:** `itdr.detections.MassSessionChecker`

### Hypothesis
A burst of distinct new sessions for one user in a short window indicates automated session/token minting after a credential compromise.

### Required telemetry
- Successful LOGIN / TOKEN_REFRESH events, tracked cross-session per user

### Detection logic
`≥5 distinct session ids for one user within 120 s ⇒ HIGH; confidence grows with the count.`

### Known false-positive modes
- Load-balanced apps or SDKs that legitimately open many short-lived sessions — exclude service principals.
- Aggressive token refresh by a single misconfigured client.

### Tuning guidance
- Raise the count threshold for known automation accounts; separate baseline for service principals.

### References
- https://attack.mitre.org/techniques/T1136/

## Brute Force Succeeded

**Technique:** T1110 — Brute Force  
**Tactic:** Credential Access  
**Severity:** CRITICAL  
**Implementation:** `itdr.wazuh_detections.SSHBruteForceSuccessChecker`

### Hypothesis
Password guessing is common and mostly harmless noise; password guessing that SUCCEEDS is a compromised credential with no ambiguity. Correlating the burst and the success on the same source IP is what separates an attacker who got in from a scanner that did not.

### Required telemetry
- Failed authentication events with source IP (sshd 5716/5710/5760, Windows 4625)
- Successful authentication events with source IP (sshd 5715, PAM 5501, Windows 4624)

### Detection logic
`Per (user, source IP): maintain a 300s sliding window of failures. On a success from that same pair, flag if the window holds >= 5 failures and the success lands within 120s of the last one. Confidence 0.75 at 5 failures, ramping to 1.0 by 15. That ramp is calibrated against the risk model, not chosen by feel: at CRITICAL severity (90) a detection needs confidence > 0.834 to reach the CRITICAL alert tier (75) unaided, so a large burst must clear it.`

### Known false-positive modes
- A user who genuinely forgot their password, retried past the threshold, then succeeded. Mitigated by requiring 5+ failures — above typical human typo volume — but not eliminated. This is the dominant FP mode.
- Automation with a stale credential that is rotated and retried: a script fails repeatedly, someone fixes the secret, the next run succeeds. Looks identical.
- Shared NAT egress: several users behind one public IP can pool failures that belong to different people, then any one of them succeeding trips the rule.

### Tuning guidance
- fail_count (default 5) — raise to 8-10 on hosts with interactive users who fumble passwords; lower to 3 on service-account-only hosts where any failure is abnormal.
- success_grace (default 120s) — the attacker's success follows their burst closely. Shrinking this to 30s sharply cuts the forgotten-password FP at some cost to recall.
- Correlate with new_source_ip: a burst-then-success from an IP the account has never used is far stronger evidence than one from the user's usual address.

### References
- https://attack.mitre.org/techniques/T1110/
- Wazuh stock rules 5710, 5712, 5716, 5763

## First-Seen Source IP

**Technique:** T1078 — Valid Accounts  
**Tactic:** Initial Access / Persistence  
**Severity:** LOW  
**Implementation:** `itdr.wazuh_detections.NewSourceIPChecker`

### Hypothesis
An account authenticating from an address it has never used is weakly suspicious on its own and strongly suspicious in company. Its job is not to alert; its job is to add the points that push a genuinely bad session over the line.

### Required telemetry
- Successful authentication events with source IP
- Per-user history of previously observed sources

### Detection logic
`Track the last 32 distinct source IPs per user. After a learning period of 3 observed sources, flag the first authentication from an address not in that set. Confidence fixed at 0.6; severity LOW by design.`

### Known false-positive modes
- Ordinary mobility — new laptop, home vs office, hotel Wi-Fi, phone tethering. This fires legitimately a lot and is deliberately scored low because of it.
- Dynamic residential IPs: a DHCP lease renewal or router reboot changes the address with no user action at all.
- Cold start: an account with fewer than 3 observed sources has no baseline, so every address is 'new'. Suppressed by the learning period rather than alerted on.

### Tuning guidance
- learn_after (default 3) — raise for populations with high mobility; the cost is a longer blind window on new accounts.
- Prefer subnet or ASN granularity over exact IP in environments with dynamic addressing; exact-IP matching is the noisiest possible choice and is used here only because host logs carry nothing richer.
- Never promote this to a standalone alerting severity. If it is firing alone, the correct response is to tune it out, not to escalate it.

### References
- https://attack.mitre.org/techniques/T1078/

## Credential Used Across Endpoints

**Technique:** T1021 — Remote Services  
**Tactic:** Lateral Movement  
**Severity:** HIGH  
**Implementation:** `itdr.wazuh_detections.LateralMovementChecker`

### Hypothesis
A human works from one or two machines. A credential authenticating to several distinct endpoints inside a few minutes is either an attacker moving laterally with stolen credentials, or automation that should be running as a service account under a different identity.

### Required telemetry
- Successful authentication events
- Agent/endpoint identity per event
- Per-user cross-host history

### Detection logic
`Per user: a 600s sliding window of (timestamp, endpoint) for successes only. Flag when the window contains 3 or more distinct endpoints. Fires once at the threshold crossing, not on every subsequent event.`

### Known false-positive modes
- Configuration management and monitoring — Ansible, Puppet, backup agents and health checks legitimately touch many hosts fast. This is the dominant FP and the reason the rule is HIGH rather than CRITICAL.
- Administrators doing genuine fleet work during an incident or a patch window.
- Jump-host topologies where one bastion account is the designed path to everything.

### Tuning guidance
- host_threshold (default 3) — raise in environments where admin fan-out is routine.
- Maintain an allowlist of automation accounts and exclude them outright. This single measure removes most FPs; do it before touching thresholds.
- window_s (default 600s) — shrink to sharpen the distinction between a burst of lateral movement and a human working across hosts over an afternoon.

### References
- https://attack.mitre.org/techniques/T1021/

## Escalation After Remote Login

**Technique:** T1548 — Abuse Elevation Control Mechanism  
**Tactic:** Privilege Escalation  
**Severity:** HIGH  
**Implementation:** `itdr.wazuh_detections.PrivilegeEscalationChecker`

### Hypothesis
sudo is routine and alerting on it is useless. What is not routine is the sequence: authenticate from the network, then immediately become root. That ordering is the tail of a compromise, whereas an admin who has been working on the box for an hour is just working.

### Required telemetry
- Successful remote logins with source IP
- Privilege escalation events (sudo 5402, su 5404)
- Ordering and elapsed time between the two

### Detection logic
`A successful remote login (source IP present) arms a 300s window for that (user, endpoint). A subsequent successful sudo/su inside the window flags. Console logins never arm it; the window is consumed on fire so one login yields at most one detection.`

### Known false-positive modes
- Normal administrative practice — many engineers SSH in and run `sudo -i` as the first thing they do. On an admin-heavy host this fires constantly and legitimately.
- Deployment and CI pipelines that connect and immediately escalate as a designed step.
- Break-glass and on-call response, which looks exactly like an intruder by construction.

### Tuning guidance
- window_s (default 300s) — the shorter it is, the more specific the 'landed and immediately escalated' pattern.
- Exclude known administrator accounts, or invert the logic for them: alert when a NON-admin escalates rather than when anyone does.
- Highest value when correlated. Escalation after a brute-force success is a different event from escalation after a normal login, and only the risk model sees that.

### References
- https://attack.mitre.org/techniques/T1548/

## Off-Hours Authentication

**Technique:** T1078 — Valid Accounts  
**Tactic:** Initial Access / Defense Evasion  
**Severity:** LOW  
**Implementation:** `itdr.wazuh_detections.OffHoursAccessChecker`

### Hypothesis
Attackers prefer hours when nobody is watching. Taken alone this is nearly worthless — plenty of legitimate work happens at night — but as a multiplier on an already suspicious session it meaningfully shifts the priority.

### Required telemetry
- Successful interactive authentication events
- Event timestamps with the originating timezone offset preserved

### Detection logic
`Flag successful logins outside 08:00-20:00 local, or at any hour on a weekend. Evaluated in the event's own timezone, which Wazuh preserves, so a laptop in IST is judged against IST. Reported at most once per user, per endpoint, per local date.`

### Known false-positive modes
- Night shifts, on-call rotations, and globally distributed teams, for whom 'off-hours' is simply their working day.
- Scheduled jobs and maintenance windows, which are deliberately placed at night.
- Any timezone assumption at all. A fixed 08:00-20:00 window is wrong for someone somewhere in every organisation.

### Tuning guidance
- start_hour / end_hour — set per population, not globally. One window for an entire company is always wrong.
- Per-user learned baselines beat a fixed window: alert on deviation from THIS account's normal hours rather than from an arbitrary office schedule.
- The once-per-day cap is load-bearing, not cosmetic. Firing per login let this detector accumulate ~11 risk points per event until it raised a NOTABLE alert entirely on its own — observed on live data, nine logins in one night. A weak signal that repeats must never be able to cross a tier without corroboration.

### References
- https://attack.mitre.org/techniques/T1078/
