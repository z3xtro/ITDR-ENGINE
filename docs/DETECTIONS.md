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
