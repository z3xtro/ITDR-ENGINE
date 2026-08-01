"""
itdr.catalog
============
Detection-as-code catalog. Every detection ships with its own metadata:
hypothesis, telemetry requirements, false-positive analysis, and tuning
knobs. `python -m itdr.catalog` regenerates docs/DETECTIONS.md so the
documentation can never drift from the code — the doc IS the registry.

This mirrors how mature detection engineering teams operate: a detection
without documented FP modes and tuning guidance is not production-ready.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .detections import (ImpossibleTravelChecker, MFAFatigueChecker,
                         MassSessionChecker, RefreshTokenReplayChecker,
                         SessionMutationChecker, TorAccessChecker)


@dataclass(frozen=True)
class DetectionDoc:
    checker_cls: type
    name: str
    mitre_id: str
    mitre_name: str
    tactic: str
    severity: str
    hypothesis: str
    telemetry: list[str]
    logic: str
    false_positives: list[str]
    tuning: list[str]
    references: list[str] = field(default_factory=list)


CATALOG: list[DetectionDoc] = [
    DetectionDoc(
        checker_cls=ImpossibleTravelChecker,
        name="Impossible Travel",
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        tactic="Initial Access / Defense Evasion",
        severity="HIGH",
        hypothesis=(
            "Two successful authentications for the same user from "
            "locations that no physical means of travel could connect "
            "in the elapsed time indicate credential compromise — the "
            "second login is an attacker, not the user."),
        telemetry=["Successful authentication events with geo-IP "
                   "resolution (lat/lon)", "Per-user login history "
                   "(cross-session)"],
        logic=("velocity = haversine(prev_success_geo, geo) / Δt ; "
               "flag if velocity > 800 km/h AND distance > 50 km. "
               "Confidence ramps 0.5 → 1.0 between 800 and 4,000 km/h."),
        false_positives=[
            "VPN/proxy egress switching (user joins corporate VPN "
            "mid-session → geo jumps to VPN concentrator). Mitigate by "
            "allowlisting known corporate egress ranges upstream.",
            "Geo-IP database inaccuracy for mobile carriers. The 50 km "
            "minimum-distance floor absorbs most of this jitter.",
            "Shared service accounts used from multiple sites "
            "simultaneously — exclude service principals or route them "
            "to a separate baseline.",
        ],
        tuning=[
            "`max_kmh` (default 800): lower to ~500 for high-security "
            "tenants willing to review commercial-flight edge cases.",
            "`min_distance_km` (default 50): raise to 150+ if your "
            "geo-IP source is city-imprecise.",
        ],
        references=["https://attack.mitre.org/techniques/T1078/"],
    ),
    DetectionDoc(
        checker_cls=SessionMutationChecker,
        name="Session Context Mutation",
        mitre_id="T1550.004",
        mitre_name="Use Alternate Authentication Material: Web Session "
                   "Cookie",
        tactic="Lateral Movement / Defense Evasion",
        severity="HIGH–CRITICAL",
        hypothesis=(
            "A session token presented mid-session from a different "
            "device fingerprint (User-Agent) or network (/24 subnet) "
            "without re-authentication indicates the token was stolen "
            "and replayed — AiTM phishing kits and infostealers both "
            "produce exactly this pattern."),
        telemetry=["All session-scoped events (token refresh, API "
                   "access) with client IP + User-Agent",
                   "Stable session identifiers across the session "
                   "lifetime"],
        logic=("On established sessions only (never the first event, "
               "never at LOGIN/MFA boundaries): UA change ⇒ conf 0.85 "
               "HIGH; subnet change ⇒ conf 0.55 MEDIUM; both ⇒ conf "
               "0.95 CRITICAL."),
        false_positives=[
            "Mobile roaming and CGNAT legitimately rotate IPs — this "
            "is why subnet-only mutation is deliberately scored at "
            "0.55, below the alert threshold on its own.",
            "Browser auto-updates change the UA version string. "
            "Consider comparing parsed UA family+OS rather than the "
            "raw string for strictness reduction.",
            "Corporate proxies that rewrite or strip UA headers.",
        ],
        tuning=[
            "Compare /16 instead of /24 for carrier-grade-NAT-heavy "
            "user bases (reduces subnet-change noise further).",
            "Add an allowlist of managed-device UA transitions if MDM "
            "data is available.",
        ],
        references=["https://attack.mitre.org/techniques/T1550/004/"],
    ),
    DetectionDoc(
        checker_cls=MFAFatigueChecker,
        name="MFA Fatigue (Push Bombing)",
        mitre_id="T1621",
        mitre_name="Multi-Factor Authentication Request Generation",
        tactic="Credential Access",
        severity="HIGH",
        hypothesis=(
            "An attacker with valid credentials spams MFA push "
            "notifications until the victim approves one out of "
            "exhaustion or confusion. A rejection burst followed "
            "closely by an acceptance is the capitulation signature "
            "(the Uber 2022 breach pattern)."),
        telemetry=["MFA challenge events with results (cross-session "
                   "per user — attacker pushes and victim approval may "
                   "ride different session IDs)"],
        logic=("≥ 5 MFA FAILs within 120 s, then a SUCCESS within 90 s "
               "of the last failure. The burst is consumed on firing "
               "to prevent duplicate alerts. Confidence grows +0.08 "
               "per failure beyond the threshold."),
        false_positives=[
            "A user with a broken authenticator retrying repeatedly, "
            "then succeeding after a fix. Rare at ≥5-in-2-min "
            "density, but pair the alert with a user-confirmation "
            "step (e.g. Slack bot asking 'was this you?') before "
            "containment.",
            "Time-drifted TOTP codes causing repeated soft failures — "
            "distinguishable upstream by failure sub-reason if the "
            "IdP provides it.",
        ],
        tuning=[
            "`fail_count` (default 5) / `fail_window` (default 120 s): "
            "tighten to 3/60 for admin accounts.",
            "`success_grace` (default 90 s): the max gap between the "
            "last rejection and the capitulation approval.",
        ],
        references=["https://attack.mitre.org/techniques/T1621/"],
    ),
    DetectionDoc(
        checker_cls=TorAccessChecker,
        name="TOR Exit Access",
        mitre_id="T1090.003", mitre_name="Proxy: Multi-hop Proxy",
        tactic="Command and Control / Defense Evasion",
        severity="MEDIUM",
        hypothesis=(
            "Authentication from a known TOR exit node is a strong "
            "anonymization signal — legitimate enterprise users rarely "
            "reach corporate IdPs over TOR. Enriched, not raw."),
        telemetry=["Client IP", "TOR exit list (offline seed + optional "
                   "live refresh from check.torproject.org)"],
        logic=("IP ∈ TOR exit set on a SUCCESS event ⇒ MEDIUM/conf 0.70. "
               "Also adds +0.15 confidence to Impossible Travel."),
        false_positives=[
            "Privacy-conscious legitimate users on TOR. Scope to "
            "workforce IdPs where TOR is out-of-policy to minimize this.",
            "Stale exit-list entries — refresh periodically."],
        tuning=["Swap the offline seed for a scheduled live refresh in "
                "high-security tenants."],
        references=["https://attack.mitre.org/techniques/T1090/003/"]),
    DetectionDoc(
        checker_cls=RefreshTokenReplayChecker,
        name="Refresh Token Replay",
        mitre_id="T1550.004", mitre_name="Use Alternate Authentication "
        "Material: Web Session Cookie",
        tactic="Defense Evasion / Lateral Movement",
        severity="HIGH",
        hypothesis=(
            "A refresh/token event on an established session arriving "
            "from a different IP than the session origin indicates a "
            "stolen refresh token replayed from attacker infrastructure."),
        telemetry=["Token refresh events with client IP",
                   "Established session origin IP"],
        logic=("TOKEN_REFRESH on an established session where refresh IP "
               "≠ session IP ⇒ HIGH; +0.2 confidence if the refresh IP "
               "is TOR/hosting."),
        false_positives=[
            "Legitimate network changes mid-session (roaming). Correlate "
            "with geo distance to suppress benign same-city hops.",
            "Corporate egress IP rotation."],
        tuning=["Require a minimum geo distance between session and "
                "refresh IP before firing."],
        references=["https://attack.mitre.org/techniques/T1550/004/"]),
    DetectionDoc(
        checker_cls=MassSessionChecker,
        name="Mass Session Creation",
        mitre_id="T1136", mitre_name="Create Account (session flooding)",
        tactic="Persistence / Credential Access",
        severity="HIGH",
        hypothesis=(
            "A burst of distinct new sessions for one user in a short "
            "window indicates automated session/token minting after a "
            "credential compromise."),
        telemetry=["Successful LOGIN / TOKEN_REFRESH events, tracked "
                   "cross-session per user"],
        logic=("≥5 distinct session ids for one user within 120 s ⇒ HIGH; "
               "confidence grows with the count."),
        false_positives=[
            "Load-balanced apps or SDKs that legitimately open many "
            "short-lived sessions — exclude service principals.",
            "Aggressive token refresh by a single misconfigured client."],
        tuning=["Raise the count threshold for known automation "
                "accounts; separate baseline for service principals."],
        references=["https://attack.mitre.org/techniques/T1136/"]),
]


def coverage_table() -> str:
    rows = ["| Detection | Technique | Tactic | Severity |",
            "|---|---|---|---|"]
    for d in CATALOG:
        rows.append(f"| {d.name} | [{d.mitre_id}]"
                    f"(https://attack.mitre.org/techniques/"
                    f"{d.mitre_id.replace('.', '/')}/) {d.mitre_name} "
                    f"| {d.tactic} | {d.severity} |")
    return "\n".join(rows)


def render_markdown() -> str:
    out = [
        "# Detection Catalog",
        "",
        "> Auto-generated from `itdr/catalog.py` — regenerate with "
        "`python -m itdr.catalog`. The code is the source of truth; "
        "this document cannot drift.",
        "",
        "## MITRE ATT&CK Coverage",
        "",
        coverage_table(),
        "",
    ]
    for d in CATALOG:
        out += [
            f"## {d.name}",
            "",
            f"**Technique:** {d.mitre_id} — {d.mitre_name}  ",
            f"**Tactic:** {d.tactic}  ",
            f"**Severity:** {d.severity}  ",
            f"**Implementation:** `{d.checker_cls.__module__}."
            f"{d.checker_cls.__name__}`",
            "",
            "### Hypothesis",
            d.hypothesis,
            "",
            "### Required telemetry",
            *[f"- {t}" for t in d.telemetry],
            "",
            "### Detection logic",
            f"`{d.logic}`",
            "",
            "### Known false-positive modes",
            *[f"- {fp}" for fp in d.false_positives],
            "",
            "### Tuning guidance",
            *[f"- {t}" for t in d.tuning],
            "",
        ]
        if d.references:
            out += ["### References",
                    *[f"- {r}" for r in d.references], ""]
    return "\n".join(out)


def main() -> None:
    docs = Path(__file__).resolve().parent.parent / "docs"
    docs.mkdir(exist_ok=True)
    target = docs / "DETECTIONS.md"
    target.write_text(render_markdown())
    print(f"wrote {target} ({len(CATALOG)} detections)")


if __name__ == "__main__":
    main()
