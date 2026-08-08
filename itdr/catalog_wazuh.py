"""
itdr.catalog_wazuh
==================
Detection-as-code entries for the host-native (Wazuh) detectors.

Same contract as `itdr.catalog`: every detection carries its hypothesis,
required telemetry, documented false-positive modes, and tuning knobs.
A detection without a written FP analysis is not production-ready — an
analyst who cannot predict when a rule lies will stop trusting it, and a
rule nobody trusts is worse than no rule, because it still costs triage
time.

The FP notes here are not hypothetical. Two of them describe defects
found on a live Wazuh manager within an hour of first contact.
"""

from __future__ import annotations

from .catalog_types import DetectionDoc
from .wazuh_detections import (LateralMovementChecker, NewSourceIPChecker,
                               OffHoursAccessChecker,
                               PrivilegeEscalationChecker,
                               SSHBruteForceSuccessChecker)

WAZUH_CATALOG: list[DetectionDoc] = [
    DetectionDoc(
        checker_cls=SSHBruteForceSuccessChecker,
        name="Brute Force Succeeded",
        mitre_id="T1110",
        mitre_name="Brute Force",
        tactic="Credential Access",
        severity="CRITICAL",
        hypothesis=(
            "Password guessing is common and mostly harmless noise; "
            "password guessing that SUCCEEDS is a compromised credential "
            "with no ambiguity. Correlating the burst and the success on "
            "the same source IP is what separates an attacker who got in "
            "from a scanner that did not."),
        telemetry=["Failed authentication events with source IP "
                   "(sshd 5716/5710/5760, Windows 4625)",
                   "Successful authentication events with source IP "
                   "(sshd 5715, PAM 5501, Windows 4624)"],
        logic=("Per (user, source IP): maintain a 300s sliding window of "
               "failures. On a success from that same pair, flag if the "
               "window holds >= 5 failures and the success lands within "
               "120s of the last one. Confidence 0.75 at 5 failures, "
               "ramping to 1.0 by 15. That ramp is calibrated against "
               "the risk model, not chosen by feel: at CRITICAL "
               "severity (90) a detection needs confidence > 0.834 to "
               "reach the CRITICAL alert tier (75) unaided, so a large "
               "burst must clear it."),
        false_positives=[
            "A user who genuinely forgot their password, retried past "
            "the threshold, then succeeded. Mitigated by requiring 5+ "
            "failures — above typical human typo volume — but not "
            "eliminated. This is the dominant FP mode.",
            "Automation with a stale credential that is rotated and "
            "retried: a script fails repeatedly, someone fixes the "
            "secret, the next run succeeds. Looks identical.",
            "Shared NAT egress: several users behind one public IP can "
            "pool failures that belong to different people, then any "
            "one of them succeeding trips the rule.",
        ],
        tuning=[
            "fail_count (default 5) — raise to 8-10 on hosts with "
            "interactive users who fumble passwords; lower to 3 on "
            "service-account-only hosts where any failure is abnormal.",
            "success_grace (default 120s) — the attacker's success "
            "follows their burst closely. Shrinking this to 30s sharply "
            "cuts the forgotten-password FP at some cost to recall.",
            "Correlate with new_source_ip: a burst-then-success from an "
            "IP the account has never used is far stronger evidence "
            "than one from the user's usual address.",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1110/",
            "Wazuh stock rules 5710, 5712, 5716, 5763",
        ],
    ),
    DetectionDoc(
        checker_cls=NewSourceIPChecker,
        name="First-Seen Source IP",
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        tactic="Initial Access / Persistence",
        severity="LOW",
        hypothesis=(
            "An account authenticating from an address it has never used "
            "is weakly suspicious on its own and strongly suspicious in "
            "company. Its job is not to alert; its job is to add the "
            "points that push a genuinely bad session over the line."),
        telemetry=["Successful authentication events with source IP",
                   "Per-user history of previously observed sources"],
        logic=("Track the last 32 distinct source IPs per user. After a "
               "learning period of 3 observed sources, flag the first "
               "authentication from an address not in that set. "
               "Confidence fixed at 0.6; severity LOW by design."),
        false_positives=[
            "Ordinary mobility — new laptop, home vs office, hotel "
            "Wi-Fi, phone tethering. This fires legitimately a lot and "
            "is deliberately scored low because of it.",
            "Dynamic residential IPs: a DHCP lease renewal or router "
            "reboot changes the address with no user action at all.",
            "Cold start: an account with fewer than 3 observed sources "
            "has no baseline, so every address is 'new'. Suppressed by "
            "the learning period rather than alerted on.",
        ],
        tuning=[
            "learn_after (default 3) — raise for populations with high "
            "mobility; the cost is a longer blind window on new accounts.",
            "Prefer subnet or ASN granularity over exact IP in "
            "environments with dynamic addressing; exact-IP matching is "
            "the noisiest possible choice and is used here only because "
            "host logs carry nothing richer.",
            "Never promote this to a standalone alerting severity. If it "
            "is firing alone, the correct response is to tune it out, "
            "not to escalate it.",
        ],
        references=["https://attack.mitre.org/techniques/T1078/"],
    ),
    DetectionDoc(
        checker_cls=LateralMovementChecker,
        name="Credential Used Across Endpoints",
        mitre_id="T1021",
        mitre_name="Remote Services",
        tactic="Lateral Movement",
        severity="HIGH",
        hypothesis=(
            "A human works from one or two machines. A credential "
            "authenticating to several distinct endpoints inside a few "
            "minutes is either an attacker moving laterally with stolen "
            "credentials, or automation that should be running as a "
            "service account under a different identity."),
        telemetry=["Successful authentication events",
                   "Agent/endpoint identity per event",
                   "Per-user cross-host history"],
        logic=("Per user: a 600s sliding window of (timestamp, endpoint) "
               "for successes only. Flag when the window contains 3 or "
               "more distinct endpoints. Fires once at the threshold "
               "crossing, not on every subsequent event."),
        false_positives=[
            "Configuration management and monitoring — Ansible, Puppet, "
            "backup agents and health checks legitimately touch many "
            "hosts fast. This is the dominant FP and the reason the rule "
            "is HIGH rather than CRITICAL.",
            "Administrators doing genuine fleet work during an incident "
            "or a patch window.",
            "Jump-host topologies where one bastion account is the "
            "designed path to everything.",
        ],
        tuning=[
            "host_threshold (default 3) — raise in environments where "
            "admin fan-out is routine.",
            "Maintain an allowlist of automation accounts and exclude "
            "them outright. This single measure removes most FPs; do it "
            "before touching thresholds.",
            "window_s (default 600s) — shrink to sharpen the "
            "distinction between a burst of lateral movement and a "
            "human working across hosts over an afternoon.",
        ],
        references=["https://attack.mitre.org/techniques/T1021/"],
    ),
    DetectionDoc(
        checker_cls=PrivilegeEscalationChecker,
        name="Escalation After Remote Login",
        mitre_id="T1548",
        mitre_name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        severity="HIGH",
        hypothesis=(
            "sudo is routine and alerting on it is useless. What is not "
            "routine is the sequence: authenticate from the network, "
            "then immediately become root. That ordering is the tail of "
            "a compromise, whereas an admin who has been working on the "
            "box for an hour is just working."),
        telemetry=["Successful remote logins with source IP",
                   "Privilege escalation events (sudo 5402, su 5404)",
                   "Ordering and elapsed time between the two"],
        logic=("A successful remote login (source IP present) arms a "
               "300s window for that (user, endpoint). A subsequent "
               "successful sudo/su inside the window flags. Console "
               "logins never arm it; the window is consumed on fire so "
               "one login yields at most one detection."),
        false_positives=[
            "Normal administrative practice — many engineers SSH in and "
            "run `sudo -i` as the first thing they do. On an "
            "admin-heavy host this fires constantly and legitimately.",
            "Deployment and CI pipelines that connect and immediately "
            "escalate as a designed step.",
            "Break-glass and on-call response, which looks exactly like "
            "an intruder by construction.",
        ],
        tuning=[
            "window_s (default 300s) — the shorter it is, the more "
            "specific the 'landed and immediately escalated' pattern.",
            "Exclude known administrator accounts, or invert the logic "
            "for them: alert when a NON-admin escalates rather than "
            "when anyone does.",
            "Highest value when correlated. Escalation after a "
            "brute-force success is a different event from escalation "
            "after a normal login, and only the risk model sees that.",
        ],
        references=["https://attack.mitre.org/techniques/T1548/"],
    ),
    DetectionDoc(
        checker_cls=OffHoursAccessChecker,
        name="Off-Hours Authentication",
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        tactic="Initial Access / Defense Evasion",
        severity="LOW",
        hypothesis=(
            "Attackers prefer hours when nobody is watching. Taken "
            "alone this is nearly worthless — plenty of legitimate work "
            "happens at night — but as a multiplier on an already "
            "suspicious session it meaningfully shifts the priority."),
        telemetry=["Successful interactive authentication events",
                   "Event timestamps with the originating timezone "
                   "offset preserved"],
        logic=("Flag successful logins outside 08:00-20:00 local, or at "
               "any hour on a weekend. Evaluated in the event's own "
               "timezone, which Wazuh preserves, so a laptop in IST is "
               "judged against IST. Reported at most once per user, per "
               "endpoint, per local date."),
        false_positives=[
            "Night shifts, on-call rotations, and globally distributed "
            "teams, for whom 'off-hours' is simply their working day.",
            "Scheduled jobs and maintenance windows, which are "
            "deliberately placed at night.",
            "Any timezone assumption at all. A fixed 08:00-20:00 window "
            "is wrong for someone somewhere in every organisation.",
        ],
        tuning=[
            "start_hour / end_hour — set per population, not globally. "
            "One window for an entire company is always wrong.",
            "Per-user learned baselines beat a fixed window: alert on "
            "deviation from THIS account's normal hours rather than "
            "from an arbitrary office schedule.",
            "The once-per-day cap is load-bearing, not cosmetic. "
            "Firing per login let this detector accumulate ~11 risk "
            "points per event until it raised a NOTABLE alert entirely "
            "on its own — observed on live data, nine logins in one "
            "night. A weak signal that repeats must never be able to "
            "cross a tier without corroboration.",
        ],
        references=["https://attack.mitre.org/techniques/T1078/"],
    ),
]
