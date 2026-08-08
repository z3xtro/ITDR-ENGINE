"""
itdr.triage
===========
Turn an alert into an investigation.

An alert line tells an analyst that something happened. It does not tell
them what to do, and the gap between those two things is where SOC time
actually goes. This module renders the dossier a responder needs at 3am,
in the order they need it:

    1. Verdict and confidence   — what the engine thinks, and how sure
    2. Blast radius             — which account, which hosts, which IP
    3. Timeline                 — what happened, in order, with evidence
    4. ATT&CK context           — what stage of an intrusion this is
    5. Containment status       — what was already done automatically
    6. Next actions             — concrete steps, in priority order
    7. If this is a false positive — the specific benign explanation to
                                     rule out first, from the catalog

Point 7 is the one most tooling omits. Every detection in the catalog
documents its own false-positive modes; surfacing them next to the
alert turns "is this real?" from an open-ended question into a short
checklist. An analyst who can disprove an alert quickly is worth more
than one who escalates everything.

Rendering is Rich for the terminal and Markdown for a ticket or a case
comment, from the same structure — so the case attached to TheHive says
exactly what the analyst saw.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import ITDRAlert, SessionState

# Concrete response guidance per detection. Written as an ordered
# checklist because that is how an on-call analyst reads at speed.
_PLAYBOOK: dict[str, list[str]] = {
    "ssh_bruteforce_success": [
        "Treat the account as compromised until proven otherwise — the "
        "password is known to an attacker regardless of how it was used.",
        "Confirm the success is real: check `last` and `/var/log/secure` "
        "on the endpoint for a session that actually opened.",
        "Rotate the credential and terminate live sessions "
        "(`pkill -u <user>`), then check for persistence: new SSH keys "
        "in ~/.ssh/authorized_keys, cron entries, new local accounts.",
        "Block the source IP at the perimeter if it is external.",
        "Search for the same source IP against other accounts and hosts "
        "— brute force is rarely aimed at one target.",
    ],
    "privilege_escalation": [
        "Establish whether this user legitimately holds sudo rights.",
        "Pull the sudo command itself from the endpoint "
        "(`/var/log/secure`, `journalctl _COMM=sudo`) — what they ran "
        "matters more than that they escalated.",
        "Check for persistence created as root: systemd units, cron, "
        "SUID binaries, modified authorized_keys.",
        "If the preceding login is also suspicious, treat the host as "
        "compromised rather than the account.",
    ],
    "lateral_movement": [
        "Identify whether this is automation. Config management and "
        "backup agents produce this pattern legitimately and should be "
        "allowlisted rather than triaged repeatedly.",
        "Map what the account can reach — the endpoints seen may be a "
        "subset of the endpoints reachable.",
        "Check for the same credential in use on hosts outside the "
        "alerted set.",
        "If not automation, contain at the identity layer, not per-host "
        "— blocking one endpoint moves the attacker, it doesn't stop them.",
    ],
    "new_source_ip": [
        "Contact the user. This is frequently benign and they will "
        "resolve it in one message.",
        "Check the address: hosting/VPN/Tor ranges are far more "
        "suspicious than residential.",
        "Weak on its own — escalate only alongside another signal.",
    ],
    "off_hours_access": [
        "Check the user's normal working pattern before treating this "
        "as anomalous; night shift and on-call make it meaningless.",
        "Weak on its own — a supporting signal, not a finding.",
    ],
    "impossible_travel": [
        "Rule out VPN or proxy egress first — this is the dominant "
        "benign explanation by a wide margin.",
        "Confirm both logins succeeded and neither is a backend or "
        "integration record.",
        "If genuine, revoke sessions and rotate credentials; the "
        "attacker holds valid authentication material.",
    ],
    "session_mutation": [
        "Compare the before/after user agent and subnet — a wholesale "
        "change mid-session indicates a replayed token.",
        "Revoke the session rather than the account if the mutation is "
        "confined to one session.",
    ],
    "mfa_fatigue": [
        "Contact the user immediately and confirm whether they approved "
        "a prompt they did not initiate.",
        "If they did, treat MFA as compromised: revoke sessions, "
        "re-enrol factors, rotate the password.",
        "Consider enabling number matching, which defeats this attack "
        "class outright.",
    ],
}

_TACTIC_STAGE = {
    "T1110": "Credential Access — the attacker is obtaining credentials",
    "T1078": "Initial Access / Persistence — valid credentials in use",
    "T1021": "Lateral Movement — expanding reach across the estate",
    "T1548": "Privilege Escalation — acquiring higher rights",
    "T1550.004": "Defense Evasion — using stolen session material",
    "T1621": "Credential Access — MFA request generation",
    "T1090.003": "Command and Control — anonymised network path",
    "T1136": "Persistence — account creation",
}


@dataclass
class Dossier:
    alert: ITDRAlert
    session: Optional[SessionState] = None
    containment: list[str] = field(default_factory=list)
    case_url: str = ""

    # -- derived -------------------------------------------------------

    @property
    def endpoints(self) -> list[str]:
        hosts = set()
        for d in self.alert.detections:
            ep = d.evidence.get("endpoint")
            if ep:
                hosts.add(str(ep))
            for ep in (d.evidence.get("endpoints") or []):
                hosts.add(str(ep))
        if not hosts and "@" in self.alert.session_id:
            hosts.add(self.alert.session_id.rsplit("@", 1)[1])
        return sorted(hosts)

    @property
    def techniques(self) -> list[str]:
        return sorted({d.mitre for d in self.alert.detections if d.mitre})

    @property
    def strongest(self):
        return max(self.alert.detections,
                   key=lambda d: d.risk_points, default=None)

    def actions(self) -> list[str]:
        """Merge playbooks for every detection, strongest first, without
        repeating identical guidance."""
        out: list[str] = []
        for d in sorted(self.alert.detections,
                        key=lambda d: d.risk_points, reverse=True):
            for step in _PLAYBOOK.get(d.checker, []):
                if step not in out:
                    out.append(step)
        if not out:
            out.append("No playbook registered for these detections — "
                       "triage manually and add one to itdr/triage.py.")
        return out

    def false_positive_checks(self) -> list[tuple[str, str]]:
        """The benign explanations to rule out, pulled from the catalog
        so they can never drift from the documented detection."""
        try:
            from .catalog import CATALOG
        except Exception:                               # noqa: BLE001
            return []
        by_checker = {getattr(doc.checker_cls, "name", ""): doc
                      for doc in CATALOG}
        out = []
        for d in self.alert.detections:
            doc = by_checker.get(d.checker)
            if doc and doc.false_positives:
                out.append((d.checker, doc.false_positives[0]))
        return out


# ------------------------------------------------------------ rendering --

def render_terminal(dossier: Dossier, console: Optional[Console] = None):
    c = console or Console()
    a = dossier.alert
    style = "bold red" if a.tier == "CRITICAL" else "yellow"

    c.print(Panel(
        Text(f"{a.tier} · alert #{a.id} · risk {a.risk_score}",
             style=style),
        subtitle=f"{a.user_id} on {', '.join(dossier.endpoints) or '?'}",
        border_style=style))

    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold cyan", width=14)
    t.add_column()
    t.add_row("account", a.user_id)
    t.add_row("source IP", a.client_ip or "—")
    t.add_row("endpoints", ", ".join(dossier.endpoints) or "—")
    t.add_row("techniques", ", ".join(dossier.techniques) or "—")
    t.add_row("session", a.session_id)
    if dossier.case_url:
        t.add_row("case", dossier.case_url)
    c.print(t)

    c.print("\n[bold]What happened[/]")
    tl = Table(show_edge=False, pad_edge=False)
    tl.add_column("signal", style="bold")
    tl.add_column("sev")
    tl.add_column("conf", justify="right")
    tl.add_column("risk", justify="right")
    tl.add_column("evidence")
    for d in sorted(a.detections, key=lambda d: d.risk_points,
                    reverse=True):
        ev = ", ".join(f"{k}={v}" for k, v in
                       list(d.evidence.items())[:3])
        tl.add_row(d.checker, d.severity.name, f"{d.confidence:.2f}",
                   f"+{d.risk_points}", ev)
    c.print(tl)

    for tid in dossier.techniques:
        stage = _TACTIC_STAGE.get(tid)
        if stage:
            c.print(f"  [dim]{tid}: {stage}[/]")

    if dossier.containment:
        c.print("\n[bold]Already done automatically[/]")
        for act in dossier.containment:
            c.print(f"  [green]•[/] {act}")

    c.print("\n[bold]Next actions[/]")
    for i, step in enumerate(dossier.actions(), 1):
        c.print(f"  [bold]{i}.[/] {step}")

    fps = dossier.false_positive_checks()
    if fps:
        c.print("\n[bold]Rule out first[/] [dim](most likely benign "
                "explanation per signal)[/]")
        for checker, fp in fps:
            c.print(f"  [yellow]?[/] [bold]{checker}[/]: {fp}")


def render_markdown(dossier: Dossier) -> str:
    """Same dossier as Markdown, for a ticket or a TheHive case."""
    a = dossier.alert
    L = [f"## {a.tier} — alert #{a.id} — risk {a.risk_score}",
         "",
         f"**Account:** `{a.user_id}`  ",
         f"**Source IP:** `{a.client_ip or '—'}`  ",
         f"**Endpoints:** {', '.join(f'`{e}`' for e in dossier.endpoints) or '—'}  ",
         f"**ATT&CK:** {', '.join(dossier.techniques) or '—'}  ",
         f"**Session:** `{a.session_id}`",
         "",
         "### What happened",
         "",
         "| Signal | Severity | Confidence | Risk | Evidence |",
         "|---|---|---|---|---|"]
    for d in sorted(a.detections, key=lambda d: d.risk_points,
                    reverse=True):
        ev = ", ".join(f"{k}={v}" for k, v in list(d.evidence.items())[:3])
        L.append(f"| `{d.checker}` | {d.severity.name} | "
                 f"{d.confidence:.2f} | +{d.risk_points} | {ev} |")

    stages = [f"- **{t}** — {_TACTIC_STAGE[t]}"
              for t in dossier.techniques if t in _TACTIC_STAGE]
    if stages:
        L += ["", "### Where this sits in an intrusion", ""] + stages

    if dossier.containment:
        L += ["", "### Already done automatically", ""]
        L += [f"- {c}" for c in dossier.containment]

    L += ["", "### Next actions", ""]
    L += [f"{i}. {s}" for i, s in enumerate(dossier.actions(), 1)]

    fps = dossier.false_positive_checks()
    if fps:
        L += ["", "### Rule out first", "",
              "The most likely benign explanation for each signal, from "
              "the detection catalog:", ""]
        L += [f"- **`{c}`** — {fp}" for c, fp in fps]

    L += ["", "---", "*Generated by the ITDR engine triage module.*"]
    return "\n".join(L)


def dossier_for(alert: ITDRAlert, containment: Optional[list[str]] = None,
                case_url: str = "") -> Dossier:
    return Dossier(alert=alert, containment=containment or [],
                   case_url=case_url)
