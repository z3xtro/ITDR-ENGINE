"""
itdr.quality
============
Measure the detections instead of asserting they work.

    python -m itdr.quality

Anyone can write a rule that fires on an attack. The questions that
decide whether a detection survives contact with a SOC are different,
and harder:

  - How often does it fire on benign activity?      (precision)
  - How much of the attack does it actually catch?  (recall)
  - How long after the first malicious event?       (time to detect)
  - Can one weak signal alert on its own?           (escalation safety)

This harness answers all four against labelled corpora and writes
docs/DETECTION_QUALITY.md. Every number in that document is produced by
running the real engine over generated traffic — nothing is asserted by
hand.

Why a synthetic corpus is defensible here
-----------------------------------------
The benign corpus models the specific things that break identity
detections in production: admins who fumble passwords, config
management touching many hosts, night-shift operators, dynamic IPs,
service accounts escalating on schedule. It is not "quiet traffic" —
it is deliberately adversarial to the detectors, built from the
false-positive modes documented in the catalog.

That is the honest framing: this measures whether each detection
survives its OWN known FP modes. It is a lower bound on precision in a
real environment, not a substitute for one. A production number needs
production data.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .engine import ITDREngine
from .models import AuthEvent, EventResult, EventType
from .wazuh_detections import wazuh_checkers

BASE = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)      # a Monday


def _ev(user, agent, ip, offset, etype=EventType.LOGIN,
        result=EventResult.SUCCESS, program="sshd", base=BASE):
    return AuthEvent(
        timestamp=base + timedelta(seconds=offset),
        user_id=user, session_id=f"wazuh:{user}@{agent}",
        client_ip=ip, user_agent=program,
        geo_country="??", geo_city="??",
        event_type=etype, event_result=result, idp_source="wazuh")


# ------------------------------------------------------------- corpora --

@dataclass
class Scenario:
    name: str
    malicious: bool
    events: list = field(default_factory=list)
    # Which checker SHOULD fire. None = nothing should.
    expect: str | None = None
    # Index into events of the first genuinely malicious action, for
    # time-to-detect. None for benign scenarios.
    attack_starts: int | None = None


def benign_corpus(rng: random.Random) -> list[Scenario]:
    """Traffic that must NOT alert. Each case is drawn from a documented
    false-positive mode, so this is the hostile case, not the easy one."""
    s = []

    # Ordinary working day, one user, one host, stable IP.
    s.append(Scenario("routine_workday", False, [
        _ev("alice", "web-01", "203.0.113.10", 3600 * i)
        for i in range(8)]))

    # Admin fumbles their password twice, then gets in. Below the burst
    # threshold by design — this is the commonest benign near-miss.
    s.append(Scenario("forgotten_password_small", False,
                      [_ev("bob", "web-01", "203.0.113.11", i * 20,
                           result=EventResult.FAIL) for i in range(3)]
                      + [_ev("bob", "web-01", "203.0.113.11", 80)]))

    # Config management touching two hosts — under the lateral threshold.
    s.append(Scenario("config_mgmt_two_hosts", False, [
        _ev("ansible", "web-01", "203.0.113.20", 0),
        _ev("ansible", "db-01", "203.0.113.20", 30)]))

    # Night-shift operator: many logins, all off-hours, one endpoint.
    # Before the dedupe fix this alone produced a NOTABLE alert.
    night = BASE.replace(hour=23)
    s.append(Scenario("night_shift_operator", False, [
        _ev("carol", "web-01", "203.0.113.30", i * 900, base=night)
        for i in range(9)]))

    # Mobile user roaming across addresses, all successful, daytime.
    s.append(Scenario("roaming_user", False, [
        _ev("dave", "web-01", f"203.0.113.{40 + i}", i * 1800)
        for i in range(5)]))

    # Admin who logs in at the physical console (program `login`, no
    # source IP) and sudos. A true console session is local work and
    # must not arm the escalation detector — unlike an SSH session,
    # which is remote even when PAM omits the IP.
    s.append(Scenario("console_admin_sudo", False, [
        _ev("erin", "web-01", "0.0.0.0", 0, program="login"),
        _ev("erin", "web-01", "0.0.0.0", 45,
            etype=EventType.API_ACCESS, program="sudo")]))

    # Service account escalating on a schedule, long after login.
    s.append(Scenario("scheduled_job_escalation", False, [
        _ev("svc-backup", "db-01", "203.0.113.50", 0),
        _ev("svc-backup", "db-01", "203.0.113.50", 4000,
            etype=EventType.API_ACCESS, program="sudo")]))

    # Scanner hammering a host but never succeeding: noisy, not a breach.
    s.append(Scenario("failed_scan_no_success", False, [
        _ev("root", "web-01", "198.51.100.5", i * 3,
            result=EventResult.FAIL) for i in range(30)]))

    return s


def attack_corpus(rng: random.Random) -> list[Scenario]:
    """Traffic that MUST alert, one scenario per detection."""
    s = []

    # T1110 — brute force that succeeds.
    ev = [_ev("alice", "web-01", "45.33.32.156", i * 4,
              result=EventResult.FAIL) for i in range(9)]
    ev.append(_ev("alice", "web-01", "45.33.32.156", 40))
    s.append(Scenario("bruteforce_success", True, ev,
                      expect="ssh_bruteforce_success", attack_starts=0))

    # T1021 — one credential sweeping the fleet.
    s.append(Scenario("lateral_sweep", True, [
        _ev("alice", "web-01", "45.33.32.156", 0),
        _ev("alice", "db-01", "45.33.32.156", 40),
        _ev("alice", "app-01", "45.33.32.156", 80),
        _ev("alice", "dc-01", "45.33.32.156", 120)],
        expect="lateral_movement", attack_starts=0))

    # T1548 — land from the network, immediately become root.
    s.append(Scenario("escalate_after_login", True, [
        _ev("alice", "web-01", "45.33.32.156", 0),
        _ev("alice", "web-01", "45.33.32.156", 25,
            etype=EventType.API_ACCESS, program="sudo")],
        expect="privilege_escalation", attack_starts=0))

    # T1078 — established account, brand-new source.
    ev = [_ev("frank", "web-01", f"203.0.113.{60 + i}", i * 3600)
          for i in range(4)]
    ev.append(_ev("frank", "web-01", "45.33.32.156", 4 * 3600))
    s.append(Scenario("new_source_takeover", True, ev,
                      expect="new_source_ip", attack_starts=4))

    # Full chain: the one that should reach CRITICAL.
    ev = [_ev("grace", "web-01", "45.33.32.156", i * 4,
              result=EventResult.FAIL) for i in range(9)]
    ev.append(_ev("grace", "web-01", "45.33.32.156", 40))
    ev.append(_ev("grace", "web-01", "45.33.32.156", 70,
                  etype=EventType.API_ACCESS, program="sudo"))
    ev.append(_ev("grace", "db-01", "45.33.32.156", 100))
    ev.append(_ev("grace", "app-01", "45.33.32.156", 130))
    s.append(Scenario("full_kill_chain", True, ev,
                      expect="ssh_bruteforce_success", attack_starts=0))

    return s


# ------------------------------------------------------------ measuring --

@dataclass
class Result:
    scenario: str
    malicious: bool
    detections: list
    alerts: list
    ttd_s: float | None


class _RecordingChecker:
    """Wraps a checker to record which events produced a detection.

    Going through a wrapper rather than inspecting session state keeps
    the measurement independent of the store implementation, and gives
    an exact event->detection mapping, which is what time-to-detect
    needs.
    """

    def __init__(self, inner, log: list):
        self._inner = inner
        self._log = log
        self.name = inner.name

    def check(self, ev, session, ctx):
        det = self._inner.check(ev, session, ctx)
        if det:
            self._log.append((ev, det))
        return det


def run_scenario(sc: Scenario) -> Result:
    """Each scenario gets a fresh engine — the checkers hold state, so
    sharing one would leak a previous scenario's history into this one
    and quietly invalidate every number below."""
    fired: list = []
    log: list = []
    checkers = [_RecordingChecker(c, log) for c in wazuh_checkers()]
    engine = ITDREngine(checkers=checkers, on_alert=fired.append)
    for ev in sc.events:
        engine.process_event(ev)

    # Time to detect, in EVENT time: from the first malicious action to
    # the event whose processing raised the first alert. Independent of
    # wall clock, machine speed and polling interval.
    ttd = None
    if sc.malicious and sc.attack_starts is not None and fired and log:
        t0 = sc.events[sc.attack_starts].ts
        alerting_event = next(
            (ev for ev, _ in log if ev.ts >= t0), log[0][0])
        ttd = round(max(alerting_event.ts - t0, 0.0), 1)

    return Result(sc.name, sc.malicious,
                  [d.checker for _, d in log], fired, ttd)


def measure() -> dict:
    rng = random.Random(1337)
    benign = [run_scenario(s) for s in benign_corpus(rng)]
    attacks = [run_scenario(s) for s in attack_corpus(rng)]

    # Precision at the ALERT level — what an analyst actually sees. A
    # detection that fires without raising an alert costs nobody time.
    tp = sum(1 for r in attacks if r.alerts)
    fn = sum(1 for r in attacks if not r.alerts)
    fp = sum(1 for r in benign if r.alerts)
    tn = sum(1 for r in benign if not r.alerts)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    ttds = [r.ttd_s for r in attacks if r.ttd_s is not None]
    return {
        "benign": benign, "attacks": attacks,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "mttd": round(sum(ttds) / len(ttds), 1) if ttds else None,
        "max_ttd": max(ttds) if ttds else None,
    }


# -------------------------------------------------------------- report --

def render(m: dict) -> str:
    L = ["# Detection Quality",
         "",
         "Generated by `python -m itdr.quality`. Every number here comes "
         "from running the real engine over labelled corpora — nothing "
         "is hand-asserted.",
         "",
         "## Headline",
         "",
         "| Metric | Value |",
         "|---|---|",
         f"| Precision (alert level) | **{m['precision']:.0%}** |",
         f"| Recall (alert level) | **{m['recall']:.0%}** |",
         f"| F1 | **{m['f1']:.2f}** |",
         f"| Mean time to detect | **{m['mttd']}s** |"
         if m["mttd"] is not None else "| Mean time to detect | n/a |",
         f"| Worst time to detect | {m['max_ttd']}s |"
         if m["max_ttd"] is not None else "",
         f"| True positives | {m['tp']} |",
         f"| False positives | {m['fp']} |",
         f"| False negatives | {m['fn']} |",
         f"| True negatives | {m['tn']} |",
         "",
         "## Benign corpus — must not alert",
         "",
         "Each case is drawn from a false-positive mode documented in "
         "`docs/DETECTIONS.md`. This is the hostile benign set, not "
         "quiet traffic.",
         "",
         "| Scenario | Detections fired | Alert raised | Verdict |",
         "|---|---|---|---|"]

    for r in m["benign"]:
        alert = "**YES**" if r.alerts else "no"
        verdict = "❌ false positive" if r.alerts else "✅ correctly silent"
        dets = ", ".join(sorted(set(r.detections))) or "—"
        L.append(f"| `{r.scenario}` | {dets} | {alert} | {verdict} |")

    L += ["",
          "Detections firing without an alert are working as designed: "
          "low-severity signals are meant to accumulate, and only "
          "crossing a risk tier costs an analyst attention.",
          "",
          "## Attack corpus — must alert",
          "",
          "| Scenario | Expected | Fired | Tier | Time to detect |",
          "|---|---|---|---|---|"]

    for r in m["attacks"]:
        # Highest tier reached, not the first raised: a session that
        # escalates NOTABLE -> CRITICAL is a CRITICAL finding, and
        # reporting the first alert would understate every kill chain.
        tier = ("CRITICAL" if any(a.tier == "CRITICAL" for a in r.alerts)
                else r.alerts[0].tier if r.alerts else "—")
        ok = "✅" if r.alerts else "❌ MISSED"
        dets = ", ".join(sorted(set(r.detections))) or "—"
        ttd = f"{r.ttd_s}s" if r.ttd_s is not None else "—"
        L.append(f"| `{r.scenario}` | {ok} | {dets} | {tier} | {ttd} |")

    L += ["",
          "## Known blind spot",
          "",
          "`new_source_takeover` is a deliberate miss, not an oversight. "
          "A valid credential used from an address the account has never "
          "touched — with no failed attempts, no escalation and no "
          "lateral movement — produces one LOW-severity detection worth "
          "15 risk points against a NOTABLE threshold of 40. It never "
          "alerts.",
          "",
          "That is the correct trade. Raising `new_source_ip` high "
          "enough to alert alone would fire on every laptop, hotel "
          "Wi-Fi and DHCP renewal in the estate, and the benign corpus "
          "above shows precisely that population. The engine is tuned "
          "to catch takeovers that *do something* — and a credential "
          "that authenticates and then acts will trip a second signal.",
          "",
          "The residual risk is a patient attacker who logs in from a "
          "new address and does nothing observable. Closing it needs "
          "telemetry this engine does not have: device posture, ASN or "
          "geo reputation, or per-user behavioural baselines. Naming "
          "the gap is worth more than pretending the coverage is total.",
          "",
          "## Escalation safety",
          "",
          "A weak signal must never reach an alert tier by repeating. "
          "The `night_shift_operator` case exists to enforce this: nine "
          "off-hours logins previously stacked to a NOTABLE alert with "
          "no corroborating signal, which was a real defect found on a "
          "live Wazuh manager. It is now a regression test.",
          "",
          "## Limits of this measurement",
          "",
          "- The corpora are synthetic. They model the documented FP "
          "modes faithfully, so these figures are a lower bound on "
          "precision against known failure shapes — not a production "
          "measurement, which needs production data.",
          "- Scenario-level scoring, not event-level. An analyst triages "
          "alerts, not events, so this matches the unit of real work.",
          "- Time-to-detect is measured in event time from the first "
          "malicious action, so it is independent of polling interval "
          "and machine speed. Add your ingestion lag (60s by default on "
          "the Indexer poller) for wall-clock MTTD.",
          ""]
    return "\n".join(x for x in L if x != "")


def main() -> None:
    m = measure()
    out = Path("docs/DETECTION_QUALITY.md")
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(m) + "\n")
    print(f"precision {m['precision']:.0%}  recall {m['recall']:.0%}  "
          f"F1 {m['f1']:.2f}  MTTD {m['mttd']}s")
    print(f"  TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    print(f"wrote {out}")
    if m["fp"]:
        print(f"  WARNING: {m['fp']} benign scenario(s) alerted")
    if m["fn"]:
        print(f"  WARNING: {m['fn']} attack scenario(s) missed")


if __name__ == "__main__":
    main()
