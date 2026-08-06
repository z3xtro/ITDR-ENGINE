"""
Host-native detection tests.

These assert the behaviour that justifies the module existing: that the
checkers fire on real host attack sequences, and — just as important —
that they stay quiet on the benign sequences that look similar.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from itdr.engine import ITDREngine
from itdr.models import AuthEvent, EventResult, EventType
from itdr.state import _MemContext
from itdr.wazuh_detections import (LateralMovementChecker,
                                   NewSourceIPChecker,
                                   OffHoursAccessChecker,
                                   PrivilegeEscalationChecker,
                                   SSHBruteForceSuccessChecker,
                                   combined_checkers, wazuh_checkers)

BASE = datetime(2026, 8, 6, 14, 0, 0, tzinfo=timezone.utc)


def ev(user="alice", agent="web-01", ip="203.0.113.45", offset=0.0,
       etype=EventType.LOGIN, result=EventResult.SUCCESS, program="sshd"):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset),
        user_id=user, session_id=f"wazuh:{user}@{agent}",
        client_ip=ip, user_agent=program,
        geo_country="??", geo_city="??",
        event_type=etype, event_result=result, idp_source="wazuh")


def run(checker, events):
    """Feed events through one checker with a throwaway session."""
    from itdr.models import SessionState
    ctx = _MemContext()
    sessions: dict[str, SessionState] = {}
    hits = []
    for e in events:
        s = sessions.setdefault(
            e.session_id, SessionState(session_id=e.session_id,
                                       user_id=e.user_id))
        d = checker.check(e, s, ctx)
        if d:
            hits.append(d)
        s.touch(e)
    return hits


class TestSSHBruteForceSuccess:
    def test_burst_then_success_is_critical(self):
        c = SSHBruteForceSuccessChecker(fail_count=5, window_s=300)
        events = [ev(offset=i, result=EventResult.FAIL) for i in range(6)]
        events.append(ev(offset=10))
        hits = run(c, events)
        assert len(hits) == 1
        assert hits[0].checker == "ssh_bruteforce_success"
        assert hits[0].mitre == "T1110"
        assert hits[0].evidence["failed_attempts"] >= 5

    def test_confidence_scales_with_burst_size(self):
        small = run(SSHBruteForceSuccessChecker(),
                    [ev(offset=i, result=EventResult.FAIL) for i in range(5)]
                    + [ev(offset=10)])
        large = run(SSHBruteForceSuccessChecker(),
                    [ev(offset=i, result=EventResult.FAIL) for i in range(25)]
                    + [ev(offset=30)])
        assert large[0].confidence > small[0].confidence

    def test_few_failures_then_success_is_a_typo_not_an_attack(self):
        c = SSHBruteForceSuccessChecker(fail_count=5)
        hits = run(c, [ev(offset=i, result=EventResult.FAIL)
                       for i in range(2)] + [ev(offset=5)])
        assert hits == []

    def test_success_long_after_burst_does_not_fire(self):
        """The attacker's success follows the burst closely; a login the
        next morning after yesterday's scan is unrelated."""
        c = SSHBruteForceSuccessChecker(fail_count=5, window_s=300,
                                        success_grace=120)
        hits = run(c, [ev(offset=i, result=EventResult.FAIL)
                       for i in range(6)] + [ev(offset=1000)])
        assert hits == []

    def test_burst_and_success_from_different_ips_do_not_correlate(self):
        c = SSHBruteForceSuccessChecker(fail_count=5)
        hits = run(c, [ev(offset=i, ip="198.51.100.9",
                          result=EventResult.FAIL) for i in range(6)]
                   + [ev(offset=10, ip="203.0.113.45")])
        assert hits == []

    def test_fires_once_not_on_every_subsequent_login(self):
        c = SSHBruteForceSuccessChecker(fail_count=5)
        events = [ev(offset=i, result=EventResult.FAIL) for i in range(6)]
        events += [ev(offset=10), ev(offset=20), ev(offset=30)]
        assert len(run(c, events)) == 1


class TestNewSourceIP:
    def test_quiet_during_learning_period(self):
        c = NewSourceIPChecker(learn_after=3)
        hits = run(c, [ev(ip=f"203.0.113.{i}", offset=i) for i in range(3)])
        assert hits == []

    def test_fires_after_baseline_established(self):
        c = NewSourceIPChecker(learn_after=3)
        events = [ev(ip=f"203.0.113.{i}", offset=i) for i in range(3)]
        events.append(ev(ip="198.51.100.77", offset=99))
        hits = run(c, events)
        assert len(hits) == 1
        assert hits[0].evidence["new_ip"] == "198.51.100.77"

    def test_known_ip_never_fires(self):
        c = NewSourceIPChecker(learn_after=2)
        events = [ev(ip="203.0.113.1", offset=0), ev(ip="203.0.113.2", offset=1)]
        events += [ev(ip="203.0.113.1", offset=i) for i in range(2, 8)]
        assert run(c, events) == []

    def test_console_login_ignored(self):
        c = NewSourceIPChecker(learn_after=0)
        assert run(c, [ev(ip="0.0.0.0")]) == []


class TestLateralMovement:
    def test_one_account_across_several_hosts_fires(self):
        c = LateralMovementChecker(host_threshold=3, window_s=600)
        hits = run(c, [ev(agent="web-01", offset=0),
                       ev(agent="db-01", offset=30),
                       ev(agent="app-01", offset=60)])
        assert len(hits) == 1
        assert hits[0].mitre == "T1021"
        assert hits[0].evidence["endpoint_count"] == 3

    def test_repeated_logins_to_one_host_do_not_fire(self):
        c = LateralMovementChecker(host_threshold=3)
        hits = run(c, [ev(agent="web-01", offset=i * 10) for i in range(8)])
        assert hits == []

    def test_slow_spread_outside_window_does_not_fire(self):
        c = LateralMovementChecker(host_threshold=3, window_s=600)
        hits = run(c, [ev(agent="web-01", offset=0),
                       ev(agent="db-01", offset=5000),
                       ev(agent="app-01", offset=10000)])
        assert hits == []

    def test_failed_logins_are_the_bruteforce_detectors_job(self):
        c = LateralMovementChecker(host_threshold=3)
        hits = run(c, [ev(agent=f"h{i}", offset=i, result=EventResult.FAIL)
                       for i in range(5)])
        assert hits == []


class TestPrivilegeEscalation:
    def test_sudo_soon_after_remote_login_fires(self):
        c = PrivilegeEscalationChecker(window_s=300)
        hits = run(c, [ev(offset=0),
                       ev(offset=30, etype=EventType.API_ACCESS,
                          program="sudo")])
        assert len(hits) == 1
        assert hits[0].mitre == "T1548"

    def test_sudo_without_preceding_login_is_routine_admin_work(self):
        c = PrivilegeEscalationChecker()
        hits = run(c, [ev(offset=0, etype=EventType.API_ACCESS,
                          program="sudo")])
        assert hits == []

    def test_sudo_long_after_login_is_just_working(self):
        c = PrivilegeEscalationChecker(window_s=300)
        hits = run(c, [ev(offset=0),
                       ev(offset=4000, etype=EventType.API_ACCESS)])
        assert hits == []

    def test_console_login_does_not_arm_the_detector(self):
        c = PrivilegeEscalationChecker()
        hits = run(c, [ev(offset=0, ip="0.0.0.0"),
                       ev(offset=10, etype=EventType.API_ACCESS)])
        assert hits == []


class TestOffHours:
    def test_night_login_fires(self):
        c = OffHoursAccessChecker(start_hour=8, end_hour=20)
        night = AuthEvent(
            timestamp=datetime(2026, 8, 6, 3, 0, tzinfo=timezone.utc),
            user_id="alice", session_id="wazuh:alice@web-01",
            client_ip="203.0.113.45", user_agent="sshd",
            geo_country="??", geo_city="??",
            event_type=EventType.LOGIN, event_result=EventResult.SUCCESS)
        assert len(run(c, [night])) == 1

    def test_midday_weekday_login_is_quiet(self):
        c = OffHoursAccessChecker(start_hour=8, end_hour=20)
        # 2026-08-06 is a Thursday, 14:00 UTC
        assert run(c, [ev()]) == []


class TestPipelineIntegration:
    def test_attack_chain_escalates_to_a_critical_alert(self):
        """The real payoff: a brute-force compromise followed by
        escalation must clear the CRITICAL threshold through the actual
        engine, not just produce isolated detections."""
        alerts = []
        engine = ITDREngine(checkers=wazuh_checkers(),
                            on_alert=alerts.append)
        for i in range(8):
            engine.process_event(ev(offset=i, result=EventResult.FAIL))
        engine.process_event(ev(offset=12))
        engine.process_event(ev(offset=40, etype=EventType.API_ACCESS,
                                program="sudo"))
        assert alerts, "attack chain produced no alert"
        assert any(a.tier == "CRITICAL" for a in alerts)

    def test_normal_activity_produces_no_alert(self):
        """False-positive guard — an ordinary working day must stay
        silent, or the whole thing is unusable."""
        alerts = []
        engine = ITDREngine(checkers=wazuh_checkers(),
                            on_alert=alerts.append)
        for i in range(10):
            engine.process_event(ev(offset=i * 60, ip="203.0.113.45"))
        assert alerts == []

    def test_combined_set_includes_both_families(self):
        names = {c.name for c in combined_checkers()}
        assert "ssh_bruteforce_success" in names      # host-native
        assert "impossible_travel" in names           # IdP-oriented

    def test_checkers_are_fresh_instances_per_call(self):
        """They carry state; sharing instances across engines would
        leak one deployment's history into another."""
        a, b = wazuh_checkers(), wazuh_checkers()
        assert a[0] is not b[0]
