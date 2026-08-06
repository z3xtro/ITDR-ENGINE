"""
Tests for the ITDR engine. Run:  python -m pytest tests/ -v
Covers: haversine math, each checker's trigger + non-trigger paths,
threshold tiering, session pruning, protected-principal guardrail,
and concurrent ingestion (thread safety).
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from itdr.detections import (EngineContext, ImpossibleTravelChecker,
                             MFAFatigueChecker, SessionMutationChecker,
                             haversine_km)
from itdr.engine import ITDREngine
from itdr.models import (AuthEvent, EventResult, EventType, GeoPoint,
                         SessionState)
from itdr.respond import ResponderConfig, SOARResponder
from itdr.simulator import (CITIES, UA_CHROME_WIN, UA_PYTHON, _ev,
                            scenario_benign, scenario_impossible_travel,
                            scenario_mfa_fatigue, scenario_token_theft)


def drain(engine: ITDREngine, scenario) -> list:
    alerts = []
    for _, ev in scenario:
        alerts.extend(engine.process_event(ev))
    return alerts


# ------------------------------------------------------------------ math --

def test_haversine_known_distance():
    chennai = GeoPoint("IN", "Chennai", *CITIES["Chennai"][1:])
    mumbai = GeoPoint("IN", "Mumbai", *CITIES["Mumbai"][1:])
    d = haversine_km(chennai, mumbai)
    assert 1020 <= d <= 1060          # real-world ~1035 km


# -------------------------------------------------------------- checkers --

def test_impossible_travel_fires():
    engine = ITDREngine()
    alerts = drain(engine, scenario_impossible_travel())
    assert alerts, "impossible travel should raise an alert"
    det = alerts[0].detections[0]
    assert det.checker == "impossible_travel"
    assert det.evidence["required_velocity_kmh"] > 800


def test_slow_travel_does_not_fire():
    """Chennai -> Mumbai over 6 hours (~172 km/h) is legit."""
    engine = ITDREngine()
    t = datetime.now(timezone.utc)
    u = "traveler"
    e1 = _ev(t, u, f"s-{uuid.uuid4().hex[:8]}", "1.1.1.1",
             UA_CHROME_WIN, "Chennai", EventType.LOGIN,
             EventResult.SUCCESS)
    e2 = _ev(t + timedelta(hours=6), u, f"s-{uuid.uuid4().hex[:8]}",
             "2.2.2.2", UA_CHROME_WIN, "Mumbai", EventType.LOGIN,
             EventResult.SUCCESS)
    assert not engine.process_event(e1)
    assert not engine.process_event(e2)


def test_mfa_fatigue_fires_and_benign_does_not():
    engine = ITDREngine()
    assert drain(engine, scenario_mfa_fatigue()), "fatigue should alert"
    engine2 = ITDREngine()
    assert not drain(engine2, scenario_benign()), "benign must stay quiet"


def test_single_mfa_fail_then_success_is_quiet():
    """One fat-fingered push is not an attack."""
    engine = ITDREngine()
    t = datetime.now(timezone.utc)
    sid = "s-onefail"
    fail = _ev(t, "u1", sid, "1.1.1.1", UA_CHROME_WIN, "Chennai",
               EventType.MFA_CHALLENGE, EventResult.FAIL)
    ok = _ev(t + timedelta(seconds=20), "u1", sid, "1.1.1.1",
             UA_CHROME_WIN, "Chennai", EventType.LOGIN,
             EventResult.SUCCESS)
    assert not engine.process_event(fail)
    assert not engine.process_event(ok)


def test_token_theft_double_detection_escalates_to_critical():
    engine = ITDREngine()
    alerts = drain(engine, scenario_token_theft())
    assert any(a.tier == "CRITICAL" for a in alerts)
    critical = next(a for a in alerts if a.tier == "CRITICAL")
    checkers = {d.checker for d in critical.detections}
    assert "session_mutation" in checkers


def test_mutation_requires_established_session():
    """First event of a session can never be a 'mutation'."""
    checker = SessionMutationChecker()
    s = SessionState(session_id="s1", user_id="u1")
    ev = _ev(datetime.now(timezone.utc), "u1", "s1", "9.9.9.9",
             UA_PYTHON, "Moscow", EventType.API_ACCESS,
             EventResult.SUCCESS)
    assert checker.check(ev, s, EngineContext()) is None


# ---------------------------------------------------------------- engine --

def test_session_pruning():
    engine = ITDREngine(session_ttl=0.05, prune_interval=0.0)
    for _, ev in scenario_benign():
        engine.process_event(ev)
    assert engine.active_sessions() >= 1
    time.sleep(0.1)
    # any event triggers the lazy prune pass
    for _, ev in scenario_benign(user="someone.else"):
        engine.process_event(ev)
        break
    assert engine.stats["sessions_pruned"] >= 1


def test_thread_safety_under_concurrent_load():
    engine = ITDREngine()
    errors: list[Exception] = []

    def worker(n: int):
        try:
            for _, ev in scenario_benign(user=f"user{n}"):
                engine.process_event(ev)
            for _, ev in scenario_mfa_fatigue(user=f"user{n}"):
                engine.process_event(ev)
        except Exception as e:                      # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    assert engine.stats["events"] == 8 * (6 + 8)
    # every worker's fatigue scenario should have alerted exactly once
    assert engine.stats["alerts"] == 8


# ------------------------------------------------------------- responder --

def test_dry_run_is_default_and_protected_users_skipped(tmp_path):
    cfg = ResponderConfig(audit_log=str(tmp_path / "audit.jsonl"))
    assert cfg.dry_run is True

    responder = SOARResponder(cfg)
    engine = ITDREngine(on_alert=responder.handle_alert)
    drain(engine, scenario_token_theft(user="breakglass-admin"))
    assert any("SKIPPED containment" in a for a in responder.actions)
    assert not any("would revoke" in a for a in responder.actions)


def test_critical_alert_triggers_revocation_in_dry_run(tmp_path):
    cfg = ResponderConfig(audit_log=str(tmp_path / "audit.jsonl"))
    responder = SOARResponder(cfg)
    engine = ITDREngine(on_alert=responder.handle_alert)
    drain(engine, scenario_token_theft())
    assert any("[DRY-RUN] would revoke" in a for a in responder.actions)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
