"""Tests for the enhancement layer: enrichment, three new detections,
metrics, and JSON replay — plus a benign-silence guard."""

from datetime import datetime, timedelta, timezone

import pytest

from itdr.detections import (MassSessionChecker, RefreshTokenReplayChecker,
                             TorAccessChecker)
from itdr.enrichment import IPEnricher
from itdr.engine import ITDREngine
from itdr.metrics import render_metrics
from itdr.models import AuthEvent, EventResult, EventType, SessionState
from itdr.simulator import scenario_benign, scenario_token_theft, _ev, CITIES


def ev(user, sess, ip, etype, ua="Chrome/126", city="Chennai",
       result=EventResult.SUCCESS, t=None):
    country, lat, lon = CITIES[city]
    return AuthEvent(timestamp=t or datetime.now(timezone.utc),
                     user_id=user, session_id=sess, client_ip=ip,
                     user_agent=ua, geo_country=country, geo_city=city,
                     geo_lat=lat, geo_lon=lon, event_type=etype,
                     event_result=result)


# ------------------------------------------------------------ enrichment --

def test_tor_and_hosting_classification():
    enr = IPEnricher()
    tor = enr.enrich("185.220.101.42")
    assert tor.is_tor and tor.risk_bonus >= 20 and "TOR_EXIT" in tor.tags
    clean = enr.enrich("203.0.113.10")
    assert not clean.is_tor and clean.label == "clean"


# --------------------------------------------------------- new detectors --

def test_tor_access_fires_on_tor_ip():
    d = TorAccessChecker().check(
        ev("u", "s", "185.220.101.42", EventType.LOGIN),
        SessionState("s", "u"), None)
    assert d and d.checker == "tor_access" and d.mitre == "T1090.003"


def test_tor_access_quiet_on_clean_ip():
    assert TorAccessChecker().check(
        ev("u", "s", "8.8.8.8", EventType.LOGIN),
        SessionState("s", "u"), None) is None


def test_refresh_replay_requires_new_ip():
    c = RefreshTokenReplayChecker()
    s = SessionState("s", "u")
    s.current_ip = "203.0.113.10"
    s.history.append(ev("u", "s", "203.0.113.10", EventType.LOGIN))
    # same IP → quiet
    assert c.check(ev("u", "s", "203.0.113.10", EventType.TOKEN_REFRESH),
                   s, None) is None
    # new IP → fires
    d = c.check(ev("u", "s", "185.220.101.42", EventType.TOKEN_REFRESH), s, None)
    assert d and d.checker == "refresh_replay"


def test_mass_session_burst():
    from itdr.state import _MemContext
    c, ctx = MassSessionChecker(count=5, window=120), _MemContext()
    t = datetime.now(timezone.utc)
    fired = None
    for i in range(5):
        fired = c.check(ev("u", f"sess-{i}", "203.0.113.10",
                           EventType.LOGIN, t=t + timedelta(seconds=i)),
                        SessionState(f"sess-{i}", "u"), ctx)
    assert fired and fired.evidence["distinct_sessions"] >= 5


# ---------------------------------------------------------------- safety --

def test_benign_still_silent_with_new_checkers():
    engine = ITDREngine()
    alerts = []
    for _, e in scenario_benign():
        alerts.extend(engine.process_event(e))
    assert not alerts, "new detectors must not fire on benign traffic"


def test_token_theft_escalates_with_enrichment():
    engine = ITDREngine()
    alerts = []
    for _, e in scenario_token_theft():
        alerts.extend(engine.process_event(e))
    crit = [a for a in alerts if a.tier == "CRITICAL"]
    assert crit
    checkers = {d.checker for a in crit for d in a.detections}
    assert {"tor_access", "refresh_replay", "session_mutation"} <= checkers


# --------------------------------------------------------------- metrics --

def test_metrics_render():
    engine = ITDREngine()
    for _, e in scenario_benign():
        engine.process_event(e)
    text = render_metrics(engine)
    assert "itdr_events_total" in text
    assert "itdr_active_sessions" in text


# ── Regression: the live Okta false positive Keshav hit on 2026-07-07 ──
# A single real login (Chennai) plus an Okta backend record carrying an
# AWS us-west-2 IP (geolocates to "Boardman, US") produced a ~13-billion
# km/h "impossible travel" alert. Neither a datacenter destination nor a
# zero-time multi-record artifact may ever raise a travel alert again.

def _ev(minutes, city, lat, lon, ip, user="keshav@vit.ac.in"):
    from datetime import datetime, timedelta, timezone
    from itdr.models import AuthEvent, EventType, EventResult
    base = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
    return AuthEvent(
        timestamp=base + timedelta(minutes=minutes), user_id=user,
        session_id="sess-live", client_ip=ip, user_agent="Chrome/126",
        geo_country=city[1], geo_city=city[0], geo_lat=lat, geo_lon=lon,
        event_type=EventType.LOGIN, event_result=EventResult.SUCCESS)


def test_aws_datacenter_destination_is_not_travel():
    from itdr.engine import ITDREngine
    alerts = []
    eng = ITDREngine(on_alert=alerts.append)
    # real human login from Chennai, then an Okta/AWS backend record
    eng.process_event(_ev(0, ("Chennai", "India"), 13.08, 80.27,
                          "203.0.113.10"))
    eng.process_event(_ev(0, ("Boardman", "United States"), 45.78, -119.52,
                          "44.224.10.20"))     # AWS us-west-2
    assert not alerts, "datacenter destination must not flag as travel"


def test_same_instant_records_are_not_travel():
    from itdr.engine import ITDREngine
    alerts = []
    eng = ITDREngine(on_alert=alerts.append)
    # two residential-looking records at the same instant (0 min apart)
    eng.process_event(_ev(0, ("Chennai", "India"), 13.08, 80.27,
                          "203.0.113.10"))
    eng.process_event(_ev(0, ("Mumbai", "India"), 19.07, 72.87,
                          "203.0.114.10"))
    assert not alerts, "zero-elapsed multi-record artifact must not flag"


def test_real_impossible_travel_still_fires():
    """Guard against over-correction: genuine travel must still alert."""
    from itdr.engine import ITDREngine
    alerts = []
    eng = ITDREngine(on_alert=alerts.append)
    eng.process_event(_ev(0, ("Chennai", "India"), 13.08, 80.27,
                          "203.0.113.10"))
    eng.process_event(_ev(8, ("Moscow", "Russia"), 55.75, 37.61,
                          "77.88.55.60"))      # residential-ish, 8 min later
    assert any("impossible_travel" in {d.checker for d in a.detections}
               for a in alerts), "real impossible travel must still fire"
