"""
Tests for the scale + real-telemetry layers:
  - RedisStore: full pipeline runs identically on Redis (fakeredis),
    session serialization round-trips, TTL eviction is delegated
  - Pollers: Okta System Log and Entra Graph records map correctly
    into AuthEvent (recorded-fixture style, no network)
"""

from __future__ import annotations

import fakeredis
import pytest

from itdr.engine import ITDREngine
from itdr.models import EventResult, EventType
from itdr.pollers import map_entra_event, map_okta_event
from itdr.simulator import scenario_benign, scenario_token_theft
from itdr.state import RedisStore, session_from_json, session_to_json


# ------------------------------------------------------------------ redis --

def make_redis_store(ttl: int = 1800) -> RedisStore:
    return RedisStore(client=fakeredis.FakeRedis(decode_responses=True),
                      session_ttl=ttl)


def test_redis_backend_full_pipeline_parity():
    """The token-theft scenario must produce the same CRITICAL alert on
    Redis as it does in memory."""
    alerts_mem, alerts_redis = [], []
    mem = ITDREngine(on_alert=alerts_mem.append)
    red = ITDREngine(on_alert=alerts_redis.append,
                     store=make_redis_store())
    for _, ev in scenario_token_theft():
        mem.process_event(ev)
    for _, ev in scenario_token_theft():
        red.process_event(ev)

    assert [a.tier for a in alerts_mem] == [a.tier for a in alerts_redis]
    assert any(a.tier == "CRITICAL" for a in alerts_redis)
    m = {d.checker for a in alerts_redis for d in a.detections}
    assert "session_mutation" in m


def test_redis_benign_stays_silent():
    engine = ITDREngine(store=make_redis_store())
    alerts = []
    for _, ev in scenario_benign():
        alerts.extend(engine.process_event(ev))
    assert not alerts


def test_session_serialization_roundtrip():
    engine = ITDREngine(store=make_redis_store())
    sid = None
    for _, ev in scenario_token_theft():
        engine.process_event(ev)
        sid = ev.session_id
    s = engine.store.load(sid, "")
    restored = session_from_json(session_to_json(s))
    assert restored.risk_score == s.risk_score
    assert restored.current_user_agent == s.current_user_agent
    assert len(restored.detections) == len(s.detections)
    assert restored.responded_tiers == s.responded_tiers


def test_redis_ttl_is_set_on_sessions():
    store = make_redis_store(ttl=123)
    engine = ITDREngine(store=store)
    for _, ev in scenario_benign():
        engine.process_event(ev)
        key = f"itdr:sess:{ev.session_id}"
        break
    assert 0 < store.r.ttl(key) <= 123


# ---------------------------------------------------------------- pollers --

OKTA_FIXTURE = {
    "eventType": "user.session.start",
    "published": "2026-07-06T09:15:23.000Z",
    "actor": {"id": "00u1abcd", "alternateId": "asha.nair@corp.example",
              "type": "User"},
    "client": {
        "ipAddress": "203.0.113.10",
        "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/126.0"},
        "geographicalContext": {
            "city": "Chennai", "country": "India",
            "geolocation": {"lat": 13.0827, "lon": 80.2707}},
    },
    "outcome": {"result": "SUCCESS"},
    "authenticationContext": {"externalSessionId": "idx-102938"},
}

ENTRA_FIXTURE = {
    "createdDateTime": "2026-07-06T09:20:11Z",
    "userPrincipalName": "ravi.kumar@corp.example",
    "correlationId": "c0ffee00-1234",
    "ipAddress": "198.51.100.66",
    "status": {"errorCode": 500121},          # MFA denied
    "authenticationRequirement": "multiFactorAuthentication",
    "deviceDetail": {"browser": "Edge 126.0"},
    "location": {"city": "Mumbai", "countryOrRegion": "IN",
                 "geoCoordinates": {"latitude": 19.076,
                                    "longitude": 72.8777}},
}


def test_okta_mapping():
    ev = map_okta_event(OKTA_FIXTURE)
    assert ev is not None
    assert ev.user_id == "asha.nair@corp.example"
    assert ev.session_id == "idx-102938"
    assert ev.event_type is EventType.LOGIN
    assert ev.event_result is EventResult.SUCCESS
    assert ev.geo_lat == pytest.approx(13.0827)
    assert ev.idp_source == "okta"


def test_entra_mapping_mfa_denial():
    ev = map_entra_event(ENTRA_FIXTURE)
    assert ev is not None
    assert ev.user_id == "ravi.kumar@corp.example"
    assert ev.event_type is EventType.MFA_CHALLENGE
    assert ev.event_result is EventResult.FAIL
    assert ev.geo_lon == pytest.approx(72.8777)
    assert ev.idp_source == "entra"


def test_okta_mapping_handles_missing_fields():
    ev = map_okta_event({"eventType": "user.session.start",
                         "actor": {"alternateId": "x@y.z"}})
    assert ev is not None and ev.client_ip == "0.0.0.0"
    assert map_okta_event({"eventType": "x", "actor": {}}) is None
