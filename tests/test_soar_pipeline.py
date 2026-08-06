"""End to end: a Wazuh alert arriving on the listener drives detection,
containment, and TheHive case creation in the order the design requires
— containment before case management, and a dead TheHive changing
nothing about either."""

import json
import urllib.request
from datetime import datetime, timedelta, timezone

from itdr.engine import ITDREngine
from itdr.models import EventResult, EventType
from itdr.respond import ResponderConfig, SOARResponder
from itdr.thehive import TheHiveBridge, TheHiveClient, TheHiveConfig
from itdr.wazuh import WazuhListener, map_wazuh_alert

from test_thehive import FakeSession


def wazuh_login(user, ip, agent, ts, geo, ok=True):
    """A geo-enriched Wazuh sshd success — the manager shape when
    MaxMind GeoIP is configured."""
    country, city, lat, lon = geo
    groups = ["syslog", "sshd",
              "authentication_success" if ok else "authentication_failed"]
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"id": "5715" if ok else "5760", "level": 3,
                 "groups": groups},
        "agent": {"id": "001", "name": agent},
        "predecoder": {"program_name": "sshd"},
        "data": {"srcip": ip, "dstuser": user},
        "GeoLocation": {"country_name": country, "city_name": city,
                        "location": {"lat": lat, "lon": lon}},
    }


def build_stack(fail_thehive=False):
    session = FakeSession(fail_on={"/alert"} if fail_thehive else None)
    bridge = TheHiveBridge(TheHiveClient(
        TheHiveConfig(url="http://thehive:9000", api_key="k"),
        session=session))
    responder = SOARResponder(ResponderConfig(
        dry_run=True, audit_log="/dev/null"))
    cases = []

    def on_alert(alert):
        before = len(responder.actions)
        responder.handle_alert(alert)
        cases.append(bridge.record(
            alert, containment_actions=responder.actions[before:]))

    engine = ITDREngine(on_alert=on_alert)
    return engine, responder, bridge, session, cases


def compromise_scenario(user="alice"):
    """The shape a real Wazuh feed produces for a compromised account:
    a legitimate login from Berlin, then a brute-force burst from
    elsewhere that lands — the success arriving from Sydney four minutes
    after Berlin, which is also physically impossible.

    Two correlated signals (T1110 + T1078) is what carries the session
    past the CRITICAL line into containment. One alone would not.
    """
    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    events = [wazuh_login(user, "203.0.113.7", "web-01", t0,
                          ("Germany", "Berlin", 52.52, 13.40))]
    # 10 failures in ~20s: machine-speed guessing.
    for i in range(10):
        events.append(wazuh_login(
            user, "198.51.100.9", "web-01",
            t0 + timedelta(minutes=3, seconds=2 * i),
            ("Australia", "Sydney", -33.87, 151.21), ok=False))
    events.append(wazuh_login(
        user, "198.51.100.9", "web-01", t0 + timedelta(minutes=4),
        ("Australia", "Sydney", -33.87, 151.21)))
    return events


def test_wazuh_alert_drives_detection_containment_and_a_case():
    engine, responder, bridge, session, cases = build_stack()
    for rec in compromise_scenario():
        engine.process_event(map_wazuh_alert(rec))

    assert engine.stats["detections"] >= 1
    assert engine.stats["alerts"] >= 1

    # containment ran (dry-run narration, nothing touched)
    assert any("would revoke" in a for a in responder.actions)

    # and it reached TheHive as an alert
    assert bridge.stats["alerts"] >= 1
    assert ("POST", "/alert") in [(m, p) for m, p, _ in session.calls]


def test_containment_precedes_case_creation():
    """Ordering is a safety property: a slow or dead TheHive must never
    sit between a hijacked session and its revocation."""
    engine, responder, bridge, session, _ = build_stack()
    order = []

    original_revoke = responder.revoke_user_session
    responder.revoke_user_session = lambda *a, **k: (
        order.append("contain") or original_revoke(*a, **k))
    original_request = session.request

    def tracking_request(method, url, **kw):
        if url.endswith("/alert"):
            order.append("case")
        return original_request(method, url, **kw)

    session.request = tracking_request

    for rec in compromise_scenario():
        engine.process_event(map_wazuh_alert(rec))

    assert "contain" in order and "case" in order
    assert order.index("contain") < order.index("case")


def test_thehive_outage_does_not_break_containment():
    engine, responder, bridge, session, _ = build_stack(fail_thehive=True)
    for rec in compromise_scenario():
        engine.process_event(map_wazuh_alert(rec))

    assert bridge.stats["errors"] >= 1              # case management lost
    assert any("would revoke" in a for a in responder.actions)  # still contained
    assert engine.stats["alerts"] >= 1


def test_listener_to_case_over_http():
    """The real ingestion path: HTTP POST from the manager's integration
    script through to a TheHive alert."""
    engine, responder, bridge, session, _ = build_stack()
    scenario = compromise_scenario()
    listener = WazuhListener(sink=engine.process_event, token="tok",
                             host="127.0.0.1", port=0)
    listener.start()
    try:
        for rec in scenario:
            req = urllib.request.Request(
                f"http://127.0.0.1:{listener.port}/wazuh",
                data=json.dumps(rec).encode(),
                headers={"X-ITDR-Token": "tok"}, method="POST")
            assert urllib.request.urlopen(req, timeout=5).status == 200
    finally:
        listener.stop()

    assert listener.received == len(scenario)
    assert engine.stats["alerts"] >= 1
    assert bridge.stats["alerts"] >= 1
