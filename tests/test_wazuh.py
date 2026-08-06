"""Wazuh ingestion: field mapping, alert filtering, and the authenticated
push listener. No Wazuh install required — fixtures are real alert
shapes and the listener is exercised over a loopback socket."""

import json
import urllib.error
import urllib.request

import pytest

from itdr.engine import ITDREngine
from itdr.models import EventResult, EventType
from itdr.wazuh import (WazuhListener, iter_alerts_file, map_wazuh_alert)


def ssh_fail(user="alice", ip="203.0.113.7", agent="web-01"):
    """Wazuh rule 5760 — sshd authentication failure."""
    return {
        "timestamp": "2026-08-06T10:15:00.000+0000",
        "rule": {"id": "5760", "level": 5,
                 "description": "sshd: authentication failed.",
                 "groups": ["syslog", "sshd", "authentication_failed"]},
        "agent": {"id": "001", "name": agent, "ip": "10.0.0.11"},
        "predecoder": {"program_name": "sshd"},
        "data": {"srcip": ip, "dstuser": user, "srcport": "52344"},
    }


def ssh_success(user="alice", ip="203.0.113.7", agent="web-01",
                ts="2026-08-06T10:16:00.000+0000", geo=None):
    rec = {
        "timestamp": ts,
        "rule": {"id": "5715", "level": 3,
                 "description": "sshd: authentication success.",
                 "groups": ["syslog", "sshd", "authentication_success"]},
        "agent": {"id": "001", "name": agent, "ip": "10.0.0.11"},
        "predecoder": {"program_name": "sshd"},
        "data": {"srcip": ip, "dstuser": user},
    }
    if geo:
        rec["GeoLocation"] = geo
    return rec


# ----------------------------------------------------------- mapping --

def test_maps_ssh_failure():
    ev = map_wazuh_alert(ssh_fail())
    assert ev is not None
    assert ev.user_id == "alice"
    assert ev.client_ip == "203.0.113.7"
    assert ev.event_type is EventType.LOGIN
    assert ev.event_result is EventResult.FAIL
    assert ev.idp_source == "wazuh"
    # session key is per user per endpoint
    assert ev.session_id == "wazuh:alice@web-01"
    # no browser on SSH: the authenticating program takes the slot
    assert ev.user_agent == "sshd"


def test_maps_ssh_success_with_geo():
    ev = map_wazuh_alert(ssh_success(geo={
        "country_name": "Germany", "city_name": "Berlin",
        "location": {"lat": 52.52, "lon": 13.40}}))
    assert ev.event_result is EventResult.SUCCESS
    assert ev.geo_country == "Germany"
    assert ev.geo is not None and ev.geo.lat == 52.52


def test_missing_geo_yields_none_not_zeros():
    # Impossible travel must stay quiet rather than compute against
    # invented coordinates at (0, 0).
    ev = map_wazuh_alert(ssh_success())
    assert ev.geo_lat is None and ev.geo_lon is None
    assert ev.geo is None


def test_maps_windows_security_event():
    rec = {
        "timestamp": "2026-08-06T11:00:00.000+0000",
        "rule": {"id": "60122", "level": 5,
                 "description": "Logon failure",
                 "groups": ["windows", "authentication_failed"]},
        "agent": {"id": "002", "name": "win-ws-03"},
        "data": {"win": {"eventdata": {"targetUserName": "bob",
                                       "ipAddress": "198.51.100.9"}}},
    }
    ev = map_wazuh_alert(rec)
    assert ev.user_id == "bob"
    assert ev.client_ip == "198.51.100.9"
    assert ev.session_id == "wazuh:bob@win-ws-03"


def test_non_auth_alert_is_skipped():
    rec = {"timestamp": "2026-08-06T10:00:00.000+0000",
           "rule": {"id": "550", "groups": ["ossec", "syscheck"]},
           "agent": {"name": "web-01"},
           "data": {"file": "/etc/passwd"}}
    assert map_wazuh_alert(rec) is None


@pytest.mark.parametrize("user", [None, "SYSTEM", "(unknown)"])
def test_machine_accounts_and_missing_users_skipped(user):
    rec = ssh_fail()
    if user is None:
        rec["data"].pop("dstuser")
    else:
        rec["data"]["dstuser"] = user
    assert map_wazuh_alert(rec) is None


def test_malformed_timestamp_does_not_crash():
    rec = ssh_fail()
    rec["timestamp"] = "not-a-timestamp"
    ev = map_wazuh_alert(rec)
    assert ev is not None                  # falls back to now()


def test_localhost_ip_normalized():
    rec = ssh_fail(ip="::1")
    assert map_wazuh_alert(rec).client_ip == "0.0.0.0"


# ----------------------------------------------------------- replay --

def test_iter_alerts_file_skips_junk(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text("\n".join([
        json.dumps(ssh_fail()),
        "{ not json",                       # corrupt line
        "",                                 # blank line
        json.dumps({"rule": {"groups": ["syscheck"]}}),   # non-auth
        json.dumps(ssh_success()),
    ]))
    events = list(iter_alerts_file(p))
    assert len(events) == 2
    assert [e.event_result.value for e in events] == ["FAIL", "SUCCESS"]


def test_replayed_failures_drive_the_engine(tmp_path):
    """End to end: a brute-force burst from an agent reaches the engine
    as normal AuthEvents and accumulates session state."""
    p = tmp_path / "alerts.json"
    p.write_text("\n".join(
        json.dumps(ssh_fail()) for _ in range(8)))
    engine = ITDREngine()
    for ev in iter_alerts_file(p):
        engine.process_event(ev)
    assert engine.stats["events"] == 8
    assert engine.active_sessions() == 1


# --------------------------------------------------------- listener --

@pytest.fixture
def listener():
    received = []
    lis = WazuhListener(sink=received.append, token="test-token",
                        host="127.0.0.1", port=0)
    lis.start()
    yield lis, received
    lis.stop()


def _post(port, body, token="test-token", path="/wazuh"):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "X-ITDR-Token": token},
        method="POST")
    return urllib.request.urlopen(req, timeout=5)


def test_listener_requires_a_token():
    with pytest.raises(ValueError):
        WazuhListener(sink=lambda e: None, token="")


def test_listener_accepts_authenticated_alert(listener):
    lis, received = listener
    resp = _post(lis.port, ssh_fail())
    assert resp.status == 200
    assert json.loads(resp.read())["accepted"] == 1
    assert len(received) == 1
    assert received[0].user_id == "alice"
    assert lis.received == 1


def test_listener_accepts_batches(listener):
    lis, received = listener
    _post(lis.port, [ssh_fail(), ssh_success(), {"rule": {"groups": []}}])
    assert len(received) == 2               # non-auth record filtered


def test_listener_rejects_bad_token(listener):
    lis, received = listener
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(lis.port, ssh_fail(), token="wrong")
    assert e.value.code == 401
    assert received == []
    assert lis.rejected == 1


def test_listener_rejects_malformed_json(listener):
    lis, _ = listener
    req = urllib.request.Request(
        f"http://127.0.0.1:{lis.port}/wazuh", data=b"{not json",
        headers={"X-ITDR-Token": "test-token"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 400


def test_listener_survives_a_failing_sink():
    """A crash in the engine must not kill the ingestion thread."""
    def boom(ev):
        raise RuntimeError("engine exploded")

    lis = WazuhListener(sink=boom, token="t", host="127.0.0.1", port=0)
    lis.start()
    try:
        resp = _post(lis.port, ssh_fail(), token="t")
        assert resp.status == 200
        assert json.loads(resp.read())["accepted"] == 0
        # still serving afterwards
        assert _post(lis.port, ssh_fail(), token="t").status == 200
    finally:
        lis.stop()
