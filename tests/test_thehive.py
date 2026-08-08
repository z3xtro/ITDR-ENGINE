"""TheHive SOAR bridge: payload construction, the case pipeline, and
the failure isolation that keeps case management from ever stalling
containment. A fake transport stands in for the server."""

import json

import pytest

from itdr.models import Detection, ITDRAlert, Severity
from itdr.thehive import (TheHiveBridge, TheHiveClient, TheHiveConfig,
                          alert_from_itdr)


def make_alert(tier="CRITICAL", user="alice@corp.example"):
    return ITDRAlert(
        user_id=user, session_id="wazuh:alice@web-01", risk_score=118.5,
        tier=tier, client_ip="203.0.113.7", user_agent="sshd",
        detections=[
            Detection(checker="impossible_travel",
                      title="Impossible Travel", severity=Severity.HIGH,
                      confidence=0.9, evidence={"kmh": 4200},
                      mitre="T1078"),
            Detection(checker="session_mutation",
                      title="Session Context Mutation",
                      severity=Severity.CRITICAL, confidence=0.85,
                      evidence={"subnet_changed": True},
                      mitre="T1550.004"),
        ])


# ----------------------------------------------------------- payload --

def test_payload_carries_tier_severity_and_tags():
    p = alert_from_itdr(make_alert())
    assert p["severity"] == 3
    assert p["source"] == "itdr-engine"
    assert "itdr" in p["tags"]
    assert "tier:critical" in p["tags"]
    assert "T1550.004" in p["tags"]           # MITRE pivots in TheHive
    assert "impossible_travel" in p["tags"]


def test_notable_maps_to_lower_severity():
    assert alert_from_itdr(make_alert(tier="NOTABLE"))["severity"] == 2


def test_payload_dedup_key_is_stable_and_unique():
    a, b = make_alert(), make_alert()
    assert alert_from_itdr(a)["sourceRef"] != alert_from_itdr(b)["sourceRef"]
    assert alert_from_itdr(a)["sourceRef"] == alert_from_itdr(a)["sourceRef"]


def test_observables_cover_ip_ua_and_identity():
    obs = {(o["dataType"], o["data"])
           for o in alert_from_itdr(make_alert())["observables"]}
    assert ("ip", "203.0.113.7") in obs
    assert ("user-agent", "sshd") in obs
    assert ("mail", "alice@corp.example") in obs


def test_non_email_identity_is_not_typed_as_mail():
    obs = alert_from_itdr(make_alert(user="root"))["observables"]
    assert {"other"} == {o["dataType"] for o in obs if o["data"] == "root"}


def test_placeholder_ip_is_not_an_observable():
    a = make_alert()
    a.client_ip = "0.0.0.0"
    types = [o["dataType"] for o in alert_from_itdr(a)["observables"]]
    assert "ip" not in types


def test_description_lists_every_detection():
    # The body is now the full triage dossier rather than a bare table,
    # so it names detections by checker id and carries response guidance.
    desc = alert_from_itdr(make_alert())["description"]
    assert "impossible_travel" in desc
    assert "session_mutation" in desc
    assert "118.5" in desc
    assert "Next actions" in desc


# ------------------------------------------------------ fake transport --

class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.content = json.dumps(payload).encode()

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Records calls; returns ids so the pipeline can chain."""

    def __init__(self, fail_on=None, status_for=None):
        self.calls = []
        self.headers = {}
        self.fail_on = fail_on or set()
        self.status_for = status_for or {}

    def request(self, method, url, json=None, timeout=None, verify=None):
        path = url.split("/api/v1", 1)[1]
        self.calls.append((method, path, json))
        for marker in self.fail_on:
            if marker in path:
                raise RuntimeError(f"boom on {path}")
        status = self.status_for.get(path, 200)
        if path == "/alert":
            return FakeResponse({"_id": "alert-1"}, status)
        if path.endswith("/case"):
            return FakeResponse({"_id": "case-1"}, status)
        if path.endswith("/task"):
            return FakeResponse({"_id": "task-1"}, status)
        return FakeResponse({"ok": True}, status)


def build_bridge(**kw):
    session = FakeSession(**kw)
    client = TheHiveClient(
        TheHiveConfig(url="http://thehive:9000", api_key="k"),
        session=session)
    return TheHiveBridge(client), session


# ------------------------------------------------------- case pipeline --

def test_critical_opens_case_with_containment_task_logs():
    bridge, session = build_bridge()
    case_id = bridge.record(make_alert(), containment_actions=[
        "alert#1 REVOKED all sessions for alice@corp.example",
        "alert#1 FORCED MFA re-enrollment for alice@corp.example",
    ])

    assert case_id == "case-1"
    paths = [(m, p) for m, p, _ in session.calls]
    assert ("POST", "/alert") in paths
    assert ("POST", "/alert/alert-1/case") in paths
    assert ("POST", "/case/case-1/task") in paths
    assert paths.count(("POST", "/task/task-1/log")) == 2
    assert ("PATCH", "/task/task-1") in paths        # task completed
    assert bridge.stats == {"alerts": 1, "cases": 1, "errors": 0}


def test_containment_narration_is_preserved_verbatim():
    bridge, session = build_bridge()
    bridge.record(make_alert(), containment_actions=[
        "alert#1 [DRY-RUN] would revoke all sessions"])
    logs = [body["message"] for m, p, body in session.calls
            if p.endswith("/log")]
    assert logs == ["alert#1 [DRY-RUN] would revoke all sessions"]


def test_notable_creates_alert_but_no_case():
    bridge, session = build_bridge()
    assert bridge.record(make_alert(tier="NOTABLE")) is None
    assert [p for _, p, _ in session.calls] == ["/alert"]
    assert bridge.stats["cases"] == 0


def test_case_without_actions_leaves_task_open_for_the_analyst():
    bridge, session = build_bridge()
    bridge.record(make_alert(), containment_actions=[])
    paths = [(m, p) for m, p, _ in session.calls]
    assert ("POST", "/case/case-1/task") in paths
    assert ("PATCH", "/task/task-1") not in paths


# ---------------------------------------------------- failure isolation --

def test_alert_failure_never_raises_into_the_engine():
    bridge, session = build_bridge(fail_on={"/alert"})
    assert bridge.record(make_alert()) is None
    assert bridge.stats["errors"] == 1
    assert bridge.stats["cases"] == 0


def test_case_promotion_failure_is_contained():
    """Containment already ran; a broken case pipeline is bookkeeping
    loss, not an exception path into the responder."""
    bridge, session = build_bridge(fail_on={"/case"})
    assert bridge.record(make_alert(), ["revoked"]) is None
    assert bridge.stats["alerts"] == 1
    assert bridge.stats["errors"] == 1


def test_task_log_failure_is_contained():
    bridge, _ = build_bridge(fail_on={"/log"})
    assert bridge.record(make_alert(), ["revoked"]) is None
    assert bridge.stats["errors"] == 1


# ---------------------------------------------------------- disposition --

def test_false_positive_closes_the_tracked_case():
    bridge, session = build_bridge()
    alert = make_alert()
    bridge.record(alert, ["revoked"])

    assert bridge.close_false_positive(alert.id, note="VPN egress") is True
    patch = [(p, b) for m, p, b in session.calls
             if m == "PATCH" and p == "/case/case-1"]
    assert patch and patch[0][1]["status"] == "FalsePositive"
    assert patch[0][1]["summary"] == "VPN egress"


def test_false_positive_on_untracked_alert_is_a_safe_noop():
    bridge, session = build_bridge()
    assert bridge.close_false_positive(999) is False
    assert session.calls == []


# --------------------------------------------------------------- client --

def test_client_retries_transient_faults_then_succeeds(monkeypatch):
    monkeypatch.setattr("itdr.thehive.time.sleep", lambda s: None)

    class Flaky(FakeSession):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def request(self, method, url, **kw):
            self.attempts += 1
            if self.attempts < 3:
                return FakeResponse({}, 503)
            return FakeResponse({"_id": "alert-1"})

    session = Flaky()
    client = TheHiveClient(
        TheHiveConfig(url="http://thehive:9000", api_key="k"),
        session=session)
    assert client.create_alert({})["_id"] == "alert-1"
    assert session.attempts == 3


def test_client_sends_bearer_auth():
    session = FakeSession()
    TheHiveClient(TheHiveConfig(url="http://x", api_key="secret"),
                  session=session)
    assert session.headers["Authorization"] == "Bearer secret"


def test_bridge_is_opt_in(monkeypatch):
    from itdr.thehive import build_bridge_from_env
    monkeypatch.delenv("THEHIVE_URL", raising=False)
    monkeypatch.delenv("THEHIVE_API_KEY", raising=False)
    assert build_bridge_from_env() is None
    # URL alone isn't enough — both halves required
    monkeypatch.setenv("THEHIVE_URL", "http://thehive:9000")
    assert build_bridge_from_env() is None
