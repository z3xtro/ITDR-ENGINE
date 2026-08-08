"""
Tests for the detection-engineering surface: Sigma export, ATT&CK
coverage, measured quality, and the analyst dossier.

These assert the properties that make the artifacts trustworthy — a
Sigma rule that doesn't parse, or a coverage layer that overstates what
is detected, is worse than not shipping one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from itdr.catalog import CATALOG
from itdr.engine import ITDREngine
from itdr.export import navigator_layer, sigma_rule, write_exports
from itdr.models import AuthEvent, EventResult, EventType
from itdr.triage import dossier_for, render_markdown, render_terminal
from itdr.wazuh_detections import wazuh_checkers

yaml = pytest.importorskip("yaml")


BASE = datetime(2026, 8, 8, 23, 0, tzinfo=timezone.utc)


def ev(offset, result=EventResult.SUCCESS, etype=EventType.LOGIN,
       agent="web-01", program="sshd"):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset),
        user_id="alice", session_id=f"wazuh:alice@{agent}",
        client_ip="45.33.32.156", user_agent=program,
        geo_country="??", geo_city="??",
        event_type=etype, event_result=result, idp_source="wazuh")


def critical_alert():
    alerts = []
    engine = ITDREngine(checkers=wazuh_checkers(), on_alert=alerts.append)
    for i in range(10):
        engine.process_event(ev(i * 4, result=EventResult.FAIL))
    engine.process_event(ev(44))
    engine.process_event(ev(70, etype=EventType.API_ACCESS, program="sudo"))
    crit = [a for a in alerts if a.tier == "CRITICAL"]
    assert crit, "fixture failed to produce a CRITICAL alert"
    return crit[-1]


class TestSigmaExport:
    def test_every_catalog_entry_produces_parseable_yaml(self):
        for doc in CATALOG:
            parsed = yaml.safe_load(sigma_rule(doc))
            assert parsed["title"] == doc.name

    def test_required_sigma_fields_present(self):
        required = {"title", "id", "status", "description", "logsource",
                    "detection", "level", "falsepositives", "tags"}
        for doc in CATALOG:
            assert required <= set(yaml.safe_load(sigma_rule(doc)))

    def test_detection_block_has_a_condition(self):
        for doc in CATALOG:
            det = yaml.safe_load(sigma_rule(doc))["detection"]
            assert "condition" in det

    def test_ids_are_stable_across_runs(self):
        """A Sigma rule's id is its identity across repos; regenerating
        must not churn it or downstream tracking breaks."""
        doc = CATALOG[0]
        assert (yaml.safe_load(sigma_rule(doc))["id"]
                == yaml.safe_load(sigma_rule(doc))["id"])

    def test_stateful_detections_are_marked_experimental(self):
        """A correlation-based detection loses its correlation in Sigma.
        Shipping it as production-ready would misrepresent it."""
        by_name = {d.name: d for d in CATALOG}
        rule = yaml.safe_load(sigma_rule(by_name["Brute Force Succeeded"]))
        assert rule["status"] == "experimental"
        assert "degrades" in rule["description"].lower()

    def test_attack_tags_are_wellformed(self):
        for doc in CATALOG:
            tags = yaml.safe_load(sigma_rule(doc))["tags"]
            assert any(t.startswith("attack.t") for t in tags)
            assert all(t.startswith("attack.") for t in tags)

    def test_write_exports_produces_files(self, tmp_path):
        stats = write_exports(tmp_path)
        assert stats["sigma_rules"] == len(CATALOG)
        assert (tmp_path / "attack-navigator-layer.json").exists()
        assert len(list((tmp_path / "sigma").glob("*.yml"))) == len(CATALOG)


class TestNavigatorLayer:
    def test_layer_shape_is_valid(self):
        layer = navigator_layer()
        assert layer["domain"] == "enterprise-attack"
        assert layer["techniques"]
        for t in layer["techniques"]:
            assert t["techniqueID"].startswith("T")
            assert 0 <= t["score"] <= 100

    def test_every_catalogued_technique_appears(self):
        ids = {t["techniqueID"] for t in navigator_layer()["techniques"]}
        assert {d.mitre_id for d in CATALOG} == ids

    def test_score_reflects_strongest_detection_not_count(self):
        """A technique covered only by a LOW heuristic must not look as
        well covered as one backed by a CRITICAL detection."""
        by_id = {t["techniqueID"]: t for t in navigator_layer()["techniques"]}
        assert by_id["T1110"]["score"] > by_id["T1090.003"]["score"]


class TestMeasuredQuality:
    def test_benign_corpus_raises_no_alerts(self):
        """The precision claim in DETECTION_QUALITY.md must hold."""
        from itdr.quality import benign_corpus, run_scenario
        import random
        for sc in benign_corpus(random.Random(0)):
            r = run_scenario(sc)
            assert not r.alerts, f"{sc.name} false-positived: {r.alerts}"

    def test_bruteforce_success_reaches_critical_alone(self):
        """Regression: the confidence ramp once topped out at 0.82, so
        90 * 0.82 = 73.6 fell under the CRITICAL threshold of 75 and the
        least ambiguous host signal could not raise a CRITICAL alert."""
        assert critical_alert().tier == "CRITICAL"

    def test_measure_reports_no_false_positives(self):
        from itdr.quality import measure
        m = measure()
        assert m["fp"] == 0
        assert m["precision"] == 1.0
        assert m["mttd"] is not None


class TestTriageDossier:
    def test_markdown_contains_the_analyst_essentials(self):
        md = render_markdown(dossier_for(critical_alert()))
        for expected in ["CRITICAL", "alice", "45.33.32.156",
                         "Next actions", "Rule out first",
                         "ssh_bruteforce_success"]:
            assert expected in md

    def test_actions_are_ordered_strongest_signal_first(self):
        d = dossier_for(critical_alert())
        actions = d.actions()
        assert "compromised" in actions[0].lower()

    def test_false_positive_checks_come_from_the_catalog(self):
        """Guidance must not drift from the documented detection."""
        checks = dossier_for(critical_alert()).false_positive_checks()
        assert checks
        names = {c for c, _ in checks}
        assert "ssh_bruteforce_success" in names

    def test_containment_actions_surface_when_supplied(self):
        md = render_markdown(dossier_for(
            critical_alert(), containment=["firewall-drop 45.33.32.156"]))
        assert "Already done automatically" in md
        assert "firewall-drop" in md

    def test_endpoints_recovered_from_evidence(self):
        assert "web-01" in dossier_for(critical_alert()).endpoints

    def test_terminal_render_does_not_raise(self):
        from rich.console import Console
        render_terminal(dossier_for(critical_alert()),
                        console=Console(file=open("/dev/null", "w")))

    def test_thehive_alert_body_uses_the_dossier(self):
        """The case an analyst opens should carry the investigation, not
        a bare table."""
        from itdr.thehive import alert_from_itdr
        payload = alert_from_itdr(critical_alert())
        assert "Next actions" in payload["description"]
        assert "Rule out first" in payload["description"]
