"""
Console tests: state shaping, rendering, and the live Wazuh source.

The rendering assertions are deliberately about *content* rather than
markup — a console that renders beautifully but drops the critical alert
count is worse than one that looks plain.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from itdr.dashboard import (LiveWazuhSource, collect_state, demo_state,
                            render_document, render_page)
from itdr.engine import ITDREngine
from itdr.models import AuthEvent, EventResult, EventType
from itdr.wazuh_detections import wazuh_checkers

BASE = datetime(2026, 8, 8, 23, 0, tzinfo=timezone.utc)


def ev(offset, result=EventResult.SUCCESS, etype=EventType.LOGIN,
       agent="web-01", user="alice"):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset),
        user_id=user, session_id=f"wazuh:{user}@{agent}",
        client_ip="45.33.32.156", user_agent="sshd",
        geo_country="??", geo_city="??",
        event_type=etype, event_result=result, idp_source="wazuh")


def engine_with_attack(user="alice"):
    alerts = []
    e = ITDREngine(checkers=wazuh_checkers(), on_alert=alerts.append)
    for i in range(10):
        e.process_event(ev(i * 4, result=EventResult.FAIL, user=user))
    e.process_event(ev(44, user=user))
    return e, alerts


class TestState:
    def test_counts_reflect_the_engine(self):
        e, alerts = engine_with_attack()
        st = collect_state(e, None, alerts)
        assert st["events"] == 11
        assert st["alerts_total"] >= 1
        assert st["critical"] + st["notable"] == len(alerts)

    def test_rows_sorted_by_risk_descending(self):
        e, alerts = engine_with_attack()
        risks = [r["risk"] for r in collect_state(e, None, alerts)["rows"]]
        assert risks == sorted(risks, reverse=True)

    def test_empty_state_does_not_crash(self):
        st = collect_state(ITDREngine(), None, [])
        assert st["critical"] == 0 and st["rows"] == []

    def test_volume_buckets_are_twelve(self):
        e, alerts = engine_with_attack()
        assert len(collect_state(e, None, alerts)["volume"]) == 12


class TestRendering:
    def test_page_shows_the_critical_count(self):
        st = demo_state()
        assert st["critical"] > 0, "demo should produce a critical alert"
        assert str(st["critical"]) in render_page(st)

    def test_document_is_self_contained(self):
        """A CDN reference breaks the offline snapshot and any host with
        a strict content-security policy."""
        doc = render_document(demo_state())
        for forbidden in ("http://", "https://cdn", "<script src"):
            assert forbidden not in doc

    def test_user_content_is_escaped(self):
        """Account names come from telemetry an attacker can influence."""
        e, alerts = engine_with_attack(user="<script>x</script>")
        html = render_page(collect_state(e, None, alerts))
        assert "<script>x</script>" not in html
        assert "&lt;script&gt;" in html

    def test_refresh_meta_only_when_requested(self):
        st = demo_state()
        assert 'http-equiv="refresh"' in render_document(st, refresh=30)
        assert 'http-equiv="refresh"' not in render_document(st)

    def test_empty_engine_renders_a_message_not_a_broken_table(self):
        html = render_page(collect_state(ITDREngine(), None, []))
        assert "No alerts yet" in html

    def test_both_themes_define_every_colour_token(self):
        """A token defined only inside the dark block leaves light mode
        resolving against an undefined var."""
        doc = render_document(demo_state())
        for tok in ("--surface", "--ink", "--crit", "--s0", "--grid"):
            assert doc.count(f"{tok}:") >= 3   # root + media + data-theme

    def test_axis_labels_are_not_duplicated_at_small_maxima(self):
        """Regression: a max of 1 rendered the y-axis as 0, 0, 1."""
        from itdr.dashboard import _area_chart
        svg = _area_chart([0, 1, 0, 1])
        labels = [s.split("<")[0] for s in svg.split('text-anchor="end">')[1:]]
        assert len(labels) == len(set(labels))


class TestLiveSource:
    class FakePoller:
        def __init__(self, events, fail=False):
            self.events = events
            self.fail = fail
            self.calls = 0

        def fetch(self):
            self.calls += 1
            if self.fail:
                raise RuntimeError("indexer unreachable")
            return iter(self.events)

    def _source(self, events, fail=False):
        engine = ITDREngine(checkers=wazuh_checkers())
        src = LiveWazuhSource(self.FakePoller(events, fail), engine)
        engine.on_alert = src.alerts.append
        return src

    def test_poll_feeds_the_engine_and_produces_alerts(self):
        events = [ev(i * 4, result=EventResult.FAIL) for i in range(10)]
        events.append(ev(44))
        src = self._source(events)
        assert src.poll_once() == 11
        assert len(src.alerts) >= 1
        assert src.state()["source"] == "wazuh-indexer"

    def test_indexer_failure_leaves_console_serving_last_good_state(self):
        """A dead indexer must not take the console down with it."""
        src = self._source([], fail=True)
        assert src.poll_once() == 0
        assert src.last_error and "unreachable" in src.last_error
        assert src.state()["events"] == 0        # renders, does not raise

    def test_engine_persists_across_polls_so_correlation_survives(self):
        """Rebuilding the engine per poll would reset every sliding
        window, and no correlation would ever fire."""
        src = self._source([])
        src.poller.events = [ev(i * 4, result=EventResult.FAIL)
                             for i in range(10)]
        src.poll_once()
        src.poller.events = [ev(44)]             # success in a later poll
        src.poll_once()
        assert len(src.alerts) >= 1, "correlation did not survive the poll"

    def test_alerts_ring_is_bounded(self):
        assert self._source([]).alerts.maxlen == 500
