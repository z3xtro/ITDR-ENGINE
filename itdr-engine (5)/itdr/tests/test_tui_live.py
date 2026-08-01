"""Live-canvas integration test: the demo replay must drive the TUI's
node states, risk flags, and SOAR log from real engine output."""

import asyncio

import pytest

from itdr.tui import ITDRCanvasApp


@pytest.mark.asyncio
async def test_replay_lights_up_canvas():
    app = ITDRCanvasApp(replay_speed=50)
    async with app.run_test(size=(158, 44)) as pilot:
        await pilot.pause()
        assert app.state.phase == "idle"
        assert not any(c.fired for c in app.state.checkers.values())

        await pilot.press("r")
        for _ in range(80):
            await asyncio.sleep(0.05)
            if app.state.phase == "complete":
                break

        st = app.state
        assert st.phase == "complete"
        assert (st.events, st.sessions, st.alerts) == (20, 5, 3)
        # token theft now trips multiple detectors and fires CRITICAL via
        # the tor/refresh/mutation cluster — assert on the cluster, not on
        # which specific node happens to carry it.
        crit = [c for c in st.checkers.values()
                if c.fired and c.tier == "critical"]
        assert crit, "expected a critical detection on the canvas"
        assert max(c.risk for c in crit) >= 100
        # mfa, travel, and the mutation/tor/refresh cluster all light up
        for node in ("mfa", "travel", "mutate"):
            assert st.checkers[node].fired, f"{node} node should light up"
        assert any("would revoke" in a for a in st.soar_raw)

        # reset returns the canvas to a quiet state
        await pilot.press("x")
        await pilot.pause()
        assert app.state.phase == "idle"
        assert not any(c.fired for c in app.state.checkers.values())


class StubPoller:
    """Emits Okta-shaped AuthEvents; second pass includes an attack."""

    def __init__(self):
        from itdr.pollers import map_okta_event
        self.map = map_okta_event
        self.passes = 0

    def fetch(self):
        from datetime import datetime, timedelta, timezone
        self.passes += 1
        t = datetime.now(timezone.utc)

        def rec(minutes, city, lat, lon, ip, ua="Mozilla/5.0 Chrome/126"):
            return {
                "eventType": "user.session.start",
                "published": (t + timedelta(minutes=minutes)
                              ).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "actor": {"alternateId": "krish@dev.okta"},
                "client": {"ipAddress": ip,
                           "userAgent": {"rawUserAgent": ua},
                           "geographicalContext": {
                               "city": city, "country": "??",
                               "geolocation": {"lat": lat, "lon": lon}}},
                "outcome": {"result": "SUCCESS"},
                "authenticationContext": {
                    "externalSessionId": f"okta-sess-{self.passes}-{minutes}"},
            }
        if self.passes == 1:      # benign pass
            recs = [rec(0, "Chennai", 13.08, 80.27, "203.0.113.10")]
        else:                     # impossible travel pass
            recs = [rec(8, "Moscow", 55.75, 37.61, "77.88.55.60")]
        return [self.map(r) for r in recs]


@pytest.mark.asyncio
async def test_live_stream_mode_with_stub_poller():
    app = ITDRCanvasApp(poller=StubPoller(), poll_interval=0.15)
    async with app.run_test(size=(158, 44)) as pilot:
        await pilot.pause()
        assert app.state.mode == "live"
        await pilot.press("r")
        for _ in range(60):
            await asyncio.sleep(0.05)
            if app.state.checkers["travel"].fired:
                break
        st = app.state
        assert st.phase == "streaming"          # live mode never "completes"
        assert st.events >= 2
        assert st.checkers["travel"].fired      # real detection from
        assert st.checkers["travel"].user == "krish@dev.okta"   # okta schema
        assert "last poll" in st.status or "polling" in st.status
