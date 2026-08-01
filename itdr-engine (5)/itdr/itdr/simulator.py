"""
itdr.simulator
==============
Deterministic telemetry generator for demos and tests. Produces benign
baseline traffic plus three scripted attacks, one per checker:

  scenario_mfa_fatigue       -> push-bombing burst then capitulation
  scenario_token_theft       -> mid-session UA + subnet mutation
  scenario_impossible_travel -> Mumbai login, Sao Paulo 20 min later

Each scenario yields (delay_seconds, AuthEvent) tuples so the demo can
replay them in accelerated wall-clock time while keeping the EVENT
timestamps realistic (that's what the math runs on).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator

from .models import AuthEvent, EventResult, EventType

CITIES = {
    "Chennai":   ("IN", 13.0827, 80.2707),
    "Mumbai":    ("IN", 19.0760, 72.8777),
    "Bengaluru": ("IN", 12.9716, 77.5946),
    "Sao Paulo": ("BR", -23.5505, -46.6333),
    "Moscow":    ("RU", 55.7558, 37.6173),
}

UA_CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                 "AppleWebKit/537.36 Chrome/126.0 Safari/537.36")
UA_PYTHON = "python-requests/2.32.0"
UA_EDGE_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
               "AppleWebKit/537.36 Edg/126.0")

Step = tuple[float, AuthEvent]


def _ev(t: datetime, user: str, session: str, ip: str, ua: str,
        city: str, etype: EventType, result: EventResult) -> AuthEvent:
    country, lat, lon = CITIES[city]
    return AuthEvent(
        timestamp=t, user_id=user, session_id=session,
        client_ip=ip, user_agent=ua,
        geo_country=country, geo_city=city, geo_lat=lat, geo_lon=lon,
        event_type=etype, event_result=result,
    )


def scenario_benign(user: str = "asha.nair",
                    start: datetime | None = None) -> Iterator[Step]:
    """Normal workday: login, some API activity, logout."""
    t = start or datetime.now(timezone.utc)
    sid = f"sess-{uuid.uuid4().hex[:12]}"
    ip, ua, city = "203.0.113.10", UA_CHROME_WIN, "Chennai"
    yield 0.2, _ev(t, user, sid, ip, ua, city,
                   EventType.LOGIN, EventResult.SUCCESS)
    for i in range(4):
        t += timedelta(minutes=7)
        yield 0.15, _ev(t, user, sid, ip, ua, city,
                        EventType.API_ACCESS, EventResult.SUCCESS)
    t += timedelta(minutes=5)
    yield 0.15, _ev(t, user, sid, ip, ua, city,
                    EventType.LOGOUT, EventResult.SUCCESS)


def scenario_mfa_fatigue(user: str = "ravi.kumar",
                         start: datetime | None = None) -> Iterator[Step]:
    """T1621: 6 rejected pushes in ~90s, victim approves the 7th."""
    t = start or datetime.now(timezone.utc)
    sid = f"sess-{uuid.uuid4().hex[:12]}"
    ip, city = "198.51.100.66", "Mumbai"
    for _ in range(6):
        yield 0.25, _ev(t, user, sid, ip, UA_CHROME_WIN, city,
                        EventType.MFA_CHALLENGE, EventResult.FAIL)
        t += timedelta(seconds=15)
    t += timedelta(seconds=20)
    yield 0.4, _ev(t, user, sid, ip, UA_CHROME_WIN, city,
                   EventType.LOGIN, EventResult.SUCCESS)
    t += timedelta(minutes=1)
    yield 0.2, _ev(t, user, sid, ip, UA_CHROME_WIN, city,
                   EventType.API_ACCESS, EventResult.SUCCESS)


def scenario_token_theft(user: str = "asha.nair",
                         start: datetime | None = None) -> Iterator[Step]:
    """T1550.004: victim's session token replayed from attacker infra —
    same session_id, different UA and subnet, no re-authentication."""
    t = start or datetime.now(timezone.utc)
    sid = f"sess-{uuid.uuid4().hex[:12]}"
    yield 0.2, _ev(t, user, sid, "203.0.113.10", UA_CHROME_WIN, "Chennai",
                   EventType.LOGIN, EventResult.SUCCESS)
    t += timedelta(minutes=3)
    yield 0.2, _ev(t, user, sid, "203.0.113.10", UA_CHROME_WIN, "Chennai",
                   EventType.API_ACCESS, EventResult.SUCCESS)
    # --- token exfiltrated; attacker replays it ---
    t += timedelta(minutes=4)
    yield 0.5, _ev(t, user, sid, "185.220.101.42", UA_PYTHON, "Moscow",
                   EventType.TOKEN_REFRESH, EventResult.SUCCESS)
    t += timedelta(seconds=30)
    yield 0.2, _ev(t, user, sid, "185.220.101.42", UA_PYTHON, "Moscow",
                   EventType.API_ACCESS, EventResult.SUCCESS)


def scenario_impossible_travel(user: str = "meera.iyer",
                               start: datetime | None = None
                               ) -> Iterator[Step]:
    """T1078: success in Mumbai, then success in Sao Paulo 20 minutes
    later — ~13,700 km, requires ~41,000 km/h."""
    t = start or datetime.now(timezone.utc)
    sid1 = f"sess-{uuid.uuid4().hex[:12]}"
    yield 0.2, _ev(t, user, sid1, "203.0.113.77", UA_CHROME_WIN, "Mumbai",
                   EventType.LOGIN, EventResult.SUCCESS)
    t += timedelta(minutes=20)
    sid2 = f"sess-{uuid.uuid4().hex[:12]}"
    yield 0.5, _ev(t, user, sid2, "192.0.2.200", UA_EDGE_MAC, "Sao Paulo",
                   EventType.LOGIN, EventResult.SUCCESS)


def full_demo() -> Iterator[Step]:
    base = datetime.now(timezone.utc)
    yield from scenario_benign(start=base)
    yield from scenario_mfa_fatigue(start=base + timedelta(minutes=2))
    yield from scenario_token_theft(start=base + timedelta(minutes=6))
    yield from scenario_impossible_travel(start=base + timedelta(minutes=12))
