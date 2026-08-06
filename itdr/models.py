"""
itdr.models
===========
Strict, typed data models for the ITDR analytics engine.

  AuthEvent    -> normalized identity telemetry (Okta / Entra ID shaped)
  SessionState -> live snapshot + rolling history of one session
  Detection    -> single checker hit (internal, pre-correlation)
  ITDRAlert    -> high-fidelity alert emitted when session risk breaches
                  a threshold (what a SOC analyst / SOAR consumes)
"""

from __future__ import annotations

import itertools
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Deque, Optional

_alert_ids = itertools.count(1)


class EventResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"


class EventType(str, Enum):
    """Normalized identity event taxonomy (subset of Okta/Entra verbs)."""
    LOGIN = "user.authentication.login"
    MFA_CHALLENGE = "user.mfa.challenge"
    TOKEN_REFRESH = "user.session.token_refresh"
    API_ACCESS = "user.session.api_access"
    LOGOUT = "user.session.end"


class Severity(IntEnum):
    INFO = 10
    LOW = 25
    MEDIUM = 45
    HIGH = 70
    CRITICAL = 90


@dataclass(frozen=True, slots=True)
class GeoPoint:
    country: str
    city: str
    lat: float
    lon: float


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One normalized telemetry record from an Identity Provider.

    Frozen: events are immutable facts. All derived state lives in
    SessionState, never on the event itself.
    """
    timestamp: datetime
    user_id: str
    session_id: str
    client_ip: str
    user_agent: str
    geo_country: str
    geo_city: str
    event_type: EventType
    event_result: EventResult
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    idp_source: str = "sim"                 # "okta" | "entra" | "sim"

    @property
    def ts(self) -> float:
        return self.timestamp.timestamp()

    @property
    def geo(self) -> Optional[GeoPoint]:
        if self.geo_lat is None or self.geo_lon is None:
            return None
        return GeoPoint(self.geo_country, self.geo_city,
                        self.geo_lat, self.geo_lon)

    @property
    def ip_subnet(self) -> str:
        """/24 bucket for IPv4 — cheap subnet-change comparison."""
        parts = self.client_ip.rsplit(".", 1)
        return parts[0] if len(parts) == 2 else self.client_ip


@dataclass(slots=True)
class Detection:
    """A single checker hit. Internal currency of the pipeline."""
    checker: str                            # "impossible_travel" | ...
    title: str
    severity: Severity
    confidence: float                       # 0..1
    evidence: dict
    mitre: str = ""

    @property
    def risk_points(self) -> float:
        return round(self.severity * self.confidence, 1)


@dataclass(slots=True)
class SessionState:
    """Live snapshot of one authenticated session.

    History windows are bounded deques -> memory-safe by construction.
    """
    session_id: str
    user_id: str
    current_ip: str = ""
    current_subnet: str = ""
    current_user_agent: str = ""
    current_geo: Optional[GeoPoint] = None
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_seen_wall: float = field(default_factory=time.time)
    last_success_geo: Optional[GeoPoint] = None
    last_success_ts: float = 0.0
    risk_score: float = 0.0
    history: Deque[AuthEvent] = field(
        default_factory=lambda: deque(maxlen=100))
    detections: list[Detection] = field(default_factory=list)
    responded_tiers: set = field(default_factory=set)

    def touch(self, ev: AuthEvent) -> None:
        """Update the live snapshot with the newest event."""
        self.last_seen = ev.ts
        self.last_seen_wall = time.time()   # eviction keys off arrival time
        self.history.append(ev)
        self.current_ip = ev.client_ip
        self.current_subnet = ev.ip_subnet
        self.current_user_agent = ev.user_agent
        if ev.geo:
            self.current_geo = ev.geo
        if ev.event_result is EventResult.SUCCESS and ev.geo:
            self.last_success_geo = ev.geo
            self.last_success_ts = ev.ts

    def add_detection(self, det: Detection) -> None:
        self.detections.append(det)
        self.risk_score = round(self.risk_score + det.risk_points, 1)

    @property
    def age_idle(self) -> float:
        return time.time() - self.last_seen_wall


@dataclass(slots=True)
class ITDRAlert:
    """High-fidelity alert: one or more correlated detections on a
    session whose aggregate risk crossed a threshold."""
    user_id: str
    session_id: str
    risk_score: float
    tier: str                               # "NOTABLE" | "CRITICAL"
    detections: list[Detection]
    client_ip: str
    user_agent: str
    created: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))
    id: int = field(default_factory=lambda: next(_alert_ids))

    def summary(self) -> str:
        checks = " + ".join(d.checker for d in self.detections)
        return (f"[{self.tier}] #{self.id} user={self.user_id} "
                f"session={self._short_session} risk={self.risk_score} "
                f"({checks})")

    @property
    def _short_session(self) -> str:
        """Abbreviate the session id without destroying it.

        IdP session ids are long opaque strings where a 12-char prefix
        is plenty to correlate against. Wazuh ids are `user@endpoint`,
        and truncating those to 12 chars cuts at the '@' — hiding the
        endpoint, which is the single most useful field on a host alert.
        """
        sid = self.session_id
        if len(sid) <= 28:
            return sid
        return sid[:28] + "…"
