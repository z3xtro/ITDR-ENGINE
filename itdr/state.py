"""
itdr.state
==========
Pluggable session-state backends. Fixes the "one process, in memory"
scale ceiling: the engine talks to a SessionStore interface, and you
choose the backend at construction time.

  InMemoryStore  -> single-process (default; zero dependencies)
  RedisStore     -> shared state across N engine workers behind a queue.
                    Session eviction is delegated to Redis key TTLs —
                    no pruning code needed at all.

Honest scaling note (documented, not hidden): RedisStore uses
read-modify-write per event without a distributed lock. Safe when
events are PARTITIONED BY USER across workers (e.g. Kafka keyed by
user_id — the standard deployment shape); concurrent writers on the
SAME user could race. A Lua-script/WATCH upgrade path exists if you
need unpartitioned workers.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional, Protocol

from .models import (AuthEvent, Detection, EventResult, EventType,
                     GeoPoint, SessionState, Severity)

# ------------------------------------------------------------ serializers --

def _event_to_dict(ev: AuthEvent) -> dict:
    return {
        "timestamp": ev.timestamp.isoformat(),
        "user_id": ev.user_id, "session_id": ev.session_id,
        "client_ip": ev.client_ip, "user_agent": ev.user_agent,
        "geo_country": ev.geo_country, "geo_city": ev.geo_city,
        "geo_lat": ev.geo_lat, "geo_lon": ev.geo_lon,
        "event_type": ev.event_type.value,
        "event_result": ev.event_result.value,
        "idp_source": ev.idp_source,
    }


def _event_from_dict(d: dict) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime.fromisoformat(d["timestamp"]),
        user_id=d["user_id"], session_id=d["session_id"],
        client_ip=d["client_ip"], user_agent=d["user_agent"],
        geo_country=d["geo_country"], geo_city=d["geo_city"],
        geo_lat=d.get("geo_lat"), geo_lon=d.get("geo_lon"),
        event_type=EventType(d["event_type"]),
        event_result=EventResult(d["event_result"]),
        idp_source=d.get("idp_source", "sim"),
    )


def _geo_to_dict(g: Optional[GeoPoint]) -> Optional[dict]:
    if g is None:
        return None
    return {"country": g.country, "city": g.city, "lat": g.lat, "lon": g.lon}


def _geo_from_dict(d: Optional[dict]) -> Optional[GeoPoint]:
    return GeoPoint(**d) if d else None


def session_to_json(s: SessionState) -> str:
    return json.dumps({
        "session_id": s.session_id, "user_id": s.user_id,
        "current_ip": s.current_ip, "current_subnet": s.current_subnet,
        "current_user_agent": s.current_user_agent,
        "current_geo": _geo_to_dict(s.current_geo),
        "created": s.created, "last_seen": s.last_seen,
        "last_seen_wall": s.last_seen_wall,
        "last_success_geo": _geo_to_dict(s.last_success_geo),
        "last_success_ts": s.last_success_ts,
        "risk_score": s.risk_score,
        "history": [_event_to_dict(e) for e in s.history],
        "detections": [{
            "checker": d.checker, "title": d.title,
            "severity": int(d.severity), "confidence": d.confidence,
            "evidence": d.evidence, "mitre": d.mitre,
        } for d in s.detections],
        "responded_tiers": sorted(s.responded_tiers),
    })


def session_from_json(raw: str) -> SessionState:
    d = json.loads(raw)
    s = SessionState(session_id=d["session_id"], user_id=d["user_id"])
    s.current_ip = d["current_ip"]
    s.current_subnet = d["current_subnet"]
    s.current_user_agent = d["current_user_agent"]
    s.current_geo = _geo_from_dict(d["current_geo"])
    s.created = d["created"]
    s.last_seen = d["last_seen"]
    s.last_seen_wall = d["last_seen_wall"]
    s.last_success_geo = _geo_from_dict(d["last_success_geo"])
    s.last_success_ts = d["last_success_ts"]
    s.risk_score = d["risk_score"]
    s.history = deque((_event_from_dict(e) for e in d["history"]),
                      maxlen=100)
    s.detections = [Detection(checker=x["checker"], title=x["title"],
                              severity=Severity(x["severity"]),
                              confidence=x["confidence"],
                              evidence=x["evidence"], mitre=x["mitre"])
                    for x in d["detections"]]
    s.responded_tiers = set(d["responded_tiers"])
    return s


# ------------------------------------------------------------ interfaces --

class UserContext(Protocol):
    """Cross-session per-user state the checkers need."""
    def record_mfa_fail(self, user: str, ts: float) -> None: ...
    def mfa_fails(self, user: str) -> list[float]: ...
    def clear_mfa_fails(self, user: str) -> None: ...
    def record_auth_fail(self, user: str, ts: float) -> None: ...
    def auth_fails(self, user: str) -> list[float]: ...
    def clear_auth_fails(self, user: str) -> None: ...
    def last_success(self, user: str) -> Optional[tuple[GeoPoint, float]]: ...
    def set_last_success(self, user: str, geo: GeoPoint,
                         ts: float) -> None: ...
    def record_session(self, user: str, session_id: str,
                       ts: float) -> None: ...
    def recent_sessions(self, user: str,
                        window: float) -> list[tuple[str, float]]: ...


class SessionStore(Protocol):
    ctx: UserContext
    def load(self, session_id: str, user_id: str) -> SessionState: ...
    def save(self, session: SessionState) -> None: ...
    def active_count(self) -> int: ...
    def maybe_prune(self) -> int: ...


# -------------------------------------------------------------- in-memory --

class _MemContext:
    def __init__(self):
        self._fails: dict[str, deque[float]] = {}
        self._auth_fails: dict[str, deque[float]] = {}
        self._last: dict[str, tuple[GeoPoint, float]] = {}
        self._sessions_seen: dict[str, deque] = {}

    def record_mfa_fail(self, user: str, ts: float) -> None:
        self._fails.setdefault(user, deque(maxlen=64)).append(ts)

    def mfa_fails(self, user: str) -> list[float]:
        return list(self._fails.get(user, ()))

    def clear_mfa_fails(self, user: str) -> None:
        self._fails.pop(user, None)

    def record_auth_fail(self, user: str, ts: float) -> None:
        self._auth_fails.setdefault(user, deque(maxlen=256)).append(ts)

    def auth_fails(self, user: str) -> list[float]:
        return list(self._auth_fails.get(user, ()))

    def clear_auth_fails(self, user: str) -> None:
        self._auth_fails.pop(user, None)

    def last_success(self, user: str):
        return self._last.get(user)

    def set_last_success(self, user: str, geo: GeoPoint, ts: float) -> None:
        self._last[user] = (geo, ts)

    def record_session(self, user: str, session_id: str, ts: float) -> None:
        self._sessions_seen.setdefault(user, deque(maxlen=64)) \
            .append((session_id, ts))

    def recent_sessions(self, user: str, window: float):
        import time as _t
        now = _t.time()
        return [(s, t) for s, t in self._sessions_seen.get(user, ())
                if now - t <= window]


class InMemoryStore:
    """Single-process store. Lock lives in the ENGINE (which wraps the
    whole read-check-write cycle), so this class stays lock-free."""

    def __init__(self, session_ttl: float = 1800.0,
                 prune_interval: float = 60.0):
        self.ctx = _MemContext()
        self.session_ttl = session_ttl
        self.prune_interval = prune_interval
        self._sessions: dict[str, SessionState] = {}
        self._last_prune = time.time()

    def load(self, session_id: str, user_id: str) -> SessionState:
        s = self._sessions.get(session_id)
        if s is None:
            s = SessionState(session_id=session_id, user_id=user_id)
            self._sessions[session_id] = s
        return s

    def save(self, session: SessionState) -> None:
        self._sessions[session.session_id] = session

    def active_count(self) -> int:
        return len(self._sessions)

    def maybe_prune(self) -> int:
        now = time.time()
        if now - self._last_prune < self.prune_interval:
            return 0
        self._last_prune = now
        dead = [sid for sid, s in self._sessions.items()
                if s.age_idle > self.session_ttl]
        for sid in dead:
            del self._sessions[sid]
        return len(dead)


# ------------------------------------------------------------------ redis --

class _RedisContext:
    def __init__(self, r, prefix: str, ttl: int):
        self.r, self.prefix, self.ttl = r, prefix, ttl

    def _fk(self, user: str) -> str:
        return f"{self.prefix}:mfa:{user}"

    def _afk(self, user: str) -> str:
        return f"{self.prefix}:authfail:{user}"

    def _push_capped(self, key: str, ts: float, cap: int) -> None:
        pipe = self.r.pipeline()
        pipe.rpush(key, ts)
        pipe.ltrim(key, -cap, -1)
        pipe.expire(key, self.ttl)
        pipe.execute()

    def record_mfa_fail(self, user: str, ts: float) -> None:
        self._push_capped(self._fk(user), ts, 64)

    def mfa_fails(self, user: str) -> list[float]:
        return [float(x) for x in self.r.lrange(self._fk(user), 0, -1)]

    def clear_mfa_fails(self, user: str) -> None:
        self.r.delete(self._fk(user))

    def record_auth_fail(self, user: str, ts: float) -> None:
        # Brute-force bursts are far denser than MFA pushes, so this
        # list gets a deeper cap.
        self._push_capped(self._afk(user), ts, 256)

    def auth_fails(self, user: str) -> list[float]:
        return [float(x) for x in self.r.lrange(self._afk(user), 0, -1)]

    def clear_auth_fails(self, user: str) -> None:
        self.r.delete(self._afk(user))

    def last_success(self, user: str):
        raw = self.r.get(f"{self.prefix}:last:{user}")
        if not raw:
            return None
        d = json.loads(raw)
        return (GeoPoint(d["country"], d["city"], d["lat"], d["lon"]),
                d["ts"])

    def record_session(self, user: str, session_id: str, ts: float) -> None:
        k = f"{self.prefix}:usersess:{user}"
        pipe = self.r.pipeline()
        pipe.rpush(k, json.dumps([session_id, ts]))
        pipe.ltrim(k, -64, -1)
        pipe.expire(k, self.ttl)
        pipe.execute()

    def recent_sessions(self, user: str, window: float):
        import time as _t
        now = _t.time()
        out = []
        for raw in self.r.lrange(f"{self.prefix}:usersess:{user}", 0, -1):
            sid, ts = json.loads(raw)
            if now - ts <= window:
                out.append((sid, ts))
        return out

    def set_last_success(self, user: str, geo: GeoPoint, ts: float) -> None:
        self.r.set(f"{self.prefix}:last:{user}",
                   json.dumps({"country": geo.country, "city": geo.city,
                               "lat": geo.lat, "lon": geo.lon, "ts": ts}),
                   ex=self.ttl)


class RedisStore:
    """Shared state across N workers. Eviction = Redis key TTL (refreshed
    on every save), so idle sessions disappear with zero pruning code."""

    def __init__(self, url: str = "redis://localhost:6379/0",
                 session_ttl: int = 1800, prefix: str = "itdr",
                 client=None):
        import redis
        self.r = client or redis.Redis.from_url(url, decode_responses=True)
        self.prefix = prefix
        self.session_ttl = session_ttl
        self.ctx = _RedisContext(self.r, prefix, session_ttl)

    def _sk(self, session_id: str) -> str:
        return f"{self.prefix}:sess:{session_id}"

    def load(self, session_id: str, user_id: str) -> SessionState:
        raw = self.r.get(self._sk(session_id))
        if raw:
            return session_from_json(raw)
        return SessionState(session_id=session_id, user_id=user_id)

    def save(self, session: SessionState) -> None:
        self.r.set(self._sk(session.session_id),
                   session_to_json(session), ex=self.session_ttl)

    def active_count(self) -> int:
        return sum(1 for _ in self.r.scan_iter(f"{self.prefix}:sess:*"))

    def maybe_prune(self) -> int:
        return 0        # Redis TTLs handle eviction natively
