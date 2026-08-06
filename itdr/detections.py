"""
itdr.detections
===============
Real-time telemetry checkers. Each implements:

    check(event: AuthEvent, session: SessionState,
          engine_ctx: EngineContext) -> Optional[Detection]

Checkers are STATELESS where possible; per-user cross-session state
(needed by MFA fatigue) lives in EngineContext, owned by the engine,
so the whole pipeline stays trivially testable.

The math
--------
1. Impossible Travel
     velocity = haversine(geo_prev, geo_now) / Δt
     flag if velocity > 800 km/h (subsonic ceiling for legit travel).
     Confidence scales with how absurd the velocity is, capped at 1.0.

2. Session Context Mutation
     For an already-established session_id:
       UA string changed        -> strong token-theft indicator
       IP /24 subnet changed    -> medium indicator (CGNAT/mobile can
                                   legitimately roam, so lower confidence)
     Both mutating at once -> confidence ~1.0.

3. MFA Fatigue (velocity anomaly)
     Sliding window of MFA FAILs per user (cross-session, because the
     attacker's pushes and the victim's approval can ride different
     session ids). If >= `fail_count` fails within `fail_window` seconds
     and a SUCCESS lands within `success_grace` seconds of the last
     fail -> classic push-bombing capitulation pattern.
"""

from __future__ import annotations

import math
from typing import Optional, Protocol

from .models import (AuthEvent, Detection, EventResult, EventType,
                     GeoPoint, SessionState, Severity)
from .enrichment import DEFAULT_ENRICHER
from .state import UserContext, _MemContext

EARTH_RADIUS_KM = 6371.0


def EngineContext() -> UserContext:
    """Backwards-compatible constructor: a fresh in-memory user context."""
    return _MemContext()


def haversine_km(a: GeoPoint, b: GeoPoint) -> float:
    """Great-circle distance between two lat/lon points in km."""
    la1, lo1, la2, lo2 = map(math.radians, (a.lat, a.lon, b.lat, b.lon))
    dlat, dlon = la2 - la1, lo2 - lo1
    h = (math.sin(dlat / 2) ** 2
         + math.cos(la1) * math.cos(la2) * math.sin(dlon / 2) ** 2)
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(h))


class Checker(Protocol):
    name: str
    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]: ...


# ------------------------------------------------------------------------
class ImpossibleTravelChecker:
    name = "impossible_travel"

    def __init__(self, max_kmh: float = 800.0, min_distance_km: float = 50.0,
                 min_elapsed_s: float = 20.0):
        self.max_kmh = max_kmh
        self.min_distance_km = min_distance_km   # ignore geo-IP jitter
        self.min_elapsed_s = min_elapsed_s       # reject same-action records

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_result is not EventResult.SUCCESS or ev.geo is None:
            return None

        # A login whose source IP is cloud/datacenter space is almost
        # always an IdP backend or integration record (Okta on AWS
        # us-west-2 → "Boardman, US"), NOT the human. Don't let it set or
        # trip the travel baseline — it produces light-speed false
        # positives against the user's real location.
        rep = DEFAULT_ENRICHER.enrich(ev.client_ip)
        if rep.is_hosting:
            return None

        prev = ctx.last_success(ev.user_id)
        # Record the new success regardless of verdict.
        ctx.set_last_success(ev.user_id, ev.geo, ev.ts)
        if prev is None:
            return None

        prev_geo, prev_ts = prev
        elapsed_s = ev.ts - prev_ts
        # Two records at (nearly) the same instant = one logical action
        # emitting multiple System Log entries, not travel. Physically,
        # no human relocates in seconds; treat as an artifact.
        if elapsed_s < self.min_elapsed_s:
            return None
        dt_h = max(elapsed_s / 3600.0, 1e-6)
        dist = haversine_km(prev_geo, ev.geo)
        if dist < self.min_distance_km:
            return None
        velocity = dist / dt_h
        if velocity <= self.max_kmh:
            return None

        # Confidence: 800 km/h -> 0.5, >= 4000 km/h -> 1.0
        confidence = min(0.5 + (velocity - self.max_kmh) / 6400.0, 1.0)
        confidence = min(confidence + (0.15 if rep.is_tor else 0.0), 1.0)
        return Detection(
            checker=self.name,
            title="Impossible travel between successful logins",
            severity=Severity.HIGH,
            confidence=round(confidence, 2),
            mitre="T1078",
            evidence={
                "from": f"{prev_geo.city}, {prev_geo.country}",
                "to": f"{ev.geo.city}, {ev.geo.country}",
                "distance_km": round(dist, 1),
                "elapsed_min": round(dt_h * 60, 1),
                "required_velocity_kmh": round(velocity, 0),
                "threshold_kmh": self.max_kmh,
                "ip_reputation": rep.label,
            },
        )


# ------------------------------------------------------------------------
class SessionMutationChecker:
    name = "session_mutation"

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        # Only meaningful once the session has an established fingerprint.
        if not session.current_user_agent or len(session.history) == 0:
            return None
        # A brand-new login legitimately (re)sets context; mutations only
        # matter on mid-session activity (token refresh / API access).
        if ev.event_type in (EventType.LOGIN, EventType.MFA_CHALLENGE):
            return None

        ua_changed = ev.user_agent != session.current_user_agent
        subnet_changed = ev.ip_subnet != session.current_subnet
        if not (ua_changed or subnet_changed):
            return None

        if ua_changed and subnet_changed:
            confidence, sev = 0.95, Severity.CRITICAL
        elif ua_changed:
            confidence, sev = 0.85, Severity.HIGH
        else:  # subnet only — mobile roaming / CGNAT happens
            confidence, sev = 0.55, Severity.MEDIUM

        return Detection(
            checker=self.name,
            title="Mid-session context mutation (possible token theft)",
            severity=sev,
            confidence=confidence,
            mitre="T1550.004",
            evidence={
                "session_id": session.session_id,
                "ua_before": session.current_user_agent,
                "ua_after": ev.user_agent,
                "ua_changed": ua_changed,
                "subnet_before": session.current_subnet,
                "subnet_after": ev.ip_subnet,
                "subnet_changed": subnet_changed,
                "event_type": ev.event_type.value,
            },
        )


# ------------------------------------------------------------------------
class MFAFatigueChecker:
    name = "mfa_fatigue"

    def __init__(self, fail_count: int = 5, fail_window: float = 120.0,
                 success_grace: float = 90.0):
        self.fail_count = fail_count
        self.fail_window = fail_window
        self.success_grace = success_grace

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_type is not EventType.MFA_CHALLENGE:
            # A successful LOGIN right after a fail-burst also counts as
            # the capitulation step.
            if not (ev.event_type is EventType.LOGIN
                    and ev.event_result is EventResult.SUCCESS):
                return None

        now = ev.ts

        if ev.event_result is EventResult.FAIL:
            ctx.record_mfa_fail(ev.user_id, now)
            return None

        # SUCCESS path: was there a qualifying burst just before this?
        fails = ctx.mfa_fails(ev.user_id)
        recent = [t for t in fails if now - t <= self.fail_window
                  + self.success_grace]
        if not recent:
            return None
        burst = [t for t in recent if recent[-1] - t <= self.fail_window]
        if len(burst) < self.fail_count:
            return None
        if now - recent[-1] > self.success_grace:
            return None

        ctx.clear_mfa_fails(ev.user_id)  # consume; no re-fire on next success
        return Detection(
            checker=self.name,
            title="MFA fatigue: rejection burst followed by acceptance",
            severity=Severity.HIGH,
            confidence=round(
                min(0.6 + 0.08 * (len(burst) - self.fail_count), 1.0), 2),
            mitre="T1621",
            evidence={
                "fail_count": len(burst),
                "window_s": self.fail_window,
                "burst_span_s": round(burst[-1] - burst[0], 1),
                "success_delay_s": round(now - recent[-1], 1),
            },
        )


# ------------------------------------------------------------------------
class TorAccessChecker:
    """Standalone TOR/anonymized-infrastructure access detection. Even a
    single successful login from a TOR exit is worth surfacing (T1090)."""
    name = "tor_access"

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_result is not EventResult.SUCCESS:
            return None
        rep = DEFAULT_ENRICHER.enrich(ev.client_ip)
        if not rep.is_tor:
            return None
        return Detection(
            checker=self.name,
            title="Access from TOR exit node",
            severity=Severity.MEDIUM,
            confidence=0.7,
            mitre="T1090.003",
            evidence={"ip": ev.client_ip, "reputation": rep.label,
                      "user": ev.user_id},
        )


# ------------------------------------------------------------------------
class RefreshTokenReplayChecker:
    """Refresh/token events on an established session from a DIFFERENT IP
    than the session's origin indicate a stolen refresh token being
    replayed from attacker infrastructure (T1550.004 / OAuth abuse)."""
    name = "refresh_replay"

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_type is not EventType.TOKEN_REFRESH:
            return None
        if not session.current_ip or len(session.history) == 0:
            return None
        if ev.client_ip == session.current_ip:
            return None
        rep = DEFAULT_ENRICHER.enrich(ev.client_ip)
        conf = 0.7 + (0.2 if (rep.is_tor or rep.is_hosting) else 0.0)
        return Detection(
            checker=self.name,
            title="Refresh token replay from new origin",
            severity=Severity.HIGH,
            confidence=round(min(conf, 1.0), 2),
            mitre="T1550.004",
            evidence={"session_ip": session.current_ip,
                      "refresh_ip": ev.client_ip,
                      "ip_reputation": rep.label,
                      "session_id": session.session_id},
        )


# ------------------------------------------------------------------------
class MassSessionChecker:
    """Many NEW sessions for one user in a short window = session-flooding
    / token minting after credential compromise (T1136-adjacent)."""
    name = "mass_session"

    def __init__(self, count: int = 5, window: float = 120.0):
        self.count = count
        self.window = window

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_type not in (EventType.LOGIN, EventType.TOKEN_REFRESH):
            return None
        if ev.event_result is not EventResult.SUCCESS:
            return None
        ctx.record_session(ev.user_id, ev.session_id, ev.ts)
        recent = ctx.recent_sessions(ev.user_id, self.window)
        distinct = {s for s, _ in recent}
        if len(distinct) < self.count:
            return None
        return Detection(
            checker=self.name,
            title="Mass session creation burst",
            severity=Severity.HIGH,
            confidence=round(min(0.6 + 0.05 * (len(distinct) - self.count),
                                 1.0), 2),
            mitre="T1136",
            evidence={"distinct_sessions": len(distinct),
                      "window_s": self.window, "user": ev.user_id},
        )


# ------------------------------------------------------------------------
class AuthFailureBurstChecker:
    """Failed-login burst followed by a success — credential stuffing or
    password guessing that finally landed (T1110).

    This is the detection host telemetry can actually feed. Wazuh ships
    sshd/PAM/Windows Security records, which are LOGIN success/fail and
    nothing else: there are no token-refresh or API-access events for
    SessionMutation to compare, and no MFA challenge records for
    MFAFatigue. Without this checker, a Wazuh-sourced session tops out
    at impossible-travel's 70 points and can never reach the CRITICAL
    containment tier.

    Failures are tracked per user across sessions, because a brute-force
    run against one account produces a new session key per attempt on
    some sources.
    """
    name = "auth_failure_burst"

    def __init__(self, fail_count: int = 8, fail_window: float = 300.0,
                 success_grace: float = 120.0):
        self.fail_count = fail_count
        self.fail_window = fail_window
        self.success_grace = success_grace

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_type is not EventType.LOGIN:
            return None

        if ev.event_result is EventResult.FAIL:
            ctx.record_auth_fail(ev.user_id, ev.ts)
            return None

        fails = ctx.auth_fails(ev.user_id)
        if not fails:
            return None
        # The burst must be recent AND dense: a slow trickle of typos
        # across a workday is not an attack.
        burst = [t for t in fails if fails[-1] - t <= self.fail_window]
        if len(burst) < self.fail_count:
            return None
        if ev.ts - fails[-1] > self.success_grace:
            return None

        ctx.clear_auth_fails(ev.user_id)   # consume; one alert per burst
        span = burst[-1] - burst[0]
        # Machine-speed guessing (many attempts, tiny span) is a stronger
        # signal than a user fumbling a password eight times.
        rate = len(burst) / max(span, 1.0)
        confidence = min(0.55 + 0.05 * (len(burst) - self.fail_count)
                         + (0.2 if rate > 0.5 else 0.0), 1.0)
        return Detection(
            checker=self.name,
            title="Failed-login burst followed by successful authentication",
            severity=Severity.HIGH,
            confidence=round(confidence, 2),
            mitre="T1110",
            evidence={
                "fail_count": len(burst),
                "window_s": self.fail_window,
                "burst_span_s": round(span, 1),
                "attempts_per_s": round(rate, 2),
                "success_delay_s": round(ev.ts - fails[-1], 1),
                "source_ip": ev.client_ip,
            },
        )


DEFAULT_CHECKERS: list = [
    ImpossibleTravelChecker(),
    AuthFailureBurstChecker(),
    SessionMutationChecker(),
    MFAFatigueChecker(),
    TorAccessChecker(),
    RefreshTokenReplayChecker(),
    MassSessionChecker(),
]
