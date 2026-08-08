"""
itdr.wazuh_detections
=====================
Detections designed for HOST authentication telemetry.

Why this module exists
----------------------
The checkers in `itdr.detections` were built for IdP telemetry, and two
of the three headline ones cannot fire on Wazuh data at all:

  MFAFatigueChecker      needs EventType.MFA_CHALLENGE. Host auth logs
                         have no MFA concept — sshd and PAM never emit it.
  ImpossibleTravelChecker needs geo coordinates. Wazuh only populates
                         GeoLocation when GeoIP is configured on the
                         manager (off by default), and it never resolves
                         for RFC1918 traffic, which is most of a lab.

Mapping Wazuh into the existing pipeline and stopping there yields a
system that ingests real events and detects almost nothing. These
checkers cover the attacks host telemetry *can* actually evidence.

  SSHBruteForceSuccess   fail burst then success — credential compromise
  NewSourceIP            first time this account authenticated from here
  LateralMovement        one account, several endpoints, short window
  PrivilegeEscalation    sudo/su to root soon after a suspicious login
  OffHoursAccess         interactive auth outside working hours

State model
-----------
These correlate across sessions *and* across hosts, which the shared
`UserContext` protocol doesn't express (it's keyed by user alone, and
the Redis implementation mirrors that schema). Rather than widen a
protocol two backends implement, each checker owns bounded internal
state — every window is a deque with a maxlen, so memory is capped by
construction.

The tradeoff, stated plainly: this state is per-process, so with several
engine replicas behind one Wazuh manager each replica sees only its own
slice and correlation weakens. Single-process deployments — which is
every lab and most small SOCs — are unaffected. Moving these windows
into `UserContext` is the fix when it matters.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Deque, Optional

from .models import (AuthEvent, Detection, EventResult, EventType,
                     SessionState, Severity)
from .state import UserContext


def _agent_of(ev: AuthEvent) -> str:
    """Recover the endpoint from the synthetic session id
    (``wazuh:{user}@{agent}``); '?' for non-Wazuh events."""
    if "@" not in ev.session_id:
        return "?"
    return ev.session_id.rsplit("@", 1)[1]


def _prune(window: Deque[tuple], now: float, horizon: float) -> None:
    while window and now - window[0][0] > horizon:
        window.popleft()


# ------------------------------------------------------------------------
class SSHBruteForceSuccessChecker:
    """Failed-password burst followed by a success from the same IP.

    This is the host analogue of MFA-fatigue capitulation, and it is the
    single highest-fidelity signal available in SSH logs: brute forcing
    is noisy and common, but brute forcing that *succeeds* is a
    compromised credential, full stop.

    Correlating on (user, source IP) rather than user alone is what keeps
    this precise. A user fumbling their own password from their laptop
    and then getting in is the same event shape; the difference is that
    an attacker's burst is faster and larger, so the thresholds are set
    above human-typo volume rather than trying to distinguish intent.
    """
    name = "ssh_bruteforce_success"

    def __init__(self, fail_count: int = 5, window_s: float = 300.0,
                 success_grace: float = 120.0):
        self.fail_count = fail_count
        self.window_s = window_s
        self.success_grace = success_grace
        # (user, ip) -> deque of fail timestamps
        self._fails: dict[tuple[str, str], Deque[tuple]] = {}

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_type not in (EventType.LOGIN,):
            return None
        key = (ev.user_id, ev.client_ip)

        if ev.event_result is EventResult.FAIL:
            w = self._fails.setdefault(key, deque(maxlen=256))
            w.append((ev.ts,))
            _prune(w, ev.ts, self.window_s)
            return None

        # SUCCESS: did a burst just precede it from this same source?
        w = self._fails.get(key)
        if not w:
            return None
        _prune(w, ev.ts, self.window_s)
        fails = len(w)
        if fails < self.fail_count:
            return None
        gap = ev.ts - w[-1][0]
        if gap > self.success_grace:
            return None

        self._fails.pop(key, None)      # consumed; don't re-alert
        # 5 fails -> 0.75, 20+ -> 1.0
        confidence = min(0.75 + (fails - self.fail_count) * 0.017, 1.0)
        return Detection(
            checker=self.name,
            title="Successful login after failed-password burst",
            severity=Severity.CRITICAL,
            confidence=round(confidence, 2),
            mitre="T1110",
            evidence={
                "user": ev.user_id,
                "source_ip": ev.client_ip,
                "endpoint": _agent_of(ev),
                "failed_attempts": fails,
                "window_s": self.window_s,
                "seconds_to_success": round(gap, 1),
                "program": ev.user_agent,
            },
        )


# ------------------------------------------------------------------------
class NewSourceIPChecker:
    """First successful authentication for this account from this IP.

    Low severity on its own — new laptops, new coffee shops, DHCP churn.
    It earns its place by *compounding*: paired with a brute-force
    success or an off-hours login it pushes a session over the line,
    which is exactly the correlation the risk model is built around.

    A learning period suppresses the cold-start problem: until an account
    has `learn_after` observed sources, every IP is "new" and alerting
    would be pure noise.
    """
    name = "new_source_ip"

    def __init__(self, learn_after: int = 3, max_tracked: int = 32):
        self.learn_after = learn_after
        self.max_tracked = max_tracked
        self._seen: dict[str, Deque[str]] = {}

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_result is not EventResult.SUCCESS:
            return None
        if ev.event_type not in (EventType.LOGIN,):
            return None
        if ev.client_ip in ("0.0.0.0", ""):     # console/local login
            return None

        seen = self._seen.setdefault(ev.user_id, deque(maxlen=self.max_tracked))
        known = ev.client_ip in seen
        count_before = len(seen)
        if not known:
            seen.append(ev.client_ip)

        if known or count_before < self.learn_after:
            return None

        return Detection(
            checker=self.name,
            title="First-seen source IP for this account",
            severity=Severity.LOW,
            confidence=0.6,
            mitre="T1078",
            evidence={
                "user": ev.user_id,
                "new_ip": ev.client_ip,
                "endpoint": _agent_of(ev),
                "known_sources": count_before,
            },
        )


# ------------------------------------------------------------------------
class LateralMovementChecker:
    """One account authenticating to several distinct endpoints fast.

    A human uses one or two machines. A credential sweeping a fleet is
    either an attacker moving laterally or automation that should be
    running as a service account — both worth surfacing.

    Only successes count: failed attempts across many hosts are a
    scanner, which the brute-force detector already owns.
    """
    name = "lateral_movement"

    def __init__(self, host_threshold: int = 3, window_s: float = 600.0):
        self.host_threshold = host_threshold
        self.window_s = window_s
        self._hosts: dict[str, Deque[tuple]] = {}

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_result is not EventResult.SUCCESS:
            return None
        if ev.event_type not in (EventType.LOGIN,):
            return None

        agent = _agent_of(ev)
        w = self._hosts.setdefault(ev.user_id, deque(maxlen=128))
        w.append((ev.ts, agent))
        _prune(w, ev.ts, self.window_s)

        distinct = {a for _, a in w}
        if len(distinct) < self.host_threshold:
            return None

        # Fire once per escalation step, not on every event thereafter.
        if len(distinct) > self.host_threshold:
            return None

        return Detection(
            checker=self.name,
            title="Account authenticated to multiple endpoints rapidly",
            severity=Severity.HIGH,
            confidence=0.7,
            mitre="T1021",
            evidence={
                "user": ev.user_id,
                "endpoints": sorted(distinct),
                "endpoint_count": len(distinct),
                "window_s": self.window_s,
                "source_ip": ev.client_ip,
            },
        )


# ------------------------------------------------------------------------
class PrivilegeEscalationChecker:
    """Root escalation shortly after that account authenticated.

    sudo is completely routine, so this deliberately does NOT alert on
    escalation by itself. It fires only when the escalation follows a
    *recent remote* login — the sequence "got in from the network, then
    immediately became root" is the tail end of a compromise, whereas an
    admin who has been on the box for an hour is just working.
    """
    name = "privilege_escalation"

    def __init__(self, window_s: float = 300.0):
        self.window_s = window_s
        self._recent_login: dict[tuple[str, str], tuple[float, str]] = {}

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        agent = _agent_of(ev)
        key = (ev.user_id, agent)

        if (ev.event_type is EventType.LOGIN
                and ev.event_result is EventResult.SUCCESS):
            # Only remote logins arm this; console logins have no source.
            if ev.client_ip not in ("0.0.0.0", ""):
                self._recent_login[key] = (ev.ts, ev.client_ip)
            return None

        # sudo/su map to API_ACCESS (see itdr.wazuh._RULE_MAP)
        if not (ev.event_type is EventType.API_ACCESS
                and ev.event_result is EventResult.SUCCESS):
            return None

        armed = self._recent_login.get(key)
        if not armed:
            return None
        login_ts, login_ip = armed
        gap = ev.ts - login_ts
        if gap < 0 or gap > self.window_s:
            return None

        self._recent_login.pop(key, None)       # one alert per login
        return Detection(
            checker=self.name,
            title="Privilege escalation soon after remote login",
            severity=Severity.HIGH,
            confidence=0.65,
            mitre="T1548",
            evidence={
                "user": ev.user_id,
                "endpoint": agent,
                "login_source_ip": login_ip,
                "seconds_after_login": round(gap, 1),
                "program": ev.user_agent,
            },
        )


# ------------------------------------------------------------------------
class OffHoursAccessChecker:
    """Interactive authentication outside working hours.

    Weak alone and jurisdiction-dependent, so it carries low confidence
    and exists to compound with stronger signals. Hours are evaluated in
    the event's own timezone — Wazuh preserves the agent's UTC offset, so
    a laptop in IST is judged against IST business hours, not the
    server's.
    """
    name = "off_hours_access"

    def __init__(self, start_hour: int = 8, end_hour: int = 20,
                 weekend_is_off: bool = True, max_tracked: int = 512):
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.weekend_is_off = weekend_is_off
        # (user, endpoint, local date) already reported. Without this the
        # checker fires on EVERY login, and since a night shift is all
        # off-hours it stacks ~11 risk points per login until a single
        # weak signal crosses NOTABLE by itself. Observed on real data:
        # nine logins produced nine identical detections and a spurious
        # alert. Working outside business hours is one fact about a
        # night, not one fact per login.
        self._fired: Deque[tuple] = deque(maxlen=max_tracked)

    def check(self, ev: AuthEvent, session: SessionState,
              ctx: UserContext) -> Optional[Detection]:
        if ev.event_result is not EventResult.SUCCESS:
            return None
        if ev.event_type is not EventType.LOGIN:
            return None

        hour = ev.timestamp.hour
        weekday = ev.timestamp.weekday()        # 0=Mon .. 6=Sun
        off_hour = hour < self.start_hour or hour >= self.end_hour
        off_day = self.weekend_is_off and weekday >= 5
        if not (off_hour or off_day):
            return None

        key = (ev.user_id, _agent_of(ev), ev.timestamp.date().isoformat())
        if key in self._fired:
            return None
        self._fired.append(key)

        return Detection(
            checker=self.name,
            title="Authentication outside working hours",
            severity=Severity.LOW,
            confidence=0.45 if off_hour else 0.35,
            mitre="T1078",
            evidence={
                "user": ev.user_id,
                "local_time": ev.timestamp.strftime("%a %H:%M %Z").strip(),
                "endpoint": _agent_of(ev),
                "source_ip": ev.client_ip,
                "business_hours": f"{self.start_hour:02d}:00-"
                                  f"{self.end_hour:02d}:00",
            },
        )


# ------------------------------------------------------------------------

def wazuh_checkers() -> list:
    """The host-native set, fresh instances (they carry state)."""
    return [
        SSHBruteForceSuccessChecker(),
        NewSourceIPChecker(),
        LateralMovementChecker(),
        PrivilegeEscalationChecker(),
        OffHoursAccessChecker(),
    ]


def combined_checkers() -> list:
    """Host-native checkers PLUS the IdP-oriented ones.

    The originals stay in the chain deliberately: impossible travel and
    Tor access do fire on Wazuh data once GeoIP is enabled and the source
    is internet-facing, and the auth-failure-burst checker is source
    agnostic. They simply abstain when the telemetry can't support them.
    """
    from .detections import DEFAULT_CHECKERS
    return wazuh_checkers() + list(DEFAULT_CHECKERS)
