"""
itdr.engine
===========
The stateful core. Thread-safe session store + sequential detection
pipeline + risk aggregation + alert emission.

Concurrency model
-----------------
One RLock guards the session store and per-user context. Checker logic
runs inside the lock (it's pure CPU, microseconds per event); responder
callbacks are invoked OUTSIDE the lock so a slow webhook can never stall
ingestion.

Memory model
------------
- SessionState.history is a bounded deque (maxlen=100).
- Sessions idle longer than `session_ttl` are evicted lazily: a prune
  pass runs at most every `prune_interval` seconds, amortized into
  process_event() -> no background thread required, no leak possible.

Risk model
----------
Each Detection contributes severity * confidence points to its session.
    risk >= notable_threshold  -> emit NOTABLE alert
    risk >= critical_threshold -> emit CRITICAL alert (SOAR eligible)
A session only emits once per tier (no alert spam), but keeps
accumulating score so escalation NOTABLE -> CRITICAL still fires.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from .detections import DEFAULT_CHECKERS, Checker
from .models import AuthEvent, ITDRAlert, SessionState
from .state import InMemoryStore, SessionStore

log = logging.getLogger("itdr.engine")

AlertCallback = Callable[[ITDRAlert], None]


class ITDREngine:
    def __init__(
        self,
        checkers: Optional[list[Checker]] = None,
        notable_threshold: float = 40.0,
        critical_threshold: float = 75.0,
        session_ttl: float = 1800.0,          # 30 min idle -> evict
        prune_interval: float = 60.0,
        on_alert: Optional[AlertCallback] = None,
        store: Optional[SessionStore] = None,
    ):
        self.checkers = checkers if checkers is not None else DEFAULT_CHECKERS
        self.notable_threshold = notable_threshold
        self.critical_threshold = critical_threshold
        self.session_ttl = session_ttl
        self.prune_interval = prune_interval
        self.on_alert = on_alert

        self._lock = threading.RLock()
        self.store: SessionStore = store or InMemoryStore(
            session_ttl=session_ttl, prune_interval=prune_interval)

        # observability counters
        self.stats = {"events": 0, "detections": 0, "alerts": 0,
                      "sessions_pruned": 0}

    # ------------------------------------------------------------ public --

    def process_event(self, ev: AuthEvent) -> list[ITDRAlert]:
        """Main entry point. Safe to call from multiple threads."""
        alerts: list[ITDRAlert] = []
        with self._lock:
            self.stats["events"] += 1
            pruned = self.store.maybe_prune()
            if pruned:
                self.stats["sessions_pruned"] += pruned
                log.info("pruned %d idle sessions", pruned)

            session = self.store.load(ev.session_id, ev.user_id)

            # 1) run the detection pipeline against PRE-update state
            for checker in self.checkers:
                det = checker.check(ev, session, self.store.ctx)
                if det:
                    session.add_detection(det)
                    self.stats["detections"] += 1
                    log.info("detection %s user=%s conf=%.2f (+%.1f risk)",
                             det.checker, ev.user_id, det.confidence,
                             det.risk_points)

            # 2) fold the event into the session snapshot
            session.touch(ev)

            # 3) threshold evaluation (once per tier per session)
            alert = self._evaluate(session)
            if alert:
                alerts.append(alert)

            # 4) persist the updated session
            self.store.save(session)

        # 4) fire callbacks OUTSIDE the lock
        for a in alerts:
            self.stats["alerts"] += 1
            if self.on_alert:
                try:
                    self.on_alert(a)
                except Exception:                       # noqa: BLE001
                    log.exception("alert callback failed")
        return alerts

    def get_session(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            s = self.store.load(session_id, "")
            return s if s.current_ip or s.history else None

    def active_sessions(self) -> int:
        with self._lock:
            return self.store.active_count()

    # ----------------------------------------------------------- private --

    def _evaluate(self, s: SessionState) -> Optional[ITDRAlert]:
        tier: Optional[str] = None
        if (s.risk_score >= self.critical_threshold
                and "CRITICAL" not in s.responded_tiers):
            tier = "CRITICAL"
        elif (s.risk_score >= self.notable_threshold
                and "NOTABLE" not in s.responded_tiers
                and "CRITICAL" not in s.responded_tiers):
            tier = "NOTABLE"
        if tier is None:
            return None
        s.responded_tiers.add(tier)
        return ITDRAlert(
            user_id=s.user_id,
            session_id=s.session_id,
            risk_score=s.risk_score,
            tier=tier,
            detections=list(s.detections),
            client_ip=s.current_ip,
            user_agent=s.current_user_agent,
        )
