"""
itdr.thehive
============
TheHive 5 SOAR integration: turns the containment responder's actions
into a full case-management pipeline.

    ITDRAlert ──▶ TheHive alert (always, with observables)
        │
        └─ CRITICAL tier ──▶ promote to case
                               ├─ "Automated containment" task
                               │     └─ one task log per playbook action
                               └─ analyst disposition:
                                     false positive -> close case FP
                                     (rollback hook in itdr.enforcement)

Design rules
------------
- Pure builder (`alert_from_itdr`) separated from transport, same
  pattern as itdr.pollers — unit-testable without a server.
- The bridge NEVER raises into the engine: a dead TheHive must not
  stall ingestion or containment. Failures are logged and counted.
- Deduplication rides on TheHive's (type, source, sourceRef) unique
  constraint; a replayed alert is a logged no-op.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from .models import ITDRAlert

log = logging.getLogger("itdr.thehive")

try:
    import requests
    _REQUESTS = True
except ImportError:                                    # pragma: no cover
    _REQUESTS = False

_RETRY_STATUS = {429, 500, 502, 503, 504}

# ITDR tier -> TheHive severity (1 low / 2 medium / 3 high / 4 critical)
_SEVERITY = {"NOTABLE": 2, "CRITICAL": 3}


def alert_from_itdr(a: ITDRAlert) -> dict:
    """ITDRAlert -> TheHive v1 alert payload. Pure; fixture-testable."""
    lines = [
        f"**Session risk {a.risk_score}** — tier {a.tier}",
        "",
        "| Detection | Severity | Confidence | MITRE |",
        "|---|---|---|---|",
    ]
    tags = {"itdr", f"tier:{a.tier.lower()}"}
    for d in a.detections:
        lines.append(f"| {d.title} | {d.severity.name} "
                     f"| {d.confidence:.2f} | {d.mitre or '-'} |")
        tags.add(d.checker)
        if d.mitre:
            tags.add(d.mitre)
    lines += ["",
              f"- user: `{a.user_id}`",
              f"- session: `{a.session_id}`",
              f"- source IP: `{a.client_ip}`"]

    observables = []
    if a.client_ip and a.client_ip != "0.0.0.0":
        observables.append({"dataType": "ip", "data": a.client_ip,
                            "message": "session source IP",
                            "tags": ["itdr"]})
    if a.user_agent:
        observables.append({"dataType": "user-agent",
                            "data": a.user_agent,
                            "message": "session user agent",
                            "tags": ["itdr"]})
    observables.append({
        "dataType": "mail" if "@" in a.user_id else "other",
        "data": a.user_id,
        "message": "targeted identity",
        "tags": ["itdr", "identity"]})

    return {
        "type": "itdr-session-risk",
        "source": "itdr-engine",
        # sourceRef must be unique per alert -> engine alert id +
        # session key makes replays collide (= dedup) instead of duping.
        "sourceRef": f"itdr-{a.id}-{a.session_id}",
        "title": f"[ITDR/{a.tier}] {a.user_id}: "
                 + " + ".join(d.checker for d in a.detections),
        "description": "\n".join(lines),
        "severity": _SEVERITY.get(a.tier, 2),
        "tags": sorted(tags),
        "observables": observables,
        "date": int(a.created.timestamp() * 1000),
    }


# --------------------------------------------------------------- client --

@dataclass
class TheHiveConfig:
    url: str
    api_key: str
    verify_tls: bool = True
    timeout: float = 30.0


class TheHiveClient:
    """Minimal TheHive 5 (v1 API) client. Bearer auth, retry with
    backoff on transient faults. `session` is injectable for tests."""

    def __init__(self, config: TheHiveConfig, session=None):
        if session is None and not _REQUESTS:
            raise RuntimeError("pip install requests")
        self.cfg = config
        self.base = config.url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, json_body: dict | None = None,
                 max_attempts: int = 4):
        url = f"{self.base}/api/v1{path}"
        delay = 1.0
        for attempt in range(1, max_attempts + 1):
            resp = self.session.request(
                method, url, json=json_body,
                timeout=self.cfg.timeout, verify=self.cfg.verify_tls)
            if resp.status_code in _RETRY_STATUS and attempt < max_attempts:
                log.warning("%s %s -> %d (retry %d/%d)", method, path,
                            resp.status_code, attempt, max_attempts)
                time.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        raise RuntimeError("unreachable")               # pragma: no cover

    # -- API surface the bridge needs ----------------------------------

    def create_alert(self, payload: dict) -> dict:
        return self._request("POST", "/alert", payload)

    def promote_to_case(self, alert_id: str) -> dict:
        return self._request("POST", f"/alert/{alert_id}/case", {})

    def create_case_task(self, case_id: str, title: str,
                         group: str = "containment",
                         description: str = "") -> dict:
        return self._request("POST", f"/case/{case_id}/task",
                             {"title": title, "group": group,
                              "description": description,
                              "status": "InProgress"})

    def add_task_log(self, task_id: str, message: str) -> dict:
        return self._request("POST", f"/task/{task_id}/log",
                             {"message": message})

    def complete_task(self, task_id: str) -> dict:
        return self._request("PATCH", f"/task/{task_id}",
                             {"status": "Completed"})

    def close_case(self, case_id: str, status: str = "TruePositive",
                   summary: str = "") -> dict:
        return self._request("PATCH", f"/case/{case_id}",
                             {"status": status, "summary": summary})


# --------------------------------------------------------------- bridge --

class TheHiveBridge:
    """Consumes ITDRAlerts after the SOARResponder has acted and mirrors
    everything into TheHive. Case management only — containment already
    happened (or was dry-run-narrated) in the responder; the bridge's
    job is to make that auditable and analyst-actionable."""

    def __init__(self, client: TheHiveClient):
        self.client = client
        # session_id/alert_id -> TheHive case id, for FP dispositions
        self.cases: dict[int, str] = {}
        self.stats = {"alerts": 0, "cases": 0, "errors": 0}

    def record(self, alert: ITDRAlert,
               containment_actions: list[str] | None = None) -> Optional[str]:
        """Create the TheHive alert; on CRITICAL, promote to a case and
        log the containment playbook. Returns the case id (if any).
        Never raises — SOAR bookkeeping must not break detection."""
        try:
            created = self.client.create_alert(alert_from_itdr(alert))
            self.stats["alerts"] += 1
        except Exception as e:                          # noqa: BLE001
            # 400 on a duplicate sourceRef = already recorded (dedup).
            self.stats["errors"] += 1
            log.warning("thehive alert create failed for #%d: %s",
                        alert.id, e)
            return None

        if alert.tier != "CRITICAL":
            return None

        try:
            case = self.client.promote_to_case(created["_id"])
            case_id = case["_id"]
            self.cases[alert.id] = case_id
            self.stats["cases"] += 1

            task = self.client.create_case_task(
                case_id, "Automated containment",
                description="Playbook executed by the ITDR engine "
                            "SOARResponder. One log entry per action; "
                            "see the engine's JSONL audit trail for "
                            "request ids.")
            task_id = task["_id"]
            for action in (containment_actions or []):
                self.client.add_task_log(task_id, action)
            if containment_actions:
                self.client.complete_task(task_id)
            log.info("thehive case %s opened for alert #%d (%d actions)",
                     case_id, alert.id, len(containment_actions or []))
            return case_id
        except Exception as e:                          # noqa: BLE001
            self.stats["errors"] += 1
            log.warning("thehive case pipeline failed for #%d: %s",
                        alert.id, e)
            return None

    def close_false_positive(self, alert_id: int, note: str = "") -> bool:
        """Analyst disposition: the alert was benign. Close the case as
        FalsePositive. Pair with IdentityResponder.rollback_containment
        to reverse any reversible containment."""
        case_id = self.cases.get(alert_id)
        if not case_id:
            log.warning("no thehive case tracked for alert #%d", alert_id)
            return False
        try:
            self.client.close_case(
                case_id, status="FalsePositive",
                summary=note or "Marked false positive; containment "
                                "rolled back where reversible.")
            return True
        except Exception as e:                          # noqa: BLE001
            self.stats["errors"] += 1
            log.warning("thehive close failed for case %s: %s", case_id, e)
            return False


def build_bridge_from_env() -> Optional[TheHiveBridge]:
    """TheHive wiring is opt-in: both THEHIVE_URL and THEHIVE_API_KEY
    must be set, otherwise the engine runs exactly as before."""
    import os
    url = os.environ.get("THEHIVE_URL", "").strip()
    key = os.environ.get("THEHIVE_API_KEY", "").strip()
    if not (url and key):
        return None
    verify = os.environ.get("THEHIVE_VERIFY_TLS", "true").lower() != "false"
    client = TheHiveClient(TheHiveConfig(url=url, api_key=key,
                                         verify_tls=verify))
    return TheHiveBridge(client)
