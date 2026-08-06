"""
itdr.respond
============
SOAR response orchestration. Consumes ITDRAlerts; on CRITICAL tier it
executes containment playbooks against a (mock) Identity Provider API.

Guardrails
----------
- `dry_run=True` by DEFAULT: passive compliance mode. Every action is
  fully planned, logged, and audited — but the IdP call is simulated.
- Protected principals (break-glass admins) can never be auto-revoked.
- Every decision — including "did nothing" — lands in a JSONL audit log.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .models import ITDRAlert

log = logging.getLogger("itdr.respond")


@dataclass
class ResponderConfig:
    dry_run: bool = True
    idp_base_url: str = "https://idp.example.com/api/v1"
    protected_users: set[str] = field(
        default_factory=lambda: {"breakglass-admin"})
    audit_log: str = "itdr_audit.jsonl"
    notable_notify_only: bool = True


class MockIdPClient:
    """Simulates the IdP management API surface we'd call in production
    (Okta: DELETE /api/v1/users/{id}/sessions ; Entra: revokeSignInSessions).
    Swapping this for a real client is a one-class change."""

    def __init__(self, base_url: str, dry_run: bool):
        self.base_url = base_url
        self.dry_run = dry_run

    def _call(self, method: str, path: str, payload: dict) -> dict:
        request_id = str(uuid.uuid4())[:8]
        mode = "DRY-RUN" if self.dry_run else "LIVE"
        log.info("[%s] %s %s%s payload=%s req=%s",
                 mode, method, self.base_url, path,
                 json.dumps(payload), request_id)
        # In live mode this is where requests.request(...) would go.
        return {"status": 200 if not self.dry_run else 0,
                "simulated": self.dry_run, "request_id": request_id}

    def revoke_sessions(self, user_id: str, session_id: str) -> dict:
        return self._call("DELETE", f"/users/{user_id}/sessions",
                          {"session_id": session_id,
                           "reason": "itdr_auto_containment"})

    def require_mfa_reenroll(self, user_id: str) -> dict:
        return self._call("POST", f"/users/{user_id}/lifecycle/reset_factors",
                          {"reason": "itdr_auto_containment"})

    def notify_soc(self, alert: ITDRAlert) -> dict:
        return self._call("POST", "/hooks/soc-channel",
                          {"text": alert.summary()})


class SOARResponder:
    def __init__(self, config: ResponderConfig | None = None):
        self.cfg = config or ResponderConfig()
        self.idp = MockIdPClient(self.cfg.idp_base_url, self.cfg.dry_run)
        self.actions: list[str] = []            # for dashboards/tests
        self._audit_path = Path(self.cfg.audit_log)

    # -- entry point wired into ITDREngine(on_alert=...) -------------------

    def handle_alert(self, alert: ITDRAlert) -> None:
        self._audit("alert_received", alert=alert.summary(),
                    tier=alert.tier, risk=alert.risk_score)

        if alert.tier == "NOTABLE":
            self.idp.notify_soc(alert)
            self._record(alert, "SOC notified (notable, no containment)")
            return

        # CRITICAL tier -> containment playbook
        if alert.user_id in self.cfg.protected_users:
            self._record(alert, f"SKIPPED containment: {alert.user_id} "
                                "is a protected principal (manual review)")
            self._audit("containment_skipped_protected",
                        user=alert.user_id)
            return

        self.revoke_user_session(alert.user_id, alert.session_id, alert)
        self.idp.require_mfa_reenroll(alert.user_id)
        verb = ("[DRY-RUN] would force" if self.cfg.dry_run else "FORCED")
        self._record(alert, f"{verb} MFA re-enrollment for {alert.user_id}")
        self.idp.notify_soc(alert)
        self._record(alert, "SOC notified with containment report")

    # -- individual playbook actions ---------------------------------------

    def revoke_user_session(self, user_id: str, session_id: str,
                            alert: ITDRAlert | None = None) -> dict:
        result = self.idp.revoke_sessions(user_id, session_id)
        verb = ("[DRY-RUN] would revoke" if self.cfg.dry_run
                else "REVOKED")
        msg = (f"{verb} all sessions for {user_id} "
               f"(trigger session {session_id[:12]}, "
               f"req={result['request_id']})")
        if alert:
            self._record(alert, msg)
        else:
            self.actions.append(msg)
        self._audit("session_revocation",
                    user=user_id, session=session_id,
                    dry_run=self.cfg.dry_run,
                    request_id=result["request_id"])
        return result

    # -- helpers ------------------------------------------------------------

    def _record(self, alert: ITDRAlert, msg: str) -> None:
        line = f"alert#{alert.id} {msg}"
        self.actions.append(line)
        log.info(line)

    def _audit(self, kind: str, **fields) -> None:
        rec = {"ts": time.time(), "kind": kind,
               "dry_run": self.cfg.dry_run, **fields}
        try:
            with self._audit_path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass
