"""
itdr.wazuh
==========
Wazuh SIEM telemetry: real authentication events from real endpoints.

Wazuh agents ship OS auth logs (sshd, PAM, Windows Security) to the
Wazuh manager, which fires our `custom-itdr` integration script on every
authentication-group alert. The script POSTs the alert JSON to the
WazuhListener below, and `map_wazuh_alert` normalizes it into the same
AuthEvent the Okta/Entra pollers produce — the engine never knows the
difference.

    endpoint ─▶ wazuh-agent ─▶ wazuh-manager ─▶ custom-itdr ─▶ HTTP POST
                                                                  │
                                    WazuhListener ◀───────────────┘
                                        │ map_wazuh_alert()
                                        ▼
                                  ITDREngine.process_event()

Field mapping is a pure function (fixture-testable, no network), same
pattern as itdr.pollers. `iter_alerts_file` replays a manager's
alerts.json offline for demos and regression tests.

Sessions: host logs carry no IdP session id, so events are keyed
`wazuh:{user}@{host}` — one logical session per user per endpoint.
IP / geo changes on that key are exactly the token-replay-shaped signals
the detection pipeline looks for.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Iterator, Optional

from .models import AuthEvent, EventResult, EventType

log = logging.getLogger("itdr.wazuh")

# Wazuh rule groups -> normalized event taxonomy. Anything outside these
# groups was already filtered out by the <integration><group> allowlist
# on the manager, but we re-check here so a replayed alerts.json (which
# contains everything) maps safely too.
_SUCCESS_GROUPS = {"authentication_success"}
_FAIL_GROUPS = {"authentication_failed", "authentication_failures",
                "invalid_login", "invalid_access"}
_LOGOUT_GROUPS = {"session_closed"}


def _wazuh_user(rec: dict) -> Optional[str]:
    """Extract the acted-on account from the decoder fields.

    Linux decoders put it in data.dstuser/srcuser; Windows Security
    events carry it in data.win.eventdata.targetUserName.
    """
    data = rec.get("data") or {}
    user = data.get("dstuser") or data.get("srcuser")
    if not user:
        win = ((data.get("win") or {}).get("eventdata") or {})
        user = win.get("targetUserName")
    if not user or user in ("(unknown)", "SYSTEM", "ANONYMOUS LOGON"):
        return None
    return user


def _wazuh_srcip(rec: dict) -> str:
    data = rec.get("data") or {}
    ip = data.get("srcip")
    if not ip:
        win = ((data.get("win") or {}).get("eventdata") or {})
        ip = win.get("ipAddress")
    if not ip or ip in ("-", "::1"):
        return "0.0.0.0"
    return ip


def map_wazuh_alert(rec: dict) -> Optional[AuthEvent]:
    """Wazuh alert JSON -> AuthEvent. Pure function; fixture-testable.

    Returns None for alerts that aren't authentication telemetry (no
    user, or rule groups outside the auth taxonomy).
    """
    rule = rec.get("rule") or {}
    groups = set(rule.get("groups") or [])

    if groups & _SUCCESS_GROUPS:
        etype, result = EventType.LOGIN, EventResult.SUCCESS
    elif groups & _FAIL_GROUPS:
        etype, result = EventType.LOGIN, EventResult.FAIL
    elif groups & _LOGOUT_GROUPS:
        etype, result = EventType.LOGOUT, EventResult.SUCCESS
    else:
        return None

    user = _wazuh_user(rec)
    if not user:
        return None

    agent = (rec.get("agent") or {}).get("name", "unknown-host")

    ts_raw = rec.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(timezone.utc)

    geo = rec.get("GeoLocation") or {}
    loc = geo.get("location") or {}

    # No browser on an SSH/console login: the "user agent" slot carries
    # the authenticating program instead (sshd, su, winlogon...), which
    # still gives SessionMutation a context dimension to compare.
    program = ((rec.get("predecoder") or {}).get("program_name")
               or (rule.get("groups") or ["wazuh"])[0])

    return AuthEvent(
        timestamp=ts,
        user_id=user,
        session_id=f"wazuh:{user}@{agent}",
        client_ip=_wazuh_srcip(rec),
        user_agent=str(program),
        geo_country=geo.get("country_name", "??"),
        geo_city=geo.get("city_name", "??"),
        geo_lat=loc.get("lat"),
        geo_lon=loc.get("lon"),
        event_type=etype,
        event_result=result,
        idp_source="wazuh",
    )


def iter_alerts_file(path: str | Path) -> Iterator[AuthEvent]:
    """Replay a Wazuh manager's alerts.json (NDJSON) offline.

    Malformed lines and non-auth alerts are skipped, never fatal — the
    archive contains every rule Wazuh ever fired.
    """
    with Path(path).open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = map_wazuh_alert(rec)
            if ev:
                yield ev


# ------------------------------------------------------------- listener --

class WazuhListener:
    """Threaded HTTP endpoint for the manager-side integration script.

    POST /wazuh with the alert JSON body (one object, or a JSON array).
    Authentication: shared token in the X-ITDR-Token header, compared
    constant-time. Without a configured token the listener refuses to
    start — an open ingestion port is an event-injection primitive.
    """

    def __init__(self, sink: Callable[[AuthEvent], None], token: str,
                 host: str = "0.0.0.0", port: int = 8099):
        if not token:
            raise ValueError("WazuhListener requires a shared token "
                             "(set WAZUH_SHARED_TOKEN)")
        self.sink = sink
        self.token = token
        self.host = host
        self.port = port
        self.received = 0            # observability counters
        self.rejected = 0
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):                          # noqa: N802
                if self.path.rstrip("/") not in ("", "/wazuh"):
                    return self._reply(404, "not found")
                supplied = self.headers.get("X-ITDR-Token", "")
                if not hmac.compare_digest(supplied, listener.token):
                    listener.rejected += 1
                    return self._reply(401, "bad token")
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(length))
                except (ValueError, json.JSONDecodeError):
                    return self._reply(400, "invalid json")

                records = body if isinstance(body, list) else [body]
                accepted = 0
                for rec in records:
                    ev = map_wazuh_alert(rec) if isinstance(rec, dict) \
                        else None
                    if ev is None:
                        continue
                    try:
                        listener.sink(ev)
                        accepted += 1
                    except Exception:                   # noqa: BLE001
                        log.exception("sink failed for wazuh event")
                listener.received += accepted
                self._reply(200, json.dumps({"accepted": accepted}))

            def _reply(self, code: int, msg: str):
                payload = msg.encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json"
                                 if msg.startswith("{") else "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt, *args):          # route to logging
                log.debug("listener: " + fmt, *args)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]       # resolve port 0
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="wazuh-listener",
            daemon=True)
        self._thread.start()
        log.info("wazuh listener on %s:%d (POST /wazuh)",
                 self.host, self.port)

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
