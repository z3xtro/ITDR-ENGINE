"""
itdr.wazuh
==========
Wazuh SIEM telemetry: real authentication events from real endpoints.

Two ingestion paths, because they suit different stages of a build-out:

  PULL (WazuhIndexerPoller) — query the Wazuh Indexer's ``wazuh-alerts-*``
      indices over the OpenSearch API. Needs nothing but credentials, so
      it works against a stock install the minute it comes up. Start here.

  PUSH (WazuhListener) — the manager's ``custom-itdr`` integration POSTs
      each alert as it fires. Sub-second latency, but it needs an
      ossec.conf edit and a manager restart. Move here once the pipeline
      shape is settled.

Both funnel through ``map_wazuh_alert``, a pure function turning a Wazuh
alert into the same ``AuthEvent`` the Okta/Entra pollers produce — the
engine never learns which source it came from.

Why rule IDs, not just groups
-----------------------------
Wazuh's rule *groups* are broad and inconsistently applied across
decoders (``authentication_success`` covers an SSH login and a Windows
service logon alike). The *rule ID* is exact and stable across releases,
so classification keys off IDs first and falls back to groups only for
rules this map doesn't know. That fallback matters: custom and
third-party rulesets carry IDs we can't enumerate.

Session identity
----------------
Host logs carry no IdP session id, so events key as
``wazuh:{user}@{agent}`` — one logical session per account per endpoint.
Context changes on that key (source IP, authenticating program) are the
same shape the session-mutation detector already understands.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Deque, Iterator, Optional

from .models import AuthEvent, EventResult, EventType

log = logging.getLogger("itdr.wazuh")

try:
    import requests
    _REQUESTS = True
except ImportError:                                    # pragma: no cover
    _REQUESTS = False


# ---------------------------------------------------------------- mapping --

# Rule ID -> (EventType, EventResult). Sourced from the stock Wazuh
# ruleset (ruleset/rules/0095-sshd_rules.xml, 0025-sendmail_rules.xml,
# 0580-win-security_rules.xml, pam/su/sudo rule files).
_RULE_MAP: dict[str, tuple[EventType, EventResult]] = {
    # -- sshd ---------------------------------------------------------
    "5715": (EventType.LOGIN, EventResult.SUCCESS),   # successful sshd login
    "5501": (EventType.LOGIN, EventResult.SUCCESS),   # PAM session opened
    "5502": (EventType.LOGOUT, EventResult.SUCCESS),  # PAM session closed
    "5716": (EventType.LOGIN, EventResult.FAIL),      # sshd auth failed
    "5710": (EventType.LOGIN, EventResult.FAIL),      # non-existent user
    "5711": (EventType.LOGIN, EventResult.FAIL),      # blacklisted user
    "5712": (EventType.LOGIN, EventResult.FAIL),      # sshd brute force
    "5713": (EventType.LOGIN, EventResult.FAIL),      # short password / corrupt
    "5714": (EventType.LOGIN, EventResult.FAIL),      # possible breakin
    "5760": (EventType.LOGIN, EventResult.FAIL),      # auth failure (generic)
    "5763": (EventType.LOGIN, EventResult.FAIL),      # brute force blocked
    # -- su / sudo (privilege transitions) ----------------------------
    # API_ACCESS rather than LOGIN: these ride an ALREADY-established
    # session, which is exactly what SessionMutationChecker inspects.
    "5401": (EventType.API_ACCESS, EventResult.FAIL),     # sudo failed
    "5402": (EventType.API_ACCESS, EventResult.SUCCESS),  # sudo to root
    "5403": (EventType.API_ACCESS, EventResult.FAIL),     # su failed
    "5404": (EventType.API_ACCESS, EventResult.SUCCESS),  # su to root
    # -- PAM / login ---------------------------------------------------
    "5503": (EventType.LOGIN, EventResult.FAIL),      # PAM auth failed
    "5504": (EventType.LOGIN, EventResult.FAIL),      # PAM bad password
    "5551": (EventType.LOGIN, EventResult.FAIL),      # repeated login fail
    "5555": (EventType.LOGIN, EventResult.FAIL),      # login failed
    # -- Windows Security ----------------------------------------------
    "60106": (EventType.LOGIN, EventResult.SUCCESS),  # logon success (4624)
    "60122": (EventType.LOGIN, EventResult.FAIL),     # logon failure (4625)
    "60137": (EventType.LOGOUT, EventResult.SUCCESS), # logoff (4634)
    "60204": (EventType.LOGIN, EventResult.FAIL),     # account lockout
    "92652": (EventType.LOGIN, EventResult.FAIL),     # RDP brute force
}

# Group-based fallback for rules outside _RULE_MAP (custom rulesets).
_SUCCESS_GROUPS = {"authentication_success"}
_FAIL_GROUPS = {"authentication_failed", "authentication_failures",
                "invalid_login", "invalid_access", "win_authentication_failed",
                "authentication_denied", "brute_force"}
_LOGOUT_GROUPS = {"session_closed", "logoff"}

# Accounts that are machine identities, not humans. Auth events for these
# are constant background noise on any real host and would swamp the
# risk model; the engine is about *human* identity compromise.
_MACHINE_ACCOUNTS = {
    "(unknown)", "-", "", "system", "anonymous logon", "local service",
    "network service", "dwm-1", "dwm-2", "umfd-0", "umfd-1",
}


def _classify(rec: dict) -> Optional[tuple[EventType, EventResult]]:
    """Rule ID first (exact), rule groups second (best-effort)."""
    rule = rec.get("rule") or {}
    rid = str(rule.get("id", ""))
    if rid in _RULE_MAP:
        return _RULE_MAP[rid]

    groups = {g.lower() for g in (rule.get("groups") or [])}
    if groups & _LOGOUT_GROUPS:
        return EventType.LOGOUT, EventResult.SUCCESS
    if groups & _FAIL_GROUPS:
        return EventType.LOGIN, EventResult.FAIL
    if groups & _SUCCESS_GROUPS:
        return EventType.LOGIN, EventResult.SUCCESS
    return None


def _wazuh_user(rec: dict) -> Optional[str]:
    """Extract the acted-on account across decoder dialects.

    Linux decoders use data.dstuser (target) / data.srcuser (actor);
    Windows Security puts it in data.win.eventdata.targetUserName.
    """
    data = rec.get("data") or {}
    win = ((data.get("win") or {}).get("eventdata") or {})

    user = (data.get("dstuser") or win.get("targetUserName")
            or data.get("srcuser") or win.get("subjectUserName"))
    if not user:
        return None
    user = str(user).strip()
    # Windows machine accounts end in $ (DESKTOP-ABC$) — never humans.
    if user.lower() in _MACHINE_ACCOUNTS or user.endswith("$"):
        return None
    # Strip a domain prefix so DOMAIN\alice and alice are one identity.
    if "\\" in user:
        user = user.split("\\", 1)[1]
    return user


def _wazuh_srcip(rec: dict) -> str:
    data = rec.get("data") or {}
    win = ((data.get("win") or {}).get("eventdata") or {})
    ip = data.get("srcip") or win.get("ipAddress")
    if not ip or str(ip) in ("-", "::1", "127.0.0.1", "localhost"):
        return "0.0.0.0"
    return str(ip)


def _wazuh_program(rec: dict) -> str:
    """The authenticating program stands in for the user agent.

    There is no browser on an SSH or console login, but *which* program
    authenticated (sshd vs su vs sudo vs winlogon) is a genuine context
    dimension — a session whose program changes mid-stream is the host
    analogue of a mutated user agent.
    """
    pre = (rec.get("predecoder") or {}).get("program_name")
    if pre:
        return str(pre)
    decoder = (rec.get("decoder") or {}).get("name")
    if decoder:
        return str(decoder)
    return "wazuh"


def _parse_ts(raw: str) -> datetime:
    """Wazuh stamps ISO-8601 with a numeric offset (+0000 or +00:00)."""
    if not raw:
        return datetime.now(timezone.utc)
    txt = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(txt)
    except ValueError:
        pass
    # Older managers emit +0000 (no colon), which fromisoformat rejects
    # before Python 3.11.
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def map_wazuh_alert(rec: dict) -> Optional[AuthEvent]:
    """Wazuh alert JSON -> AuthEvent. Pure function; fixture-testable.

    Returns None for anything that isn't human authentication telemetry
    (unknown rule, machine account, non-auth rule groups).
    """
    classified = _classify(rec)
    if classified is None:
        return None
    etype, result = classified

    user = _wazuh_user(rec)
    if not user:
        return None

    agent = (rec.get("agent") or {}).get("name", "unknown-host")

    # GeoLocation only exists when GeoIP is enabled on the manager, which
    # it isn't by default and never resolves for RFC1918 traffic. Absent
    # geo simply means the travel detector abstains for this event.
    geo = rec.get("GeoLocation") or {}
    loc = geo.get("location") or {}

    return AuthEvent(
        timestamp=_parse_ts(rec.get("timestamp", "")),
        user_id=user,
        session_id=f"wazuh:{user}@{agent}",
        client_ip=_wazuh_srcip(rec),
        user_agent=_wazuh_program(rec),
        geo_country=geo.get("country_name", "??"),
        geo_city=geo.get("city_name", "??"),
        geo_lat=loc.get("lat"),
        geo_lon=loc.get("lon"),
        event_type=etype,
        event_result=result,
        idp_source="wazuh",
    )


class AuthEventDeduper:
    """Collapse the several alerts Wazuh fires for one logical login.

    A single SSH login trips both rule 5715 (sshd: authentication
    success) and rule 5501 (PAM: login session opened) within the same
    second — and on some configurations 5502/5715 pairs too. They are
    genuinely distinct rules, but they describe ONE authentication, and
    counting them separately inflates everything downstream: risk scores
    double, brute-force windows fill twice as fast, and a quiet host
    looks twice as busy as it is.

    Observed on a live manager: nine mapped alerts represented five
    actual logins (6x 5501 + 3x 5715).

    Two events collapse when they share user, endpoint, event type and
    result, and land within `window_s` of each other. Distinct actions —
    a failure then a success, a login then a sudo — never collapse,
    because the type/result is part of the key.
    """

    def __init__(self, window_s: float = 2.0, maxlen: int = 1024):
        self.window_s = window_s
        self._seen: Deque[tuple[float, tuple]] = deque(maxlen=maxlen)
        self.collapsed = 0

    def is_duplicate(self, ev: AuthEvent) -> bool:
        key = (ev.user_id, ev.session_id, ev.event_type, ev.event_result)
        now = ev.ts
        while self._seen and now - self._seen[0][0] > self.window_s:
            self._seen.popleft()
        for ts, k in self._seen:
            if k == key and abs(now - ts) <= self.window_s:
                self.collapsed += 1
                return True
        self._seen.append((now, key))
        return False


def alert_agent(rec: dict) -> str:
    """Agent name for a raw alert — needed by the host-native detectors,
    which correlate per endpoint and can't recover it from AuthEvent."""
    return (rec.get("agent") or {}).get("name", "unknown-host")


def iter_alerts_file(path: str | Path) -> Iterator[AuthEvent]:
    """Replay a manager's alerts.json (NDJSON) offline.

    Malformed lines and non-auth alerts are skipped, never fatal — that
    archive holds every rule Wazuh has ever fired.
    """
    with Path(path).open(errors="replace") as f:
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


# ------------------------------------------------------------ API client --

class WazuhAPIError(RuntimeError):
    pass


class WazuhAPIClient:
    """Wazuh manager REST API (default port 55000).

    Handles the JWT dance: basic-auth once for a token, then bearer on
    everything, re-authenticating transparently when it expires (tokens
    are short-lived, 900s by default).

    TLS: stock installs ship a self-signed certificate, so `verify=False`
    is the working default for a lab. It is a real downgrade — pass a CA
    bundle path once you have one.
    """

    def __init__(self, url: str, user: str, password: str,
                 verify: bool | str = False, timeout: float = 30.0,
                 session=None):
        if session is None and not _REQUESTS:
            raise RuntimeError("pip install requests")
        self.base = url.rstrip("/")
        self.user = user
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.session = session or requests.Session()
        self._token: Optional[str] = None

    def authenticate(self) -> str:
        basic = base64.b64encode(
            f"{self.user}:{self.password}".encode()).decode()
        resp = self.session.post(
            f"{self.base}/security/user/authenticate",
            headers={"Authorization": f"Basic {basic}"},
            verify=self.verify, timeout=self.timeout)
        if resp.status_code != 200:
            raise WazuhAPIError(
                f"authentication failed ({resp.status_code}): {resp.text[:200]}")
        self._token = (resp.json().get("data") or {}).get("token")
        if not self._token:
            raise WazuhAPIError("no token in authentication response")
        return self._token

    def _request(self, method: str, path: str, **kw):
        if self._token is None:
            self.authenticate()
        url = f"{self.base}{path}"
        resp = self.session.request(
            method, url, headers={"Authorization": f"Bearer {self._token}"},
            verify=self.verify, timeout=self.timeout, **kw)
        if resp.status_code == 401:                    # token expired
            self.authenticate()
            resp = self.session.request(
                method, url,
                headers={"Authorization": f"Bearer {self._token}"},
                verify=self.verify, timeout=self.timeout, **kw)
        if resp.status_code >= 400:
            raise WazuhAPIError(
                f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
        return resp.json() if resp.content else {}

    def manager_info(self) -> dict:
        data = (self._request("GET", "/manager/info").get("data") or {})
        # Wazuh 4.x wraps most responses in affected_items; older builds
        # returned the fields inline. Handle both so the version doesn't
        # silently render as '?'.
        items = data.get("affected_items")
        if isinstance(items, list) and items:
            return items[0] or {}
        return data

    def agents(self, status: str = "active") -> list[dict]:
        body = self._request("GET", f"/agents?status={status}&limit=500")
        return ((body.get("data") or {}).get("affected_items") or [])

    def run_active_response(self, command: str, agent_ids: list[str],
                            arguments: Optional[list[str]] = None,
                            alert: Optional[dict] = None) -> dict:
        """Fire an active-response command on specific agents.

        `command` must be prefixed with '!' to name a script configured
        in ossec.conf (the API rejects unprefixed names).
        """
        payload: dict = {"command": command}
        if arguments:
            payload["arguments"] = arguments
        if alert:
            payload["alert"] = alert
        agents = ",".join(agent_ids)
        return self._request(
            "PUT", f"/active-response?agents_list={agents}", json=payload)


# --------------------------------------------------------- indexer poller --

class WazuhIndexerPoller:
    """Pull authentication alerts from the Wazuh Indexer (OpenSearch).

    This is the zero-config ingestion path: it reads the same
    ``wazuh-alerts-*`` indices the dashboard renders, so it works against
    a stock install without touching ossec.conf or restarting anything.

    Restart-safety: the newest alert timestamp seen is persisted to
    `cursor_file`, and queries are strictly `gt` that value, so a restart
    resumes at the frontier without replaying or dropping events.
    """

    def __init__(self, url: str, user: str, password: str,
                 verify: bool | str = False,
                 index: str = "wazuh-alerts-*",
                 cursor_file: str = ".wazuh_cursor.json",
                 lookback_minutes: int = 15,
                 page_size: int = 500,
                 timeout: float = 30.0,
                 dedupe: bool = True,
                 session=None):
        if session is None and not _REQUESTS:
            raise RuntimeError("pip install requests")
        self.deduper = AuthEventDeduper() if dedupe else None
        self.base = url.rstrip("/")
        self.index = index
        self.verify = verify
        self.timeout = timeout
        self.page_size = page_size
        self.lookback = lookback_minutes
        self._cursor_path = Path(cursor_file)
        self.session = session or requests.Session()
        self.session.auth = (user, password)

    # -- cursor ---------------------------------------------------------

    def _load_cursor(self) -> str:
        try:
            return json.loads(self._cursor_path.read_text())["cursor"]
        except (OSError, json.JSONDecodeError, KeyError):
            since = (datetime.now(timezone.utc)
                     - timedelta(minutes=self.lookback))
            return since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _save_cursor(self, cursor: str) -> None:
        try:
            self._cursor_path.write_text(json.dumps({"cursor": cursor}))
        except OSError:
            log.warning("could not persist wazuh cursor to %s",
                        self._cursor_path)

    # -- query ----------------------------------------------------------

    def _query(self, since: str, search_after: Optional[list]) -> dict:
        # Filter server-side on the auth rule groups so the manager does
        # the work; the mapper still re-checks every record.
        body: dict = {
            "size": self.page_size,
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            "query": {"bool": {
                "filter": [
                    {"range": {"timestamp": {"gt": since}}},
                    {"terms": {"rule.groups": [
                        "authentication_success", "authentication_failed",
                        "authentication_failures", "invalid_login",
                        "win_authentication_failed", "brute_force",
                        "session_closed",
                    ]}},
                ]}},
        }
        if search_after:
            body["search_after"] = search_after
        resp = self.session.post(
            f"{self.base}/{self.index}/_search",
            json=body, verify=self.verify, timeout=self.timeout)
        if resp.status_code >= 400:
            raise WazuhAPIError(
                f"indexer search -> {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def fetch(self) -> Iterator[AuthEvent]:
        """One polling pass. Yields new AuthEvents since the cursor."""
        since = self._load_cursor()
        newest = since
        search_after: Optional[list] = None

        while True:
            body = self._query(since, search_after)
            hits = ((body.get("hits") or {}).get("hits") or [])
            if not hits:
                break
            for hit in hits:
                src = hit.get("_source") or {}
                ts = src.get("timestamp")
                if ts and ts > newest:
                    newest = ts
                ev = map_wazuh_alert(src)
                if ev and not (self.deduper
                               and self.deduper.is_duplicate(ev)):
                    yield ev
            if len(hits) < self.page_size:
                break
            search_after = hits[-1].get("sort")
            if not search_after:
                break

        if newest != since:
            self._save_cursor(newest)

    def fetch_raw(self, limit: int = 50) -> list[dict]:
        """Recent auth alerts as raw dicts — used by the doctor to show
        what the mapper accepts and what it rejects."""
        since = (datetime.now(timezone.utc) - timedelta(days=1)
                 ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        saved, self.page_size = self.page_size, limit
        try:
            body = self._query(since, None)
        finally:
            self.page_size = saved
        return [h.get("_source") or {}
                for h in ((body.get("hits") or {}).get("hits") or [])]


# ------------------------------------------------------------- listener --

class WazuhListener:
    """Threaded HTTP endpoint for the manager-side integration script.

    POST /wazuh with the alert JSON body (one object, or a JSON array).
    Authentication: shared token in the X-ITDR-Token header, compared
    constant-time. Without a configured token the listener refuses to
    start — an open ingestion port is an event-injection primitive.
    """

    def __init__(self, sink: Callable[[AuthEvent], None], token: str,
                 host: str = "0.0.0.0", port: int = 8099,
                 raw_sink: Optional[Callable[[dict], None]] = None):
        if not token:
            raise ValueError("WazuhListener requires a shared token "
                             "(set WAZUH_SHARED_TOKEN)")
        self.sink = sink
        self.raw_sink = raw_sink
        self.token = token
        self.host = host
        self.port = port
        self.received = 0            # observability counters
        self.rejected = 0
        self.unmapped = 0
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
                    if not isinstance(rec, dict):
                        continue
                    if listener.raw_sink is not None:
                        try:
                            listener.raw_sink(rec)
                        except Exception:               # noqa: BLE001
                            log.exception("raw sink failed")
                    ev = map_wazuh_alert(rec)
                    if ev is None:
                        listener.unmapped += 1
                        continue
                    try:
                        listener.sink(ev)
                        accepted += 1
                    except Exception:                   # noqa: BLE001
                        log.exception("sink failed for wazuh event")
                listener.received += accepted
                self._reply(200, json.dumps({"accepted": accepted}))

            def do_GET(self):                           # noqa: N802
                # Unauthenticated liveness probe: counters only, no data.
                if self.path.rstrip("/") == "/health":
                    return self._reply(200, json.dumps({
                        "status": "ok",
                        "received": listener.received,
                        "unmapped": listener.unmapped,
                        "rejected": listener.rejected}))
                return self._reply(404, "not found")

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
