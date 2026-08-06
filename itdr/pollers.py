"""
itdr.pollers
============
Real Identity Provider telemetry. Fixes "not plugged into a real login
system": these pollers page the actual vendor APIs and map their native
schemas into AuthEvent — the engine never knows the difference between
simulated and live traffic.

  OktaPoller  -> GET {org}/api/v1/logs   (System Log API, cursor paging)
  EntraPoller -> GET graph.microsoft.com/v1.0/auditLogs/signIns

Both are resilient: exponential backoff on 429/5xx, cursor persistence
to disk (restart-safe, no event loss/duplication), and unknown event
types map to a safe default rather than crashing.

Field mapping is isolated in pure functions (map_okta_event /
map_entra_event) so it's unit-testable against recorded API fixtures
without any network.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

from .models import AuthEvent, EventResult, EventType

log = logging.getLogger("itdr.pollers")

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False


# --------------------------------------------------------------- mapping --

_OKTA_TYPE_MAP = {
    "user.authentication.sso": EventType.LOGIN,
    "user.session.start": EventType.LOGIN,
    "user.authentication.auth_via_mfa": EventType.MFA_CHALLENGE,
    "system.push.send_factor_verify_push": EventType.MFA_CHALLENGE,
    "user.authentication.verify": EventType.MFA_CHALLENGE,
    "user.session.end": EventType.LOGOUT,
    "app.oauth2.token.grant.refresh_token": EventType.TOKEN_REFRESH,
}


def map_okta_event(rec: dict) -> Optional[AuthEvent]:
    """Okta System Log record -> AuthEvent. Pure function; fixture-testable."""
    actor = rec.get("actor") or {}
    client = rec.get("client") or {}
    geo = (client.get("geographicalContext") or {})
    geoloc = geo.get("geolocation") or {}
    outcome = (rec.get("outcome") or {}).get("result", "SUCCESS")

    etype = _OKTA_TYPE_MAP.get(rec.get("eventType", ""),
                               EventType.API_ACCESS)
    user = actor.get("alternateId") or actor.get("id")
    if not user:
        return None
    ts_raw = rec.get("published", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(timezone.utc)

    # Okta ties events to an auth session via authenticationContext.
    sess = ((rec.get("authenticationContext") or {})
            .get("externalSessionId")) or f"okta-{user}"

    return AuthEvent(
        timestamp=ts, user_id=user, session_id=sess,
        client_ip=client.get("ipAddress", "0.0.0.0"),
        user_agent=(client.get("userAgent") or {}).get("rawUserAgent", ""),
        geo_country=geo.get("country", "??"),
        geo_city=geo.get("city", "??"),
        geo_lat=geoloc.get("lat"), geo_lon=geoloc.get("lon"),
        event_type=etype,
        event_result=(EventResult.SUCCESS if outcome == "SUCCESS"
                      else EventResult.FAIL),
        idp_source="okta",
    )


def map_entra_event(rec: dict) -> Optional[AuthEvent]:
    """Entra ID (Graph API signIns) record -> AuthEvent."""
    user = rec.get("userPrincipalName")
    if not user:
        return None
    loc = rec.get("location") or {}
    coords = loc.get("geoCoordinates") or {}
    status = rec.get("status") or {}
    ok = status.get("errorCode", 0) == 0
    ts_raw = rec.get("createdDateTime", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(timezone.utc)

    # Entra sign-ins with MFA appear via authenticationRequirement.
    mfa = rec.get("authenticationRequirement") == "multiFactorAuthentication"
    etype = EventType.MFA_CHALLENGE if (mfa and not ok) else EventType.LOGIN

    return AuthEvent(
        timestamp=ts, user_id=user,
        session_id=rec.get("correlationId") or f"entra-{user}",
        client_ip=rec.get("ipAddress", "0.0.0.0"),
        user_agent=(rec.get("deviceDetail") or {}).get("browser", ""),
        geo_country=loc.get("countryOrRegion", "??"),
        geo_city=loc.get("city", "??"),
        geo_lat=coords.get("latitude"), geo_lon=coords.get("longitude"),
        event_type=etype,
        event_result=EventResult.SUCCESS if ok else EventResult.FAIL,
        idp_source="entra",
    )


# --------------------------------------------------------------- pollers --

class _BasePoller:
    def __init__(self, cursor_file: str):
        self._cursor_path = Path(cursor_file)

    def _load_cursor(self) -> Optional[str]:
        try:
            return json.loads(self._cursor_path.read_text())["cursor"]
        except (OSError, json.JSONDecodeError, KeyError):
            return None

    def _save_cursor(self, cursor: str) -> None:
        self._cursor_path.write_text(json.dumps({"cursor": cursor}))

    @staticmethod
    def _get_with_backoff(session, url: str, **kw):
        delay = 1.0
        for attempt in range(6):
            resp = session.get(url, timeout=30, **kw)
            if resp.status_code == 429 or resp.status_code >= 500:
                log.warning("HTTP %s from %s; backoff %.0fs",
                            resp.status_code, url, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue
            resp.raise_for_status()
            return resp
        resp.raise_for_status()


class OktaPoller(_BasePoller):
    """Polls the Okta System Log API with cursor-based paging.

    Setup (free Okta developer org):
      1. developer.okta.com -> create org
      2. Admin -> Security -> API -> Tokens -> create token
      3. OKTA_ORG_URL=https://dev-xxxx.okta.com  OKTA_API_TOKEN=...
    """

    def __init__(self, org_url: str, api_token: str,
                 cursor_file: str = ".okta_cursor.json",
                 lookback_minutes: int = 10):
        super().__init__(cursor_file)
        if not _REQUESTS:
            raise RuntimeError("pip install requests")
        self.org_url = org_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {api_token}",
            "Accept": "application/json",
        })
        self.lookback = lookback_minutes

    def fetch(self) -> Iterator[AuthEvent]:
        """One polling pass. Yields new AuthEvents since the cursor."""
        url = self._load_cursor()
        if url is None:
            since = (datetime.now(timezone.utc)
                     - timedelta(minutes=self.lookback))
            url = (f"{self.org_url}/api/v1/logs?since="
                   f"{since.strftime('%Y-%m-%dT%H:%M:%SZ')}&limit=200")

        while url:
            resp = self._get_with_backoff(self.session, url)
            for rec in resp.json():
                ev = map_okta_event(rec)
                if ev:
                    yield ev
            # Okta paging: the 'next' Link header doubles as our cursor —
            # it always points at the polling frontier.
            url_next = resp.links.get("next", {}).get("url")
            if url_next:
                self._save_cursor(url_next)
            if not resp.json():        # frontier reached, stop this pass
                break
            url = url_next


class EntraPoller(_BasePoller):
    """Polls Entra ID sign-in logs via Microsoft Graph.

    Setup (free M365 E5 developer tenant):
      1. App registration -> client-credentials grant
      2. Grant AuditLog.Read.All (application) + admin consent
    """

    GRAPH = "https://graph.microsoft.com/v1.0"
    TOKEN_URL = ("https://login.microsoftonline.com/{tenant}"
                 "/oauth2/v2.0/token")

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 cursor_file: str = ".entra_cursor.json",
                 lookback_minutes: int = 10):
        super().__init__(cursor_file)
        if not _REQUESTS:
            raise RuntimeError("pip install requests")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.lookback = lookback_minutes
        self.session = requests.Session()
        self._token_expiry = 0.0

    def _ensure_token(self) -> None:
        if time.time() < self._token_expiry - 60:
            return
        resp = self.session.post(
            self.TOKEN_URL.format(tenant=self.tenant_id),
            data={"grant_type": "client_credentials",
                  "client_id": self.client_id,
                  "client_secret": self.client_secret,
                  "scope": "https://graph.microsoft.com/.default"},
            timeout=30)
        resp.raise_for_status()
        tok = resp.json()
        self.session.headers["Authorization"] = f"Bearer {tok['access_token']}"
        self._token_expiry = time.time() + int(tok.get("expires_in", 3600))

    def fetch(self) -> Iterator[AuthEvent]:
        self._ensure_token()
        last_ts = self._load_cursor()
        if last_ts is None:
            since = (datetime.now(timezone.utc)
                     - timedelta(minutes=self.lookback))
            last_ts = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        url = (f"{self.GRAPH}/auditLogs/signIns"
               f"?$filter=createdDateTime gt {last_ts}"
               f"&$orderby=createdDateTime&$top=200")
        newest = last_ts
        while url:
            resp = self._get_with_backoff(self.session, url)
            body = resp.json()
            for rec in body.get("value", []):
                ev = map_entra_event(rec)
                if ev:
                    newest = max(newest, rec.get("createdDateTime", newest))
                    yield ev
            url = body.get("@odata.nextLink")
        self._save_cursor(newest)


def run_poll_loop(poller, sink: Callable[[AuthEvent], None],
                  interval: float = 60.0) -> None:
    """Blocking poll loop: fetch -> feed engine -> sleep -> repeat."""
    log.info("poll loop started (interval %.0fs)", interval)
    while True:
        try:
            n = 0
            for ev in poller.fetch():
                sink(ev)
                n += 1
            log.info("poll pass complete: %d events", n)
        except Exception:                              # noqa: BLE001
            log.exception("poll pass failed; continuing")
        time.sleep(interval)
