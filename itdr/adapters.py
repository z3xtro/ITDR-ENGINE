"""
itdr.adapters
=============
Provider-agnostic containment adapters. Each concrete adapter maps the
same four containment primitives onto one identity provider's official
management API. The responder orchestrates them without knowing which
provider it's talking to.

    BaseIdPAdapter (Protocol)
      ├── OktaAdapter    → Okta Management API (SSWS token)
      ├── EntraAdapter   → Microsoft Graph (client-credentials bearer)
      └── DryRunAdapter  → simulates every call, touches nothing

SAFETY: DryRunAdapter is the default everywhere. The concrete adapters
only ever issue real HTTP calls when the responder is explicitly in
ACTIVE_ENFORCEMENT mode AND the adapter was constructed with live
credentials — two independent gates.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol, runtime_checkable

try:
    import httpx
    _HTTPX = True
except ImportError:                                    # pragma: no cover
    _HTTPX = False

log = logging.getLogger("itdr.adapters")

# Transient HTTP conditions worth retrying with backoff.
_RETRY_STATUS = {429, 500, 502, 503, 504}


@runtime_checkable
class BaseIdPAdapter(Protocol):
    """The containment contract every provider adapter fulfils."""
    name: str

    async def revoke_user_sessions(self, user_identity: str) -> bool: ...
    async def invalidate_tokens(self, user_identity: str) -> bool: ...
    async def enforce_mfa_reset(self, user_identity: str) -> bool: ...
    async def quarantine_account(self, user_identity: str,
                                 suspend: bool = True) -> bool: ...


async def _request_with_backoff(client, method: str, url: str,
                                max_attempts: int = 5, **kw) -> bool:
    """Issue one request, retrying transient faults with exponential
    backoff. Returns True on 2xx, False on non-retryable failure."""
    delay = 1.0
    for attempt in range(1, max_attempts + 1):
        try:
            resp = await client.request(method, url, timeout=30, **kw)
        except Exception as e:                         # noqa: BLE001
            log.warning("%s %s attempt %d network error: %s",
                        method, url, attempt, e)
            if attempt == max_attempts:
                return False
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
            continue
        if resp.status_code in _RETRY_STATUS:
            log.warning("%s %s -> %d (retry %d/%d)", method, url,
                        resp.status_code, attempt, max_attempts)
            if attempt == max_attempts:
                return False
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
            continue
        ok = 200 <= resp.status_code < 300
        log.info("%s %s -> %d (%s)", method, url, resp.status_code,
                 "ok" if ok else "fail")
        return ok
    return False


# ─────────────────────────────────────────────────────────── Okta ──

class OktaAdapter:
    """Okta Management API. Requires an SSWS API token with user-admin
    scope. userId may be the Okta login/email (the API resolves it)."""
    name = "okta"

    def __init__(self, domain: str, api_token: str):
        if not _HTTPX:
            raise RuntimeError("pip install httpx")
        self.domain = domain.rstrip("/")
        self._client = httpx.AsyncClient(headers={
            "Authorization": f"SSWS {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    async def revoke_user_sessions(self, user_identity: str) -> bool:
        # oauthTokens=true also invalidates OAuth refresh/access tokens,
        # so this single call covers "invalidate_tokens" as well.
        url = (f"{self.domain}/api/v1/users/{user_identity}/sessions"
               f"?oauthTokens=true")
        return await _request_with_backoff(self._client, "DELETE", url)

    async def invalidate_tokens(self, user_identity: str) -> bool:
        url = (f"{self.domain}/api/v1/users/{user_identity}/sessions"
               f"?oauthTokens=true")
        return await _request_with_backoff(self._client, "DELETE", url)

    async def enforce_mfa_reset(self, user_identity: str) -> bool:
        url = (f"{self.domain}/api/v1/users/{user_identity}"
               f"/lifecycle/reset_factors")
        return await _request_with_backoff(self._client, "POST", url)

    async def quarantine_account(self, user_identity: str,
                                 suspend: bool = True) -> bool:
        verb = "suspend" if suspend else "unsuspend"
        url = (f"{self.domain}/api/v1/users/{user_identity}"
               f"/lifecycle/{verb}")
        return await _request_with_backoff(self._client, "POST", url)

    async def aclose(self) -> None:
        await self._client.aclose()


# ────────────────────────────────────────────────────────── Entra ──

class EntraAdapter:
    """Microsoft Entra ID via Graph. Requires an app registration with
    User.RevokeSessions.All + User.ReadWrite.All (application) and a
    client-credentials token."""
    name = "entra"
    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        if not _HTTPX:
            raise RuntimeError("pip install httpx")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._client = httpx.AsyncClient()
        self._token: str | None = None

    async def _auth(self) -> None:
        if self._token:
            return
        url = (f"https://login.microsoftonline.com/{self.tenant_id}"
               f"/oauth2/v2.0/token")
        resp = await self._client.post(url, timeout=30, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default"})
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        self._client.headers["Authorization"] = f"Bearer {self._token}"

    async def revoke_user_sessions(self, user_identity: str) -> bool:
        await self._auth()
        url = f"{self.GRAPH}/users/{user_identity}/revokeSignInSessions"
        return await _request_with_backoff(self._client, "POST", url)

    async def invalidate_tokens(self, user_identity: str) -> bool:
        # revokeSignInSessions resets signInSessionsValidFromDateTime,
        # invalidating all issued tokens — same primitive.
        return await self.revoke_user_sessions(user_identity)

    async def enforce_mfa_reset(self, user_identity: str) -> bool:
        # Delete the user's registered auth methods (requires
        # UserAuthenticationMethod.ReadWrite.All). Best-effort per method.
        await self._auth()
        url = (f"{self.GRAPH}/users/{user_identity}"
               f"/authentication/methods")
        try:
            resp = await self._client.get(url, timeout=30)
            resp.raise_for_status()
        except Exception:                              # noqa: BLE001
            return False
        ok = True
        for m in resp.json().get("value", []):
            mid = m.get("id")
            if not mid:
                continue
            ok &= await _request_with_backoff(
                self._client, "DELETE", f"{url}/{mid}")
        return ok

    async def quarantine_account(self, user_identity: str,
                                 suspend: bool = True) -> bool:
        await self._auth()
        url = f"{self.GRAPH}/users/{user_identity}"
        return await _request_with_backoff(
            self._client, "PATCH", url,
            json={"accountEnabled": not suspend})

    async def aclose(self) -> None:
        await self._client.aclose()


# ───────────────────────────────────────────────────────── DryRun ──

class DryRunAdapter:
    """Simulates every containment call. The DEFAULT everywhere: it can
    never touch a real account, so it's safe in demos, CI, and any run
    where live credentials weren't deliberately supplied."""
    name = "dry-run"

    def __init__(self, wraps: str = "generic"):
        self.wraps = wraps
        self.calls: list[str] = []

    async def _sim(self, action: str, user: str) -> bool:
        self.calls.append(f"{action}:{user}")
        await asyncio.sleep(0)          # keep it a real coroutine
        log.info("[DRY-RUN:%s] would %s for %s", self.wraps, action, user)
        return True

    async def revoke_user_sessions(self, u: str) -> bool:
        return await self._sim("revoke_sessions", u)

    async def invalidate_tokens(self, u: str) -> bool:
        return await self._sim("invalidate_tokens", u)

    async def enforce_mfa_reset(self, u: str) -> bool:
        return await self._sim("mfa_reset", u)

    async def quarantine_account(self, u: str, suspend: bool = True) -> bool:
        return await self._sim("quarantine" if suspend else "unquarantine", u)

    async def aclose(self) -> None:
        return None
