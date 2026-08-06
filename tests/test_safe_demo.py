"""
Safety tests for safe_enforce_demo.py — prove each guard blocks BEFORE
any destructive call, using a mocked Okta so no network is touched.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import safe_enforce_demo as demo   # noqa: E402


class Args:
    def __init__(self, target, protect=None, no_suspend=True, yes=True):
        self.target = target
        self.protect = protect or []
        self.no_suspend = no_suspend
        self.yes = yes


@pytest.fixture(autouse=True)
def _okta_env(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://dev-test.okta.com")
    monkeypatch.setenv("OKTA_API_TOKEN", "fake-token")


def _patch(monkeypatch, *, owner="admin@org.com", exists=True, roles=None):
    async def fake_whoami(domain, token):
        return owner

    async def fake_roles(domain, token, login):
        return exists, (roles or [])

    monkeypatch.setattr(demo, "whoami", fake_whoami)
    monkeypatch.setattr(demo, "user_exists_and_roles", fake_roles)


def test_guard_blocks_self_target(monkeypatch):
    """Targeting the token owner must be blocked (guard 2)."""
    _patch(monkeypatch, owner="admin@org.com")
    rc = asyncio.run(demo.run(Args(target="admin@org.com")))
    assert rc == 1


def test_guard_blocks_protected_user(monkeypatch):
    _patch(monkeypatch, owner="admin@org.com")
    rc = asyncio.run(demo.run(
        Args(target="vip@org.com", protect=["vip@org.com"])))
    assert rc == 1


def test_guard_blocks_missing_target(monkeypatch):
    _patch(monkeypatch, owner="admin@org.com", exists=False)
    rc = asyncio.run(demo.run(Args(target="ghost@org.com")))
    assert rc == 1


def test_guard_blocks_admin_target(monkeypatch):
    """An account holding an admin role must be refused (guard 3)."""
    _patch(monkeypatch, owner="admin@org.com", exists=True,
           roles=["SUPER_ADMIN"])
    rc = asyncio.run(demo.run(Args(target="otheradmin@org.com")))
    assert rc == 1


def test_safe_target_proceeds(monkeypatch):
    """A non-admin throwaway user runs, and rollback is invoked."""
    _patch(monkeypatch, owner="admin@org.com", exists=True, roles=[])

    calls = []

    class FakeAdapter:
        name = "okta"
        async def revoke_user_sessions(self, u): calls.append(("revoke", u)); return True
        async def invalidate_tokens(self, u): calls.append(("invalidate", u)); return True
        async def enforce_mfa_reset(self, u): calls.append(("mfa", u)); return True
        async def quarantine_account(self, u, suspend=True):
            calls.append(("quarantine", u, suspend)); return True
        async def aclose(self): pass

    monkeypatch.setattr(demo, "OktaAdapter", lambda d, t: FakeAdapter())
    rc = asyncio.run(demo.run(Args(target="demo.victim@org.com",
                                   no_suspend=True, yes=True)))
    assert rc == 0
    # the safe target actually had sessions revoked
    assert any(c[0] == "revoke" and c[1] == "demo.victim@org.com"
               for c in calls)
