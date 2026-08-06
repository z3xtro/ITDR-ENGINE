"""
Tests for active enforcement. No network: a FakeAdapter records calls
and can be told to fail, so we verify the ORCHESTRATION logic — gating,
correlation requirement, protected users, retry accounting, and
rollback — without touching a real IdP.
"""

from __future__ import annotations

import asyncio

import pytest

from itdr.enforcement import (EnforcementConfig, IdentityResponder, Mode,
                              PLAYBOOK)
from rich.console import Console


class FakeAdapter:
    name = "fake"

    def __init__(self, fail: set[str] | None = None):
        self.calls: list[str] = []
        self.fail = fail or set()

    async def _do(self, action: str, user: str) -> bool:
        self.calls.append(action)
        await asyncio.sleep(0)
        return action not in self.fail

    async def revoke_user_sessions(self, u): return await self._do("revoke", u)
    async def invalidate_tokens(self, u): return await self._do("tokens", u)
    async def enforce_mfa_reset(self, u): return await self._do("mfa", u)

    async def quarantine_account(self, u, suspend=True):
        return await self._do("quarantine" if suspend else "unquarantine", u)

    async def aclose(self): pass


def _responder(adapter, **cfg):
    return IdentityResponder(
        adapter=adapter,
        config=EnforcementConfig(**cfg),
        console=Console(file=open("/dev/null", "w"), force_terminal=False))


def test_dry_run_never_calls_adapter():
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.DRY_RUN)
    asyncio.run(r.contain("asha.nair", 1, risk=250, signals=4))
    assert fake.calls == []          # nothing touched in dry-run


def test_active_enforcement_runs_full_playbook():
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT,
                   risk_threshold=100, min_correlated_signals=2)
    txn = asyncio.run(r.contain("asha.nair", 2, risk=250, signals=4))
    assert fake.calls == ["revoke", "tokens", "mfa", "quarantine"]
    assert txn.mode == "ACTIVE"
    assert all(e.status == "ok" for e in txn.entries)


def test_single_signal_blocks_enforcement():
    """Correlation interlock: one detector is never enough to act."""
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT,
                   risk_threshold=100, min_correlated_signals=2)
    txn = asyncio.run(r.contain("asha.nair", 3, risk=250, signals=1))
    assert fake.calls == []
    assert txn.mode == "DRY_RUN"


def test_low_risk_blocks_enforcement():
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT,
                   risk_threshold=100, min_correlated_signals=2)
    txn = asyncio.run(r.contain("asha.nair", 4, risk=55, signals=3))
    assert fake.calls == []
    assert txn.mode == "DRY_RUN"


def test_protected_user_never_contained():
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT,
                   risk_threshold=100, min_correlated_signals=2,
                   protected_users=frozenset({"breakglass-admin"}))
    txn = asyncio.run(r.contain("breakglass-admin", 5, risk=999, signals=9))
    assert fake.calls == []
    assert txn.mode == "DRY_RUN"


def test_partial_failure_is_recorded():
    fake = FakeAdapter(fail={"mfa"})
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT,
                   risk_threshold=100, min_correlated_signals=2)
    txn = asyncio.run(r.contain("asha.nair", 6, risk=250, signals=4))
    statuses = {e.step: e.status for e in txn.entries}
    assert statuses["enforce_mfa_reset"] == "failed"
    assert statuses["revoke_user_sessions"] == "ok"


def test_rollback_reverses_quarantine_only():
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT,
                   risk_threshold=100, min_correlated_signals=2)
    asyncio.run(r.contain("asha.nair", 7, risk=250, signals=4))
    fake.calls.clear()
    ok = asyncio.run(r.rollback_containment(7))
    assert ok
    assert fake.calls == ["unquarantine"]   # only the reversible step


def test_rollback_unknown_alert_is_safe():
    fake = FakeAdapter()
    r = _responder(fake, mode=Mode.ACTIVE_ENFORCEMENT)
    assert asyncio.run(r.rollback_containment(999)) is False


def test_default_adapter_is_dryrun():
    """Constructing with no adapter must yield a safe simulator."""
    from itdr.adapters import DryRunAdapter
    r = IdentityResponder(config=EnforcementConfig(
        mode=Mode.ACTIVE_ENFORCEMENT),
        console=Console(file=open("/dev/null", "w")))
    assert isinstance(r.adapter, DryRunAdapter)
    txn = asyncio.run(r.contain("x", 1, risk=999, signals=9))
    # even in ACTIVE mode, the dry-run adapter only simulates
    assert r.adapter.calls == ["revoke_sessions:x", "invalidate_tokens:x",
                               "mfa_reset:x", "quarantine:x"]
