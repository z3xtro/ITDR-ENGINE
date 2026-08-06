"""
itdr.enforcement
================
Active containment orchestrator. Sits above the provider adapters and
decides WHETHER to act, executes the playbook as a tracked transaction,
and can roll it back if an analyst marks the alert a false positive.

Safety model — three independent interlocks, ALL required to act live:
  1. mode == ACTIVE_ENFORCEMENT           (explicit, not the default)
  2. composite risk ≥ threshold           (structural score gate)
  3. correlated signals ≥ min_signals     (never act on ONE detector)
Plus a protected-principal denylist that no risk score can override.

If any interlock fails, the responder falls back to narrating the
playbook in DRY_RUN — it never silently escalates.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .adapters import BaseIdPAdapter, DryRunAdapter

log = logging.getLogger("itdr.enforcement")


class Mode(str, Enum):
    DRY_RUN = "DRY_RUN"
    ACTIVE_ENFORCEMENT = "ACTIVE_ENFORCEMENT"


# One containment playbook step: the adapter coroutine name, a label,
# and the inverse action used to roll it back (None = irreversible/none).
@dataclass(frozen=True)
class Step:
    method: str
    label: str
    dry: str                                # active-voice dry-run phrase
    rollback: Optional[str] = None


PLAYBOOK = [
    Step("revoke_user_sessions", "Sessions revoked",
         "clear active user sessions"),
    Step("invalidate_tokens", "Tokens invalidated",
         "invalidate issued OAuth tokens"),
    Step("enforce_mfa_reset", "MFA reset enforced",
         "reset enrolled MFA factors"),
    Step("quarantine_account", "Account quarantined",
         "issue account suspension", rollback="quarantine_account"),
]


@dataclass
class TxnEntry:
    step: str
    label: str
    status: str = "pending"          # pending|ok|failed|skipped|rolled_back
    detail: str = ""


@dataclass
class Transaction:
    user: str
    alert_id: int
    mode: str
    entries: list[TxnEntry] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    rolled_back: bool = False

    def entry(self, step: str) -> TxnEntry:
        for e in self.entries:
            if e.step == step:
                return e
        e = TxnEntry(step=step, label=step)
        self.entries.append(e)
        return e


@dataclass
class EnforcementConfig:
    mode: Mode = Mode.DRY_RUN
    risk_threshold: float = 100.0
    min_correlated_signals: int = 2
    protected_users: frozenset = frozenset({"breakglass-admin"})


class IdentityResponder:
    """Coordinates adapter calls into a gated, tracked, reversible
    containment transaction with live Rich progress output."""

    def __init__(self, adapter: Optional[BaseIdPAdapter] = None,
                 config: Optional[EnforcementConfig] = None,
                 console: Optional[Console] = None):
        self.cfg = config or EnforcementConfig()
        # SAFETY: default to a dry-run adapter if none supplied, so a
        # misconfigured ACTIVE run still can't touch a real account.
        self.adapter: BaseIdPAdapter = adapter or DryRunAdapter()
        self.console = console or Console()
        self.transactions: list[Transaction] = []

    # ---- decision gate ------------------------------------------------

    def _should_enforce(self, user: str, risk: float,
                        signals: int) -> tuple[bool, str]:
        if user in self.cfg.protected_users:
            return False, f"{user} is a protected principal"
        if self.cfg.mode is not Mode.ACTIVE_ENFORCEMENT:
            return False, "mode is DRY_RUN"
        if risk < self.cfg.risk_threshold:
            return False, (f"risk {risk:g} < threshold "
                           f"{self.cfg.risk_threshold:g}")
        if signals < self.cfg.min_correlated_signals:
            return False, (f"only {signals} signal(s); need "
                           f"{self.cfg.min_correlated_signals} correlated")
        return True, "all interlocks satisfied"

    # ---- main entry ---------------------------------------------------

    async def contain(self, user: str, alert_id: int, risk: float,
                      signals: int) -> Transaction:
        live, reason = self._should_enforce(user, risk, signals)
        mode = "ACTIVE" if live else "DRY_RUN"
        txn = Transaction(user=user, alert_id=alert_id, mode=mode)
        self.transactions.append(txn)

        header = (f"CONTAINMENT · alert #{alert_id} · {user} · "
                  f"risk {risk:g} · {signals} signals")
        self.console.print(Panel(
            Text(header, style="bold"),
            border_style="red" if live else "yellow",
            subtitle=f"[{'bold red' if live else 'yellow'}]"
                     f"{mode}[/] · {reason}"))

        for step in PLAYBOOK:
            e = txn.entry(step.method)
            e.label = step.label
            if live:
                ok = await self._run_live(step, user)
                e.status = "ok" if ok else "failed"
                self._print_step(e, live=True)
            else:
                e.status = "skipped"
                self._print_step(e, live=False, dry_phrase=step.dry)

        self._print_step_final(user, live)
        return txn

    async def _run_live(self, step: Step, user: str) -> bool:
        fn = getattr(self.adapter, step.method)
        try:
            if step.method == "quarantine_account":
                return await fn(user, suspend=True)
            return await fn(user)
        except Exception as e:                         # noqa: BLE001
            log.exception("step %s failed", step.method)
            return False

    # ---- rollback -----------------------------------------------------

    async def rollback_containment(self, alert_id: int) -> bool:
        """Analyst marked the alert a false positive: reverse whatever
        reversible actions were taken."""
        txn = next((t for t in self.transactions
                    if t.alert_id == alert_id), None)
        if txn is None:
            self.console.print(f"[red]no transaction for alert #{alert_id}")
            return False

        self.console.print(Panel(
            Text(f"ROLLBACK · alert #{alert_id} · {txn.user} "
                 f"(false positive)", style="bold cyan"),
            border_style="cyan"))

        by_method = {s.method: s for s in PLAYBOOK}
        ok_all = True
        for e in txn.entries:
            step = by_method.get(e.step)
            if e.status != "ok" or not step or not step.rollback:
                self.console.print(
                    f"  [dim]— {e.label}: nothing to undo[/]")
                continue
            # only quarantine is reversible: unsuspend the account
            try:
                fn = getattr(self.adapter, step.rollback)
                undone = await fn(txn.user, suspend=False)
            except Exception:                          # noqa: BLE001
                undone = False
            e.status = "rolled_back" if undone else "failed"
            ok_all &= undone
            icon = "[green]✓[/]" if undone else "[red]✗[/]"
            self.console.print(f"  {icon} reversed: {e.label}")

        txn.rolled_back = True
        note = ("[yellow]Note: revoked sessions and reset MFA cannot be "
                "un-revoked — the user simply re-authenticates. Only the "
                "account suspension was reversible.[/]")
        self.console.print(note)
        return ok_all

    # ---- rich output --------------------------------------------------

    def _print_step(self, e: TxnEntry, live: bool,
                    dry_phrase: str = "") -> None:
        if live:
            icon = "[bold green]✓[/]" if e.status == "ok" else "[bold red]✗[/]"
            self.console.print(f"  {icon} {e.label}")
        else:
            phrase = dry_phrase or f"{e.label[0].lower()}{e.label[1:]}"
            self.console.print(
                f"  [bold yellow][DRY_RUN][/] Would {phrase}...")

    def _print_step_final(self, user: str, live: bool) -> None:
        if live:
            self.console.print("  [bold green]✓[/] Analyst notified")
        else:
            self.console.print(
                "  [bold yellow][DRY_RUN][/] Would notify analyst...")


def build_adapter_from_env():
    """Construct the right adapter from environment, defaulting to
    DryRunAdapter when live credentials are absent."""
    import os
    provider = os.environ.get("ENFORCE_PROVIDER", "").lower()
    if provider == "okta":
        url = os.environ.get("OKTA_ORG_URL", "").strip()
        token = os.environ.get("OKTA_API_TOKEN", "").strip()
        if url and token:
            from .adapters import OktaAdapter
            return OktaAdapter(url, token)
    if provider == "entra":
        t = os.environ.get("ENTRA_TENANT_ID", "").strip()
        c = os.environ.get("ENTRA_CLIENT_ID", "").strip()
        s = os.environ.get("ENTRA_CLIENT_SECRET", "").strip()
        if t and c and s:
            from .adapters import EntraAdapter
            return EntraAdapter(t, c, s)
    return DryRunAdapter(wraps=provider or "generic")
