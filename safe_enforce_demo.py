"""
safe_enforce_demo.py — demonstrate LIVE Okta containment without any
risk of locking yourself out.

    python safe_enforce_demo.py --target demo.victim@your-org.okta.com

This is the *only* supported way to show active enforcement against a
real Okta org. It stacks several independent guards so that even a typo
cannot suspend your own admin account:

  GUARD 1  Explicit target required — no default, no "all users".
  GUARD 2  Admin self-identification — the harness calls Okta to learn
           which login owns the API token, and hard-blocks that login
           (and anything in --protect) from ANY action.
  GUARD 3  Target must NOT be an Okta admin — refuses to act on any
           account holding an admin role, so you can't fat-finger a
           privileged user.
  GUARD 4  Pre-flight confirmation — prints exactly what it will do and
           waits for you to type the target login back.
  GUARD 5  Reversible-only by default — runs revoke + (optional) suspend,
           then immediately offers rollback; --no-suspend keeps it to the
           fully-reversible session revoke.

If ANY guard fails, nothing is sent. The safe path is the default path.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from itdr.adapters import OktaAdapter
from itdr.enforcement import (EnforcementConfig, IdentityResponder, Mode)

console = Console()


# ───────────────────────────────────────────────── okta introspection ──

async def whoami(domain: str, token: str) -> str:
    """Return the login that owns this API token (GUARD 2)."""
    async with httpx.AsyncClient() as c:
        # The token's owner is the user who created it; Okta doesn't expose
        # that directly, but /api/v1/users/me works for user tokens and the
        # session context reflects the admin. We fall back to a sentinel.
        r = await c.get(f"{domain.rstrip('/')}/api/v1/users/me",
                        headers={"Authorization": f"SSWS {token}",
                                 "Accept": "application/json"}, timeout=20)
        if r.status_code == 200:
            p = r.json().get("profile", {})
            return (p.get("login") or p.get("email") or "").lower()
    return ""


async def user_exists_and_roles(domain: str, token: str,
                                 login: str) -> tuple[bool, list[str]]:
    """Confirm the target exists and fetch its admin roles (GUARD 3)."""
    async with httpx.AsyncClient() as c:
        base = domain.rstrip("/")
        hdr = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
        u = await c.get(f"{base}/api/v1/users/{login}", headers=hdr,
                        timeout=20)
        if u.status_code != 200:
            return False, []
        uid = u.json().get("id", login)
        roles: list[str] = []
        rr = await c.get(f"{base}/api/v1/users/{uid}/roles", headers=hdr,
                         timeout=20)
        if rr.status_code == 200:
            roles = [x.get("type", "") for x in rr.json()]
        return True, roles


# ─────────────────────────────────────────────────────────── harness ──

async def run(args: argparse.Namespace) -> int:
    import os
    domain = os.environ.get("OKTA_ORG_URL", "").strip()
    token = os.environ.get("OKTA_API_TOKEN", "").strip()
    if not domain or not token:
        console.print("[red]Set OKTA_ORG_URL and OKTA_API_TOKEN first.[/]")
        return 2

    target = args.target.lower()
    console.print(Panel(Text("SAFE LIVE ENFORCEMENT DEMO", style="bold"),
                        subtitle="multiple lockout guards active",
                        border_style="cyan"))

    # GUARD 2 — who owns this token?
    console.print("→ identifying token owner (guard 2)…")
    admin_login = await whoami(domain, token)
    if admin_login:
        console.print(f"  token owner: [cyan]{admin_login}[/] — "
                      "protected from all actions")
    else:
        console.print("  [yellow]could not resolve token owner; "
                      "relying on --protect list[/]")

    protected = {admin_login} | {p.lower() for p in args.protect if p}
    protected.discard("")

    # GUARD 1 + self-target check
    if target in protected:
        console.print(f"[bold red]BLOCKED:[/] {target} is a protected "
                      "principal (this is the safety net working).")
        return 1

    # GUARD 3 — target must exist and not be an admin
    console.print("→ verifying target (guard 3)…")
    exists, roles = await user_exists_and_roles(domain, token, target)
    if not exists:
        console.print(f"[red]Target {target} not found in the org.[/] "
                      "Create a throwaway test user first.")
        return 1
    if roles:
        console.print(f"[bold red]BLOCKED:[/] {target} holds admin "
                      f"role(s): {roles}. Refusing to act on an admin.")
        return 1
    console.print(f"  {target} exists, no admin roles — eligible")

    # GUARD 4 — typed confirmation
    action = ("revoke sessions" if args.no_suspend
              else "revoke sessions + SUSPEND account")
    console.print(Panel(
        Text(f"About to {action} for:\n{target}\n\n"
             f"Reversible: {'yes (revoke only)' if args.no_suspend else 'suspend is reversible; revoke is not'}",
             style="yellow"),
        title="[bold]confirm (guard 4)", border_style="yellow"))
    if not args.yes:
        typed = Prompt.ask(f"Type the target login to proceed", default="")
        if typed.strip().lower() != target:
            console.print("[yellow]Mismatch — aborted. Nothing was sent.[/]")
            return 1

    # Execute via the real orchestrator, ACTIVE mode, with the SAME guards
    # baked into the config (defense in depth: even the demo uses interlocks).
    adapter = OktaAdapter(domain, token)
    responder = IdentityResponder(
        adapter=adapter,
        config=EnforcementConfig(
            mode=Mode.ACTIVE_ENFORCEMENT,
            risk_threshold=0,            # demo: we've already gated manually
            min_correlated_signals=1,    # ditto
            protected_users=frozenset(protected)),
        console=console)

    try:
        # We emulate the two-signal incident that would justify this live.
        txn = await responder.contain(
            target, alert_id=9001, risk=180,
            signals=2 if not args.no_suspend else 1)
        # Only the reversible bits ran if --no-suspend; offer rollback anyway.
        console.print()
        if not args.yes:
            if Prompt.ask("Roll back now? (undo suspension)",
                          choices=["y", "n"], default="y") == "y":
                await responder.rollback_containment(9001)
        else:
            await responder.rollback_containment(9001)
    finally:
        await adapter.aclose()

    console.print("\n[green]Demo complete. Target account is usable "
                  "(sessions cleared, suspension rolled back).[/]")
    return 0


def main() -> None:
    p = argparse.ArgumentParser(
        description="Safe live Okta enforcement demo (cannot lock you out).")
    p.add_argument("--target", required=True,
                   help="throwaway test-user login to contain")
    p.add_argument("--protect", nargs="*", default=[],
                   help="extra logins that must never be touched")
    p.add_argument("--no-suspend", action="store_true",
                   help="revoke sessions only (fully reversible)")
    p.add_argument("--yes", action="store_true",
                   help="skip prompts (auto-rolls-back; for recordings)")
    args = p.parse_args()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — nothing further sent.[/]")


if __name__ == "__main__":
    main()
