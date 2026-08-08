"""
itdr.wazuh_doctor
=================
Point this at a running Wazuh install and it tells you, concretely,
whether the ITDR pipeline can consume it.

    python -m itdr.wazuh_doctor

Seven checks, each independently pass/fail, run in dependency order and
reported even when an earlier one fails:

  1. config      required environment variables are present
  2. indexer     the Wazuh Indexer answers and has alert indices
  3. manager     the manager API authenticates; version reported
  4. agents      at least one agent is actively reporting
  5. alerts      authentication alerts exist in the last 24h
  6. mapping     how many of those alerts the mapper accepts, and WHY
                 the rejected ones were rejected
  7. detection   replay the real alerts through the real engine and
                 report what fired

Check 6 is the one that matters. "I'm receiving events" is easy to
believe and usually half-true — the interesting question is which of
your actual alerts become AuthEvents and which silently vanish, and
that is exactly what a naive integration hides.

Nothing here writes to Wazuh. It is read-only and safe to run against
production.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text



from .wazuh import (WazuhAPIClient, WazuhAPIError, WazuhIndexerPoller,
                    _classify, _wazuh_user, alert_agent, map_wazuh_alert,
                    silence_tls_warnings)

silence_tls_warnings()

console = Console()

PASS = "[bold green]PASS[/]"
FAIL = "[bold red]FAIL[/]"
WARN = "[bold yellow]WARN[/]"


class Doctor:
    def __init__(self):
        self.indexer_url = os.environ.get(
            "WAZUH_INDEXER_URL", "https://localhost:9200")
        self.indexer_user = os.environ.get("WAZUH_INDEXER_USER", "admin")
        self.indexer_pass = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
        self.api_url = os.environ.get(
            "WAZUH_API_URL", "https://localhost:55000")
        self.api_user = os.environ.get("WAZUH_API_USER", "wazuh-wui")
        self.api_pass = os.environ.get("WAZUH_API_PASSWORD", "")
        verify_raw = os.environ.get("WAZUH_VERIFY_TLS", "false").lower()
        self.verify: bool | str = verify_raw == "true"
        self.results: list[tuple[str, str, str]] = []
        self.raw_alerts: list[dict] = []

    def record(self, name: str, status: str, detail: str) -> None:
        self.results.append((name, status, detail))
        icon = {PASS: "✓", FAIL: "✗", WARN: "!"}.get(status, "?")
        colour = {PASS: "green", FAIL: "red", WARN: "yellow"}.get(
            status, "white")
        console.print(f"  [{colour}]{icon}[/] [bold]{name:<10}[/] {detail}")

    # -- 1 ---------------------------------------------------------------
    def check_config(self) -> bool:
        # Only the Indexer is required. The manager API is used for agent
        # inventory and Active Response containment — useful, but not
        # needed to ingest and detect, so its absence must not block a
        # run that would otherwise work.
        if not self.indexer_pass:
            self.record("config", FAIL, "missing: WAZUH_INDEXER_PASSWORD")
            return False
        if not self.api_pass:
            self.record("config", WARN,
                        f"indexer={self.indexer_url} — no "
                        "WAZUH_API_PASSWORD, so agent inventory and "
                        "containment checks will be skipped (ingestion "
                        "and detection do not need it)")
            return True
        self.record("config", PASS,
                    f"indexer={self.indexer_url} api={self.api_url} "
                    f"verify_tls={self.verify}")
        return True

    # -- 2 ---------------------------------------------------------------
    def check_indexer(self) -> bool:
        try:
            import requests
            s = requests.Session()
            s.auth = (self.indexer_user, self.indexer_pass)
            r = s.get(f"{self.indexer_url.rstrip('/')}/_cat/indices/"
                      "wazuh-alerts-*?format=json",
                      verify=self.verify, timeout=15)
            if r.status_code == 401:
                self.record("indexer", FAIL,
                            "401 — bad WAZUH_INDEXER_USER/PASSWORD")
                return False
            if r.status_code >= 400:
                self.record("indexer", FAIL,
                            f"HTTP {r.status_code}: {r.text[:120]}")
                return False
            indices = r.json()
            if not indices:
                self.record("indexer", WARN,
                            "reachable, but no wazuh-alerts-* indices yet "
                            "(no alerts have ever been written)")
                return True
            total = sum(int(i.get("docs.count") or 0) for i in indices)
            self.record("indexer", PASS,
                        f"{len(indices)} alert index/indices, "
                        f"{total:,} documents")
            return True
        except Exception as e:                          # noqa: BLE001
            self.record("indexer", FAIL, f"unreachable: {e}")
            return False

    # -- 3 ---------------------------------------------------------------
    def check_manager(self) -> Optional[WazuhAPIClient]:
        if not self.api_pass:
            self.record("manager", WARN,
                        "skipped — WAZUH_API_PASSWORD not set (needed "
                        "only for agent inventory and containment)")
            return None
        try:
            client = WazuhAPIClient(self.api_url, self.api_user,
                                    self.api_pass, verify=self.verify)
            info = client.manager_info()
            self.record("manager", PASS,
                        f"authenticated — Wazuh {info.get('version', '?')} "
                        f"({info.get('type', 'manager')})")
            return client
        except WazuhAPIError as e:
            self.record("manager", FAIL, str(e)[:160])
            return None
        except Exception as e:                          # noqa: BLE001
            self.record("manager", FAIL, f"unreachable: {e}")
            return None

    # -- 4 ---------------------------------------------------------------
    def check_agents(self, client: Optional[WazuhAPIClient]) -> bool:
        if client is None:
            status = WARN if not self.api_pass else FAIL
            self.record("agents", status, "skipped — no manager connection")
            return False
        try:
            agents = client.agents(status="active")
        except Exception as e:                          # noqa: BLE001
            self.record("agents", FAIL, f"query failed: {e}")
            return False
        # Agent 000 is the manager itself; it always shows active and
        # doesn't prove any endpoint is enrolled.
        real = [a for a in agents if a.get("id") != "000"]
        if not real:
            self.record("agents", WARN,
                        "only the manager (000) is active — no endpoint "
                        "is enrolled, so there is no real telemetry yet")
            return False
        names = ", ".join(f"{a.get('name')}({a.get('id')})" for a in real[:5])
        self.record("agents", PASS, f"{len(real)} active: {names}")
        return True

    # -- 5 ---------------------------------------------------------------
    def check_alerts(self) -> bool:
        try:
            poller = WazuhIndexerPoller(
                self.indexer_url, self.indexer_user, self.indexer_pass,
                verify=self.verify, cursor_file="/dev/null", dedupe=False)
            self.raw_alerts = poller.fetch_raw(limit=200)
        except Exception as e:                          # noqa: BLE001
            self.record("alerts", FAIL, f"query failed: {e}")
            return False
        if not self.raw_alerts:
            self.record("alerts", WARN,
                        "no authentication alerts in the last 24h — "
                        "log into an enrolled endpoint, then re-run")
            return False
        self.record("alerts", PASS,
                    f"{len(self.raw_alerts)} auth alerts in the last 24h")
        return True

    # -- 6 ---------------------------------------------------------------
    def check_mapping(self) -> bool:
        if not self.raw_alerts:
            self.record("mapping", FAIL, "skipped — no alerts to map")
            return False

        mapped, reasons = [], Counter()
        rules_ok, rules_bad = Counter(), Counter()
        for rec in self.raw_alerts:
            rid = str((rec.get("rule") or {}).get("id", "?"))
            ev = map_wazuh_alert(rec)
            if ev:
                mapped.append(ev)
                rules_ok[f"{rid} {(rec.get('rule') or {}).get('description','')[:40]}"] += 1
                continue
            # Explain the rejection precisely — this is the whole point.
            if _classify(rec) is None:
                reasons["rule not in auth taxonomy"] += 1
            elif not _wazuh_user(rec):
                reasons["no human account (machine/system identity)"] += 1
            else:
                reasons["other"] += 1
            rules_bad[f"{rid} {(rec.get('rule') or {}).get('description','')[:40]}"] += 1

        pct = 100.0 * len(mapped) / len(self.raw_alerts)
        status = PASS if mapped else FAIL
        self.record("mapping", status,
                    f"{len(mapped)}/{len(self.raw_alerts)} alerts "
                    f"become AuthEvents ({pct:.0f}%)")

        if rules_ok:
            t = Table(title="mapped", title_justify="left",
                      show_edge=False, pad_edge=False)
            t.add_column("count", justify="right", style="green")
            t.add_column("rule")
            for rule, n in rules_ok.most_common(8):
                t.add_row(str(n), rule)
            console.print(t)
        if reasons:
            t = Table(title="not mapped", title_justify="left",
                      show_edge=False, pad_edge=False)
            t.add_column("count", justify="right", style="yellow")
            t.add_column("reason")
            for reason, n in reasons.most_common():
                t.add_row(str(n), reason)
            console.print(t)
            top = ", ".join(r for r, _ in rules_bad.most_common(3))
            console.print(f"  [dim]most common unmapped rules: {top}[/]")

        self._mapped = mapped
        return bool(mapped)

    # -- 7 ---------------------------------------------------------------
    def check_detection(self) -> bool:
        mapped = getattr(self, "_mapped", [])
        if not mapped:
            self.record("detection", FAIL, "skipped — nothing mapped")
            return False

        from .engine import ITDREngine
        from .wazuh import AuthEventDeduper
        from .wazuh_detections import combined_checkers

        # Replay through the same dedupe the live poller applies, or the
        # report overstates volume: one login can arrive as 5715 + 5501.
        deduper = AuthEventDeduper()
        fired: list = []
        engine = ITDREngine(checkers=combined_checkers(),
                            on_alert=fired.append)
        for ev in sorted(mapped, key=lambda e: e.ts):
            if not deduper.is_duplicate(ev):
                engine.process_event(ev)

        s = engine.stats
        detail = (f"{s['events']} events -> {s['detections']} detections, "
                  f"{s['alerts']} alerts")
        if deduper.collapsed:
            detail += (f" ({deduper.collapsed} duplicate alert(s) collapsed "
                       "— one login can fire several Wazuh rules)")
        self.record("detection", PASS if s["detections"] else WARN, detail)

        if not s["detections"]:
            console.print(
                "  [dim]No detections is a normal result for quiet "
                "telemetry — it means the pipeline ran, not that it is "
                "broken. Generate a burst of failed SSH logins followed "
                "by a success to exercise it.[/]")
        for a in fired[:5]:
            console.print(f"  [bold red]ALERT[/] {a.summary()}")
        return True

    # -- driver ----------------------------------------------------------
    def run(self) -> int:
        console.print(Panel(
            Text("ITDR · Wazuh connectivity and pipeline diagnostic",
                 style="bold"),
            subtitle="read-only — nothing is written to Wazuh",
            border_style="cyan"))

        ok_config = self.check_config()
        if not ok_config:
            console.print(Panel(
                "Set the connection variables and re-run:\n\n"
                "  export WAZUH_INDEXER_URL=https://localhost:9200\n"
                "  export WAZUH_INDEXER_USER=admin\n"
                "  export WAZUH_INDEXER_PASSWORD=...\n"
                "  export WAZUH_API_URL=https://localhost:55000\n"
                "  export WAZUH_API_USER=wazuh-wui\n"
                "  export WAZUH_API_PASSWORD=...\n\n"
                "For the docker single-node stack the passwords are in "
                "wazuh-docker/single-node/docker-compose.yml "
                "(INDEXER_PASSWORD / API_PASSWORD).",
                title="next step", border_style="yellow"))
            return 1

        self.check_indexer()
        client = self.check_manager()
        self.check_agents(client)
        if self.check_alerts():
            self.check_mapping()
            self.check_detection()

        failed = [n for n, s, _ in self.results if s == FAIL]
        warned = [n for n, s, _ in self.results if s == WARN]
        console.print()
        if failed:
            console.print(Panel(
                f"failed: {', '.join(failed)}",
                title="result", border_style="red"))
            return 1
        if warned:
            console.print(Panel(
                f"usable, with gaps: {', '.join(warned)}",
                title="result", border_style="yellow"))
            return 0
        console.print(Panel(
            "All checks passed — the engine can consume this Wazuh "
            "install.\n\nRun it for real:\n"
            "  IDP=wazuh-indexer python -m itdr.service",
            title="result", border_style="green"))
        return 0


def main() -> int:
    try:
        return Doctor().run()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
