#!/usr/bin/env python3
"""
soar_demo.py — the Wazuh → ITDR → TheHive pipeline, end to end, with no
infrastructure required.

    python soar_demo.py                 # fully offline (fake TheHive)
    python soar_demo.py --live-thehive  # POST to a real TheHive 5

Feeds Wazuh-shaped alerts through the real mapper, the real engine, the
real containment responder (DRY_RUN), and the real TheHive bridge —
against a recording transport unless --live-thehive is passed. What you
see is the actual pipeline, not a narration of one.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from itdr.engine import ITDREngine
from itdr.respond import ResponderConfig, SOARResponder
from itdr.thehive import (TheHiveBridge, TheHiveClient, TheHiveConfig,
                          alert_from_itdr, build_bridge_from_env)
from itdr.wazuh import map_wazuh_alert

console = Console()


def wazuh_alert(user, ip, agent, ts, geo, ok=True):
    country, city, lat, lon = geo
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "id": "5715" if ok else "5760",
            "level": 3 if ok else 5,
            "description": ("sshd: authentication success."
                            if ok else "sshd: authentication failed."),
            "groups": ["syslog", "sshd",
                       "authentication_success" if ok
                       else "authentication_failed"]},
        "agent": {"id": "001", "name": agent, "ip": "10.0.0.11"},
        "predecoder": {"program_name": "sshd"},
        "data": {"srcip": ip, "dstuser": user},
        "GeoLocation": {"country_name": country, "city_name": city,
                        "location": {"lat": lat, "lon": lon}},
    }


def scenario():
    """A real compromise shape: the user works from Berlin, then an
    attacker guesses the password from Sydney and gets in."""
    t0 = datetime.now(timezone.utc) - timedelta(minutes=6)
    yield wazuh_alert("alice", "203.0.113.7", "web-01", t0,
                      ("Germany", "Berlin", 52.52, 13.40))
    for i in range(11):
        yield wazuh_alert("alice", "198.51.100.9", "web-01",
                          t0 + timedelta(minutes=3, seconds=3 * i),
                          ("Australia", "Sydney", -33.87, 151.21), ok=False)
    yield wazuh_alert("alice", "198.51.100.9", "web-01",
                      t0 + timedelta(minutes=4),
                      ("Australia", "Sydney", -33.87, 151.21))


class RecordingSession:
    """Stands in for a TheHive server: records the calls the bridge makes
    and hands back plausible ids so the pipeline chains."""

    def __init__(self):
        self.calls = []
        self.headers = {}

    def request(self, method, url, json=None, timeout=None, verify=None):
        path = url.split("/api/v1", 1)[1]
        self.calls.append((method, path, json))
        body = {"ok": True}
        if path == "/alert":
            body = {"_id": "~8200"}
        elif path.endswith("/case"):
            body = {"_id": "~12328", "number": 41}
        elif path.endswith("/task"):
            body = {"_id": "~16424"}
        return _Resp(body)


class _Resp:
    def __init__(self, body):
        self._b, self.status_code = body, 200
        self.content = b"{}"

    def json(self):
        return self._b

    def raise_for_status(self):
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-thehive", action="store_true",
                    help="POST to the real TheHive at $THEHIVE_URL")
    args = ap.parse_args()

    if args.live_thehive:
        bridge = build_bridge_from_env()
        if bridge is None:
            console.print("[red]--live-thehive needs THEHIVE_URL and "
                          "THEHIVE_API_KEY set.[/]")
            return 2
        recorder = None
        console.print(f"[bold]Live mode:[/] {bridge.client.base}")
    else:
        recorder = RecordingSession()
        bridge = TheHiveBridge(TheHiveClient(
            TheHiveConfig(url="http://thehive.local:9000", api_key="demo"),
            session=recorder))

    responder = SOARResponder(ResponderConfig(
        dry_run=True, audit_log="itdr_audit.jsonl"))
    fired = []

    def on_alert(alert):
        before = len(responder.actions)
        responder.handle_alert(alert)
        actions = responder.actions[before:]
        case_id = bridge.record(alert, containment_actions=actions)
        fired.append((alert, actions, case_id))

    engine = ITDREngine(on_alert=on_alert)

    console.print(Panel(
        "[bold]Wazuh → ITDR → TheHive[/]\n"
        "sshd auth records from agent [cyan]web-01[/] "
        "(1 legit login, 11 failures, 1 success)",
        border_style="cyan", title="stage 1 · ingestion"))

    table = Table(box=None, pad_edge=False)
    for col in ("time", "user", "src ip", "geo", "result"):
        table.add_column(col, style="dim" if col == "time" else "")
    events = 0
    for rec in scenario():
        ev = map_wazuh_alert(rec)
        if ev is None:
            continue
        events += 1
        engine.process_event(ev)
        if events <= 3 or events >= 12:
            style = ("green" if ev.event_result.value == "SUCCESS"
                     else "red")
            table.add_row(ev.timestamp.strftime("%H:%M:%S"), ev.user_id,
                          ev.client_ip, f"{ev.geo_city}, {ev.geo_country}",
                          f"[{style}]{ev.event_result.value}[/]")
        elif events == 4:
            table.add_row("…", "…", "…", "…", "[dim]8 more failures[/]")
    console.print(table)
    console.print(f"\n[dim]{events} events · "
                  f"{engine.stats['detections']} detections · "
                  f"{engine.stats['alerts']} alerts[/]\n")

    if not fired:
        console.print("[yellow]no alert fired[/]")
        return 1

    alert, actions, case_id = fired[-1]
    console.print(Panel(
        "\n".join(f"[bold]{d.title}[/]  "
                  f"{d.severity.name} × {d.confidence} = "
                  f"[bold]{d.risk_points}[/] pts   [dim]{d.mitre}[/]"
                  for d in alert.detections)
        + f"\n\n[bold]session risk {alert.risk_score}[/] → "
          f"[bold red]{alert.tier}[/]",
        border_style="red", title="stage 2 · correlated detection"))

    console.print(Panel(
        "\n".join(f"• {a}" for a in actions),
        border_style="yellow", title="stage 3 · containment (DRY_RUN)"))

    if recorder is not None:
        payload = next(b for m, p, b in recorder.calls if p == "/alert")
        console.print(Panel(
            Syntax(json.dumps(payload, indent=2)[:1400], "json",
                   theme="ansi_dark", word_wrap=True),
            border_style="blue",
            title="stage 4 · TheHive alert payload"))
        flow = Table(box=None)
        flow.add_column("method", style="cyan")
        flow.add_column("endpoint")
        for m, p, _ in recorder.calls:
            flow.add_row(m, p)
        console.print(Panel(flow, border_style="blue",
                            title="stage 5 · case pipeline calls"))
    else:
        console.print(Panel(f"case [bold]{case_id}[/] opened in TheHive",
                            border_style="blue", title="stage 4 · case"))

    console.print(Panel(
        "Analyst marks it a false positive:\n"
        "  [cyan]bridge.close_false_positive(alert.id)[/]  → case closed FP\n"
        "  [cyan]await responder.rollback_containment(alert.id)[/]  → "
        "unsuspends the account\n"
        "[dim]Revoked sessions and reset MFA can't be un-revoked — the "
        "user just re-authenticates.[/]",
        border_style="cyan", title="stage 6 · disposition"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
