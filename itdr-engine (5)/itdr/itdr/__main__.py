"""
python -m itdr            -> run the full attack-scenario demo (dry-run)
python -m itdr --live     -> same, with dry_run disabled (mock IdP only)
python -m itdr --speed 10 -> replay faster
"""

from __future__ import annotations

import argparse
import logging
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import ITDREngine
from .models import ITDRAlert
from .respond import ResponderConfig, SOARResponder
from .simulator import full_demo

logging.basicConfig(filename="itdr.log", level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

console = Console()

TIER_STYLE = {"NOTABLE": "yellow", "CRITICAL": "bold red"}


def render_alert(alert: ITDRAlert) -> None:
    t = Table.grid(padding=(0, 1))
    t.add_column(style="bold cyan", width=14)
    t.add_column()
    t.add_row("user", alert.user_id)
    t.add_row("session", alert.session_id)
    t.add_row("risk score", f"{alert.risk_score}")
    t.add_row("source", f"{alert.client_ip}  {alert.user_agent[:48]}")
    for d in alert.detections:
        ev = ", ".join(f"{k}={v}" for k, v in list(d.evidence.items())[:4])
        t.add_row(d.checker,
                  f"[{d.severity.name}] conf={d.confidence} "
                  f"{d.mitre}  {ev}")
    style = TIER_STYLE[alert.tier]
    console.print(Panel(t, title=f"[{style}]{alert.tier} ALERT #{alert.id}",
                        border_style=style))


def main() -> None:
    p = argparse.ArgumentParser(prog="itdr")
    p.add_argument("--live", action="store_true",
                   help="disable dry_run (mock IdP calls marked LIVE)")
    p.add_argument("--speed", type=float, default=1.0)
    args = p.parse_args()

    responder = SOARResponder(ResponderConfig(dry_run=not args.live))
    engine = ITDREngine(on_alert=lambda a: (render_alert(a),
                                            responder.handle_alert(a)))

    mode = "LIVE" if args.live else "DRY-RUN (passive compliance mode)"
    console.print(Panel(f"ITDR analytics engine — demo replay — [bold]{mode}",
                        border_style="cyan"))

    for delay, ev in full_demo():
        time.sleep(delay / max(args.speed, 0.01))
        console.print(
            f"[dim]{ev.timestamp:%H:%M:%S}[/] "
            f"[cyan]{ev.event_type.value:<34}[/] "
            f"{ev.event_result.value:<7} {ev.user_id:<12} "
            f"{ev.geo_city:<10} {ev.client_ip:<16} "
            f"[dim]{ev.user_agent[:34]}[/]")
        engine.process_event(ev)

    console.print()
    s = engine.stats
    summary = (f"events={s['events']}  detections={s['detections']}  "
               f"alerts={s['alerts']}  active_sessions="
               f"{engine.active_sessions()}")
    console.print(Panel(summary, title="run summary", border_style="green"))
    console.print("[bold]responder action log:")
    for a in responder.actions:
        style = "yellow" if "DRY-RUN" in a else "white"
        console.print(f"  [{style}]{a}")


if __name__ == "__main__":
    main()
