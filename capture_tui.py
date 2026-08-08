"""Capture the actual ITDR demo TUI as an image via Rich's SVG export."""

from pathlib import Path

import itdr.__main__ as demo
from rich.console import Console
from rich.panel import Panel

# Swap in a recording console at a README-friendly width
console = Console(record=True, width=106, force_terminal=True)
demo.console = console

from itdr.engine import ITDREngine
from itdr.respond import ResponderConfig, SOARResponder
from itdr.simulator import full_demo

responder = SOARResponder(ResponderConfig(dry_run=True,
                                          audit_log="/tmp/audit.jsonl"))
engine = ITDREngine(on_alert=lambda a: (demo.render_alert(a),
                                        responder.handle_alert(a)))

console.print(Panel("ITDR analytics engine — demo replay — "
                    "[bold]DRY-RUN (passive compliance mode)",
                    border_style="cyan"))

for _, ev in full_demo():
    console.print(
        f"[dim]{ev.timestamp:%H:%M:%S}[/] "
        f"[cyan]{ev.event_type.value:<34}[/] "
        f"{ev.event_result.value:<7} {ev.user_id:<12} "
        f"{ev.geo_city:<10} {ev.client_ip:<16} "
        f"[dim]{ev.user_agent[:18]}[/]")
    engine.process_event(ev)

console.print()
s = engine.stats
console.print(Panel(f"events={s['events']}  detections={s['detections']}  "
                    f"alerts={s['alerts']}  active_sessions="
                    f"{engine.active_sessions()}",
                    title="run summary", border_style="green"))
console.print("[bold]responder action log:")
for a in responder.actions:
    style = "yellow" if "DRY-RUN" in a else "white"
    console.print(f"  [{style}]{a}")

# Relative to this file, so the capture works from any checkout rather
# than only the machine it was first written on.
_out = Path(__file__).resolve().parent / "docs" / "tui-demo.svg"
_out.parent.mkdir(parents=True, exist_ok=True)
console.save_svg(str(_out), title="python -m itdr  ·  ITDR Engine")
print(f"SVG saved -> {_out}")
