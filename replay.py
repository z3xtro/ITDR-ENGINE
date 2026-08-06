"""
replay.py — replay a recorded incident timeline through the engine.

    python replay.py incidents/impossible_travel.json
    python replay.py incidents/impossible_travel.json --speed 5

An incident file is a JSON list of AuthEvent records (same field names
as the AuthEvent dataclass). This makes detections reproducible: capture
a real incident once, replay it forever for demos, regression, and
tuning — closing the loop the enhancement doc asked for.

    python replay.py --export impossible_travel   # write a sample file
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from itdr.engine import ITDREngine
from itdr.models import AuthEvent, EventResult, EventType
from itdr.respond import ResponderConfig, SOARResponder
from itdr.simulator import (scenario_impossible_travel, scenario_mfa_fatigue,
                            scenario_token_theft)

SCENARIOS = {
    "impossible_travel": scenario_impossible_travel,
    "mfa_fatigue": scenario_mfa_fatigue,
    "token_theft": scenario_token_theft,
}


def event_to_record(ev: AuthEvent) -> dict:
    return {"timestamp": ev.timestamp.isoformat(), "user_id": ev.user_id,
            "session_id": ev.session_id, "client_ip": ev.client_ip,
            "user_agent": ev.user_agent, "geo_country": ev.geo_country,
            "geo_city": ev.geo_city, "geo_lat": ev.geo_lat,
            "geo_lon": ev.geo_lon, "event_type": ev.event_type.value,
            "event_result": ev.event_result.value}


def record_to_event(d: dict) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime.fromisoformat(d["timestamp"]),
        user_id=d["user_id"], session_id=d["session_id"],
        client_ip=d["client_ip"], user_agent=d["user_agent"],
        geo_country=d["geo_country"], geo_city=d["geo_city"],
        geo_lat=d.get("geo_lat"), geo_lon=d.get("geo_lon"),
        event_type=EventType(d["event_type"]),
        event_result=EventResult(d["event_result"]))


def export(name: str) -> None:
    if name not in SCENARIOS:
        sys.exit(f"unknown scenario '{name}'. choices: {list(SCENARIOS)}")
    recs = [event_to_record(ev) for _, ev in SCENARIOS[name]()]
    out = Path("incidents"); out.mkdir(exist_ok=True)
    path = out / f"{name}.json"
    path.write_text(json.dumps(recs, indent=2))
    print(f"wrote {path} ({len(recs)} events)")


def _resolve(path: str) -> Path:
    """Accept a full path, a bare filename, or a scenario name.
    Falls back to the incidents/ folder and appends .json so that
    `replay.py impossible_travel` just works after `--export`."""
    for cand in (path, f"incidents/{path}",
                 f"{path}.json", f"incidents/{path}.json"):
        p = Path(cand)
        if p.exists():
            return p
    sys.exit(f"incident file not found: {path}\n"
             f"  export one first:  python replay.py --export impossible_travel")


def replay(path: str, speed: float) -> None:
    resolved = _resolve(path)
    records = json.loads(resolved.read_text())
    responder = SOARResponder(ResponderConfig())

    def on_alert(a):
        print(f"  🚨 [{a.tier}] {a.user_id} risk={a.risk_score} "
              f"({'+'.join(sorted({d.checker for d in a.detections}))})")
        responder.handle_alert(a)

    engine = ITDREngine(on_alert=on_alert)
    print(f"▶ replaying {resolved} · {len(records)} events · x{speed}\n")
    prev_ts = None
    for d in records:
        ev = record_to_event(d)
        if prev_ts is not None:
            gap = (ev.timestamp - prev_ts).total_seconds()
            time.sleep(min(max(gap, 0), 3) / speed)
        prev_ts = ev.timestamp
        print(f"  {ev.timestamp:%H:%M:%S} {ev.event_type.value:<34} "
              f"{ev.event_result.value:<7} {ev.user_id:<12} {ev.geo_city}")
        engine.process_event(ev)

    print(f"\n✓ done · events={engine.stats['events']} "
          f"detections={engine.stats['detections']} "
          f"alerts={engine.stats['alerts']}")
    for a in responder.actions:
        print(f"    {a}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("file", nargs="?", help="incident JSON to replay")
    p.add_argument("--speed", type=float, default=1.0)
    p.add_argument("--export", metavar="NAME",
                   help=f"write a sample incident file: {list(SCENARIOS)}")
    args = p.parse_args()
    if args.export:
        export(args.export)
    elif args.file:
        replay(args.file, args.speed)
    else:
        p.error("provide an incident file or --export NAME")


if __name__ == "__main__":
    main()
