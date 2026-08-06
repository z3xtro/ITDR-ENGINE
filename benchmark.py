"""
benchmark.py — engine throughput measurement.

    python benchmark.py [--events 200000] [--users 500]

Generates a realistic event mix (mostly benign, ~2% attack-shaped) and
measures sustained single-thread throughput through the full pipeline
(all three checkers + risk aggregation + session state).
"""

from __future__ import annotations

import argparse
import random
import time
import uuid
from datetime import datetime, timedelta, timezone

from itdr.engine import ITDREngine
from itdr.models import AuthEvent, EventResult, EventType
from itdr.simulator import CITIES, UA_CHROME_WIN, UA_EDGE_MAC


def generate(n_events: int, n_users: int) -> list[AuthEvent]:
    rng = random.Random(7)
    cities = list(CITIES.keys())
    uas = [UA_CHROME_WIN, UA_EDGE_MAC]
    users = [f"user{i:04d}" for i in range(n_users)]
    sessions = {u: f"s-{uuid.uuid4().hex[:12]}" for u in users}
    # realistic: each user has a stable home IP; rare legitimate changes
    home_ip = {u: f"10.{rng.randint(0,255)}.{rng.randint(0,255)}."
                  f"{rng.randint(1,254)}" for u in users}
    home_ua = {u: rng.choice(uas) for u in users}
    home_city = {u: rng.choice(cities[:3]) for u in users}
    t = datetime.now(timezone.utc)
    events = []
    for i in range(n_events):
        u = rng.choice(users)
        if rng.random() < 0.001:               # occasional network move
            home_ip[u] = (f"10.{rng.randint(0,255)}."
                          f"{rng.randint(0,255)}.{rng.randint(1,254)}")
        city = home_city[u]
        country, lat, lon = CITIES[city]
        etype = rng.choices(
            [EventType.API_ACCESS, EventType.LOGIN,
             EventType.TOKEN_REFRESH, EventType.MFA_CHALLENGE],
            weights=[70, 15, 10, 5])[0]
        result = (EventResult.FAIL if (etype is EventType.MFA_CHALLENGE
                                       and rng.random() < 0.3)
                  else EventResult.SUCCESS)
        events.append(AuthEvent(
            timestamp=t + timedelta(seconds=i * 0.05),
            user_id=u, session_id=sessions[u],
            client_ip=home_ip[u],
            user_agent=home_ua[u],
            geo_country=country, geo_city=city, geo_lat=lat, geo_lon=lon,
            event_type=etype, event_result=result,
        ))
    return events


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--events", type=int, default=200_000)
    p.add_argument("--users", type=int, default=500)
    args = p.parse_args()

    print(f"generating {args.events:,} events across {args.users} users…")
    events = generate(args.events, args.users)

    engine = ITDREngine()
    start = time.perf_counter()
    for ev in events:
        engine.process_event(ev)
    elapsed = time.perf_counter() - start

    eps = args.events / elapsed
    print(f"\nprocessed  : {args.events:,} events")
    print(f"elapsed    : {elapsed:.2f} s")
    print(f"throughput : {eps:,.0f} events/sec (single thread)")
    print(f"per event  : {1e6 * elapsed / args.events:.1f} µs")
    print(f"detections : {engine.stats['detections']}  "
          f"alerts: {engine.stats['alerts']}  "
          f"sessions: {engine.active_sessions()}")


if __name__ == "__main__":
    main()
