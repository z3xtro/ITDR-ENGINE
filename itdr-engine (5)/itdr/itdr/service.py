"""
itdr.service
============
Always-on service entry point:  python -m itdr.service

Configuration by environment variables (12-factor style):

  IDP=okta|entra|sim          telemetry source (default: sim, loops demo)
  POLL_INTERVAL=60            seconds between polling passes
  STATE_BACKEND=memory|redis  session state (default: memory)
  REDIS_URL=redis://redis:6379/0
  DRY_RUN=true|false          SOAR containment gate (default: true)
  WEBHOOK_URL=...             optional Slack/Discord alert webhook

  # okta:   OKTA_ORG_URL, OKTA_API_TOKEN
  # entra:  ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time

from .engine import ITDREngine
from .respond import ResponderConfig, SOARResponder

logging.basicConfig(
    stream=sys.stdout, level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("itdr.service")


def build_store():
    if os.environ.get("STATE_BACKEND", "memory").lower() == "redis":
        from .state import RedisStore
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        log.info("state backend: redis (%s)", url)
        return RedisStore(url=url)
    log.info("state backend: in-memory")
    return None                     # engine defaults to InMemoryStore


def build_engine() -> tuple[ITDREngine, SOARResponder]:
    dry_run = os.environ.get("DRY_RUN", "true").lower() != "false"
    responder = SOARResponder(ResponderConfig(dry_run=dry_run))

    def on_alert(alert):
        log.warning("ALERT %s", alert.summary())
        responder.handle_alert(alert)

    engine = ITDREngine(on_alert=on_alert, store=build_store())
    if os.environ.get("METRICS", "true").lower() != "false":
        from .metrics import start_metrics_server
        port = int(os.environ.get("METRICS_PORT", "9108"))
        start_metrics_server(engine, responder, port=port)
        log.info("metrics: http://0.0.0.0:%d/metrics", port)
    log.info("engine ready (dry_run=%s)", dry_run)
    return engine, responder


def main() -> None:
    engine, _ = build_engine()
    idp = os.environ.get("IDP", "sim").lower()
    interval = float(os.environ.get("POLL_INTERVAL", "60"))

    stop = {"flag": False}

    def _sig(*_):
        log.info("shutdown signal received")
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    if idp == "okta":
        from .pollers import OktaPoller
        poller = OktaPoller(os.environ["OKTA_ORG_URL"],
                            os.environ["OKTA_API_TOKEN"])
    elif idp == "entra":
        from .pollers import EntraPoller
        poller = EntraPoller(os.environ["ENTRA_TENANT_ID"],
                             os.environ["ENTRA_CLIENT_ID"],
                             os.environ["ENTRA_CLIENT_SECRET"])
    else:
        poller = None
        log.info("IDP=sim: looping demo scenarios (set IDP=okta|entra "
                 "for live telemetry)")

    while not stop["flag"]:
        try:
            if poller:
                n = 0
                for ev in poller.fetch():
                    engine.process_event(ev)
                    n += 1
                log.info("poll pass: %d events | stats=%s | sessions=%d",
                         n, engine.stats, engine.active_sessions())
            else:
                from .simulator import full_demo
                for _, ev in full_demo():
                    if stop["flag"]:
                        break
                    engine.process_event(ev)
                log.info("demo cycle complete | stats=%s", engine.stats)
        except Exception:                              # noqa: BLE001
            log.exception("pass failed; retrying next interval")
        for _ in range(int(interval)):
            if stop["flag"]:
                break
            time.sleep(1)

    log.info("service stopped cleanly")


if __name__ == "__main__":
    main()
