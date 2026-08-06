"""
itdr.metrics
============
Prometheus-format metrics. Exposes engine counters over HTTP so the
system is Grafana/Prometheus-scrapeable — a real operational signal.

Zero dependencies: emits the text exposition format by hand and serves
it from the stdlib http.server, so there's nothing extra to install.

    from itdr.metrics import start_metrics_server
    start_metrics_server(engine, responder, port=9108)
    # -> curl http://localhost:9108/metrics
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

log = logging.getLogger("itdr.metrics")


def render_metrics(engine, responder=None) -> str:
    s = engine.stats
    lines = [
        "# HELP itdr_events_total Auth events processed.",
        "# TYPE itdr_events_total counter",
        f"itdr_events_total {s['events']}",
        "# HELP itdr_detections_total Detections fired.",
        "# TYPE itdr_detections_total counter",
        f"itdr_detections_total {s['detections']}",
        "# HELP itdr_alerts_total Alerts emitted.",
        "# TYPE itdr_alerts_total counter",
        f"itdr_alerts_total {s['alerts']}",
        "# HELP itdr_sessions_pruned_total Idle sessions evicted.",
        "# TYPE itdr_sessions_pruned_total counter",
        f"itdr_sessions_pruned_total {s['sessions_pruned']}",
        "# HELP itdr_active_sessions Current live sessions.",
        "# TYPE itdr_active_sessions gauge",
        f"itdr_active_sessions {engine.active_sessions()}",
    ]
    if responder is not None:
        lines += [
            "# HELP itdr_soar_actions_total SOAR actions taken.",
            "# TYPE itdr_soar_actions_total counter",
            f"itdr_soar_actions_total {len(responder.actions)}",
        ]
    return "\n".join(lines) + "\n"


def start_metrics_server(engine, responder=None, port: int = 9108) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            body = render_metrics(engine, responder).encode()
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):        # silence access logging
            pass

    server = HTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("metrics on http://0.0.0.0:%d/metrics", port)
    return server
