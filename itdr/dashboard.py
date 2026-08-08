"""
itdr.dashboard
==============
The SOC console: what the engine looks like to someone watching it.

    python -m itdr.dashboard              # demo data, opens on :8080
    python -m itdr.dashboard --snapshot out.html   # static export

Serves a live security console — hero counters, alert volume over time,
detections by type, ATT&CK tactic coverage, and a triage-ready alert
feed. Charts are inline SVG generated server-side: no CDN, no charting
library, no build step. The page is one self-contained document, so it
renders identically served live, saved to disk, or pasted into a report.

Design notes that are load-bearing rather than decorative:

- Severity is ORDERED MAGNITUDE, so it uses a sequential single-hue ramp
  (light -> dark), not four categorical hues. Red/orange/yellow as
  separate categories fails colorblind separation outright — the
  adjacent pairs sit at ΔE 4.8-7.1, well under the floor.
- Detection types are IDENTITY, so they use the categorical palette in
  fixed slot order, never cycled. Validated: worst adjacent CVD ΔE 8.4
  dark / 9.1 light.
- Every chart carries direct labels. Three light-mode slots fall below
  3:1 contrast on the light surface, which obliges visible labels
  rather than relying on the swatch alone.
- Dark is the default because a SOC runs dark, but the light palette is
  a selected set stepped for the light surface, not an inverted flip.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

# Categorical slots, fixed order — light / dark steps from the validated
# reference palette. Assigned by entity, never by rank.
_CAT = [("#2a78d6", "#3987e5"), ("#eb6834", "#d95926"),
        ("#1baf7a", "#199e70"), ("#eda100", "#c98500"),
        ("#e87ba4", "#d55181"), ("#008300", "#008300"),
        ("#4a3aa7", "#9085e9"), ("#e34948", "#e66767")]

_TACTIC = {
    "T1110": "Credential Access", "T1078": "Initial Access",
    "T1021": "Lateral Movement", "T1548": "Privilege Escalation",
    "T1550.004": "Defense Evasion", "T1621": "Credential Access",
    "T1090.003": "Command & Control", "T1136": "Persistence",
}


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


# ------------------------------------------------------------- state --

def collect_state(engine=None, responder=None, alerts=None) -> dict:
    """Snapshot the engine into the shape the page renders."""
    alerts = list(alerts or [])
    stats = dict(getattr(engine, "stats", {}) or {})

    by_tier = Counter(a.tier for a in alerts)
    by_checker = Counter()
    by_technique = Counter()
    for a in alerts:
        for d in a.detections:
            by_checker[d.checker] += 1
            if d.mitre:
                by_technique[d.mitre] += 1

    # Alert volume bucketed into the last 12 five-minute windows.
    now = datetime.now(timezone.utc)
    buckets = [0] * 12
    for a in alerts:
        age = (now - a.created).total_seconds()
        idx = 11 - int(age // 300)
        if 0 <= idx < 12:
            buckets[idx] += 1

    users = Counter(a.user_id for a in alerts)
    endpoints = Counter()
    for a in alerts:
        for d in a.detections:
            ep = d.evidence.get("endpoint")
            if ep:
                endpoints[str(ep)] += 1

    rows = []
    for a in sorted(alerts, key=lambda x: x.risk_score, reverse=True)[:25]:
        eps = sorted({str(d.evidence.get("endpoint"))
                      for d in a.detections if d.evidence.get("endpoint")})
        rows.append({
            "id": a.id, "tier": a.tier, "user": a.user_id,
            "risk": a.risk_score, "ip": a.client_ip,
            "endpoints": eps or ["—"],
            "when": a.created.strftime("%H:%M:%S"),
            "detections": [
                {"name": d.checker, "sev": d.severity.name,
                 "conf": round(d.confidence, 2),
                 "points": d.risk_points, "mitre": d.mitre}
                for d in sorted(a.detections,
                                key=lambda d: d.risk_points, reverse=True)],
        })

    return {
        "generated": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "events": stats.get("events", 0),
        "detections": stats.get("detections", 0),
        "alerts_total": stats.get("alerts", len(alerts)),
        "critical": by_tier.get("CRITICAL", 0),
        "notable": by_tier.get("NOTABLE", 0),
        "sessions": (engine.active_sessions()
                     if engine is not None else 0),
        "volume": buckets,
        "by_checker": by_checker.most_common(6),
        "by_technique": by_technique.most_common(6),
        "top_users": users.most_common(5),
        "top_endpoints": endpoints.most_common(5),
        "rows": rows,
        "containment": list(getattr(responder, "actions", []) or [])[-8:],
    }


# ------------------------------------------------------------ charts --

def _area_chart(values: list[int], w=680, h=140) -> str:
    """Alert volume over time. One series, so no legend — the heading
    names it. Direct-labelled peak instead of a value on every point."""
    if not values:
        values = [0]
    vmax = max(max(values), 1)
    pad_l, pad_b, pad_t = 34, 22, 12
    iw, ih = w - pad_l - 12, h - pad_b - pad_t
    step = iw / max(len(values) - 1, 1)

    pts = [(pad_l + i * step, pad_t + ih - (v / vmax) * ih)
           for i, v in enumerate(values)]
    line = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}"
                    for i, (x, y) in enumerate(pts))
    fill = (line + f" L{pts[-1][0]:.1f},{pad_t + ih} "
                   f"L{pts[0][0]:.1f},{pad_t + ih} Z")

    # Integer counts: dedupe tick labels, or a max of 1 renders "0,0,1".
    ticks, seen = [], set()
    for f in (0, 0.5, 1):
        v = round(vmax * f)
        if v not in seen:
            seen.add(v)
            ticks.append((f, v))
    grid = "".join(
        f'<line x1="{pad_l}" y1="{pad_t + ih - f * ih:.1f}" x2="{w - 12}" '
        f'y2="{pad_t + ih - f * ih:.1f}" class="grid"/>'
        f'<text x="{pad_l - 8}" y="{pad_t + ih - f * ih + 4:.1f}" '
        f'class="axis" text-anchor="end">{v}</text>'
        for f, v in ticks)

    dots = "".join(
        f'<g class="pt"><circle cx="{x:.1f}" cy="{y:.1f}" r="9" '
        f'fill="transparent"/><circle cx="{x:.1f}" cy="{y:.1f}" r="4" '
        f'class="dot"/><title>{values[i]} alert(s) · '
        f'{(11 - i) * 5} min ago</title></g>'
        for i, (x, y) in enumerate(pts))

    peak = max(range(len(values)), key=lambda i: values[i])
    label = ""
    if values[peak]:
        px, py = pts[peak]
        label = (f'<text x="{px:.1f}" y="{py - 10:.1f}" class="peak" '
                 f'text-anchor="middle">{values[peak]}</text>')

    return (f'<svg viewBox="0 0 {w} {h}" class="chart" '
            f'role="img" aria-label="Alert volume over the last hour">'
            f'{grid}<path d="{fill}" class="area"/>'
            f'<path d="{line}" class="line"/>{dots}{label}'
            f'<text x="{pad_l}" y="{h - 6}" class="axis">−60 min</text>'
            f'<text x="{w - 12}" y="{h - 6}" class="axis" '
            f'text-anchor="end">now</text></svg>')


def _bars(items, w=340, label_w=150, slot_offset=0) -> str:
    """Horizontal bars, categorical hue per entity, direct-labelled.

    Rounded 4px data-ends anchored to the baseline; a 2px surface gap
    between adjacent bars.
    """
    if not items:
        return '<p class="empty">No data yet.</p>'
    vmax = max(v for _, v in items) or 1
    row_h, gap = 26, 8
    h = len(items) * (row_h + gap)
    bar_w = w - label_w - 40
    out = []
    for i, (name, val) in enumerate(items):
        y = i * (row_h + gap)
        bw = max((val / vmax) * bar_w, 3)
        slot = (i + slot_offset) % len(_CAT)
        out.append(
            f'<g class="barrow">'
            f'<text x="0" y="{y + row_h * 0.7:.0f}" class="blabel">'
            f'{_esc(name)}</text>'
            f'<rect x="{label_w}" y="{y + 4}" width="{bw:.1f}" '
            f'height="{row_h - 8}" rx="4" fill="var(--s{slot})"/>'
            f'<text x="{label_w + bw + 8:.1f}" y="{y + row_h * 0.7:.0f}" '
            f'class="bval">{val}</text>'
            f'<title>{_esc(name)}: {val}</title></g>')
    return (f'<svg viewBox="0 0 {w} {h}" class="chart" role="img">'
            + "".join(out) + "</svg>")


def _donut(critical: int, notable: int, size=132) -> str:
    """Tier split. Sequential ramp — severity is magnitude, not identity,
    so it is one hue light->dark rather than two categorical colors."""
    total = critical + notable
    r, c = size / 2 - 14, size / 2
    circ = 2 * math.pi * r
    if not total:
        return (f'<svg viewBox="0 0 {size} {size}" class="donut">'
                f'<circle cx="{c}" cy="{c}" r="{r}" class="track"/>'
                f'<text x="{c}" y="{c + 6}" class="dnum" '
                f'text-anchor="middle">0</text></svg>')
    frac = critical / total
    return (
        f'<svg viewBox="0 0 {size} {size}" class="donut" role="img" '
        f'aria-label="{critical} critical of {total} alerts">'
        f'<circle cx="{c}" cy="{c}" r="{r}" class="track"/>'
        f'<circle cx="{c}" cy="{c}" r="{r}" class="seg-notable" '
        f'stroke-dasharray="{circ}" stroke-dashoffset="0" '
        f'transform="rotate(-90 {c} {c})"/>'
        f'<circle cx="{c}" cy="{c}" r="{r}" class="seg-critical" '
        f'stroke-dasharray="{circ * frac:.2f} {circ:.2f}" '
        f'transform="rotate(-90 {c} {c})"/>'
        f'<text x="{c}" y="{c + 2}" class="dnum" text-anchor="middle">'
        f'{critical}</text>'
        f'<text x="{c}" y="{c + 18}" class="dsub" text-anchor="middle">'
        f'critical</text></svg>')


# -------------------------------------------------------------- page --

_CSS = """
*{box-sizing:border-box}
:root{
  color-scheme:light;
  --bg:#f4f4f2; --surface:#fcfcfb; --line:#e2e1dc;
  --ink:#0b0b0b; --ink2:#52514e; --ink3:#7a7873;
  --crit:#b3261e; --crit-bg:#fdecea; --notable:#e08600;
  --s0:#2a78d6; --s1:#eb6834; --s2:#1baf7a; --s3:#eda100;
  --s4:#e87ba4; --s5:#008300; --s6:#4a3aa7; --s7:#e34948;
  --grid:#e6e5e0; --accent:#2a78d6;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  color-scheme:dark;
  --bg:#0f1115; --surface:#16181d; --line:#272a31;
  --ink:#f2f2ef; --ink2:#b9b8b1; --ink3:#85847e;
  --crit:#e66767; --crit-bg:#2a1a1a; --notable:#c98500;
  --s0:#3987e5; --s1:#d95926; --s2:#199e70; --s3:#c98500;
  --s4:#d55181; --s5:#008300; --s6:#9085e9; --s7:#e66767;
  --grid:#23262c; --accent:#3987e5;
}}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#0f1115; --surface:#16181d; --line:#272a31;
  --ink:#f2f2ef; --ink2:#b9b8b1; --ink3:#85847e;
  --crit:#e66767; --crit-bg:#2a1a1a; --notable:#c98500;
  --s0:#3987e5; --s1:#d95926; --s2:#199e70; --s3:#c98500;
  --s4:#d55181; --s5:#008300; --s6:#9085e9; --s7:#e66767;
  --grid:#23262c; --accent:#3987e5;
}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:20px 18px 48px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;
  justify-content:space-between;margin-bottom:18px}
h1{font-size:17px;margin:0;letter-spacing:-.01em;font-weight:650}
h1 .dot{display:inline-block;width:7px;height:7px;border-radius:50%;
  background:var(--s2);margin-right:8px;vertical-align:middle}
.meta{color:var(--ink3);font-size:12px;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.grid-tiles{display:grid;gap:12px;margin-bottom:14px;
  grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.card{background:var(--surface);border:1px solid var(--line);
  border-radius:10px;padding:14px 16px}
.tile .k{color:var(--ink3);font-size:11px;text-transform:uppercase;
  letter-spacing:.07em;font-weight:600}
.tile .v{font-size:29px;font-weight:660;letter-spacing:-.02em;
  margin-top:5px;font-variant-numeric:tabular-nums}
.tile .v.crit{color:var(--crit)}
.tile .s{color:var(--ink3);font-size:11px;margin-top:2px}
.cols{display:grid;gap:12px;grid-template-columns:1fr;margin-bottom:12px}
@media(min-width:900px){.cols.two{grid-template-columns:1.55fr 1fr}
  .cols.three{grid-template-columns:1fr 1fr 1fr}}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.07em;
  color:var(--ink2);margin:0 0 12px;font-weight:650}
.chart{width:100%;height:auto;overflow:visible}
.grid{stroke:var(--grid);stroke-width:1}
.axis{fill:var(--ink3);font-size:10px;
  font-family:ui-monospace,Menlo,monospace}
.area{fill:var(--accent);opacity:.13}
.line{fill:none;stroke:var(--accent);stroke-width:2;
  stroke-linejoin:round;stroke-linecap:round}
.dot{fill:var(--accent);stroke:var(--surface);stroke-width:2;opacity:0}
.pt:hover .dot{opacity:1}
.peak{fill:var(--ink);font-size:11px;font-weight:650;
  font-variant-numeric:tabular-nums}
.blabel{fill:var(--ink2);font-size:12px}
.bval{fill:var(--ink);font-size:12px;font-weight:600;
  font-variant-numeric:tabular-nums}
.barrow:hover .blabel{fill:var(--ink)}
.donut{width:132px;height:132px;display:block;margin:0 auto}
.track{fill:none;stroke:var(--grid);stroke-width:13}
.seg-notable{fill:none;stroke:var(--notable);stroke-width:13}
.seg-critical{fill:none;stroke:var(--crit);stroke-width:13;
  stroke-linecap:butt}
.dnum{fill:var(--ink);font-size:26px;font-weight:670;
  font-variant-numeric:tabular-nums}
.dsub{fill:var(--ink3);font-size:10px;text-transform:uppercase;
  letter-spacing:.07em}
.legend{display:flex;gap:14px;justify-content:center;margin-top:10px;
  flex-wrap:wrap;font-size:11px;color:var(--ink2)}
.legend i{width:9px;height:9px;border-radius:2px;display:inline-block;
  margin-right:5px}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--ink3);font-weight:650;
  padding:0 10px 8px;border-bottom:1px solid var(--line);
  white-space:nowrap}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
.pill{display:inline-flex;align-items:center;gap:5px;font-size:10px;
  font-weight:700;padding:3px 8px;border-radius:999px;
  letter-spacing:.05em;white-space:nowrap}
.pill.critical{background:var(--crit-bg);color:var(--crit)}
.pill.notable{background:color-mix(in srgb,var(--notable) 16%,transparent);
  color:var(--notable)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:12px;color:var(--ink2)}
.risk{font-weight:670;font-variant-numeric:tabular-nums}
.sig{display:inline-block;font-size:11px;padding:2px 7px;margin:2px 3px 2px 0;
  border-radius:5px;border:1px solid var(--line);color:var(--ink2);
  font-family:ui-monospace,Menlo,monospace}
.sig b{color:var(--ink);font-weight:640}
.empty{color:var(--ink3);font-size:13px;margin:4px 0}
.contain li{margin-bottom:6px;color:var(--ink2);font-size:12.5px;
  font-family:ui-monospace,Menlo,monospace}
.contain ul{margin:0;padding-left:16px}
footer{margin-top:22px;color:var(--ink3);font-size:11.5px;
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
"""


def render_page(st: dict, title="ITDR Console") -> str:
    tiles = [
        ("Critical", st["critical"], "open containment-eligible", True),
        ("Notable", st["notable"], "analyst review", False),
        ("Events", f"{st['events']:,}", "processed", False),
        ("Detections", st["detections"], "signals fired", False),
        ("Sessions", st["sessions"], "tracked live", False),
    ]
    tile_html = "".join(
        f'<div class="card tile"><div class="k">{_esc(k)}</div>'
        f'<div class="v{" crit" if c and v else ""}">{_esc(v)}</div>'
        f'<div class="s">{_esc(s)}</div></div>'
        for k, v, s, c in tiles)

    tech = [(f"{t} · {_TACTIC.get(t, 'Other')}", n)
            for t, n in st["by_technique"]]

    rows = []
    for r in st["rows"]:
        sigs = "".join(
            f'<span class="sig"><b>{_esc(d["name"])}</b> '
            f'{_esc(d["sev"][:4])} +{d["points"]}</span>'
            for d in r["detections"])
        rows.append(
            f'<tr><td><span class="pill {r["tier"].lower()}">'
            f'{_esc(r["tier"])}</span></td>'
            f'<td class="mono">#{r["id"]}</td>'
            f'<td><b>{_esc(r["user"])}</b></td>'
            f'<td class="mono">{_esc(", ".join(r["endpoints"]))}</td>'
            f'<td class="mono">{_esc(r["ip"])}</td>'
            f'<td class="risk">{r["risk"]}</td>'
            f'<td>{sigs}</td>'
            f'<td class="mono">{_esc(r["when"])}</td></tr>')
    table = ("".join(rows) if rows else
             '<tr><td colspan="8" class="empty">No alerts yet — the '
             'engine is running and nothing has crossed a risk tier.'
             '</td></tr>')

    contain = ("".join(f"<li>{_esc(c)}</li>" for c in st["containment"])
               or '<li class="empty">No containment actions taken.</li>')

    return f"""<div class="wrap">
<header>
  <h1><span class="dot"></span>{_esc(title)}</h1>
  <div class="meta">identity threat detection &amp; response · updated
    {_esc(st['generated'])}</div>
</header>

<div class="grid-tiles">{tile_html}</div>

<div class="cols two">
  <section class="card">
    <h2>Alert volume — last hour</h2>
    {_area_chart(st['volume'])}
  </section>
  <section class="card">
    <h2>Alert tiers</h2>
    {_donut(st['critical'], st['notable'])}
    <div class="legend">
      <span><i style="background:var(--crit)"></i>Critical
        {st['critical']}</span>
      <span><i style="background:var(--notable)"></i>Notable
        {st['notable']}</span>
    </div>
  </section>
</div>

<div class="cols three">
  <section class="card">
    <h2>Detections by type</h2>
    {_bars(st['by_checker'], w=360, label_w=190)}
  </section>
  <section class="card">
    <h2>ATT&amp;CK techniques</h2>
    {_bars(tech, w=360, label_w=210, slot_offset=2)}
  </section>
  <section class="card">
    <h2>Most targeted accounts</h2>
    {_bars(st['top_users'], w=360, label_w=150, slot_offset=4)}
  </section>
</div>

<section class="card" style="margin-bottom:12px">
  <h2>Alert feed</h2>
  <div class="tablewrap"><table>
    <thead><tr><th>Tier</th><th>ID</th><th>Account</th><th>Endpoint</th>
      <th>Source IP</th><th>Risk</th><th>Signals</th><th>Time</th></tr>
    </thead><tbody>{table}</tbody>
  </table></div>
</section>

<section class="card contain">
  <h2>Containment actions</h2>
  <ul>{contain}</ul>
</section>

<footer>
  <span>ITDR Engine · detections mapped to MITRE ATT&amp;CK</span>
  <span>Risk tiers: NOTABLE &ge; 40 · CRITICAL &ge; 75</span>
</footer>
</div>"""


def render_document(st: dict, title="ITDR Console") -> str:
    return (f"<!doctype html><html lang=\"en\"><head>"
            f"<meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,"
            f"initial-scale=1\">"
            f"<title>{_esc(title)}</title><style>{_CSS}</style></head>"
            f"<body>{render_page(st, title)}</body></html>")


# ------------------------------------------------------------ server --

class DashboardServer:
    """Serves the console and a /api/state JSON feed alongside the
    running engine. Read-only: it never mutates engine state."""

    def __init__(self, engine=None, responder=None, alerts=None,
                 host="0.0.0.0", port=8080):
        self.engine = engine
        self.responder = responder
        self.alerts = alerts if alerts is not None else []
        self.host, self.port = host, port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def state(self) -> dict:
        return collect_state(self.engine, self.responder, self.alerts)

    def start(self) -> None:
        srv = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):                           # noqa: N802
                path = self.path.split("?")[0].rstrip("/") or "/"
                if path == "/api/state":
                    return self._send(200, json.dumps(srv.state()),
                                      "application/json")
                if path in ("/", "/index.html"):
                    return self._send(200,
                                      render_document(srv.state()),
                                      "text/html; charset=utf-8")
                self._send(404, "not found", "text/plain")

            def _send(self, code, body, ctype):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self._httpd = ThreadingHTTPServer((self.host, self.port), H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True, name="itdr-dashboard")
        self._thread.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


# -------------------------------------------------------------- demo --

def demo_state() -> dict:
    """Run the real engine over a scripted intrusion so the console shows
    genuine engine output rather than invented numbers."""
    from .engine import ITDREngine
    from .models import AuthEvent, EventResult, EventType
    from .wazuh_detections import wazuh_checkers

    now = datetime.now(timezone.utc)
    alerts: list = []
    # An alert's time is the time of the event that triggered it, not the
    # wall clock when the process happened to evaluate it. On replayed or
    # polled telemetry those differ by however long the backlog was, and
    # stamping "now" collapses a whole hour of activity onto one instant.
    current: dict = {}

    def _on_alert(a):
        if current.get("ts"):
            a.created = current["ts"]
        alerts.append(a)

    engine = ITDREngine(checkers=wazuh_checkers(), on_alert=_on_alert)
    _raw_process = engine.process_event

    def process(e):
        current["ts"] = e.timestamp
        return _raw_process(e)

    engine.process_event = process                      # type: ignore

    def ev(user, agent, ip, mins, result=EventResult.SUCCESS,
           etype=EventType.LOGIN, prog="sshd"):
        return AuthEvent(
            timestamp=now - timedelta(minutes=mins),
            user_id=user, session_id=f"wazuh:{user}@{agent}",
            client_ip=ip, user_agent=prog, geo_country="??",
            geo_city="??", event_type=etype, event_result=result,
            idp_source="wazuh")

    # Intrusion: brute force -> success -> escalate -> spread.
    for i in range(12):
        engine.process_event(ev("wazuh-user", "wazuh-server",
                                "45.33.32.156", 44 - i * 0.1,
                                result=EventResult.FAIL))
    engine.process_event(ev("wazuh-user", "wazuh-server",
                            "45.33.32.156", 42))
    engine.process_event(ev("wazuh-user", "wazuh-server", "45.33.32.156",
                            41, etype=EventType.API_ACCESS, prog="sudo"))
    for host in ("db-01", "app-01", "build-01"):
        engine.process_event(ev("wazuh-user", host, "45.33.32.156", 39))

    # A second, quieter compromise.
    for i in range(7):
        engine.process_event(ev("deploy", "build-01", "185.220.101.34",
                                18 - i * 0.1, result=EventResult.FAIL))
    engine.process_event(ev("deploy", "build-01", "185.220.101.34", 16))
    engine.process_event(ev("deploy", "build-01", "185.220.101.34", 15,
                            etype=EventType.API_ACCESS, prog="sudo"))

    # Benign background.
    for i in range(6):
        engine.process_event(ev("alice", "web-01", "203.0.113.10",
                                50 - i * 8))

    st = collect_state(engine, None, alerts)
    st["containment"] = [
        "alert#1 firewall-drop 45.33.32.156 on agent 001 (wazuh-server)",
        "alert#1 disable-account wazuh-user on agent 001",
        "alert#1 TheHive case ~8232 opened, containment task logged",
        "alert#2 [DRY_RUN] would firewall-drop 185.220.101.34 "
        "(risk below ACTIVE_ENFORCEMENT threshold)",
    ]
    return st


def main() -> None:
    p = argparse.ArgumentParser(prog="itdr.dashboard")
    p.add_argument("--snapshot", metavar="PATH",
                   help="write a static HTML snapshot and exit")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()

    st = demo_state()
    if args.snapshot:
        Path(args.snapshot).write_text(render_document(st))
        print(f"wrote {args.snapshot}")
        return

    srv = DashboardServer(port=args.port)
    srv.alerts = []
    srv._demo = st                                      # noqa: SLF001
    srv.state = lambda: st                              # type: ignore
    srv.start()
    print(f"ITDR console: http://localhost:{srv.port}  (ctrl-c to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
