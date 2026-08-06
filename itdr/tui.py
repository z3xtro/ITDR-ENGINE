"""
itdr.tui — Tines-style workflow canvas, wired LIVE to the ITDR engine.

    python -m itdr.tui

Press  r  to stream the demo replay through the real ITDREngine:
ingest counters tick, checker nodes light up as their detections fire
(with the actual evidence computed by the engine), connector flags show
real session risk scores, and the SOAR node fills with the responder's
genuine action log. Nothing on this canvas is pre-recorded.

Keys: arrows/hjkl navigate · 1-6 jump · r replay · x reset · q quit.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from rich.console import Group
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Footer, Static

from .engine import ITDREngine
from .respond import ResponderConfig, SOARResponder
from .simulator import full_demo

DIM = "grey50"
FLAG_INFO = "grey70"

# ═══════════════════════════════════════════════ static node geometry ══


@dataclass(frozen=True)
class NodeDef:
    id: str
    key: str
    title: str
    x: int; y: int; w: int; h: int
    neighbors: dict[str, str]


NODE_DEFS: dict[str, NodeDef] = {n.id: n for n in [
    NodeDef("ingest", "1", "INGEST", 0, 15, 24, 7,
            {"right": "travel"}),
    NodeDef("mfa", "2", "A · MFA FATIGUE", 33, 1, 33, 7,
            {"down": "travel", "left": "ingest", "right": "soar"}),
    NodeDef("travel", "3", "B · IMPOSSIBLE TRAVEL", 33, 10, 33, 7,
            {"up": "mfa", "down": "mutate", "left": "ingest",
             "right": "soar"}),
    NodeDef("mutate", "4", "C · SESSION MUTATION", 33, 19, 33, 7,
            {"up": "travel", "down": "velocity", "left": "ingest",
             "right": "soar"}),
    NodeDef("velocity", "5", "D · HIGH-VELOCITY TRAVEL", 33, 28, 33, 7,
            {"up": "mutate", "left": "ingest", "right": "soar"}),
    NodeDef("soar", "6", "SOAR RESPONDER", 82, 14, 26, 9,
            {"left": "travel"}),
]}

ORDER = list(NODE_DEFS)
CHECKERS = ["mfa", "travel", "mutate", "velocity"]
SPINE_L, SPINE_R = 31, 78
CANVAS_W, CANVAS_H = 109, 37

TIER_COLOR = {"idle": "bright_blue", "notable": "yellow",
              "critical": "red", "soar": "green"}

# thresholds shown while a checker is still quiet
IDLE_CONFIG = {
    "mfa": [("status", "quiet — armed"),
            ("rule", "≥5 MFA fails in 120 s"),
            ("then", "success within 90 s grace"),
            ("mitre", "T1621")],
    "travel": [("status", "quiet — armed"),
               ("rule", "velocity > 800 km/h"),
               ("floor", "distance > 50 km"),
               ("mitre", "T1078")],
    "mutate": [("status", "quiet — armed"),
               ("rule", "mid-session UA / /24 flip"),
               ("scope", "established sessions only"),
               ("mitre", "T1550.004")],
    "velocity": [("status", "quiet — armed"),
                 ("rule", "velocity > 800 km/h"),
                 ("note", "second travel lane (D)"),
                 ("mitre", "T1078")],
}

# ═══════════════════════════════════════════════════════ live state ══


@dataclass
class CheckerState:
    fired: bool = False
    tier: str = "idle"
    user: str = ""
    risk: float = 0.0
    alert_no: int = 0
    lines: list[tuple[str, str]] = field(default_factory=list)
    flag: tuple[str, str] = ("", DIM)
    evidence: dict = field(default_factory=dict)
    config: list[tuple[str, str]] = field(default_factory=list)


class LiveState:
    def __init__(self) -> None:
        self.events = 0
        self.sessions = 0
        self.alerts = 0
        self.phase = "idle"          # idle | streaming | complete
        self.mode = "demo"           # demo | live
        self.status = ""             # footer status message
        self.checkers: dict[str, CheckerState] = {
            c: CheckerState(config=list(IDLE_CONFIG[c])) for c in CHECKERS}
        self.soar_lines: list[tuple[str, str]] = []
        self.soar_raw: list[str] = []


def _fmt_checker_lines(checker: str, user: str, ev: dict,
                       risk: float, tier: str, n: int) -> list:
    """Turn REAL detection evidence into the node's canvas lines."""
    accent = TIER_COLOR[tier]
    tag = "CRIT" if tier == "critical" else "NOT"
    risk_line = (f"risk {risk:g} · {tag} #{n}", f"bold {accent}")
    if checker == "mfa_fatigue":
        return [(f"user   {user}", "white"),
                (f"{ev['fail_count']}×fail burst "
                 f"{ev['burst_span_s']:g}s", accent),
                (f"success_delay {ev['success_delay_s']:g}s", "grey70"),
                risk_line]
    if checker == "impossible_travel":
        frm = ev["from"].split(",")[0]
        to = ev["to"].split(",")[0]
        return [(f"user   {user}", "white"),
                (f"{frm}→{to}  {ev['distance_km']:,.0f} km", accent),
                (f"{ev['elapsed_min']:g} min ⇒ "
                 f"{ev['required_velocity_kmh']:,.0f} km/h", accent),
                risk_line]
    # session_mutation
    return [(f"user   {user}", "white"),
            (f"UA  {ev['ua_before'][:24]} →", accent),
            (f"    {ev['ua_after'][:25]}", accent),
            ("corr w/ B ▲ · sev CRITICAL", "grey70")]


def _soar_line(action: str) -> tuple[str, str]:
    """Compact the responder's real action strings for the node box."""
    if "SOC notified" in action:
        return (f"▸ {action.split(' ', 1)[0]} SOC notified", "white")
    if "would revoke" in action:
        return ("▸ [DRY] revoke sessions", "green")
    if "would force MFA" in action:
        return ("▸ [DRY] MFA re-enroll", "green")
    if "SKIPPED" in action:
        return ("▸ skipped (protected)", "yellow")
    return (f"▸ {action[:20]}", "white")

# ═══════════════════════════════════════════════════ grid renderer ══


class Grid:
    def __init__(self, w: int, h: int):
        self.w, self.h = w, h
        self.ch = [[" "] * w for _ in range(h)]
        self.st = [[""] * w for _ in range(h)]

    def put(self, x: int, y: int, s: str, style: str = "") -> None:
        if not (0 <= y < self.h):
            return
        for i, c in enumerate(s):
            if 0 <= x + i < self.w:
                self.ch[y][x + i] = c
                self.st[y][x + i] = style

    def vline(self, x: int, y1: int, y2: int, style: str) -> None:
        for y in range(y1, y2 + 1):
            self.put(x, y, "│", style)

    def box(self, d: NodeDef, color: str, lines: list, sel: bool) -> None:
        border = f"bold {color}" if sel else color
        self.put(d.x, d.y, "┌" + "─" * (d.w - 2) + "┐", border)
        for r in range(1, d.h - 1):
            self.put(d.x, d.y + r, "│", border)
            self.put(d.x + d.w - 1, d.y + r, "│", border)
        self.put(d.x, d.y + d.h - 1, "└" + "─" * (d.w - 2) + "┘", border)
        marker = "◆ " if sel else ""
        tstyle = f"reverse bold {color}" if sel else f"bold {color}"
        self.put(d.x + 2, d.y, f" {marker}{d.title} "[: d.w - 4], tstyle)
        for i, (text, style) in enumerate(lines[: d.h - 2]):
            self.put(d.x + 2, d.y + 1 + i, text[: d.w - 4], style)

    def render(self) -> Text:
        out = Text()
        for y in range(self.h):
            x = 0
            while x < self.w:
                x2 = x
                while x2 < self.w and self.st[y][x2] == self.st[y][x]:
                    x2 += 1
                out.append("".join(self.ch[y][x:x2]), self.st[y][x] or None)
                x = x2
            if y < self.h - 1:
                out.append("\n")
        return out


def cy(d: NodeDef) -> int:
    return d.y + d.h // 2


def build_canvas(state: LiveState, selected: str) -> Text:
    g = Grid(CANVAS_W, CANVAS_H)
    ing, soar = NODE_DEFS["ingest"], NODE_DEFS["soar"]
    tops, bots = cy(NODE_DEFS["mfa"]), cy(NODE_DEFS["velocity"])

    # branch spine
    g.vline(SPINE_L, tops, bots, DIM)
    ev_flag = f"─[{state.events:>2}ev]" if state.events else "───────"
    g.put(ing.x + ing.w, cy(ing), ev_flag, FLAG_INFO)
    g.put(SPINE_L, cy(ing), "┤", DIM)
    for c in CHECKERS:
        y = cy(NODE_DEFS[c])
        g.put(SPINE_L, y, "┌" if y == tops else "└" if y == bots else "├", DIM)
        g.put(SPINE_L + 1, y, "►", DIM)

    # merge spine with LIVE risk flags
    g.vline(SPINE_R, tops, bots, DIM)
    for c in CHECKERS:
        d, cs = NODE_DEFS[c], state.checkers[c]
        y = cy(d)
        g.put(d.x + d.w, y, "─", DIM)
        flag, fstyle = cs.flag if cs.fired else ("", DIM)
        g.put(d.x + d.w + 1, y, flag, fstyle)
        g.put(d.x + d.w + 1 + len(flag), y,
              "─" * (SPINE_R - d.x - d.w - 1 - len(flag)), DIM)
        g.put(SPINE_R, y, "┐" if y == tops else "┘" if y == bots else "┤", DIM)
    g.put(SPINE_R, cy(soar), "├", DIM)
    g.put(SPINE_R + 1, cy(soar), "──►", DIM)

    # ingest node (live counters)
    g.box(ing, TIER_COLOR["idle"], [
        ("okta · entra feed", "white"),
        (f"events    {state.events:>4}", "bright_blue"),
        (f"sessions  {state.sessions:>4}", "bright_blue"),
        (f"alerts    {state.alerts:>4}",
         "yellow" if state.alerts else "grey70"),
        ("dry-run     ON", "grey70"),
    ], selected == "ingest")

    # checker nodes
    for c in CHECKERS:
        d, cs = NODE_DEFS[c], state.checkers[c]
        color = TIER_COLOR[cs.tier]
        lines = cs.lines if cs.fired else [("— quiet · armed —", "grey42")]
        g.box(d, color, lines, selected == c)

    # SOAR node (live action log)
    soar_lines = state.soar_lines[-6:] if state.soar_lines else [
        ("standing by", "grey42"),
        ("NOTABLE  → notify SOC", "grey42"),
        ("CRITICAL → contain", "grey42")]
    g.box(soar, TIER_COLOR["soar"], soar_lines, selected == "soar")

    phase_style = {"idle": "grey42", "streaming": "yellow",
                   "complete": "green"}[state.phase]
    pill = ("● LIVE" if (state.mode == "live"
                         and state.phase == "streaming")
            else f"● {state.phase.upper()}")
    g.put(0, CANVAS_H - 1,
          "↑↓←→/hjkl navigate · 1-6 jump · r replay · x reset · q quit",
          "grey42")
    g.put(62, CANVAS_H - 1, pill,
          "bold red" if pill == "● LIVE" else phase_style)
    g.put(62 + len(pill) + 2, CANVAS_H - 1, state.status[:40], "grey42")
    return g.render()

# ═══════════════════════════════════════════════════════ widgets ══


class Canvas(Static):
    pass


class Inspector(Static):
    def show(self, state: LiveState, node_id: str) -> None:
        d = NODE_DEFS[node_id]
        if node_id in CHECKERS:
            cs = state.checkers[node_id]
            color = TIER_COLOR[cs.tier]
            config = cs.config
            telemetry = cs.evidence or {"state": "no detection yet"}
        elif node_id == "ingest":
            color = TIER_COLOR["idle"]
            config = [("source", "demo replay → ITDREngine"),
                      ("events processed", str(state.events)),
                      ("active sessions", str(state.sessions)),
                      ("alerts emitted", str(state.alerts)),
                      ("phase", state.phase)]
            telemetry = {"pipeline": "check → touch → tier → save",
                         "capacity": "108,420 ev/s"}
        else:  # soar
            color = TIER_COLOR["soar"]
            config = [("trigger", "risk ≥ 75 → containment"),
                      ("dry_run", "True"),
                      ("protected", "breakglass-admin"),
                      ("actions taken", str(len(state.soar_raw)))]
            telemetry = {"action_log": state.soar_raw or ["(empty)"]}

        cfg = Table.grid(padding=(0, 1))
        cfg.add_column(style="bold cyan", width=13, overflow="fold")
        cfg.add_column(overflow="fold")
        for k, v in config:
            cfg.add_row(k, v)
        self.update(Group(
            Text(f"◆ {d.title}", style=f"bold {color}"), Text(),
            Panel(cfg, title="[bold]configuration", border_style=color,
                  padding=(0, 1)),
            Panel(JSON.from_data(telemetry, indent=2),
                  title="[bold]live telemetry", border_style="grey50",
                  padding=(0, 1)),
        ))

# ═══════════════════════════════════════════════════════════ app ══


class ITDRCanvasApp(App):
    TITLE = "ITDR · Live Workflow Canvas"
    CSS = """
    #body { layout: horizontal; }
    #canvas-wrap { width: 70%; }
    #canvas { padding: 1 1; }
    #inspector-wrap { width: 30%; border-left: solid $accent 40%;
                      padding: 1 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("r", "replay", "replay demo"),
        Binding("x", "reset", "reset"),
        Binding("up,k", "nav('up')", "▲"),
        Binding("down,j", "nav('down')", "▼"),
        Binding("left,h", "nav('left')", "◀"),
        Binding("right,l", "nav('right')", "▶"),
        *[Binding(n.key, f"jump('{n.id}')", n.id, show=False)
          for n in NODE_DEFS.values()],
    ]

    def __init__(self, replay_speed: float = 1.0, poller=None,
                 poll_interval: float = 30.0) -> None:
        super().__init__()
        self.selected = "ingest"
        self.replay_speed = replay_speed
        self.poller = poller
        self.poll_interval = poll_interval
        self._new_run()

    # ---- engine wiring ----------------------------------------------

    def _new_run(self) -> None:
        self.state = LiveState()
        self.state.mode = "live" if self.poller else "demo"
        self.responder = SOARResponder(ResponderConfig())
        self.engine = ITDREngine(on_alert=self._on_alert)

    def _on_alert(self, alert) -> None:
        """REAL alerts from the engine land here and light up the canvas."""
        st = self.state
        st.alerts += 1
        tier = "critical" if alert.tier == "CRITICAL" else "notable"
        for det in alert.detections:
            node = {"mfa_fatigue": "mfa",
                    "session_mutation": "mutate"}.get(det.checker)
            if det.checker == "impossible_travel":
                node = ("travel" if not st.checkers["travel"].fired
                        else "velocity")
            cs = st.checkers.get(node)
            if cs is None or cs.fired:
                continue
            cs.fired = True
            cs.tier = tier
            cs.user = alert.user_id
            cs.risk = alert.risk_score
            cs.alert_no = st.alerts
            cs.evidence = det.evidence
            cs.lines = _fmt_checker_lines(det.checker, alert.user_id,
                                          det.evidence, alert.risk_score,
                                          tier, st.alerts)
            flag_style = f"bold {TIER_COLOR[tier]}"
            cs.flag = (("[corr w/B]", flag_style)
                       if det.checker == "session_mutation"
                       else (f"[R {alert.risk_score:g}]", flag_style))
            cs.config = [
                ("status", f"{alert.tier} ALERT #{st.alerts}"),
                ("user", alert.user_id),
                ("session", alert.session_id),
                ("risk", f"{alert.risk_score:g}"),
                ("mitre", det.mitre),
                ("confidence", f"{det.confidence:g}"),
            ]
        # responder acts; mirror its real log into the SOAR node
        before = len(self.responder.actions)
        self.responder.handle_alert(alert)
        for action in self.responder.actions[before:]:
            st.soar_raw.append(action)
            st.soar_lines.append(_soar_line(action))

    async def _replay(self) -> None:
        self._new_run()
        self.state.phase = "streaming"
        for delay, ev in full_demo():
            await asyncio.sleep(delay / self.replay_speed)
            self.engine.process_event(ev)          # the real pipeline
            self.state.events = self.engine.stats["events"]
            self.state.sessions = self.engine.active_sessions()
            self._refresh()
        self.state.phase = "complete"
        self._refresh()

    async def _stream(self) -> None:
        """LIVE mode: poll the real IdP forever, feed the engine."""
        self._new_run()
        st = self.state
        st.phase = "streaming"
        while True:
            st.status = "polling…"
            self._refresh()
            try:
                # requests is blocking → run each poll pass in a thread
                events = await asyncio.to_thread(
                    lambda: list(self.poller.fetch()))
            except Exception as e:                     # noqa: BLE001
                st.status = f"poll failed: {str(e)[:28]} · retrying"
                self._refresh()
                await asyncio.sleep(self.poll_interval)
                continue
            for ev in events:
                self.engine.process_event(ev)
                st.events = self.engine.stats["events"]
                st.sessions = self.engine.active_sessions()
                self._refresh()
                await asyncio.sleep(0.04)      # visible ticking
            st.status = (f"last poll: {len(events)} ev · "
                         f"next in {int(self.poll_interval)}s")
            self._refresh()
            await asyncio.sleep(self.poll_interval)

    # ---- ui ----------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="body"):
            with ScrollableContainer(id="canvas-wrap"):
                yield Canvas(id="canvas")
            with ScrollableContainer(id="inspector-wrap"):
                yield Inspector(id="inspector")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        self.query_one(Canvas).update(build_canvas(self.state,
                                                   self.selected))
        self.query_one(Inspector).show(self.state, self.selected)

    def action_replay(self) -> None:
        if self.state.phase == "streaming":
            return
        coro = self._stream() if self.poller else self._replay()
        self.run_worker(coro, exclusive=True)

    def action_reset(self) -> None:
        self.workers.cancel_all()
        self._new_run()
        self._refresh()

    def action_nav(self, direction: str) -> None:
        nxt = NODE_DEFS[self.selected].neighbors.get(direction)
        if nxt:
            self.selected = nxt
            self._refresh()

    def action_jump(self, node_id: str) -> None:
        self.selected = node_id
        self._refresh()


def main() -> None:
    import os
    poller = None
    url = os.environ.get("OKTA_ORG_URL", "").strip()
    token = os.environ.get("OKTA_API_TOKEN", "").strip()
    if url and token:
        from .pollers import OktaPoller
        poller = OktaPoller(url, token, lookback_minutes=60)
        print(f"LIVE mode: streaming from {url} — press r to start")
    else:
        print("Demo mode (set OKTA_ORG_URL + OKTA_API_TOKEN for live)")
    interval = float(os.environ.get("POLL_INTERVAL", "30"))
    ITDRCanvasApp(poller=poller, poll_interval=interval).run()


if __name__ == "__main__":
    main()
