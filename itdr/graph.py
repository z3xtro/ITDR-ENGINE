"""
itdr.graph
==========
The behavioural identity graph — the foundation of blast-radius analysis.

The idea in one line: build a live graph from the authentication events
the engine *already* ingests, so that when an identity is flagged we can
ask not just "is this compromised?" but "how much can it reach?"

Behavioural, not structural
---------------------------
This is the distinction from BloodHound and attack-path tools. Those
compute reach from a static snapshot of *permissions* — an AD ACL dump —
answering what an attacker COULD do. This graph is built from *observed
logins*: the paths that have actually been used. An edge exists because
someone authenticated over it, not because a config allows it.

    identity --AUTHENTICATED_TO--> host      (a successful login)
    identity --HAS_ROOT_ON-------> host      (a successful sudo/su)

Those two edge types are all the reachability model needs: where an
identity has been, and where it can act as root. Everything the
blast-radius walk does (step 2) is built on the queries here.

Time-decayed
------------
Reach is not permanent. A login an hour ago is stronger evidence of a
usable path than one six months ago, so every edge carries timestamps
and a half-life decay weight. Stale edges fade and can be pruned — which
also keeps the graph bounded.

Storage
-------
In-memory adjacency for now (a lab, a single process). The public API is
deliberately storage-agnostic — `observe`, `hosts_for`, `identities_on`,
`root_hosts_for` — so a Redis-backed backend (the same swap the engine's
RedisStore already uses for session state) is a change of internals, not
a rewrite. That backend is what turns this from "runs on my laptop" into
"runs for an org."

This module is pure and side-effect free: no network, no engine imports
beyond the event model. It is unit-tested in isolation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Optional

from .models import AuthEvent, EventResult, EventType

# Default decay half-life: a week. An edge exactly one half-life old has
# weight 0.5; two half-lives, 0.25; and so on. Chosen because usable
# credential paths in most environments turn over on roughly that scale
# — tune per deployment.
DEFAULT_HALF_LIFE_S = 7 * 24 * 3600


class EdgeType(str, Enum):
    AUTHENTICATED_TO = "authenticated_to"   # identity has logged into host
    HAS_ROOT_ON = "has_root_on"             # identity can act as root there


@dataclass(slots=True)
class Edge:
    """A directed, time-stamped edge from an identity to a host.

    Collapses all observations of the same (identity, host, type) into
    one edge, tracking how often and how recently it was seen — the graph
    stays small no matter how noisy the telemetry.
    """
    src: str                     # identity
    dst: str                     # host
    etype: EdgeType
    first_seen: float
    last_seen: float
    count: int = 1

    def observe(self, ts: float) -> None:
        self.count += 1
        if ts > self.last_seen:
            self.last_seen = ts
        if ts < self.first_seen:
            self.first_seen = ts

    def weight(self, now: float, half_life: float) -> float:
        """Recency-decayed strength in (0, 1]. A path used just now is
        ~1.0; one a half-life old is ~0.5; older fades toward 0."""
        age = max(now - self.last_seen, 0.0)
        return 0.5 ** (age / half_life)


class IdentityGraph:
    """A behavioural identity→host graph built from AuthEvents.

    Feed it every event via `observe`; query it for reach. Only
    *successful* events create edges — a failed login grants no path.
    """

    def __init__(self, half_life_s: float = DEFAULT_HALF_LIFE_S,
                 now_fn: Callable[[], float] = time.time):
        self.half_life_s = half_life_s
        self._now = now_fn                      # injectable for tests
        # (src, dst, etype) -> Edge
        self._edges: dict[tuple[str, str, EdgeType], Edge] = {}
        # adjacency indexes for O(1) reach queries
        self._out: dict[str, set[tuple[str, EdgeType]]] = {}   # identity ->
        self._in: dict[str, set[tuple[str, EdgeType]]] = {}    # host ->
        self._identities: set[str] = set()
        self._hosts: set[str] = set()

    # ---------------------------------------------------------- ingest --

    @staticmethod
    def host_of(ev: AuthEvent) -> str:
        """Resolve the host a session touched.

        Wazuh sessions are keyed `wazuh:{user}@{host}`, so the host is the
        suffix. IdP sessions (Okta/Entra) carry an opaque id with no host;
        fall back to the provider label so those identities still anchor
        to a resource node rather than vanishing.
        """
        sid = ev.session_id or ""
        if "@" in sid:
            return sid.rsplit("@", 1)[1]
        return ev.idp_source or "unknown"

    def observe(self, ev: AuthEvent) -> None:
        """Fold one event into the graph. Non-successful and non-relevant
        events are ignored — they grant no reach."""
        if ev.event_result is not EventResult.SUCCESS:
            return

        if ev.event_type is EventType.LOGIN:
            self._add_edge(ev.user_id, self.host_of(ev),
                           EdgeType.AUTHENTICATED_TO, ev.ts)
        elif ev.event_type is EventType.API_ACCESS:
            # sudo/su success — the identity can act as root on this host.
            host = self.host_of(ev)
            # A root foothold implies presence, so record both: it means
            # the escalation counts as reach even if the login that
            # preceded it was on a different (IP-less) record.
            self._add_edge(ev.user_id, host,
                           EdgeType.AUTHENTICATED_TO, ev.ts)
            self._add_edge(ev.user_id, host,
                           EdgeType.HAS_ROOT_ON, ev.ts)
        # LOGOUT, MFA_CHALLENGE, TOKEN_REFRESH, failures: no edge.

    def _add_edge(self, src: str, dst: str, etype: EdgeType,
                  ts: float) -> None:
        key = (src, dst, etype)
        edge = self._edges.get(key)
        if edge is None:
            self._edges[key] = Edge(src, dst, etype, ts, ts, 1)
        else:
            edge.observe(ts)
        self._out.setdefault(src, set()).add((dst, etype))
        self._in.setdefault(dst, set()).add((src, etype))
        self._identities.add(src)
        self._hosts.add(dst)

    # ----------------------------------------------------------- query --

    def hosts_for(self, identity: str) -> set[str]:
        """Hosts this identity has authenticated to."""
        return {dst for (dst, et) in self._out.get(identity, ())
                if et is EdgeType.AUTHENTICATED_TO}

    def root_hosts_for(self, identity: str) -> set[str]:
        """Hosts where this identity can act as root."""
        return {dst for (dst, et) in self._out.get(identity, ())
                if et is EdgeType.HAS_ROOT_ON}

    def identities_on(self, host: str) -> set[str]:
        """Identities that have authenticated to this host — the accounts
        an attacker with root there could harvest."""
        return {src for (src, et) in self._in.get(host, ())
                if et is EdgeType.AUTHENTICATED_TO}

    def edge(self, src: str, dst: str, etype: EdgeType) -> Optional[Edge]:
        return self._edges.get((src, dst, etype))

    def edge_weight(self, src: str, dst: str, etype: EdgeType) -> float:
        e = self._edges.get((src, dst, etype))
        return e.weight(self._now(), self.half_life_s) if e else 0.0

    def identities(self) -> set[str]:
        return set(self._identities)

    def hosts(self) -> set[str]:
        return set(self._hosts)

    def edges(self) -> Iterable[Edge]:
        return self._edges.values()

    # --------------------------------------------------------- upkeep --

    def prune(self, min_weight: float = 0.05) -> int:
        """Drop edges whose decayed weight has fallen below `min_weight`
        — stale paths an attacker could no longer realistically use.
        Keeps the graph bounded. Returns the number removed."""
        now = self._now()
        dead = [k for k, e in self._edges.items()
                if e.weight(now, self.half_life_s) < min_weight]
        for k in dead:
            e = self._edges.pop(k)
            self._out.get(e.src, set()).discard((e.dst, e.etype))
            self._in.get(e.dst, set()).discard((e.src, e.etype))
        # forget nodes that no longer have any edges
        self._identities = {e.src for e in self._edges.values()}
        self._hosts = {e.dst for e in self._edges.values()}
        return len(dead)

    def stats(self) -> dict:
        return {
            "identities": len(self._identities),
            "hosts": len(self._hosts),
            "edges": len(self._edges),
            "auth_edges": sum(1 for e in self._edges.values()
                              if e.etype is EdgeType.AUTHENTICATED_TO),
            "root_edges": sum(1 for e in self._edges.values()
                              if e.etype is EdgeType.HAS_ROOT_ON),
        }
