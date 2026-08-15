"""
Behavioural identity-graph tests (step 1).

These lock down the foundation the blast-radius walk stands on: edges
form from the right events, only successes grant reach, timestamps and
decay behave, and the reach queries return what step 2 will consume.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from itdr.graph import (DEFAULT_HALF_LIFE_S, EdgeType, IdentityGraph)
from itdr.models import AuthEvent, EventResult, EventType

BASE = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def ev(user, host, offset=0.0, result=EventResult.SUCCESS,
       etype=EventType.LOGIN, program="sshd"):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset),
        user_id=user, session_id=f"wazuh:{user}@{host}",
        client_ip="192.168.1.50", user_agent=program,
        geo_country="??", geo_city="??",
        event_type=etype, event_result=result, idp_source="wazuh")


class TestEdgeFormation:
    def test_successful_login_creates_auth_edge(self):
        g = IdentityGraph()
        g.observe(ev("alice", "web-01"))
        assert g.hosts_for("alice") == {"web-01"}
        assert "alice" in g.identities()
        assert "web-01" in g.hosts()

    def test_sudo_creates_root_edge_and_presence(self):
        """A root foothold implies presence: the escalation records both
        AUTHENTICATED_TO and HAS_ROOT_ON, so reach counts even when the
        preceding login was on a separate IP-less record."""
        g = IdentityGraph()
        g.observe(ev("alice", "web-01", etype=EventType.API_ACCESS,
                     program="sudo"))
        assert g.root_hosts_for("alice") == {"web-01"}
        assert "web-01" in g.hosts_for("alice")

    def test_failed_login_grants_no_reach(self):
        g = IdentityGraph()
        g.observe(ev("mallory", "web-01", result=EventResult.FAIL))
        assert g.hosts_for("mallory") == set()
        assert g.stats()["edges"] == 0

    def test_non_auth_events_are_ignored(self):
        g = IdentityGraph()
        for t in (EventType.LOGOUT, EventType.MFA_CHALLENGE,
                  EventType.TOKEN_REFRESH):
            g.observe(ev("alice", "web-01", etype=t))
        assert g.stats()["edges"] == 0

    def test_repeated_login_collapses_to_one_edge(self):
        g = IdentityGraph()
        for i in range(20):
            g.observe(ev("alice", "web-01", offset=i))
        assert g.stats()["auth_edges"] == 1
        e = g.edge("alice", "web-01", EdgeType.AUTHENTICATED_TO)
        assert e.count == 20

    def test_distinct_hosts_are_distinct_edges(self):
        g = IdentityGraph()
        g.observe(ev("alice", "web-01"))
        g.observe(ev("alice", "db-01"))
        assert g.hosts_for("alice") == {"web-01", "db-01"}


class TestReachQueries:
    """The exact surface the blast-radius walk (step 2) will call."""

    def test_identities_on_host_lists_harvestable_accounts(self):
        g = IdentityGraph()
        g.observe(ev("alice", "web-01"))
        g.observe(ev("bob", "web-01"))
        g.observe(ev("carol", "db-01"))
        assert g.identities_on("web-01") == {"alice", "bob"}
        assert g.identities_on("db-01") == {"carol"}

    def test_the_canonical_pivot_chain_is_queryable(self):
        """alice root on web-01; bob also on web-01; bob root on db-01.
        Every hop the walk needs must be answerable from the queries."""
        g = IdentityGraph()
        g.observe(ev("alice", "web-01", etype=EventType.API_ACCESS))  # root
        g.observe(ev("bob", "web-01"))                                # present
        g.observe(ev("bob", "db-01", etype=EventType.API_ACCESS))     # root
        assert "web-01" in g.root_hosts_for("alice")
        assert "bob" in g.identities_on("web-01")
        assert "db-01" in g.root_hosts_for("bob")

    def test_host_resolution_from_idp_session(self):
        """IdP sessions have no host in the id; they anchor to the
        provider so the identity still has a resource node."""
        e = AuthEvent(timestamp=BASE, user_id="alice",
                      session_id="okta-8f3c2a1b", client_ip="1.2.3.4",
                      user_agent="chrome", geo_country="US", geo_city="NYC",
                      event_type=EventType.LOGIN,
                      event_result=EventResult.SUCCESS, idp_source="okta")
        assert IdentityGraph.host_of(e) == "okta"


class TestTimeDecay:
    def test_fresh_edge_is_full_strength(self):
        g = IdentityGraph(now_fn=lambda: BASE.timestamp())
        g.observe(ev("alice", "web-01", offset=0))
        w = g.edge_weight("alice", "web-01", EdgeType.AUTHENTICATED_TO)
        assert 0.99 <= w <= 1.0

    def test_one_half_life_halves_weight(self):
        later = BASE.timestamp() + DEFAULT_HALF_LIFE_S
        g = IdentityGraph(now_fn=lambda: later)
        g.observe(ev("alice", "web-01", offset=0))
        w = g.edge_weight("alice", "web-01", EdgeType.AUTHENTICATED_TO)
        assert abs(w - 0.5) < 0.01

    def test_recency_uses_the_newest_observation(self):
        """A path re-used recently is strong even if first seen long ago."""
        clock = {"t": BASE.timestamp()}
        g = IdentityGraph(now_fn=lambda: clock["t"])
        g.observe(ev("alice", "web-01", offset=0))
        # re-observe almost a decay-window later
        g.observe(ev("alice", "web-01", offset=DEFAULT_HALF_LIFE_S - 10))
        clock["t"] = BASE.timestamp() + DEFAULT_HALF_LIFE_S
        w = g.edge_weight("alice", "web-01", EdgeType.AUTHENTICATED_TO)
        assert w > 0.99   # last_seen is recent, so barely decayed

    def test_prune_drops_stale_edges(self):
        clock = {"t": BASE.timestamp()}
        g = IdentityGraph(now_fn=lambda: clock["t"])
        g.observe(ev("alice", "web-01", offset=0))
        clock["t"] = BASE.timestamp() + DEFAULT_HALF_LIFE_S * 6  # ~1.5% wt
        removed = g.prune(min_weight=0.05)
        assert removed == 1
        assert g.hosts_for("alice") == set()
        assert g.stats()["edges"] == 0


class TestHygiene:
    def test_stats_shape(self):
        g = IdentityGraph()
        g.observe(ev("alice", "web-01"))
        g.observe(ev("alice", "web-01", etype=EventType.API_ACCESS))
        s = g.stats()
        assert s["identities"] == 1 and s["hosts"] == 1
        assert s["auth_edges"] == 1 and s["root_edges"] == 1

    def test_unknown_identity_queries_are_empty_not_errors(self):
        g = IdentityGraph()
        assert g.hosts_for("nobody") == set()
        assert g.root_hosts_for("nobody") == set()
        assert g.identities_on("nowhere") == set()
