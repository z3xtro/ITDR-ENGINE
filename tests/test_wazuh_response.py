"""
Active Response containment and Indexer/API transport tests.

Everything here runs against a recording fake transport — no Wazuh
required — but asserts the exact request shapes a real manager expects,
so a wrong endpoint or payload key fails here rather than silently
no-op'ing against production.
"""

from __future__ import annotations

import json

import pytest

from itdr.wazuh import WazuhAPIClient, WazuhAPIError, WazuhIndexerPoller
from itdr.wazuh_response import (ActiveResponseConfig,
                                 WazuhActiveResponseAdapter)


class FakeResponse:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)
        self.content = self.text.encode()

    def json(self):
        return self._payload


class FakeSession:
    """Records every call and replays scripted responses."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}
        self.auth = None
        self.headers = {}
        self.default = FakeResponse(200, {"data": {}})

    def _resolve(self, method, url):
        # Match on the PATH only. '/active-response?agents_list=001'
        # contains the substring 'agents', so matching the whole URL
        # silently routes active-response calls to the agents fixture.
        path = url.split("?", 1)[0]
        for key, resp in self.responses.items():
            if key in path:
                return resp() if callable(resp) else resp
        return self.default

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self._resolve(method, url)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._resolve("POST", url)

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._resolve("GET", url)


def api_client(responses=None):
    s = FakeSession(responses or {})
    s.responses.setdefault(
        "security/user/authenticate",
        FakeResponse(200, {"data": {"token": "jwt-token"}}))
    return WazuhAPIClient("https://wazuh:55000", "wazuh-wui", "pw",
                          session=s), s


class TestAPIClient:
    def test_authenticate_sends_basic_auth_and_keeps_token(self):
        c, s = api_client()
        assert c.authenticate() == "jwt-token"
        _, url, kw = s.calls[0]
        assert "security/user/authenticate" in url
        assert kw["headers"]["Authorization"].startswith("Basic ")

    def test_subsequent_calls_use_bearer_token(self):
        c, s = api_client({"manager/info": FakeResponse(
            200, {"data": {"version": "v4.9.0"}})})
        assert c.manager_info()["version"] == "v4.9.0"
        bearer = [kw for m, u, kw in s.calls if "manager/info" in u][0]
        assert bearer["headers"]["Authorization"] == "Bearer jwt-token"

    def test_bad_credentials_raise_a_clear_error(self):
        s = FakeSession({"authenticate": FakeResponse(401, {}, "unauthorized")})
        c = WazuhAPIClient("https://wazuh:55000", "u", "bad", session=s)
        with pytest.raises(WazuhAPIError, match="authentication failed"):
            c.authenticate()

    def test_expired_token_triggers_reauth_and_retry(self):
        """Wazuh JWTs expire in 900s; a long-running service must not
        die the first time one lapses."""
        state = {"n": 0}

        def info():
            state["n"] += 1
            if state["n"] == 1:
                return FakeResponse(401, {}, "token expired")
            return FakeResponse(200, {"data": {"version": "v4.9.0"}})

        c, s = api_client({"manager/info": info})
        assert c.manager_info()["version"] == "v4.9.0"
        assert sum(1 for m, u, _ in s.calls if "authenticate" in u) == 2

    def test_active_response_payload_shape(self):
        c, s = api_client({"active-response": FakeResponse(200, {"data": {}})})
        c.run_active_response("!firewall-drop", ["001", "002"],
                              alert={"data": {"srcip": "93.184.216.34"}})
        method, url, kw = [x for x in s.calls if "active-response" in x[1]][0]
        assert method == "PUT"
        assert "agents_list=001,002" in url
        assert kw["json"]["command"] == "!firewall-drop"
        assert kw["json"]["alert"]["data"]["srcip"] == "93.184.216.34"


class TestIndexerPoller:
    def _hits(self, docs):
        return FakeResponse(200, {"hits": {"hits": [
            {"_source": d, "sort": [d.get("timestamp"), str(i)]}
            for i, d in enumerate(docs)]}})

    def _alert(self, user="alice", ts="2026-08-06T14:00:00.000Z"):
        return {"timestamp": ts,
                "rule": {"id": "5715", "groups": ["authentication_success"]},
                "agent": {"name": "web-01"},
                "predecoder": {"program_name": "sshd"},
                "data": {"srcip": "203.0.113.45", "dstuser": user}}

    def test_fetch_maps_hits_to_auth_events(self, tmp_path):
        s = FakeSession({"_search": self._hits(
            [self._alert("alice"), self._alert("bob")])})
        p = WazuhIndexerPoller("https://idx:9200", "admin", "pw", session=s,
                               cursor_file=str(tmp_path / "c.json"))
        assert [e.user_id for e in p.fetch()] == ["alice", "bob"]

    def test_query_filters_on_auth_groups_server_side(self, tmp_path):
        s = FakeSession({"_search": self._hits([])})
        p = WazuhIndexerPoller("https://idx:9200", "admin", "pw", session=s,
                               cursor_file=str(tmp_path / "c.json"))
        list(p.fetch())
        body = s.calls[0][2]["json"]
        groups = body["query"]["bool"]["filter"][1]["terms"]["rule.groups"]
        assert "authentication_success" in groups
        assert body["sort"][0] == {"timestamp": "asc"}

    def test_cursor_persists_frontier_across_restarts(self, tmp_path):
        cursor = tmp_path / "c.json"
        cursor.write_text(json.dumps({"cursor": "2026-08-06T00:00:00.000Z"}))
        s = FakeSession({"_search": self._hits(
            [self._alert(ts="2026-08-06T14:00:00.000Z"),
             self._alert(ts="2026-08-06T15:30:00.000Z")])})
        p = WazuhIndexerPoller("https://idx:9200", "admin", "pw", session=s,
                               cursor_file=str(cursor))
        list(p.fetch())
        assert json.loads(cursor.read_text())["cursor"] == \
            "2026-08-06T15:30:00.000Z"

        # A fresh poller must resume strictly after the frontier.
        s2 = FakeSession({"_search": self._hits([])})
        p2 = WazuhIndexerPoller("https://idx:9200", "admin", "pw", session=s2,
                                cursor_file=str(cursor))
        list(p2.fetch())
        rng = s2.calls[0][2]["json"]["query"]["bool"]["filter"][0]["range"]
        assert rng["timestamp"]["gt"] == "2026-08-06T15:30:00.000Z"

    def test_indexer_error_raises_rather_than_silently_returning_nothing(
            self, tmp_path):
        s = FakeSession({"_search": FakeResponse(403, {}, "forbidden")})
        p = WazuhIndexerPoller("https://idx:9200", "admin", "pw", session=s,
                               cursor_file=str(tmp_path / "c.json"))
        with pytest.raises(WazuhAPIError):
            list(p.fetch())


class TestActiveResponseSafety:
    def _adapter(self, cfg=None, responses=None):
        c, s = api_client(responses or {
            "agents": FakeResponse(200, {"data": {"affected_items": [
                {"id": "001", "name": "web-01"}]}}),
            "active-response": FakeResponse(200, {"data": {}})})
        return WazuhActiveResponseAdapter(c, cfg), s

    async def test_blocks_public_ip_on_resolved_agent(self):
        a, s = self._adapter()
        a.set_target(source_ip="93.184.216.34", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is True
        ar = [x for x in s.calls if "active-response" in x[1]][0]
        assert "agents_list=001" in ar[1]
        assert ar[2]["json"]["alert"]["data"]["srcip"] == "93.184.216.34"

    async def test_refuses_rfc1918_by_default(self):
        """A lab's 'attacker' is usually another VM on the same bridge;
        blocking it can cut the manager off from its own agents."""
        a, s = self._adapter()
        a.set_target(source_ip="192.168.1.50", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is False
        assert not [x for x in s.calls if "active-response" in x[1]]

    async def test_private_ip_blocked_when_explicitly_enabled(self):
        a, _ = self._adapter(ActiveResponseConfig(block_private_ips=True))
        a.set_target(source_ip="192.168.1.50", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is True

    async def test_never_block_list_wins_over_everything(self):
        a, _ = self._adapter(ActiveResponseConfig(
            never_block=frozenset({"93.184.216.34"})))
        a.set_target(source_ip="93.184.216.34", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is False

    async def test_refuses_loopback(self):
        a, _ = self._adapter(ActiveResponseConfig(block_private_ips=True))
        a.set_target(source_ip="127.0.0.1", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is False

    async def test_console_login_has_nothing_to_block(self):
        a, _ = self._adapter()
        a.set_target(source_ip="0.0.0.0", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is False

    async def test_fails_closed_when_no_agent_resolves(self):
        a, s = self._adapter(responses={
            "agents": FakeResponse(200, {"data": {"affected_items": []}}),
            "active-response": FakeResponse(200, {"data": {}})})
        a.set_target(source_ip="93.184.216.34", agent_names=["ghost-host"])
        assert await a.revoke_user_sessions("alice") is False
        assert not [x for x in s.calls if "active-response" in x[1]]


class TestActiveResponseCapabilities:
    def _adapter(self):
        c, s = api_client({
            "agents": FakeResponse(200, {"data": {"affected_items": [
                {"id": "001", "name": "web-01"}]}}),
            "active-response": FakeResponse(200, {"data": {}})})
        return WazuhActiveResponseAdapter(c), s

    async def test_quarantine_disables_the_account(self):
        a, s = self._adapter()
        a.set_target(agent_names=["web-01"])
        assert await a.quarantine_account("alice") is True
        ar = [x for x in s.calls if "active-response" in x[1]][0]
        assert ar[2]["json"]["command"] == "!disable-account"
        assert ar[2]["json"]["alert"]["data"]["dstuser"] == "alice"

    async def test_unsupported_primitives_report_false_not_fake_success(self):
        """The honesty guarantee: a host has no tokens and no enrolled
        MFA, so these must not claim work they never did."""
        a, s = self._adapter()
        a.set_target(agent_names=["web-01"])
        assert await a.invalidate_tokens("alice") is False
        assert await a.enforce_mfa_reset("alice") is False
        assert not [x for x in s.calls if "active-response" in x[1]]
        assert any("unsupported" in c for c in a.calls)

    async def test_unquarantine_is_manual_and_says_so(self):
        a, _ = self._adapter()
        a.set_target(agent_names=["web-01"])
        assert await a.quarantine_account("alice", suspend=False) is False
        assert any("manual" in c for c in a.calls)

    async def test_satisfies_the_adapter_protocol(self):
        from itdr.adapters import BaseIdPAdapter
        a, _ = self._adapter()
        assert isinstance(a, BaseIdPAdapter)

    async def test_manager_error_degrades_instead_of_raising(self):
        """A manager without <active-response> configured must not take
        the containment path down with it."""
        a, _ = self._adapter()
        a.client.session.responses["active-response"] = FakeResponse(
            400, {}, "command not configured")
        a.set_target(source_ip="93.184.216.34", agent_names=["web-01"])
        assert await a.revoke_user_sessions("alice") is False
