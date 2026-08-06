"""
Mapping tests built on real Wazuh alert shapes.

The fixtures below are trimmed copies of alerts the stock ruleset
actually emits (sshd 5710/5715/5716, sudo 5402, Windows 60106/60122).
Keeping them structurally faithful is the point: a mapper tested only
against invented JSON passes right up until it meets a real manager.
"""

from __future__ import annotations

import json

import pytest

from itdr.models import EventResult, EventType
from itdr.wazuh import (alert_agent, iter_alerts_file, map_wazuh_alert,
                        _parse_ts)


def sshd_alert(rule_id="5715", user="alice", srcip="203.0.113.45",
               agent="web-01", ts="2026-08-06T14:22:31.123+0000",
               description="sshd: authentication success"):
    return {
        "timestamp": ts,
        "rule": {"id": rule_id, "level": 3, "description": description,
                 "groups": ["syslog", "sshd", "authentication_success"]},
        "agent": {"id": "001", "name": agent, "ip": "10.0.0.11"},
        "manager": {"name": "wazuh-manager"},
        "predecoder": {"program_name": "sshd", "timestamp": "Aug  6 14:22:31"},
        "decoder": {"name": "sshd"},
        "data": {"srcip": srcip, "srcport": "48122", "dstuser": user},
        "location": "/var/log/auth.log",
        "full_log": f"Aug  6 14:22:31 {agent} sshd[123]: Accepted password "
                    f"for {user} from {srcip} port 48122 ssh2",
    }


def windows_alert(rule_id="60106", user="alice", srcip="203.0.113.45"):
    return {
        "timestamp": "2026-08-06T14:25:00.000+0000",
        "rule": {"id": rule_id, "level": 3,
                 "description": "Windows logon success",
                 "groups": ["windows", "authentication_success"]},
        "agent": {"id": "002", "name": "win-01"},
        "decoder": {"name": "windows_eventchannel"},
        "data": {"win": {"eventdata": {
            "targetUserName": user, "ipAddress": srcip,
            "logonType": "10"}}},
    }


class TestClassification:
    def test_sshd_success_maps_to_successful_login(self):
        ev = map_wazuh_alert(sshd_alert("5715"))
        assert ev is not None
        assert ev.event_type is EventType.LOGIN
        assert ev.event_result is EventResult.SUCCESS
        assert ev.user_id == "alice"
        assert ev.client_ip == "203.0.113.45"
        assert ev.idp_source == "wazuh"

    @pytest.mark.parametrize("rule_id", ["5710", "5716", "5712", "5760"])
    def test_sshd_failure_rules_map_to_failed_login(self, rule_id):
        ev = map_wazuh_alert(sshd_alert(rule_id))
        assert ev is not None
        assert ev.event_result is EventResult.FAIL

    def test_sudo_maps_to_api_access_not_login(self):
        """sudo rides an established session — it must NOT look like a
        fresh login, or the session-mutation checker skips it."""
        rec = sshd_alert("5402", description="Successful sudo to ROOT")
        rec["predecoder"]["program_name"] = "sudo"
        ev = map_wazuh_alert(rec)
        assert ev is not None
        assert ev.event_type is EventType.API_ACCESS
        assert ev.event_result is EventResult.SUCCESS

    def test_session_closed_maps_to_logout(self):
        ev = map_wazuh_alert(sshd_alert("5502"))
        assert ev is not None
        assert ev.event_type is EventType.LOGOUT

    def test_unknown_rule_falls_back_to_groups(self):
        """Custom rulesets use IDs we can't enumerate; groups carry it."""
        rec = sshd_alert("100234")
        rec["rule"]["groups"] = ["custom", "authentication_failed"]
        ev = map_wazuh_alert(rec)
        assert ev is not None
        assert ev.event_result is EventResult.FAIL

    def test_non_auth_alert_is_dropped(self):
        rec = sshd_alert("550")
        rec["rule"]["groups"] = ["ossec", "syscheck"]
        rec["rule"]["description"] = "File modified"
        assert map_wazuh_alert(rec) is None


class TestIdentityExtraction:
    def test_windows_target_user_and_ip(self):
        ev = map_wazuh_alert(windows_alert())
        assert ev is not None
        assert ev.user_id == "alice"
        assert ev.client_ip == "203.0.113.45"

    def test_domain_prefix_stripped_so_identity_is_stable(self):
        """DOMAIN\\alice and alice must be one identity or cross-host
        correlation silently splits in two."""
        ev = map_wazuh_alert(windows_alert(user="CORP\\alice"))
        assert ev is not None
        assert ev.user_id == "alice"

    @pytest.mark.parametrize("user", ["SYSTEM", "-", "(unknown)",
                                      "DESKTOP-A1B2$", "LOCAL SERVICE"])
    def test_machine_accounts_are_dropped(self, user):
        assert map_wazuh_alert(windows_alert(user=user)) is None

    def test_alert_with_no_user_is_dropped(self):
        rec = sshd_alert()
        rec["data"] = {"srcip": "203.0.113.45"}
        assert map_wazuh_alert(rec) is None

    def test_srcuser_used_when_dstuser_absent(self):
        rec = sshd_alert()
        rec["data"] = {"srcip": "1.2.3.4", "srcuser": "bob"}
        ev = map_wazuh_alert(rec)
        assert ev is not None and ev.user_id == "bob"


class TestSessionIdentity:
    def test_session_key_is_user_at_endpoint(self):
        ev = map_wazuh_alert(sshd_alert(user="alice", agent="web-01"))
        assert ev.session_id == "wazuh:alice@web-01"

    def test_same_user_different_hosts_are_distinct_sessions(self):
        a = map_wazuh_alert(sshd_alert(user="alice", agent="web-01"))
        b = map_wazuh_alert(sshd_alert(user="alice", agent="db-01"))
        assert a.session_id != b.session_id

    def test_agent_recoverable_from_raw_alert(self):
        assert alert_agent(sshd_alert(agent="web-09")) == "web-09"


class TestFieldEdgeCases:
    def test_localhost_normalized_to_zero_ip(self):
        """Console logins have no meaningful source; they must not look
        like a remote IP or the new-source-IP checker misfires."""
        for local in ("127.0.0.1", "::1", "-"):
            ev = map_wazuh_alert(sshd_alert(srcip=local))
            assert ev.client_ip == "0.0.0.0"

    def test_missing_geolocation_is_not_fatal(self):
        """GeoIP is off by default — absent geo must simply mean the
        travel checker abstains, not a crash."""
        ev = map_wazuh_alert(sshd_alert())
        assert ev.geo is None
        assert ev.geo_country == "??"

    def test_geolocation_used_when_present(self):
        rec = sshd_alert()
        rec["GeoLocation"] = {"country_name": "India", "city_name": "Chennai",
                              "location": {"lat": 13.08, "lon": 80.27}}
        ev = map_wazuh_alert(rec)
        assert ev.geo is not None
        assert ev.geo.city == "Chennai"
        assert ev.geo.lat == pytest.approx(13.08)

    def test_program_name_becomes_user_agent_context(self):
        ev = map_wazuh_alert(sshd_alert())
        assert ev.user_agent == "sshd"

    @pytest.mark.parametrize("ts", [
        "2026-08-06T14:22:31.123+0000",     # Wazuh default, no colon
        "2026-08-06T14:22:31.123+00:00",    # ISO with colon
        "2026-08-06T14:22:31Z",             # Zulu
    ])
    def test_timestamp_formats_parse(self, ts):
        parsed = _parse_ts(ts)
        assert parsed.year == 2026 and parsed.hour == 14

    def test_garbage_timestamp_does_not_crash(self):
        assert _parse_ts("not-a-date") is not None


class TestFileReplay:
    def test_ndjson_replay_skips_junk_and_non_auth(self, tmp_path):
        f = tmp_path / "alerts.json"
        noise = {"timestamp": "2026-08-06T14:00:00.000+0000",
                 "rule": {"id": "550", "groups": ["syscheck"]},
                 "agent": {"name": "web-01"}, "data": {}}
        f.write_text("\n".join([
            json.dumps(sshd_alert(user="alice")),
            "{ not json",
            "",
            json.dumps(noise),
            json.dumps(sshd_alert(user="bob")),
        ]))
        users = [e.user_id for e in iter_alerts_file(f)]
        assert users == ["alice", "bob"]
