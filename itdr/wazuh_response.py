"""
itdr.wazuh_response
===================
Containment that actually touches the endpoint, via Wazuh Active
Response.

This is the piece that makes the whole build real. Every other adapter
in this project asks an identity provider to invalidate something
abstract; Active Response reaches the machine the attacker is logged
into and drops their packets at its firewall.

    ITDRAlert ─▶ IdentityResponder ─▶ WazuhActiveResponseAdapter
                                          │ PUT /active-response
                                          ▼
                                     wazuh-manager
                                          │ (agent protocol)
                                          ▼
                                  wazuh-agent on the host
                                     firewall-drop  ──▶ iptables / netsh
                                     disable-account ─▶ passwd -l

Honest capability mapping
-------------------------
The `BaseIdPAdapter` contract was written for Okta and Entra, and two of
its four primitives have no host analogue. Rather than return True and
imply work that never happened, those report unsupported and the
transaction records them as skipped:

    revoke_user_sessions  -> firewall-drop the source IP. Not literally
                             session revocation, but it severs the
                             attacker's network path, which is the
                             operative effect on a host.
    quarantine_account    -> disable-account. Real: locks the account.
    invalidate_tokens     -> UNSUPPORTED. Hosts don't issue tokens.
    enforce_mfa_reset     -> UNSUPPORTED. PAM has no MFA to reset here.

Prerequisites on the manager
----------------------------
`firewall-drop` ships enabled in the stock ossec.conf. `disable-account`
does NOT — it needs a <command>/<active-response> block, and it only
works on Linux agents. See deploy/wazuh/README.md. An adapter method
whose command isn't configured returns False rather than raising, so a
partially-configured manager degrades instead of breaking containment.

Safety
------
Blocking is destructive and trivially weaponized: an attacker who can
forge a source IP can make you firewall your own users off. Three
guards, all on by default:

  1. A never-block list (RFC1918 by default, plus anything configured)
     so a lab can't firewall its own management network.
  2. Timeout-bounded blocks — Wazuh AR reverses `firewall-drop` after
     its configured timeout, so a false positive self-heals.
  3. The engine's existing interlocks upstream (ACTIVE_ENFORCEMENT mode,
     risk threshold, minimum correlated signals) still gate every call.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

from .wazuh import WazuhAPIClient, WazuhAPIError

log = logging.getLogger("itdr.wazuh_response")


@dataclass
class ActiveResponseConfig:
    """Tuning for endpoint containment."""
    # AR command names as configured in ossec.conf. The '!' prefix is
    # required by the API — it means "a script named in ossec.conf".
    block_command: str = "!firewall-drop"
    disable_command: str = "!disable-account"
    # Never firewall these, whatever the risk score says.
    never_block: frozenset = frozenset()
    # Excludes everything Python's ipaddress calls private — RFC1918,
    # plus loopback, link-local, CGNAT and the reserved documentation
    # ranges. Off by default because in a lab the "attacker" is usually
    # another VM on the same bridge, and blocking it can cut the manager
    # off from its own agents.
    block_private_ips: bool = False
    # Agents to act on when the alert's endpoint can't be resolved.
    # Empty = act on nothing (fail closed).
    fallback_agents: list[str] = field(default_factory=list)


class WazuhActiveResponseAdapter:
    """Endpoint containment through the Wazuh manager's AR subsystem.

    Satisfies the `BaseIdPAdapter` protocol so it drops straight into
    the existing `IdentityResponder` playbook with no changes there.

    `user_identity` arrives as the bare account name. The endpoint and
    source IP it should act on are supplied out of band via
    `set_target()` before the playbook runs, because the protocol's
    signature only carries the identity.
    """
    name = "wazuh-active-response"

    def __init__(self, client: WazuhAPIClient,
                 config: Optional[ActiveResponseConfig] = None):
        self.client = client
        self.cfg = config or ActiveResponseConfig()
        self._agent_cache: dict[str, str] = {}      # agent name -> id
        self._target_ip: Optional[str] = None
        self._target_agents: list[str] = []
        self.calls: list[str] = []                  # audit for dashboards

    # -- targeting -------------------------------------------------------

    def set_target(self, source_ip: Optional[str] = None,
                   agent_names: Optional[list[str]] = None) -> None:
        """Bind the next containment run to a source IP and endpoints."""
        self._target_ip = source_ip
        self._target_agents = agent_names or []

    async def _resolve_agents(self) -> list[str]:
        """Agent names -> numeric agent ids the API expects."""
        if not self._target_agents:
            return list(self.cfg.fallback_agents)
        unknown = [n for n in self._target_agents
                   if n not in self._agent_cache]
        if unknown:
            try:
                agents = await asyncio.to_thread(self.client.agents)
                for a in agents:
                    if a.get("name") and a.get("id"):
                        self._agent_cache[a["name"]] = a["id"]
            except (WazuhAPIError, Exception) as e:     # noqa: BLE001
                log.warning("agent lookup failed: %s", e)
        ids = [self._agent_cache[n] for n in self._target_agents
               if n in self._agent_cache]
        if not ids:
            log.warning("no agent ids resolved for %s; falling back to %s",
                        self._target_agents, self.cfg.fallback_agents)
            return list(self.cfg.fallback_agents)
        return ids

    def _blockable(self, ip: Optional[str]) -> tuple[bool, str]:
        if not ip or ip in ("0.0.0.0", ""):
            return False, "no source IP on the alert (local/console login)"
        if ip in self.cfg.never_block:
            return False, f"{ip} is on the never-block list"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"{ip} is not a valid IP"
        if addr.is_loopback:
            return False, "refusing to block loopback"
        if addr.is_private and not self.cfg.block_private_ips:
            return False, (f"{ip} is in private/reserved space and "
                           "block_private_ips is off (set it to act "
                           "inside a lab network)")
        return True, "ok"

    # -- BaseIdPAdapter contract -----------------------------------------

    async def revoke_user_sessions(self, user_identity: str) -> bool:
        """Firewall-drop the attacker's source IP on the endpoint(s).

        The nearest honest equivalent of session revocation on a host:
        it doesn't tear down the PAM session record, it severs the path
        the session runs over.
        """
        ok, why = self._blockable(self._target_ip)
        if not ok:
            log.warning("skipping IP block for %s: %s", user_identity, why)
            self.calls.append(f"block_skipped:{user_identity}:{why}")
            return False

        agent_ids = await self._resolve_agents()
        if not agent_ids:
            log.warning("no agents resolved; not blocking %s", self._target_ip)
            self.calls.append(f"block_skipped:{user_identity}:no agents")
            return False

        try:
            await asyncio.to_thread(
                self.client.run_active_response,
                self.cfg.block_command, agent_ids, None,
                {"data": {"srcip": self._target_ip}})
        except Exception as e:                          # noqa: BLE001
            log.warning("firewall-drop failed for %s: %s", self._target_ip, e)
            return False

        log.info("firewall-drop %s on agents %s", self._target_ip, agent_ids)
        self.calls.append(f"blocked:{self._target_ip}:{','.join(agent_ids)}")
        return True

    async def quarantine_account(self, user_identity: str,
                                 suspend: bool = True) -> bool:
        """Lock (or unlock) the OS account on the endpoint(s).

        Reversible, which is what makes it the rollback anchor for a
        false-positive disposition.
        """
        agent_ids = await self._resolve_agents()
        if not agent_ids:
            self.calls.append(f"quarantine_skipped:{user_identity}:no agents")
            return False
        if not suspend:
            # Wazuh's stock disable-account has no enable path; unlocking
            # is a deliberate human step. Say so rather than report a
            # success that didn't happen.
            log.warning("account unlock for %s must be done on the host "
                        "(`passwd -u %s`); stock Wazuh AR cannot reverse "
                        "disable-account", user_identity, user_identity)
            self.calls.append(f"unquarantine_manual:{user_identity}")
            return False
        try:
            await asyncio.to_thread(
                self.client.run_active_response,
                self.cfg.disable_command, agent_ids, None,
                {"data": {"dstuser": user_identity}})
        except Exception as e:                          # noqa: BLE001
            log.warning("disable-account failed for %s: %s (is the "
                        "<active-response> block configured?)",
                        user_identity, e)
            return False
        log.info("disable-account %s on agents %s", user_identity, agent_ids)
        self.calls.append(f"quarantined:{user_identity}:{','.join(agent_ids)}")
        return True

    async def invalidate_tokens(self, user_identity: str) -> bool:
        """Not applicable to host telemetry — hosts issue no tokens."""
        log.info("invalidate_tokens is not applicable to a Wazuh endpoint "
                 "(%s); skipping rather than reporting false success",
                 user_identity)
        self.calls.append(f"unsupported:invalidate_tokens:{user_identity}")
        return False

    async def enforce_mfa_reset(self, user_identity: str) -> bool:
        """Not applicable — PAM here has no enrolled MFA factors."""
        log.info("enforce_mfa_reset is not applicable to a Wazuh endpoint "
                 "(%s); skipping rather than reporting false success",
                 user_identity)
        self.calls.append(f"unsupported:enforce_mfa_reset:{user_identity}")
        return False

    async def aclose(self) -> None:
        return None


def build_wazuh_adapter_from_env():
    """Construct the AR adapter from environment, or None if the manager
    API isn't configured. Never raises — absent config just means the
    caller keeps whatever adapter it already had."""
    import os
    url = os.environ.get("WAZUH_API_URL", "").strip()
    user = os.environ.get("WAZUH_API_USER", "").strip()
    pw = os.environ.get("WAZUH_API_PASSWORD", "").strip()
    if not (url and user and pw):
        return None

    verify_raw = os.environ.get("WAZUH_VERIFY_TLS", "false").strip()
    verify: bool | str
    if verify_raw.lower() in ("true", "false", ""):
        verify = verify_raw.lower() == "true"
    else:
        verify = verify_raw                     # a CA bundle path

    never = {x.strip() for x in
             os.environ.get("WAZUH_NEVER_BLOCK", "").split(",") if x.strip()}
    cfg = ActiveResponseConfig(
        never_block=frozenset(never),
        block_private_ips=os.environ.get(
            "WAZUH_BLOCK_PRIVATE_IPS", "false").lower() == "true",
        fallback_agents=[x.strip() for x in os.environ.get(
            "WAZUH_FALLBACK_AGENTS", "").split(",") if x.strip()],
    )
    client = WazuhAPIClient(url, user, pw, verify=verify)
    return WazuhActiveResponseAdapter(client, cfg)
