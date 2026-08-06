"""
itdr.enrichment
===============
IP reputation enrichment. Real SOCs never score a raw IP in isolation —
they enrich it first. This module classifies a client IP as TOR exit,
hosting/VPN ASN, or clean, and the result feeds extra risk into
detections (a login is more suspicious from a TOR exit than from a
residential ISP).

Offline-first: ships with a small static TOR/hosting-range set so it
works with zero network and zero API keys (the demo and CI need no
internet). `refresh_tor_list()` can pull the live Tor Project exit list
when network is available, but it's never required.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

log = logging.getLogger("itdr.enrichment")

# A small, offline seed set. Real deployments refresh from the live
# Tor exit list; these are stable, well-known research/demo values.
_STATIC_TOR_EXITS = {
    "185.220.101.42", "185.220.100.240", "185.220.101.1",
    "171.25.193.25", "204.13.164.118", "192.42.116.16",
}

# Hosting / VPN / bulletproof ASNs (by CIDR seed). Logins from these
# are inherently more suspicious than residential ISP space.
# Cloud-datacenter blocks matter for a second reason: IdP backend and
# integration records carry infrastructure IPs (e.g. Okta on AWS
# us-west-2 geolocates to "Boardman, United States") and must never be
# mistaken for a human's location. Real deployments load the full
# published cloud ranges (AWS ip-ranges.json etc.); these are seeds.
_HOSTING_RANGES = [
    ipaddress.ip_network("185.220.100.0/22"),   # tor-heavy
    ipaddress.ip_network("204.13.164.0/22"),
    ipaddress.ip_network("45.132.192.0/22"),     # common VPS
    ipaddress.ip_network("193.29.13.0/24"),
    # AWS us-west-2 (Boardman, OR) + common AWS blocks
    ipaddress.ip_network("44.224.0.0/11"),
    ipaddress.ip_network("34.208.0.0/12"),
    ipaddress.ip_network("52.32.0.0/11"),
    ipaddress.ip_network("54.184.0.0/13"),
    ipaddress.ip_network("35.160.0.0/13"),
]


@dataclass(frozen=True)
class IPReputation:
    ip: str
    is_tor: bool
    is_hosting: bool
    risk_bonus: int          # extra points contributed to a detection
    tags: tuple[str, ...]

    @property
    def label(self) -> str:
        return ", ".join(self.tags) if self.tags else "clean"


class IPEnricher:
    def __init__(self, tor_exits: set[str] | None = None):
        self.tor_exits = set(tor_exits or _STATIC_TOR_EXITS)

    def refresh_tor_list(self, timeout: float = 5.0) -> bool:
        """Best-effort pull of the live Tor exit list. Returns success."""
        try:
            import requests
            r = requests.get("https://check.torproject.org/exit-addresses",
                             timeout=timeout)
            r.raise_for_status()
            exits = {ln.split()[1] for ln in r.text.splitlines()
                     if ln.startswith("ExitAddress")}
            if exits:
                self.tor_exits |= exits
                log.info("tor list refreshed: %d exits", len(self.tor_exits))
                return True
        except Exception as e:                         # noqa: BLE001
            log.warning("tor refresh failed (offline is fine): %s", e)
        return False

    def _is_hosting(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in _HOSTING_RANGES)

    def enrich(self, ip: str) -> IPReputation:
        is_tor = ip in self.tor_exits
        is_hosting = self._is_hosting(ip)
        tags, bonus = [], 0
        if is_tor:
            tags.append("TOR_EXIT")
            bonus += 20
        if is_hosting and not is_tor:
            tags.append("HOSTING_ASN")
            bonus += 12
        return IPReputation(ip=ip, is_tor=is_tor, is_hosting=is_hosting,
                            risk_bonus=bonus, tags=tuple(tags))


# process-wide default enricher (checkers import this)
DEFAULT_ENRICHER = IPEnricher()
