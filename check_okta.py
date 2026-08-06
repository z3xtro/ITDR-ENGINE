"""
check_okta.py — verify your Okta credentials BEFORE launching the TUI.

    $env:OKTA_ORG_URL="https://dev-XXXXX.okta.com"
    $env:OKTA_API_TOKEN="your_token"
    python check_okta.py

Confirms: URL reachable, token accepted, and shows the most recent
System Log events mapped into the engine's AuthEvent schema.
"""

import os
import sys

from itdr.pollers import OktaPoller


def main() -> None:
    url = os.environ.get("OKTA_ORG_URL", "").strip()
    token = os.environ.get("OKTA_API_TOKEN", "").strip()
    if not url or not token:
        sys.exit("Set OKTA_ORG_URL and OKTA_API_TOKEN first.\n"
                 '  $env:OKTA_ORG_URL="https://dev-XXXXX.okta.com"\n'
                 '  $env:OKTA_API_TOKEN="00abc..."')

    print(f"→ connecting to {url} ...")
    poller = OktaPoller(url, token, cursor_file=".okta_cursor.json",
                        lookback_minutes=60)
    try:
        events = list(poller.fetch())
    except Exception as e:                              # noqa: BLE001
        sys.exit(f"✗ FAILED: {e}\n"
                 "  - 401 = bad/expired token (make a new one)\n"
                 "  - name resolution error = check the org URL\n"
                 "  - token must be from Security → API → Tokens")

    print(f"✓ token accepted · {len(events)} events in the last hour\n")
    for ev in events[-10:]:
        print(f"  {ev.timestamp:%H:%M:%S}  {ev.event_type.value:<36} "
              f"{ev.event_result.value:<8} {ev.user_id:<30} "
              f"{ev.geo_city}, {ev.geo_country}  {ev.client_ip}")
    if not events:
        print("  (no events yet — log in/out of Okta once, rerun this)")
    print("\nReady. Launch the live canvas with:  python -m itdr.tui")


if __name__ == "__main__":
    main()
