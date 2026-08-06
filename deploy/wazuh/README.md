# Stage 1 — Wazuh: real agents, real auth telemetry

Bring this up **first** and confirm real events flow before touching
TheHive. Wazuh's single-node stack wants ~4 GB on its own.

## 1. Deploy Wazuh (official single-node compose)

The official repo carries the cert scaffolding the stack needs — don't
hand-roll it:

```bash
git clone -b v4.9.2 --depth 1 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Dashboard: `https://localhost` (admin / SecretPassword — change it).

## 2. Enroll one or two real agents

On an endpoint (your laptop, a VM, a spare Pi):

```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
sudo WAZUH_MANAGER=<manager-ip> dpkg -i wazuh-agent_4.9.2-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

**Checkpoint:** SSH into the endpoint (or fail a sudo password) and see
the alert appear in the dashboard under Security events. Do not proceed
until this works — everything downstream consumes these alerts.

## 3. Forward auth alerts to the ITDR engine

On the **manager** (for docker: the `wazuh.manager` container):

```bash
# from this directory
docker cp integrations/custom-itdr single-node-wazuh.manager-1:/var/ossec/integrations/custom-itdr
docker exec single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-itdr
docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-itdr
```

Add the `<integration>` block from [`ossec-integration.xml`](ossec-integration.xml)
to `/var/ossec/etc/ossec.conf` inside `<ossec_config>`, with:

- `hook_url` → `http://<engine-host>:8099/wazuh`
- `api_key`  → the same value as the engine's `WAZUH_SHARED_TOKEN`

Then restart the manager: `docker compose restart wazuh.manager`.

## 4. Run the engine in Wazuh mode

```bash
WAZUH_SHARED_TOKEN=<same-token> IDP=wazuh python -m itdr.service
# or via the root docker-compose.yml:
IDP=wazuh WAZUH_SHARED_TOKEN=<same-token> docker compose up
```

**Checkpoint:** the engine heartbeat logs `wazuh listener: received=N`
climbing as you log in/out of the agent endpoint.

## 5. Verify a detection end to end

Fail SSH auth ≥5 times quickly, then succeed — or replay a captured
`alerts.json` offline:

```python
from itdr.engine import ITDREngine
from itdr.wazuh import iter_alerts_file
eng = ITDREngine(on_alert=lambda a: print(a.summary()))
for ev in iter_alerts_file("alerts.json"):
    eng.process_event(ev)
```

When this checkpoint passes, move to Stage 2:
[`../thehive/docker-compose.yml`](../thehive/docker-compose.yml).
