# Deployment guide

🇧🇷 [Versão em português](GUIA-DE-IMPLANTACAO.md)

Step by step for three situations. Pick yours:

| Scenario | When | Go to |
|---|---|---|
| **A** | No Zabbix yet, you want **Zabbix + Grafana** | [Scenario A](#scenario-a-new-deployment-with-grafana) |
| **B** | No Zabbix yet, you want **Zabbix only** (native dashboards) | [Scenario B](#scenario-b-new-deployment-without-grafana) |
| **C** | **Zabbix already in production** (with or without Grafana) | [Scenario C](#scenario-c-existing-zabbix) |

> The tool is meant for **local networks**: LAN, VLANs and branch offices over VPN/MPLS. Run the scan from a machine inside the network, ideally the Zabbix server or proxy itself, and only on networks you are responsible for.

---

## Shortcut: interactive wizard

If you would rather not edit files by hand, one command installs the tool and opens a wizard that covers scenarios A, B and C:

```bash
curl -fsSL https://raw.githubusercontent.com/GustavoMS0/zabbix-autodiscovery/main/install.sh | bash        # Linux, e.g. on the Zabbix server
```

```powershell
irm https://raw.githubusercontent.com/GustavoMS0/zabbix-autodiscovery/main/install.ps1 | iex               # Windows, with just the URL and an API token
```

The wizard detects a local Zabbix, validates the token, suggests networks from the IPs already in Zabbix and the machine's own IPs, writes `config.yaml` and `.env`, and runs `check`, `setup`, `scan` and `apply`. On a Zabbix that already has hosts it also offers `audit`, `organize`, add-on templates and services. Every change asks for confirmation and defaults to "no". The rest of this guide explains the same steps for doing them manually.

**Fresh server (Linux):** if no Zabbix answers on the machine, the wizard offers to install one. It installs Docker with the official script (get.docker.com, asks for your sudo password) if needed, writes `deploy/.env` with random passwords, starts Zabbix 8 (and Grafana, if you want) from `deploy/docker-compose.yml`, creates the Admin API token and changes the default Admin password. It then goes straight to networks and scanning, without opening the Zabbix frontend.

---

## Before you start (all scenarios)

**1. Machine that runs the tool.** Linux, Windows or macOS, able to reach every network to be scanned.

```bash
# Linux / macOS
git clone https://github.com/GustavoMS0/zabbix-autodiscovery
cd zabbix-autodiscovery
./zabbix-autodiscovery.sh init        # creates the Python environment, config.yaml and .env
```

```powershell
# Windows (needs uv: winget install astral-sh.uv, or Python 3.10+)
git clone https://github.com/GustavoMS0/zabbix-autodiscovery
cd zabbix-autodiscovery
.\zabbix-autodiscovery.ps1 init
```

Below, `zabbix-autodiscovery` means `./zabbix-autodiscovery.sh` (Linux) or `.\zabbix-autodiscovery.ps1` (Windows).

**2. On the devices.**
- Switches, APs, firewalls, printers and UPS: **SNMP enabled**, allowing the Zabbix IP and the scanning machine. Prefer your own community or SNMPv3 over `public`.
- Servers: **Zabbix Agent 2** with `Server=` and `ServerActive=` pointing to Zabbix. Agent 2 is also required for SSL certificate monitoring.
- Firewalls between networks: allow ICMP, UDP 161 and TCP 10050 from Zabbix and from the scanning machine.

**3. Edit `config.yaml`** (the minimum):

```yaml
zabbix:
  url: http://ZABBIX-IP:8080
scan:
  networks:
    - {network: 192.168.0.0/24, site: HQ}
    - {network: 192.168.10.0/24, site: Branch-01}
```

Secrets go in **`.env`**, next to `config.yaml`:

```
ZABBIX_TOKEN=<API token>
SNMP_COMMUNITY=<your SNMP community>
```

The group names in the rules (`Network/Switches`, `Servers/Windows`…) are free text: change them to your own convention before the first `setup`.

---

## Scenario A: new deployment WITH Grafana

**1. Start Zabbix + Grafana with Docker** (Linux server with Docker Compose):

```bash
cd deploy
cp .env.example .env
# edit .env: change EVERY password (POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD, ZABBIX_GRAFANA_PASSWORD)
docker compose --profile zabbix --profile grafana up -d
```

| Service | Address | First login |
|---|---|---|
| Zabbix | `http://SERVER:8080` | `Admin` / `zabbix` (change it) |
| Grafana | `http://SERVER:3000` | `admin` / value of `GRAFANA_ADMIN_PASSWORD` |

**2. Create the API token** in Zabbix: *Users → API tokens → Create*, for the Admin user (Super admin role). Put it in `ZABBIX_TOKEN` in the tool's `.env`.

**3. Grafana user.** Keep the `grafana_user` section in `config.yaml`. In the **tool's** `.env`, use the same user and password as `deploy/.env`:

```
ZABBIX_GRAFANA_USER=grafana
ZABBIX_GRAFANA_PASSWORD=<same as deploy/.env>
```

**4. Prepare, discover and onboard:**

```bash
zabbix-autodiscovery check                         # read-only: token and permissions
zabbix-autodiscovery setup                         # groups, templates, dashboards and the Grafana user
zabbix-autodiscovery scan -o inventory.csv         # only reads the network
#   review the CSV (";" separated): column "action" = add | review | ignore
zabbix-autodiscovery apply -i inventory.csv --dry-run
zabbix-autodiscovery apply -i inventory.csv
zabbix-autodiscovery setup --rebuild-dashboards    # dashboards with the newly added hosts
zabbix-autodiscovery maps                          # one map per site
```

**5. Grafana dashboards.** The dashboards shipped in `deploy/grafana/dashboards` use the example group names. If you renamed groups in `config.yaml`, regenerate them and restart Grafana:

```bash
zabbix-autodiscovery grafana-dashboards -o deploy/grafana/dashboards
cd deploy && docker compose restart grafana
```

In Grafana, the dashboards are in the **Zabbix AutoDiscovery** folder.

---

## Scenario B: new deployment WITHOUT Grafana

Same as scenario A, with three differences:

1. Start Zabbix only:
   ```bash
   cd deploy && cp .env.example .env     # change the passwords
   docker compose --profile zabbix up -d
   ```
   A Zabbix installed from packages, without Docker, works too.
2. In `config.yaml`, **delete the `grafana_user` section**.
3. Skip step 5. Dashboards live in Zabbix itself, under *Dashboards*, prefixed **AutoDiscovery -**: overview, switches, firewalls, APs, printers, servers, UPS, server hardware, maps, certificates and domains.

---

## Scenario C: existing Zabbix

The tool **does not change what already exists**:
- hosts already monitored (same IP or DNS) are skipped;
- a name already used with another IP is treated as a possible duplicate and skipped;
- existing macros, groups, users and dashboards are kept.

Everything it creates has the `AutoDiscovery -` prefix or the `origin=autodiscovery` tag.

**1. Token.** Create an API token for a **Super admin** user. On Zabbix 8 the role must have "API access" enabled. Point `zabbix.url` to your Zabbix.

**2. Diagnosis (nothing is changed):**

```bash
zabbix-autodiscovery check      # permissions, available templates, what would be created
zabbix-autodiscovery audit      # duplicate IPs, cloned machines, agents, unsupported items
```

**3. Find what is not monitored yet:**

```bash
zabbix-autodiscovery scan -o inventory.csv
# or in parts: scan --site HQ -o hq.csv   |   scan --network 192.168.10.0/24 -o branch.csv
zabbix-autodiscovery apply -i inventory.csv --dry-run    # check the list
zabbix-autodiscovery setup                               # groups, templates and dashboards (idempotent)
zabbix-autodiscovery apply -i inventory.csv
```

**4. Organize the hosts you already had** (optional, recommended):

```bash
zabbix-autodiscovery organize --dry-run           # type/site groups and tags that would be added
zabbix-autodiscovery organize                     # only adds; removes nothing
zabbix-autodiscovery update-templates --all       # switch port usage, printer supplies
zabbix-autodiscovery services -i inventory.csv    # service tags and checks (databases, AD, clusters)
zabbix-autodiscovery setup --rebuild-dashboards
zabbix-autodiscovery maps
```

**5. Grafana (optional):**
- **You already have Grafana:** run `zabbix-autodiscovery grafana-dashboards -o dashboards/` and import the files in *Dashboards → New → Import*. Each dashboard has a datasource selector, so it works with your existing Zabbix datasource.
- **You want a new Grafana for this Zabbix:** in `deploy/.env`, set `ZABBIX_API_URL=http://YOUR-ZABBIX/api_jsonrpc.php` and the Grafana credentials. Configure `grafana_user` in `config.yaml`, run `zabbix-autodiscovery setup` (it creates the read-only user), then start Grafana only: `docker compose --profile grafana up -d`.

---

## After the deployment: suggested routine

| How often | What to do |
|---|---|
| Monthly (or after network changes) | `scan -o new.csv` → `diff -old previous.csv -new new.csv` (new, missing or changed devices) → `apply` the new ones |
| After onboarding hosts | `setup --rebuild-dashboards` and `maps --rebuild` |
| When an agent is installed on a server | `agent-sync` (switches to agent templates and clears the "agent missing" alert) |
| From time to time | `audit` (duplicates, agents with the wrong name, unsupported items) |
| New sites or domains to watch | Add them to the `web` section of `config.yaml` and run `web` |

**In the CSV**, rows marked `review` need your decision. The `note` column explains why, for example "the device did not answer SNMP".

---

## Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| `API token expired` | Token expired | Create a new token and update `.env` |
| `check` warns about the role | User is not Super admin, or the role has no API access (Zabbix 8) | Use a Super admin or enable API access in the role |
| Server in `review` as "agent installed, scanner refused" | The scanning machine's IP is not in the agent's `Server=` | Scan from the Zabbix server, or add the IP to `Server=` |
| Network device in `review` with "no SNMP answer" | SNMP disabled or blocked by an ACL | Enable SNMP and scan again, or onboard it with ICMP only by editing the CSV |
| Hosts missing from the scan | A firewall blocks the scanning machine | Scan from the Zabbix server/proxy or open the ports |
| Empty Grafana graphs | Group names differ from the ones the dashboards use | `grafana-dashboards -o deploy/grafana/dashboards` and restart Grafana |
| Certificate shows "Unsupported item key" | The `agent2_host` runs the classic agent | Install Zabbix Agent 2 on that host |
