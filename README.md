# zabbix-autodiscovery

[![CI](https://github.com/GustavoMS0/zabbix-autodiscovery/actions/workflows/ci.yml/badge.svg)](https://github.com/GustavoMS0/zabbix-autodiscovery/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

🇧🇷 [Leia em português](README.pt-BR.md)

**Scan your corporate networks, automatically identify infrastructure equipment, and onboard them into Zabbix with the right template, host group, interface, and tags.** Workstations and laptops are filtered out automatically. Native Zabbix dashboards are included (Grafana dashboards are optional).

> **Scope: local environments.** zabbix-autodiscovery is built for **on-premises networks**: the LAN, VLANs and branch offices reached over VPN or MPLS, scanned from a machine inside them (ideally the Zabbix server or proxy). It does not inventory cloud resources (AWS, Azure, GCP) or the internet, and it should only be run on networks you are responsible for.

```text
$ zabbix-autodiscovery scan -o inventory.csv
Scanning: 192.168.0.0/24, 192.168.10.0/24, 192.168.20.0/24
  category            action    count
  switch              add       12
  firewall            add       2
  ap                  add       16
  printer             add       8
  cctv                add       14
  server-windows      add       6
  server-hardware     add       4
  workstation         ignore    73
  unknown             ignore    110
  Host name sources (add/review): snmp=48, agent=6, netbios=4, dns=2

$ zabbix-autodiscovery apply -i inventory.csv --dry-run
  + 192.168.10.52   printer     PRN-FINANCE       [Network/Printers + Sites/Branch-01]  name via snmp
      templates: AutoDiscovery - Printer by SNMP, Generic by SNMP
  + 192.168.10.22   server-hw   idrac-SRV01       [Infrastructure/Server Hardware + Sites/Branch-01]  name via snmp
      templates: Dell iDRAC by SNMP
  = 192.168.0.1     firewall    IP already monitored, skipped
```

---

## Key Features

- **Comprehensive Concurrent Discovery:** High-speed asynchronous scanning using ICMP Ping, TCP ports, SNMP v1/v2c/v3, Zabbix Agent (passive query), NetBIOS (UDP 137), HTTP/TLS banner probing, and forward-confirmed reverse DNS. A second pass with extended timeouts prevents false negatives on busy or VPN links.
- **Name-Agnostic Classification:** Never guesses a device role based on its host name. Decides strictly by what the device answers technically (SNMP sysObjectID, sysDescr, open ports, server banner, and `system.uname`). Comes with rules for:
  - **Network & Wi-Fi:** Cisco, HPE/Aruba, H3C, Huawei, Juniper, MikroTik, TP-Link, D-Link, Ubiquiti/UniFi, Ruckus, Meraki;
  - **Firewalls & Security:** Fortinet/FortiGate, pfSense, OPNsense, Palo Alto, Sophos, SonicWall, Check Point;
  - **CCTV & IP Cameras:** Hikvision, Dahua, Intelbras (MHDX/NVD/VIP), Axis (RTSP ports 554, 8000, 37777);
  - **VoIP & IP Telephony:** Grandstream, Yealink, Asterisk, FreePBX, Issabel (SIP port 5060);
  - **Servers & Hypervisors:** Windows Server, Linux (Debian, Ubuntu, RHEL), VMware ESXi, Hyper-V, Proxmox VE, iDRAC (Dell), iLO (HPE);
  - **Power, Storage & Peripherals:** APC, Eaton, SMS, NHS UPS; managed rack PDUs; Synology, QNAP, TrueNAS storage; HP, Brother, Epson, Kyocera, Ricoh, Lexmark, Xerox, and Zebra printers.
- **Strict Workstation Exclusion:** Microsoft's SNMP sysObjectID separates workstations from servers even on Windows 11 and Windows Server 2025 (which share build 26100). On machines without SNMP, port fingerprints and the Zabbix agent prevent adding laptops or desktop PCs.
- **Detection of Servers without Agent:** Servers detected without port 10050 receive the `AutoDiscovery - Zabbix agent missing` template and tag `agent=missing`. An alert fires only while the server answers ping (preventing duplicate alerts with host down). Once the agent is installed, `agent-sync` promotes them to OS templates.
- **Change Audit & Rogue Device Detection (`diff`):** Compare two inventory scans to instantly spot newly connected network equipment (*rogue devices*), decommissioned hosts, or changes in ports and hostnames.
- **Bundled Add-on Templates:**
  - **Printers (RFC 3805):** Lifetime page counter, consumables (toner/drum) discovered automatically with percentage calculations, status, and serial number;
  - **Switches:** Percentage of physical ports in use calculated from an SNMP IF-MIB walk (Zabbix 7.0+).
- **Optimized Native Zabbix Dashboards:** Pre-configured dashboards per device category with vector SVG graphs (network traffic, errors, temperature), Top Hosts latency/CPU/Memory rankings, and Honeycomb matrix views (7.0+) or complete `hostavail` tables (6.0 LTS). No Grafana required.
- **SSL Certificate and Domain Expiration Monitoring:** Checks TLS certificates via Zabbix Agent 2 and domain expiration via RDAP (RFC 7480/9082) without external scripts.
- **Site Topology Maps:** Automated Zabbix network maps per site with category rows and icon status indicators.
- **Compatibility:** Zabbix **6.0 LTS to 8.0**. Runs on Linux, Windows, and macOS (Python 3.10+).

---

## Quick Start & Installation

### Installation:
```bash
# Via pip or uv (recommended)
pip install git+https://github.com/GustavoMS0/zabbix-autodiscovery
```

On Windows without global Python: run `./zabbix-autodiscovery.ps1 init` (uses [uv](https://docs.astral.sh/uv/) or system Python).  
On Linux/macOS: run `./zabbix-autodiscovery.sh init`.

---

## Implementation Guide: Choose Your Scenario

`zabbix-autodiscovery` is built to handle both brand-new Zabbix deployments and **long-standing production environments with zero risk of breaking existing configurations**.

```
                           ┌───────────────────────────────────────────────┐
                           │          zabbix-autodiscovery init            │
                           └──────────────────────┬────────────────────────┘
                                                  ▼
                                      What is your scenario?
                                                  │
                 ┌────────────────────────────────┴────────────────────────────────┐
                 ▼                                                                 ▼
      【 SCENARIO 1: NEW ZABBIX 】                                     【 SCENARIO 2: EXISTING ZABBIX 】
      • zabbix-autodiscovery check                                     • zabbix-autodiscovery check
      • zabbix-autodiscovery setup                                     • zabbix-autodiscovery audit  (health report)
      • zabbix-autodiscovery scan -o inventory.csv                     • zabbix-autodiscovery scan -o inventory.csv
      • zabbix-autodiscovery apply -i inventory.csv                    • zabbix-autodiscovery diff (compare scans)
      • zabbix-autodiscovery maps                                      • zabbix-autodiscovery apply (new hosts only)
      • zabbix-autodiscovery web                                       • zabbix-autodiscovery organize (organize old)
                                                                       • zabbix-autodiscovery update-templates --all
```

---

### Scenario 1: New Zabbix Deployment (Greenfield / From Scratch)

Ideal when setting up a fresh Zabbix installation and you want to onboard dozens or hundreds of devices in minutes with clean naming, groups, and templates.

1. **Deploy Zabbix (if not already running):**
   You can use the bundled Docker Compose stack in `deploy/`:
   ```bash
   cd deploy
   cp .env.example .env     # Set secure passwords in .env
   docker compose --profile zabbix --profile grafana up -d
   ```
2. **Generate an API Token:**
   In Zabbix frontend, go to *Users → API tokens* and create a token for a user with **Super admin** role. (On Zabbix 8.0, ensure API access is enabled on the user's role).
3. **Initialize Configuration:**
   ```bash
   mkdir my-monitoring && cd my-monitoring
   zabbix-autodiscovery init
   ```
   This creates `config.yaml` and `.env`.
4. **Configure Secrets and Networks:**
   * In `.env`: set your `ZABBIX_TOKEN` and `SNMP_COMMUNITY`.
   * In `config.yaml`: set your `zabbix.url` and network CIDRs under `scan.networks`.
5. **Validate Prerequisites:**
   ```bash
   zabbix-autodiscovery check
   ```
   Validates API connectivity, token permissions, and template availability.
6. **Provision Base Objects in Zabbix:**
   ```bash
   zabbix-autodiscovery setup
   ```
   Creates host groups, the global `{$SNMP_COMMUNITY}` macro (only if missing), agent missing template, and native dashboards.
7. **Scan and Classify the Networks:**
   ```bash
   zabbix-autodiscovery scan -o inventory.csv
   ```
   Probes all responsive devices and outputs `inventory.csv`.
8. **Review and Apply:**
   Open `inventory.csv` in Excel or an editor. Only rows with `action = add` will be created in Zabbix. Rows marked `review` need your decision; the `note` column says why. When a device matched a rule that needs SNMP but did not answer SNMP (e.g. a camera found by its RTSP port), nothing is guessed: enable SNMP on the device and scan again, or set `interface`/`templates` yourself (e.g. `icmp` / `ICMP Ping`) and change `action` to `add`.
   ```bash
   zabbix-autodiscovery apply -i inventory.csv --dry-run   # Preview plan
   zabbix-autodiscovery apply -i inventory.csv             # Create hosts in Zabbix
   ```
9. **Generate Site Topology Maps:**
   ```bash
   zabbix-autodiscovery maps
   ```
   Generates site maps with icons reflecting host problem states.

---

### Scenario 2: Existing Production Zabbix (Brownfield / Safe Onboarding)

If you have an active Zabbix installation with hundreds of monitored hosts, **you can run `zabbix-autodiscovery` with complete confidence**:

> [!IMPORTANT]
> **Production Safety Guarantees:**
> - **Existing hosts are never overwritten or deleted.** Any IP or DNS already present in Zabbix is automatically skipped during `apply`.
> - **Existing global macros are preserved.** If `{$SNMP_COMMUNITY}` already exists with another value, it is not modified; new hosts receive a host-level macro instead.
> - **All created objects are traceable.** Prefixed with `AutoDiscovery - ` and tagged with `origin=autodiscovery`.
> - **Safe simulations everywhere.** Mutation commands support `--dry-run`.

#### Recommended Safe Workflow for Existing Zabbix:

1. **Audit Zabbix Health (Read-Only):**
   ```bash
   zabbix-autodiscovery audit
   ```
   Generates a non-intrusive diagnostic report:
   - Identifies duplicate IPs (multiple hosts configured with the same IP);
   - Detects cloned VMs sharing the same `system.hostname`;
   - Flags agent `Hostname=` mismatches (a leading cause of active check failures);
   - Lists hosts with agent templates where the agent is unreachable;
   - Lists hosts with the highest count of unsupported items.

2. **Scan the Networks for Unmonitored Devices:**
   ```bash
   zabbix-autodiscovery scan -o inventory.csv
   ```
   *Tip:* Target specific subnets or sites without editing `config.yaml`:
   ```bash
   zabbix-autodiscovery scan --network 10.0.0.0/24 -o branch-scan.csv
   zabbix-autodiscovery scan --site Branch-01 -o site1.csv
   ```

3. **Check for Changes and Rogue Devices (`diff`):**
   Compare previous scans with the latest scan:
   ```bash
   zabbix-autodiscovery diff -old inventory-previous.csv -new inventory.csv
   ```

4. **Onboard Only the Newly Discovered Devices:**
   ```bash
   zabbix-autodiscovery apply -i inventory.csv --dry-run
   zabbix-autodiscovery apply -i inventory.csv
   ```
   Any device already in Zabbix outputs `IP already monitored, skipped` and remains untouched.

5. **Bring Legacy Hosts into Standard Groups and Tags:**
   If your pre-existing hosts lack consistent grouping, `organize` assigns them to their device type group (e.g. *Network/Switches*, *Network/Firewalls*) and site groups, adding standard `type` and `site` tags:
   ```bash
   zabbix-autodiscovery organize --dry-run
   zabbix-autodiscovery organize
   ```
   *Note:* `organize` is purely additive. It never removes legacy groups unless explicitly requested via `--remove-groups LegacyGroup1,LegacyGroup2`.

6. **Link Complementary Add-on Templates to Existing Hosts:**
   To add port usage metrics or printer consumable discovery to legacy hosts without altering their vendor templates:
   ```bash
   zabbix-autodiscovery update-templates --all --dry-run
   zabbix-autodiscovery update-templates --all
   ```

---

## Service Detection

Besides the device type, the scan identifies the **services** each host runs: databases (SQL Server, MySQL/MariaDB, PostgreSQL, Oracle, MongoDB, Redis, Elasticsearch…), **clusters** (Windows Failover Cluster, SQL AlwaysOn, Hyper-V live migration, Pacemaker, Galera, Kubernetes, etcd…), directory (Active Directory, LDAP, Kerberos, DNS), mail, messaging (RabbitMQ, Kafka, MQTT), virtualization (ESXi, Proxmox, Docker), backup (Veeam), file sharing, remote access and monitoring.

- When the protocol allows, the service is **confirmed by talking to it**: MySQL greeting, PostgreSQL SSL handshake, Redis `PING`, SSH/SMTP/FTP/IMAP banners, Elasticsearch, Prometheus, Grafana and Docker HTTP answers. Another program listening on the same port is not reported.
- Results go to the `services` column and become `service=<name>` tags in Zabbix, so you can filter hosts and problems by service.
- Services of the groups in `service_checks` (databases, clusters, directory, mail, messaging, backup and virtualization by default) get a template **AutoDiscovery - Service <name>** that raises a problem when the port stops answering. It checks from the Zabbix server or proxy and needs no credentials. For deep metrics (queries, replication…), link the official Zabbix template of that product as well.
- `apply` handles new hosts. For hosts already in Zabbix, `services -i inventory.csv [--dry-run]` adds the tags and checks, matching hosts by IP.
- Rules can use services too: `services_any: [mssql]` or `services_all: [kubernetes-api, etcd]`.

## Command Reference

| Command | Modifies Zabbix? | Description |
|---|---|---|
| `zabbix-autodiscovery init [--force]` | No | Creates starter `config.yaml` and `.env` files. |
| `zabbix-autodiscovery check` | No | Validates API connectivity, token role, templates, and network overlap. |
| `zabbix-autodiscovery audit` | No | Non-intrusive health audit: duplicate IPs, cloned machines, item errors, agent issues. |
| `zabbix-autodiscovery scan [-o CSV] [--network CIDR] [--site NAME]` | No | Probes networks, classifies discovered devices, and writes inventory CSV. |
| `zabbix-autodiscovery diff -old CSV1 -new CSV2` | No | Compares two scan inventories to detect new devices, removals, and changes. |
| `zabbix-autodiscovery apply -i CSV [--dry-run]` | **Yes** | Onboards CSV rows with `action=add`. Skips already monitored IPs/names. |
| `zabbix-autodiscovery setup [--no-dashboards] [--rebuild-dashboards]` | **Yes** | Provisions host groups, SNMP macro, agent missing template, and dashboards. |
| `zabbix-autodiscovery agent-sync [--dry-run]` | **Yes** | Promotes `agent=missing` servers to OS agent templates once their agent answers. |
| `zabbix-autodiscovery organize [--dry-run] [--remove-groups G1,G2]` | **Yes** | Assigns pre-existing hosts into standardized type/site groups with tags. |
| `zabbix-autodiscovery update-templates [--all] [--dry-run]` | **Yes** | Links category add-on templates (switch ports, printer MIB) to existing hosts. |
| `zabbix-autodiscovery services -i CSV [--dry-run]` | **Yes** | Adds service tags and service checks to hosts already in Zabbix (matched by IP). |
| `zabbix-autodiscovery maps [--dry-run] [--rebuild]` | **Yes** | Generates per-site topology maps with status icons and a map dashboard. |
| `zabbix-autodiscovery web [-i CSV] [--dry-run]` | **Yes** | Sets up SSL certificate tracking (Zabbix Agent 2) and domain expiration (RDAP). |
| `zabbix-autodiscovery grafana-dashboards -o DIR` | No | Exports Grafana dashboard JSON files matching your configured host groups. |

---

## Native Zabbix Dashboards

When running `zabbix-autodiscovery setup`, optimized native dashboards are built directly inside Zabbix matching your host group names. Zabbix graphs select hosts by name (not by group), so graphs list the hosts of each type's groups when the dashboard is built: after onboarding new hosts, run `zabbix-autodiscovery setup --rebuild-dashboards`.

1. **Category-Specific Dashboards:**
   - Dedicated views for: *Switches*, *Routers*, *Firewalls*, *Access Points*, *Printers*, *Servers*, *UPS*, *Storage*, *CCTV*, *VoIP*, and *PDUs*.
2. **SVG Vector Graphs (`svggraph`):**
   - Inbound/outbound interface traffic (`*Bits received*` / `*Bits sent*`), discards, errors, and temperature graphs rendered natively without third-party plugins.
3. **Performance Rankings (`tophosts`):**
   - Top hosts ranked by ICMP response time and packet loss;
   - Top servers ranked by CPU and Memory utilization (Zabbix 6.4+ / 7.0+).
4. **Availability & Matrices:**
   - **Zabbix 7.0 / 8.0:** Honeycomb matrix panels for ICMP availability and Zabbix agent reachability.
   - **Zabbix 6.0 LTS:** Full Host Availability (`hostavail`) summary tables showing Up/Down/Unknown counts per group.
5. **Servers Without Agent:**
   - Dedicated dashboard widget tracking servers missing the Zabbix agent.

---

## Multi-Site & Proxy Architecture

Organize networks by physical location in `config.yaml`:

```yaml
site_group: "Sites/{site}"                 # Creates host groups like "Sites/HQ" and "Sites/Branch-01"
scan:
  networks:
    - {network: 192.168.0.0/24, site: HQ}
    - {network: 10.20.0.0/23,   site: Branch-01, proxy: proxy-branch-01}
    - 172.16.5.0/24                        # Network without explicit site
```

Each host automatically receives a `site=<name>` tag and joins its site host group, enabling seamless filtering in Zabbix and Grafana.

---

## Contributing

Contributions including new vendor classification rules, dashboards, and enhancements are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the terms of the [MIT License](LICENSE).
