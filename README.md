# zabbix-autodiscovery

[![CI](https://github.com/GustavoMS0/zabbix-autodiscovery/actions/workflows/ci.yml/badge.svg)](https://github.com/GustavoMS0/zabbix-autodiscovery/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

🇧🇷 [Leia em português](README.pt-BR.md)

**Scan your networks, find the infrastructure devices, and onboard them into Zabbix with the right template, host group, interface and tags.** Workstations and laptops are left out. Grafana dashboards are optional.

```text
$ zabbix-autodiscovery scan -o inventory.csv
Scanning: 10.0.0.0/24, 10.10.0.0/24, 10.20.0.0/24
  category            action    count
  ap                  add       16
  printer             add       17
  server-hardware     add       6
  switch              add       4
  server-windows      add       3
  workstation         ignore    53
  unknown             ignore    124
  Host name sources (add/review): snmp=40, netbios=4, dns=1, ip=9

$ zabbix-autodiscovery apply -i inventory.csv --dry-run
  + 10.20.0.52      printer           PRN-WAREHOUSE      [Network/Printers + Sites/Branch-01]  name via snmp
      templates: Generic by SNMP
  + 10.20.0.22      server-hardware   idrac-ABC1234      [Infrastructure/Server Hardware + Sites/Branch-01]  name via snmp
      templates: Dell iDRAC by SNMP
  = 10.10.0.47      ap                IP already monitored, skipped
```

## Features

- **Discovery** via ping, TCP ports, SNMP v1/v2c/v3, Zabbix agent, NetBIOS and forward-confirmed reverse DNS. A second pass with longer timeouts avoids false negatives on busy or VPN links.
- **Classification by what the device answers, never by its name.** Rules use the SNMP sysObjectID/sysDescr, the agent's `system.uname` and open ports, so they work with any naming convention. They ship with rules for Cisco, HPE/Aruba, H3C, Huawei, Juniper, TP-Link, D-Link, MikroTik, Dell, Fortinet, pfSense, Palo Alto, Sophos, Ubiquiti/UniFi, Ruckus, Meraki, the major printer brands, APC/Eaton/NHS UPS, Synology/QNAP, iDRAC/iLO, ESXi and Windows/Linux servers.
- **Workstations are excluded.** Microsoft's SNMP sysObjectID separates workstations from servers and domain controllers. Windows 11 and Server 2025 share build 26100 and are still told apart. The agent's OS string and port fingerprints cover machines without SNMP.
- **Real host names**, from the agent's `Hostname=`, then the SNMP sysName (factory defaults are discarded), then NetBIOS, then forward-confirmed DNS. The CSV shows where each name came from.
- **Review before change.** `scan` writes a CSV you can edit in Excel. `apply --dry-run` shows exactly what would be created. `check` validates everything without touching Zabbix.
- **Safe on an existing Zabbix.** Hosts already monitored (same IP or DNS) are skipped. Existing macros, groups, users and dashboards are never modified. Everything zabbix-autodiscovery creates is prefixed `AutoDiscovery -` or tagged `origin=autodiscovery`.
- **Servers without a Zabbix agent** get a template that raises a *"Zabbix agent missing"* problem. `agent-sync` switches them to agent templates once the agent is installed.
- **Printers** (page counter, toner/drum levels, status, serial), **switch port usage** and **site maps** with an icon per device type.
- **SSL certificates and domain expiration** (RDAP), with alerts and a dashboard sorted by days left. The scan also identifies web servers (IIS, nginx, Apache…) and their certificates.
- **Multiple sites**, each with a name (becomes a `site` tag and a `Sites/<name>` group) and an optional Zabbix proxy.
- **Dashboards per device type**: native Zabbix dashboards (no Grafana needed) and/or Grafana dashboards. Both are built from your own host group names.
- Zabbix **6.0 → 8.0**. Runs on Linux, macOS and Windows (Python 3.10+).

## Quick start

```bash
pip install git+https://github.com/GustavoMS0/zabbix-autodiscovery   # or: pipx / uv tool install
mkdir my-site && cd my-site
zabbix-autodiscovery init            # writes config.yaml and .env
```

1. In Zabbix, create an API token (*Users → API tokens*) for a Super admin user. On Zabbix 8.0 the user's role must have **API access** enabled.
2. Put the token and your SNMP community in `.env`. Set `zabbix.url` and `scan.networks` in `config.yaml`.
3. Run:

```bash
zabbix-autodiscovery check                              # read-only validation
zabbix-autodiscovery scan  -o inventory.csv             # scan + classify; Zabbix is not touched
#   review inventory.csv: set the "action" column to add | review | ignore
zabbix-autodiscovery apply -i inventory.csv --dry-run   # show the plan
zabbix-autodiscovery setup                              # groups, agent-missing template, dashboards
zabbix-autodiscovery apply -i inventory.csv             # create the hosts
```

Without installing anything on Windows: `.\zabbix-autodiscovery.ps1 init` (needs [uv](https://docs.astral.sh/uv/)). On Linux/macOS: `./zabbix-autodiscovery.sh init`.

> Run the scan from a machine that can reach every network, preferably the Zabbix server or proxy itself. Zabbix agents only answer IPs listed in their `Server=`.

## Commands

| Command | Changes Zabbix? | What it does |
|---|---|---|
| `zabbix-autodiscovery init` | no | Writes a starter `config.yaml` and `.env` |
| `zabbix-autodiscovery check` | no | Token, role, templates available per rule, macro, overlapping discovery rules, planned changes |
| `zabbix-autodiscovery scan -o FILE` | no | Scans `scan.networks`, classifies every responsive IP, writes the CSV |
| `zabbix-autodiscovery apply -i FILE [--dry-run]` | yes | Creates rows with `action=add`. Skips anything already monitored |
| `zabbix-autodiscovery setup [--native-discovery] [--no-dashboards]` | yes | Host groups, `{$SNMP_COMMUNITY}` (only if missing), agent-missing template, Zabbix dashboards, optional Grafana read-only user, optional continuous discovery |
| `zabbix-autodiscovery agent-sync [--dry-run]` | yes | Moves `agent=missing` hosts to agent templates when their agent answers |
| `zabbix-autodiscovery update-templates [--dry-run]` | yes | Links the category add-on templates to existing hosts |
| `zabbix-autodiscovery audit` | no | Organization, duplicate IPs, agent and item problems |
| `zabbix-autodiscovery organize [--dry-run]` | yes | Puts pre-existing hosts in their type and site groups, with tags |
| `zabbix-autodiscovery maps [--dry-run] [--rebuild]` | yes | One map per site with an icon per device type, plus a dashboard |
| `zabbix-autodiscovery web [--dry-run] [-i FILE]` | yes | SSL certificate and domain expiration monitoring |
| `zabbix-autodiscovery grafana-dashboards -o DIR` | no | Writes Grafana dashboard JSON files from your config |

## The inventory CSV

Each responsive IP becomes one row. The columns you normally edit:

| Column | Meaning |
|---|---|
| `action` | `add` (will be created), `review` (uncertain: decide), `ignore` |
| `hostname` / `visible_name` | Zabbix technical and visible names. `name_source` tells where the name came from |
| `group`, `templates`, `interface`, `site` | What `apply` will use. `A|B` in templates means the first one that exists |

Everything else (`sysobjectid`, `sysdescr`, `ports`, `agent_uname`, `netbios`, `dns`...) is evidence to help you decide.

## How devices are classified

Rules live in `config.yaml` and are evaluated in order. The first match wins:

```yaml
- name: intelbras-switch
  category: switch
  group: Network/Switches
  match:                                   # a list means "any of"; a mapping means "all of"
    - {sysobjectid_prefix: [1.3.6.1.4.1.26138]}
    - {sysdescr_regex: 'intelbras'}
  templates: ["Intelbras by SNMP|Network Generic Device by SNMP"]
  interface: snmp                          # snmp | agent | icmp
  tags: {}                                 # extra host tags
  action: add                              # add | review | ignore
```

Available conditions: `sysobjectid_prefix`, `sysdescr_regex`, `agent_uname_regex`, `ports_any`, `ports_all`, `ports_none`, `snmp`, `agent`, `alive`.

How workstations are told apart from servers, without names:

| Evidence | Result |
|---|---|
| SNMP sysObjectID `…311.1.1.3.1.1` | workstation → ignore |
| SNMP sysObjectID `…311.1.1.3.1.2` / `…3.1.3` | Windows server / domain controller |
| Agent `system.uname` contains "Windows … Server" | Windows server → **add** |
| Agent `system.uname` is Windows without "Server" (Windows 10/11 with an agent) | workstation → ignore |
| No SNMP/agent, Kerberos + LDAP (88 + 389) | domain controller without agent |
| No SNMP/agent, SMB + WinRM or SQL (445 + 5985/1433) | probable server → review |
| No SNMP/agent, only Windows ports (135/139/445/3389) | workstation → ignore |
| No SNMP/agent, SSH without Windows/printer ports | probable Linux → review |

> Do not combine `ICMP Ping` with `… by SNMP` templates: SNMP templates already contain the ICMP items, and the duplicate keys make host creation fail.

## Multiple sites and proxies

```yaml
site_group: "Sites/{site}"                 # extra host group per site ("" disables it)
scan:
  networks:
    - {network: 192.168.0.0/24, site: HQ}
    - {network: 10.20.0.0/23,   site: Recife, proxy: proxy-recife}
    - 172.16.5.0/24                        # no site
```

Every host gets the tag `site=<name>` and also joins `Sites/<name>`, so you can filter by device type or by site, in Zabbix and in Grafana. If a site is not routable from where you run zabbix-autodiscovery, scan it from a machine on that site with a config listing only its networks. `apply` accepts any of the resulting CSVs.

## Servers without a Zabbix agent

Servers detected without an agent are created with the tag `agent=missing` and the template **AutoDiscovery - Zabbix agent missing**. The Zabbix server checks port 10050 every 5 minutes. The trigger *"Zabbix agent missing on {HOST.NAME}"* fires only while the host answers ping, so a host that is down does not also raise this alert. Once the agent is installed the problem resolves by itself. Then run `zabbix-autodiscovery agent-sync` to link the agent templates. To get notified, create a trigger action with the condition *tag agent = missing*.

## Printers, switch ports and maps

**Category add-on templates** are linked to every SNMP host of a category, on top of the vendor template:

```yaml
category_templates:
  printer: ["AutoDiscovery - Printer by SNMP"]
  switch: ["AutoDiscovery - Switch port usage"]
```

- **AutoDiscovery - Printer by SNMP** reads the standard Printer-MIB (RFC 3805), which almost every network printer implements (HP, Brother, Epson, Samsung, Kyocera, Ricoh…). It collects the total page counter, every consumable (toner, ink, drum) discovered automatically with its level in %, device and printer status, the panel message, model and serial number. Alerts fire below 10% and 3% (`{$PRINTER.SUPPLY.WARN}` / `{$PRINTER.SUPPLY.HIGH}`) and when the printer reports a warning or is down. Zabbix ships no printer template, so without this one printers only get ping and uptime.
- **AutoDiscovery - Switch port usage** computes physical ports in use, total ports, % used and enabled ports without link from one SNMP walk of the IF-MIB. It warns above 90% (`{$SWITCH.PORT.USAGE.WARN}`). Needs Zabbix 7.0+.
- `apply` links them to new hosts. `update-templates [--dry-run]` links them to hosts created earlier.

**Maps:** `maps [--dry-run] [--rebuild]` creates one Zabbix map per site, with every host in the site's networks (including hosts you already had). Hosts are grouped in rows by type, with an icon per type that changes color with problems. A dashboard *AutoDiscovery - Maps* shows one page per site. Icons default to the images bundled with Zabbix. Each category or vendor can use another built-in image or your own PNG, for example a photo of the model; product photos are not bundled with the project.

```yaml
maps:
  name_format: "Site: {site}"
  icons:
    printer: Printer                       # built-in Zabbix image
    vendor:HP: icons/hp-laserjet.png       # local PNG, uploaded once
```

**SNMP version:** credentials are tried from the highest version down (v3, then v2c, then v1), keeping the config order within the same version. The first that answers is used.

## Organizing what already exists

On a Zabbix that was already in use, the hosts you had before are not changed by `apply`. Three commands bring them into the same organization:

- `audit` (read-only): what `organize` would change, the same IP on more than one host (possible duplicates), agent templates on hosts whose agent is unavailable, and the hosts with the most unsupported items.
- `organize [--dry-run] [--remove-groups G1,G2]`: every host of the configured networks joins the group of its type and of its site and gets the `type` / `site` tags. For hosts not created by this tool, the type comes from the templates they use (FortiGate → firewall, Comware/Aruba → switch, Dell iDRAC → server hardware…), then from their group names. It only adds, unless you list legacy groups to remove.
- `update-templates --all`: also links the category add-on templates (e.g. switch port usage) to those hosts.

## SSL certificates and domain expiration

`zabbix-autodiscovery web` monitors the sites and domains listed in the `web` section of the config:

```yaml
web:
  certificates:
    group: Web/Certificates
    agent2_host: Zabbix server       # existing host whose Zabbix agent 2 reads the certificates
    warn_days: 30
    high_days: 7
    sites: [https://www.example.com/, mail.example.com:443]
  domains:
    group: Web/Domains
    warn_days: 30
    high_days: 7
    list: [example.com, example.com.br]
```

- **Certificates:** one host per site, with the template *AutoDiscovery - SSL certificate*. It tracks the days until expiration, the validation result (invalid, expired, wrong name), the issuer and the SANs. The check runs on a **Zabbix agent 2** (WebCertificate plugin): the classic agent answers "Unsupported item key". Point `agent2_host` at a host with agent 2, for example the Zabbix server itself.
- **Domains:** one host per domain, with the template *AutoDiscovery - Domain expiration*. The Zabbix server queries **RDAP**, the official successor of WHOIS, every 12 hours, directly at each TLD's registry (registro.br, Verisign…), found through IANA's bootstrap list. No scripts are needed, only internet access from the Zabbix server or proxy.
- **Alerts:** warning below `warn_days`, high below `high_days`, plus a problem when a check keeps failing.
- **Dashboard:** *AutoDiscovery - Certificates and domains* lists everything sorted by days left.
- **Discovered certificates:** `scan` also records each HTTP(S) port's server (IIS, nginx, Apache…) and certificate (`web_servers`, `cert_*` columns). `web -i inventory.csv` adds the publicly trusted ones; self-signed certificates (printers, iDRAC…) are skipped.

## Dashboards

`setup` creates one **native Zabbix dashboard** per device type found in your rules: overview, switches, routers, firewalls, access points, printers, servers, UPS, storage and server hardware. They contain problems filtered by the type's host groups, a honeycomb of ICMP availability and metrics (Zabbix 7.0+), and the hosts with the highest ICMP latency. No Grafana is required.

**Grafana** is optional:

- **New stack:** `deploy/docker-compose.yml` brings up Zabbix 8.0 + PostgreSQL and/or Grafana 12 with the Zabbix plugin, datasource and the bundled dashboards already provisioned:

  ```bash
  cd deploy && cp .env.example .env      # change every password
  docker compose --profile zabbix --profile grafana up -d    # or only one of the profiles
  ```

  With only `--profile grafana`, set `ZABBIX_API_URL` in `.env` to point Grafana at an existing Zabbix. `zabbix-autodiscovery setup` creates the read-only user it needs (`grafana_user` in the config).
- **Existing Grafana:** `zabbix-autodiscovery grafana-dashboards -o dashboards/`, then *Dashboards → New → Import*. Each dashboard has a datasource selector, so no UID editing is needed.

Grafana panels select items by regex, because every vendor template names items differently. If a panel stays empty for some model, adjust `SPECS` in `src/zabbix_autodiscovery/dashboards.py`.

## Using it on an existing Zabbix

| Situation | Behavior |
|---|---|
| Host already monitored (same IP or DNS) | skipped, never changed |
| Name already used by another host (same device on another IP?) | skipped as a possible duplicate (`--allow-duplicate-names` creates it as `name-IP`) |
| Global `{$SNMP_COMMUNITY}` already exists | kept; the community goes to the new host as a host macro |
| Groups with the same names | reused |
| Template, dashboard, role, user with zabbix-autodiscovery's names | created only if missing |
| `--native-discovery` while monitored hosts are inside the ranges | refused (the actions would also apply to them) unless `--force` |
| Template names that differ in your version | alternatives per rule (`A|B`); `check` lists anything missing |

Start with a small network, always run `apply --dry-run` first, and filter by `origin=autodiscovery` to review or roll back.

**Fixing agent `Hostname=` mismatches** reported by `audit` (typical of cloned VMs): run `tools/fix-agent-hostname.ps1` as Administrator on the Windows server, or remotely with `toolsix-agent-hostname.ps1 -ComputerName SRV01,SRV02` (no WinRM needed: it uses the `C$` admin share and the service manager, TCP 445/135). It sets `Hostname=` to the computer name, keeps a backup and restarts the agent. Add `-WhatIf` to preview.

## Requirements on the devices

- **Network gear, printers, UPS:** SNMP enabled, with the ACL allowing the Zabbix server and the scanning machine.
- **Servers:** Zabbix agent 2 with `Server=` / `ServerActive=` pointing to Zabbix. When the scanner's IP is not in `Server=`, the server is detected as *agent installed, scanner refused* (`review`).
- **Firewalls between networks:** ICMP, UDP 161 and TCP 10050 from Zabbix and the scanner.

## Contributing

New vendor rules, dashboards and fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). When a device is misclassified, the [issue template](.github/ISSUE_TEMPLATE/device-rule.md) asks for the CSV columns needed to write a rule.

## License

[MIT](LICENSE)
