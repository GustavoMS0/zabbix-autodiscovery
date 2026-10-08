# Changelog

## 0.1.0 (unreleased)

First public version.

- `scan`: ping, TCP ports, SNMP v1/v2c/v3, Zabbix agent, NetBIOS and forward-confirmed reverse DNS, with a second pass for responsive hosts.
- Rule-based classification by SNMP, agent and ports, never by host name, with rules for the most common network, printer, UPS, storage and server vendors.
- Host name detection (agent → SNMP sysName → NetBIOS → confirmed DNS) with the source recorded in the CSV.
- `apply` with `--dry-run`, which skips hosts that are already monitored.
- `check`: read-only validation of token, role, templates, macros and planned changes.
- `setup`: host groups, the "Zabbix agent missing" template, native Zabbix dashboards per device type, an optional Grafana read-only user and optional continuous discovery.
- `agent-sync`: moves servers to agent templates once the agent is installed.
- Multiple sites with a `site` tag, a site host group and a per-network Zabbix proxy.
- `grafana-dashboards` and an optional Docker deployment (Zabbix 8.0, PostgreSQL, Grafana 12).
- `web`: SSL certificate monitoring (Zabbix agent 2) and domain expiration through RDAP at each TLD's registry, with alerts and a dashboard sorted by days left.
- The scan identifies web servers (HTTP `Server` header) and TLS certificates; new `web_server_regex` rule condition (e.g. IIS → Windows server).
- `apply` skips hosts whose name already exists with another IP (possible duplicate) unless `--allow-duplicate-names`.
- Printer template (Printer-MIB): page counter, auto-discovered supplies with level %, status, model, serial.
- Switch port usage template (ports in use / total / %), from one IF-MIB walk.
- `category_templates` + `update-templates` to link add-on templates to new and existing hosts.
- `maps`: one Zabbix map per site with an icon per device type (built-in images or your own PNGs) and a dashboard with one page per site.
- SNMP credentials are tried from the highest version down (v3 → v2c → v1).
- `audit` and `organize`: report on and organize the hosts that already existed (type and site groups, tags), with the type inferred from their templates; `update-templates --all`.
- `audit` also finds the same machine on several hosts (system.hostname), host IPs that disagree with DNS and agent `Hostname=` mismatches; `agent-sync` falls back to the data Zabbix collected when the agent only allows the Zabbix server.
- Hyper-V hosts (vmms service running, as collected by the Windows agent template) are classified as hypervisors by `organize` and `maps`.
- Native dashboards: SVG graphs (traffic, temperature, errors, pages, voltage), top hosts and host availability for Zabbix 6.0/6.4; `setup --rebuild-dashboards` refreshes them with the current hosts.
- CCTV (Hikvision, Dahua, Intelbras, Axis), VoIP (Grandstream, Yealink, Asterisk/FreePBX), Proxmox and rack PDU rules.
- Devices that match a rule needing SNMP but do not answer SNMP go to `review` with an explanation in the new `note` column.
- `wizard`: interactive step-by-step assistant (Portuguese or English), plus one-line installers `install.sh` (Linux/macOS) and `install.ps1` (Windows) that download or update the tool and start it. On a Linux machine without Zabbix, the wizard can install Docker and start Zabbix 8 (optionally Grafana) from `deploy/`, creating the API token and changing the default Admin password.
- `diff` compares two inventories; `scan --network/--site` scans part of the configured networks.
- API retries never repeat a write that may have been executed (only connection failures and 502/503).
- Service detection (databases, clusters, directory, mail, virtualization, messaging, backup...) confirmed by protocol when possible; `service` tags, per-service port checks and the `services` command for existing hosts.
- Scope documented: local / on-premises networks.
- Supports Zabbix 6.0 to 8.0.
