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
- Supports Zabbix 6.0 to 8.0.
