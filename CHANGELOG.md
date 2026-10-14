# Changelog

## Unreleased

- Map module 1.1 (`interactive_map_zoom`), tested on Zabbix 8.0: only native map SVGs are touched (graphs and honeycomb widgets were being zoomed and covered by the HUD); zoom/pan/focus math now accounts for the viewBox scaling and the SVG position, so the wheel zooms around the cursor and "Próximo alerta" centres the right element (most severe first, using Zabbix 8's highlight markup) instead of throwing the map off-screen; a drag that starts on a host no longer opens its menu; the user's zoom survives map refreshes; `Monitoring -> Maps` gets a window-sized pan area; `alert()` and the 800 ms polling were replaced by an inline message and a MutationObserver; smaller HUD with zoom level.
- Removed the standalone HTML map (`interactive-map` command, menu option 15, `--serve/--port/--open`): the tool no longer writes files outside Zabbix/Grafana. The interactive map is the native Zabbix map (`maps`) plus the frontend module `deploy/zabbix-modules/interactive_map_zoom`, now mounted read-only into the `zabbix-web` container and enabled by `maps` on Zabbix 7.0+ (failure-tolerant; `maps.enable_module: false` to skip). The module's HUD is built with `textContent` (no `innerHTML`) and no longer logs to the console.
- Config: `${VAR}` is expanded after YAML parsing, so secrets containing `#`, starting with `&*!{` or looking like numbers are kept verbatim; invalid YAML is a clear config error.
- `.env` files (`init`, `wizard`, `deploy/.env`) are created with mode 600 from the start.
- `{$SNMP_COMMUNITY}` is created as a secret macro (an existing plain macro with the same value is converted); per-host community macros are secret too.
- The Grafana read-only role only allows read API methods (`*.get`, `apiinfo.version`, `user.login/logout/checkAuthentication`, `sla.getsli`).
- `install.sh` and the wizard's Docker install download scripts to temporary files before running them; the uv installer is pinned (`ZAD_UV_VERSION`); `ZAD_REF` documented for release tags.
- `dependencies`: only switch → gateway for sites with a single gateway (HA pairs are skipped with a warning), no more endpoint/VM links inferred from map positions, never adds a second parent to a trigger, explicit `noc.dependencies`, prints a warning and requires `--yes` (or `--dry-run`).
- `sla`: timezone configurable (`noc.sla_timezone`, default `America/Sao_Paulo`).
- Rules without `action` default to `review` everywhere (`check`, host groups, dashboards, native discovery), matching the classifier.
- Unknown SNMPv3 `auth_protocol`/`priv_protocol` is reported as a config error instead of a crash.
- `agent-sync`: agents probed concurrently (bounded), one failing host no longer aborts the run, the ICMP retry only happens on duplicate-key errors, and the host's visible name is preserved when the technical name follows the agent's `Hostname=`.
- `check`: discovery-rule overlap uses real address ranges (no substring false positives).
- Non-JSON / HTTP error responses from the API become a clear `ZabbixError` with the status and the start of the body.
- `setup --native-discovery` updates existing actions and removes stale ones only after the new ones exist.
- `web` no longer crashes when `certificates:` or `domains:` is empty.
- `scan` refuses more than `scan.max_targets` addresses (default 65536, a /16) unless `--force`; concurrency is capped at 256.
- Docker deploy: Grafana Zabbix plugin pinned (`GRAFANA_ZABBIX_PLUGIN_VERSION=6.9.1`), required passwords enforced with `${VAR:?}`.
- PyInstaller is an optional extra (`pip install -e ".[build]"`) for `build_exe.py`.
- `contrib/modules/modern_noc_theme`: removed the duplicated root `style.css` (the manifest uses `assets/css/style.css`).
- README.en.md synced with README.md (export, dependencies, sla, clean-unsupported, menu, interactive map inside Zabbix).

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
