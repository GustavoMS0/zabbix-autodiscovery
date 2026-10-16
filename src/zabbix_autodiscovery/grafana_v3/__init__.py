"""AutoDiscovery v3 Grafana dashboards ("NOC escuro neon" — unified hierarchical topology & enriched telemetry).

Published side by side in the Grafana folder "AutoDiscovery v3" so v1, v2 and v3 can be compared without
removing any existing dashboards.

- style.py           v3 design system wrapper (re-exports v2 tokens/builders with v3 UIDs, tags and links).
- overview.py        "Visão Geral" TV dashboard with Wi-Fi client KPI and direct link to the unified topology.
- topology.py        Unified hierarchical ECharts network topology (ISP -> SD-WAN -> FW -> Core -> Dist/Srv/AP/UPS).
- access_points.py   Enriched with UniFi connected clients KPI, Model/Firmware columns and per-AP/per-SSID charts.
- switches.py        Enriched with Dell FastPath CPU/Memory/Temperature telemetry and CPU/Memory history charts.
- ups.py             Enriched with real ICMP ping & latency telemetry on Nobreak-SP.
- server_hardware.py Enriched with real ICMP ping & latency telemetry alongside SNMP on Dell iDRACs.
- firewalls.py       v3 Firewalls, WAN & SD-WAN dashboard.
- servers.py         v3 Windows/Linux servers & hypervisors dashboard.
- printers.py        v3 Printers & supplies dashboard.
"""

from importlib import import_module

from .. import dashboards as v1

TV_MODULES = ["overview", "topology", "site_maps"]
CATEGORY_MODULES = {
    "firewalls": "firewalls",
    "switches": "switches",
    "access-points": "access_points",
    "servers": "servers",
    "server-hardware": "server_hardware",
    "printers": "printers",
    "ups": "ups",
}


def build_all(cfg, datasource_uid="zabbix", api=None, log=print):
    """{filename: dashboard} for the v3 set."""
    keys = {s["key"] for s in v1.specs_to_build(cfg, api, log=log)}
    modules = TV_MODULES + [m for k, m in CATEGORY_MODULES.items() if k in keys]
    out = {}
    for name in modules:
        mod = import_module(f"{__name__}.{name}")
        if name in ("topology", "site_maps"):
            built = mod.build(cfg, datasource_uid=datasource_uid, api=api)
        else:
            built = mod.build(cfg, datasource_uid=datasource_uid)
        for dash in built if isinstance(built, list) else [built]:
            out[f"{dash['uid']}.json"] = dash
    return out

