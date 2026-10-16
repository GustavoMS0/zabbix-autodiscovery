"""AutoDiscovery v2 Grafana dashboards ("NOC escuro neon").

A redesign of the v1 dashboards (dashboards.py / topology.py), published side by side in the Grafana
folder "AutoDiscovery v2" so both can be compared. The v1 generator stays untouched: its item regexes,
windows and value semantics were verified against live data and are imported from there.

- style.py     design system: palette, thresholds, PT-BR value maps, Zabbix targets, transforms,
               panel builders, layout and the dashboard wrapper. Start there.
- overview.py  "Visão Geral" TV dashboard (1920x1080, no scroll), the reference implementation.

Every dashboard module exposes build(cfg, datasource_uid="zabbix") -> dashboard dict (or a list of them)
with uid "autodiscovery-<key>-v2" and the tag "autodiscovery-v2".
"""

from importlib import import_module

from .. import dashboards as v1

# TV dashboards are always written: they summarise every site/category, not one device type.
TV_MODULES = ["overview", "topology_canvas", "topology_echarts"]
# v1 spec key -> v2 module. A category dashboard is written only when its v1 spec would be (same
# host-group rules and, with a Zabbix API, at least one enabled host), so v1 and v2 cover the same set.
CATEGORY_MODULES = {"firewalls": "firewalls", "switches": "switches", "access-points": "access_points",
                    "servers": "servers", "server-hardware": "server_hardware", "printers": "printers",
                    "ups": "ups"}


def build_all(cfg, datasource_uid="zabbix", api=None, log=print):
    """{filename: dashboard} for the v2 set. api=None (offline) keeps every category with host groups,
    exactly like dashboards.specs_to_build."""
    keys = {s["key"] for s in v1.specs_to_build(cfg, api, log=log)}
    modules = TV_MODULES + [m for k, m in CATEGORY_MODULES.items() if k in keys]
    out = {}
    for name in modules:
        built = import_module(f"{__name__}.{name}").build(cfg, datasource_uid=datasource_uid)
        for dash in built if isinstance(built, list) else [built]:
            out[f"{dash['uid']}.json"] = dash
    return out
