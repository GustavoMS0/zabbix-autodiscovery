"""Per-device-type dashboards, rendered either as native Zabbix dashboards or as Grafana JSON.

One spec drives both outputs. Host groups are taken from the config rules (category -> group),
so dashboards follow whatever group names each installation uses.
"""
import json
import re

from .config import category_groups

PREFIX = "AutoDiscovery - "
AGENT_PORT_ITEM = "Zabbix agent: port 10050 reachable"

# Item filters: "zbx" is a Zabbix item-name pattern (honeycomb, * wildcard),
# "re" is the Grafana-Zabbix plugin regex (each vendor template names items differently).
CPU = {"zbx": "*CPU utilization*", "re": r"/CPU utilization/i"}
MEM = {"zbx": "*Memory utilization*", "re": r"/Memory utilization/i"}
TEMP = {"zbx": "*emperature*", "re": r"/temperature/i"}
TRAFFIC_IN = {"re": r"/Bits received/"}
TRAFFIC_OUT = {"re": r"/Bits sent/"}
ERRORS = {"re": r"/packets with errors/i"}
UPTIME = {"re": r"/uptime/i"}
SUPPLIES = {"zbx": "*oner*", "re": r"/(toner|cartridge|supply|ink|drum|marker)/i"}


def network_panels(extra=()):
    return [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "CPU", **CPU},
        {"kind": "gauge", "title": "Memory", **MEM},
        {"kind": "series", "title": "Inbound traffic (top 10 interfaces)", "unit": "bps", "top": 10, **TRAFFIC_IN},
        {"kind": "series", "title": "Outbound traffic (top 10 interfaces)", "unit": "bps", "top": 10, **TRAFFIC_OUT},
        {"kind": "series", "title": "Interface errors (top 10)", "top": 10, **ERRORS},
        {"kind": "latency"},
        *extra,
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]


SPECS = [
    {"key": "overview", "title": "Network overview", "categories": None, "panels": [
        {"kind": "problems", "min_severity": 2},
        {"kind": "availability"},
        {"kind": "agent_missing", "w": 12},
        {"kind": "agent_status", "w": 12},
        {"kind": "latency"},
        {"kind": "loss"},
    ]},
    {"key": "switches", "title": "Switches", "categories": ["switch"], "panels": network_panels([
        {"kind": "series", "title": "Temperature", "unit": "celsius", **TEMP},
        {"kind": "series", "title": "Interface discards (top 10)", "top": 10, "re": r"/packets discarded/i"},
    ])},
    {"key": "routers", "title": "Routers", "categories": ["router"], "panels": network_panels([
        {"kind": "series", "title": "Temperature", "unit": "celsius", **TEMP},
    ])},
    {"key": "firewalls", "title": "Firewalls", "categories": ["firewall"], "panels": network_panels([
        {"kind": "series", "title": "Active sessions", "re": r"/session/i"},
        {"kind": "series", "title": "VPN / tunnels", "re": r"/(vpn|tunnel)/i"},
    ])},
    {"key": "access-points", "title": "Access points", "categories": ["ap"], "panels": network_panels([
        {"kind": "series", "title": "Connected clients", "re": r"/(client|station|associated)/i"},
        {"kind": "series", "title": "Signal / noise", "re": r"/(signal|noise|ccq)/i"},
    ])},
    {"key": "printers", "title": "Printers", "categories": ["printer"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "Supply levels (toner/ink/drum)", "w": 24, "h": 10, "low_is_bad": True,
         "per_item": True, **SUPPLIES},
        {"kind": "series", "title": "Page counter", "w": 24, "re": r"/(page|counter|impress)/i"},
        {"kind": "latency", "w": 24},
    ]},
    {"key": "servers", "title": "Servers", "categories": ["server-windows", "server-linux", "hypervisor"],
     "panels": [
         {"kind": "problems"},
         {"kind": "agent_missing", "w": 12},
         {"kind": "agent_status", "w": 12},
         {"kind": "availability"},
         {"kind": "gauge", "title": "CPU", **CPU},
         {"kind": "gauge", "title": "Memory", **MEM},
         {"kind": "gauge", "title": "Disk usage per volume", "w": 24, "h": 10, "per_item": True,
          "zbx": "*Space utilization*", "re": r"/Space: Used, in %|Space utilization/"},
         {"kind": "series", "title": "Network traffic (top 10)", "unit": "bps", "top": 10, "w": 24,
          "re": r"/Bits (received|sent)/"},
         {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
     ]},
    {"key": "ups", "title": "UPS", "categories": ["ups"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "Battery charge", "low_is_bad": True,
         "zbx": "*attery*", "re": r"/battery.*(capacity|charge)/i"},
        {"kind": "gauge", "title": "Output load", "zbx": "*load*", "re": r"/output.*load/i"},
        {"kind": "series", "title": "Remaining runtime", "unit": "s", "re": r"/runtime/i"},
        {"kind": "series", "title": "Input voltage", "unit": "volt", "re": r"/input.*voltage/i"},
    ]},
    {"key": "storage", "title": "Storage / NAS", "categories": ["storage"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "Volume usage", "w": 24, "h": 10, "per_item": True,
         "zbx": "*olume*", "re": r"/(volume|space|storage).*(used|utilization|usage)/i"},
        {"kind": "gauge", "title": "CPU", **CPU},
        {"kind": "gauge", "title": "Memory", **MEM},
        {"kind": "series", "title": "Disk temperature", "unit": "celsius", **TEMP},
    ]},
    {"key": "server-hardware", "title": "Server hardware (iDRAC/iLO)", "categories": ["server-hardware"],
     "panels": [
         {"kind": "problems"},
         {"kind": "availability"},
         {"kind": "series", "title": "Temperatures", "unit": "celsius", **TEMP},
         {"kind": "series", "title": "Fans", "unit": "rpm", "re": r"/fan/i"},
         {"kind": "stat", "title": "Overall / power supply status", "per_item": True,
          "re": r"/(overall|global|system|power supply|psu).*status/i"},
     ]},
    {"key": "cctv", "title": "CCTV & Cameras", "categories": ["cctv"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "latency"},
        {"kind": "series", "title": "Network traffic (top 10)", "unit": "bps", "top": 10, **TRAFFIC_IN},
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]},
    {"key": "voip", "title": "VoIP & Telephony", "categories": ["voip"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "latency"},
        {"kind": "series", "title": "Network traffic (top 10)", "unit": "bps", "top": 10, **TRAFFIC_IN},
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]},
    {"key": "pdu", "title": "PDU", "categories": ["pdu"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "Output load", "zbx": "*load*", "re": r"/output.*load|load/i"},
        {"kind": "series", "title": "Input voltage", "unit": "volt", "re": r"/input.*voltage|voltage/i"},
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]},
]


def groups_for(spec, cfg):
    """Host groups shown by a dashboard (all rule groups for the overview)."""
    mapping = category_groups(cfg)
    if spec["categories"] is None:
        return sorted(set(mapping.values()))
    return sorted({mapping[c] for c in spec["categories"] if c in mapping})


# ======================================================================= Grafana

DS = {"type": "alexanderzobnin-zabbix-datasource", "uid": "zabbix"}
UP_DOWN = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red"},
                                         "1": {"text": "UP", "color": "green"}}}]
AGENT_MAP = [{"type": "value", "options": {"0": {"text": "NO AGENT", "color": "red"},
                                           "1": {"text": "OK", "color": "green"}}}]
RED_GREEN = [{"color": "red", "value": None}, {"color": "green", "value": 1}]
PCT = [{"color": "green", "value": None}, {"color": "orange", "value": 80}, {"color": "red", "value": 90}]
PCT_LOW = [{"color": "red", "value": None}, {"color": "orange", "value": 20}, {"color": "green", "value": 50}]


def _group_regex(groups):
    if not groups:
        return "/^$/"
    return "/^(" + "|".join(re.escape(g).replace("/", "\\/") for g in groups) + ")$/"


def _target(item, functions=(), ref="A"):
    return {"refId": ref, "queryType": "0", "datasource": DS,
            "group": {"filter": "$group"}, "host": {"filter": "$host"},
            "application": {"filter": ""}, "itemTag": {"filter": ""}, "item": {"filter": item},
            "functions": list(functions), "options": {"showDisabledItems": False, "skipEmptyValues": True}}


def _alias(text):
    return {"def": {"name": "setAlias", "category": "Alias"}, "params": [text]}


def _top(n):
    return {"def": {"name": "top", "category": "Filter"}, "params": [str(n), "avg"]}


def _problems(title, tags="", min_severity=1):
    return {"type": "alexanderzobnin-zabbix-triggers-panel", "title": title, "datasource": DS,
            "targets": [{"refId": "A", "queryType": "5", "datasource": DS,
                         "group": {"filter": "$group"}, "host": {"filter": "$host"},
                         "application": {"filter": ""}, "proxy": {"filter": ""},
                         "trigger": {"filter": ""}, "tags": {"filter": tags},
                         "showProblems": "problems",
                         "options": {"minSeverity": min_severity, "acknowledged": 2,
                                     "sortProblems": "priority", "hostsInMaintenance": False,
                                     "limit": 500}}],
            "options": {"hostField": True, "hostGroups": True, "severityField": True, "ageField": True,
                        "showTags": True, "pageSize": 10}}


def _stat(title, item, unit=None, mappings=None, steps=None, per_item=False):
    label = "$__zbx_host_name: $__zbx_item" if per_item else "$__zbx_host_name"
    defaults = {"mappings": mappings or []}
    if unit:
        defaults["unit"] = unit
    if steps:
        defaults["thresholds"] = {"mode": "absolute", "steps": steps}
    return {"type": "stat", "title": title, "datasource": DS,
            "targets": [_target(item, [_alias(label)])],
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
                        "colorMode": "background", "graphMode": "none", "textMode": "value_and_name",
                        "orientation": "auto", "wideLayout": True},
            "fieldConfig": {"defaults": defaults, "overrides": []}}


def _gauge(title, item, steps, per_item=False):
    p = _stat(title, item, unit="percent", steps=steps, per_item=per_item)
    p["type"] = "bargauge"
    p["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
                    "orientation": "horizontal", "displayMode": "gradient", "showUnfilled": True}
    p["fieldConfig"]["defaults"].update(min=0, max=100)
    return p


def _series(title, item, unit=None, top=None, label="$__zbx_host_name: $__zbx_item"):
    defaults = {"unit": unit} if unit else {}
    return {"type": "timeseries", "title": title, "datasource": DS,
            "targets": [_target(item, [_alias(label)] + ([_top(top)] if top else []))],
            "fieldConfig": {"defaults": defaults, "overrides": []},
            "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"]},
                        "tooltip": {"mode": "multi", "sort": "desc"}}}


def _grafana_panel(p, spec_title):
    kind = p["kind"]
    if kind == "problems":
        return _problems(f"Problems - {spec_title}", min_severity=p.get("min_severity", 1)), 24, 8
    if kind == "availability":
        return _stat("Availability (ICMP)", "ICMP ping", mappings=UP_DOWN, steps=RED_GREEN), 24, 6
    if kind == "agent_missing":
        return _problems("Servers without Zabbix agent", tags="agent:missing"), p.get("w", 24), 7
    if kind == "agent_status":
        return (_stat("Zabbix agent", f"/{re.escape(AGENT_PORT_ITEM)}/", mappings=AGENT_MAP, steps=RED_GREEN),
                p.get("w", 24), 7)
    if kind == "latency":
        return _series("ICMP latency", "ICMP response time", "s", label="$__zbx_host_name"), p.get("w", 12), 8
    if kind == "loss":
        return _series("ICMP packet loss", "ICMP loss", "percent", label="$__zbx_host_name"), p.get("w", 12), 8
    if kind == "gauge":
        steps = PCT_LOW if p.get("low_is_bad") else PCT
        return _gauge(p["title"], p["re"], steps, p.get("per_item")), p.get("w", 12), p.get("h", 7)
    if kind == "series":
        return _series(p["title"], p["re"], p.get("unit"), p.get("top")), p.get("w", 12), p.get("h", 8)
    if kind == "stat":
        return _stat(p["title"], p["re"], unit=p.get("unit"), per_item=p.get("per_item")), 24, p.get("h", 5)
    raise ValueError(f"unknown panel kind {kind}")


def _layout(sized):
    x = y = row_h = 0
    panels = []
    for i, (panel, w, h) in enumerate(sized, 1):
        if x + w > 24:
            x, y, row_h = 0, y + row_h, 0
        panel["id"] = i
        panel["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        x += w
        row_h = max(row_h, h)
        panels.append(panel)
    return panels


def grafana_dashboard(spec, cfg, datasource_uid="zabbix"):
    group_re = _group_regex(groups_for(spec, cfg))
    ds = {"type": DS["type"], "uid": "${datasource}"}
    variables = [
        {"name": "datasource", "label": "Zabbix", "type": "datasource", "query": DS["type"],
         "current": {"text": datasource_uid, "value": datasource_uid}, "hide": 0},
        {"name": "group", "label": "Group", "type": "query", "datasource": ds,
         "query": {"queryType": "group", "group": group_re, "host": "", "application": "",
                   "itemTag": "", "item": ""},
         "multi": True, "includeAll": True, "allValue": group_re, "refresh": 1, "sort": 1,
         "current": {"text": "All", "value": "$__all"}},
        {"name": "host", "label": "Host", "type": "query", "datasource": ds,
         "query": {"queryType": "host", "group": "$group", "host": "/.*/", "application": "",
                   "itemTag": "", "item": ""},
         "multi": True, "includeAll": True, "allValue": "/.*/", "refresh": 2, "sort": 1,
         "current": {"text": "All", "value": "$__all"}},
    ]
    sized = [_grafana_panel(dict(p), spec["title"]) for p in spec["panels"]]
    text = json.dumps(_layout(sized))
    panels = json.loads(text.replace(json.dumps(DS)[1:-1], json.dumps(ds)[1:-1]))
    return {
        "uid": f"autodiscovery-{spec['key']}", "title": f"{PREFIX}{spec['title']}",
        "tags": ["autodiscovery", "zabbix"], "timezone": "browser", "refresh": "1m",
        "schemaVersion": 39, "editable": True, "time": {"from": "now-6h", "to": "now"},
        "links": [{"title": "AutoDiscovery dashboards", "type": "dashboards", "tags": ["autodiscovery"],
                   "asDropdown": True, "includeVars": False, "keepTime": True}],
        "templating": {"list": variables},
        "panels": panels,
    }

# Native Zabbix dashboards are built by zbxdash.py from the items that exist on the hosts.
