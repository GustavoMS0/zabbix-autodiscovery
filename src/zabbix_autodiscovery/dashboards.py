"""Per-device-type dashboards, rendered either as native Zabbix dashboards or as Grafana JSON.

One spec drives both outputs. Host groups are taken from the config rules (category -> group),
so dashboards follow whatever group names each installation uses.
"""
import json
import re

from .config import category_groups

PREFIX = "AutoDiscovery - "
AGENT_PORT_ITEM = "Zabbix agent: port 10050 reachable"
AGENT_STATUS_RE = rf"/^(Zabbix agent availability|{re.escape(AGENT_PORT_ITEM)})$/"

# Item filters: "zbx" is a Zabbix item-name pattern (honeycomb, * wildcard),
# "re" is the Grafana-Zabbix plugin regex (each vendor template names items differently).
# Regexes are anchored where possible: a loose regex pulls hundreds of items (per-core CPU, VLANs, status
# items) and the history query of the plugin then gets slow or fails (Zabbix returns HTTP 500 on ~350k rows).
CPU = {"zbx": "*utilization*", "re": r"/(^|: )CPU utilization$/i"}     # load average is not a % (own panels)
MEM = {"zbx": "*Memory utilization*", "re": r"/Memory utilization/i"}
TEMP = {"zbx": "*emp*", "re": r"/^(?!.*(status|alarm|tempo|walk)).*(temperat|temp\b)/i"}  # not alarms / runtime
# Physical interfaces only: LAGs, VLANs, stack/CPU ports, loopbacks, FortiLink and the FortiGate virtual
# interfaces (ssl.root, VPN-FGFM...) and sub-interfaces (eth0.40) multiply the items without adding information.
IF_PHYSICAL = r"^Interface (?!.*(lag|vlan|stack|user defined|cpu interface|loo?pback|fortilink|fgfm|" \
              r"(ssl|l2t|naf|wqtn?)\.|\.\d+\())"
TRAFFIC_IN = {"re": f"/{IF_PHYSICAL}.*: Bits received$/i"}
TRAFFIC_OUT = {"re": f"/{IF_PHYSICAL}.*: Bits sent$/i"}
ERRORS = {"re": f"/{IF_PHYSICAL}.*: (Inbound|Outbound) packets with errors$/i"}
ERRORS_IN = {"re": f"/{IF_PHYSICAL}.*: Inbound packets with errors$/i"}
DISCARDS_IN = {"re": f"/{IF_PHYSICAL}.*: Inbound packets discarded$/i"}
UPTIME = {"re": r"/^(Uptime \(network\)|System uptime|Uptime)$/"}   # not "Uptime (hardware)": 0 on switches
SUPPLIES = {"zbx": "*Level %*", "re": r"/: Level %$/"}                # not the raw level (up to 100000)
LOAD_1M = {"re": r"/^Load average \(1m avg\)$/"}
WAN_RE = r"interface\s+(?!fortilink|loopback)(wan\d*|uplink\d*|internet\d*|a\([^)]*(wan|internet|net\s*fiber|mbps|ligga|its|easy|america|mega)[^)]*\))"
WAN_IN = {"re": f"/{WAN_RE}.*: bits received/i"}
WAN_OUT = {"re": f"/{WAN_RE}.*: bits sent/i"}
WAN_STATUS = {"re": f"/{WAN_RE}.*: operational status/i"}
SDWAN_LATENCY = {"re": r"/^SD-WAN .*: Latency$/"}
SDWAN_JITTER = {"re": r"/^SD-WAN .*: Jitter$/"}
SDWAN_LOSS = {"re": r"/(sd-wan|sla).*packets? loss$/i"}               # not the probe "packets ... per second"

UNKNOWN_COLOR = "#8e8e8e"
# ICMP ping (0/1) and the zabbix[host,*,available] items (0 = not available, 1 = available, 2 = unknown)
UP_DOWN = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red"},
                                         "1": {"text": "UP", "color": "green"},
                                         "2": {"text": "UNKNOWN", "color": UNKNOWN_COLOR}}}]
RED_GREEN = [{"color": "red", "value": None}, {"color": "green", "value": 1}, {"color": UNKNOWN_COLOR, "value": 2}]
# FortiGate "VPN status" value map
VPN_MAP = [{"type": "value", "options": {"1": {"text": "DOWN", "color": "red"},
                                         "2": {"text": "UP", "color": "green"}}}]
VPN_STEPS = [{"color": "red", "value": None}, {"color": "green", "value": 2}]
# Dell iDRAC ObjectStatusEnum
IDRAC_MAP = [{"type": "value", "options": {"1": {"text": "OTHER", "color": UNKNOWN_COLOR},
                                           "2": {"text": "UNKNOWN", "color": UNKNOWN_COLOR},
                                           "3": {"text": "OK", "color": "green"},
                                           "4": {"text": "NON-CRITICAL", "color": "orange"},
                                           "5": {"text": "CRITICAL", "color": "red"},
                                           "6": {"text": "NON-RECOVERABLE", "color": "red"}}}]
IDRAC_STEPS = [{"color": UNKNOWN_COLOR, "value": None}, {"color": "green", "value": 3},
               {"color": "orange", "value": 4}, {"color": "red", "value": 5}]
LOAD_STEPS = [{"color": "green", "value": None}, {"color": "orange", "value": 1.5}, {"color": "red", "value": 3}]
NOT_EXPOSED = "Not exposed via SNMP by this model"
# Panels marked "heavy" read the raw history of many items (trends are off: trend.get fails with plugin 6.9.1).
# Measured with all hosts: OK at 24h; switches fail from 2d, the others from 3d (empty HTTP 500 = PHP memory).
LONG_RANGE_NOTE = ("Raw history of many items: with all hosts selected, ranges longer than about 2 days "
                   "(1 day on switches) can exceed the Zabbix frontend memory limit and fail with HTTP 500. "
                   "Select fewer hosts or raise ZBX_MEMORYLIMIT on the Zabbix web container.")
# Dashboards with heavy panels offer only the quick ranges that work with all hosts (spec "max_range"
# overrides the cap). A longer range can still be typed or zoomed to: the panels then hit the limit above.
MAX_RANGE = "2d"
QUICK_RANGES = [("5m", "Last 5 minutes"), ("15m", "Last 15 minutes"), ("30m", "Last 30 minutes"),
                ("1h", "Last 1 hour"), ("3h", "Last 3 hours"), ("6h", "Last 6 hours"), ("12h", "Last 12 hours"),
                ("1d", "Last 24 hours"), ("2d", "Last 2 days"), ("7d", "Last 7 days")]

OPER_STATUS_MAP = [
    {
        "type": "value",
        "options": {
            "1": {"text": "UP", "color": "green", "index": 0},
            "2": {"text": "DOWN", "color": "red", "index": 1},
            "3": {"text": "TESTING", "color": "yellow", "index": 2},
            "4": {"text": "UNKNOWN", "color": "orange", "index": 3},
            "5": {"text": "DORMANT", "color": "blue", "index": 4},
            "6": {"text": "NOT PRESENT", "color": "dark-grey", "index": 5},
            "7": {"text": "DOWN", "color": "red", "index": 6},
        },
    }
]
OPER_STATUS_STEPS = [
    {"color": "red", "value": None},
    {"color": "green", "value": 1},
    {"color": "red", "value": 2},
]


def network_panels(extra=(), **override):
    """Panels shared by network devices. override replaces a base panel by name (None drops it):
    cpu, memory, traffic_in, traffic_out, errors, latency."""
    base = {
        "cpu": {"kind": "gauge", "title": "CPU", "no_value": NOT_EXPOSED,
                "description": "Only devices whose template exposes CPU utilization are listed.", **CPU},
        "memory": {"kind": "gauge", "title": "Memory", "no_value": NOT_EXPOSED,
                   "description": "Only devices whose template exposes memory utilization are listed.", **MEM},
        "traffic_in": {"kind": "series", "title": "Inbound traffic (top 10 interfaces)", "unit": "bps", "top": 10,
                       "heavy": True, **TRAFFIC_IN},
        "traffic_out": {"kind": "series", "title": "Outbound traffic (top 10 interfaces)", "unit": "bps",
                        "top": 10, "heavy": True, **TRAFFIC_OUT},
        "errors": {"kind": "series", "title": "Interface errors (top 10)", "top": 10, "top_fn": "max",
                   "heavy": True, **ERRORS},
        "latency": {"kind": "latency"},
    }
    unknown = set(override) - set(base)
    if unknown:
        raise ValueError(f"unknown network panel(s) {sorted(unknown)}")
    base.update(override)
    latency = base.pop("latency")
    return [
        {"kind": "problems"},
        {"kind": "availability"},
        *(p for p in base.values() if p),
        *([latency] if latency else []),
        *extra,
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]


# Panel keys besides kind/title/re (all optional): unit, w, h, top + top_fn, per_item, label, fns (extra
# plugin functions), draw ("bars"), mdp (maxDataPoints), time_from (stat/gauge window), no_value, description,
# more (extra series queries [{"re", "label"}]), heavy (adds LONG_RANGE_NOTE to the description).
# Spec keys: avail_re / avail_time_from (item of the availability panel), refresh (dashboard auto-refresh),
# max_range (longest quick range offered when a panel is heavy, default MAX_RANGE).
SPECS = [
    {"key": "overview", "title": "Network overview", "categories": None, "panels": [
        {"kind": "problems", "min_severity": 2},
        {"kind": "availability"},
        {"kind": "agent_missing", "w": 12},
        {"kind": "agent_status", "w": 12},
        {"kind": "latency", "worst": 10, "heavy": True},
        {"kind": "loss", "worst": 10, "heavy": True},
    ]},
    # ~370 physical ports: the interface panels fail from 2 days with all switches
    {"key": "switches", "title": "Switches", "categories": ["switch"], "max_range": "1d",
     "panels": network_panels([
        {"kind": "series", "title": "Temperature", "unit": "celsius", **TEMP},
    # inbound only, one query each: errors + discards of ~370 ports in a single regex time out
    ], errors={"kind": "series", "title": "Inbound errors & discards (top 10 each)", "top": 10, "top_fn": "max",
               "heavy": True, **ERRORS_IN, "more": [{"label": "$__zbx_host_name: $__zbx_item", **DISCARDS_IN}]})},
    {"key": "routers", "title": "Routers", "categories": ["router"], "panels": network_panels([
        {"kind": "series", "title": "Temperature", "unit": "celsius", **TEMP},
    ])},
    {"key": "firewalls", "title": "Firewalls", "categories": ["firewall"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "wan_status", "title": "WAN Links Operational Status", **WAN_STATUS},
        {"kind": "wan_traffic", "title": "Internet Links / WAN Inbound Traffic", "unit": "bps", "top": 10, **WAN_IN},
        {"kind": "wan_traffic", "title": "Internet Links / WAN Outbound Traffic", "unit": "bps", "top": 10, **WAN_OUT},
        {"kind": "series", "title": "SD-WAN Links Latency", "unit": "ms", "heavy": True, **SDWAN_LATENCY},
        {"kind": "series", "title": "SD-WAN Links Jitter", "unit": "ms", "heavy": True, **SDWAN_JITTER},
        {"kind": "series", "title": "SD-WAN Links Packet Loss", "unit": "percent", "heavy": True,
         **SDWAN_LOSS},
        {"kind": "gauge", "title": "CPU", **CPU},
        {"kind": "gauge", "title": "Memory", **MEM},
        {"kind": "series", "title": "Active sessions", "label": "$__zbx_host_name",
         "re": r"/^VDOM root: Active sessions$/"},
        {"kind": "series", "title": "Active VPN tunnels / SSL VPN users",
         "re": r"/^Active (IPsec VPN tunnels|SSL VPN users)$/"},
        {"kind": "state", "title": "VPN tunnel status", "mappings": VPN_MAP, "steps": VPN_STEPS,
         "alias_re": r"/VPN (.*): Tunnel Status$/", "re": r"/^VPN .*: Tunnel Status$/"},
        {"kind": "series", "title": "Inbound traffic (physical interfaces, top 10)", "unit": "bps", "top": 10,
         "heavy": True, **TRAFFIC_IN},
        {"kind": "series", "title": "Outbound traffic (physical interfaces, top 10)", "unit": "bps", "top": 10,
         "heavy": True, **TRAFFIC_OUT},
        {"kind": "series", "title": "Inbound interface errors (top 10)", "top": 10, "top_fn": "max", "heavy": True,
         **ERRORS_IN},
        {"kind": "latency"},
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]},
    # UniFi APs: CPU is only a load average, eth0 is the uplink, wifi/ra are the radios
    # 30 s items on ~16 APs read ~322k rows in 7 days, at the HTTP 500 limit: flagged heavy
    {"key": "access-points", "title": "Access points", "categories": ["ap"], "panels": network_panels([
        {"kind": "series", "title": "CPU Load average (1m)", "label": "$__zbx_host_name", "heavy": True,
         **LOAD_1M},
        # no "Connected clients" panel yet: the AirOS template has no client items on UniFi; it needs a
        # "AutoDiscovery - UniFi wireless" template (per-ESSID clients, MIB 1.3.6.1.4.1.41112.1.6.1.2.1.8)
    ], cpu={"kind": "gauge", "title": "CPU load (1m)", "unit": "none", "max": None, "steps": LOAD_STEPS, **LOAD_1M},
        traffic_in={"kind": "series", "title": "Uplink traffic in (eth0)", "unit": "bps", "label": "$__zbx_host_name",
                    "heavy": True, "re": r"/^Interface eth0\(\): Bits received$/"},
        traffic_out={"kind": "series", "title": "Uplink traffic out (eth0)", "unit": "bps",
                     "label": "$__zbx_host_name", "heavy": True, "re": r"/^Interface eth0\(\): Bits sent$/"},
        latency={"kind": "latency", "heavy": True},
        errors={"kind": "series", "title": "Interface errors (top 10)", "unit": "pps", "top": 10, "top_fn": "max",
                "heavy": True, "re": r"/^Interface (eth0|wifi\d|ra\d|rai\d)\(\): .*packets with errors$/"})},
    {"key": "printers", "title": "Printers", "categories": ["printer"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "Supply levels (toner/ink/drum)", "w": 24, "h": 10, "low_is_bad": True,
         "per_item": True, "time_from": "3h", **SUPPLIES},
        {"kind": "series", "title": "Pages printed", "w": 24, "unit": "none", "label": "$__zbx_host_name",
         "fns": ["delta"], "draw": "bars", "re": r"/^Printer: Total page count$/"},
        # ~18 printers pinged every 30 s: 7 days is ~360k rows (HTTP 500), 5 days still works
        {"kind": "latency", "w": 24, "heavy": True},
    ]},
    {"key": "servers", "title": "Servers", "categories": ["server-windows", "server-linux", "hypervisor"],
     "avail_re": r"/^(ICMP ping|Zabbix agent availability)$/",
     # traffic top 10 still reads every interface's history: OK at 7d, HTTP 500 at 30d
     "max_range": "7d",
     "panels": [
         {"kind": "problems"},
         {"kind": "agent_missing", "w": 12},
         {"kind": "agent_status", "w": 12},
         {"kind": "availability"},
         {"kind": "gauge", "title": "CPU", **CPU},
         {"kind": "gauge", "title": "Memory", **MEM},
         {"kind": "gauge", "title": "Disk usage per volume", "w": 24, "h": 10, "per_item": True,
          "zbx": "*Space utilization*", "re": r"/Space: Used, in %|Space utilization/"},
         {"kind": "series", "title": "Inbound traffic (top 10)", "unit": "bps", "top": 10, **TRAFFIC_IN},
         {"kind": "series", "title": "Outbound traffic (top 10)", "unit": "bps", "top": 10, **TRAFFIC_OUT},
         {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
     ]},
    {"key": "ups", "title": "UPS", "categories": ["ups"], "panels": [
        {"kind": "problems"},
        {"kind": "availability"},
        {"kind": "gauge", "title": "Battery charge", "low_is_bad": True,
         "zbx": "*carga*", "re": r"/(battery.*(capacity|charge)|bateria.*carga)/i"},
        {"kind": "gauge", "title": "Output load", "zbx": "*carga*",
         "re": r"/(output.*load|sa[ií]da.*(percentual de carga|carga)|percentual de carga)/i"},
        {"kind": "series", "title": "Remaining runtime", "unit": "m",
         "re": r"/(runtime|tempo restante)/i"},
        {"kind": "series", "title": "Input voltage", "unit": "volt",
         "re": r"/(input.*voltage|entrada.*tens[aã]o|tens[aã]o.*entrada)/i"},
        {"kind": "series", "title": "Output voltage", "unit": "volt",
         "re": r"/(output.*voltage|sa[ií]da.*tens[aã]o|tens[aã]o.*sa[ií]da)/i"},
        {"kind": "series", "title": "Battery temperature", "unit": "celsius", **TEMP},
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
    # iDRAC items keep only changed values with a 6h heartbeat: status tiles need a 24h window
    {"key": "server-hardware", "title": "Server hardware (iDRAC/iLO)", "categories": ["server-hardware"],
     "avail_re": r"/^SNMP agent availability$/", "avail_time_from": "24h",
     "panels": [
         {"kind": "problems"},
         {"kind": "availability"},
         {"kind": "series", "title": "Temperatures", "unit": "celsius", "re": r"/^Probe \[.*Temp.*\]: Value$/"},
         {"kind": "series", "title": "Fans", "unit": "rpm", "mdp": 200, "heavy": True,
          "re": r"/^Fan \[.*\]: Speed$/"},
         {"kind": "stat", "title": "Overall / power supply status", "per_item": True, "time_from": "24h",
          "mappings": IDRAC_MAP, "steps": IDRAC_STEPS,
          "re": r"/^(Overall system health status|Power supply \[.*\]: State)$/"},
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
        {"kind": "gauge", "title": "Output load", "zbx": "*load*",
         "re": r"/(output|outlet|phase).*(load|current|power)(?!.*average)/i"},
        {"kind": "series", "title": "Input voltage", "unit": "volt", "re": r"/(input|phase).*voltage(?!.*status)/i"},
        {"kind": "stat", "title": "Uptime", "unit": "s", **UPTIME},
    ]},
]


def groups_for(spec, cfg):
    """Host groups shown by a dashboard (all rule groups for the overview)."""
    mapping = category_groups(cfg)
    if spec["categories"] is None:
        return sorted(set(mapping.values()))
    return sorted({mapping[c] for c in spec["categories"] if c in mapping})


def host_counts(api, groups):
    """{group: number of enabled hosts} from Zabbix (a group that does not exist yet counts as 0).
    Disabled hosts are left out, as in provision.setup_zabbix_dashboards: they collect no data."""
    found = api.call("hostgroup.get", {"output": ["groupid", "name"], "filter": {"name": list(groups)}})
    counts = dict.fromkeys(groups, 0)
    for g in found:
        counts[g["name"]] = int(api.call("host.get", {"groupids": [g["groupid"]], "filter": {"status": 0},
                                                      "countOutput": True}) or 0)
    return counts


def specs_to_build(cfg, api=None, log=print):
    """Specs that get a dashboard: those with a host group in the rules and, when a Zabbix API is given,
    at least one host in those groups. Without an API (offline) or if the lookup fails, every spec with groups
    is kept, so generation never depends on Zabbix being reachable."""
    specs = [s for s in SPECS if groups_for(s, cfg)]
    if api is None:
        return specs
    try:
        counts = host_counts(api, sorted({g for s in specs for g in groups_for(s, cfg)}))
    except Exception as exc:                 # any API/network error: fall back to the offline behaviour
        log(f"  ! could not count hosts per group ({exc}); generating every dashboard")
        return specs
    kept = []
    for spec in specs:
        if sum(counts.get(g, 0) for g in groups_for(spec, cfg)):
            kept.append(spec)
        else:
            log(f"  - skipped '{spec['key']}': no hosts in {', '.join(groups_for(spec, cfg))}")
    return kept


# ======================================================================= Grafana

DS = {"type": "alexanderzobnin-zabbix-datasource", "uid": "zabbix"}
# 1 = OK for both items; zabbix[host,agent,available] also has 2 = unknown
AGENT_MAP = [{"type": "value", "options": {"0": {"text": "NO AGENT", "color": "red"},
                                           "1": {"text": "OK", "color": "green"},
                                           "2": {"text": "UNKNOWN", "color": UNKNOWN_COLOR}}}]
PCT = [{"color": "green", "value": None}, {"color": "orange", "value": 80}, {"color": "red", "value": 90}]
PCT_LOW = [{"color": "red", "value": None}, {"color": "orange", "value": 20}, {"color": "green", "value": 50}]
STAT_WINDOW = "15m"        # stat/gauge panels show the last value: no need to fetch the whole dashboard range
STAT_MDP = 100
SERIES_MDP = 500


def _group_regex(groups):
    if not groups:
        return "/^$/"
    return "/^(" + "|".join(re.escape(g).replace("/", "\\/") for g in groups) + ")$/"


def _target(item, functions=(), ref="A", group="$group", host="$host"):
    # useTrends 'false': plugin 6.9 sends "sortfield" to trend.get, which Zabbix 8.0 rejects, so every range
    # over 4 days (trendsRange) failed. Switch back to 'default' once the plugin is fixed.
    return {"refId": ref, "queryType": "0", "datasource": DS,
            "group": {"filter": group}, "host": {"filter": host},
            "application": {"filter": ""}, "itemTag": {"filter": ""}, "item": {"filter": item},
            "functions": list(functions),
            "options": {"showDisabledItems": False, "skipEmptyValues": True, "disableDataAlignment": True,
                        "useTrends": "false"}}


def _fn(name, category, params=(), param_defs=(), default_params=()):
    """A Grafana-Zabbix plugin function (the backend reads def.name and params)."""
    return {
        "def": {"name": name, "category": category, "params": list(param_defs),
                "defaultParams": list(default_params)},
        "params": list(params),
        "text": f"{name}({', '.join(str(p) for p in params)})",
    }


AGG_OPTIONS = ["avg", "min", "max", "sum", "count", "median", "first", "last"]


def _alias(text):
    return _fn("setAlias", "Alias", [text], [{"name": "alias", "type": "string"}])


def _top(n, fn="avg"):
    """top(n, fn): fn "max" keeps the series with the worst burst (avg hides short error spikes)."""
    return _fn("top", "Filter", [int(n), fn],
               [{"name": "number", "type": "int"}, {"name": "value", "type": "string", "options": AGG_OPTIONS}],
               [5, "avg"])


def _group_by(interval, fn="avg"):
    return _fn("groupBy", "Transform", [interval, fn],
               [{"name": "interval", "type": "string"},
                {"name": "function", "type": "string", "options": AGG_OPTIONS}],
               ["1m", "avg"])


def _delta():
    """Difference between consecutive values (e.g. pages printed per interval from a page counter)."""
    return _fn("delta", "Transform")


FUNCTIONS = {"delta": _delta}       # spec "fns" names


def _replace_alias(regexp, new_alias):
    return _fn("replaceAlias", "Alias", [regexp, new_alias],
               [{"name": "regexp", "type": "string"}, {"name": "newAlias", "type": "string"}],
               ["/(.*)/", "$1"])


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


def _describe(panel, no_value=None, description=None):
    if no_value:
        panel["fieldConfig"]["defaults"]["noValue"] = no_value
    if description:
        panel["description"] = description
    return panel


def _stat(title, item, unit=None, mappings=None, steps=None, per_item=False, wide=True, functions=None,
          time_from=STAT_WINDOW, no_value=None, description=None):
    """Last value per series. time_from limits the query to a short window (hidden in the panel header):
    the panel only shows lastNotNull, and it keeps working on ranges the history API cannot serve."""
    if functions is None:
        label = "$__zbx_host_name: $__zbx_item" if per_item else "$__zbx_host_name"
        functions = [_alias(label)]
    defaults = {"mappings": mappings or []}
    if unit:
        defaults["unit"] = unit
    if steps:
        defaults["thresholds"] = {"mode": "absolute", "steps": steps}
    panel = {"type": "stat", "title": title, "datasource": DS, "maxDataPoints": STAT_MDP,
             "targets": [_target(item, functions)],
             "options": {"reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
                         "colorMode": "background", "graphMode": "none", "textMode": "value_and_name",
                         "orientation": "auto", "wideLayout": wide},
             "fieldConfig": {"defaults": defaults, "overrides": []}}
    if time_from:
        panel.update(timeFrom=time_from, hideTimeOverride=True)
    return _describe(panel, no_value, description)


def _gauge(title, item, steps, per_item=False, unit="percent", max_value=100, **kwargs):
    p = _stat(title, item, unit=unit, steps=steps, per_item=per_item, **kwargs)
    p["type"] = "bargauge"
    p["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
                    "orientation": "horizontal", "displayMode": "gradient", "showUnfilled": True}
    p["fieldConfig"]["defaults"]["min"] = 0
    if max_value is not None:
        p["fieldConfig"]["defaults"]["max"] = max_value
    return p


def _series(title, item, unit=None, top=None, label="$__zbx_host_name: $__zbx_item", top_fn="avg", pre=(),
            mdp=SERIES_MDP, draw=None, no_value=None, description=None, more=()):
    """Time series. pre: functions applied before the alias (groupBy, delta...).
    more: extra (item, label) queries B, C... with the same functions; separate history queries stay fast
    where one regex over all the items times out."""
    defaults = {"unit": unit} if unit else {}
    if draw == "bars":
        defaults["custom"] = {"drawStyle": "bars", "fillOpacity": 80, "lineWidth": 1}
    head = list(pre) + ([_top(top, top_fn)] if top else [])
    targets = [_target(it, head + [_alias(lb)], ref=chr(ord("A") + n))
               for n, (it, lb) in enumerate([(item, label), *more])]
    panel = {"type": "timeseries", "title": title, "datasource": DS, "maxDataPoints": mdp,
             "targets": targets,
             "fieldConfig": {"defaults": defaults, "overrides": []},
             "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"]},
                         "tooltip": {"mode": "multi", "sort": "desc"}}}
    return _describe(panel, no_value, description)


def _grafana_panel(p, spec):
    panel, w, h = _panel_body(p, spec)
    if p.get("heavy"):
        panel["description"] = " ".join(filter(None, [panel.get("description"), LONG_RANGE_NOTE]))
    return panel, w, h


def _panel_body(p, spec):
    kind = p["kind"]
    spec_title = spec["title"]
    if kind == "problems":
        return _problems(f"Problems - {spec_title}", min_severity=p.get("min_severity", 1)), 24, 8
    if kind == "availability":
        item = spec.get("avail_re", "ICMP ping")
        icmp = item == "ICMP ping"
        return _stat("Availability (ICMP)" if icmp else "Availability", item, mappings=UP_DOWN, steps=RED_GREEN,
                     per_item=not icmp and "|" in item, time_from=spec.get("avail_time_from", STAT_WINDOW)), 24, 6
    if kind == "wan_status":
        fns = [
            _alias("$__zbx_host_name: $__zbx_item"),
            # runs on the "host: item" alias, so match after the host prefix (no ^ anchor)
            _replace_alias(r"/: (?:Interface\s+)?([^:]+):\s+Operational status$/i", " - $1"),
        ]
        return _stat(p["title"], p["re"], mappings=OPER_STATUS_MAP, steps=OPER_STATUS_STEPS,
                     per_item=True, wide=False, functions=fns), p.get("w", 24), p.get("h", 6)
    if kind == "state":
        # one tile per item with a value map (e.g. VPN tunnels); alias_re trims the item name
        fns = [_alias("$__zbx_host_name: $__zbx_item")]
        if p.get("alias_re"):
            fns.append(_replace_alias(p["alias_re"], "$1"))
        return _stat(p["title"], p["re"], mappings=p.get("mappings"), steps=p.get("steps"), wide=False,
                     functions=fns, time_from=p.get("time_from", STAT_WINDOW)), p.get("w", 24), p.get("h", 8)
    if kind == "wan_traffic":
        fns = [
            _alias("$__zbx_host_name: $__zbx_item"),
            _replace_alias(r"/: (?:Interface\s+)?([^:]+):\s+Bits (?:received|sent)$/i", " - $1"),
        ]
        if p.get("top"):
            fns.append(_top(p["top"]))
        defaults = {"unit": p.get("unit", "bps")}
        return {
            "type": "timeseries", "title": p["title"], "datasource": DS, "maxDataPoints": SERIES_MDP,
            "targets": [_target(p["re"], fns)],
            "fieldConfig": {"defaults": defaults, "overrides": []},
            "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"]},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
        }, p.get("w", 12), p.get("h", 8)
    if kind == "agent_missing":
        return _problems("Servers without Zabbix agent", tags="agent:missing"), p.get("w", 24), 7
    if kind == "agent_status":
        return _stat("Zabbix agent", AGENT_STATUS_RE, mappings=AGENT_MAP, steps=RED_GREEN), p.get("w", 24), 7
    if kind in ("latency", "loss"):
        title, item, unit = (("ICMP latency", "ICMP response time", "s") if kind == "latency"
                             else ("ICMP packet loss", "ICMP loss", "percent"))
        if p.get("worst"):
            # many hosts: 5-minute averages of the worst N only (about 24x fewer points)
            return _series(f"{title} (worst {p['worst']})", item, unit, top=p["worst"], top_fn="max",
                           label="$__zbx_host_name", pre=[_group_by("5m")]), p.get("w", 12), 8
        return _series(title, item, unit, label="$__zbx_host_name"), p.get("w", 12), 8
    if kind == "gauge":
        steps = p.get("steps") or (PCT_LOW if p.get("low_is_bad") else PCT)
        return _gauge(p["title"], p["re"], steps, p.get("per_item"), unit=p.get("unit", "percent"),
                      max_value=p.get("max", 100), time_from=p.get("time_from", STAT_WINDOW),
                      no_value=p.get("no_value"), description=p.get("description")), p.get("w", 12), p.get("h", 7)
    if kind == "series":
        return _series(p["title"], p["re"], p.get("unit"), p.get("top"),
                       label=p.get("label", "$__zbx_host_name: $__zbx_item"), top_fn=p.get("top_fn", "avg"),
                       pre=[FUNCTIONS[f]() for f in p.get("fns", ())], mdp=p.get("mdp", SERIES_MDP),
                       draw=p.get("draw"), no_value=p.get("no_value"), description=p.get("description"),
                       more=[(q["re"], q.get("label", "$__zbx_host_name: $__zbx_item")) for q in p.get("more", ())]), \
            p.get("w", 12), p.get("h", 8)
    if kind == "stat":
        return _stat(p["title"], p["re"], unit=p.get("unit"), mappings=p.get("mappings"),
                     steps=p.get("steps"), per_item=p.get("per_item", False),
                     time_from=p.get("time_from", STAT_WINDOW), no_value=p.get("no_value"),
                     description=p.get("description")), p.get("w", 24), p.get("h", 5)
    raise ValueError(f"unknown panel kind {kind}")


def _quick_ranges(spec):
    """Quick ranges of the time picker up to the spec cap, or None (Grafana defaults) without heavy panels."""
    if "max_range" not in spec and not any(p.get("heavy") for p in spec["panels"]):
        return None
    return quick_ranges(spec.get("max_range", MAX_RANGE))


def quick_ranges(cap):
    """Time picker quick ranges from 5m up to cap (a QUICK_RANGES key)."""
    keys = [k for k, _ in QUICK_RANGES]
    return [{"from": f"now-{k}", "to": "now", "display": text} for k, text in QUICK_RANGES[:keys.index(cap) + 1]]


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
        # refresh 1 (on load), not 2 (on every time-range change): the host list does not follow the time range
        {"name": "host", "label": "Host", "type": "query", "datasource": ds,
         "query": {"queryType": "host", "group": "$group", "host": "/.*/", "application": "",
                   "itemTag": "", "item": ""},
         "multi": True, "includeAll": True, "allValue": "/.*/", "refresh": 1, "sort": 1,
         "current": {"text": "All", "value": "$__all"}},
    ]
    sized = [_grafana_panel(dict(p), spec) for p in spec["panels"]]
    text = json.dumps(_layout(sized))
    panels = json.loads(text.replace(json.dumps(DS)[1:-1], json.dumps(ds)[1:-1]))
    quick = _quick_ranges(spec)
    return {
        "uid": f"autodiscovery-{spec['key']}", "title": f"{PREFIX}{spec['title']}",
        # 5m: SNMP items are polled every 3m (printers every 30m), a 1m refresh only repeated the same queries
        "tags": ["autodiscovery", "zabbix"], "timezone": "browser", "refresh": spec.get("refresh", "5m"),
        "schemaVersion": 39, "editable": True, "time": {"from": "now-6h", "to": "now"},
        "links": [{"title": "AutoDiscovery dashboards", "type": "dashboards", "tags": ["autodiscovery"],
                   "asDropdown": True, "includeVars": False, "keepTime": True}],
        "templating": {"list": variables},
        **({"timepicker": {"quick_ranges": quick}} if quick else {}),
        "panels": panels,
    }

# Native Zabbix dashboards are built by zbxdash.py from the items that exist on the hosts.
