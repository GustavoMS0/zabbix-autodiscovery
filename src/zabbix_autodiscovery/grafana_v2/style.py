"""Design system of the AutoDiscovery v2 Grafana dashboards ("NOC escuro neon").

Every v2 dashboard is built from these helpers so palette, typography, spacing and behaviour stay the same
everywhere. They are plain functions returning Grafana JSON dicts; anything they do not cover can be set
on the returned dict directly (or passed through **extra / options=).

Quick start
-----------
    from . import style as S

    cpu = S.target(S.CPU_RE, S.alias("$__zbx_host_name"), group="$group", host="$host")
    panels = S.grid(
        S.row("Saúde"),
        (4, [(S.kpi("CPU média", [cpu], unit="percent", steps=S.PCT, calcs=("mean",)), 6),
             (S.status_grid("Disponibilidade", [S.target(S.AVAIL_RE, S.alias("$__zbx_host_name"))],
                            mappings=S.AVAIL_MAP, steps=S.AVAIL_STEPS, time_from="7h"), 18)]),
        (8, [(S.timeseries("Tráfego", [...], unit="bps"), 24)]),
    )
    return S.dashboard("switches", "Switches", panels, datasource_uid=ds,
                       variables=S.category_variables(group_re))

Building blocks (details in each docstring)
-------------------------------------------
Tokens      OK WARN CRIT UNKNOWN INFO ACCENT (neon "ink" for values/lines on the dark panel), FILL_* (deep
            tile backgrounds that keep white text legible), SERIES (8 validated categorical colours),
            SEVERITIES / SEVERITY_COLOR / SEVERITY_NAME (Zabbix severities in PT-BR).
Thresholds  steps(base, (value, color), ...) and presets PCT, PCT_LOW, TEMP_INLET, LATENCY_S (seconds),
            LOSS_PCT, COUNT_BAD, AVAIL_RATIO (percentunit), LOAD, NEUTRAL.
Value maps  AVAIL_MAP (icmpping 0/1 and zabbix[host,*,available] 0/1/2), OPER_MAP (ifOperStatus), IDRAC_MAP,
            VPN_MAP, AGENT_MAP, each with a *_STEPS companion; value_map({...}) for new ones;
            no_data_map() (grey "SEM DADOS"); as_fill(x) swaps the neon colours for FILL_* (background tiles).
Targets     target(item, *functions, ref=, group=, host=) wraps dashboards._target (keeps useTrends 'false'
            and the history options). Functions: alias, replace_alias, top, bottom, group_by, delta,
            remove_above, sum_series, sort_series. Frontend-only queries: problems_target (problems panel),
            triggers_target (+ severity_transforms / severity_overrides = severity counters).
            dashboard_target(panel_id): reuse another panel's data, no extra Zabbix query.
Item regex  CPU_RE, MEM_RE, TEMP_RE, TRAFFIC_IN_RE/OUT, ERRORS_IN_RE, DISCARDS_IN_RE, UPTIME_RE,
            SUPPLIES_RE, LOAD_1M_RE, WAN_*_RE, SDWAN_*_RE, AGENT_STATUS_RE, AVAIL_RE: the verified v1 ones.
Transforms  tf(id, **options), organize, calc_binary, reduce_rows, reduce_fields, filter_fields, sort_by,
            as_text (keep a field for name templates without drawing it) and the health pipeline:
            health_targets(dims) + health_transforms() -> one row per site/category with
            Online / Total / Offline / Disponibilidade (see overview.py for tiles and KPI totals).
Panels      stat, kpi, status_grid, gauge, bargauge (rank=True: sorted worst first), timeseries
            (+ series_colors), state_timeline, status_history, table (+ col_color, col_gauge, col_width,
            col_props), text, banner, problems, row. Common keyword arguments of every panel:
            description, unit, decimals, min, max, mappings, steps, color, links, no_value, overrides,
            transformations, transparent, time_from (fixed window, hidden in the header), mdp
            (maxDataPoints), interval, datasource, id, display_name.
Layout      grid(*rows): rows of (height, [(panel, width), ...]) on the 24-column grid, row() section
            headers (collapsed rows carry their children), stack(...) for a column of panels inside a
            row. TV dashboards: TV_HEIGHT (27) grid units fill 1920x1080 in kiosk mode without scrolling.
Dashboard   dashboard(key, title, panels, ...) -> uid "autodiscovery-<key>-v2", title "AutoDiscovery v2 -
            <title>", PT-BR quick ranges capped by range_cap, shared crosshair, links to the other v2
            dashboards (tag "autodiscovery-v2"); tv=True hides the kiosk control bar and refreshes every 1m.
Variables   datasource_var, group_var, host_var, site_var (+ site_group_re(cfg, "$site")), site_hosts_var
            (+ SITE_HOSTS_RE), category_variables.
Config      sites(cfg) and categories(cfg): the Filiais/* site groups and the v2 category dashboards with
            their host groups (from the config rules, like v1); dashboard_url / data_link link to them.

Grafana behaviour worth knowing (all verified on Grafana 13.2 + plugin 6.9.1)
-----------------------------------------------------------------------------
- Grafana has no custom categorical palette for dynamic series: series named at build time get SERIES
  colours through series_colors(); top-N/per-host series use color=COLOR_SHADES (shades of cyan: the neon
  look, identity via legend/tooltip) or the Grafana classic palette (color=None).
- Alias functions (setAlias/replaceAlias) and problems/trigger queries run in the browser: /api/ds/query
  shows raw item names and cannot run them. Check those panels on a screenshot.
- Stat/gauge panels only show the last value: give them a short time_from window (STAT_WINDOW) so they
  stay cheap and keep working on ranges the Zabbix history API cannot serve.
- reduceOptions.fields matches display names: once a displayName is set, select fields with transforms
  (filter_fields / as_text) instead. A calculated field ignores the default displayName: use an override
  (col_props(name, displayName=...)). Name templates format every field with the panel unit, so give the
  unit to the drawn field through the same override.
- The plugin's "count by problems" trigger mode returns 0 with Zabbix 8 (it sends triggerids []);
  triggers_target uses the per-group table mode instead.
- SQL expressions cannot read the plugin's frames (no frame type), so aggregation across hosts happens in
  frontend transforms.
"""
import json
import re

from .. import dashboards as v1
from ..topology import AVAIL_RE

# ---------------------------------------------------------------------------------------------- tokens
# Neon "ink": values, lines and timeline bars on the dark panel (#181b1f). Bright on purpose: read from
# across the room on a TV, but not pure RGB primaries (garish).
OK = "#22E58A"          # neon green
WARN = "#FFB224"        # amber
CRIT = "#FF4D5E"        # neon red
UNKNOWN = "#7B8794"     # slate: no data / unknown state, never confused with a status colour
INFO = "#4FA3FF"        # blue, the "Informação" severity
ACCENT = "#22D3EE"      # cyan: identity of the NOC look (titles, neutral counters, single series)
ACCENT_2 = "#A78BFA"    # violet: second neutral accent (e.g. totals beside a cyan counter)
TEXT = "#E6EDF7"
MUTED = "#8B98AD"
# Deep fills for colorMode "background" tiles: Grafana puts white text on them, so a status grid reads as
# calm dark-green when all is well and a loud red block when something breaks.
FILL_OK = "#0E6B45"
FILL_WARN = "#A15C00"
FILL_CRIT = "#C0132F"
FILL_UNKNOWN = "#3A4250"
FILL_INFO = "#0B5A6B"
_TO_FILL = {OK: FILL_OK, WARN: FILL_WARN, CRIT: FILL_CRIT, UNKNOWN: FILL_UNKNOWN, ACCENT: FILL_INFO,
            INFO: FILL_INFO}

# Categorical colours for series named at build time (refIds, In/Out...), in this fixed order. Validated
# with the dataviz palette checker on the dark panel surface #181b1f: lightness band, chroma, adjacent CVD
# separation (worst 13.6) and normal-vision separation (worst 18.8), contrast >= 3:1. Status colours are
# deliberately absent: green/red keep meaning ok/broken.
SERIES = ["#0CA5BF", "#E4661A", "#8B6CF6", "#B88A0A", "#E54C96", "#3D85F2", "#0F9C8B", "#C94BE6"]
COLOR_SHADES = {"mode": "shades", "fixedColor": ACCENT}       # many anonymous series: shades of cyan
COLOR_CLASSIC = {"mode": "palette-classic"}

# Zabbix severities (priority 0..5) in PT-BR; used by the problems panel and the severity counters.
SEVERITIES = [
    (0, "Não classificado", UNKNOWN),
    (1, "Informação", INFO),
    (2, "Atenção", "#FFD23F"),
    (3, "Média", "#FF9F1C"),
    (4, "Alta", "#FF5A3C"),
    (5, "Desastre", "#FF1F5A"),
]
SEVERITY_COLOR = {p: c for p, _, c in SEVERITIES}
SEVERITY_NAME = {p: n for p, n, _ in SEVERITIES}

# ------------------------------------------------------------------------------------------ thresholds


def steps(base, *pairs):
    """Absolute threshold steps: steps(OK, (80, WARN), (90, CRIT)) -> base below 80, WARN from 80..."""
    return [{"color": base, "value": None}] + [{"color": c, "value": v} for v, c in pairs]


PCT = steps(OK, (80, WARN), (90, CRIT))                 # utilisation %: high is bad
PCT_LOW = steps(CRIT, (20, WARN), (50, OK))             # toner, battery %: low is bad
TEMP_INLET = steps(OK, (27, WARN), (32, CRIT))          # server inlet °C (topology v1, ASHRAE-like)
LATENCY_S = steps(OK, (0.05, WARN), (0.15, CRIT))       # ICMP response time is in seconds in Zabbix
LOSS_PCT = steps(OK, (5, WARN), (20, CRIT))
COUNT_BAD = steps(OK, (1, CRIT))                        # offline hosts, down links: any is bad
AVAIL_RATIO = steps(CRIT, (0.9, WARN), (1, OK))         # unit percentunit: 100% green, <90% red
LOAD = steps(OK, (v1.LOAD_STEPS[1]["value"], WARN), (v1.LOAD_STEPS[2]["value"], CRIT))  # AP load average
NEUTRAL = steps(ACCENT)                                 # plain counters: always cyan

# ---------------------------------------------------------------------------------------- value maps


def value_map(options):
    """{"1": ("ONLINE", OK), ...} -> Grafana value mapping list (index keeps the legend order)."""
    return [{"type": "value", "options": {str(k): {"text": t, "color": c, "index": i}
                                          for i, (k, (t, c)) in enumerate(options.items())}}]


def no_data_map(text="SEM DADOS", color=UNKNOWN):
    """Special mapping for null/NaN: grey "SEM DADOS" instead of the base threshold colour (often red)."""
    return [{"type": "special", "options": {"match": "null+nan", "result": {"text": text, "color": color,
                                                                           "index": 99}}}]


def as_fill(obj):
    """Copy of value maps or threshold steps with the neon colours replaced by the FILL_* tile colours
    (for colorMode "background" panels, where a neon background would put dark text on bright green)."""
    text = json.dumps(obj)
    for neon, fill in _TO_FILL.items():
        text = text.replace(f'"{neon}"', f'"{fill}"')
    return json.loads(text)


# Same numeric semantics as v1 (verified in Zabbix): icmpping 1 up / 0 down; zabbix[host,*,available]
# 0 not available / 1 available / 2 unknown (valuemap zabbix.host.available).
AVAIL_MAP = value_map({"0": ("OFFLINE", CRIT), "1": ("ONLINE", OK), "2": ("DESCONHECIDO", UNKNOWN)})
AVAIL_STEPS = steps(CRIT, (1, OK), (2, UNKNOWN))
# Zabbix agent availability / "port 10050 reachable": 1 = OK for both, the first also has 2 = unknown
AGENT_MAP = value_map({"0": ("SEM AGENTE", CRIT), "1": ("OK", OK), "2": ("DESCONHECIDO", UNKNOWN)})
AGENT_STEPS = AVAIL_STEPS
# IF-MIB ifOperStatus
OPER_MAP = value_map({"1": ("ONLINE", OK), "2": ("OFFLINE", CRIT), "3": ("EM TESTE", WARN),
                      "4": ("DESCONHECIDO", UNKNOWN), "5": ("DORMENTE", INFO), "6": ("AUSENTE", UNKNOWN),
                      "7": ("OFFLINE", CRIT)})
OPER_STEPS = steps(CRIT, (1, OK), (2, CRIT))
# Dell iDRAC ObjectStatusEnum
IDRAC_MAP = value_map({"1": ("OUTRO", UNKNOWN), "2": ("DESCONHECIDO", UNKNOWN), "3": ("OK", OK),
                       "4": ("ALERTA", WARN), "5": ("CRÍTICO", CRIT), "6": ("IRRECUPERÁVEL", CRIT)})
IDRAC_STEPS = steps(UNKNOWN, (3, OK), (4, WARN), (5, CRIT))
# FortiGate VPN tunnel status
VPN_MAP = value_map({"1": ("OFFLINE", CRIT), "2": ("ONLINE", OK)})
VPN_STEPS = steps(CRIT, (2, OK))

# ------------------------------------------------------------------------------------------- targets
DS_TYPE = v1.DS["type"]
DSV = {"type": DS_TYPE, "uid": "${datasource}"}             # every panel follows the $datasource variable
DASHBOARD_DS = {"type": "datasource", "uid": "-- Dashboard --"}
STAT_WINDOW = v1.STAT_WINDOW            # 15m: last-value panels
STAT_MDP = v1.STAT_MDP
SERIES_MDP = v1.SERIES_MDP
# Verified item regexes of v1, re-exported so dashboard modules import everything from here.
CPU_RE, MEM_RE, TEMP_RE = v1.CPU["re"], v1.MEM["re"], v1.TEMP["re"]
TRAFFIC_IN_RE, TRAFFIC_OUT_RE = v1.TRAFFIC_IN["re"], v1.TRAFFIC_OUT["re"]
ERRORS_IN_RE, DISCARDS_IN_RE = v1.ERRORS_IN["re"], v1.DISCARDS_IN["re"]
UPTIME_RE, SUPPLIES_RE, LOAD_1M_RE = v1.UPTIME["re"], v1.SUPPLIES["re"], v1.LOAD_1M["re"]
WAN_IN_RE, WAN_OUT_RE, WAN_STATUS_RE = v1.WAN_IN["re"], v1.WAN_OUT["re"], v1.WAN_STATUS["re"]
SDWAN_LATENCY_RE, SDWAN_JITTER_RE, SDWAN_LOSS_RE = (v1.SDWAN_LATENCY["re"], v1.SDWAN_JITTER["re"],
                                                     v1.SDWAN_LOSS["re"])
AGENT_STATUS_RE = v1.AGENT_STATUS_RE
# AVAIL_RE (ICMP ping | SNMP agent availability | Zabbix agent availability) comes from topology.py.


def target(item, *functions, ref="A", group="$group", host="$host"):
    """Zabbix metrics query. item: item name or /regex/; functions: alias(), top()... in the order the
    plugin applies them (backend functions first, alias last). group/host: filters or regexes."""
    t = v1._target(item, functions, ref=ref, group=group, host=host)
    t["datasource"] = dict(DSV)
    return t


def _fn(name, category, params=(), param_defs=(), defaults=()):
    return v1._fn(name, category, params, param_defs, defaults)


def alias(text):
    """setAlias (frontend). Macros: $__zbx_host_name, $__zbx_item, $__zbx_item_key..."""
    return v1._alias(text)


def replace_alias(regexp, new):
    """replaceAlias (frontend), runs on the current alias: do not anchor on the item name with ^."""
    return v1._replace_alias(regexp, new)


def top(n, fn="avg"):
    return v1._top(n, fn)


def bottom(n, fn="avg"):
    return _fn("bottom", "Filter", [int(n), fn],
               [{"name": "number", "type": "int"}, {"name": "value", "type": "string",
                                                    "options": v1.AGG_OPTIONS}], [5, "avg"])


def group_by(interval, fn="avg"):
    return v1._group_by(interval, fn)


def delta():
    return v1._delta()


def remove_above(value):
    """Values above `value` become null (e.g. availability 2 = unknown, so max() of up/down stays 0/1)."""
    return _fn("removeAboveValue", "Transform", [value], [{"name": "number", "type": "float"}], [0])


def sum_series():
    return _fn("sumSeries", "Aggregate")


def sort_series(direction="desc"):
    return _fn("sortSeries", "Filter", [direction],
               [{"name": "direction", "type": "string", "options": ["asc", "desc"]}], ["asc"])


def problems_target(group="$group", host="$host", min_severity=2, ref="A", tags="", limit=200):
    """Problems query (frontend-only) for the problems panel: current problems, worst first."""
    return {"refId": ref, "queryType": "5", "datasource": dict(DSV), "schema": 13,
            "group": {"filter": group}, "host": {"filter": host}, "application": {"filter": ""},
            "proxy": {"filter": ""}, "trigger": {"filter": ""}, "tags": {"filter": tags},
            "itemTag": {"filter": ""}, "showProblems": "problems",
            "options": {"minSeverity": min_severity, "severities": [s for s in range(6) if s >= min_severity],
                        "acknowledged": 2, "sortProblems": "severity", "hostsInMaintenance": False,
                        "hostProxy": False, "limit": limit, "useTimeRange": False}}


def triggers_target(group="/.*/", host="/.*/", min_severity=0, ref="A"):
    """Triggers in problem state counted per host group and severity (frontend-only query). Result: one
    row per group matching `group`, columns "Host group", Disaster, High, Average, Warning, Information,
    "Not classified" (plugin names; severity_transforms() renames them). A host counts in each of its
    matching groups, so pick disjoint groups (e.g. the Filiais/* site groups) to total them.
    Not the plugin's "count by problems" mode: with Zabbix 8 it sends triggerids [] and always returns 0."""
    return {"refId": ref, "queryType": "4", "countTriggersBy": "", "datasource": dict(DSV), "schema": 13,
            "group": {"filter": group}, "host": {"filter": host}, "application": {"filter": ""},
            "proxy": {"filter": ""}, "trigger": {"filter": ""}, "tags": {"filter": ""}, "itemTag": {"filter": ""},
            "options": {"minSeverity": min_severity, "acknowledged": 2, "count": False, "useTimeRange": False,
                        "showDisabledItems": False}}


SEVERITY_FIELDS = {5: "Disaster", 4: "High", 3: "Average", 2: "Warning", 1: "Information", 0: "Not classified"}


def severity_transforms(min_severity=2):
    """triggers_target table -> one row with the totals per severity, PT-BR upper-case names, worst first."""
    keep = [p for p in range(5, -1, -1) if p >= min_severity]
    return [reduce_fields(("sum",)),
            organize(rename={SEVERITY_FIELDS[p]: SEVERITY_NAME[p].upper() for p in keep},
                     exclude=["Host group"] + [SEVERITY_FIELDS[p] for p in range(6) if p < min_severity],
                     order=[SEVERITY_FIELDS[p] for p in keep])]


def severity_overrides(min_severity=2, zero_color="#3A4250"):
    """Each severity counter grey at 0 and in its severity colour from 1 (fields of severity_transforms)."""
    return [{"matcher": {"id": "byName", "options": SEVERITY_NAME[p].upper()},
             "properties": [{"id": "thresholds", "value": {"mode": "absolute",
                                                           "steps": steps(zero_color, (1, SEVERITY_COLOR[p]))}}]}
            for p in range(5, min_severity - 1, -1)]


def dashboard_target(panel_id, with_transforms=True, ref="A"):
    """Reuse the data of panel `panel_id` of the same dashboard (the "-- Dashboard --" datasource):
    no extra Zabbix query. The panel using it needs datasource=DASHBOARD_DS."""
    return {"refId": ref, "datasource": dict(DASHBOARD_DS), "panelId": panel_id,
            "withTransforms": with_transforms}


# -------------------------------------------------------------------------------------- transforms


def tf(id_, **options):
    return {"id": id_, "options": options}


def organize(rename=None, exclude=(), order=None):
    return tf("organize", renameByName=rename or {}, excludeByName={n: True for n in exclude},
              indexByName={n: i for i, n in enumerate(order or [])})


def calc_binary(left, operator, right, alias_):
    """New field left <operator> right (field names or numbers: a number is a fixed value)."""
    def side(x):
        return {"fixed": str(x)} if isinstance(x, (int, float)) else {"matcher": {"id": "byName", "options": x}}
    return tf("calculateField", mode="binary", alias=alias_, replaceFields=False,
              binary={"left": side(left), "operator": operator, "right": side(right)})


def reduce_rows(calcs=("lastNotNull",)):
    """One row per series: Field (display name, i.e. the alias) + one column per calc ("Last *"...)."""
    return tf("reduce", mode="seriesToRows", reducers=list(calcs), includeTimeField=False)


def reduce_fields(calcs=("sum",)):
    """Each numeric field reduced to one value, field names kept (e.g. totals of a per-site table)."""
    return tf("reduce", mode="reduceFields", reducers=list(calcs), includeTimeField=False)


def filter_fields(regex):
    return tf("filterFieldsByName", include={"pattern": regex})


def as_text(*fields):
    """Turn numeric fields into strings: they stay usable in display name templates
    (${__data.fields.Total}) but are no longer drawn as values by stat/bar gauge panels. Prefer this to
    reduceOptions.fields: that filter matches display names, so it breaks once displayName is set."""
    return tf("convertFieldType", fields={},
              conversions=[{"targetField": f, "destinationType": "string"} for f in fields])


def sort_by(field, desc=True):
    return tf("sortBy", fields={}, sort=[{"field": field, "desc": desc}])


# Column names the reduce transform gives each calc (needed to point at the reduced column).
CALC_NAMES = {"mean": "Mean", "max": "Max", "min": "Min", "lastNotNull": "Last *", "last": "Last",
              "sum": "Total", "count": "Count"}


# Health pipeline: how many hosts of each site/category are reachable. Each host counts once with its best
# availability check (ICMP ping, else SNMP/agent availability), so iDRACs (SNMP only) and servers (agent
# only) are not missed as in an ICMP-only count. Unknown (2) is removed on the backend, so max() is 0/1.
# The dimension name travels in a JSON alias because labels only carry the host.
HEALTH_WINDOW = "7h"       # iDRAC availability keeps only changes with a 6h heartbeat (topology v1)
_LAST = "Last *"           # column name of the lastNotNull reducer


def health_targets(dims):
    """dims: [{"name": "Matriz - Sede Principal", "group": "/^Filiais\\/Matriz$/", "link": "/d/...?var-site=BA"}]
    (link optional: a relative URL, e.g. dashboard_url(...), for a data link "${__data.fields.link}").
    One query per dimension: the latest availability of every host of the group, aliased as JSON."""
    out = []
    for n, d in enumerate(dims):
        label = json.dumps({"dim": d["name"], "link": d.get("link", ""), "host": "$__zbx_host_name"},
                           ensure_ascii=False)
        out.append(target(AVAIL_RE, group_by("1h", "last"), remove_above(1), alias(label),
                          ref=_ref(n), group=d["group"], host="/.*/"))
    return out


def health_transforms():
    """Rows dim | link | Online | Total | Offline | Disponibilidade (ratio 0..1), in the order of dims.
    Tiles per row: add as_text("Online", "Total", "Offline") so only Disponibilidade is drawn and the
    others feed the tile name. Totals: add reduce_fields(("sum",))."""
    best = f"{_LAST} (max)"
    return [
        reduce_rows(),
        tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
        tf("groupBy", fields={"dim": {"operation": "groupby", "aggregations": []},
                              "link": {"operation": "groupby", "aggregations": []},
                              "host": {"operation": "groupby", "aggregations": []},
                              _LAST: {"operation": "aggregate", "aggregations": ["max"]}}),
        tf("groupBy", fields={"dim": {"operation": "groupby", "aggregations": []},
                              "link": {"operation": "groupby", "aggregations": []},
                              best: {"operation": "aggregate", "aggregations": ["sum", "count"]}}),
        organize(rename={f"{best} (sum)": "Online", f"{best} (count)": "Total"}),
        calc_binary("Total", "-", "Online", "Offline"),
        calc_binary("Online", "/", "Total", "Disponibilidade"),
    ]


def _ref(n):
    return chr(ord("A") + n)


# ------------------------------------------------------------------------------------------ panels


def panel(type_, title="", targets=(), *, description=None, unit=None, decimals=None, min=None, max=None,
          mappings=None, steps=None, color=None, links=None, no_value=None, overrides=None,
          transformations=None, transparent=False, time_from=None, mdp=None, interval=None,
          datasource=None, options=None, custom=None, id=None, display_name=None, **extra):
    """Any panel. steps -> absolute thresholds (and colour by thresholds unless color= is given).
    display_name: field display name template, e.g. "${__data.fields.dim}" for one value per row.
    **extra goes to the panel itself (not the field config)."""
    defaults = {}
    for key, value in (("unit", unit), ("decimals", decimals), ("min", min), ("max", max),
                       ("noValue", no_value), ("links", links), ("custom", custom),
                       ("displayName", display_name)):
        if value is not None:
            defaults[key] = value
    defaults["mappings"] = mappings or []
    if steps:
        defaults["thresholds"] = {"mode": "absolute", "steps": steps}
    if color:
        defaults["color"] = color
    elif steps:
        defaults["color"] = {"mode": "thresholds"}
    p = {"type": type_, "title": title, "datasource": datasource or dict(DSV), "targets": list(targets),
         "fieldConfig": {"defaults": defaults, "overrides": list(overrides or [])},
         "options": options or {}, "transparent": transparent}
    if id is not None:
        p["id"] = id
    if description:
        p["description"] = description
    if transformations:
        p["transformations"] = list(transformations)
    if time_from:
        p.update(timeFrom=time_from, hideTimeOverride=True)
    if mdp:
        p["maxDataPoints"] = mdp
    if interval:
        p["interval"] = interval
    p.update(extra)
    return p


def _reduce(calcs, fields="", values=False):
    return {"values": values, "calcs": list(calcs), "fields": fields}


def stat(title, targets, *, calcs=("lastNotNull",), fields="", values=False, color_mode="value",
         graph="none", text_mode="auto", orientation="auto", justify="center", wide=True, title_size=None,
         value_size=None, min_width=None, min_height=None, time_from=STAT_WINDOW, mdp=STAT_MDP, **kw):
    """Stat panel. color_mode: "value" (neon number on the dark panel, default), "background" (gradient
    tile; pair with as_fill() colours), "background_solid", "none". graph: "none" | "area" (sparkline;
    then pass time_from=None so it follows the dashboard range). values=True shows one value per row
    of a table (e.g. health_transforms output)."""
    text = {}
    if title_size:
        text["titleSize"] = title_size
    if value_size:
        text["valueSize"] = value_size
    opts = {"reduceOptions": _reduce(calcs, fields, values), "orientation": orientation,
            "textMode": text_mode, "colorMode": color_mode, "graphMode": graph, "justifyMode": justify,
            "wideLayout": wide, "showPercentChange": False, "text": text}
    if min_width:
        opts["minVizWidth"] = min_width
    if min_height:
        opts["minVizHeight"] = min_height
    return panel("stat", title, targets, options=opts, time_from=time_from, mdp=mdp, **kw)


def kpi(title, targets, *, value_size=56, sparkline=False, **kw):
    """Big-number tile for a TV wall: value only, large text. sparkline=True adds a trend area under the
    number over the dashboard range (time_from is dropped unless given)."""
    if sparkline:
        kw.setdefault("time_from", None)
        kw.setdefault("mdp", 120)
    return stat(title, targets, text_mode="value", value_size=value_size,
                graph="area" if sparkline else "none", **kw)


def status_grid(title, targets, *, mappings, steps, fill=True, title_size=13, value_size=18,
                min_width=150, min_height=46, text_mode="value_and_name", **kw):
    """One tile per series (host, link, tunnel...) coloured by a value map. fill=True uses the deep FILL_*
    background tiles (calm green grid, loud red tile), fill=False neon text on the dark panel."""
    return stat(title, targets, mappings=as_fill(mappings) if fill else mappings,
                steps=as_fill(steps) if fill else steps, color_mode="background" if fill else "value",
                text_mode=text_mode, wide=False, title_size=title_size, value_size=value_size,
                min_width=min_width, min_height=min_height, **kw)


def gauge(title, targets, *, steps=PCT, unit="percent", min=0, max=100, markers=True, calcs=("lastNotNull",),
          time_from=STAT_WINDOW, mdp=STAT_MDP, title_size=None, value_size=None, **kw):
    """Classic radial gauge with threshold markers (few series: 1-8)."""
    text = {k: v for k, v in (("titleSize", title_size), ("valueSize", value_size)) if v}
    opts = {"reduceOptions": _reduce(calcs), "orientation": "auto", "showThresholdMarkers": markers,
            "showThresholdLabels": False, "sizing": "auto", "minVizWidth": 75, "minVizHeight": 75, "text": text}
    return panel("gauge", title, targets, unit=unit, min=min, max=max, steps=steps, options=opts,
                 time_from=time_from, mdp=mdp, **kw)


def bargauge(title, targets, *, steps=PCT, unit="percent", min=0, max=100, mode="gradient",
             orientation="horizontal", calcs=("lastNotNull",), name_placement="auto", unfilled=True,
             bar_height=None, rank=False, time_from=STAT_WINDOW, mdp=STAT_MDP, title_size=None,
             value_size=None, **kw):
    """Bar gauge, one bar per series: the best way to rank many hosts (CPU, disks, toner, latency).
    mode: "gradient" (neon fade, default), "lcd" (segmented, retro NOC), "basic". bar_height (px) fixes
    the bar thickness so long lists stay tidy (sizing manual). rank=True sorts the bars, worst (highest
    calcs[0]) first: series become rows (reduce + sortBy transforms), names come from the aliases."""
    text = {k: v for k, v in (("titleSize", title_size), ("valueSize", value_size)) if v}
    reduce_opts = _reduce(calcs)
    if rank:
        col = CALC_NAMES.get(calcs[0], calcs[0])
        kw["transformations"] = [reduce_rows(calcs[:1]), sort_by(col)] + list(kw.get("transformations") or [])
        reduce_opts = _reduce(("lastNotNull",), fields=f"/^{re.escape(col)}$/", values=True)
    opts = {"reduceOptions": reduce_opts, "orientation": orientation, "displayMode": mode,
            "valueMode": "color", "namePlacement": name_placement, "showUnfilled": unfilled,
            "sizing": "manual" if bar_height else "auto", "minVizWidth": 8, "minVizHeight": bar_height or 16,
            "maxVizHeight": bar_height or 300, "text": text, "legend": {"showLegend": False}}
    return panel("bargauge", title, targets, unit=unit, min=min, max=max, steps=steps, options=opts,
                 time_from=time_from, mdp=mdp, **kw)


def series_custom(draw="line", fill=18, line_width=2, gradient="opacity", stack=False, points="never",
                  span_nulls=900000, thresholds_style="off", axis_soft_min=None):
    """fieldConfig.defaults.custom of time series. span_nulls (ms) bridges normal gaps between samples
    but leaves real outages visible."""
    c = {"drawStyle": draw, "lineInterpolation": "smooth", "lineWidth": line_width, "fillOpacity": fill,
         "gradientMode": gradient, "showPoints": points, "pointSize": 4, "spanNulls": span_nulls,
         "axisBorderShow": False, "axisPlacement": "auto", "axisColorMode": "text", "axisLabel": "",
         "barAlignment": 0, "insertNulls": False, "stacking": {"mode": "normal" if stack else "none", "group": "A"},
         "thresholdsStyle": {"mode": thresholds_style},
         "hideFrom": {"legend": False, "tooltip": False, "viz": False}}
    if draw == "bars":
        c.update(fillOpacity=max(fill, 70), lineWidth=1, gradientMode="hue")
    if axis_soft_min is not None:
        c["axisSoftMin"] = axis_soft_min
    return c


def timeseries(title, targets, *, unit=None, legend="table", legend_calcs=("mean", "max", "lastNotNull"),
               sort_by="Max", draw="line", fill=18, line_width=2, stack=False, color=None,
               thresholds_style="off", steps=None, mdp=SERIES_MDP, axis_soft_min=None, **kw):
    """Time series. legend: "table" (right, with mean/max/last, sorted desc by sort_by), "list" (bottom),
    "hidden". color: None = Grafana classic palette, COLOR_SHADES for many anonymous series, or
    {"mode": "fixed", "fixedColor": ACCENT} for a single series. thresholds_style "line+area"/"dashed"
    draws the steps on the chart."""
    if legend == "table":
        leg = {"showLegend": True, "displayMode": "table", "placement": "right", "calcs": list(legend_calcs),
               "sortBy": sort_by, "sortDesc": True}
    elif legend == "list":
        leg = {"showLegend": True, "displayMode": "list", "placement": "bottom", "calcs": []}
    else:
        leg = {"showLegend": False, "displayMode": "list", "placement": "bottom", "calcs": []}
    opts = {"legend": leg, "tooltip": {"mode": "multi", "sort": "desc", "hideZeros": False}}
    return panel("timeseries", title, targets, unit=unit, options=opts, mdp=mdp, steps=steps,
                 color=color or COLOR_CLASSIC,
                 custom=series_custom(draw, fill, line_width, stack=stack, thresholds_style=thresholds_style,
                                      axis_soft_min=axis_soft_min), **kw)


def series_colors(names, by="byFrameRefID"):
    """Overrides giving named series (refIds, or display names with by="byName") the SERIES colours in
    order."""
    return [{"matcher": {"id": by, "options": n},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": SERIES[i % len(SERIES)]}}]}
            for i, n in enumerate(names)]


def state_timeline(title, targets, *, mappings, steps, row_height=0.8, show_value="auto", legend=False,
                   fill=80, mdp=SERIES_MDP, **kw):
    """State over time per series (links, tunnels, hosts): neon bars, merged equal values."""
    opts = {"mergeValues": True, "showValue": show_value, "alignValue": "center", "rowHeight": row_height,
            "legend": {"showLegend": legend, "displayMode": "list", "placement": "bottom"},
            "tooltip": {"mode": "single", "sort": "none"}}
    return panel("state-timeline", title, targets, mappings=mappings, steps=steps, options=opts, mdp=mdp,
                 custom={"fillOpacity": fill, "lineWidth": 0, "hideFrom": {"legend": False, "tooltip": False,
                                                                            "viz": False}}, **kw)


def status_history(title, targets, *, mappings, steps, row_height=0.85, col_width=0.9, show_value="never",
                   legend=False, fill=80, mdp=60, **kw):
    """Grid of status samples per series (e.g. hourly availability heatmap)."""
    opts = {"showValue": show_value, "rowHeight": row_height, "colWidth": col_width,
            "legend": {"showLegend": legend, "displayMode": "list", "placement": "bottom"},
            "tooltip": {"mode": "single", "sort": "none"}}
    return panel("status-history", title, targets, mappings=mappings, steps=steps, options=opts, mdp=mdp,
                 custom={"fillOpacity": fill, "lineWidth": 1, "hideFrom": {"legend": False, "tooltip": False,
                                                                            "viz": False}}, **kw)


def table(title, targets, *, columns=(), cell_height="sm", sort_by=None, filterable=False, footer=None,
          align="auto", **kw):
    """Table. columns: col_* overrides. sort_by: [("Field", desc_bool)]. footer: reducer list, e.g.
    ["sum"], shown at the bottom."""
    opts = {"showHeader": True, "cellHeight": cell_height,
            "sortBy": [{"displayName": n, "desc": d} for n, d in (sort_by or [])],
            "footer": {"show": bool(footer), "reducer": list(footer or ["sum"]), "countRows": False,
                       "fields": ""}}
    custom = {"align": align, "cellOptions": {"type": "auto"}, "inspect": False, "filterable": filterable}
    kw.setdefault("overrides", [])
    kw["overrides"] = list(kw["overrides"]) + list(columns)
    return panel("table", title, targets, options=opts, custom=custom, **kw)


def _col(name, *props, by="byName"):
    return {"matcher": {"id": by, "options": name}, "properties": [{"id": k, "value": v} for k, v in props]}


def col_color(name, mode="background", gradient=True, by="byName"):
    """Colour a column by its thresholds/value map: mode "background" (tile-like cell) or "text"."""
    cell = ({"type": "color-background", "mode": "gradient" if gradient else "basic"} if mode == "background"
            else {"type": "color-text"})
    return _col(name, ("custom.cellOptions", cell), by=by)


def col_gauge(name, mode="gradient", by="byName"):
    """In-cell bar gauge: mode "gradient" | "lcd" | "basic"."""
    return _col(name, ("custom.cellOptions", {"type": "gauge", "mode": mode, "valueDisplayMode": "color"}), by=by)


def col_width(name, px, by="byName"):
    return _col(name, ("custom.width", px), by=by)


def col_props(name, by="byName", **props):
    """Any field properties for one column: col_props("Valor", unit="percent", displayName="Uso")."""
    return _col(name, *props.items(), by=by)


def text(content, *, mode="markdown", transparent=True, title="", **kw):
    p = panel("text", title, (), options={"mode": mode, "content": content,
                                          "code": {"language": "plaintext", "showLineNumbers": False,
                                                   "showMiniMap": False}},
              transparent=transparent, **kw)
    del p["datasource"], p["targets"]        # no query
    return p


def tv_links():
    """Panel links between the three TV dashboards (overview + both topology prototypes). Panel links, not
    dashboard links: Grafana 13 kiosk still draws dashboard links as a control bar that pushes the grid off
    the 1080px screen. They show as an icon in the banner's header on hover."""
    return [data_link("Visão Geral", dashboard_url("overview")),
            data_link("Topologia · protótipo A (Canvas)", dashboard_url("topology-canvas")),
            data_link("Topologia · protótipo B (ECharts)", dashboard_url("topology-echarts"))]


def banner(title, subtitle="", *, legend=True, align="left", links=None):
    """Dashboard header for kiosk/TV mode (Grafana hides the title there): accent bar, big title, small
    caps subtitle and, optionally, the status colour legend. Transparent text panel, HTML with inline
    styles (kept by Grafana's sanitizer). links: panel links (e.g. tv_links()) for TV dashboards."""
    chips = ""
    if legend:
        chips = "".join(
            f'<span style="display:inline-block;margin-right:14px;color:{MUTED};font-size:12px;">'
            f'<span style="color:{c};font-size:14px;">&#9679;</span> {t}</span>'
            for t, c in (("ONLINE", OK), ("ATENÇÃO", WARN), ("OFFLINE / CRÍTICO", CRIT), ("SEM DADOS", UNKNOWN)))
        chips = f'<div style="margin-top:6px;">{chips}</div>'
    sub = (f'<div style="color:{MUTED};font-size:12px;letter-spacing:3px;text-transform:uppercase;">'
           f'{subtitle}</div>') if subtitle else ""
    html = (f'<div style="border-left:4px solid {ACCENT};padding:2px 0 2px 14px;text-align:{align};">'
            f'{sub}<div style="color:{TEXT};font-size:26px;font-weight:700;letter-spacing:1px;line-height:1.2;">'
            f'{title}</div>{chips}</div>')
    p = text(html, mode="html")
    if links:
        p["links"] = list(links)         # panel links (panel(links=) sets field data links instead)
    return p


def problems(title, targets, *, page_size=10, font_size="100%", layout="table", host_groups=False,
             tags=False, age=True, ack=False, **kw):
    """Zabbix problems panel (live feed), PT-BR severities in the neon palette. layout "table" | "list".
    targets: [problems_target(...)]."""
    sev = [{"priority": p, "severity": n, "color": c, "show": True} for p, n, c in SEVERITIES]
    opts = {"schemaVersion": 8, "layout": layout, "fontSize": font_size, "pageSize": page_size,
            "hostField": True, "hostTechNameField": False, "hostIpField": False, "hostProxy": False,
            "hostGroups": host_groups, "showTags": tags, "statusField": False, "statusIcon": False,
            "severityField": True, "ackField": ack, "ageField": age, "opdataField": False,
            "descriptionField": False, "descriptionAtNewLine": False, "showDatasourceName": False,
            "sortProblems": "priority", "problemTimeline": True, "highlightBackground": False,
            "highlightNewEvents": True, "highlightNewerThan": "1h", "customLastChangeFormat": False,
            "lastChangeFormat": "", "resizedColumns": [], "allowDangerousHTML": False,
            "triggerSeverity": sev, "okEventColor": OK, "ackEventColor": ACCENT, "markAckEvents": False,
            "showSearchFilter": False}
    return panel("alexanderzobnin-zabbix-triggers-panel", title, targets, options=opts, **kw)


def row(title, collapsed=False, children=()):
    """Section header. collapsed=True: the children rows ((h, [(panel, w)...])) live inside the row and
    load only when it is opened (cheap dashboards, rich detail on demand). Grafana treats every panel
    below a row as part of it, so once one section uses row(), start each following section with a row()
    too."""
    return {"type": "row", "title": title, "collapsed": collapsed, "panels": [], "_children": list(children)}


# ------------------------------------------------------------------------------------------- layout
GRID_W = 24
# 1920x1080 kiosk: a grid unit is 30px + 8px gap; 27 units fill the screen without a scrollbar.
TV_HEIGHT = 27


def stack(*items):
    """A column of panels inside a grid row: stack((panel, h), (panel, h)). Heights should add up to
    the row height."""
    return {"_stack": list(items)}


def grid(*rows):
    """Lay out rows top to bottom. A row is (height, [(panel, width), ...]) whose widths add up to <= 24,
    a row() header, or a list of rows. A cell may be stack(...) instead of a panel. Panels keep an
    explicit "id" (needed by dashboard_target); the others get the next free ids."""
    flat = []

    def place(rows_, y):
        out = []
        for r in rows_:
            if isinstance(r, list):
                sub, y = place(r, y)
                out += sub
            elif isinstance(r, dict) and r.get("type") == "row":
                r = dict(r)
                children = r.pop("_children", [])
                r["gridPos"] = {"x": 0, "y": y, "w": GRID_W, "h": 1}
                y += 1
                out.append(r)
                if r["collapsed"]:
                    r["panels"], _ = place(children, y)
                else:
                    sub, y = place(children, y)
                    out += sub
            else:
                h, cells = r
                x = 0
                for cell, w in cells:
                    if isinstance(cell, dict) and "_stack" in cell:
                        yy = y
                        for p, ph in cell["_stack"]:
                            p["gridPos"] = {"x": x, "y": yy, "w": w, "h": ph}
                            out.append(p)
                            yy += ph
                    else:
                        cell["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
                        out.append(cell)
                    x += w
                if x > GRID_W:
                    raise ValueError(f"grid row wider than {GRID_W}: {x}")
                y += h
        return out, y

    panels, _ = place(list(rows), 0)
    for p in panels:
        flat.append(p)
        flat.extend(p.get("panels", []) if p.get("type") == "row" else [])
    used = {p["id"] for p in flat if "id" in p}
    next_id = 1
    for p in flat:
        if "id" not in p:
            while next_id in used:
                next_id += 1
            p["id"] = next_id
            used.add(next_id)
    return panels


# ---------------------------------------------------------------------------------- dashboard wrapper
PREFIX = "AutoDiscovery v2 - "
TAG = "autodiscovery-v2"
QUICK_RANGES = [("5m", "Últimos 5 minutos"), ("15m", "Últimos 15 minutos"), ("30m", "Últimos 30 minutos"),
                ("1h", "Última 1 hora"), ("3h", "Últimas 3 horas"), ("6h", "Últimas 6 horas"),
                ("12h", "Últimas 12 horas"), ("1d", "Últimas 24 horas"), ("2d", "Últimos 2 dias"),
                ("7d", "Últimos 7 dias"), ("30d", "Últimos 30 dias")]


def uid(key):
    return f"autodiscovery-{key}-v2"


def quick_ranges(cap="7d"):
    """PT-BR quick ranges up to cap (raw history is heavy: cap at what the dashboard's panels survive,
    v1 measured 1d for switches, 2d for the many-item dashboards, 7d for servers)."""
    keys = [k for k, _ in QUICK_RANGES]
    return [{"from": f"now-{k}", "to": "now", "display": t} for k, t in QUICK_RANGES[:keys.index(cap) + 1]]


def dashboard(key, title, panels, *, datasource_uid="zabbix", variables=(), refresh="5m", time_from="now-6h",
              range_cap="2d", description="", tv=False, extra_tags=()):
    """Complete dashboard. tv=True: 1m refresh, datasource variable, time picker and links hidden (the
    kiosk view is the whole screen; navigate with the panels' data links). refresh 5m elsewhere: SNMP
    items are polled every 3m (v1 measurement)."""
    return {
        "uid": uid(key), "title": f"{PREFIX}{title}", "description": description,
        "tags": ["autodiscovery", TAG, *extra_tags], "timezone": "browser", "editable": True,
        "graphTooltip": 1,                  # shared crosshair: hover one chart, see the same instant on all
        "refresh": "1m" if tv else refresh, "schemaVersion": 41, "fiscalYearStartMonth": 0,
        "time": {"from": time_from, "to": "now"},
        # TV: no time picker and no links, so kiosk mode shows no control bar and the grid gets the screen
        "timepicker": {"hidden": True} if tv else (
            {"quick_ranges": quick_ranges(range_cap)} if range_cap else {}),
        "links": [] if tv else [{"title": "Dashboards v2", "type": "dashboards", "tags": [TAG],
                                 "asDropdown": True, "includeVars": False, "keepTime": True,
                                 "icon": "external link", "targetBlank": False}],
        "templating": {"list": [datasource_var(datasource_uid, hide=2 if tv else 0), *variables]},
        "annotations": {"list": []},
        "panels": panels,
    }


def dashboard_url(key, keep_time=True, **vars_):
    """Relative URL of a v2 dashboard; vars_ become var-<name>=<value> (e.g. site="BA")."""
    params = ["${__url_time_range}"] if keep_time else []
    params += [f"var-{k}={v}" for k, v in vars_.items()]
    return f"/d/{uid(key)}" + ("?" + "&".join(params) if params else "")


def data_link(title, url, new_tab=False):
    return {"title": title, "url": url, "targetBlank": new_tab}


# ---------------------------------------------------------------------------------------- variables


def datasource_var(datasource_uid="zabbix", hide=0):
    return {"name": "datasource", "label": "Zabbix", "type": "datasource", "query": DS_TYPE,
            "current": {"text": datasource_uid, "value": datasource_uid}, "hide": hide}


def group_var(group_re, label="Grupo", hide=0):
    """Host groups of a category dashboard (All = the category regex)."""
    return {"name": "group", "label": label, "type": "query", "datasource": dict(DSV),
            "query": {"queryType": "group", "group": group_re, "host": "", "application": "", "itemTag": "",
                      "item": ""},
            "multi": True, "includeAll": True, "allValue": group_re, "refresh": 1, "sort": 1, "hide": hide,
            "current": {"text": "Todos", "value": "$__all"}}


def host_var(group="$group", label="Host", hide=0):
    # refresh 1 (on load), not 2: the host list does not follow the time range (v1 measurement)
    return {"name": "host", "label": label, "type": "query", "datasource": dict(DSV),
            "query": {"queryType": "host", "group": group, "host": "/.*/", "application": "", "itemTag": "",
                      "item": ""},
            "multi": True, "includeAll": True, "allValue": "/.*/", "refresh": 1, "sort": 1, "hide": hide,
            "current": {"text": "Todos", "value": "$__all"}}


def site_var(cfg, label="Filial", hide=0):
    """Custom variable whose values are regex fragments for /^Filiais\\/$site$/ (All = .*, inserted
    unescaped by Grafana). Use SITE_GROUP_RE in targets."""
    opts = [(s["label"], s["key"]) for s in sites(cfg)]
    return {"name": "site", "label": label, "type": "custom", "hide": hide,
            "query": ", ".join(f"{t} : {v}" for t, v in opts),
            "options": [{"text": "Todas", "value": "$__all", "selected": True}]
            + [{"text": t, "value": v, "selected": False} for t, v in opts],
            "current": {"text": "Todas", "value": "$__all"}, "multi": False, "includeAll": True,
            "allValue": ".*"}


def site_hosts_var(cfg):
    """Hidden: hosts of the chosen site, to combine a category group with a site (host=SITE_HOSTS_RE)."""
    return {"name": "site_hosts", "label": "Hosts da filial", "type": "query", "datasource": dict(DSV),
            "query": {"queryType": "host", "group": site_group_re(cfg, "$site"), "host": "/.*/",
                      "application": "", "itemTag": "", "item": ""},
            "multi": True, "includeAll": True, "refresh": 2, "sort": 1, "hide": 2,
            "current": {"text": "All", "value": "$__all"}}


SITE_HOSTS_RE = "/^$site_hosts$/"


def category_variables(group_re):
    """group + host variables of a category dashboard."""
    return [group_var(group_re), host_var()]


# ------------------------------------------------------------------------------------------ config
SITE_LABELS = {"Matriz": "Matriz - Sede Principal", "RJ": "Rio de Janeiro", "BA": "Bahia", "PR": "Paraná"}
# v2 category dashboards, in display order: (v1 spec key = v2 key, PT-BR title). Specs whose groups have
# no hosts in this installation (routers, storage, pdu, cctv, voip) are not part of v2.
CATEGORY_KEYS = [("firewalls", "Firewalls"), ("switches", "Switches"), ("access-points", "Access Points"),
                 ("servers", "Servidores"), ("server-hardware", "Hardware"),
                 ("printers", "Impressoras"), ("ups", "Nobreaks")]


def _regex_escape(text):
    return re.escape(text).replace("/", "\\/")


def site_group_re(cfg, site, raw=False):
    """/^Filiais\\/<site>$/ from the config's site_group format. A "$site" variable or raw=True (e.g.
    ".*" for every site) keeps its regex meaning; plain names are escaped."""
    fmt = cfg.get("site_group") or "Filiais/{site}"
    head, _, tail = fmt.partition("{site}")
    value = site if raw or site.startswith("$") else _regex_escape(site)
    return f"/^{_regex_escape(head)}{value}{_regex_escape(tail)}$/"


def sites(cfg):
    """[{"key": "Matriz", "label": "Matriz - Sede Principal", "group": "/^Filiais\\/Matriz$/"}...] in config order."""
    seen, out = set(), []
    for s in cfg.get("_sites", []):
        key = s.get("site")
        if key and key not in seen:
            seen.add(key)
            out.append({"key": key, "label": SITE_LABELS.get(key, key), "group": site_group_re(cfg, key)})
    return out


def categories(cfg):
    """v2 category dashboards with their host groups: [{"key", "title", "uid", "groups", "group"}]."""
    specs = {s["key"]: s for s in v1.SPECS}
    out = []
    for key, title in CATEGORY_KEYS:
        groups = v1.groups_for(specs[key], cfg) if key in specs else []
        if groups:
            out.append({"key": key, "title": title, "uid": uid(key), "groups": groups,
                        "group": v1._group_regex(groups)})
    return out
