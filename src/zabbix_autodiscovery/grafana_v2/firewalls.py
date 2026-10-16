"""Firewalls · Links & SD-WAN: desktop analysis dashboard of the FortiGates (1920 wide, scrolling).

Layout (rows):
  KPI strip   banner | firewalls / links WAN / SLAs SD-WAN / túneis VPN online "N" (caption "de M")
              | sessões ativas | problemas ativos por severidade (grey at 0, severity colour otherwise)
  Saúde      one table row per firewall (status, CPU, memória, temperatura, sessões, IPsec, ICMP, uptime)
              + CPU / memória / sessões over time (one fixed colour per firewall in every chart)
  Links WAN   status tiles, oper status timeline, download / upload per firewall (repeated by $host:
              2 links per chart instead of 8 tangled lines; upload mirrored below the axis)
  SD-WAN      health-check tiles, packet-loss heatmap (status history: 32 links stay readable, unlike 32
              overlapping lines), worst latency / jitter / loss as ranked bars
  VPN         tunnel tiles (inactive tunnels grey), tunnels "online / ativos" and SSL users per firewall,
              tunnel timeline (the known unused tunnels grey there too)
  Interfaces  top 10 traffic in / out of LAN ports and tunnels, interfaces with errors / discards
  Problemas   the live feed, last: the severity counters of the KPI strip already say whether to scroll
              here, and an empty "No problems found" box no longer takes the best spot of the page

Item regexes, windows and value semantics are the verified v1 ones (dashboards.py via style.py); the
FortiGate-only items (SD-WAN health-check state, VDOM sessions, VPN counters, CPU on-die temperature) were
checked on the 4 FortiGates: WAN oper status 8 items, SD-WAN 32 members, VPN tunnels 35 (31 without the
backup FGFM tunnels), counters 8.
"""
import json

from . import style as S

KEY = "firewalls"
TITLE = "Firewalls · Links e SD-WAN"

# FortiGate items not shared with other dashboards (names checked in Zabbix)
SESSIONS_RE = r"/^VDOM root: Active sessions$/"
SESSION_RATE_RE = r"/^VDOM root: Sessions rate$/"
IPSEC_RE = r"/^Active IPsec VPN tunnels$/"
SSL_USERS_RE = r"/^Active SSL VPN users$/"
TEMP_ITEM = "Sensor CPU ON-DIE Temperature: Value"
TEMP_RE = f"/^{TEMP_ITEM}$/"
# VPN-FGFM_MGMT2 is the backup FortiManager tunnel: down by design (its triggers are disabled in Zabbix),
# a permanently red tile would teach operators to ignore red here
VPN_STATUS_RE = r"/^VPN (?!VPN-FGFM_MGMT2:).*: Tunnel Status$/"
SDWAN_STATE_RE = r"/^SD-WAN .*: Health check state$/"
# VPN counters keep only changes (discard unchanged, 1h heartbeat): last-value panels need > 1h
COUNTER_WINDOW = "2h"
# A tunnel with no UP sample in this window is "INATIVO" (configured but not in use, e.g. a backup path
# whose trigger stays OK in Zabbix), grey instead of red. Status items are 1/min: 31 x 1440 points.
VPN_ACTIVE_WINDOW = "24h"
VPN_MDP = 1500                      # > 1440: no consolidation, the max of the window is a real sample

# Short names of links, health-check members and tunnels. replaceAlias runs on the "host: item" alias,
# so the patterns start after the host (no ^).
HOST_ITEM = "$__zbx_host_name: $__zbx_item"
# "FW-SP · Megatelecom 50Mbps (wan1)" on tiles and history alike: FW-PR's second port is aliased just
# "wan2" on the FortiGate, so the port name "(a)" is what keeps it identifiable
WAN_NAME = (r"/: Interface\s+([^(:]+)\(([^)]*)\):\s+Operational status$/i", " · $2 ($1)")
SDWAN_TUNNEL = (r"/: SD-WAN \[[^\]]*\]:\[([^\]]*-[^\]]*)\]: .*$/", " · $1")    # BAH-MEGA-NET: unique
SDWAN_NAME = (r"/: SD-WAN \[([^\]]*)\]:\[([^\]]*)\]: .*$/", " · $1 › $2")       # a, wan: need the SLA
IF_DESCR = (r"/: Interface\s+([^(:]+)\(([^)]+)\): Bits (received|sent)$/i", " · $2 ($1)")
IF_NAME = (r"/: Interface\s+(.*?)(\(\))?: Bits (received|sent)$/i", " · $1")

# FortiGate SD-WAN health-check state (valuemap "Health check state"): 0 alive, 1 dead
SLA_MAP = S.value_map({"0": ("OK", S.OK), "1": ("FALHA", S.CRIT)})
SLA_STEPS = S.steps(S.OK, (1, S.CRIT))
# Tunnel state computed by _vpn_state(): 0 inactive (never up in VPN_ACTIVE_WINDOW), 1 down, 2 up
TUNNEL_MAP = S.value_map({"0": ("INATIVO", S.UNKNOWN), "1": ("OFFLINE", S.CRIT), "2": ("ONLINE", S.OK)})
TUNNEL_STEPS = S.steps(S.UNKNOWN, (1, S.CRIT), (2, S.OK))
# Raw status (1 down, 2 up) of the INACTIVE_TUNNELS in the timeline: down is their normal state
TUNNEL_INACTIVE_MAP = S.value_map({"1": ("INATIVO", S.UNKNOWN), "2": ("ONLINE", S.OK)})
TUNNEL_INACTIVE_STEPS = S.steps(S.UNKNOWN, (2, S.OK))
# SD-WAN thresholds: inter-site IPsec latency is 1-55 ms here, so the colours flag real degradation only
SDWAN_LATENCY_MS = S.steps(S.OK, (100, S.WARN), (200, S.CRIT))
SDWAN_JITTER_MS = S.steps(S.OK, (15, S.WARN), (30, S.CRIT))
SDWAN_LOSS = S.steps(S.OK, (1, S.WARN), (5, S.CRIT))
# Many small status tiles (32 SLA members, 31 tunnels): Grafana packs about 16 per row. The state is
# written under the name ("OK" / "FALHA"), larger than the wrapped name, so a failure is not signalled by
# colour alone and the state is what the eye reads first.
MANY_TILES = {"text_mode": "value_and_name", "title_size": 11, "value_size": 16, "min_width": 112,
              "min_height": 52}
# "N online of M" tiles: colour by Online / Total (percentage thresholds against the Total field)
SHARE_STEPS = S.steps(S.CRIT, (75, S.WARN), (100, S.OK))
# CPU on-die sensor of the FortiGates (58-62 °C in normal operation): not the server inlet scale
TEMP_DIE = S.steps(S.OK, (70, S.WARN), (85, S.CRIT))
# One colour per firewall in every chart (health, interfaces), from the validated categorical palette.
# Only the cool entries: SERIES[1] orange and [3] ochre read as WARN next to the amber thresholds (FW-PR's
# memory line ran just under the dashed 80 % line, and a one-firewall view looked "amber everywhere").
# Hostnames of the 4 FortiGates in Zabbix; another firewall keeps the default colour of the panel.
FIREWALL_COLORS = {"FW-SP": S.SERIES[0], "FW-RJ": S.SERIES[2], "FW-BA": S.SERIES[5], "FW-PR": S.SERIES[4]}
FIREWALLS = list(FIREWALL_COLORS)
# Tunnels configured but never up (history.get, 7 days: 0 UP samples of ~10k). The tiles find inactive
# tunnels by themselves (no UP in 24h -> INATIVO); the timeline cannot, so it greys these rows by name
# instead of drawing the loudest red of the page for something that is not a failure. Such a tunnel still
# turns green when it comes up; remove it from here once it is in use.
INACTIVE_TUNNELS = {"FW-PR": ["BAH-LIGGA-NETFI", "RJ-LIGGA-INT10"], "FW-RJ": ["VIT-INT-LIGGA"]}


def _named(item, name, *functions, group="$group", host="$host", ref="A"):
    """Target aliased "host: item" and shortened by the (regex, replacement) `name` (or a list of them,
    applied in order). sortSeries first: the backend sorts by "host: item", so every list, map and
    timeline shows the same members in the same order, grouped by firewall."""
    names = name if isinstance(name, list) else [name]
    return S.target(item, *functions, S.sort_series("asc"), S.alias(HOST_ITEM),
                    *(S.replace_alias(*n) for n in names), ref=ref, group=group, host=host)


def _scale(factor):
    return S._fn("scale", "Transform", [factor], [{"name": "factor", "type": "float"}], [100])


def _unary(op, field, alias_):
    return S.tf("calculateField", mode="unary", alias=alias_, replaceFields=False,
                unary={"operator": op, "fieldName": field})


def _per_host(item, *functions, ref="A"):
    return S.target(item, *functions, S.sort_series("asc"), S.alias("$__zbx_host_name"), ref=ref)


def _fw_colors(prefix=False):
    """Fixed colour per firewall for series named exactly "FW-SP" (per-host charts) or, prefix=True,
    starting with "FW-SP · " (interfaces: "FW-SP · lan1")."""
    return [{"matcher": {"id": "byRegexp", "options": f"^{fw} · .*"} if prefix else {"id": "byName", "options": fw},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
            for fw, c in FIREWALL_COLORS.items()]


# Tunnel state from the last value and the max of the window (status 1 down, 2 up), one row per tunnel:
# Ativo = 1 when the tunnel was up at least once, Up = 1 when it is up now, Estado = Ativo * (1 + Up)
# -> 0 inactive, 1 down, 2 up. ceil/floor keep it integral if the plugin ever consolidates samples.
def _vpn_state():
    last, peak = S.CALC_NAMES["lastNotNull"], S.CALC_NAMES["max"]
    return [S.reduce_rows(("lastNotNull", "max")),
            S.calc_binary(peak, "-", 1, "peak1"), _unary("ceil", "peak1", "Ativo"),
            S.calc_binary(last, "-", 1, "last1"), _unary("floor", "last1", "Up"),
            S.calc_binary("Up", "+", 1, "up1"), S.calc_binary("Ativo", "*", "up1", "Estado")]


# ------------------------------------------------------------------------------------------ KPI strip


def _share_kpi(title, targets, row_tf, description, health=False, time_from=S.STAT_WINDOW, mdp=S.STAT_MDP,
               caption="de ${__data.fields.Total}", extra=()):
    """Big "N" online with the caption "de M" above it, green only when every item is up. row_tf:
    transforms that turn the series into one row per item with "Online" and "Total" 0/1 columns (extra:
    more 0/1 columns for the caption; made text after the sum, so neither drawn nor part of the scale).
    The colour uses percentage thresholds: with min 0 and no max, Grafana takes the max of the numeric
    fields of the panel, i.e. Total, so the percentage is Online / Total. Total has to stay numeric for
    that, so the drawn field is picked by display name: every caption starts with "de " ("4 monitorados"
    read "1 monitorados" once filtered to one firewall)."""
    keep = S.filter_fields(f"^({'|'.join(('Online', 'Total', *extra))})$")
    tfs = [*(S.health_transforms() if health else row_tf), keep, S.reduce_fields(("sum",))]
    if extra:
        tfs.append(S.as_text(*extra))
    p = S.kpi(title, targets, transformations=tfs, value_size=58, decimals=0, min=0, description=description,
              time_from=S.HEALTH_WINDOW if health else time_from, mdp=20 if health else mdp,
              fields="/^de /", values=True, overrides=[S.col_props("Online", displayName=caption)])
    p["fieldConfig"]["defaults"].update(thresholds={"mode": "percentage", "steps": SHARE_STEPS},
                                        color={"mode": "thresholds"})
    p["options"].update(textMode="value_and_name", wideLayout=False)
    p["options"]["text"]["titleSize"] = 14
    return p


def _one_per_row():
    # Total = 1 per item (a field times 0, plus 1)
    return [S.calc_binary("Last *", "*", 0, "zero"), S.calc_binary("zero", "+", 1, "Total")]


def _kpis():
    health = S.health_targets([{"name": "Firewalls", "group": "$group"}])
    for t in health:                    # health_targets reads every host of the group: follow $host too
        t["host"]["filter"] = "$host"
    firewalls = _share_kpi("FIREWALLS ONLINE", health, None,
                           "Firewalls alcançáveis agora (ping ICMP, SNMP ou agente).", health=True)
    links = _share_kpi(
        "LINKS WAN ONLINE", [S.target(S.WAN_STATUS_RE, S.alias(HOST_ITEM))],
        # ifOperStatus: 1 up; 2 down, 7 lowerLayerDown... -> floor(1 / x) is 1 only for up
        [S.reduce_rows(), S.calc_binary(1, "/", "Last *", "inv"), _unary("floor", "inv", "Online"),
         *_one_per_row()],
        "Interfaces WAN / internet com status operacional UP.")
    slas = _share_kpi(
        "SLAs SD-WAN OK", [S.target(SDWAN_STATE_RE, S.alias(HOST_ITEM))],
        [S.reduce_rows(), S.calc_binary(1, "-", "Last *", "Online"), *_one_per_row()],     # 0 alive, 1 dead
        "Membros dos health-checks SD-WAN (SLA) em estado alive.")
    # "de 28 ativos · 31 config.": the tiles below list 31 tunnels, the 3 INATIVO are not in the 28
    tunnels = _share_kpi(
        "TÚNEIS ONLINE", [S.target(VPN_STATUS_RE, S.alias(HOST_ITEM))],
        [*_vpn_state(), S.calc_binary("Ativo", "*", 0, "zero"), S.calc_binary("zero", "+", 1, "Cfg"),
         S.organize(rename={"Up": "Online", "Ativo": "Total"})],
        "Túneis IPsec (fase 2) com status UP, entre os túneis ativos: os que ficaram fora nas últimas "
        "24 h inteiras (sem uso, aparecem em cinza como INATIVO) e o túnel reserva de gerência "
        "VPN-FGFM_MGMT2 não contam.",
        time_from=VPN_ACTIVE_WINDOW, mdp=VPN_MDP,
        caption="de ${__data.fields.Total} ativos · ${__data.fields.Cfg} config.", extra=("Cfg",))
    # sum of the last value of each firewall: the same number as the Sessões column of the table
    sessions = S.kpi(
        "SESSÕES ATIVAS", [_per_host(SESSIONS_RE)],
        transformations=[S.reduce_rows(), S.filter_fields(r"^Last \*$"), S.reduce_fields(("sum",))],
        # auto decimals: "17.6 K" for the sum, "983" for one firewall (decimals 1 printed "983.0")
        steps=S.NEUTRAL, unit="short", value_size=58, display_name="soma dos firewalls",
        description="Soma do último valor de sessões ativas (VDOM root) de cada firewall.")
    sessions["fieldConfig"]["defaults"]["color"] = {"mode": "fixed", "fixedColor": S.ACCENT}
    sessions["options"].update(textMode="value_and_name", wideLayout=False)
    sessions["options"]["text"]["titleSize"] = 14
    # the counters replace the feed at the top (as in the overview): grey zeros say "nothing open" in one
    # glance, and the full list sits at the end of the page
    problems = S.stat("PROBLEMAS ATIVOS POR SEVERIDADE",
                      [S.triggers_target(group="$group", host="$host", min_severity=2)],
                      transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
                      text_mode="value_and_name", color_mode="value", value_size=46, title_size=13,
                      steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None,
                      description="Triggers em problema agora nos firewalls filtrados, por severidade (lista "
                                  "completa no fim da página).")
    return firewalls, links, slas, tunnels, sessions, problems


# --------------------------------------------------------------------------------------------- saúde
TABLE_METRICS = [
    # (column, item) in display order
    ("Status", "ICMP ping"),
    ("CPU", S.CPU_RE),
    ("Memória", S.MEM_RE),
    ("Sessões", SESSIONS_RE),
    ("Sessões/s", SESSION_RATE_RE),           # short headers: 11 columns must fit at 1440 px
    ("Túneis IPsec", IPSEC_RE),
    ("Latência", "ICMP response time"),
    ("Perda", "ICMP loss"),
    ("Uptime", S.UPTIME_RE),
]


# uptime in days: Grafana duration units are English ("4 months"); ICMP latency in ms: Zabbix reports seconds
# and the "s" unit auto-scaled the LAN-close FW-SP to "191 µs" next to "32.9 ms" in the same column
SCALE = {"Uptime": 1 / 86400, "Latência": 1000}
LATENCY_MS = S.steps(S.OK, (50, S.WARN), (150, S.CRIT))      # = S.LATENCY_S in ms


def _text_target(item, ref):
    """Text-mode query (frontend-only): FortiGate sensor values are character items in Zabbix, which
    metrics queries skip. No alias functions in this mode: the series is named "<host>: <item>"."""
    t = S.target(item, ref=ref)
    t.update(queryType="2", textFilter="", useCaptureGroups=False, resultFormat="time_series")
    return t


def _health_table():
    """One row per firewall, one column per metric: every query is named "<firewall>: <column>" (the
    text query of the temperature: "<firewall>: <item>"), the names are split by a regexp and the rows
    pivoted with groupingToMatrix (fw x m). Short headers, fixed Firewall / Status widths and a low
    minimum column width: Grafana's default minimum (150 px) x 11 columns scrolled sideways at 1440 px."""
    targets = [S.target(item, *([_scale(SCALE[col])] if col in SCALE else []),
                        S.alias(f"$__zbx_host_name: {col}"), ref=S._ref(n))
               for n, (col, item) in enumerate(TABLE_METRICS)]
    targets.append(_text_target(TEMP_RE, S._ref(len(targets))))
    cols = [c for c, _ in TABLE_METRICS]
    order = ["fw\\m", *cols[:3], TEMP_ITEM, *cols[3:]]           # original names (before rename)
    tfs = [S.tf("convertFieldType", fields={},           # the temperature arrives as text: number first
                conversions=[{"targetField": "Value", "destinationType": "number"}]),
           # with one host selected the text query names its frame "<item>", without the "<host>: "
           # prefix, and the split below took the sensor for a firewall (a fake row and a raw "Value"
           # column). Put the prefix back; with several hosts the names start with "FW-" and this skips.
           S.tf("renameByRegex", regex=f"^({TEMP_ITEM})$", renamePattern="${host}: $1"),
           S.reduce_rows(),
           S.tf("extractFields", source="Field", format="regexp", regExp="/^(?<fw>[^:]+): (?<m>.+)$/",
                replace=False, keepTime=False),
           S.tf("groupingToMatrix", columnField="m", rowField="fw", valueField="Last *", emptyValue="null"),
           S.organize(rename={"fw\\m": "Firewall", TEMP_ITEM: "Temperatura"}, order=order)]
    link = S.data_link("Filtrar o dashboard por ${__value.raw}",
                       S.dashboard_url(KEY, **{"host": "${__value.raw}"}))
    # neutral counters (sessões, IPsec) stay in the default text colour: blue text read as a link
    columns = [
        S.col_props("Firewall", links=[link], **{"custom.width": 90}),
        S.col_props("Status", mappings=S.as_fill(S.AVAIL_MAP), **{"custom.width": 110}),
        S.col_color("Status", gradient=False),
        S.col_props("CPU", unit="percent", min=0, max=100, decimals=0,
                    thresholds={"mode": "absolute", "steps": S.PCT}),
        S.col_gauge("CPU"),
        S.col_props("Memória", unit="percent", min=0, max=100, decimals=0,
                    thresholds={"mode": "absolute", "steps": S.PCT}),
        S.col_gauge("Memória"),
        S.col_props("Temperatura", unit="celsius", decimals=0, thresholds={"mode": "absolute", "steps": TEMP_DIE}),
        S.col_color("Temperatura", mode="text"),
        S.col_props("Latência", unit="ms", decimals=1,
                    thresholds={"mode": "absolute", "steps": LATENCY_MS}),
        S.col_color("Latência", mode="text"),
        S.col_props("Perda", unit="percent", decimals=0, thresholds={"mode": "absolute", "steps": S.LOSS_PCT}),
        S.col_color("Perda", mode="text"),
        S.col_props("Uptime", unit="suffix: dias", decimals=0),
    ]
    for col in ("Sessões", "Sessões/s", "Túneis IPsec"):
        columns.append(S.col_props(col, unit="none", decimals=0))
    p = S.table("VISÃO POR FIREWALL", targets, columns=columns, transformations=tfs, cell_height="lg",
                time_from=COUNTER_WINDOW, mdp=S.STAT_MDP, align="center",
                description="Último valor de cada firewall (temperatura: sensor on-die da CPU; latência e "
                            "perda: ping ICMP do Zabbix; sessões/s: novas sessões por segundo). Clique no "
                            "nome para filtrar o dashboard.")
    p["fieldConfig"]["defaults"]["custom"]["minWidth"] = 80
    p["options"]["sortBy"] = [{"displayName": "Firewall", "desc": False}]
    return p


def _health_series():
    # low fill: 4 overlapping areas turned the memory chart into one muddy block; soft axis limits
    # instead of 0-100 %: CPU sits at 0-5 % and memory at 60-70 %, a full scale flattened both lines
    cpu = S.timeseries("CPU", [_per_host(S.CPU_RE)], unit="percent", min=0, steps=S.PCT, fill=6,
                       thresholds_style="dashed", legend="list", color=S.COLOR_SHADES, overrides=_fw_colors(),
                       description="Utilização de CPU por firewall (linhas tracejadas: 80 % e 90 %).")
    cpu["fieldConfig"]["defaults"]["custom"]["axisSoftMax"] = 25
    mem = S.timeseries("MEMÓRIA", [_per_host(S.MEM_RE)], unit="percent", max=100, steps=S.PCT, fill=0,
                       thresholds_style="dashed", legend="list", color=S.COLOR_SHADES, overrides=_fw_colors(),
                       description="Utilização de memória por firewall (linhas tracejadas: 80 % e 90 %).")
    mem["fieldConfig"]["defaults"]["custom"]["axisSoftMin"] = 40
    ses = S.timeseries("SESSÕES ATIVAS", [_per_host(SESSIONS_RE)], unit="short", legend="list", fill=6,
                       axis_soft_min=0, color=S.COLOR_SHADES, overrides=_fw_colors(),
                       description="Sessões ativas (VDOM root) por firewall.")
    return cpu, mem, ses


# ------------------------------------------------------------------------------------------ links WAN
# Per-firewall traffic chart: aliased by item only (the panel title carries the firewall). The interface
# named wan / wan1 is the primary link of each FortiGate here (the other one is "a" or wan2): fixed
# colours by that role (cyan / violet), so the two links of a chart never share a colour and no status or
# warm hue is used.
WAN_SHORT = r"/^Interface\s+([^(:]+)\(([^)]*)\):.*$/i"
PRIMARY_LINK = r".*\((wan|wan1)\).*"


def _wan_traffic():
    targets = [S.target(item, S.group_by("5m", "avg"), S.sort_series("asc"), S.alias("$__zbx_item"),
                        S.replace_alias(WAN_SHORT, f"$2 ($1) · {arrow}"), ref=ref)
               # the word first: the legend sorts by name, "download" < "upload" (bare arrows sorted ↑ first)
               for ref, item, arrow in (("A", S.WAN_IN_RE, "download ↓"), ("B", S.WAN_OUT_RE, "upload ↑"))]
    overrides = [
        {"matcher": {"id": "byRegexp", "options": PRIMARY_LINK},
         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": S.SERIES[0]}}]},
        # upload mirrored below the axis, lighter fill: download and upload of a link read as one shape
        {"matcher": {"id": "byRegexp", "options": ".*↑$"},
         "properties": [{"id": "custom.transform", "value": "negative-Y"}, {"id": "custom.fillOpacity", "value": 8}]},
    ]
    # max / last only: at w6 a mean column too cut the link names
    p = S.timeseries("${host} · TRÁFEGO WAN", targets, unit="bps", legend="table",
                     legend_calcs=("max", "lastNotNull"), fill=22,
                     color={"mode": "fixed", "fixedColor": S.ACCENT_2}, overrides=overrides,
                     description="Download (↓, acima do eixo) e upload (↑, abaixo) dos links WAN do firewall, "
                                 "média de 5 min.", repeat="host", repeatDirection="h", maxPerRow=4)
    p["options"]["legend"].update(placement="bottom", sortBy="Name", sortDesc=False)
    return p


def _wan():
    tiles = S.status_grid(
        "LINKS WAN · STATUS OPERACIONAL", [_named(S.WAN_STATUS_RE, WAN_NAME)],
        mappings=S.OPER_MAP, steps=S.OPER_STEPS, title_size=13, value_size=22, min_width=200, min_height=60,
        description="Status operacional (ifOperStatus) das interfaces WAN / internet de cada firewall.")
    timeline = S.state_timeline(
        "LINKS WAN · HISTÓRICO DE STATUS", [_named(S.WAN_STATUS_RE, WAN_NAME)],
        mappings=S.OPER_MAP, steps=S.OPER_STEPS, row_height=0.75, show_value="never",
        description="Quedas e oscilações dos links WAN no período.")
    return tiles, timeline, _wan_traffic()


# --------------------------------------------------------------------------------------------- SD-WAN


def _heatmap(title, item, steps, fn, unit, description):
    """Status history as a heatmap: one row per SLA member, one cell per interval coloured by thresholds.
    $__interval is interpolated by the plugin in the browser (mdp 48: about 7 min cells over 6h)."""
    return S.status_history(title, [_named(item, [SDWAN_TUNNEL, SDWAN_NAME], S.group_by("$__interval", fn))],
                            mappings=[], steps=steps, unit=unit, mdp=48, row_height=0.9, col_width=0.92,
                            legend=True, interval="1m", decimals=0, description=description)


def _worst(title, item, unit, steps, max_, description, calc="max"):
    """Ranked bars of the 6 worst SLA members on 5-min averages: the culprit is named, with its value,
    without hovering (6 cyan lines could not be told apart). calc "max": the worst 5-min average of the
    range (latency, jitter: smooth signals); "mean": the average of the whole range (loss: the probes drop
    single packets all the time; a raw max turned one 40 % sample out of 359 into a full red bar next to
    "SLAs 32/32 OK", and even the worst 5-min average stays red for one burst. The heatmap above shows
    when; these bars say who loses packets overall). Fixed max: the bar length means the same on every
    refresh."""
    return S.bargauge(
        title, [_named(item, [SDWAN_TUNNEL, SDWAN_NAME], S.group_by("5m", "avg"),
                       S.top(6, "max" if calc == "max" else "avg"))],
        calcs=(calc,), rank=True, unit=unit, min=0, max=max_, steps=steps, mode="basic", bar_height=20,
        name_placement="left", value_size=15, decimals=1 if calc == "max" else 2, time_from=None,
        mdp=S.SERIES_MDP, description=description)


def _sdwan():
    tiles = S.status_grid(
        "SLAs SD-WAN · ESTADO DOS HEALTH-CHECKS", [_named(SDWAN_STATE_RE, [SDWAN_TUNNEL, SDWAN_NAME])],
        mappings=SLA_MAP, steps=SLA_STEPS, **MANY_TILES,
        description="Estado de cada membro dos health-checks SD-WAN: firewall · SLA › link.")
    # loss only, full width: a latency map was 32 rows of the same teal (it encodes path length, not
    # health); the ranked latency / jitter bars below name the worst paths instead.
    # avg, not max: the probes lose single packets all the time (1-2% blips on every link), the max
    # painted the whole map amber
    loss = _heatmap("PERDA DE PACOTES SD-WAN · MAPA DE CALOR", S.SDWAN_LOSS_RE, SDWAN_LOSS, "avg", "percent",
                    "Perda de pacotes média por membro de SLA e intervalo. Verde < 1%, âmbar < 5%, "
                    "vermelho a partir de 5%.")
    worst = [_worst("LATÊNCIA · 6 PIORES (PICO DE 5 MIN)", S.SDWAN_LATENCY_RE, "ms", SDWAN_LATENCY_MS, 250,
                    "Os 6 membros de SLA com a maior latência média de 5 minutos no período."),
             _worst("JITTER · 6 PIORES (PICO DE 5 MIN)", S.SDWAN_JITTER_RE, "ms", SDWAN_JITTER_MS, 40,
                    "Os 6 membros de SLA com o maior jitter médio de 5 minutos no período."),
             _worst("PERDA MÉDIA · 6 PIORES", S.SDWAN_LOSS_RE, "percent", SDWAN_LOSS, 5,
                    "Os 6 membros de SLA com a maior perda de pacotes média no período inteiro. Picos "
                    "curtos aparecem no mapa de calor acima.", calc="mean")]
    return tiles, loss, worst


# ------------------------------------------------------------------------------------------------ VPN
VPN_TILES_ID = 50          # source of the per-firewall tunnel counts (dashboard_target)


def _vpn():
    # JSON alias: the tiles show "fw · túnel", the per-firewall panel groups the same rows by fw
    label = json.dumps({"fw": "$__zbx_host_name", "t": "$__zbx_item"}, ensure_ascii=False)
    query = S.target(VPN_STATUS_RE, S.sort_series("asc"), S.alias(label),
                     S.replace_alias(r'/"VPN (.*): Tunnel Status"/', '"$1"'))
    tiles = S.status_grid(
        "TÚNEIS VPN IPSEC", [query], id=VPN_TILES_ID,
        # 8 tiles per row at w16 (31 tunnels: 8/8/8/7): rows of 9 left a much wider last row
        mappings=TUNNEL_MAP, steps=TUNNEL_STEPS, **{**MANY_TILES, "min_width": 160}, values=True,
        time_from=VPN_ACTIVE_WINDOW, mdp=VPN_MDP,
        transformations=[*_vpn_state(),
                         S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
                         S.filter_fields("^(fw|t|Estado)$")],
        overrides=[S.col_props("Estado", displayName="${__data.fields.fw} · ${__data.fields.t}")],
        description="Status de cada túnel IPsec (fase 2) por firewall. INATIVO (cinza): nenhum UP nas "
                    "últimas 24 h, túnel configurado mas sem uso; não conta como falha. O túnel reserva "
                    "de gerência VPN-FGFM_MGMT2 fica de fora.")
    # "All values" mode draws at most `limit` rows, 25 by default: 6 of the 31 tunnels were silently missing
    tiles["options"]["reduceOptions"]["limit"] = 200
    # tunnels online / active per firewall, coloured by share like the health tiles of the overview
    per_fw = S.status_grid(
        "TÚNEIS ONLINE POR FIREWALL", [S.dashboard_target(VPN_TILES_ID)], datasource=dict(S.DASHBOARD_DS),
        mappings=S.no_data_map("SEM TÚNEIS"), steps=S.AVAIL_RATIO,
        title_size=13, value_size=22, min_width=110, min_height=60, values=True, time_from=None, mdp=None,
        transformations=[
            S.calc_binary("Estado", "/", 2, "half"), _unary("floor", "half", "on"), _unary("ceil", "half", "act"),
            S.tf("groupBy", fields={"fw": {"operation": "groupby", "aggregations": []},
                                    "on": {"operation": "aggregate", "aggregations": ["sum"]},
                                    "act": {"operation": "aggregate", "aggregations": ["sum"]}}),
            S.organize(rename={"on (sum)": "Online", "act (sum)": "Total"}),
            S.calc_binary("Online", "/", "Total", "Disponibilidade"),
            S.as_text("Online", "Total")],
        # unit on the drawn field only: the name template formats Online / Total with the panel unit
        overrides=[S.col_props("Disponibilidade", unit="percentunit", decimals=0,
                               displayName="${__data.fields.fw} · ${__data.fields.Online}/${__data.fields.Total}")],
        description="Túneis online / túneis ativos de cada firewall (inativos fora da conta).")
    ssl = S.stat(
        "USUÁRIOS SSL VPN", [_per_host(SSL_USERS_RE)], steps=S.NEUTRAL, unit="short", decimals=0,
        text_mode="value_and_name", title_size=13, value_size=30, wide=False, time_from=COUNTER_WINDOW,
        description="Usuários conectados à VPN SSL em cada firewall (último valor).")
    names = "|".join(f"{fw} · {t}" for fw, ts in INACTIVE_TUNNELS.items() for t in ts)
    inactive = {"matcher": {"id": "byRegexp", "options": f"^({names})$"},
                "properties": [{"id": "mappings", "value": TUNNEL_INACTIVE_MAP},
                               {"id": "thresholds", "value": {"mode": "absolute", "steps": TUNNEL_INACTIVE_STEPS}}]}
    timeline = S.state_timeline(
        "TÚNEIS VPN · HISTÓRICO", [_named(VPN_STATUS_RE, (r"/: VPN (.*): Tunnel Status$/", " · $1"))],
        mappings=S.VPN_MAP, steps=S.VPN_STEPS, row_height=0.8, show_value="never", overrides=[inactive],
        description="Quedas e reconexões dos túneis IPsec no período. Os túneis configurados mas sem uso "
                    "(INATIVO nos blocos acima) aparecem em cinza, não como falha.")
    return tiles, per_fw, ssl, timeline


# ----------------------------------------------------------------------------------------- interfaces
# LAN ports and tunnels only: the WAN ports have their own row (wan, wan1, "a(<provider>)"), and the
# software-switch parents (lan, internal, WIFI) repeat the traffic of their member port (lan1, internal1,
# lan3), which padded the top 10 with duplicates. Inserted into the v1 physical-interface lookahead.
_NOT_WAN_OR_SWITCH = r"(?:lan|internal|wifi|wan\d*)\(|a\([^)]|"
_NOT_SWITCH = r"(?:lan|internal|wifi)\(|"


def _ports(item_re, exclude):
    head = "/^Interface (?!"
    assert item_re.startswith(head), item_re
    return head + exclude + item_re[len(head):]


def _error_target(item_re, metric, kind, ref):
    """Worst interfaces of one counter as JSON {fw, iface, tipo}: the table splits the alias."""
    label = json.dumps({"fw": "$__zbx_host_name", "iface": "$__zbx_item", "tipo": kind}, ensure_ascii=False)
    return S.target(_ports(item_re, _NOT_SWITCH), S.top(10, "max"), S.alias(label),
                    S.replace_alias(rf"/Interface\s+(.+?)(\(\))?: {metric}/", "$1"), ref=ref)


def _interfaces():
    heavy = (" Histórico bruto de muitas interfaces: com todos os firewalls, períodos acima de ~2 dias "
             "podem estourar a memória do frontend do Zabbix.")
    traffic = []
    for title, item, what in (("TRÁFEGO DE ENTRADA · TOP 10", S.TRAFFIC_IN_RE, "recebido"),
                              ("TRÁFEGO DE SAÍDA · TOP 10", S.TRAFFIC_OUT_RE, "enviado")):
        traffic.append(S.timeseries(
            title, [_named(_ports(item, _NOT_WAN_OR_SWITCH), [IF_DESCR, IF_NAME], S.top(10))],
            # colour = firewall, as in the health charts: the classic palette drew status-like greens and
            # reds and repeated colours, so a legend colour could not identify a line
            unit="bps", legend="table", legend_calcs=("mean", "max", "lastNotNull"), axis_soft_min=0,
            color=S.COLOR_SHADES, overrides=_fw_colors(prefix=True),
            description=f"Portas LAN e túneis com maior tráfego {what} (as WAN estão na seção Links WAN; "
                        "switches de software como lan / internal / WIFI ficam de fora para não repetir "
                        "a porta membro)." + heavy))
    # only the interfaces that had errors or discards: a list of green zeros read like a problem list
    peak = S.CALC_NAMES["max"]
    errors = S.table(
        "INTERFACES COM ERROS OU DESCARTES DE ENTRADA",
        [_error_target(S.ERRORS_IN_RE, "Inbound packets with errors", "Erros", "A"),
         _error_target(S.DISCARDS_IN_RE, "Inbound packets discarded", "Descartes", "B")],
        transformations=[S.reduce_rows(("max",)),
                         S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
                         S.organize(rename={"fw": "Firewall", "iface": "Interface", "tipo": "Tipo", peak: "Pico"},
                                    exclude=["Field"], order=["fw", "iface", "tipo", peak]),
                         S.tf("filterByValue", type="include", match="any",
                              filters=[{"fieldName": "Pico", "config": {"id": "greater", "options": {"value": 0}}}]),
                         S.sort_by("Pico")],
        columns=[S._col("Pico", ("custom.cellOptions", {"type": "gauge", "mode": "gradient",
                                                        "valueDisplayMode": "color"}),
                        ("unit", "pps"), ("decimals", 2), ("min", 0),
                        ("thresholds", {"mode": "absolute", "steps": S.steps(S.OK, (0.01, S.WARN), (1, S.CRIT))}),
                        ("color", {"mode": "thresholds"}))],
        cell_height="sm", mdp=200, no_value="Nenhuma interface com erros ou descartes no período",
        description="Interfaces com pacotes recebidos com erro ou descartados no período (pico); as "
                    "que ficaram em zero não aparecem." + heavy)
    return traffic[0], traffic[1], errors


# ------------------------------------------------------------------------------------------ dashboard


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)
    firewalls, links, slas, tunnels, sessions, severities = _kpis()
    table = _health_table()
    cpu, mem, ses = _health_series()
    wan_tiles, wan_timeline, wan_traffic = _wan()
    sla_tiles, sla_loss, sla_worst = _sdwan()
    vpn_tiles, vpn_per_fw, vpn_ssl, vpn_timeline = _vpn()
    if_in, if_out, if_err = _interfaces()
    # column widths by hand as in switches (the plugin cannot wrap): the problem name gets the room
    problems = S.problems("PROBLEMAS ATIVOS", [S.problems_target(min_severity=1)], page_size=8,
                          font_size="110%", host_groups=False, tags=False, age=False,
                          description="Problemas abertos nos firewalls (inclusive Informação), do mais grave "
                                      "ao menos grave.")
    problems["options"].update(resizedColumns=[{"id": "host", "value": 160}, {"id": "name", "value": 1420},
                                               {"id": "lastchange", "value": 130}],
                               customLastChangeFormat=True, lastChangeFormat="DD/MM HH:mm")

    panels = S.grid(
        (4, [(S.banner("FIREWALLS", "Rede · WAN · VPN"), 4), (firewalls, 3), (links, 3), (slas, 3),
             (tunnels, 3), (sessions, 3), (severities, 5)]),
        S.row("Saúde dos firewalls", children=[
            (8, [(table, 24)]),
            (8, [(cpu, 8), (mem, 8), (ses, 8)]),
        ]),
        S.row("Links WAN", children=[
            (4, [(wan_tiles, 24)]),
            (7, [(wan_timeline, 24)]),
            (11, [(wan_traffic, 6)]),
        ]),
        S.row("SD-WAN · SLA", children=[
            (8, [(sla_tiles, 24)]),
            (17, [(sla_loss, 24)]),          # 32 rows: below h16 the row labels overlap
            (7, [(sla_worst[0], 8), (sla_worst[1], 8), (sla_worst[2], 8)]),
        ]),
        S.row("VPN", children=[
            (9, [(vpn_tiles, 16), (S.stack((vpn_per_fw, 5), (vpn_ssl, 4)), 8)]),
            (14, [(vpn_timeline, 24)]),
        ]),
        S.row("Interfaces", children=[
            (9, [(if_in, 24)]),
            (9, [(if_out, 24)]),
            (5, [(if_err, 24)]),
        ]),
        S.row("Problemas ativos", children=[
            (9, [(problems, 24)]),
        ]),
    )
    return S.dashboard(KEY, TITLE, panels, datasource_uid=datasource_uid, range_cap="2d",
                       variables=S.category_variables(cat["group"]),
                       description="Firewalls FortiGate: saúde, links WAN, SLAs SD-WAN, túneis VPN e interfaces.")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.firewalls config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
