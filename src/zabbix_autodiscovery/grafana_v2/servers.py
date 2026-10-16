"""Servidores: desktop analysis of the Windows/Linux servers and hypervisors (1920 wide, scrolling OK).

Layout:
  y0   h4   banner | disponibilidade | CPU máx. | memória máx. | disco máx. | menor uptime (worst host named)
  y4   h15  visão por servidor (one row per host, worst first) | problemas ativos (h6) / volumes mais cheios (h9)
  y19  h9   CPU por servidor · mapa de calor | memória por servidor · mapa de calor
  y28  h8   tráfego de entrada · mapa de calor | tráfego de saída · mapa de calor (log bins, Mb/s)

The per-host table is a "status matrix": every metric is one query aliased as JSON {"h": host, "m": column},
reduced to its last value and pivoted host x column in the browser (groupingToMatrix). One cheap 15-minute
query set feeds the table and, through the "-- Dashboard --" datasource, the KPI tiles too.

History is drawn as heat maps (one row per server, one cell per interval), the same language as the SD-WAN
maps of the firewalls dashboard: Grafana cannot give dynamic top-N series the validated SERIES colours (no
custom palette, no index matcher), and 10 cyan shades made the line charts unreadable. A row label never
needs a legend to be matched.
"""
import json
import re

from . import style as S

KEY = "servers"
TITLE = "Servidores"
MATRIX_ID = 20              # source of the KPI tiles (dashboard_target)
MATRIX_WINDOW = "15m"       # every matrix item is polled each 30s-1m (FS items depend on a 1m master item)
# v1 verified: the servers' availability is ICMP ping where linked, else the agent availability (2 = unknown)
DISK_RE = r"/Space: Used, in %|Space utilization/"
RAM_TOTAL_RE = r"/^Total memory$/"
NO_DATA = "Sem dados para a seleção"   # PT-BR empty-panel text (drill-down on a host without the metric)
DAYS = "suffix: dias"       # PT-BR: Grafana's duration units only speak English ("1 day, 8 hours")
# Top-N sized to what the panels show: the h8 heat maps hold 8 rows, the h9 volume list 10 bars of 18px
TOP_IF = 8
TOP_VOLUMES = 10
FEED_ROWS = 2               # problems that fit the h6 feed: pageSize = visible rows, no half-empty pager
# "host: Interface <long driver name>(<connection name>): Bits received" -> "host · <connection name>"
IF_ALIASES = (S.replace_alias(r"/: Interface .*\(([^()]*)\): Bits (received|sent)$/", " · $1"),
              S.replace_alias(r"/: Interface ([^:]+): Bits (received|sent)$/", " · $1"))
# Volume label: "host · FS [VDDBDEV(T:)]: Space: Used, in %" -> "host · T:" (Linux: "host · /"). The volume
# labels made the long ones ("Seagate Backup Plus Drive") truncate; the panel description says so.
VOLUME_ALIASES = (S.replace_alias(r"/ · FS \[.*\(([A-Z]:)\)\]: Space: Used, in %$/", " · $1"),
                  S.replace_alias(r"/ · FS \[(.*)\]: Space: Used, in %$/", " · $1"))

# Heat map colours: one dim teal ramp, evenly spaced in lightness and kept well below ACCENT, that turns
# amber/red only where PCT does (80/90 %): a healthy map reads calm and only a real issue is loud. Checked
# with the dataviz validator against the #181b1f panel (monotone lightness, adjacent dL >= 0.06, lowest
# step at 2:1 so the "< 20%" cells stay visible as cells).
TEAL_RAMP = ("#1A5560", "#16697A", "#137F93", "#1596AD")
PCT_RAMP = S.steps(TEAL_RAMP[0], (20, TEAL_RAMP[1]), (40, TEAL_RAMP[2]), (60, TEAL_RAMP[3]), (80, S.WARN),
                   (90, S.CRIT))
# Traffic has no "bad" level on a 1 Gb/s server link: intensity only, on log-spaced bins (1/10/100/500
# Mb/s; linear bins drew 50 and 190 Mb/s alike), the same teal ramp ending in cyan, no status colour
BPS_RAMP = S.steps(TEAL_RAMP[0], (1e6, TEAL_RAMP[1]), (1e7, TEAL_RAMP[2]), (1e8, TEAL_RAMP[3]), (5e8, S.ACCENT))
# Healthy cells of the status matrices: darker than FILL_OK, so full columns of ONLINE / OK stay calm and
# the strong FILL_* blocks are kept for the codes that need attention
CALM_OK_FILL = "#0F4A33"


def scale(factor):
    """scale() of the plugin (backend): e.g. seconds -> days."""
    return S._fn("scale", "Transform", [factor], [{"name": "factor", "type": "float"}], [100])


def offset(delta):
    """offset() of the plugin (backend): shifts a status code into its own range of a value map."""
    return S._fn("offset", "Transform", [delta], [{"name": "delta", "type": "float"}], [-100])


# Agent column, coded so that a higher number is a worse state (the table sorts on it). v1's
# AGENT_STATUS_RE folds two different items: "Zabbix agent availability" (agent template linked; 1 up /
# 0 down, unknown removed) is flipped to 0 OK / 1 down; "port 10050 reachable" (template "Zabbix agent
# missing": something answers on the port, but the server has no agent template, so no CPU/memory/disk) is
# shifted to 10 closed / 11 open. The two items never share a host (checked in Zabbix), so the max() fold
# of the matrix is unaffected.
AGENT_ITEM_RE = r"/^Zabbix agent availability$/"
AGENT_PORT_RE = r"/^Zabbix agent: port 10050 reachable$/"
AGENT_COL_MAP = S.value_map({"0": ("OK", S.OK), "1": ("SEM AGENTE", S.CRIT), "10": ("PORTA FECHADA", S.CRIT),
                             "11": ("SEM TEMPLATE", S.WARN)})
AGENT_COL_STEPS = S.steps(S.OK, (1, S.CRIT), (11, S.WARN))
# NGINX-SRV has a second "CPU utilization" item (LLD "Nginx process discovery", key proc.cpu.util[nginx])
# with the same name and tag as the host CPU: v1's CPU_RE matches both. The series carry the item key in
# their alias and the browser drops the process item (the plugin has no exclude function). Grafana anchors
# a pattern without slashes (^...$), hence the .* on both sides.
CPU_KEY_ALIAS = S.alias("$__zbx_host_name|$__zbx_item_key")
DROP_PROCESS_CPU = [S.tf("filterFieldsByName", exclude={"pattern": r".*\|proc\.cpu.*"}),
                    S.tf("renameByRegex", regex=r"^(.*)\|.*$", renamePattern="$1")]


# ------------------------------------------------------------------------------- status matrix helpers
# Shared with server_hardware.py: one row per host, one column per metric/component.
_LAST = S.CALC_NAMES["lastNotNull"]
_WORST = f"{_LAST} (max)"


def matrix_target(item, column, *functions, ref, group="$group", host="$host"):
    """Last value of `item` per host for the matrix column `column` (several items of one host in the same
    column are folded with max(): worst status, fullest volume)."""
    label = json.dumps({"h": "$__zbx_host_name", "m": column}, ensure_ascii=False)
    return S.target(item, *functions, S.alias(label), ref=ref, group=group, host=host)


def matrix_transforms(columns, host_title="Servidor"):
    """Series -> table: host_title | columns..., one row per host, in the given column order."""
    return [
        S.reduce_rows(),
        S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
        S.tf("groupBy", fields={"h": {"operation": "groupby", "aggregations": []},
                                "m": {"operation": "groupby", "aggregations": []},
                                _LAST: {"operation": "aggregate", "aggregations": ["max"]}}),
        S.tf("groupingToMatrix", columnField="m", rowField="h", valueField=_WORST, emptyValue="null"),
        # organize matches the original field names: the pivot names its first column "<row>\<column>"
        S.organize(rename={"h\\m": host_title}, order=["h\\m", *columns]),
    ]


def not_null(field):
    """Rows whose `field` has a value (filterByValue)."""
    return S.tf("filterByValue", type="include", match="all",
                filters=[{"fieldName": field, "config": {"id": "isNotNull", "options": {}}}])


def from_matrix(column, reducer, *, steps, unit=None, decimals=0, panel_id=MATRIX_ID, named=False,
                host_title="Servidor", value_size=48, **kw):
    """KPI tile computed from one column of a matrix panel (no extra Zabbix query).
    named=False: the column reduced over every row (e.g. the worst status code).
    named=True: the worst row (reducer "max" or "min"), with its host as the tile name, so a worst-case
    tile also says WHERE. An empty selection (drill-down on a host without that metric) is a grey dash,
    never the base threshold colour (green "No data" would read as healthy)."""
    col = re.escape(column)
    if named:
        tfs = [not_null(column), S.sort_by(column, desc=reducer == "max"), S.tf("limit", limitField=1),
               S.filter_fields(f"^({re.escape(host_title)}|{col})$")]
        kw["overrides"] = list(kw.get("overrides") or []) + [
            S.col_props(column, displayName=f"${{__data.fields.{host_title}}}")]
    else:
        tfs = [S.filter_fields(f"^{col}$"), S.reduce_fields((reducer,))]
    kw["mappings"] = list(kw.get("mappings") or []) + S.no_data_map("—")
    p = S.stat(kw.pop("title"), [S.dashboard_target(panel_id)], datasource=dict(S.DASHBOARD_DS),
               transformations=tfs, steps=steps, unit=unit, decimals=decimals, no_value="—",
               text_mode="value_and_name" if named else "value", values=named, wide=False,
               title_size=14 if named else None, value_size=value_size, time_from=None, mdp=None, **kw)
    return p


def availability_kpi(title, dim_name, noun, description, group="$group"):
    """Availability of the selection as the big number (100% green, < 100% amber, < 90% red) and
    "12 de 13 <noun>" as its name. A plain "online" count stayed green with a server down: the colour
    must follow the offline hosts. Health pipeline of the overview (best availability check per host)."""
    targets = S.health_targets([{"name": dim_name, "group": group}])
    for t in targets:
        t["host"]["filter"] = "$host"
    p = S.stat(title, targets, value_size=48, title_size=14, steps=S.AVAIL_RATIO, time_from=S.HEALTH_WINDOW,
               mdp=20, values=True, text_mode="value_and_name", wide=False,
               mappings=S.no_data_map("—"), no_value="—",
               transformations=[*S.health_transforms(), S.as_text("Online", "Total", "Offline")],
               overrides=[S.col_props("Disponibilidade", unit="percentunit", decimals=0,
                                      displayName=f"${{__data.fields.Online}} de ${{__data.fields.Total}} {noun}")],
               description=description)
    return p


def calm(obj):
    """Value maps / steps with FILL_OK swapped for CALM_OK_FILL (matrix cells in a healthy state)."""
    return json.loads(json.dumps(obj).replace(f'"{S.FILL_OK}"', f'"{CALM_OK_FILL}"'))


def problems_feed(page_size, host_px=150, name_px=290):
    """Problems panel sized to its panel: pageSize = visible rows; Age is hidden and Time gets a short
    "DD/MM HH:mm" format (the plugin cannot hide Time, and Age speaks English: "33 minutes"); Host keeps
    its full name. Column ids are the plugin's (host, priority, name, lastchange)."""
    p = S.problems("PROBLEMAS ATIVOS", [S.problems_target(min_severity=1)], page_size=page_size, age=False)
    p["options"].update(customLastChangeFormat=True, lastChangeFormat="DD/MM HH:mm",
                        resizedColumns=[{"id": "host", "value": host_px}, {"id": "priority", "value": 90},
                                        {"id": "name", "value": name_px}, {"id": "lastchange", "value": 100}])
    p["description"] = ("Problemas ativos dos hosts da seleção (severidade Informação ou maior), mais graves "
                        "primeiro; Time = início do problema. Cabeçalhos em inglês: limitação do plugin Zabbix.")
    return p


def heatmap(title, targets, *, steps, unit, description, transformations=None, decimals=1):
    """History as a heat map: one row per series, one cell per interval coloured by `steps` ($__interval
    is interpolated by the plugin in the browser; mdp 48 = 7.5 min cells over 6h). noValue also replaces
    Grafana's English "No data" message of an empty panel (once the panel has finished loading)."""
    description += (f' "{NO_DATA}" = o servidor filtrado não tem essa métrica no Zabbix (ex.: monitorado só '
                    "por ping).")
    return S.status_history(title, targets, mappings=[], steps=steps, unit=unit, mdp=48, row_height=0.9,
                            col_width=0.92, legend=True, interval="1m", decimals=decimals, no_value=NO_DATA,
                            transformations=transformations, description=description)


def host_link(key, label="Filtrar por ${__value.text}"):
    """Data link of a host cell: this dashboard filtered on that host (drill-down)."""
    return [S.data_link(label, S.dashboard_url(key, host="${__value.raw}"))]


def host_column(name="Servidor", width=140, links=None):
    """Host name column in the page's text colour: Grafana's default link blue is outside the v2 palette
    (it read as the "Informação" severity); the link shows on hover."""
    props = {"custom.width": width, "color": {"mode": "fixed", "fixedColor": S.TEXT},
             "custom.cellOptions": {"type": "color-text"}}
    if links:
        props["links"] = links
    return S.col_props(name, **props)


# -------------------------------------------------------------------------------------------- panels


def _matrix():
    cols = ["Status", "Agente", "CPU", "Memória", "Disco", "RAM", "Uptime"]
    targets = [
        matrix_target(S.AVAIL_RE, "Status", S.remove_above(1), ref="A"),
        matrix_target(AGENT_ITEM_RE, "Agente", S.remove_above(1), scale(-1), offset(1), ref="B"),
        matrix_target(AGENT_PORT_RE, "Agente", offset(10), ref="H"),
        matrix_target(S.CPU_RE, "CPU", ref="C"),
        matrix_target(S.MEM_RE, "Memória", ref="D"),
        matrix_target(DISK_RE, "Disco", ref="E"),
        matrix_target(RAM_TOTAL_RE, "RAM", ref="F"),
        matrix_target(S.UPTIME_RE, "Uptime", scale(1 / 86400), ref="G"),
    ]
    # Hosts monitored by ping only (no agent template) show a grey dash: the null mapping also greys the
    # gauge, otherwise a null cell drew a green tick at 0% that read as a healthy, idle meter
    pct = dict(unit="percent", min=0, max=100, decimals=1, noValue="—", mappings=S.no_data_map("—"))
    columns = [
        host_column("Servidor", 140, host_link(KEY)),
        S.col_props("Status", mappings=calm(S.as_fill(S.AVAIL_MAP)) + S.no_data_map(color=S.FILL_UNKNOWN),
                    thresholds={"mode": "absolute", "steps": calm(S.as_fill(S.AVAIL_STEPS))},
                    color={"mode": "thresholds"}, **{"custom.width": 100, "custom.align": "center"}),
        S.col_color("Status", gradient=False),
        S.col_props("Agente", mappings=calm(S.as_fill(AGENT_COL_MAP)) + S.no_data_map("SEM AGENTE", S.FILL_CRIT),
                    thresholds={"mode": "absolute", "steps": calm(S.as_fill(AGENT_COL_STEPS))},
                    color={"mode": "thresholds"}, **{"custom.width": 120, "custom.align": "center"}),
        S.col_color("Agente", gradient=False),
        *(S.col_props(c, **pct, thresholds={"mode": "absolute", "steps": S.PCT}, color={"mode": "thresholds"})
          for c in ("CPU", "Memória", "Disco")),
        # basic bars on a neutral track: the LCD mode tinted every unlit segment with the threshold colours,
        # so each row ended in a faint red stub
        *(S.col_gauge(c, mode="basic") for c in ("CPU", "Memória", "Disco")),
        S.col_props("RAM", unit="bytes", decimals=0, noValue="—", **{"custom.width": 80, "custom.align": "right"}),
        S.col_props("Uptime", unit=DAYS, decimals=1, noValue="—", **{"custom.width": 90, "custom.align": "right"}),
    ]
    # Worst first: offline, then agent problems (codes grow with severity), then the fullest of CPU /
    # memory / disk. Chained stable sorts, least significant key first; the helper field is dropped after.
    order = [S.tf("calculateField", mode="reduceRow", alias="_pior", replaceFields=False,
                  reduce={"include": ["CPU", "Memória", "Disco"], "reducer": "max"}),
             S.sort_by("_pior", desc=True), S.sort_by("Agente", desc=True), S.sort_by("Status", desc=False),
             S.organize(exclude=["_pior"])]
    p = S.table("VISÃO POR SERVIDOR", targets, id=MATRIX_ID, columns=columns, cell_height="sm",
                time_from=MATRIX_WINDOW, mdp=30, transformations=matrix_transforms(cols) + order,
                description="Último valor dos últimos 15 minutos por servidor, piores primeiro (offline, "
                            "problema de agente, maior uso). Disco = volume mais cheio do servidor. Agente "
                            "\"SEM TEMPLATE\" = a porta 10050 responde, mas o host não tem template de agente "
                            "no Zabbix (por isso sem CPU, memória e disco). Clique no nome para filtrar a "
                            "dashboard por ele.")
    # the gauges give way first on a narrow screen (1440): Grafana's 150px default minimum scrolled the
    # table sideways and cut Disco, RAM and Uptime
    p["fieldConfig"]["defaults"]["custom"]["minWidth"] = 70
    return p


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)
    group_re = cat["group"]

    banner = S.banner("SERVIDORES", "Windows e Linux")
    online = availability_kpi("DISPONIBILIDADE", TITLE, "online",
                              "Servidores alcançáveis agora (ping ou agente Zabbix) sobre os monitorados.")
    cpu = from_matrix("CPU", "max", named=True, title="CPU MÁX.", unit="percent", decimals=1, steps=S.PCT,
                      description="Servidor com o maior uso de CPU agora (80% âmbar, 90% vermelho).")
    mem = from_matrix("Memória", "max", named=True, title="MEMÓRIA MÁX.", unit="percent", decimals=1,
                      steps=S.PCT, description="Servidor com o maior uso de memória agora (80% âmbar, 90% "
                                               "vermelho).")
    disk = from_matrix("Disco", "max", named=True, title="DISCO MÁX.", unit="percent", decimals=1,
                       steps=S.PCT, description="Servidor com o volume mais cheio (80% âmbar, 90% vermelho).")
    uptime = from_matrix("Uptime", "min", named=True, title="MENOR UPTIME", unit=DAYS, decimals=1,
                         steps=S.steps(S.WARN, (1, S.ACCENT)),
                         description="Servidor ligado há menos tempo: menos de 1 dia (âmbar) indica reinício "
                                     "recente.")

    matrix = _matrix()
    feed = problems_feed(FEED_ROWS)
    volumes = S.bargauge(
        f"VOLUMES MAIS CHEIOS · {TOP_VOLUMES} MAIORES",
        [S.target(DISK_RE, S.top(TOP_VOLUMES, "max"), S.alias("$__zbx_host_name · $__zbx_item"), *VOLUME_ALIASES)],
        rank=True, unit="percent", decimals=1, steps=S.PCT, mode="basic", bar_height=18,
        name_placement="left", value_size=15, no_value=NO_DATA,
        mappings=S.no_data_map(NO_DATA),
        description=f"Ocupação atual dos {TOP_VOLUMES} volumes mais cheios, maiores primeiro (80% âmbar, 90% "
                    "vermelho). Windows: letra da unidade; Linux: ponto de montagem.")

    cpu_map = heatmap(
        "CPU POR SERVIDOR · MAPA DE CALOR",
        [S.target(S.CPU_RE, S.group_by("$__interval", "max"), S.sort_series("asc"), CPU_KEY_ALIAS)],
        steps=PCT_RAMP, unit="percent", decimals=0, transformations=DROP_PROCESS_CPU,
        description="Pico de uso de CPU de cada servidor por intervalo: quanto mais claro, mais carregado; "
                    "âmbar a partir de 80%, vermelho de 90%.")
    mem_map = heatmap(
        "MEMÓRIA POR SERVIDOR · MAPA DE CALOR",
        [S.target(S.MEM_RE, S.group_by("$__interval", "avg"), S.sort_series("asc"), S.alias("$__zbx_host_name"))],
        steps=PCT_RAMP, unit="percent", decimals=0,
        description="Uso médio de memória de cada servidor por intervalo: quanto mais claro, mais cheio; "
                    "âmbar a partir de 80%, vermelho de 90%.")

    def traffic(title, item):
        return heatmap(
            f"{title} · {TOP_IF} MAIORES · MÉDIA POR INTERVALO",
            [S.target(item, S.group_by("$__interval", "avg"), S.top(TOP_IF, "avg"),
                             S.alias("$__zbx_host_name: $__zbx_item"), *IF_ALIASES)],
            steps=BPS_RAMP, unit="bps", decimals=0,
            description=f"As {TOP_IF} interfaces com maior tráfego médio no período, maiores no topo. Cor = "
                        "tráfego médio do intervalo em faixas de 1 / 10 / 100 / 500 Mb/s (só intensidade: "
                        "não indica problema; o valor exato fica na dica ao passar o mouse).")

    t_in = traffic("TRÁFEGO DE ENTRADA", S.TRAFFIC_IN_RE)
    t_out = traffic("TRÁFEGO DE SAÍDA", S.TRAFFIC_OUT_RE)

    panels = S.grid(
        (4, [(banner, 4), (online, 4), (cpu, 4), (mem, 4), (disk, 4), (uptime, 4)]),
        (15, [(matrix, 15), (S.stack((feed, 6), (volumes, 9)), 9)]),
        (9, [(cpu_map, 12), (mem_map, 12)]),
        (8, [(t_in, 12), (t_out, 12)]),
    )
    return S.dashboard(KEY, TITLE, panels, datasource_uid=datasource_uid, range_cap="7d",
                       variables=S.category_variables(group_re),
                       description="Servidores Windows, Linux e hypervisors: disponibilidade, agente, CPU, "
                                   "memória, disco, tráfego e uptime.")
