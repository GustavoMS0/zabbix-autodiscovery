"""Switches: desktop analysis dashboard (1920 wide, scrolls).

Layout:
  y0   h4  banner | online | offline | portas em uso | problemas por severidade
  row  Estado atual: inventory table, one row per switch (ping, latency, port usage gauge, CPU/memory,
       temperature, uptime); CPU/memory are plain text with "não exposto" where the template has no item
  row  Disponibilidade: ICMP state timeline over the range | live problems
  row  Tráfego: top 5 physical ports in | out (log axis)
  row  Qualidade: ICMP latency (top 5) | ports with inbound errors/discards (peak and mean)

Colours of per-host / per-port lines: Grafana 13 has no field matcher by index, and every built-in
palette tried ("palette-classic", "-by-name", "palette-categorical-next") puts green, amber or red on some
line (a green latency line next to the amber 50 ms threshold reads as a status); shades of cyan were too
close to tell 5 lines apart. So each rank is its own query, ranked(): top(k) then bottom(1) is exactly the
k-th series, its refId gets SERIES[k-1] through a byFrameRefID override, and the legend (sorted by mean)
lists the ranks in palette order. Cost: one query per rank (measured on the switch ports at 1 day: ~2-3 s
each, the same as one top-N query), so the charts stop at TOP_N = 5; the full lists live in the tables.

The helpers at the top (inventory table, health KPIs, filial-aware filters) are shared with
access_points.py. Item regexes and windows are the verified v1 ones (style re-exports them); the interface
panels keep v1's physical-port regexes and top-N, and the time picker stops at 1 day like v1 (~370 ports:
the raw history of every port fails from 2 days with all switches).
"""
import json

from . import style as S

KEY = "switches"
TABLE_ID = 10           # inventory table
HEALTH_ID = 11          # online KPI: its data feeds the offline KPI (dashboard_target)

NOT_EXPOSED = "não exposto"
TOP_N = 5               # lines per multi-series chart: beyond 5 the cyan shades stop being told apart
COLOR_SERIES = {"mode": "fixed", "fixedColor": S.SERIES[0]}  # fallback; ranks get S.SERIES (ranked())
LATENCY_MS = S.steps(S.OK, (50, S.WARN), (150, S.CRIT))      # S.LATENCY_S in ms (targets scale(1000))
# Switch temperature: the vendor templates' triggers fire at > 70 (warning) and > 75 °C (high), so the cell
# turns amber/red together with a Zabbix problem (BRA30's CPU idles at ~62 °C: healthy)
TEMP_SWITCH = S.steps(S.OK, (70, S.WARN), (75, S.CRIT))
# Port occupancy is capacity, not health: cyan bar, amber only when almost no port is left
PORT_USAGE = S.steps(S.ACCENT, (95, S.WARN))
# Error / discard rates (packets/s). Mean: the templates' "High error rate" trigger fires above
# {$IF.ERRORS.WARN} = 2/s for 5 min (checked in Zabbix), so a mean above 2 is amber like that problem and
# 10x that is red. Peak: one discarded packet in the range is noise, 10/s is worth a look, 100/s a fault.
PEAK_STEPS = S.steps(S.OK, (10, S.WARN), (100, S.CRIT))
RATE_STEPS = S.steps(S.OK, (2, S.WARN), (20, S.CRIT))
PEAK_MAX = 100
# Filial column of the inventory: one cheap ping query per site whose value is replaced by the site's index
# (scale(0) + offset(n)) and mapped back to the site name. The Zabbix alias macros carry no host group, so
# this is the only way to get the site into a per-host row.
_SITE_COLOR = S.TEXT


# ------------------------------------------------------------------------------------ shared helpers


def filter_variables(cfg, group_re):
    """group + filial + host. The host list is the hosts of $group that are also in the chosen filial
    ($site_hosts, hidden); with no allValue, "Todos" expands to that list, so every query follows the
    filial filter without a second host filter."""
    host = S.host_var()
    host["query"]["host"] = S.SITE_HOSTS_RE
    host.pop("allValue", None)
    return [S.group_var(group_re), S.site_var(cfg), S.site_hosts_var(cfg), host]


def _scale(factor):
    return S._fn("scale", "Transform", [factor], [{"name": "factor", "type": "float"}], [100])


def _offset(delta):
    return S._fn("offset", "Transform", [delta], [{"name": "delta", "type": "float"}], [100])


def matrix_target(item, column, *functions, ref, group="$group"):
    """Last values of `item` for the inventory table: the alias is JSON {host, m} so the frontend can
    pivot every query into one row per host (matrix_transforms). column: the table column, or
    "$__zbx_item" to take the item name (renamed in matrix_transforms)."""
    label = json.dumps({"host": "$__zbx_host_name", "m": column}, ensure_ascii=False)
    return S.target(item, *functions, S.alias(label), ref=ref, group=group)


def site_targets(cfg, first_ref):
    """Filial column: one ping query per site, value = index of the site (1..n)."""
    out = []
    for n, s in enumerate(S.sites(cfg), 1):
        out.append(matrix_target("ICMP ping", "Filial", _scale(0), _offset(n),
                                 ref=chr(ord(first_ref) + n - 1), group=s["group"]))
    return out


def site_mapping(cfg):
    return S.value_map({str(n): (s["label"], _SITE_COLOR) for n, s in enumerate(S.sites(cfg), 1)})


def matrix_transforms(name_col, rename=None, order=()):
    """JSON-aliased last values -> one row per host, one column per metric, sorted by host name."""
    rename = dict(rename or {})
    rename["host\\m"] = name_col
    original = {new: old for old, new in rename.items()}        # organize orders by the original names
    return [
        S.reduce_rows(),
        S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
        S.tf("groupingToMatrix", columnField="m", rowField="host", valueField=S.CALC_NAMES["lastNotNull"],
             emptyValue="null"),
        S.organize(rename=rename, order=[original.get(n, n) for n in (name_col, *order)]),
        S.sort_by(name_col, desc=False),
    ]


def uptime_target(ref):
    """Uptime in days (scale on the Zabbix side): Grafana's duration units only speak English ("1.1 years")."""
    return matrix_target(S.UPTIME_RE, "Uptime", _scale(1 / 86400), ref=ref)


def uptime_col(width=None):
    """Uptime in whole days; a reboot in the last 24 h shows "< 1 dia" in amber."""
    recent = [{"type": "range", "options": {"from": 0, "to": 0.999, "result": {"text": "< 1 dia", "color": S.WARN}}},
              {"type": "range", "options": {"from": 1, "to": 1.999, "result": {"text": "1 dia"}}}]
    return text_col("Uptime", S.steps(S.WARN, (1, S.TEXT)), unit="suffix: dias", decimals=0, width=width,
                    mappings=recent)


def host_link(dash_key, field):
    """Data link of the host column: the same dashboard filtered on that host and the filial. No time
    range: ${__url_time_range} renders empty in table data links (Grafana 13) and ${__from}/${__to} resolve
    to the inventory's own 15-minute window (timeFrom), which would pin every chart to an absolute 15 min.
    The dashboard default (last 6 h, relative) applies instead."""
    host = "${__data.fields[\"%s\"]}" % field
    url = f"/d/{S.uid(dash_key)}?${{site:queryparam}}&var-host={host}"
    return [S.data_link(f"Filtrar {host}", url)]


def status_col(name, mappings=S.AVAIL_MAP, steps=S.AVAIL_STEPS, width=130):
    """Status cell: deep fill tile (as in the status grids), PT-BR text."""
    return S._col(name, ("mappings", S.as_fill(mappings) + S.no_data_map(color=S.FILL_UNKNOWN)),
                  ("thresholds", {"mode": "absolute", "steps": S.as_fill(steps)}),
                  ("color", {"mode": "thresholds"}),
                  ("custom.cellOptions", {"type": "color-background", "mode": "basic"}),
                  ("custom.align", "center"), ("custom.width", width))


def text_col(name, steps, unit=None, decimals=None, width=None, no_value=None, mappings=None):
    """Numeric column in neon text coloured by thresholds."""
    props = [("thresholds", {"mode": "absolute", "steps": steps}), ("color", {"mode": "thresholds"}),
             ("custom.cellOptions", {"type": "color-text"})]
    if no_value:      # grey text through a null mapping: noValue would take the base threshold colour
        mappings = list(mappings or []) + S.no_data_map(no_value)
    for key, value in (("unit", unit), ("decimals", decimals), ("custom.width", width), ("mappings", mappings)):
        if value is not None:
            props.append((key, value))
    return S._col(name, *props)


def gauge_col(name, steps, unit="percent", min=0, max=100, decimals=0, no_value=None, width=None):
    """In-cell bar gauge, "gradient" mode: neon fill on a grey track (LCD segments tint the empty part
    with the threshold colours, which put red on healthy rows; "basic" draws a dull, dimmed bar)."""
    props = [("custom.cellOptions", {"type": "gauge", "mode": "gradient", "valueDisplayMode": "color"}),
             ("thresholds", {"mode": "absolute", "steps": steps}), ("color", {"mode": "thresholds"}),
             ("unit", unit), ("min", min), ("decimals", decimals)]
    if max is not None:
        props.append(("max", max))
    if no_value:
        props.append(("mappings", S.no_data_map(no_value)))
    if width:
        props.append(("custom.width", width))
    return S._col(name, *props)


def health_kpis(dim_name):
    """ONLINE ("de N") and OFFLINE KPIs with the overview's definition of online (best of
    ping / SNMP / agent availability), so the numbers match the overview's category tile. The offline
    tile reuses the online tile's data: one Zabbix query for both."""
    targets = S.health_targets([{"name": dim_name, "group": "$group"}])
    for t in targets:
        t["host"]["filter"] = "$host"           # follow the filial/host filters
    # short titles: the banner already names the category, and long ones are cut at 1440 px
    online = S.kpi("ONLINE", targets, id=HEALTH_ID, steps=S.steps(S.OK), calcs=("lastNotNull",),
                   transformations=[*S.health_transforms(), S.filter_fields("^(Online|Total)$"),
                                    S.as_text("Total")],
                   # "de N", not "N monitorados": a host filter gives "1 monitorados"
                   overrides=[S.col_props("Online", displayName="de ${__data.fields.Total}")],
                   time_from=S.HEALTH_WINDOW, mdp=20, values=True, value_size=52,
                   description="Alcançáveis agora por ping, SNMP ou agente (mesma regra da Visão Geral).")
    online["options"].update(textMode="value_and_name", wideLayout=False)
    online["options"]["text"]["titleSize"] = 14
    offline = S.kpi("OFFLINE", [S.dashboard_target(HEALTH_ID, with_transforms=False)],
                    datasource=dict(S.DASHBOARD_DS), steps=S.COUNT_BAD, calcs=("lastNotNull",),
                    transformations=[*S.health_transforms(), S.filter_fields("^(Offline|Total)$"),
                                     S.as_text("Total")],
                    # same caption line as ONLINE, so both big numbers sit on one baseline
                    overrides=[S.col_props("Offline", displayName="de ${__data.fields.Total}")],
                    time_from=None, mdp=None, values=True, value_size=52,
                    description="Sem nenhuma verificação de disponibilidade OK (ping, SNMP ou agente).")
    offline["options"].update(textMode="value_and_name", wideLayout=False)
    offline["options"]["text"]["titleSize"] = 14
    return online, offline


def table_kpi(title, table_id, fields, *, steps=S.NEUTRAL, unit=None, decimals=0, caption=None,
              description=None, extra_tf=(), value_size=52, value_field=None):
    """Big number summed from the inventory table's columns (no extra Zabbix query). fields: the table
    columns summed; value_field: the drawn one (default fields[0]); caption: name template under the
    number, e.g. "${__data.fields.Total} portas" (the referenced fields stay as text)."""
    value_field = value_field or fields[0]
    others = [f for f in fields if f != value_field]
    keep = "^(" + "|".join([value_field, *others]) + ")$"
    p = S.kpi(title, [S.dashboard_target(table_id)], datasource=dict(S.DASHBOARD_DS),
              transformations=[S.filter_fields("^(" + "|".join(fields) + ")$"), S.reduce_fields(("sum",)),
                               *extra_tf, S.filter_fields(keep), *([S.as_text(*others)] if others else [])],
              calcs=("lastNotNull",), steps=steps, unit=unit, decimals=decimals, value_size=value_size,
              time_from=None, mdp=None, description=description, values=bool(caption),
              overrides=[S.col_props(value_field, displayName=caption)] if caption else None)
    if caption:
        p["options"].update(textMode="value_and_name", wideLayout=False)
        p["options"]["text"]["titleSize"] = 14
    return p


def problems_kpi():
    return S.stat("PROBLEMAS ATIVOS POR SEVERIDADE", [S.triggers_target(group="$group", host="$host",
                                                                        min_severity=2)],
                  transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
                  text_mode="value_and_name", color_mode="value", value_size=46, title_size=14,
                  steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None,
                  description="Triggers em problema agora nos hosts filtrados, por severidade.")


def availability_timeline(title, noun, row_height=0.8):
    """ICMP ping per host over the range. 5-minute minimum: a bucket with any failed ping is OFFLINE, and
    the values stay exactly 0/1 so the PT-BR value map applies (an average would print 0.98)."""
    return S.state_timeline(
        # sortSeries asc sorts by name on the backend: same order as the inventory table
        title, [S.target("ICMP ping", S.group_by("5m", "min"), S.sort_series("asc"),
                         S.alias("$__zbx_host_name"))],
        mappings=S.AVAIL_MAP + S.no_data_map(), steps=S.AVAIL_STEPS, row_height=row_height,
        show_value="never", mdp=300,
        description=f"Ping de cada {noun} no período (blocos de 5 min; qualquer falha no bloco = OFFLINE).")


def ranked(item, *functions, fn="avg", n=TOP_N, pre=()):
    """n queries A.. = the n highest series by `fn`, one per refId, so each rank gets a fixed SERIES colour
    (see the module docstring). pre: functions before the ranking (e.g. scale), functions: after (aliases)."""
    return [S.target(item, *pre, S.top(k, fn), S.bottom(1, fn), *functions, ref=S._ref(k - 1))
            for k in range(1, n + 1)]


def rank_colors(n=TOP_N):
    return S.series_colors([S._ref(k) for k in range(n)])


def latency_series(title, noun):
    # ms scaled on the Zabbix side: Grafana's "s" unit mixes "34.5 ms" and "865.7 µs" in one legend
    p = S.timeseries(
        title, ranked("ICMP response time", S.alias("$__zbx_host_name"), pre=[_scale(1000)]),
        unit="ms", color=COLOR_SERIES, overrides=rank_colors(), steps=LATENCY_MS, thresholds_style="dashed",
        axis_soft_min=0, legend_calcs=("mean", "max"), sort_by="Mean",
        description=f"Tempo de resposta ICMP dos {TOP_N} {noun} com maior latência média no período (a "
                    "latência atual de todos está no inventário). Linhas tracejadas: 50 ms (atenção) e 150 ms "
                    "(crítico)." + LEGEND_NOTE)
    p["options"]["legend"]["width"] = 400
    # the Zabbix frames carry the item unit "s", which beats the panel default: forced by an override
    p["fieldConfig"]["overrides"].append(S.col_props("number", by="byType", unit="ms"))
    return p


def port_alias(metric_re="Bits (received|sent)", suffix=""):
    """"host: Interface 1/0/10(descr): Bits sent" -> "host · 1/0/10<suffix>" (replaceAlias runs on the
    alias, so it matches after the host prefix)."""
    return [S.alias("$__zbx_host_name: $__zbx_item"),
            S.replace_alias(rf"/: Interface\s+(.+?)\(.*\): {metric_re}$/", f" · $1{suffix}")]


LEGEND_NOTE = " Legenda: Mean = média, Max = pico no período."


def traffic_series(title, targets, description):
    """Traffic lines on a log-10 axis: one port at ~1 Gb/s on a linear axis flattens every other port
    (<= 30 Mb/s) into the bottom pixels. Floor at 1 kb/s: an idle radio dipping to 1 b/s would otherwise
    stretch the axis over 6 decades of noise. Light fill: on a log axis every area reaches the floor and
    the overlapping fills turn into a brown wash."""
    p = S.timeseries(title, targets, unit="bps", color=COLOR_SERIES, min=1000, fill=6,
                     overrides=rank_colors(len(targets)),
                     legend_calcs=("mean", "max"), sort_by="Mean",
                     description=description + " Eixo logarítmico (cada linha de grade = 10x)." + LEGEND_NOTE)
    p["fieldConfig"]["defaults"]["custom"]["scaleDistribution"] = {"type": "log", "log": 10}
    p["options"]["legend"]["width"] = 400     # names + 2 columns; the chart keeps the rest of the panel
    return p


def port_traffic(item_re):
    # Comware names ("GigabitEthernet1/0/10") eat the legend: shortened to the CLI abbreviations, plain
    # "Ethernet1/0/47" too so one switch does not mix "GE1/0/52" with the long form
    return ranked(item_re, *port_alias(), S.replace_alias("/Ten-GigabitEthernet/", "XGE"),
                  S.replace_alias("/GigabitEthernet/", "GE"), S.replace_alias("/ · Ethernet/", " · Eth"))


def problems_feed(page_size=6):
    """Live problems of the filtered hosts. The plugin cannot wrap text, so the widths are set by hand:
    the problem ("name" column) gets ~560 px, enough for "Interface Unit 1 Port 21(): Link down" after the
    template prefix; host and the short start time get just what they need. No age column: the start
    time already says it."""
    p = S.problems("PROBLEMAS ATIVOS", [S.problems_target()], page_size=page_size, font_size="100%",
                   age=False,
                   # the plugin's own texts (empty state "No problems found", pager) are English only
                   description="Problemas ativos (severidade Atenção ou maior) nos hosts filtrados, do mais "
                               "grave ao menos grave. Painel vazio (\"No problems found\") = nenhum problema "
                               "ativo.")
    p["options"].update(resizedColumns=[{"id": "host", "value": 170}, {"id": "name", "value": 560},
                                        {"id": "lastchange", "value": 110}],
                        customLastChangeFormat=True, lastChangeFormat="DD/MM HH:mm")
    return p


# ------------------------------------------------------------------------------------------- build


def port_target(item_re, metric, kind, ref, top_n=4):
    """Worst ports of one counter as JSON {host, porta, tipo}: the table splits the alias into columns.
    metric: the item name after "Interface X(descr): " (regex)."""
    label = json.dumps({"host": "$__zbx_host_name", "porta": "$__zbx_item", "tipo": kind}, ensure_ascii=False)
    return S.target(item_re, S.top(top_n, "max"), S.alias(label),
                    S.replace_alias(rf"/Interface\s+(.+?)\(.*\): {metric}/", "$1"), ref=ref)


def errors_table(title, name_col, targets, description, type_width=105):
    """Ports with the highest error / discard rate in the range (targets: port_target), worst peak first.
    The mean next to the peak tells a chronic fault (errors in many samples) from a one-off burst. Ports
    that stayed at 0 are dropped: a list of green zeros reads like a problem list; an empty table shows
    "Nenhuma porta com erros no período" instead. Unit "p/s" as a plain suffix: Grafana's "pps" SI-scales
    small rates to "8.33 mp/s" (millipackets), read as 8 packets. The peak bar has a fixed 0-100 p/s scale
    so one stray packet stays a sliver instead of a full red bar."""
    peak, mean = S.CALC_NAMES["max"], S.CALC_NAMES["mean"]
    tiny = [{"type": "range", "options": {"from": -1, "to": 0.00999, "result": {"text": "< 0.01 p/s"}}}]
    return S.table(
        title, targets,
        transformations=[S.reduce_rows(("mean", "max")),
                         S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
                         S.organize(rename={"host": name_col, "porta": "Porta", "tipo": "Tipo", mean: "Média",
                                            peak: "Pico"},
                                    exclude=["Field"], order=["host", "porta", "tipo", mean, peak]),
                         S.tf("filterByValue", type="include", match="any",
                              filters=[{"fieldName": "Pico", "config": {"id": "greater", "options": {"value": 0}}}]),
                         S.sort_by("Pico")],
        columns=[S.col_width(name_col, 170), S.col_width("Porta", 95), S.col_width("Tipo", type_width),
                 text_col("Média", RATE_STEPS, unit="suffix: p/s", decimals=2, width=105, mappings=tiny),
                 S._col("Pico", ("custom.cellOptions", {"type": "gauge", "mode": "basic",
                                                        "valueDisplayMode": "color"}),
                        ("unit", "suffix: p/s"), ("min", 0), ("max", PEAK_MAX),
                        ("thresholds", {"mode": "absolute", "steps": PEAK_STEPS}),
                        ("color", {"mode": "thresholds"}))],
        cell_height="sm", mdp=S.SERIES_MDP, no_value="Nenhuma porta com erros no período",
        description=description + " Pico: barra em escala fixa de 0 a 100 p/s (âmbar a partir de 10, "
                                  "vermelho a partir de 100). Média: âmbar acima de 2 p/s, o limite do trigger "
                                  "\"High error rate\" do template; vermelho acima de 20 p/s.")


def _inventory(cfg):
    w = S.STAT_WINDOW
    targets = [
        matrix_target("ICMP ping", "Ping", ref="A"),
        matrix_target("ICMP response time", "Latência", _scale(1000), ref="B"),
        matrix_target("ICMP loss", "Perda", ref="C"),
        matrix_target(r"/^Switch: (Ports in use|Physical ports|Port usage|Enabled ports without link)$/",
                      "$__zbx_item", ref="D"),
        matrix_target(S.CPU_RE, "CPU", ref="E"),
        matrix_target(S.MEM_RE, "Memória", ref="F"),
        matrix_target(S.TEMP_RE, "Temperatura", ref="G"),
        uptime_target("H"),
        *site_targets(cfg, "I"),
    ]
    rename = {"Switch: Ports in use": "Portas em uso", "Switch: Physical ports": "Portas físicas",
              "Switch: Port usage": "Uso das portas", "Switch: Enabled ports without link": "Sem link"}
    order = ["Filial", "Ping", "Latência", "Perda", "Uso das portas", "Portas em uso", "Portas físicas",
             "Sem link", "CPU", "Memória", "Temperatura", "Uptime"]
    # Widths add up to ~1210 px: at 1440 the table fits without a horizontal scrollbar; the port gauge
    # takes whatever is left (auto width).
    columns = [
        S._col("Switch", ("links", host_link(KEY, "Switch")), ("custom.width", 190)),
        S._col("Filial", ("mappings", site_mapping(cfg)), ("custom.width", 130), ("custom.align", "left")),
        status_col("Ping", width=100),
        text_col("Latência", LATENCY_MS, unit="ms", decimals=1, width=92),
        text_col("Perda", S.LOSS_PCT, unit="percent", decimals=0, width=70),
        gauge_col("Uso das portas", PORT_USAGE, decimals=0),
        # kept in the data for the PORTAS EM USO KPI, hidden: the gauge and the KPI already say it
        S._col("Portas em uso", ("custom.hidden", True)),
        text_col("Portas físicas", S.steps(S.TEXT), decimals=0, width=108),
        text_col("Sem link", S.steps(S.MUTED), decimals=0, width=80),
        # plain text: 6 of 7 templates expose no CPU/memory, and an empty gauge track reads as 0 %
        text_col("CPU", S.PCT, unit="percent", decimals=0, width=105, no_value=NOT_EXPOSED),
        text_col("Memória", S.PCT, unit="percent", decimals=0, width=105, no_value=NOT_EXPOSED),
        # the HP Comware module sensor reports a constant 0 °C: shown as "sem leitura", not as a temperature
        text_col("Temperatura", TEMP_SWITCH, unit="celsius", decimals=0, width=112, no_value="sem sensor",
                 mappings=[{"type": "range", "options": {"from": -1000, "to": 0.5,
                                                         "result": {"text": "sem leitura", "color": S.UNKNOWN}}}]),
        uptime_col(width=95),
    ]
    return S.table(
        "INVENTÁRIO E ESTADO ATUAL", targets, id=TABLE_ID, columns=columns, cell_height="md",
        transformations=matrix_transforms("Switch", rename, order), time_from=w, mdp=S.STAT_MDP,
        description="Último valor (15 min) por switch. Uso das portas = portas com link / portas físicas "
                    "(template AutoDiscovery - Switch port usage). CPU, memória e temperatura só aparecem "
                    "onde o template do fabricante expõe o item via SNMP (\"não exposto\" / \"sem sensor\" nos "
                    "demais). Uso das portas é capacidade, não saúde: barra ciano, âmbar só acima de 95 %. "
                    "Temperatura: âmbar acima de 70 °C e vermelho acima de 75 °C, os mesmos limites dos triggers "
                    "do template. Clique no nome para filtrar o dashboard nesse switch.")


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)

    banner = S.banner("SWITCHES", "Rede · LAN")
    online, offline = health_kpis("Switches")
    ports = table_kpi("PORTAS EM USO", TABLE_ID, ["Portas em uso", "Portas físicas"],
                      caption="${__data.fields[\"Portas físicas\"]} portas físicas",
                      description="Portas com link somadas em todos os switches filtrados.")
    inventory = _inventory(cfg)

    timeline = availability_timeline("DISPONIBILIDADE (PING) NO PERÍODO", "switch")
    feed = problems_feed()

    traffic_in = traffic_series(
        f"TRÁFEGO DE ENTRADA · TOP {TOP_N} PORTAS", port_traffic(S.TRAFFIC_IN_RE),
        f"As {TOP_N} portas físicas com maior média de bits recebidos no período (LAG, VLAN e portas de CPU/stack "
        "ficam de fora). Intervalos acima de 1 dia com todos os switches podem exceder o limite de memória "
        "do Zabbix.")
    traffic_out = traffic_series(
        f"TRÁFEGO DE SAÍDA · TOP {TOP_N} PORTAS", port_traffic(S.TRAFFIC_OUT_RE),
        f"As {TOP_N} portas físicas com maior média de bits enviados no período.")

    latency = latency_series("LATÊNCIA ICMP", "switches")
    # inbound only, one query each (v1: errors + discards of ~370 ports in one regex time out)
    errors = errors_table(
        "ERROS E DESCARTES DE ENTRADA · PIORES PORTAS", "Switch",
        [port_target(S.ERRORS_IN_RE, "Inbound packets with errors", "erros", "A"),
         port_target(S.DISCARDS_IN_RE, "Inbound packets discarded", "descartes", "B")],
        "Pacotes/s com erro e descartados no período (média e pico): as 4 piores portas físicas de cada "
        "contador. Só aparecem portas com pico acima de 0; média alta = falha crônica (ex.: CRC), média "
        "perto de 0 com pico alto = rajada isolada.")

    panels = S.grid(
        (4, [(banner, 5), (online, 3), (offline, 3), (ports, 4), (problems_kpi(), 9)]),
        S.row("Estado atual", children=[(10, [(inventory, 24)])]),
        # the feed gets the width: Zabbix problem names start with a long template prefix
        S.row("Disponibilidade e problemas", children=[(8, [(timeline, 11), (feed, 13)])]),
        S.row("Tráfego · portas físicas", children=[(10, [(traffic_in, 12), (traffic_out, 12)])]),
        # errors table only lists ports that had errors: usually a few rows, so the latency chart gets the room
        # 14/10: the peak bar keeps ~250 px next to the switch, port, type and mean columns
        S.row("Qualidade", children=[(9, [(latency, 14), (errors, 10)])]),
    )
    return S.dashboard(KEY, "Switches", panels, datasource_uid=datasource_uid,
                       variables=filter_variables(cfg, cat["group"]), time_from="now-6h", range_cap="1d",
                       description="Switches: estado, portas, tráfego e qualidade (análise em desktop).")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.switches config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
