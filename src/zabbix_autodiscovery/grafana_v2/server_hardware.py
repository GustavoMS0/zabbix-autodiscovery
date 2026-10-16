"""Hardware dos servidores (Dell iDRAC): desktop analysis (1920 wide, scrolling OK).

Layout:
  y0   h4   banner | online | saúde | fontes | discos | temp. | CPU máx. (worst-state tiles name the host)
  y4   h9   matriz de saúde: one row per iDRAC (worst first), one column per component, PT-BR value maps
  y13  h8   temperaturas por servidor (estado / entrada / CPU / saída) | ventoinhas | problemas ativos
  y21  h9   entrada de ar no período (27/32 °C lines) | saída de ar no período
  y30       collapsed row: every fan

iDRAC items are dependent items of SNMP walks with "discard unchanged, heartbeat 6h" (v1 measurement): a
window under 6h can hold no value at all, so every last-value panel reads 24h, the dashboard opens on 24h,
and the time series bridge the gaps (an unchanged value is simply not stored) with step lines. Fan speeds
are stored every walk.

The Estado column carries the iDRAC's own probe status (its thresholds are per model and per sensor).
Only the inlet, the room's air, also gets the fixed TEMP_INLET scale (27/32 °C, ASHRAE-like) as a
secondary cue; it agrees with the iDRAC on the live data (28 °C inlet = iDRAC warning).

Visual QA: a cold load takes 6-7 s before the matrix and the KPIs render; screenshot with a 15-20 s wait.
"""
from . import style as S
from .servers import (
    availability_kpi,
    calm,
    from_matrix,
    host_column,
    host_link,
    matrix_target,
    matrix_transforms,
    offset,
    problems_feed,
)

KEY = "server-hardware"
TITLE = "Hardware dos Servidores"
MATRIX_ID = 20              # health matrix: source of the state KPIs
TEMPS_ID = 21               # temperature table: source of the temperature KPIs
IDRAC_WINDOW = "24h"        # 6h heartbeat of the discard-unchanged preprocessing (v1: 1h = 0 frames)
FAN_WINDOW = "15m"          # fans are stored on every walk (v1: bar gauge 15m, 60 frames / 126 ms)
OVERALL_RE = r"/^Overall system health status$/"
PSU_RE = r"/^Power supply \[.*\]: State$/"
PDISK_RE = r"/^Physical disk \[.*\]: Status$/"
FAN_RE = r"/^Fan \[.*\]: Speed$/"
# Probe values: inlet (R250 "Inlet Temp", R440/R630 "System Board Inlet Temp"), exhaust and CPU sockets
INLET_RE = r"/^Probe \[(System Board )?Inlet Temp\]: Value$/"
EXHAUST_RE = r"/^Probe \[.*Exhaust Temp\]: Value$/"
CPU_TEMP_RE = r"/^Probe \[CPU\d+ Temp\]: Value$/"
TEMP_STATUS_RE = r"/^Probe \[.*Temp\]: Status$/"
# "24°C" without Grafana's space: the narrow KPI tiles otherwise wrap the unit onto a second line
CELSIUS_TIGHT = "suffix:°C"
# Fans: a stopped fan (0 rpm) is the reading that matters most, abnormally slow is suspicious
RPM_STEPS = S.steps(S.CRIT, (1, S.WARN), (1500, S.ACCENT))
NO_DATA = "Sem dados para a seleção"
# Inlet lines and text: neutral cyan while the room is fine, amber / red past the TEMP_INLET limits
INLET_STEPS = S.steps(S.ACCENT, (27, S.WARN), (32, S.CRIT))
OK_CODE = 3                 # ObjectStatusEnum "ok": the worst-state tiles name a host only when it is worse
FEED_ROWS = 4               # problems that fit the h8 feed


def remove_below(value):
    """removeBelowValue of the plugin (backend): values below `value` become null."""
    return S._fn("removeBelowValue", "Transform", [value], [{"name": "number", "type": "float"}], [0])


def transform_null(value=0):
    """transformNull of the plugin (backend): nulls become `value`."""
    return S._fn("transformNull", "Transform", [value], [{"name": "number", "type": "float"}], [0])


# ------------------------------------------------------------------------- status enums and the fold
# Status enums of the IDRAC-MIB (value maps checked in Zabbix). Several items of one host in the same column
# (8 disks, 2 PSUs...) are folded with max(). That is right for ObjectStatusEnum (3 ok < 4 non-critical <
# 5 critical < 6 non-recoverable), but not for three enums whose codes are not ordered by severity:
#   virtual disk 3 = failed < 4 = degraded; RAID battery 3 = failed and 5 = missing < 6 charging / 7 low;
#   probes 5/6 = critical/non-recoverable upper < 7 = non-critical lower.
# Those critical codes ("worse" ranges) get one extra query each that keeps only them, shifted by PROMOTE
# above every other code (everything else becomes 0, below any real code), so max() returns them first.
PROMOTE = 20
_NA = ("SEM SUPORTE", S.UNKNOWN)          # 0: health OIDs not exposed (idrac-srv01)
OBJECT_CODES = {"0": _NA, "1": ("OUTRO", S.UNKNOWN), "2": ("DESCONHECIDO", S.UNKNOWN), "3": ("OK", S.OK),
                "4": ("ALERTA", S.WARN), "5": ("CRÍTICO", S.CRIT), "6": ("IRRECUPERÁVEL", S.CRIT)}
OBJECT_STEPS = S.IDRAC_STEPS
# StatusProbeEnum (fans, temperature and voltage probes): 4/7 non-critical upper/lower...
PROBE_CODES = {"1": ("OUTRO", S.UNKNOWN), "2": ("DESCONHECIDO", S.UNKNOWN), "3": ("OK", S.OK),
               "4": ("ALERTA", S.WARN), "5": ("CRÍTICO", S.CRIT), "6": ("IRRECUPERÁVEL", S.CRIT),
               "7": ("ALERTA", S.WARN), "8": ("CRÍTICO", S.CRIT), "9": ("IRRECUPERÁVEL", S.CRIT),
               "10": ("FALHA", S.CRIT)}
PROBE_STEPS = S.steps(S.UNKNOWN, (3, S.OK), (4, S.WARN), (5, S.CRIT), (7, S.WARN), (8, S.CRIT))
PROBE_WORSE = ((5, 6),)
VDISK_CODES = {"1": ("DESCONHECIDO", S.UNKNOWN), "2": ("ONLINE", S.OK), "3": ("FALHA", S.CRIT),
               "4": ("DEGRADADO", S.WARN)}
VDISK_STEPS = S.steps(S.UNKNOWN, (2, S.OK), (3, S.CRIT), (4, S.WARN))
VDISK_WORSE = ((3, 3),)
BATTERY_CODES = {"1": ("DESCONHECIDO", S.UNKNOWN), "2": ("PRONTA", S.OK), "3": ("FALHA", S.CRIT),
                 "4": ("DEGRADADA", S.WARN), "5": ("AUSENTE", S.CRIT), "6": ("CARREGANDO", S.WARN),
                 "7": ("BAIXA", S.WARN)}
BATTERY_STEPS = S.steps(S.UNKNOWN, (2, S.OK), (3, S.CRIT), (4, S.WARN), (5, S.CRIT), (6, S.WARN))
BATTERY_WORSE = ((3, 3), (5, 5))
SMART_CODES = {"0": ("OK", S.OK), "1": ("FALHA", S.CRIT)}
SMART_STEPS = S.steps(S.OK, (1, S.CRIT))
AVAIL_CODES = {"0": ("OFFLINE", S.CRIT), "1": ("ONLINE", S.OK), "2": ("DESCONHECIDO", S.UNKNOWN)}

# (column, item regex, codes, steps, worse ranges), in order of importance: a narrow screen scrolls the
# least important columns out of view, not the ones that hold the alerts
COMPONENTS = [
    ("Geral", OVERALL_RE, OBJECT_CODES, OBJECT_STEPS, ()),
    ("Sensores", r"/^Probe \[.*\]: Status$/", PROBE_CODES, PROBE_STEPS, PROBE_WORSE),
    ("Fontes", PSU_RE, OBJECT_CODES, OBJECT_STEPS, ()),
    ("Discos", PDISK_RE, OBJECT_CODES, OBJECT_STEPS, ()),
    ("Volumes", r"/^Virtual disk \[.*\]: Status$/", VDISK_CODES, VDISK_STEPS, VDISK_WORSE),
    ("Ventoinhas", r"/^Fan \[.*\]: Status$/", PROBE_CODES, PROBE_STEPS, PROBE_WORSE),
    ("Tensão", r"/^Voltage probe \[.*\]: Status$/", PROBE_CODES, PROBE_STEPS, PROBE_WORSE),
    ("CPUs", r"/^CPU \[.*\]: Status$/", OBJECT_CODES, OBJECT_STEPS, ()),
    ("Memória", r"/^Memory \[.*\]: Status$/", OBJECT_CODES, OBJECT_STEPS, ()),
    ("Ctrl.", r"/^Controller \[.*\]: Status$/", OBJECT_CODES, OBJECT_STEPS, ()),
    ("SMART", r"/^Physical disk \[.*\]: S\.M\.A\.R\.T\. Status$/", SMART_CODES, SMART_STEPS, ()),
    ("Bat. RAID", r"/^Battery \[.*\]: Status$/", BATTERY_CODES, BATTERY_STEPS, BATTERY_WORSE),
    ("Baterias", r"/^System battery \[.*\]: Status$/", OBJECT_CODES, OBJECT_STEPS, ()),
    ("Rede", r"/^NIC \[.*\]: Status$/", OBJECT_CODES, OBJECT_STEPS, ()),
    # reachability last: when it is down the KPI "disponibilidade" already says so
    ("SNMP", r"/^SNMP agent availability$/", AVAIL_CODES, S.AVAIL_STEPS, ()),
]


def promoted_codes(codes, worse):
    """The value map codes plus the shifted copies of the `worse` ranges (same text and colour)."""
    out = dict(codes)
    for lo, hi in worse:
        for c in range(lo, hi + 1):
            out[str(c + PROMOTE)] = codes[str(c)]
    return out


def promoted_steps(steps, worse):
    return steps + [{"color": S.CRIT, "value": min(lo for lo, _ in worse) + PROMOTE}] if worse else steps


def fold(codes, worse):
    """What the matrix shows for one host whose items report `codes` (pure-Python mirror of the backend
    queries + the max() fold, for tests): the worst state's code."""
    shifted = [c + PROMOTE if any(lo <= c <= hi for lo, hi in worse) else 0 for c in codes]
    return max(list(codes) + (shifted if worse else []))


def status_targets(item, column, worse, ref_start):
    """The column's query plus one query per `worse` range: only those codes, shifted by PROMOTE, every
    other value turned into 0 (backend functions, so the browser fold stays a plain max)."""
    targets = [matrix_target(item, column, ref=S._ref(ref_start))]
    for n, (lo, hi) in enumerate(worse, start=1):
        targets.append(matrix_target(item, column, remove_below(lo), S.remove_above(hi), offset(PROMOTE),
                                     transform_null(0), ref=S._ref(ref_start + n)))
    return targets


def _status_column(name, codes, steps, worse):
    """Matrix cell: deep fill tile with the PT-BR state; a dash where the server has no such component."""
    mappings = S.value_map(promoted_codes(codes, worse))
    return [S.col_props(name, mappings=calm(S.as_fill(mappings)) + S.no_data_map("—", S.FILL_UNKNOWN),
                        thresholds={"mode": "absolute", "steps": calm(S.as_fill(promoted_steps(steps, worse)))},
                        color={"mode": "thresholds"}, noValue="—", **{"custom.align": "center"}),
            S.col_color(name, gradient=False)]


def worst_first(*keys, host_title="Servidor"):
    """Chained stable sorts, least significant key first: the host name, then each (field, desc) key in
    reverse order of importance, so the first key decides."""
    return [S.sort_by(host_title, desc=False)] + [S.sort_by(f, desc=d) for f, d in reversed(keys)]


def _matrix():
    targets = []
    for name, item, _, _, worse in COMPONENTS:
        targets += status_targets(item, name, worse, len(targets))
    columns = [host_column("Servidor", 150, host_link(KEY))]
    for name, _, codes, steps, worse in COMPONENTS:
        columns += _status_column(name, codes, steps, worse)
    # Worst first, like the servers matrix: SNMP offline, then overall health, then the probes (codes grow
    # with severity; promoted critical probe codes are the highest)
    order = worst_first(("SNMP", False), ("Geral", True), ("Sensores", True))
    p = S.table("MATRIZ DE SAÚDE DOS COMPONENTES", targets, id=MATRIX_ID, columns=columns, cell_height="sm",
                time_from=IDRAC_WINDOW, mdp=30,
                transformations=matrix_transforms([c[0] for c in COMPONENTS]) + order,
                description="Pior estado de cada componente por iDRAC, piores primeiro (últimas 24h: o iDRAC "
                            "só grava mudanças, com um valor a cada 6h). \"—\" = componente não exposto pelo "
                            "modelo. Ctrl. = controladora RAID; Bat. RAID = bateria da controladora. Clique no "
                            "nome para filtrar a dashboard por ele.")
    # Grafana's default 150px minimum would push the last columns out of view: 15 columns fit 1440px
    p["fieldConfig"]["defaults"]["custom"]["minWidth"] = 72
    p["fieldConfig"]["defaults"]["noValue"] = NO_DATA      # empty-table message (each cell has its "—")
    return p


def _worst(column, title, all_ok, description):
    """KPI: worst state of one matrix column over all servers, as PT-BR text on a neon value, with the
    worst server as its name (like CPU MÁX.). When that worst state is OK the max() row is an arbitrary
    host, so a "Fields with values" override names the whole set instead (`all_ok`)."""
    codes, steps, worse = next((c, s, w) for name, _, c, s, w in COMPONENTS if name == column)
    p = from_matrix(column, "max", named=True, title=title, steps=promoted_steps(steps, worse),
                    mappings=S.value_map(promoted_codes(codes, worse)), value_size=32, description=description)
    p["fieldConfig"]["overrides"].append(
        {"matcher": {"id": "byValue", "options": {"reducer": "lastNotNull", "op": "eq", "value": OK_CODE}},
         "properties": [{"id": "displayName", "value": all_ok}]})
    return p


def _temps_table():
    """Temperatures per server, one row per iDRAC like the health matrix (worst first): the worst probe
    status, then inlet, hottest CPU socket and exhaust as plain right-aligned numbers. Gauges here were
    always the same cyan (no meaning) and overflowed the panel; only the inlet text is tinted (TEMP_INLET)."""
    cols = [("Entrada", INLET_RE), ("CPU", CPU_TEMP_RE), ("Saída", EXHAUST_RE)]
    targets = status_targets(TEMP_STATUS_RE, "Estado", PROBE_WORSE, 0)
    targets += [matrix_target(item, name, ref=S._ref(len(targets) + n)) for n, (name, item) in enumerate(cols)]
    columns = [host_column("Servidor", 130, host_link(KEY)),
               *_status_column("Estado", PROBE_CODES, PROBE_STEPS, PROBE_WORSE), S.col_width("Estado", 90)]
    for name, _ in cols:
        # no such probe (e.g. no exhaust sensor on the R250): a grey dash
        color = ({"thresholds": {"mode": "absolute", "steps": INLET_STEPS}, "color": {"mode": "thresholds"}}
                 if name == "Entrada" else {"color": {"mode": "fixed", "fixedColor": S.TEXT}})
        columns += [S.col_props(name, unit="celsius", decimals=0, noValue="—", mappings=S.no_data_map("—"),
                                **color, **{"custom.align": "right"}),
                    S.col_color(name, mode="text")]
    p = S.table("TEMPERATURAS POR SERVIDOR", targets, id=TEMPS_ID, columns=columns, cell_height="sm",
                time_from=IDRAC_WINDOW, mdp=30,
                transformations=matrix_transforms(["Estado", *(c[0] for c in cols)])
                + worst_first(("Estado", True)),
                description="Estado = pior status dos sensores de temperatura do iDRAC (limites do próprio "
                            "servidor). Última leitura da entrada de ar (refrigeração da sala: âmbar a partir "
                            "de 27 °C, vermelho de 32 °C), do processador mais quente e da saída de ar.")
    # three "28 °C" columns need ~56px: Grafana's 150px default minimum pushed CPU and Saída out of view
    # (130 + 90 + 3 x 56 also fits the 7-wide panel at 1440 px)
    p["fieldConfig"]["defaults"]["custom"]["minWidth"] = 56
    # Grafana's empty-table message is the defaults' noValue (English "No data" otherwise); every column
    # has its own "—" for a single missing value
    p["fieldConfig"]["defaults"]["noValue"] = NO_DATA
    return p


def _fans_table():
    """Fans per server: count, slowest and fastest current speed (folded in the browser)."""
    label = '{"h": "$__zbx_host_name"}'
    t = S.target(FAN_RE, S.alias(label))
    rpm = dict(unit="rotrpm", decimals=0, min=0, max=8000, thresholds={"mode": "absolute", "steps": RPM_STEPS},
               color={"mode": "thresholds"})
    # Only the slowest fan gets a gauge (a stopped or slow fan is the signal); the fastest is a plain
    # number: two gauges overflowed the panel and cut "4440 rpm" to a misleading "44"
    columns = [host_column("Servidor", 130, host_link(KEY)),
               S.col_props("Qtd.", **{"custom.width": 50, "custom.align": "center"}),
               S.col_props("Mínima", **rpm), S.col_gauge("Mínima", mode="basic"),
               S.col_props("Máxima", unit="rotrpm", decimals=0, color={"mode": "fixed", "fixedColor": S.TEXT},
                           **{"custom.width": 90, "custom.align": "right"}),
               S.col_color("Máxima", mode="text")]
    last = S.CALC_NAMES["lastNotNull"]
    tfs = [S.reduce_rows(),
           S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
           S.tf("groupBy", fields={"h": {"operation": "groupby", "aggregations": []},
                                   last: {"operation": "aggregate", "aggregations": ["count", "min", "max"]}}),
           S.organize(rename={"h": "Servidor", f"{last} (count)": "Qtd.", f"{last} (min)": "Mínima",
                              f"{last} (max)": "Máxima"})]
    p = S.table("VENTOINHAS POR SERVIDOR", [t], columns=columns, cell_height="sm", transformations=tfs,
                sort_by=[("Mínima", False)], time_from=FAN_WINDOW, mdp=10,
                description="Rotação atual das ventoinhas de cada servidor (últimos 15 minutos), a mais lenta "
                            "primeiro. 0 rpm = parada (vermelho); abaixo de 1500 rpm (âmbar) costuma indicar "
                            "falha.")
    # Grafana's empty-table message is the defaults' noValue (English "No data" otherwise); every column
    # has its own "—" for a single missing value
    p["fieldConfig"]["defaults"]["noValue"] = NO_DATA
    return p


def _fans_detail():
    """Every fan, slowest first: a failing fan stands out at the top (sortable and filterable)."""
    label = '{"h": "$__zbx_host_name", "f": "$__zbx_item"}'
    t = S.target(FAN_RE, S.alias(label), S.replace_alias(r"/Fan \[(System Board )?(.*)\]: Speed/", "$2"))
    last = S.CALC_NAMES["lastNotNull"]
    tfs = [S.reduce_rows(),
           S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
           S.organize(rename={"h": "Servidor", "f": "Ventoinha", last: "Rotação"}, exclude=["Field"],
                      order=["h", "f", last])]
    columns = [host_column("Servidor", 220, host_link(KEY)), S.col_props("Ventoinha", **{"custom.width": 160}),
               S.col_props("Rotação", unit="rotrpm", decimals=0, min=0, max=8000,
                           thresholds={"mode": "absolute", "steps": RPM_STEPS}, color={"mode": "thresholds"}),
               S.col_gauge("Rotação", mode="basic")]
    return S.table("TODAS AS VENTOINHAS · MAIS LENTAS PRIMEIRO", [t], columns=columns, cell_height="sm",
                   transformations=tfs, sort_by=[("Rotação", False)], filterable=True, time_from=FAN_WINDOW,
                   mdp=10, description="Rotação atual de cada ventoinha (últimos 15 minutos), da mais lenta para "
                                       "a mais rápida. 0 rpm vermelho, abaixo de 1500 rpm âmbar.")


STEP_NOTE = (" O iDRAC só grava mudanças: a linha mantém o último valor até a próxima leitura diferente, e "
             "uma linha que termina antes do fim = valor inalterado desde então (não é sensor parado).")


def _temps_ts(title, item, description, **kw):
    """Temperature history, one step line per server (legend sorted by the current reading)."""
    p = S.timeseries(title, [S.target(item, S.alias("$__zbx_host_name"))], unit="celsius", fill=0, mdp=300,
                     sort_by="Last *", no_value=NO_DATA, description=description + STEP_NOTE,
                     **kw)
    # unchanged readings are not stored: bridge every gap and draw steps, a smooth curve would invent values
    p["fieldConfig"]["defaults"]["custom"].update(spanNulls=True, lineInterpolation="stepAfter")
    return p


def _inlet_ts():
    """Inlets: each line cyan while below 27 °C and amber / red past the TEMP_INLET limits (colour by
    value), with the limits as dashed lines: the hot server stands out without hovering."""
    p = _temps_ts("ENTRADA DE AR · NO PERÍODO", INLET_RE,
                  "Temperatura do ar que entra em cada servidor (refrigeração da sala). Linhas tracejadas = "
                  "limites de 27 °C (âmbar) e 32 °C (vermelho); a linha muda de cor ao passar deles.",
                  steps=INLET_STEPS, color={"mode": "thresholds"}, thresholds_style="dashed", axis_soft_min=15)
    p["fieldConfig"]["defaults"]["custom"].update(gradientMode="scheme", axisSoftMax=34)
    return p


def _exhaust_ts():
    """Exhausts: shades of violet, 1px (four step lines in a 43-45 °C band blurred into a barcode)."""
    return _temps_ts("SAÍDA DE AR · NO PERÍODO", EXHAUST_RE,
                     "Temperatura do ar que sai de cada servidor (carga + refrigeração). Só nos modelos com "
                     "sensor de saída.", color={"mode": "shades", "fixedColor": S.ACCENT_2}, line_width=1)


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)
    group_re = cat["group"]

    # short titles: the 3-wide tiles truncated "DISPONIBILIDADE" / "SAÚDE GERAL" at 1440 px
    banner = S.banner("HARDWARE", "Infra · Dell iDRAC")
    online = availability_kpi("ONLINE", "iDRAC", "iDRACs", "Disponibilidade: iDRACs que respondem ao SNMP agora "
                                                          "sobre os monitorados.")
    overall = _worst("Geral", "SAÚDE", "todos os servidores",
                     "Pior estado geral (Overall system health) entre os servidores, com o servidor afetado.")
    psu = _worst("Fontes", "FONTES", "todas as fontes",
                 "Pior estado entre todas as fontes de alimentação, com o servidor afetado.")
    disks = _worst("Discos", "DISCOS", "todos os discos",
                   "Pior estado entre todos os discos físicos, com o servidor afetado.")
    # worst temperature status (the iDRAC's thresholds), with the hottest inlet as its name
    temp = from_matrix("Estado", "max", panel_id=TEMPS_ID, title="TEMPERATURA", steps=promoted_steps(
                           PROBE_STEPS, PROBE_WORSE), mappings=S.value_map(promoted_codes(PROBE_CODES, PROBE_WORSE)),
                       value_size=32,
                       description="Pior status dos sensores de temperatura do iDRAC (limites do próprio "
                                   "servidor), com a maior temperatura de entrada de ar.")
    temp["transformations"] = [S.filter_fields("^(Estado|Entrada)$"), S.reduce_fields(("max",)),
                               S.as_text("Entrada")]
    # Entrada is text by then, formatted with the panel's status map: "25" is a promoted probe code
    # (CRÍTICO). An empty override list does not clear the default mappings, a one-entry list does.
    temp["fieldConfig"]["overrides"] += [S.col_props("Estado", displayName="entrada máx ${__data.fields.Entrada} °C"),
                                         S.col_props("Entrada", mappings=S.no_data_map("—"))]
    temp["options"].update(textMode="value_and_name", wideLayout=False)
    temp["options"]["reduceOptions"]["values"] = True
    temp["options"]["text"]["titleSize"] = 14
    cpu_max = from_matrix("CPU", "max", named=True, panel_id=TEMPS_ID, title="CPU MÁX.",
                          unit=CELSIUS_TIGHT, steps=S.NEUTRAL,
                          description="Processador mais quente agora e o seu servidor. O estado (limites do "
                                      "iDRAC) está no quadro TEMP.")

    feed = problems_feed(FEED_ROWS, name_px=260)

    panels = S.grid(
        (4, [(banner, 6), (online, 3), (overall, 3), (psu, 3), (disks, 3), (temp, 3), (cpu_max, 3)]),
        # h9 = header + 7 iDRACs at cell height sm (h8 hid the 7th behind a scroll)
        (9, [(_matrix(), 24)]),
        (8, [(_temps_table(), 7), (_fans_table(), 8), (feed, 9)]),
        (9, [(_inlet_ts(), 12), (_exhaust_ts(), 12)]),
        S.row("Detalhe: todas as ventoinhas", collapsed=True, children=[(14, [(_fans_detail(), 24)])]),
    )
    return S.dashboard(KEY, TITLE, panels, datasource_uid=datasource_uid, range_cap="7d", time_from="now-1d",
                       variables=S.category_variables(group_re),
                       description="Saúde do hardware dos servidores Dell pelo iDRAC: componentes, fontes, "
                                   "discos, temperaturas e ventoinhas.")
