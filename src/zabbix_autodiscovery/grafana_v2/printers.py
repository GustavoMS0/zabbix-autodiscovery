"""Impressoras: desktop analysis dashboard (1920 wide, scrolling is fine).

Layout:
  y0   h4   banner | online | offline | suprimentos < 10% | páginas 7 dias | problemas por severidade
  y4   h8   estado de cada impressora, full width, 2 rows of 9 (ping + hrDeviceStatus, the worst wins)
  row  SUPRIMENTOS: toner e tinta, lowest first | peças de manutenção + problemas ativos
  row  PRODUÇÃO: páginas por dia (all printers, today in a paler cyan) | ranking de páginas nos mesmos 7 dias
  row  REDE: disponibilidade no período (timeline, same host order as the tiles) | latência ICMP (10 piores)

Item names come from the "AutoDiscovery - Printer by SNMP" template (verified on the 17 SNMP printers;
NXE3841CF only has ICMP Ping, so its tile shows the ping alone).

Supplies: "Level %" is a calculated item, 100*last(level)/last(max), recomputed every 30 min even when
the printer is off, so its clock is always fresh and it kept showing the last reading of an offline
printer as current. Freshness is therefore judged by the raw SNMP "Level" item (polled every 30 min, no
"discard unchanged"): a supply is drawn only when both arrived in the 3h window. Level % is unsupported
when the printer reports -2/-3 (unknown / "some left"), so those supplies drop out too instead of a false 0%.

Missing data never reads as healthy: KPIs map null to a grey "SEM DADOS" (S.no_data_map). Numbers use no
"locale" thousands separator ("3134", not "3.134"): across the v2 suite a dot is always a decimal.
"""
import json

from . import style as S

KEY = "printers"
TITLE = "Impressoras"
DEFAULT_GROUP = "/^(Rede\\/Impressoras)$/"

HEALTH_ID = 10          # KPI source (health pipeline); the offline tile reuses its data
PAGES_DAY_ID = 13       # pages per day; the "páginas 7D" tile reuses its data (same 7 days as the chart)
SUPPLY_ID = 20          # toner/tinta ranking

PAGES_RE = r"/^Printer: Total page count$/"
DEVICE_RE = r"/^Printer: Device status$/"
# Toner/ink cartridges vs. maintenance parts (fuser, rollers, drum): parts wear slowly and are replaced by
# the technician, cartridges by the user, so they are ranked separately.
_CONSUMABLE = r"\[.*(toner|ink|cartridge|tinta).*\]"
_PART = r"\[(?!.*(toner|ink|cartridge|tinta)).*\]"
CONSUMABLE_RE = rf"/^Supply {_CONSUMABLE}: Level %$/i"
PARTS_RE = rf"/^Supply {_PART}: Level %$/i"
# raw SNMP level of the same supplies: only its clock is used (freshness), the value comes from Level %
CONSUMABLE_RAW_RE = rf"/^Supply {_CONSUMABLE}: Level$/i"
PARTS_RAW_RE = rf"/^Supply {_PART}: Level$/i"
SUPPLY_WINDOW = "3h"    # supplies are polled every 30 min
STATE_WINDOW = "3h"     # device status every 5 min, but printers in sleep mode answer only now and then
PAGES_WINDOW = "7d"     # page counters every 1h; the oldest UTC day in the window is partial and dropped
PAGES_DAYS = 7
TODAY_COLOR = "#1E899B"     # the day in progress: S.ACCENT blended 60% over the #181b1f panel
# Same limits as the template triggers: below 10% "Atenção", below 3% "Alta". Amber up to 25% gives a
# week or two of notice to buy the cartridge.
SUPPLY_STEPS = S.steps(S.CRIT, (10, S.WARN), (25, S.OK))
# Printers whose supply level is meaningless: they report 0% for every non-genuine cartridge, so the team
# disabled their supply triggers in Zabbix (host macros {$PRINTER.SUPPLY.WARN}/{$PRINTER.SUPPLY.HIGH} = -1).
# The bar list leaves them out; the KPI counts Zabbix's supply triggers, which already respect the macros.
UNMEASURED_SUPPLY_HOSTS = ("HP5FFB5E", "HPA9D24F")
# Empty KPI (no data for the selection): a grey dash, as in servers.py. "SEM DADOS" at the 52 px KPI size
# wrapped onto two lines and overflowed the w3 tiles; a green "No data" read as healthy.
NO_DATA_KPI = S.no_data_map("—")

# One state per printer, worst first: OFFLINE (no ping) > PARADA > EM TESTE > ALERTA > ONLINE. Both items
# are turned into a score on the Zabbix side (scale/offset) so a plain max() per host picks the worst:
# ping 1/0 -> 0/40; hrDeviceStatus 1..5 -> (status - 2) x 10 = -10 unknown, 0 running, 10 warning,
# 20 testing, 30 down.
STATE_MAP = S.value_map({"40": ("OFFLINE", S.CRIT), "30": ("PARADA", S.CRIT), "20": ("EM TESTE", S.INFO),
                         "10": ("ALERTA", S.WARN), "0": ("ONLINE", S.OK), "-10": ("DESCONHECIDO", S.UNKNOWN)})
STATE_STEPS = S.steps(S.UNKNOWN, (0, S.OK), (10, S.WARN), (20, S.INFO), (30, S.CRIT))

# Supply names as the printers report them ("Black Cartridge HP CE505X", "cyan ink unknown",
# "Black Toner Cartridge S/N:CRUM-...", "Tray 1 Retard Roller") -> short PT-BR labels that fit the name
# column at 1440 px ("CE505X (preto)", "T11A2 (ciano)", "Retardo bandeja 1"): the panel title already says
# toner/tinta, so the type word goes when a model code follows. replaceAlias runs in the browser, in this
# order, on "<host> · <item name>" (Level % and raw Level alike).
SUPPLY_LABEL = [
    (r"/Supply \[\s*(.*?)\s*\]: Level( %)?/", "$1"),
    (r"/\s*S\/N:\S+/", ""),
    (r"/\s+unknown\b/i", ""),
    (r"/\b(black|cyan|magenta|yellow)\s+(.+)$/i", "$2 ($1)"),
    (r"/toner cartridge/i", "Toner"),
    (r"/cartridge( HP)?/i", "Toner"),           # HP LaserJet "Black Cartridge HP CE505X": a toner
    (r"/ink supply unit|\bink\b/i", "Tinta"),
    (r"/(Toner|Tinta) (?=[A-Z0-9])/", ""),       # "Toner CE505X" -> "CE505X"; Brother "Toner (preto)" stays
    (r"/\/\S+/", ""),                            # Epson "T11A1/T11B1": first code is enough
    (r"/\(black\)/i", "(preto)"),
    (r"/\(cyan\)/i", "(ciano)"),
    (r"/\(magenta\)/i", "(magenta)"),
    (r"/\(yellow\)/i", "(amarelo)"),
    (r"/Drum Unit/i", "Cilindro"),
    (r"/Fuser/i", "Fusor"),
    (r"/Transfer Roller/i", "Transferência"),
    (r"/(MP|Tray \d+) Retard Roller/i", "Retardo $1"),
    (r"/(MP|Tray \d+) Roller/i", "Rolo $1"),
    (r"/Tray (\d+)/i", "bandeja $1"),
]


def _fn_scale(factor):
    return S._fn("scale", "Transform", [factor], [{"name": "factor", "type": "float"}], [100])


def _fn_offset(delta):
    return S._fn("offset", "Transform", [delta], [{"name": "delta", "type": "float"}], [0])


def _supply_target(item_re, column, ref):
    """Supply series named "<host> · <short label> #<column>" (column: pct = Level %, raw = SNMP level)."""
    fns = [S.alias("$__zbx_host_name · $__zbx_item")] + [S.replace_alias(r, n) for r, n in SUPPLY_LABEL]
    return S.target(item_re, *fns, S.replace_alias("/^(.*)$/", f"$1 #{column}"), ref=ref)


def _not_null(*fields):
    return S.tf("filterByValue", type="include", match="all",
                filters=[{"fieldName": f, "config": {"id": "isNotNull", "options": {}}} for f in fields])


def _lowest_first(title, pct_re, raw_re, *, panel_id=None, bar_height=22, exclude_hosts=(), description=None):
    """Supply levels as bars, the emptiest first (the opposite of S.bargauge(rank=True), which puts the
    highest value on top). Basic mode on a neutral track: only the filled part is coloured, so colour
    means "this one is low" (LCD mode tinted every unlit cell by its zone: a rainbow on every row).
    Level % and the raw level are pivoted side by side (supply x pct/raw) and a row needs both: a supply
    whose raw level stopped arriving (printer offline) is dropped instead of shown stale."""
    tfs = [S.reduce_rows(("lastNotNull",)),
           S.tf("extractFields", source="Field", format="regexp", regExp="/^(?<k>.+) #(?<m>pct|raw)$/",
                replace=False, keepTime=False),
           S.tf("groupingToMatrix", columnField="m", rowField="k", valueField=S.CALC_NAMES["lastNotNull"],
                emptyValue="null"),
           _not_null("pct", "raw")]
    if exclude_hosts:
        hosts = "|".join(exclude_hosts)
        tfs.append(S.tf("filterByValue", type="exclude", match="any",
                        filters=[{"fieldName": "k\\m",
                                  "config": {"id": "regex", "options": {"value": f"^({hosts}) · "}}}]))
    # one string field (the name) and one number (pct): each row becomes a bar named after the supply
    tfs += [S.sort_by("pct", desc=False), S.organize(rename={"k\\m": "Suprimento"}, exclude=["raw"])]
    # min -3: an empty (0%) cartridge, the worst state, still shows a red stub instead of nothing
    p = S.bargauge(title, [_supply_target(pct_re, "pct", "A"), _supply_target(raw_re, "raw", "B")],
                   id=panel_id, steps=SUPPLY_STEPS, unit="percent", min=-3, decimals=0, mode="basic",
                   bar_height=bar_height, name_placement="left", value_size=15,
                   time_from=SUPPLY_WINDOW, mdp=10, description=description,
                   mappings=S.no_data_map(), transformations=tfs)
    p["options"]["reduceOptions"] = {"values": True, "calcs": ["lastNotNull"], "fields": "/^pct$/"}
    return p


def _health_kpi(title, field, *, steps, panel_id=None, source=False, name=None, description=None):
    """Online / offline printer counts from the shared health pipeline (each printer counts once, by its
    best check: ICMP ping or SNMP availability). source=True: this tile runs the Zabbix query, the other
    reads its raw data through the Dashboard datasource."""
    if source:
        targets = S.health_targets([{"name": TITLE, "group": "$group"}])
        for t in targets:           # health_targets takes every host of the group: follow $host too
            t["host"]["filter"] = "$host"
        ds = None
    else:
        targets = [S.dashboard_target(HEALTH_ID, with_transforms=False)]
        ds = dict(S.DASHBOARD_DS)
    keep = S.filter_fields(f"^({field}|Total)$" if name else f"^{field}$")
    p = S.kpi(title, targets, id=panel_id, datasource=ds, description=description, mappings=NO_DATA_KPI,
              transformations=[*S.health_transforms(), keep, *([S.as_text("Total")] if name else [])],
              steps=steps, decimals=0, value_size=52, values=bool(name),
              time_from=S.HEALTH_WINDOW if source else None, mdp=20 if source else None,
              overrides=[S.col_props(field, displayName=name)] if name else None)
    if name:
        p["options"].update(textMode="value_and_name", wideLayout=False)
        p["options"]["text"]["titleSize"] = 14
    return p


def _state_tiles():
    """One tile per printer: ICMP ping and hrDeviceStatus folded into one state (STATE_MAP), worst wins.
    The host travels in a JSON alias because the frontend transforms only see the alias."""
    label = S.alias(json.dumps({"host": "$__zbx_host_name"}))
    # Grafana wraps tile names at "-" (GEQ10- / IMPDIR); a non-breaking hyphen keeps one line
    nbhyphen = S.replace_alias("/-/g", "‑")
    targets = [S.target("ICMP ping", _fn_scale(-40), _fn_offset(40), label, nbhyphen, ref="A"),
               S.target(DEVICE_RE, _fn_offset(-2), _fn_scale(10), label, nbhyphen, ref="B")]
    worst = f"{S.CALC_NAMES['lastNotNull']} (max)"
    return S.status_grid(
        "ESTADO DAS IMPRESSORAS", targets, mappings=STATE_MAP + S.no_data_map(color=S.UNKNOWN),
        steps=STATE_STEPS, values=True, min_width=130, min_height=60, title_size=13, value_size=18,
        # mdp 60: one point per 3 min bucket at most (status every 5 min). With 20 the browser averaged a
        # running (0) and a warning (10) reading of one bucket into an unmapped "5" tile.
        time_from=STATE_WINDOW, mdp=60,
        transformations=[
            S.reduce_rows(("lastNotNull",)),
            S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
            S.tf("groupBy", fields={"host": {"operation": "groupby", "aggregations": []},
                                    S.CALC_NAMES["lastNotNull"]: {"operation": "aggregate",
                                                                  "aggregations": ["max"]}}),
            S.sort_by("host", desc=False)],
        overrides=[S.col_props(worst, displayName="${__data.fields.host}")],
        description="Uma tile por impressora, no pior estado entre o ping ICMP e o hrDeviceStatus: OFFLINE "
                    "(sem ping) > PARADA > EM TESTE > ALERTA (papel, tampa, suprimento...) > ONLINE. "
                    "Última leitura das últimas 3 horas.")


def build(cfg, datasource_uid="zabbix"):
    cat = next((c for c in S.categories(cfg) if c["key"] == KEY), None)
    group_re = cat["group"] if cat else DEFAULT_GROUP

    # --- KPI strip ---------------------------------------------------------------------------------
    banner = S.banner("IMPRESSORAS", "Rede · impressão")
    online = _health_kpi("ONLINE", "Online", steps=S.steps(S.OK), panel_id=HEALTH_ID, source=True,
                         name="de ${__data.fields.Total} impressoras",
                         description="Impressoras que respondem agora (ping ICMP ou SNMP).")
    offline = _health_kpi("OFFLINE", "Offline", steps=S.COUNT_BAD, name="de ${__data.fields.Total} impressoras",
                          description="Impressoras sem resposta de ping nem de SNMP.")
    # Zabbix's own judgement: supply triggers in problem (tag component=supply). They honour the per-host
    # macros (printers whose readings are ignored) and "below 10%" depends on "below 3%", so each supply
    # counts once. Same numbers as the problems feed and the severity counters.
    supply_trg = S.triggers_target(group="$group", host="$host", min_severity=0)
    supply_trg["tags"]["filter"] = "component:supply"
    low = S.kpi("SUPRIMENTOS < 10%", [supply_trg],
                transformations=[S.reduce_fields(("sum",)),
                                 S.tf("calculateField", mode="reduceRow", alias="Suprimentos", replaceFields=True,
                                      reduce={"reducer": "sum", "include": list(S.SEVERITY_FIELDS.values())})],
                steps=S.steps(S.OK, (1, S.CRIT)), decimals=0, value_size=52, no_value="0", time_from=None,
                mdp=None, description="Toner, tinta e peças abaixo de 10%, contados pelos triggers de "
                                      "suprimento do Zabbix em problema agora. Impressoras com a medição "
                                      "desligada no Zabbix (cartuchos não originais) não contam.")
    pages = S.kpi("PÁGINAS · 7 DIAS", [S.dashboard_target(PAGES_DAY_ID)], datasource=dict(S.DASHBOARD_DS),
                  transformations=[S.filter_fields(r"^(Dias|Hoje \(parcial\))$"), S.reduce_fields(("sum",)),
                                   S.tf("calculateField", mode="reduceRow", alias="Páginas", replaceFields=True,
                                        reduce={"reducer": "sum"})],
                  steps=S.NEUTRAL, mappings=NO_DATA_KPI,
                  unit="none", decimals=0, value_size=52, time_from=None, mdp=None,
                  description="Páginas impressas por todas as impressoras nos 7 dias do gráfico PÁGINAS POR DIA "
                              "(dias UTC, hoje parcial).")
    severities = S.stat("PROBLEMAS ATIVOS POR SEVERIDADE",
                        [S.triggers_target(group="$group", host="$host", min_severity=2)],
                        transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
                        text_mode="value_and_name", color_mode="value", value_size=40, title_size=12,
                        steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None, mappings=NO_DATA_KPI,
                        description="Triggers em problema agora nas impressoras, por severidade.")

    # --- supplies ---------------------------------------------------------------------------------
    excluded = " e ".join(UNMEASURED_SUPPLY_HOSTS)
    consumables = _lowest_first(
        "TONER E TINTA · MENOR NÍVEL PRIMEIRO", CONSUMABLE_RE, CONSUMABLE_RAW_RE, panel_id=SUPPLY_ID,
        exclude_hosts=UNMEASURED_SUPPLY_HOSTS,
        description="Nível de cada cartucho em %, do mais vazio ao mais cheio. Vermelho abaixo de 10%, âmbar "
                    "abaixo de 25%. Só entram leituras novas (últimas 3 horas): uma impressora desligada sai "
                    "da lista em vez de repetir o último nível. Cartuchos que a impressora não mede (nível "
                    "-2/-3 no SNMP) não aparecem. "
                    f"{excluded} ficam de fora: com cartuchos não originais informam 0% em tudo, e a medição "
                    "foi desligada no Zabbix (macro {$PRINTER.SUPPLY.WARN} = -1).")
    parts = _lowest_first(
        "PEÇAS DE MANUTENÇÃO", PARTS_RE, PARTS_RAW_RE, bar_height=20, exclude_hosts=UNMEASURED_SUPPLY_HOSTS,
        description="Vida útil restante de fusor, rolos e cilindro, em %. Só leituras das últimas 3 horas: "
                    "uma impressora desligada sai da lista.")
    feed = S.problems("PROBLEMAS ATIVOS", [S.problems_target(group="$group", host="$host", min_severity=1)],
                      page_size=5, font_size="100%", layout="table", age=False)
    # short "since" column and no age column: the problem text gets the width
    feed["options"].update(customLastChangeFormat=True, lastChangeFormat="DD/MM HH:mm")

    # --- production -------------------------------------------------------------------------------
    # core bar chart, not a time series: one labelled bar per day ("13/10") with its value on top.
    # groupBy(1d) buckets start at 00:00 UTC, which the browser shows as 21:00 of the day before: each bar
    # is labelled with bucket + 12 h (its UTC date) and the last 7 buckets are kept (the oldest one in the
    # window is cut by it).
    last_days = [S.sort_by("Time", desc=True), S.tf("limit", limitField=PAGES_DAYS), S.sort_by("Time", desc=False)]
    # Today (the last bar) is still in progress, so it goes to its own paler, stacked field. The bar chart
    # ignores colorByField here and transforms have no "if" (nor a working modulo/power): with the row
    # index k = 1..7, floor(k / 7) is 1 on the 7th row and 0 on the others.
    # The empty half of each stack (Hoje on the full days, Dias today) must not print "0", but a real
    # zero day (a Sunday) must. So the full days get +1e-6 pages ("0" once formatted, not the exact 0 the
    # value map blanks) and only exact zeros are hidden.
    today_mask = [
        S.tf("calculateField", mode="index", alias="_i", replaceFields=False, index={"asPercentile": False}),
        S.calc_binary("_i", "+", 1, "_k"), S.calc_binary("_k", "/", PAGES_DAYS, "_q"),
        S.tf("calculateField", mode="unary", alias="_m", replaceFields=False,
             unary={"operator": "floor", "fieldName": "_q"}),
        S.calc_binary("Páginas", "*", "_m", "Hoje (parcial)"),
        S.calc_binary(1, "-", "_m", "_w"), S.calc_binary("_w", "*", 0.000001, "_e"),
        S.calc_binary("Páginas", "-", "Hoje (parcial)", "_d"), S.calc_binary("_d", "+", "_e", "Dias")]
    hide_zero = S.value_map({"0": ("", S.UNKNOWN)})
    per_day = S.panel(
        "barchart", "PÁGINAS IMPRESSAS POR DIA · HOJE EM ANDAMENTO",
        [S.target(PAGES_RE, S.delta(), S.group_by("1d", "sum"), S.alias("$__zbx_host_name"))],
        id=PAGES_DAY_ID, unit="none", decimals=0, min=0, color={"mode": "fixed", "fixedColor": S.ACCENT},
        time_from=PAGES_WINDOW, mdp=200,
        # solid bars: an opacity gradient faded the low bars to the panel colour and they read as empty
        custom={"fillOpacity": 90, "gradientMode": "none", "lineWidth": 0, "axisSoftMin": 0,
                "axisBorderShow": False, "axisPlacement": "auto", "axisLabel": "",
                "hideFrom": {"legend": False, "tooltip": False, "viz": False}},
        # per-printer days summed in the browser: the plugin's sumSeries interpolates the empty days of a
        # printer that was switched off (weekend), which inflated 10-12/10 from ~30 to ~230 pages
        transformations=[
            S.tf("joinByField", byField="Time", mode="outer"),
            S.tf("calculateField", mode="reduceRow", alias="Páginas", replaceFields=True,
                 reduce={"reducer": "sum"}),
            S.tf("calculateField", mode="binary", alias="Dia", replaceFields=False,
                 binary={"left": "Time", "operator": "+", "right": str(12 * 3600 * 1000)}),
            *last_days, *today_mask,
            S.organize(exclude=["Time", "Páginas", "_i", "_k", "_q", "_m", "_w", "_e", "_d"],
                       order=["Dia", "Dias", "Hoje (parcial)"])],
        overrides=[S.col_props("Dia", unit="time:DD/MM"),
                   S.col_props("Dias", displayName="Páginas", mappings=hide_zero),
                   # today: a dimmer cyan (ACCENT at ~60% over the panel). FILL_INFO navy vanished on the dark
                   # panel, and the bar chart ignores a per-field fillOpacity override
                   S.col_props("/^Hoje/", by="byRegexp", mappings=hide_zero,
                               color={"mode": "fixed", "fixedColor": TODAY_COLOR})],
        options={"orientation": "vertical", "xField": "Dia", "barWidth": 0.6, "groupWidth": 0.7,
                 "showValue": "always", "stacking": "normal", "xTickLabelRotation": 0, "xTickLabelSpacing": 0,
                 "barRadius": 0.04, "fullHighlight": False, "text": {"valueSize": 16},
                 "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom", "calcs": []},
                 "tooltip": {"mode": "multi", "sort": "none"}},
        description="Páginas impressas por dia (diferença do contador total de páginas), dias em UTC. A última "
                    "barra, mais clara, é hoje: ainda em andamento.")
    # same 7 UTC days as the chart, per printer, so both add up to the same total as the KPI
    # the per-printer frames of the chart, before its transforms: no second Zabbix query
    rank = S.bargauge(
        "PÁGINAS POR IMPRESSORA · 7 DIAS", [S.dashboard_target(PAGES_DAY_ID, with_transforms=False)],
        datasource=dict(S.DASHBOARD_DS),
        unit="none", decimals=0, min=0, max=None, steps=S.steps(S.ACCENT), mode="basic",
        name_placement="left", value_size=14, time_from=None, mdp=None,
        transformations=[*last_days, S.reduce_rows(("sum",)), S.sort_by("Total")],
        description="Páginas de cada impressora nos mesmos 7 dias do gráfico ao lado, maiores primeiro.")
    rank["options"].update(reduceOptions={"values": True, "calcs": ["lastNotNull"], "fields": "/^Total$/"},
                           valueMode="text")

    # --- network ----------------------------------------------------------------------------------
    timeline = S.state_timeline(
        "DISPONIBILIDADE NO PERÍODO",
        # sortSeries: alphabetical host order, the same as the ESTADO tiles (the plugin's order was random)
        [S.target("ICMP ping", S.sort_series("asc"), S.alias("$__zbx_host_name"))],
        mappings=S.AVAIL_MAP, steps=S.AVAIL_STEPS, row_height=0.75, show_value="never", fill=85, mdp=300,
        description="Ping ICMP de cada impressora ao longo do período: faixas vermelhas são quedas. Mesma "
                    "ordem das tiles de ESTADO.")
    timeline["options"]["text"] = {"valueSize": 14}
    # ranked bars like the overview: 8 raw 1-minute lines in shades of cyan were an unreadable hedge
    latency = S.bargauge(
        "LATÊNCIA ICMP · 10 PIORES (MÉDIA NO PERÍODO)",
        [S.target("ICMP response time", S.top(10, "avg"), S.alias("$__zbx_host_name"))],
        calcs=("mean",), rank=True, unit="s", min=0, max=0.15, steps=S.LATENCY_S, mode="gradient",
        bar_height=30, name_placement="left", value_size=16, decimals=1, time_from=None, mdp=300,
        description="Média do tempo de resposta do ping no período selecionado, maiores primeiro. Âmbar a "
                    "partir de 50 ms, vermelho a partir de 150 ms.")

    panels = S.grid(
        # KPI titles longer than ~8 characters need w4 to fit at 1440 px; the severity strip needs w6
        (4, [(banner, 4), (online, 3), (offline, 3), (low, 4), (pages, 4), (severities, 6)]),
        # Grafana's tile grid (squares.ts) takes the larger "square" that fits, then evens out the rows:
        # 24 x 8 gives 2 rows of 9 (~205 px wide at 1920, ~155 at 1440), wide enough for "BRN001BA9F4C5A5"
        # and "OFFLINE". 14 x 8/10 also gave 9 per row (~120 px, names cut); 24 x 6 put all 18 on one row.
        (8, [(_state_tiles(), 24)]),
        S.row("Suprimentos"),
        (15, [(consumables, 12), (S.stack((parts, 6), (feed, 9)), 12)]),
        S.row("Produção"),
        (13, [(per_day, 14), (rank, 10)]),
        S.row("Rede"),
        (12, [(timeline, 14), (latency, 10)]),
    )
    return S.dashboard(KEY, TITLE, panels, datasource_uid=datasource_uid,
                       variables=S.category_variables(group_re), time_from="now-6h", range_cap="2d",
                       description="Impressoras: disponibilidade, estado, suprimentos e páginas impressas.")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.printers config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
