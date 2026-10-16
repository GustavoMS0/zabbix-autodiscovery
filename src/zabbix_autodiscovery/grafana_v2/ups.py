"""Nobreaks (UPS): desktop analysis dashboard (1920 wide, scrolling is fine).

Layout:
  y0   h4   banner | conexão SNMP | fonte da saída | bateria | alarmes | ligado há | falhas de rede
  y4   h8   carga da bateria | carga na saída | temperatura da bateria (gauges) | tensões agora |
            potência ativa + autonomia
  row  ENERGIA: tensão de entrada | frequência, 5 min average (nominal bands on the chart)
  row  BATERIA E CARGA: carga na saída % | tensão da bateria | temperatura da bateria (dashed limits)
  row  EVENTOS: histórico de estado (fonte, bateria, alarmes) | problemas ativos (counter) + equipamento

Missing data never reads as healthy: every tile, gauge and counter maps null to a grey "SEM DADOS"
(S.no_data_map), except CONEXÃO, whose empty state is the red "SEM RESPOSTA". Numbers follow one
convention across the v2 suite: a dot is always a decimal separator (no "locale" thousands), so power is
an integer in W ("1648 W") rather than "1.65 kW".

Items: NHS "Prime Online GII - UPS SNMP" template (UPS-MIB, RFC 1628), verified on Nobreak-SP; the v1
regexes for charge, load, runtime and voltages also match the English UPS-MIB templates. Nobreak-SP has
no ICMP ping and no "SNMP agent availability" item, so communication is judged by the freshness of
sysUpTime (polled every 1 min; the template names it "UPS: Disponibilidade (ICMP ping via agente)").
"""
import json

from .. import dashboards as v1
from . import style as S

KEY = "ups"
TITLE = "Nobreaks"
DEFAULT_GROUP = "/^(Infra\\/Nobreaks)$/"


def _v1_re(title):
    """Item regex of a panel of the v1 UPS spec (verified there), by its title."""
    spec = next(s for s in v1.SPECS if s["key"] == KEY)
    return next(p["re"] for p in spec["panels"] if p.get("title") == title)


CHARGE_RE = _v1_re("Battery charge")
LOAD_RE = _v1_re("Output load")
RUNTIME_RE = _v1_re("Remaining runtime")
IN_VOLT_RE = _v1_re("Input voltage")
OUT_VOLT_RE = _v1_re("Output voltage")
TEMP_RE = S.TEMP_RE
BATT_VOLT_RE = r"/^(Bateria: Tens[aã]o|Battery voltage)$/i"
FREQ_RE = r"/^(Entrada|Sa[ií]da): Frequ[eê]ncia$/i"
POWER_RE = r"/^Sa[ií]da: Pot[eê]ncia ativa$/i"
SOURCE_RE = r"/^Sa[ií]da: Fonte/i"
BATT_STATUS_RE = r"/^Bateria: Status$/i"
ALARMS_RE = r"/^Alarmes: Quantidade ativa$/i"
LINEBADS_RE = r"/LineBads/i"
UPTIME_RE = r"/^UPS: (Disponibilidade \(ICMP ping via agente\)|Uptime.*)$/"   # sysUpTime, 1/100 s
COMM_WINDOW = "5m"        # sysUpTime every 1 min: nothing in 5 min = the UPS stopped answering SNMP

# UPS-MIB upsOutputSource / upsBatteryStatus (valuemaps "UPS Output Source" / "UPS Battery Status")
SOURCE_MAP = S.value_map({"1": ("OUTRA", S.UNKNOWN), "2": ("SEM SAÍDA", S.CRIT), "3": ("REDE ELÉTRICA", S.OK),
                          "4": ("BYPASS", S.WARN), "5": ("BATERIA", S.CRIT), "6": ("ELEVANDO TENSÃO", S.WARN),
                          "7": ("REDUZINDO TENSÃO", S.WARN)})
SOURCE_STEPS = S.steps(S.UNKNOWN, (2, S.CRIT), (3, S.OK), (4, S.WARN), (5, S.CRIT), (6, S.WARN))
BATT_MAP = S.value_map({"1": ("DESCONHECIDO", S.UNKNOWN), "2": ("NORMAL", S.OK), "3": ("BAIXA", S.WARN),
                        "4": ("ESGOTADA", S.CRIT)})
BATT_STEPS = S.steps(S.UNKNOWN, (2, S.OK), (3, S.WARN), (4, S.CRIT))
ALARM_MAP = S.value_map({"0": ("SEM ALARMES", S.OK)})
ALARM_TILE_MAP = S.value_map({"0": ("NENHUM", S.OK)})       # the tile title already says ALARMES
ALARM_STEPS = S.steps(S.OK, (1, S.CRIT))

# Nominal bands drawn on the charts. Input: 220 V, ANEEL PRODIST ranges (adequada 202-231 V, precária up to
# 191/233 V). Output: 120 V +-5% (amber up to +-10%). Battery: 144 V bank (12 x 12 V, firmware
# "...-144V"): float charge ~163 V, below 11.5 V/block (138 V) it is discharging, 10.5 V/block (126 V) is
# the end of discharge. Frequency: 60 Hz, PRODIST 59.9-60.1 Hz normal, 59.5-60.5 Hz tolerated.
# The charts paint only the nominal band (green); outside stays the plain panel. Red/amber zones made the
# background read "alarm" even when every value was fine.
_OUT = "transparent"
IN_VOLT_STEPS = S.steps(_OUT, (202, S.OK), (231, _OUT))
OUT_VOLT_STEPS = S.steps(_OUT, (114, S.OK), (126, _OUT))
BATT_VOLT_STEPS = S.steps(_OUT, (138, S.OK), (175, _OUT))
FREQ_STEPS = S.steps(_OUT, (59.9, S.OK), (60.1, _OUT))
# Value colours of TENSÕES AGORA: green in the adequate band, amber in the precarious one, red outside.
IN_VOLT_NOW = S.steps(S.CRIT, (191, S.WARN), (202, S.OK), (231.5, S.WARN), (233.5, S.CRIT))
OUT_VOLT_NOW = S.steps(S.CRIT, (108, S.WARN), (114, S.OK), (126.5, S.WARN), (132.5, S.CRIT))
LOAD_STEPS = S.steps(S.OK, (75, S.WARN), (90, S.CRIT))
# Lead-acid batteries lose about half their life for every ~10 °C above 25 °C; NHS rates operation to 40 °C.
BATT_TEMP_STEPS = S.steps(S.OK, (35, S.WARN), (45, S.CRIT))


def scale(factor):
    """Plugin scale(): multiply every value (sysUpTime hundredths of a second -> days)."""
    return S._fn("scale", "Transform", [factor], [{"name": "factor", "type": "float"}], [100])


def _host(item, *fns, ref="A"):
    return S.target(item, *fns, S.alias("$__zbx_host_name"), ref=ref)


def _tile(title, targets, *, mappings, steps, description, unit=None, decimals=None, time_from=S.STAT_WINDOW,
          no_value=None):
    """Big status tile of the header: deep fill background, value only (host name when several UPS).
    Null -> grey SEM DADOS fill: without it an empty ALARMES tile kept its green base step. Tiles with
    their own empty text (no_value, CONEXÃO) keep it."""
    if no_value is None:
        mappings = mappings + S.no_data_map()
    return S.stat(title, targets, mappings=S.as_fill(mappings), steps=S.as_fill(steps),
                  color_mode="background", text_mode="auto", wide=False, value_size=26, title_size=13,
                  unit=unit, decimals=decimals, time_from=time_from, no_value=no_value, description=description)


def _band_chart(title, targets, *, unit, steps, soft_min, soft_max, description, legend="hidden",
                color=None, decimals=None):
    """Time series with the nominal band painted behind the line (thresholds as area): the line stays
    cyan, the green band shows the expected range."""
    p = S.timeseries(title, targets, unit=unit, steps=steps, thresholds_style="area", legend=legend,
                     color=color or {"mode": "fixed", "fixedColor": S.ACCENT}, fill=10, decimals=decimals,
                     description=description)
    p["fieldConfig"]["defaults"]["custom"].update(axisSoftMin=soft_min, axisSoftMax=soft_max)
    return p


def _text_target(item_re, ref="A"):
    """Text items (model, firmware): text query mode, run by the plugin in the browser."""
    t = S.target(item_re, ref=ref)
    t.update(queryType="2", textFilter="", useCaptureGroups=False)
    return t


def build(cfg, datasource_uid="zabbix"):
    cat = next((c for c in S.categories(cfg) if c["key"] == KEY), None)
    group_re = cat["group"] if cat else DEFAULT_GROUP

    # --- header tiles (short titles: they must fit a 3-column tile at 1440 px too) -------------------
    banner = S.banner("NOBREAKS", "Infra · energia")
    comm = _tile("CONEXÃO", [_host(UPTIME_RE)], time_from=COMM_WINDOW, no_value="SEM RESPOSTA",
                 mappings=[{"type": "range", "options": {"from": 1, "to": 1e15,
                                                         "result": {"text": "ONLINE", "color": S.OK, "index": 0}}}],
                 steps=S.steps(S.CRIT, (1, S.OK)),
                 description="ONLINE quando o nobreak respondeu ao SNMP nos últimos 5 minutos (leitura do "
                             "sysUpTime). Sem resposta, a tile fica vermelha: SEM RESPOSTA. O Nobreak-SP não "
                             "tem item de ping ICMP no Zabbix.")
    source = _tile("FONTE DA SAÍDA", [_host(SOURCE_RE)], mappings=SOURCE_MAP, steps=SOURCE_STEPS,
                   description="De onde vem a energia da saída: REDE ELÉTRICA (normal), BATERIA (queda de "
                               "energia), BYPASS ou correção de tensão.")
    battery = _tile("BATERIA", [_host(BATT_STATUS_RE)], mappings=BATT_MAP, steps=BATT_STEPS,
                    description="Estado da bateria informado pelo nobreak (UPS-MIB upsBatteryStatus).")
    alarms = _tile("ALARMES", [_host(ALARMS_RE)], mappings=ALARM_TILE_MAP, steps=ALARM_STEPS, decimals=0,
                   description="Quantidade de alarmes ativos no nobreak (upsAlarmsPresent). NENHUM = 0.")
    # the plugin puts the item unit ("uptime") in the field config, which beats the panel defaults:
    # set the unit through an override
    # one decimal: 45.88 days rounded to "46 dias" overstated the uptime. Empty: a grey dash ("SEM DADOS"
    # wrapped onto two lines in this w3 tile)
    uptime = S.stat("LIGADO HÁ", [_host(UPTIME_RE, scale(0.01 / 86400))], decimals=1,
                    mappings=S.no_data_map("—"),
                    steps=S.NEUTRAL, value_size=34, title_size=13, time_from=COMM_WINDOW,
                    overrides=[S.col_props("/.*/", by="byRegexp", unit="suffix: dias")],
                    description="Tempo desde o último reinício da placa de rede do nobreak (sysUpTime).")
    linebads = S.stat("FALHAS DE REDE", [_host(LINEBADS_RE)], decimals=0, steps=S.COUNT_BAD, value_size=40,
                      mappings=S.no_data_map(),
                      title_size=13,
                      description="Vezes em que a entrada saiu da tolerância desde o último reinício "
                                  "(upsInputLineBads).")

    # --- gauges and readings now -------------------------------------------------------------------
    charge = S.gauge("CARGA DA BATERIA", [_host(CHARGE_RE)], steps=S.PCT_LOW, value_size=38, title_size=13,
                     mappings=S.no_data_map(),
                     description="Carga estimada restante da bateria.")
    load = S.gauge("CARGA NA SAÍDA", [_host(LOAD_RE)], steps=LOAD_STEPS, value_size=38, title_size=13,
                   mappings=S.no_data_map(),
                   description="Percentual da capacidade do nobreak em uso. Acima de 75% sobra pouca margem.")
    temp = S.gauge("TEMPERATURA DA BATERIA", [_host(TEMP_RE)], unit="celsius", min=0, max=60,
                   steps=BATT_TEMP_STEPS, value_size=38, title_size=13, mappings=S.no_data_map(),
                   description="Acima de 35 °C a vida útil da bateria cai pela metade a cada ~10 °C. O "
                               "fabricante especifica operação até 40 °C.")
    # input and output voltage now, each coloured by its own band; replaces a flat 120 V output chart
    volts = S.stat("TENSÕES AGORA",
                   [S.target(IN_VOLT_RE, S.alias("Entrada"), ref="A"),
                    S.target(OUT_VOLT_RE, S.alias("Saída"), ref="B")],
                   unit="volt", decimals=0, text_mode="value_and_name", orientation="horizontal",
                   justify="auto", value_size=40, title_size=13, wide=True,
                   steps=S.steps(S.UNKNOWN), mappings=S.no_data_map(),
                   overrides=[S.col_props("Entrada", thresholds={"mode": "absolute", "steps": IN_VOLT_NOW}),
                              S.col_props("Saída", thresholds={"mode": "absolute", "steps": OUT_VOLT_NOW})],
                   description="Tensão da rede elétrica e tensão entregue aos equipamentos agora. Verde na faixa "
                               "adequada (entrada 202-231 V, ANEEL PRODIST; saída 120 V ± 5%), âmbar na "
                               "faixa precária, vermelho fora dela.")
    # no sparkline: the 30 s samples drew a jagged area behind the number; the trend is in CARGA NA SAÍDA.
    # Integer watts: "1.66 kW" put a dot where pt-BR readers see a thousands separator, and two decimals of
    # kW were false precision. The item unit beats the panel unit, so it is set by override.
    power = S.kpi("POTÊNCIA ATIVA", [_host(POWER_RE)], decimals=0, steps=S.NEUTRAL, mappings=S.no_data_map(),
                  overrides=[S.col_props("/.*/", by="byRegexp", unit="suffix: W", decimals=0)],
                  value_size=48, title_size=13,
                  description="Potência ativa entregue na saída agora.")
    # small: the Nobreak-SP never reports runtime (the OID is not supported), a big tile would be always grey
    runtime = S.stat("AUTONOMIA", [_host(RUNTIME_RE)], unit="m", decimals=0, value_size=24,
                     title_size=13, text_mode="value",
                     mappings=S.value_map({"0": ("N/D", S.UNKNOWN)}) + S.no_data_map(),
                     steps=S.steps(S.CRIT, (10, S.WARN), (30, S.OK)),
                     description="Minutos de bateria estimados pelo nobreak. N/D: o nobreak não informa (o "
                                 "Nobreak-SP sempre envia 0, o OID não é suportado).")

    # --- energy -----------------------------------------------------------------------------------
    vin = _band_chart("TENSÃO DE ENTRADA", [_host(IN_VOLT_RE)], unit="volt", steps=IN_VOLT_STEPS,
                      soft_min=185, soft_max=240, decimals=0,
                      description="Tensão da rede elétrica. Faixa verde: 202-231 V, a faixa adequada para 220 V "
                                  "(ANEEL PRODIST).")
    # 5 min average: the readings come in 0.05 Hz steps and the raw line was a comb of 59.95/60.00 spikes
    freq = _band_chart("FREQUÊNCIA · MÉDIA 5 MIN",
                       [S.target(FREQ_RE, S.group_by("5m", "avg"), S.alias("$__zbx_item"),
                                 S.replace_alias("/^(Entrada|Sa[ií]da).*$/", "$1"),
                                 S.replace_alias("/Saida/", "Saída"))],
                       unit="hertz", steps=FREQ_STEPS, soft_min=59.6, soft_max=60.4, legend="list",
                       decimals=2,
                       description="Frequência de entrada (linha cheia) e de saída (tracejada). Faixa verde: "
                                   "59,9-60,1 Hz (ANEEL PRODIST). Média de 5 minutos: o nobreak mede em passos "
                                   "de 0,05 Hz.")
    # the two lines nearly coincide: a thick cyan input line under a dashed violet output line keeps both
    # visible (no amber/orange series: amber means WARN on this dashboard)
    freq["fieldConfig"]["overrides"] = [
        S.col_props("Entrada", color={"mode": "fixed", "fixedColor": S.ACCENT}, **{"custom.lineWidth": 4}),
        S.col_props("Saída", color={"mode": "fixed", "fixedColor": S.ACCENT_2},
                    **{"custom.lineWidth": 2, "custom.lineStyle": {"fill": "dash", "dash": [8, 6]}})]

    # --- battery and load -------------------------------------------------------------------------
    # load % only: power (W) is the same quantity scaled by the rating; a second axis suggested two
    # different things and printed misleading kW ticks. The watts are in POTÊNCIA ATIVA.
    load_hist = S.timeseries("CARGA NA SAÍDA · %", [_host(LOAD_RE)], unit="percent", legend="hidden", min=0,
                             max=100, color={"mode": "fixed", "fixedColor": S.ACCENT}, steps=LOAD_STEPS,
                             thresholds_style="dashed", fill=10, decimals=0,
                             description="Carga na saída em % da capacidade do nobreak. Linhas tracejadas: 75% "
                                         "(pouca margem) e 90% (crítico). A potência em W está em POTÊNCIA ATIVA.")
    bvolt = _band_chart("TENSÃO DA BATERIA", [_host(BATT_VOLT_RE)], unit="volt", steps=BATT_VOLT_STEPS,
                        soft_min=120, soft_max=180, decimals=0,
                        description="Banco de 144 V (12 baterias de 12 V). Em flutuação fica perto de 163 V; "
                                    "abaixo de 138 V a bateria está descarregando, 126 V é o fim da descarga.")
    # dashed limit lines, the same style as CARGA NA SAÍDA in this row: amber/red areas filled ~60% of the
    # plot and a normal 36 °C read as an alarm
    btemp = S.timeseries("TEMPERATURA DA BATERIA", [_host(TEMP_RE)], unit="celsius", legend="hidden",
                         color={"mode": "fixed", "fixedColor": S.ACCENT}, steps=BATT_TEMP_STEPS,
                         thresholds_style="dashed", fill=8, decimals=0,
                         description="Linhas tracejadas: 35 °C (âmbar, vida útil da bateria encurtando) e 45 °C "
                                     "(vermelho).")
    btemp["fieldConfig"]["defaults"]["custom"].update(axisSoftMin=25, axisSoftMax=50)

    # --- events -----------------------------------------------------------------------------------
    # colour from the value maps, not "thresholds": in that mode the state timeline buckets the values by
    # threshold ("3+", "2+") and ignores the value maps. Deep fills like the header tiles: calm green
    # rows with white text, a BATERIA segment still a loud red block.
    def by_name(name, mappings):
        return S.col_props(name, mappings=S.as_fill(mappings),
                           color={"mode": "fixed", "fixedColor": S.FILL_UNKNOWN})

    history = S.state_timeline(
        "HISTÓRICO DE ESTADO",
        [S.target(SOURCE_RE, S.alias("Fonte da saída"), ref="A"),
         S.target(BATT_STATUS_RE, S.alias("Bateria"), ref="B"),
         S.target(ALARMS_RE, S.alias("Alarmes"), ref="C")],
        mappings=[], steps=S.steps(S.UNKNOWN), row_height=0.7, show_value="auto", fill=90,
        overrides=[by_name("Fonte da saída", SOURCE_MAP), by_name("Bateria", BATT_MAP),
                   by_name("Alarmes", ALARM_MAP + [{"type": "range", "options": {
                       "from": 1, "to": 1e6, "result": {"text": "ALARME ATIVO", "color": S.CRIT, "index": 1}}}])],
        description="Fonte da saída, estado da bateria e alarmes no período: qualquer faixa fora do verde "
                    "é uma queda de energia, bateria fraca ou alarme.")
    history["options"]["text"] = {"valueSize": 15}      # in-bar text readable next to the 26 px tiles
    ident = S.stat("EQUIPAMENTO",
                   [_text_target(r"/^UPS: (Fabricante|Modelo|Vers[aã]o de firmware)$/")],
                   fields="/^(Fabricante|Modelo|Firmware)$/", text_mode="value_and_name", orientation="horizontal",
                   color_mode="none",
                   justify="auto", value_size=15, title_size=12, time_from="1d", mdp=10,
                   overrides=[S.col_props("UPS: Fabricante", displayName="Fabricante"),
                              S.col_props("UPS: Modelo", displayName="Modelo"),
                              S.col_props("/firmware/i", by="byRegexp", displayName="Firmware")],
                   description="Fabricante, modelo e firmware informados pelo nobreak.")
    # a counter reads at a glance (green 0 / red n). No list under it: with 0 problems the plugin drew an
    # English empty table whose pager was bigger than its content. The details are one click away, in the
    # overview's problems feed.
    n_problems = S.kpi("PROBLEMAS ATIVOS", [S.triggers_target(group="$group", host="$host", min_severity=0)],
                       links=[S.data_link("Ver problemas na Visão Geral",
                                          S.dashboard_url("overview", keep_time=False))],
                       transformations=[S.reduce_fields(("sum",)),
                                        S.tf("calculateField", mode="reduceRow", alias="Problemas",
                                             replaceFields=True,
                                             reduce={"reducer": "sum",
                                                     "include": list(S.SEVERITY_FIELDS.values())})],
                       steps=S.COUNT_BAD, decimals=0, value_size=40, no_value="0", time_from=None, mdp=None,
                       description="Triggers em problema agora nos nobreaks, qualquer severidade. Clique para "
                                   "ver a lista na Visão Geral.")

    panels = S.grid(
        (4, [(banner, 4), (comm, 3), (source, 4), (battery, 3), (alarms, 3), (uptime, 3), (linebads, 4)]),
        (8, [(charge, 5), (load, 5), (temp, 5), (volts, 4), (S.stack((power, 5), (runtime, 3)), 5)]),
        S.row("Energia"),
        (9, [(vin, 12), (freq, 12)]),
        S.row("Bateria e carga"),
        (9, [(load_hist, 8), (bvolt, 8), (btemp, 8)]),
        S.row("Eventos"),
        (8, [(history, 16), (S.stack((n_problems, 4), (ident, 4)), 8)]),
    )
    return S.dashboard(KEY, TITLE, panels, datasource_uid=datasource_uid,
                       variables=S.category_variables(group_re), time_from="now-6h", range_cap="2d",
                       description="Nobreaks: fonte de energia, bateria, carga, tensões e eventos.")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.ups config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
