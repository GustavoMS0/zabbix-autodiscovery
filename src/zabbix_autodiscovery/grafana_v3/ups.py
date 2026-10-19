"""Nobreaks (UPS) v3: desktop analysis dashboard enriched with real ICMP ping & latency telemetry."""
from ..grafana_v2 import ups as _v2
from . import style as S

KEY = "ups"
TITLE = "Nobreaks"
DEFAULT_GROUP = _v2.DEFAULT_GROUP


def build(cfg, datasource_uid="zabbix"):
    d = _v2.build(cfg, datasource_uid=datasource_uid)
    cat = next((c for c in S.categories(cfg) if c["key"] == KEY), None)
    group_re = cat["group"] if cat else DEFAULT_GROUP

    banner = S.banner("NOBREAKS", "Infra v3 · energia & ICMP")
    comm = _v2._tile(
        "PING ICMP", [_v2._host("ICMP ping")],
        mappings=S.AVAIL_MAP, steps=S.AVAIL_STEPS,
        description="Disponibilidade de rede em tempo real do nobreak via ICMP ping.",
    )
    rtt = S.stat(
        "LATÊNCIA ICMP", [_v2._host("ICMP response time", _v2.scale(1000))],
        unit="ms", decimals=1, value_size=32, title_size=13,
        steps=S.steps(S.OK, (50, S.WARN), (150, S.CRIT)),
        mappings=S.no_data_map("—"),
        overrides=[S.col_props("/.*/", by="byRegexp", unit="ms", decimals=1)],
        description="Tempo de resposta ICMP em milissegundos.",
    )
    source = _v2._tile("FONTE DA SAÍDA", [_v2._host(_v2.SOURCE_RE)], mappings=_v2.SOURCE_MAP, steps=_v2.SOURCE_STEPS,
                       description="De onde vem a energia da saída: REDE ELÉTRICA, BATERIA, BYPASS ou correção.")
    battery = _v2._tile("BATERIA", [_v2._host(_v2.BATT_STATUS_RE)], mappings=_v2.BATT_MAP, steps=_v2.BATT_STEPS,
                        description="Estado da bateria informado pelo nobreak (UPS-MIB upsBatteryStatus).")
    alarms = _v2._tile("ALARMES", [_v2._host(_v2.ALARMS_RE)], mappings=_v2.ALARM_TILE_MAP, steps=_v2.ALARM_STEPS,
                       decimals=0, description="Quantidade de alarmes ativos no nobreak (upsAlarmsPresent).")
    uptime = S.stat("LIGADO HÁ", [_v2._host(_v2.UPTIME_RE, _v2.scale(0.01 / 86400))], decimals=1,
                    mappings=S.no_data_map("—"), steps=S.NEUTRAL, value_size=32, title_size=13,
                    time_from=_v2.COMM_WINDOW,
                    overrides=[S.col_props("/.*/", by="byRegexp", unit="suffix: dias")],
                    description="Tempo desde o último reinício da placa SNMP do nobreak (sysUpTime).")
    linebads = S.stat("FALHAS DE REDE", [_v2._host(_v2.LINEBADS_RE)], decimals=0, steps=S.COUNT_BAD, value_size=36,
                      mappings=S.no_data_map(), title_size=13,
                      description="Vezes em que a entrada elétrica saiu da tolerância (upsInputLineBads).")

    def by_name(name, mappings):
        return S.col_props(name, mappings=S.as_fill(mappings),
                           color={"mode": "fixed", "fixedColor": S.FILL_UNKNOWN})

    history = S.state_timeline(
        "HISTÓRICO DE ESTADO (REDE, FONTE, BATERIA E ALARMES)",
        [
            S.target("ICMP ping", S.group_by("5m", "min"), S.alias("Ping ICMP"), ref="P"),
            S.target(_v2.SOURCE_RE, S.alias("Fonte da saída"), ref="A"),
            S.target(_v2.BATT_STATUS_RE, S.alias("Bateria"), ref="B"),
            S.target(_v2.ALARMS_RE, S.alias("Alarmes"), ref="C"),
        ],
        mappings=[], steps=S.steps(S.UNKNOWN), row_height=0.7, show_value="auto", fill=90,
        overrides=[
            by_name("Ping ICMP", S.AVAIL_MAP),
            by_name("Fonte da saída", _v2.SOURCE_MAP),
            by_name("Bateria", _v2.BATT_MAP),
            by_name("Alarmes", _v2.ALARM_MAP + [{"type": "range", "options": {
                "from": 1, "to": 1e6, "result": {"text": "ALARME ATIVO", "color": S.CRIT, "index": 1}}}]),
        ],
        description="Ping ICMP, fonte da saída, estado da bateria e alarmes no período.",
    )
    history["options"]["text"] = {"valueSize": 15}

    # Replace top row and history panel in the v2 panel list, and update overview link to v3
    old_panels = d["panels"]
    second_row = [p for p in old_panels if p.get("gridPos", {}).get("y") == 4]
    rest = [p for p in old_panels if p.get("gridPos", {}).get("y", 0) > 4]
    for p in rest:
        if p.get("title") == "HISTÓRICO DE ESTADO":
            history["gridPos"] = p["gridPos"]
            history["id"] = p["id"]
            p.clear()
            p.update(history)
        elif p.get("title") == "PROBLEMAS ATIVOS":
            p["fieldConfig"]["defaults"]["links"] = [
                S.data_link("Ver problemas na Visão Geral v3", S.dashboard_url("overview", keep_time=False))
            ]

    top_row = S.grid((4, [(banner, 4), (comm, 3), (rtt, 3), (source, 4), (battery, 3), (alarms, 2), (uptime, 3), (linebads, 2)]))
    return S.dashboard(
        KEY, TITLE, top_row + second_row + rest,
        datasource_uid=datasource_uid,
        variables=S.category_variables(group_re), time_from="now-6h", range_cap="2d",
        description="Nobreaks v3: disponibilidade ICMP, latência, fonte de energia, bateria, carga, tensões e eventos.",
    )

