"""Switches v3: desktop analysis dashboard enriched with Dell FastPath CPU/Memory/Temperature telemetry
and historical CPU/Memory charts."""
import json

from ..grafana_v2 import switches as _v2
from ..grafana_v2.switches import (  # noqa: F401
     COLOR_SERIES,
    HEALTH_ID,
    LATENCY_MS,
    LEGEND_NOTE,
    NOT_EXPOSED,
    PEAK_MAX,
    PEAK_STEPS,
    PORT_USAGE,
    RATE_STEPS,
    TABLE_ID,
    TEMP_SWITCH,
    TOP_N,
    _offset,
    _scale,
    errors_table,
    filter_variables,
    gauge_col,
     latency_series,
    matrix_target,
    matrix_transforms,
    port_alias,
    port_target,
    port_traffic,
    problems_feed,
    problems_kpi,
    rank_colors,
    ranked,
    site_mapping,
    site_targets,
    status_col,
    table_kpi,
    text_col,
    traffic_series,
    uptime_col,
    uptime_target,
)
from . import style as S

KEY = "switches"
# Dell FastPath VxWorks pre-allocates ~81% of its memory pool in normal operation: warn from 85%, crit from 95%
MEM_SWITCH = S.steps(S.OK, (85, S.WARN), (95, S.CRIT))


def host_link(dash_key, field):
    host = "${__data.fields[\"%s\"]}" % field
    url = f"/d/{S.uid(dash_key)}?${{site:queryparam}}&var-host={host}"
    return [S.data_link(f"Filtrar {host}", url)]


def health_kpis(dim_name):
    online, offline = _v2.health_kpis(dim_name)
    return online, offline


def availability_timeline(title, noun, row_height=0.8):
    return _v2.availability_timeline(title, noun, row_height=row_height)


def _inventory(cfg):
    p = _v2._inventory(cfg)
    for ov in p["fieldConfig"]["overrides"]:
        if ov.get("matcher", {}).get("options") == "Switch":
            for prop in ov.get("properties", []):
                if prop.get("id") == "links":
                    prop["value"] = host_link(KEY, "Switch")
        elif ov.get("matcher", {}).get("options") == "Memória":
            for prop in ov.get("properties", []):
                if prop.get("id") == "thresholds":
                    prop["value"] = {"mode": "absolute", "steps": MEM_SWITCH}
    return p


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)

    banner = S.banner("SWITCHES", "Rede v3 · LAN & FastPath")
    online, offline = health_kpis("Switches")
    ports = table_kpi("PORTAS EM USO", TABLE_ID, ["Portas em uso", "Portas físicas"],
                      caption="${__data.fields[\"Portas físicas\"]} portas físicas",
                      description="Portas com link somadas em todos os switches filtrados.")
    inventory = _inventory(cfg)

    timeline = availability_timeline("DISPONIBILIDADE (PING) NO PERÍODO", "switch")
    feed = problems_feed()

    cpu_chart = S.timeseries(
        "USO DE CPU POR SWITCH",
        ranked(S.CPU_RE, S.alias("$__zbx_host_name"), n=7),
        unit="percent", min=0, max=100, color=COLOR_SERIES, overrides=rank_colors(7),
        steps=S.PCT, thresholds_style="dashed", legend_calcs=("mean", "max"), sort_by="Mean",
        description="Utilização de CPU (%) dos switches (Dell FastPath, MikroTik, HP Comware)." + LEGEND_NOTE,
    )
    mem_chart = S.timeseries(
        "USO DE MEMÓRIA POR SWITCH",
        ranked(S.MEM_RE, S.alias("$__zbx_host_name"), n=7),
        unit="percent", min=0, max=100, color=COLOR_SERIES, overrides=rank_colors(7),
        steps=MEM_SWITCH, thresholds_style="dashed", legend_calcs=("mean", "max"), sort_by="Mean",
        description="Utilização de memória (%) dos switches (Dell FastPath, MikroTik, HP Comware)." + LEGEND_NOTE,
    )

    traffic_in = traffic_series(
        f"TRÁFEGO DE ENTRADA · TOP {TOP_N} PORTAS", port_traffic(S.TRAFFIC_IN_RE),
        f"As {TOP_N} portas físicas com maior média de bits recebidos no período.",
    )
    traffic_out = traffic_series(
        f"TRÁFEGO DE SAÍDA · TOP {TOP_N} PORTAS", port_traffic(S.TRAFFIC_OUT_RE),
        f"As {TOP_N} portas físicas com maior média de bits enviados no período.",
    )

    latency = latency_series("LATÊNCIA ICMP", "switches")
    errors = errors_table(
        "ERROS E DESCARTES DE ENTRADA · PIORES PORTAS", "Switch",
        [port_target(S.ERRORS_IN_RE, "Inbound packets with errors", "erros", "A"),
         port_target(S.DISCARDS_IN_RE, "Inbound packets discarded", "descartes", "B")],
        "Pacotes/s com erro e descartados no período (média e pico): as 4 piores portas físicas de cada contador.",
    )

    panels = S.grid(
        (4, [(banner, 5), (online, 3), (offline, 3), (ports, 4), (problems_kpi(), 9)]),
        S.row("Estado atual", children=[(10, [(inventory, 24)])]),
        S.row("Saúde · CPU e memória", children=[(8, [(cpu_chart, 12), (mem_chart, 12)])]),
        S.row("Disponibilidade e problemas", children=[(8, [(timeline, 11), (feed, 13)])]),
        S.row("Tráfego · portas físicas", children=[(10, [(traffic_in, 12), (traffic_out, 12)])]),
        S.row("Qualidade", children=[(9, [(latency, 14), (errors, 10)])]),
    )
    return S.dashboard(
        KEY, "Switches", panels, datasource_uid=datasource_uid,
        variables=filter_variables(cfg, cat["group"]), time_from="now-6h", range_cap="1d",
        description="Switches v3: estado, portas, CPU/memória Dell FastPath, tráfego e qualidade.",
    )

