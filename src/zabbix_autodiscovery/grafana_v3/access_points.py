"""Access Points v3: desktop analysis dashboard enriched with UniFi connected clients KPI,
and per-AP / per-SSID client charts."""
import json

from ..grafana_v2 import access_points as _v2
from . import style as S
from .switches import (
    COLOR_SERIES,
    LATENCY_MS,
    TOP_N,
    availability_timeline,
    errors_table,
    filter_variables,
    health_kpis,
    host_link,
    latency_series,
    port_alias,
    port_target,
    problems_feed,
    problems_kpi,
    rank_colors,
    ranked,
    table_kpi,
    traffic_series,
)

KEY = "access-points"
TABLE_ID = _v2.TABLE_ID
CLIENTS_RE = _v2.CLIENTS_RE
SSID_CLIENTS_RE = r"/^SSID \[.*\]: Connected clients$/"


def _inventory(cfg):
    p = _v2._inventory(cfg)
    for ov in p["fieldConfig"]["overrides"]:
        if ov.get("matcher", {}).get("options") == "Access Point":
            for prop in ov.get("properties", []):
                if prop.get("id") == "links":
                    prop["value"] = host_link(KEY, "Access Point")
    return p


def _clients_by_ap_chart():
    return S.timeseries(
        f"CLIENTES WI-FI CONECTADOS · TOP {TOP_N} APs",
        ranked(CLIENTS_RE, S.alias("$__zbx_host_name"), fn="max"),
        unit="short", decimals=0, min=0, fill=14,
        color=COLOR_SERIES, overrides=rank_colors(TOP_N),
        legend_calcs=("lastNotNull", "max"), sort_by="Max",
        description="Quantidade de clientes Wi-Fi conectados ao longo do tempo nos 5 APs mais movimentados.",
    )


def _clients_by_ssid_bar():
    return S.bargauge(
        "CLIENTES CONECTADOS AGORA POR AP E SSID",
        [S.target(
            SSID_CLIENTS_RE, S.top(12, "last"),
            S.alias("$__zbx_host_name · $__zbx_item"),
            S.replace_alias(r"/ · SSID \[(.*)\]: Connected clients$/", " · $1"),
        )],
        calcs=("lastNotNull",), rank=True, unit="short", min=0, decimals=0,
        steps=_v2.CLIENTS_STEPS, mode="basic", bar_height=24, name_placement="left", value_size=15,
        time_from=S.STAT_WINDOW, mdp=S.STAT_MDP,
        description="Dispositivos conectados agora por rede Wi-Fi (SSID / rádio) nos APs filtrados.",
    )


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)

    banner = S.banner("ACCESS POINTS", "Rede v3 · Wi-Fi UniFi")
    online, offline = health_kpis("Access Points")
    clients_kpi = table_kpi(
        "CLIENTES WI-FI", TABLE_ID, ["Clientes"],
        steps=_v2.CLIENTS_STEPS, caption="conectados agora",
        description="Soma dos clientes Wi-Fi conectados em todos os Access Points filtrados.",
    )
    uplink_now = _v2.uplink_kpi()
    inventory = _inventory(cfg)

    clients_ts = _clients_by_ap_chart()
    ssid_bars = _clients_by_ssid_bar()

    timeline = availability_timeline("DISPONIBILIDADE (PING) NO PERÍODO", "access point", row_height=0.75)
    feed = problems_feed(page_size=6)

    heavy = (" Itens de 3 min em ~16 APs: intervalos acima de 2 dias podem exceder o limite de memória do "
             "Zabbix.")
    up_in = _v2.uplink_series(
        f"UPLINK · RECEBIDO (REDE → AP) · TOP {TOP_N}", _v2.UPLINK_IN_RE,
        f"Bits recebidos no uplink dos {TOP_N} APs com maior média no período." + heavy,
    )
    up_out = _v2.uplink_series(
        f"UPLINK · ENVIADO (AP → REDE) · TOP {TOP_N}", _v2.UPLINK_OUT_RE,
        f"Bits enviados no uplink dos {TOP_N} APs com maior média no período." + heavy,
    )
    radios = traffic_series(
        f"RÁDIOS MAIS CARREGADOS · TOP {TOP_N} (ENVIADO AOS CLIENTES)",
        ranked(_v2.RADIO_SENT_RE, *port_alias()),
        f"Os {TOP_N} rádios (wifiN, raN, raiN) com maior média de bits enviados aos clientes no período.",
    )
    load = S.bargauge(
        "CARGA DE CPU · MÉDIA NO PERÍODO (LOAD 1 MIN)",
        [S.target(S.LOAD_1M_RE, S.group_by("5m", "avg"), S.alias("$__zbx_host_name"))],
        calcs=("mean",), rank=True, unit="none", decimals=2, min=0, max=_v2.LOAD_MAX, steps=_v2.LOAD_UNIFI,
        mode="gradient", name_placement="left", value_size=15, title_size=13, time_from=None,
        mdp=S.SERIES_MDP,
        description="Load average de 1 min de cada AP, média no período." + heavy,
    )
    load["options"].update(sizing="manual", minVizHeight=14, maxVizHeight=24)
    latency = latency_series("LATÊNCIA ICMP", "access points")
    errors = errors_table(
        "ERROS DE INTERFACE · PIORES (UPLINK E RÁDIOS)", "Access Point",
        [port_target(rf"/^Interface {_v2.RADIO_IFACES}\(\): Inbound packets with errors$/",
                     "Inbound packets with errors", "erros de entrada", "A"),
         port_target(rf"/^Interface {_v2.RADIO_IFACES}\(\): Outbound packets with errors$/",
                     "Outbound packets with errors", "erros de saída", "B")],
        "Pacotes/s com erro no período em eth0 e nos rádios (média e pico)." + heavy,
        type_width=140,
    )

    panels = S.grid(
        (4, [(banner, 5), (online, 2), (offline, 2), (clients_kpi, 3), (uplink_now, 5), (problems_kpi(), 7)]),
        S.row("Estado atual", children=[(18, [(inventory, 24)])]),
        S.row("Clientes Wi-Fi (UniFi MIB)", children=[(9, [(clients_ts, 13), (ssid_bars, 11)])]),
        S.row("Disponibilidade e problemas", children=[(9, [(timeline, 11), (feed, 13)])]),
        S.row("Uplink", children=[(9, [(up_in, 12), (up_out, 12)])]),
        S.row("Rádios e carga", children=[(13, [(radios, 12), (load, 12)])]),
        S.row("Qualidade", children=[(10, [(latency, 12), (errors, 12)])]),
    )
    return S.dashboard(
        KEY, "Access Points", panels, datasource_uid=datasource_uid,
        variables=filter_variables(cfg, cat["group"]), time_from="now-6h", range_cap="2d",
        description="Access points UniFi v3: clientes conectados por AP e SSID, estado, uplink, rádios, carga e qualidade.",
    )

