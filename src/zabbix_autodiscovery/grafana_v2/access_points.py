"""Access Points: desktop analysis dashboard (1920 wide, scrolls).

Layout:
  y0   h4  banner | online | offline | tráfego nos uplinks (recebido · enviado) | problemas por severidade
  row  Estado atual: inventory table, one row per AP (filial, ping, latency, CPU load, memory, uplink type,
       uplink received/sent, uptime)
  row  Disponibilidade e problemas: ICMP state timeline | live problems
  row  Uplink: received | sent, top 5 APs (log axis)
  row  Rádios e carga: busiest radios (top 5) | CPU load average ranked over the range
  row  Qualidade: ICMP latency (top 5) | interfaces with the most errors

The APs are UniFi on the "Ubiquiti AirOS" template (v1 findings): CPU is only a load average (no CPU %
via SNMP), wifiN / raN / raiN are the radios; connected clients are not exposed by that template yet.
Uplink: eth0 on cabled APs; mesh nodes (AP ARMAZEM / AP EXPEDIÇÃO - BAHIA) have eth0 at a constant 0 and
reach the network through the wireless station interface vwiresta<N> (only mesh nodes have it, checked
in Zabbix). The uplink is therefore eth0 + vwiresta<N>. The parent AP's vwireap<N> is not added: it is
the same traffic seen from the other end, and it would be counted twice.
Table, KPI and helper functions come from switches.py, so both dashboards read the same.
"""
import json

from . import style as S
from .switches import (
    LATENCY_MS,
    TOP_N,
    _scale,
    availability_timeline,
    errors_table,
    filter_variables,
    gauge_col,
    health_kpis,
    host_link,
    latency_series,
    matrix_target,
    matrix_transforms,
    port_alias,
    port_target,
    problems_feed,
    problems_kpi,
    ranked,
    site_mapping,
    site_targets,
    status_col,
    text_col,
    traffic_series,
    uptime_col,
    uptime_target,
)

KEY = "access-points"
TABLE_ID = 10

# v1 verified regexes (dashboards.SPECS access-points): eth0 uplink, physical radios, load average; plus
# the mesh station interface (vwiresta5 today; no VLAN suffix, so .40/.60 sub-interfaces stay out)
CABLE_IN_RE = r"/^Interface eth0\(\): Bits received$/"
CABLE_OUT_RE = r"/^Interface eth0\(\): Bits sent$/"
MESH_IN_RE = r"/^Interface vwiresta\d+\(\): Bits received$/"
MESH_OUT_RE = r"/^Interface vwiresta\d+\(\): Bits sent$/"
UPLINK_IN_RE = r"/^Interface (eth0|vwiresta\d+)\(\): Bits received$/"
UPLINK_OUT_RE = r"/^Interface (eth0|vwiresta\d+)\(\): Bits sent$/"
RADIO_IFACES = r"(eth0|wifi\d|ra\d|rai\d)"
RADIO_SENT_RE = r"/^Interface (wifi\d|ra\d|rai\d)\(\): Bits sent$/"
CLIENTS_RE = r"/^Wireless: Connected clients$/"
# UniFi load average counts kernel/IO threads: the Barueri APs sit at a flat ~2.0 all day while healthy
# (Zabbix: 1m 2.04 / 5m 2.03 / 15m 2.00), so v1's 1.5 / 3 painted them amber forever. Amber from 3,
# red from 4, gauge scale 0-5.
LOAD_UNIFI = S.steps(S.OK, (3, S.WARN), (4, S.CRIT))
LOAD_MAX = 5
CLIENTS_STEPS = S.steps(S.TEXT, (50, S.WARN), (80, S.CRIT))


def uplink_kpi():
    """RECEBIDO and ENVIADO side by side, each the sum over the filtered APs of the 15-minute mean of
    their uplink. Not one "received + sent" number: adding both directions says nothing about capacity,
    and a single last sample jumped between 31 and 60 Mb/s minutes apart. Own query (~16 APs x 2 items x
    15 min, cheap); the per-AP aliases collapse onto the direction name so groupBy can sum them."""
    names = {"A": "RECEBIDO", "B": "ENVIADO"}
    targets = [S.target(UPLINK_IN_RE, S.alias(names["A"]), ref="A"),
               S.target(UPLINK_OUT_RE, S.alias(names["B"]), ref="B")]
    mean = S.CALC_NAMES["mean"]
    p = S.stat("TRÁFEGO NOS UPLINKS", targets,
               transformations=[S.reduce_rows(("mean",)),
                                S.tf("groupBy", fields={"Field": {"operation": "groupby", "aggregations": []},
                                                        mean: {"operation": "aggregate", "aggregations": ["sum"]}}),
                                S.tf("rowsToFields", mappings=[{"fieldName": "Field", "handlerKey": "field.name"},
                                                               {"fieldName": f"{mean} (sum)",
                                                                "handlerKey": "field.value"}])],
               overrides=[S.col_props(names["A"], color={"mode": "fixed", "fixedColor": S.ACCENT}),
                          S.col_props(names["B"], color={"mode": "fixed", "fixedColor": S.ACCENT_2})],
               steps=S.NEUTRAL, unit="bps", decimals=1, text_mode="value_and_name", value_size=30,
               title_size=14, orientation="vertical", wide=False, mdp=S.STAT_MDP,
               description="Tráfego no uplink (eth0, ou o enlace mesh) somado em todos os APs filtrados: "
                           "média dos últimos 15 min de cada AP. RECEBIDO = rede → AP (o que os clientes Wi-Fi "
                           "baixam); ENVIADO = AP → rede.")
    return p


def _uplink_sum(direction):
    """Uplink <direction> = eth0 + mesh station interface, per row (calculateField reduceRow sum skips the
    missing mesh value of cabled APs)."""
    return S.tf("calculateField", mode="reduceRow", alias=f"Uplink {direction}", replaceFields=False,
                reduce={"reducer": "sum", "include": [f"eth0 {direction}", f"Mesh {direction}"]})


def _inventory(cfg):
    targets = [
        matrix_target("ICMP ping", "Ping", ref="A"),
        matrix_target("ICMP response time", "Latência", _scale(1000), ref="B"),
        matrix_target("ICMP loss", "Perda", ref="C"),
        matrix_target(CLIENTS_RE, "Clientes", ref="D"),
        matrix_target(S.LOAD_1M_RE, "Carga CPU (1 min)", ref="E"),
        matrix_target(S.MEM_RE, "Memória", ref="F"),
        matrix_target(CABLE_IN_RE, "eth0 recebido", ref="G"),
        matrix_target(CABLE_OUT_RE, "eth0 enviado", ref="H"),
        matrix_target(MESH_IN_RE, "Mesh recebido", ref="I"),
        matrix_target(MESH_OUT_RE, "Mesh enviado", ref="J"),
        uptime_target("K"),
        *site_targets(cfg, "L"),
    ]
    order = ["Filial", "Ping", "Latência", "Perda", "Clientes", "Carga CPU (1 min)", "Memória", "Mesh recebido",
             "Uplink recebido", "Uplink enviado", "Uptime"]
    mesh = [{"type": "range", "options": {"from": -1e18, "to": 1e18, "result": {"text": "MESH", "color": S.ACCENT}}}]
    # ~1110 px fixed: at 1440 the table fits without a horizontal scrollbar; the two gauges take the rest
    columns = [
        S._col("Access Point", ("links", host_link(KEY, "Access Point")), ("custom.width", 205)),
        S._col("Filial", ("mappings", site_mapping(cfg)), ("custom.width", 115), ("custom.align", "left")),
        status_col("Ping", width=95),
        text_col("Latência", LATENCY_MS, unit="ms", decimals=1, width=88),
        text_col("Perda", S.LOSS_PCT, unit="percent", decimals=0, width=68),
        text_col("Clientes", CLIENTS_STEPS, decimals=0, width=78, no_value="—"),
        gauge_col("Carga CPU (1 min)", LOAD_UNIFI, unit="none", max=LOAD_MAX, decimals=2),
        gauge_col("Memória", S.PCT),
        # the mesh station value doubles as the uplink type: any value = MESH, none = CABO
        S._col("Mesh recebido", ("displayName", "Uplink"), ("custom.width", 78), ("custom.align", "center"),
               ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": S.MUTED}),
               ("mappings", mesh + S.no_data_map("CABO", color=S.MUTED))),
        text_col("Uplink recebido", S.NEUTRAL, unit="bps", decimals=1, width=120),
        text_col("Uplink enviado", S.steps(S.ACCENT_2), unit="bps", decimals=1, width=120),
        uptime_col(width=90),
    ]
    return S.table(
        "INVENTÁRIO E ESTADO ATUAL", targets, id=TABLE_ID, columns=columns, cell_height="sm",
        transformations=[*matrix_transforms("Access Point", order=order), _uplink_sum("recebido"),
                         _uplink_sum("enviado"),
                         S.organize(exclude=["eth0 recebido", "eth0 enviado", "Mesh enviado"],
                                    order=["Access Point", *order])],
        time_from=S.STAT_WINDOW, mdp=S.STAT_MDP,
        description="Último valor (15 min) por access point. Clientes = estações Wi-Fi conectadas aos SSIDs "
                    "(template AutoDiscovery - UniFi wireless). Carga CPU = load average de 1 min (o template "
                    "UniFi/AirOS não expõe CPU em % via SNMP; os UniFi ficam perto de 2 normalmente, então "
                    "atenção a partir de 3 e crítico a partir de 4). Uplink: CABO = eth0; MESH = o AP chega à "
                    "rede pelo Wi-Fi de outro AP (interface vwiresta), e o tráfego mostrado é o do enlace mesh. "
                    "Uptime em dias; \"< 1 dia\" em âmbar = reiniciou nas últimas 24 h. Clique no nome para "
                    "filtrar o dashboard nesse AP.")


def uplink_series(title, item_re, description):
    """Top APs by uplink traffic; a mesh node's link is named "<AP> (mesh)" and its idle eth0 (always 0)
    is hidden, so it is not read as an AP passing no traffic."""
    p = traffic_series(title, ranked(item_re, S.alias("$__zbx_host_name: $__zbx_item"),
                                     S.replace_alias(r"/: Interface eth0\(.*$/", ""),
                                     S.replace_alias(r"/: Interface vwiresta.*$/", " (mesh)")),
                       description)
    p["fieldConfig"]["overrides"].append(
        {"matcher": {"id": "byValue", "options": {"reducer": "max", "op": "lte", "value": 0}},
         "properties": [{"id": "custom.hideFrom", "value": {"legend": True, "tooltip": True, "viz": True}}]})
    return p


def build(cfg, datasource_uid="zabbix"):
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)

    banner = S.banner("ACCESS POINTS", "Rede · Wi-Fi")
    online, offline = health_kpis("Access Points")
    uplink_now = uplink_kpi()
    inventory = _inventory(cfg)

    timeline = availability_timeline("DISPONIBILIDADE (PING) NO PERÍODO", "access point", row_height=0.75)
    feed = problems_feed(page_size=6)

    heavy = (" Itens de 3 min em ~16 APs: intervalos acima de 2 dias podem exceder o limite de memória do "
             "Zabbix.")
    up_in = uplink_series(
        f"UPLINK · RECEBIDO (REDE → AP) · TOP {TOP_N}", UPLINK_IN_RE,
        f"Bits recebidos no uplink dos {TOP_N} APs com maior média no período: o que a rede entrega aos "
        "clientes Wi-Fi. Uplink = eth0, ou o enlace mesh (vwiresta) nos APs sem cabo, marcados \"(mesh)\"."
        + heavy)
    up_out = uplink_series(
        f"UPLINK · ENVIADO (AP → REDE) · TOP {TOP_N}", UPLINK_OUT_RE,
        f"Bits enviados no uplink dos {TOP_N} APs com maior média no período: o que os clientes Wi-Fi enviam "
        "à rede." + heavy)
    radios = traffic_series(
        f"RÁDIOS MAIS CARREGADOS · TOP {TOP_N} (ENVIADO AOS CLIENTES)",
        ranked(RADIO_SENT_RE, *port_alias()),
        f"Os {TOP_N} rádios (wifiN, raN, raiN) com maior média de bits enviados aos clientes no período.")
    # Ranked bars instead of 16 overlapping load lines: which AP is busy over the range reads at a glance
    # (the current value is in the inventory). 5-minute averages keep the points down.
    load = S.bargauge(
        "CARGA DE CPU · MÉDIA NO PERÍODO (LOAD 1 MIN)",
        [S.target(S.LOAD_1M_RE, S.group_by("5m", "avg"), S.alias("$__zbx_host_name"))],
        calcs=("mean",), rank=True, unit="none", decimals=2, min=0, max=LOAD_MAX, steps=LOAD_UNIFI,
        mode="gradient", name_placement="left", value_size=15, title_size=13, time_from=None,
        mdp=S.SERIES_MDP,
        description="Load average de 1 min de cada AP, média no período (o UniFi não expõe CPU em % via "
                    "SNMP). Os UniFi ficam perto de 2 em operação normal: verde abaixo de 3, âmbar a partir "
                    "de 3, vermelho a partir de 4." + heavy)
    # manual sizing: bars keep the same thickness from 1 AP (filial filter) to all 16 without a scrollbar
    load["options"].update(sizing="manual", minVizHeight=14, maxVizHeight=24)
    latency = latency_series("LATÊNCIA ICMP", "access points")
    errors = errors_table(
        "ERROS DE INTERFACE · PIORES (UPLINK E RÁDIOS)", "Access Point",
        [port_target(rf"/^Interface {RADIO_IFACES}\(\): Inbound packets with errors$/",
                     "Inbound packets with errors", "erros de entrada", "A"),
         port_target(rf"/^Interface {RADIO_IFACES}\(\): Outbound packets with errors$/",
                     "Outbound packets with errors", "erros de saída", "B")],
        "Pacotes/s com erro no período em eth0 e nos rádios (média e pico): as 4 piores interfaces de cada "
        "sentido (só as que tiveram erro). Média alta = problema contínuo; pico alto com média perto de 0 = "
        "rajada isolada." + heavy, type_width=140)

    panels = S.grid(
        # uplink tile 5 wide: two values with their unit fit at 1440 px without wrapping "Mb/s"
        (4, [(banner, 5), (online, 3), (offline, 3), (uplink_now, 5), (problems_kpi(), 8)]),
        # 16 rows at "sm" (36 px in Grafana 13) + header fit in 18 units without an inner scrollbar
        S.row("Estado atual", children=[(18, [(inventory, 24)])]),
        # h9: 16 timeline rows still fit, and an empty feed (no AP problems) wastes less space
        S.row("Disponibilidade e problemas", children=[(9, [(timeline, 11), (feed, 13)])]),
        S.row("Uplink", children=[(9, [(up_in, 12), (up_out, 12)])]),
        S.row("Rádios e carga", children=[(13, [(radios, 12), (load, 12)])]),
        S.row("Qualidade", children=[(10, [(latency, 12), (errors, 12)])]),
    )
    return S.dashboard(KEY, "Access Points", panels, datasource_uid=datasource_uid,
                       variables=filter_variables(cfg, cat["group"]), time_from="now-6h", range_cap="2d",
                       description="Access points UniFi: estado, uplink, rádios, carga e qualidade (análise "
                                   "em desktop).")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.access_points config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
