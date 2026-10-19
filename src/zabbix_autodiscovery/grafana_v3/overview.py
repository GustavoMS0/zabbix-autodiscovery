"""Visão Geral v3: the NOC TV wall (1920x1080 kiosk, one screen, no scroll) with unified topology link and Wi-Fi KPI."""

from . import style as S

KEY = "overview"
SITES_PANEL_ID = 10
TOPOLOGY_KEY = "topology"


def _health_tiles(title, dims, panel_id, description, link_title="Abrir ${__data.fields.dim}"):
    targets = S.health_targets(dims)
    return S.stat(
        title, targets, id=panel_id, description=description,
        values=True, calcs=("lastNotNull",),
        color_mode="background", text_mode="value_and_name", wide=False, orientation="auto",
        title_size=14, value_size=34, min_width=170, min_height=70,
        steps=S.as_fill(S.AVAIL_RATIO),
        mappings=S.no_data_map(color=S.FILL_UNKNOWN),
        time_from=S.HEALTH_WINDOW, mdp=20,
        transformations=[*S.health_transforms(), S.as_text("Online", "Total", "Offline")],
        overrides=[S.col_props("Disponibilidade", unit="percentunit", decimals=0,
                               displayName="${__data.fields.dim} · ${__data.fields.Online}/${__data.fields.Total}")],
        links=[S.data_link(link_title, "${__data.fields.link}")],
    )


def _kpi_from_sites(title, field, *, steps, unit=None, decimals=0, description=None, extra_tf=(), name=None):
    keep = S.filter_fields(f"^({field}|Total)$" if name else f"^{field}$")
    p = S.kpi(
        title, [S.dashboard_target(SITES_PANEL_ID, with_transforms=False)],
        datasource=dict(S.DASHBOARD_DS),
        transformations=[*S.health_transforms(), S.reduce_fields(("sum",)), *extra_tf, keep,
                         *([S.as_text("Total")] if name else [])],
        calcs=("lastNotNull",), steps=steps, unit=unit, decimals=decimals, value_size=54,
        time_from=None, mdp=None, description=description, values=bool(name),
        overrides=[S.col_props(field, displayName=name)] if name else None,
    )
    if name:
        p["options"].update(textMode="value_and_name", wideLayout=False)
        p["options"]["text"]["titleSize"] = 14
    return p


def build(cfg, datasource_uid="zabbix"):
    all_sites = S.site_group_re(cfg, ".*", raw=True)

    banner = S.banner("VISÃO GERAL", "NOC v3 · Zabbix", links=S.tv_links())
    online = _kpi_from_sites("HOSTS ONLINE", "Online", steps=S.steps(S.OK), name="${__data.fields.Total} monitorados",
                             description="Hosts das filiais alcançáveis agora (ping, SNMP ou agente).")
    offline = _kpi_from_sites("HOSTS OFFLINE", "Offline", steps=S.COUNT_BAD, name="de ${__data.fields.Total} hosts",
                              description="Hosts das filiais sem nenhuma verificação de disponibilidade OK.")
    avail = _kpi_from_sites("DISPONIBILIDADE", "Global", steps=S.AVAIL_RATIO, unit="percentunit", decimals=1,
                            extra_tf=[S.calc_binary("Online", "/", "Total", "Global")],
                            description="Hosts online / hosts monitorados nas filiais.")
    wifi = S.kpi(
        "CLIENTES WI-FI",
        [S.target(r"/^Wireless: Connected clients$/", S.alias("$__zbx_host_name"), group=all_sites, host="/.*/")],
        transformations=[S.reduce_rows(("lastNotNull",)), S.reduce_fields(("sum",))],
        steps=S.NEUTRAL, decimals=0, value_size=54, display_name="nos 16 APs",
        description="Total de dispositivos conectados aos Access Points UniFi agora.",
    )
    wifi["fieldConfig"]["defaults"]["color"] = {"mode": "fixed", "fixedColor": S.ACCENT}
    wifi["options"].update(textMode="value_and_name", wideLayout=False)
    wifi["options"]["text"]["titleSize"] = 14

    problems_kpi = S.stat(
        "PROBLEMAS ATIVOS POR SEVERIDADE", [S.triggers_target(group=all_sites, min_severity=2)],
        transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
        text_mode="value_and_name", color_mode="value", value_size=46, title_size=13,
        steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None,
        description="Triggers em problema agora nos hosts das filiais (sem dependentes), por severidade.",
    )

    site_dims = [{
        "name": s["label"], "group": s["group"],
        "link": S.dashboard_url(TOPOLOGY_KEY, keep_time=False, site=s["key"]),
    } for s in S.sites(cfg)]
    cat_dims = [{
        "name": c["title"], "group": c["group"],
        "link": S.dashboard_url(c["key"], keep_time=False),
    } for c in S.categories(cfg)]
    sites = _health_tiles(
        "SAÚDE POR FILIAL", site_dims, SITES_PANEL_ID,
        "Hosts online / total por filial. Clique para abrir a Topologia da Rede v3 filtrada na filial.",
        link_title="Abrir Topologia · ${__data.fields.dim}",
    )
    cats = _health_tiles(
        "SAÚDE POR CATEGORIA", cat_dims, 11,
        "Hosts online / total por tipo de equipamento. Clique para abrir o dashboard v3 da categoria.",
    )

    feed = S.problems("PROBLEMAS ATIVOS", [S.problems_target(group=all_sites, host="/.*/", min_severity=2)],
                      page_size=14, font_size="115%", layout="table")
    latency = S.bargauge(
        "LATÊNCIA ICMP · 8 PIORES (MÉDIA 15 MIN)",
        [S.target("ICMP response time", S.top(8, "avg"), S.alias("$__zbx_host_name"),
                  group=all_sites, host="/.*/")],
        calcs=("mean",), rank=True, unit="s", min=0, max=0.15, steps=S.LATENCY_S, mode="gradient", bar_height=26,
        name_placement="left", value_size=16, title_size=13, decimals=1,
        description="Média dos últimos 15 minutos do tempo de resposta ICMP, maiores primeiro.",
    )
    loss = S.timeseries(
        "PERDA DE PACOTES ICMP · 5 PIORES",
        [S.target("ICMP loss", S.group_by("5m", "avg"), S.top(5, "max"), S.alias("$__zbx_host_name"),
                  group=all_sites, host="/.*/")],
        unit="percent", legend="list", color=S.COLOR_SHADES, fill=25, steps=S.LOSS_PCT,
        thresholds_style="dashed", axis_soft_min=0, min=0, max=100,
        description="Perda de pacotes ICMP (média de 5 min) dos 5 hosts com o maior pico no período.",
    )

    panels = S.grid(
        (4, [(banner, 5), (online, 3), (offline, 2), (avail, 3), (wifi, 3), (problems_kpi, 8)]),
        (6, [(sites, 10), (cats, 14)]),
        (17, [(feed, 14), (S.stack((latency, 9), (loss, 8)), 10)]),
    )
    return S.dashboard(
        KEY, "Visão Geral", panels, datasource_uid=datasource_uid, tv=True,
        time_from="now-6h", range_cap="2d",
        description=(
            "Painel NOC v3 para TV 1920x1080: saúde global, clientes Wi-Fi, filiais, categorias e problemas ativos."
        ),
    )

