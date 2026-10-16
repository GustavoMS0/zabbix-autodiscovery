"""Visão Geral: the NOC TV wall (1920x1080 kiosk, one screen, no scroll) and the reference implementation
of the v2 style.

Layout (TV_HEIGHT = 27 grid units):
  y0  h4   banner | hosts online | offline | disponibilidade | problemas por severidade
  y4  h6   saúde por filial (tiles -> both topology prototypes) | saúde por categoria (tiles -> dashboards v2)
  y10 h17  problemas ativos (live feed) | pior latência ICMP + perda de pacotes

Host health is computed once per tile set (style.health_targets/health_transforms): every host counts once
with its best availability check, so iDRACs (SNMP only) and servers (agent only) are included. The KPI
tiles reuse the site panel's data through the "-- Dashboard --" datasource: no extra Zabbix query.
"""
import json

from . import style as S

KEY = "overview"
SITES_PANEL_ID = 10         # source of the KPI tiles (dashboard_target)
# Site tiles open the topology. Both prototypes are offered until the user picks one: B (ECharts) filters
# by site (?var-site), A (Canvas) is one global map.
TOPOLOGY_SITE_KEY = "topology-echarts"
TOPOLOGY_GLOBAL_KEY = "topology-canvas"


def _health_tiles(title, dims, panel_id, description, link_title="Abrir ${__data.fields.dim}", extra_links=()):
    """One background tile per site/category: name and online/total in the title, availability % as the
    value, the tile links to the dashboard in the dim's "link" (alias JSON)."""
    targets = S.health_targets(dims)
    return S.stat(
        title, targets, id=panel_id, description=description,
        values=True, calcs=("lastNotNull",),
        color_mode="background", text_mode="value_and_name", wide=False, orientation="auto",
        title_size=14, value_size=34, min_width=170, min_height=70,
        steps=S.as_fill(S.AVAIL_RATIO),
        mappings=S.no_data_map(color=S.FILL_UNKNOWN),
        time_from=S.HEALTH_WINDOW, mdp=20,
        # only Disponibilidade stays numeric (drawn); the others feed the tile name
        transformations=[*S.health_transforms(), S.as_text("Online", "Total", "Offline")],
        # the name of each row's tile: dim, Online and Total are fields of the same row. An override,
        # because the calculated field carries its own display name (beats the panel defaults)
        # (unit on the drawn field only: the name template formats the other fields with their own unit)
        overrides=[S.col_props("Disponibilidade", unit="percentunit", decimals=0,
                               displayName="${__data.fields.dim} · ${__data.fields.Online}/${__data.fields.Total}")],
        # TV: the target opens with its own default range (the overview's 7h tile window means nothing there)
        # more than one link: Grafana opens a small menu on click
        links=[S.data_link(link_title, "${__data.fields.link}"), *extra_links],
    )


def _kpi_from_sites(title, field, *, steps, unit=None, decimals=0, description=None, extra_tf=(), name=None):
    """KPI tile computed from the raw data of the site panel: health table, summed over the sites.
    name: small caption under the number, a display name template over the same row (e.g.
    "de ${__data.fields.Total}"; Total then stays as text, not drawn)."""
    keep = S.filter_fields(f"^({field}|Total)$" if name else f"^{field}$")
    p = S.kpi(title, [S.dashboard_target(SITES_PANEL_ID, with_transforms=False)],
              datasource=dict(S.DASHBOARD_DS),
              transformations=[*S.health_transforms(), S.reduce_fields(("sum",)), *extra_tf, keep,
                               *([S.as_text("Total")] if name else [])],
              calcs=("lastNotNull",), steps=steps, unit=unit, decimals=decimals, value_size=60,
              time_from=None, mdp=None, description=description, values=bool(name),
              overrides=[S.col_props(field, displayName=name)] if name else None)
    if name:
        p["options"].update(textMode="value_and_name", wideLayout=False)
        p["options"]["text"]["titleSize"] = 14
    return p


def build(cfg, datasource_uid="zabbix"):
    all_sites = S.site_group_re(cfg, ".*", raw=True)

    # --- KPI strip ---------------------------------------------------------------------------------
    banner = S.banner("VISÃO GERAL", "NOC · Zabbix", links=S.tv_links())
    online = _kpi_from_sites("HOSTS ONLINE", "Online", steps=S.steps(S.OK), name="${__data.fields.Total} monitorados",
                             description="Hosts das filiais alcançáveis agora (ping, SNMP ou agente).")
    offline = _kpi_from_sites("HOSTS OFFLINE", "Offline", steps=S.COUNT_BAD, name="de ${__data.fields.Total} hosts",
                              description="Hosts das filiais sem nenhuma verificação de disponibilidade OK.")
    avail = _kpi_from_sites("DISPONIBILIDADE", "Global", steps=S.AVAIL_RATIO, unit="percentunit", decimals=1,
                            extra_tf=[S.calc_binary("Online", "/", "Total", "Global")],
                            description="Hosts online / hosts monitorados nas filiais.")
    # per-site trigger counts summed: the site groups are disjoint, so no problem counts twice
    problems_kpi = S.stat("PROBLEMAS ATIVOS POR SEVERIDADE", [S.triggers_target(group=all_sites, min_severity=2)],
                          transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
                          text_mode="value_and_name", color_mode="value", value_size=50, title_size=14,
                          steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None,
                          description="Triggers em problema agora nos hosts das filiais (sem dependentes), "
                                      "por severidade.")

    # --- health tiles ------------------------------------------------------------------------------
    site_dims = ([{"name": s["label"], "group": s["group"],
                             "link": S.dashboard_url(TOPOLOGY_SITE_KEY, keep_time=False, site=s["key"])}
                            for s in S.sites(cfg)])
    cat_dims = ([{"name": c["title"], "group": c["group"],
                            "link": S.dashboard_url(c["key"], keep_time=False)}
                           for c in S.categories(cfg)])
    sites = _health_tiles("SAÚDE POR FILIAL", site_dims, SITES_PANEL_ID,
                          "Hosts online / total por filial. Clique para abrir a topologia: protótipo B "
                          "(ECharts) só da filial ou protótipo A (Canvas) com todas.",
                          link_title="Topologia · protótipo B (ECharts) · ${__data.fields.dim}",
                          extra_links=[S.data_link("Topologia · protótipo A (Canvas)",
                                                   S.dashboard_url(TOPOLOGY_GLOBAL_KEY, keep_time=False))])
    cats = _health_tiles("SAÚDE POR CATEGORIA", cat_dims, 11,
                         "Hosts online / total por tipo de equipamento. Clique para abrir o dashboard.")

    # --- live problems + ICMP --------------------------------------------------------------------
    feed = S.problems("PROBLEMAS ATIVOS", [S.problems_target(group=all_sites, host="/.*/", min_severity=2)],
                      page_size=14, font_size="115%", layout="table")
    latency = S.bargauge(
        "LATÊNCIA ICMP · 8 PIORES (MÉDIA 15 MIN)",
        [S.target("ICMP response time", S.top(8, "avg"), S.alias("$__zbx_host_name"),
                  group=all_sites, host="/.*/")],
        calcs=("mean",), rank=True, unit="s", min=0, max=0.15, steps=S.LATENCY_S, mode="gradient", bar_height=26,
        name_placement="left", value_size=16, title_size=13, decimals=1,
        description="Média dos últimos 15 minutos do tempo de resposta ICMP, maiores primeiro.")
    loss = S.timeseries(
        "PERDA DE PACOTES ICMP · 5 PIORES",
        [S.target("ICMP loss", S.group_by("5m", "avg"), S.top(5, "max"), S.alias("$__zbx_host_name"),
                  group=all_sites, host="/.*/")],
        unit="percent", legend="list", color=S.COLOR_SHADES, fill=25, steps=S.LOSS_PCT,
        thresholds_style="dashed", axis_soft_min=0, min=0, max=100,
        description="Perda de pacotes ICMP (média de 5 min) dos 5 hosts com o maior pico no período.")

    panels = S.grid(
        (4, [(banner, 5), (online, 3), (offline, 3), (avail, 4), (problems_kpi, 9)]),
        (6, [(sites, 10), (cats, 14)]),
        (17, [(feed, 14), (S.stack((latency, 9), (loss, 8)), 10)]),
    )
    return S.dashboard(KEY, "Visão Geral", panels, datasource_uid=datasource_uid, tv=True,
                       time_from="now-6h", range_cap="2d",
                       description="Painel NOC para TV 1920x1080: saúde global, filiais, categorias e "
                                   "problemas ativos.")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.overview config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
