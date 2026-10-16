"""Hardware dos servidores (Dell iDRAC) v3: enriched with real ICMP ping reachability alongside SNMP."""
import json

from ..grafana_v2 import server_hardware as _v2
from . import style as S

KEY = "server-hardware"
TITLE = "Hardware dos Servidores"

COMPONENTS_V3 = [
    *_v2.COMPONENTS,
    ("Ping", "ICMP ping", _v2.AVAIL_CODES, S.AVAIL_STEPS, ()),
]


def _matrix():
    targets = []
    for name, item, _, _, worse in COMPONENTS_V3:
        targets += _v2.status_targets(item, name, worse, len(targets))
    columns = [_v2.host_column("Servidor", 145, [S.data_link("Filtrar por ${__value.text}", S.dashboard_url(KEY, host="${__value.raw}"))])]
    for name, _, codes, steps, worse in COMPONENTS_V3:
        columns += _v2._status_column(name, codes, steps, worse)
    order = _v2.worst_first(("Ping", False), ("SNMP", False), ("Geral", True), ("Sensores", True))
    p = S.table(
        "MATRIZ DE SAÚDE DOS COMPONENTES (SNMP + PING ICMP)", targets, id=_v2.MATRIX_ID,
        columns=columns, cell_height="sm", time_from=_v2.IDRAC_WINDOW, mdp=30,
        transformations=_v2.matrix_transforms([c[0] for c in COMPONENTS_V3]) + order,
        description="Pior estado de cada componente por iDRAC (últimas 24h), incluindo agora Ping ICMP real "
                    "além do agente SNMP para diferenciar falha física de rede de falha do daemon SNMP.",
    )
    p["fieldConfig"]["defaults"]["custom"]["minWidth"] = 68
    p["fieldConfig"]["defaults"]["noValue"] = _v2.NO_DATA
    return p


def build(cfg, datasource_uid="zabbix"):
    d = _v2.build(cfg, datasource_uid=datasource_uid)
    cat = next(c for c in S.categories(cfg) if c["key"] == KEY)
    panels = []
    for p in d["panels"]:
        if p.get("id") == _v2.MATRIX_ID:
            m = _matrix()
            m["gridPos"] = p["gridPos"]
            panels.append(m)
        else:
            # Update v2 host links inside tables to point to v3
            txt = json.dumps(p).replace(f"/d/autodiscovery-{KEY}-v2", f"/d/{S.uid(KEY)}")
            panels.append(json.loads(txt))
    return S.dashboard(
        KEY, TITLE, panels, datasource_uid=datasource_uid, range_cap="7d", time_from="now-1d",
        variables=S.category_variables(cat["group"]),
        description="Saúde do hardware dos servidores Dell pelo iDRAC (v3): componentes, fontes, discos, "
                    "temperaturas, ventoinhas e conectividade ICMP + SNMP.",
    )

