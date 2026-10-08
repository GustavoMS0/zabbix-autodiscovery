import pytest

from zabbix_autodiscovery import dashboards, zbxdash


def _items(hosts, names, with_data=True):
    return [{"hostid": h, "name": n, "lastclock": "1700000000" if with_data else "0", "state": "0"}
            for h in hosts for n in names]


SWITCH_ITEMS = (_items(["1", "2", "3", "4", "5"], ["ICMP ping", "ICMP response time", "Uptime (network)",
                                           "Switch: Port usage", "Interface Gi1(): Bits received",
                                           "Interface Gi1(): Bits sent"])
                + _items(["1"], ["#1: CPU utilization"]))           # CPU on 1 of 5 hosts only (20%)


def _fields(widget):
    return {f["name"]: f["value"] for f in widget["fields"]}


def _build(key="switches", version=(8, 0), items=SWITCH_ITEMS, hosts=("sw-1", "sw-2", "sw-3", "sw-4", "sw-5"),
           agent=False):
    spec = next(s for s in dashboards.SPECS if s["key"] == key)
    return zbxdash.build(key, spec["title"], ["10"], version, items, list(hosts), agent)


@pytest.mark.parametrize("version, width", [((8, 0), 72), ((7, 0), 72), ((6, 4), 24), ((6, 0), 24)])
def test_layout_fits_the_grid_and_does_not_overlap(version, width):
    for spec in dashboards.SPECS:
        widgets = _build(spec["key"], version)
        cells = set()
        for w in widgets:
            assert 0 <= w["x"] and w["x"] + w["width"] <= width
            for x in range(w["x"], w["x"] + w["width"]):
                for y in range(w["y"], w["y"] + w["height"]):
                    assert (x, y) not in cells, f"overlap in {spec['key']}: {w['name']}"
                    cells.add((x, y))


def test_graphs_follow_the_host_navigator():
    widgets = _build()
    nav = next(w for w in widgets if w["type"] == "hostnavigator")
    ref = _fields(nav)["reference"]
    graphs = [w for w in widgets if w["type"] == "svggraph"]
    assert graphs and all(_fields(g)["override_hostid._reference"] == f"{ref}._hostid" for g in graphs)


def test_svggraph_datasets_have_the_required_fields():
    required = {"dataset_type", "hosts.0", "items.0", "color", "type", "stacked", "transparency", "axisy",
                "timeshift", "aggregate_function"}
    for g in (w for w in _build() if w["type"] == "svggraph"):
        f = _fields(g)
        assert {k[5:] for k in f if k.startswith("ds.0.")} >= required
        assert "groupids.0" not in f and "graph_time" not in f


def test_only_existing_metrics_are_used():
    widgets = _build()
    table = next(w for w in widgets if w["type"] == "tophosts")
    items = [v for k, v in _fields(table).items() if k.endswith(".item")]
    assert "Switch: Port usage" in items and "ICMP response time" in items
    assert not any("CPU" in i for i in items)                 # on 1 of 5 hosts: below MIN_COVERAGE
    titles = [w["name"] for w in widgets if w["type"] == "svggraph"]
    assert any(t.startswith("Traffic") for t in titles)
    assert not any(t.startswith("Temperature") for t in titles)   # no temperature item at all


def test_table_uses_the_right_host_limit_field_per_version():
    t8 = next(w for w in _build(version=(8, 0)) if w["type"] == "tophosts")
    t6 = next(w for w in _build(version=(6, 4)) if w["type"] == "tophosts")
    assert _fields(t8)["show_lines"] == 100 and "count" not in _fields(t8)
    assert _fields(t6)["count"] == 100


def test_zabbix_6_has_no_navigator_or_graphs():
    types = {w["type"] for w in _build(version=(6, 4))}
    assert "hostnavigator" not in types and "svggraph" not in types and "tophosts" in types


def test_availability_prefers_icmp_and_falls_back():
    assert zbxdash.Catalog(_items(["1", "2"], ["ICMP ping", "SNMP agent availability"])).best_availability() \
        == "ICMP ping"
    servers = _items(["1", "2", "3"], ["Zabbix agent ping"]) + _items(["1"], ["ICMP ping"])
    assert zbxdash.Catalog(servers).best_availability() == "Zabbix agent ping"
    assert zbxdash.Catalog(_items(["1"], ["ICMP ping"], with_data=False)).best_availability() is None


def test_localized_vendor_names_are_recognized():
    ups = _items(["1"], ["Bateria: Carga estimada restante", "Saida: Percentual de carga",
                         "Bateria: Tempo restante estimado", "Entrada: Tensao"])
    table = next(w for w in _build("ups", items=ups, hosts=["ups-1"]) if w["type"] == "tophosts")
    items = [v for k, v in _fields(table).items() if k.endswith(".item")]
    assert items == ["Bateria: Carga estimada restante", "Saida: Percentual de carga",
                     "Bateria: Tempo restante estimado", "Entrada: Tensao"]


def test_agent_missing_panel_and_empty_groups():
    widgets = _build("servers", items=_items(["1"], ["Zabbix agent ping"]), hosts=["srv"], agent=True)
    assert any(w["name"] == "Servers without Zabbix agent" for w in widgets)
    empty = _build("switches", items=[], hosts=[])
    assert {w["type"] for w in empty} == {"problemsbysv", "hostavail", "problems"}
