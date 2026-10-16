import json
import re

from zabbix_autodiscovery import topology
from zabbix_autodiscovery.topology import build_topology_dashboard


def _metric_targets(db):
    for p in db["panels"]:
        if p["type"].endswith("triggers-panel"):
            continue
        for t in p["targets"]:
            yield p, t


def _embedded(code, name):
    m = re.search(rf"const {name} = (\[.*?\]);\n", code, re.S)
    return json.loads(m.group(1))


def test_targets_have_explicit_filters_and_no_trends():
    db = build_topology_dashboard()
    names = {v["name"] for v in db["templating"]["list"]}
    assert names == {"datasource", "site", "site_hosts"}
    for p, t in _metric_targets(db):
        assert "$group" not in t["group"]["filter"] and "$host" not in t["host"]["filter"], p["title"]
        assert t["options"]["useTrends"] == "false"
        assert t["datasource"]["uid"] == "${datasource}"
        assert "top(" not in json.dumps(t["functions"])


def test_site_variable_is_a_regex_and_site_hosts_hidden():
    db = build_topology_dashboard()
    v = {x["name"]: x for x in db["templating"]["list"]}
    assert v["site"]["includeAll"] and v["site"]["allValue"] == ".*"
    assert {o["value"] for o in v["site"]["options"]} == {"$__all", "Barueri", "RJ", "BA", "PR"}
    assert v["site_hosts"]["hide"] == 2 and v["site_hosts"]["query"]["group"] == r"/^Filiais\/$site$/"
    assert db["refresh"] == "1m"
    alerts = next(p for p in db["panels"] if p["type"].endswith("triggers-panel"))
    assert alerts["targets"][0]["group"]["filter"] == r"/^Filiais\/$site$/"
    assert alerts["options"]["pageSize"] == 10


def test_kpi_sums_hosts_instead_of_counting_points():
    kpi = build_topology_dashboard()["panels"][0]
    assert kpi["options"]["reduceOptions"]["calcs"] == ["lastNotNull"]
    assert kpi["timeFrom"] == "5m"
    aliases = [t["functions"][-1]["params"][0] for t in kpi["targets"]]
    assert aliases == ["Online", "Total", "Offline"]
    assert all(t["functions"][-2]["def"]["name"] == "sumSeries" for t in kpi["targets"])


def test_map_reads_live_status_per_host():
    p = next(p for p in build_topology_dashboard()["panels"] if p["id"] == 4)
    code = p["options"]["getOption"]
    assert "context.panel.data.series" in code
    assert "● ONLINE" not in code
    assert p["targets"][0]["item"]["filter"] == topology.AVAIL_RE
    nodes, links = _embedded(code, "allNodes"), _embedded(code, "allLinks")
    ids = {n["id"] for n in nodes}
    assert all(n["hosts"] and n["siteKey"] in {"Barueri", "RJ", "BA", "PR"} for n in nodes)
    assert all(lk["source"] in ids and lk["target"] in ids for lk in links)
    assert not re.search(r"__NODES__|__LINKS__", code)


def test_shared_items_are_limited_to_category_and_site_hosts():
    panels = {p["id"]: p for p in build_topology_dashboard()["panels"]}
    for pid, group in ((5, r"/^Servidores\/.*$/"), (6, r"/^Rede\/Firewalls$/"), (7, r"/^Infra\/.*$/")):
        for t in panels[pid]["targets"]:
            assert t["group"]["filter"] == group and t["host"]["filter"] == "/^$site_hosts$/"


def test_map_separates_reachability_from_agent_state():
    # Ping/SNMP decide up/down; a down agent on a pingable host is 'partial', not OFFLINE,
    # and the tooltip lists each check per host (verified in QuickJS against a saved ds/query).
    code = next(p for p in build_topology_dashboard()["panels"] if p["id"] == 4)["options"]["getOption"]
    assert "hostStatus" not in code and "ok === false || (prev" not in code
    assert "state = agentDown ? 'partial' : 'up'" in code
    assert "CHECK_NAMES = { ping: 'ping', snmp: 'SNMP', agent: 'agente' }" in code
    assert "m.checks" in code


def _replace_alias(fn, alias):
    """Python equivalent of the plugin replaceAlias(/re/flags, repl) on an alias."""
    pattern, repl = fn["params"]
    body, flags = pattern[1:].rsplit("/", 1)
    return re.sub(body, repl.replace("$1", r"\1"), alias, flags=re.I if "i" in flags else 0)


def test_wan_aliases_are_shortened():
    # replaceAlias runs after setAlias("$__zbx_host_name: $__zbx_item"), so it sees the host prefix
    panels = {p["id"]: p for p in build_topology_dashboard()["panels"]}
    cases = [(panels[2]["targets"][0], "FW-SP: Interface wan1(MEGA): Operational status", "FW-SP - wan1(MEGA)"),
             (panels[3]["targets"][0], "FW-BA: Interface a(NET FIBER 30Mbps): Bits received",
              "FW-BA - a(NET FIBER 30Mbps) (In)"),
             (panels[3]["targets"][1], "FW-SP: Interface wan2: Bits sent", "FW-SP - wan2 (Out)")]
    for t, alias, expected in cases:
        fns = t["functions"]
        assert fns[0]["params"] == ["$__zbx_host_name: $__zbx_item"]
        assert "$__zbx" not in fns[1]["params"][1]
        assert _replace_alias(fns[1], alias) == expected
