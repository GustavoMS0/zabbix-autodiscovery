import json
import re

import pytest

from zabbix_autodiscovery import dashboards, provision
from zabbix_autodiscovery.cli import build_parser
from zabbix_autodiscovery.config import ConfigError, category_groups, in_network, load_config, site_for


def test_sites_are_normalized(example_config):
    assert example_config["scan"]["networks"] == ["192.168.0.0/24", "192.168.10.0/24", "192.168.20.0/24"]
    assert site_for(example_config, "192.168.10.9") == {
        "network": "192.168.10.0/24", "site": "Branch-01", "proxy": "proxy-branch-01"}


def test_env_file_is_loaded(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTODISCOVERY_TEST_TOKEN", raising=False)
    (tmp_path / ".env").write_text("AUTODISCOVERY_TEST_TOKEN=abc\n")
    (tmp_path / "config.yaml").write_text(
        "zabbix: {url: http://z, token: '${AUTODISCOVERY_TEST_TOKEN}'}\nscan: {networks: [10.0.0.0/30]}\n")
    assert load_config(tmp_path / "config.yaml")["zabbix"]["token"] == "abc"


@pytest.mark.parametrize("secret", ["abc#def", "&anchor", "*alias", "!tag", "{x: 1}", "0123", "a: b", "'q"])
def test_env_values_are_not_reparsed_as_yaml(tmp_path, monkeypatch, secret):
    monkeypatch.setenv("AUTODISCOVERY_TEST_SECRET", secret)
    (tmp_path / "config.yaml").write_text(
        "zabbix:\n  url: http://z\n  token: ${AUTODISCOVERY_TEST_SECRET}\n"
        "scan:\n  networks: [10.0.0.0/30]\n"
        "snmp_credentials:\n  - {name: c, version: 2c, community: 'pre-${AUTODISCOVERY_TEST_SECRET}'}\n")
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg["zabbix"]["token"] == secret
    assert cfg["snmp_credentials"][0]["community"] == f"pre-{secret}"


def test_unset_env_value_is_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTODISCOVERY_TEST_UNSET", raising=False)
    (tmp_path / "config.yaml").write_text(
        "zabbix:\n  url: http://z\n  token: ${AUTODISCOVERY_TEST_UNSET}\n  user: u${AUTODISCOVERY_TEST_UNSET}\n"
        "scan:\n  networks: [10.0.0.0/30]\n")
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg["zabbix"]["token"] is None and cfg["zabbix"]["user"] == "u"


def test_rule_without_action_defaults_to_review(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "zabbix: {url: http://z}\nscan: {networks: [10.0.0.0/30]}\n"
        "rules: [{name: r, category: cam, group: Cameras, match: {snmp: true}}]\n")
    assert category_groups(load_config(tmp_path / "config.yaml")) == {"cam": "Cameras"}


def test_invalid_action_is_rejected(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "zabbix: {url: http://z}\nscan: {networks: [10.0.0.0/30]}\n"
        "rules: [{name: r, category: c, match: {snmp: true}, action: maybe}]\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "config.yaml")


def test_in_network():
    assert in_network("10.0.0.0/24", "10.0.0.7")
    assert in_network("10.0.1.1-10.0.1.9", "10.0.1.5")
    assert not in_network("10.0.1.1-10.0.1.9", "10.0.0.7")
    assert not in_network("10.0.0.0/24", "{#MACRO}")


def test_zabbix_iprange():
    assert provision.zabbix_iprange("192.168.0.100-192.168.0.199") == "192.168.0.100-199"
    with pytest.raises(ValueError):
        provision.zabbix_iprange("10.0.0.1-10.0.1.1")


def test_resolve_templates():
    ids, missing = provision.resolve_templates("A|B,C,D", {"B": "2", "C": "3"})
    assert ids == ["2", "3"] and missing == ["D"]


def test_grafana_dashboards_follow_config_groups(example_config):
    group = category_groups(example_config)["switch"]
    spec = next(s for s in dashboards.SPECS if s["key"] == "switches")
    dash = dashboards.grafana_dashboard(spec, example_config)
    assert dash["uid"] == "autodiscovery-switches"
    assert group.replace("/", "\\/") in dash["templating"]["list"][1]["allValue"]
    panels_text = json.dumps(dash["panels"])
    assert "${datasource}" in panels_text and '"uid": "zabbix"' not in panels_text
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids))
    assert all(p["gridPos"]["x"] + p["gridPos"]["w"] <= 24 for p in dash["panels"])


def _targets(dash):
    return [t for p in dash["panels"] for t in p.get("targets", []) if t.get("queryType") == "0"]


def _panel(dash, title):
    return next(p for p in dash["panels"] if p["title"] == title)


def test_targets_avoid_trends_and_stats_query_a_short_window(example_config):
    for spec in dashboards.SPECS:
        dash = dashboards.grafana_dashboard(spec, example_config)
        assert dash["refresh"] == "5m"
        assert next(v for v in dash["templating"]["list"] if v["name"] == "host")["refresh"] == 1
        for t in _targets(dash):
            # trend.get of plugin 6.9 fails on Zabbix 8.0: history only
            assert t["options"] == {"showDisabledItems": False, "skipEmptyValues": True,
                                    "disableDataAlignment": True, "useTrends": "false"}
        for p in dash["panels"]:
            if p["type"] in ("stat", "bargauge"):
                assert p["timeFrom"] and p["hideTimeOverride"] and p["maxDataPoints"] == 100
            elif p["type"] == "timeseries":
                assert p["maxDataPoints"] <= 500


def test_target_accepts_explicit_filters():
    t = dashboards._target("ICMP ping", group="/^Filiais\\/BA$/", host="/.*/")
    assert t["group"]["filter"] == "/^Filiais\\/BA$/" and t["host"]["filter"] == "/.*/"
    assert dashboards._target("x")["group"]["filter"] == "$group"
    assert dashboards._top(10, "max")["params"] == [10, "max"] and dashboards._top(5)["text"] == "top(5, avg)"


@pytest.mark.parametrize("name, ok", [
    ("CPU utilization", True), ("Level 1 Virtual Module #1: CPU utilization", True),
    ("CPU Core 3: Average usage over 1min", False), ("HA 1: CPU usage", False),
    ("Load average (1m avg)", False), ("CPU user time", False),
])
def test_cpu_regex_is_utilization_only(name, ok):
    assert bool(_regex(dashboards.CPU["re"]).search(name)) is ok


@pytest.mark.parametrize("name, ok", [
    ("Probe [CPU1 Temp]: Value", True), ("Bateria: Temperatura", True), ("CPU: Temperature", True),
    ("Sensor MV1514 Temperature: Value", True), ("Probe [CPU1 Temp]: Status", False),
    ("Sensor MV1514 Temperature: Alarm status", False), ("Bateria: Tempo restante estimado", False),
])
def test_temperature_regex_skips_status_and_runtime(name, ok):
    assert bool(_regex(dashboards.TEMP["re"]).search(name)) is ok


@pytest.mark.parametrize("name, ok", [
    ("Interface Gi1/0/1(): Bits received", True), ("Interface wan1(Link Primário 50Mbps): Bits received", True),
    ("Interface Unit 1 Port 20(): Bits received", True), ("Interface LAG 1(): Bits received", False),
    ("Interface Vlan interface 1(Vlan interface): Bits received", False),
    ("Interface ssl.root(): Bits received", False),
    ("Interface VPN-FGFM_MGMT(): Bits received", False), ("Interface fortilink(): Bits received", False),
    ("Interface Loopback-SDWAN(): Bits received", False), ("Interface eth0.40(): Bits received", False),
    ("Interface Gi1(): Bits sent", False),
])
def test_traffic_regex_keeps_physical_interfaces(name, ok):
    assert bool(_regex(dashboards.TRAFFIC_IN["re"]).search(name)) is ok


def test_other_fixed_regexes():
    assert _regex(dashboards.UPTIME["re"]).search("Uptime (network)")
    assert not _regex(dashboards.UPTIME["re"]).search("Uptime (hardware)")
    assert _regex(dashboards.SUPPLIES["re"]).search("Supply [Drum Unit]: Level %")
    assert not _regex(dashboards.SUPPLIES["re"]).search("Supply [Drum Unit]: Level")
    loss = _regex(dashboards.SDWAN_LOSS["re"])
    assert loss.search("SD-WAN [CTI_SLA_WAN]:[a]: Packets loss")
    assert not loss.search("SD-WAN [CTI_SLA_WAN]:[a]: Packets sent per second")
    agent = _regex(dashboards.AGENT_STATUS_RE)
    assert agent.search("Zabbix agent availability") and agent.search(dashboards.AGENT_PORT_ITEM)


def _regex(text):
    """Grafana-Zabbix /pattern/flags -> Python regex."""
    body, _, flags = text[1:].rpartition("/")
    return re.compile(body, re.I if "i" in flags else 0)


def test_availability_maps_unknown_and_follows_the_spec(example_config):
    assert dashboards.UP_DOWN[0]["options"]["2"]["text"] == "UNKNOWN"
    assert dashboards.RED_GREEN[-1] == {"color": dashboards.UNKNOWN_COLOR, "value": 2}
    hw = next(s for s in dashboards.SPECS if s["key"] == "server-hardware")
    dash = dashboards.grafana_dashboard(hw, {**example_config, "rules": [
        {"name": "r", "category": "server-hardware", "group": "Infra/HW", "match": {"snmp": True}}]})
    avail = _panel(dash, "Availability")
    assert avail["targets"][0]["item"]["filter"] == "/^SNMP agent availability$/" and avail["timeFrom"] == "24h"


def test_firewall_panels(example_config):
    spec = next(s for s in dashboards.SPECS if s["key"] == "firewalls")
    dash = dashboards.grafana_dashboard(spec, example_config)
    assert _panel(dash, "SD-WAN Links Latency")["fieldConfig"]["defaults"]["unit"] == "ms"
    vpn = _panel(dash, "VPN tunnel status")
    assert vpn["type"] == "stat" and vpn["fieldConfig"]["defaults"]["mappings"] == dashboards.VPN_MAP
    assert [f["def"]["name"] for f in vpn["targets"][0]["functions"]] == ["setAlias", "replaceAlias"]


def _replace_alias(fn, alias):
    """Python equivalent of the plugin replaceAlias(/re/flags, repl) on an alias."""
    pattern, repl = fn["params"]
    body, flags = pattern[1:].rsplit("/", 1)
    return re.sub(body, repl.replace("$1", r"\1"), alias, flags=re.I if "i" in flags else 0)


@pytest.mark.parametrize("title, alias, expected", [
    ("WAN Links Operational Status", "FW-SP: Interface wan1(MEGA): Operational status", "FW-SP - wan1(MEGA)"),
    ("Internet Links / WAN Inbound Traffic", "FW-BA: Interface a(NET FIBER 30Mbps): Bits received",
     "FW-BA - a(NET FIBER 30Mbps)"),
    ("VPN tunnel status", "FW-SP: VPN BAR-NET-AMER: Tunnel Status", "FW-SP: BAR-NET-AMER"),
])
def test_firewall_aliases_are_shortened(example_config, title, expected, alias):
    # replaceAlias runs after setAlias("$__zbx_host_name: $__zbx_item"), so it sees the host prefix
    spec = next(s for s in dashboards.SPECS if s["key"] == "firewalls")
    fns = _panel(dashboards.grafana_dashboard(spec, example_config), title)["targets"][0]["functions"]
    assert fns[0]["params"] == ["$__zbx_host_name: $__zbx_item"]
    assert _replace_alias(next(f for f in fns if f["def"]["name"] == "replaceAlias"), alias) == expected


def test_heavy_panels_warn_about_long_ranges(example_config):
    heavy = {"switches": {"Inbound traffic (top 10 interfaces)", "Outbound traffic (top 10 interfaces)",
                          "Inbound errors & discards (top 10 each)"},
             "overview": {"ICMP latency (worst 10)", "ICMP packet loss (worst 10)"},
             "server-hardware": {"Fans"},
             # ~16-18 hosts at 30 s polling: ~322k-360k rows in 7 days
             "printers": {"ICMP latency"},
             "access-points": {"Uplink traffic in (eth0)", "Uplink traffic out (eth0)", "Interface errors (top 10)",
                               "ICMP latency", "CPU Load average (1m)"}}
    for key, titles in heavy.items():
        spec = next(s for s in dashboards.SPECS if s["key"] == key)
        for p in dashboards.grafana_dashboard(spec, example_config)["panels"]:
            noted = dashboards.LONG_RANGE_NOTE in p.get("description", "")
            assert noted == (p["title"] in titles), p["title"]
    # an existing description is kept
    gauge = dashboards._grafana_panel({"kind": "gauge", "title": "x", "re": "/x/", "description": "Own text.",
                                       "heavy": True}, {"title": "t"})[0]
    assert gauge["description"] == "Own text. " + dashboards.LONG_RANGE_NOTE


def test_heavy_dashboards_cap_the_quick_ranges(example_config):
    # measured with all hosts: switches fail from 2d, the other heavy panels from 3d
    def last_range(key):
        dash = dashboards.grafana_dashboard(next(s for s in dashboards.SPECS if s["key"] == key), example_config)
        ranges = dash.get("timepicker", {}).get("quick_ranges")
        return ranges and ranges[-1]["from"]
    assert last_range("switches") == "now-1d"
    for key in ("overview", "firewalls", "access-points", "printers", "server-hardware"):
        assert last_range(key) == "now-2d", key
    assert last_range("servers") == "now-7d"     # explicit max_range: traffic fails at 30d
    assert last_range("ups") is None     # no heavy panel: Grafana defaults


def test_access_points_have_no_panel_without_items():
    # the UniFi client counters need a template that does not exist yet: no always-empty panel
    ap = next(s for s in dashboards.SPECS if s["key"] == "access-points")
    assert not any("client" in (p.get("title") or "").lower() for p in ap["panels"])


def test_network_panels_overrides():
    names = [p.get("title") for p in dashboards.network_panels(cpu=None)]
    assert "CPU" not in names and "Memory" in names
    assert {"kind": "latency"} not in dashboards.network_panels(latency=None)
    with pytest.raises(ValueError):
        dashboards.network_panels(signal=None)
    ap = next(s for s in dashboards.SPECS if s["key"] == "access-points")
    titles = [p.get("title") for p in ap["panels"]]
    assert "CPU load (1m)" in titles and "CPU" not in titles and "Signal / noise" not in titles


def test_switch_errors_and_discards_are_separate_queries(example_config):
    spec = next(s for s in dashboards.SPECS if s["key"] == "switches")
    dash = dashboards.grafana_dashboard(spec, example_config)
    panel = next(p for p in dash["panels"] if p["title"].startswith("Inbound errors & discards"))
    assert [t["refId"] for t in panel["targets"]] == ["A", "B"]
    assert all(t["functions"][0]["text"] == "top(10, max)" for t in panel["targets"])


def test_overview_latency_shows_the_worst_hosts(example_config):
    spec = next(s for s in dashboards.SPECS if s["key"] == "overview")
    dash = dashboards.grafana_dashboard(spec, example_config)
    fns = [f["text"] for f in _panel(dash, "ICMP latency (worst 10)")["targets"][0]["functions"]]
    assert fns == ["groupBy(5m, avg)", "top(10, max)", "setAlias($__zbx_host_name)"]


class _GroupsAPI:
    def __init__(self, counts=None, fail=False):
        self.counts, self.fail = counts or {}, fail

    def call(self, method, params):
        if self.fail:
            raise OSError("unreachable")
        if method == "hostgroup.get":
            return [{"groupid": g, "name": g} for g in self.counts if g in params["filter"]["name"]]
        # only enabled hosts are counted, like provision.setup_zabbix_dashboards
        assert method == "host.get" and params["filter"] == {"status": 0} and params["countOutput"]
        return str(self.counts[params["groupids"][0]])


def test_specs_with_empty_groups_are_skipped_only_when_zabbix_answers(example_config):
    groups = category_groups(example_config)
    offline = dashboards.specs_to_build(example_config)
    assert [s["key"] for s in offline] == [s["key"] for s in dashboards.SPECS
                                           if dashboards.groups_for(s, example_config)]
    assert dashboards.specs_to_build(example_config, _GroupsAPI(fail=True), log=lambda *_: None) == offline
    # the router group exists but holds only disabled hosts (0 enabled): no dashboard
    online = dashboards.specs_to_build(example_config, _GroupsAPI({groups["switch"]: 3, groups["router"]: 0}),
                                       log=lambda *_: None)
    assert [s["key"] for s in online] == ["overview", "switches"]


def test_grafana_dashboards_command_skips_empty_groups(tmp_path, example_config, monkeypatch):
    from zabbix_autodiscovery import cli

    out = tmp_path / "out"
    out.mkdir()

    monkeypatch.setattr(cli, "connect_optional", lambda cfg: _GroupsAPI({category_groups(cfg)["switch"]: 1}))
    (out / "autodiscovery-old.json").write_text("{}")
    cli.cmd_grafana_dashboards(example_config, build_parser().parse_args(
        ["grafana-dashboards", "-o", str(out)]))
    assert {p.name for p in out.iterdir()} == {"autodiscovery-overview.json", "autodiscovery-switches.json",
                                                    "autodiscovery-topology.json"}
    monkeypatch.setattr(cli, "connect_optional", lambda cfg: pytest.fail("--include-empty must not connect"))
    cli.cmd_grafana_dashboards(example_config, build_parser().parse_args(
        ["grafana-dashboards", "-o", str(out), "--include-empty"]))
    assert len(list(out.iterdir())) == len(dashboards.specs_to_build(example_config)) + 1


def test_init_writes_config_and_env(tmp_path, monkeypatch):
    from zabbix_autodiscovery.cli import cmd_init

    monkeypatch.chdir(tmp_path)
    cmd_init(build_parser().parse_args(["init"]))
    assert (tmp_path / "config.yaml").exists() and (tmp_path / ".env").exists()
    with pytest.raises(SystemExit):
        cmd_init(build_parser().parse_args(["init"]))


def test_cmd_diff(tmp_path, capsys):
    from zabbix_autodiscovery.cli import cmd_diff

    old_csv = tmp_path / "old.csv"
    new_csv = tmp_path / "new.csv"

    old_csv.write_text("ip;category;hostname;vendor;ports;sysname;rule\n"
                       "192.168.0.1;switch;SW01;Cisco;22,80;SW01;cisco\n"
                       "192.168.0.2;printer;PRN01;HP;9100;PRN01;printer\n", encoding="utf-8")
    new_csv.write_text("ip;category;hostname;vendor;ports;sysname;rule\n"
                       "192.168.0.1;switch;SW01;Cisco;22,80,443;SW01;cisco\n"
                       "192.168.0.3;firewall;FW01;Fortinet;443;FW01;fortigate\n", encoding="utf-8")

    class Args:
        old_file = str(old_csv)
        new_file = str(new_csv)

    cmd_diff(None, Args())
    captured = capsys.readouterr().out
    assert "New devices:          1" in captured
    assert "Removed devices:      1" in captured
    assert "Changed devices:      1" in captured
    assert "192.168.0.3" in captured
    assert "192.168.0.2" in captured
    assert "ports: '22,80' -> '22,80,443'" in captured


def test_zabbix_api_retry(monkeypatch):
    import requests

    from zabbix_autodiscovery.zabbix_api import ZabbixAPI

    attempts = 0

    class DummyResponse:
        def __init__(self, status_code, body):
            self.status_code = status_code
            self._body = body

        def json(self):
            return self._body

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(f"{self.status_code}")

    def fake_post(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return DummyResponse(502, {})
        return DummyResponse(200, {"result": "7.0.0"})

    monkeypatch.setattr(requests.Session, "post", fake_post)
    monkeypatch.setattr("time.sleep", lambda _: None)
    api = ZabbixAPI("http://dummy", token="test")
    assert api.version_str == "7.0.0"
    assert attempts == 2



def test_native_dashboards_skip_types_without_hosts(example_config):
    calls = []

    class API:
        version = (8, 0)

        def ensure_hostgroup(self, name):
            return "1"

        def call(self, method, params):
            calls.append(method)
            return []                     # no dashboard yet, no hosts in any group

    logged = []
    provision.setup_zabbix_dashboards(API(), example_config, log=logged.append)
    assert "dashboard.create" not in calls and "skipped (no hosts" in logged[-1]
    provision.setup_zabbix_dashboards(API(), example_config, log=logged.append, skip_empty=False)
    assert "dashboard.create" in calls
