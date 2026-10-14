import argparse
import asyncio
import os
import sys

import pytest

from zabbix_autodiscovery import cli, noc, provision, scanner
from zabbix_autodiscovery.config import ConfigError, load_config, write_private
from zabbix_autodiscovery.zabbix_api import SECRET, ZabbixAPI, ZabbixError


class FakeAPI:
    """Records calls; answers from a {method: result or callable(params)} table."""
    version = (7, 0)

    def __init__(self, answers=None):
        self.answers, self.calls = answers or {}, []

    def call(self, method, params=None, auth=True):
        self.calls.append((method, params))
        answer = self.answers.get(method, [])
        return answer(params) if callable(answer) else answer

    def methods(self):
        return [m for m, _ in self.calls]


# ---------------------------------------------------------------- SNMPv3 protocols

def test_unknown_snmpv3_protocol_is_a_config_error(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "zabbix: {url: http://z}\nscan: {networks: [10.0.0.0/30]}\n"
        "snmp_credentials: [{name: v3, version: 3, user: u, auth_pass: x, auth_protocol: SHA1024}]\n")
    with pytest.raises(ConfigError, match="auth_protocol 'SHA1024'"):
        load_config(tmp_path / "config.yaml")


def test_build_interface_rejects_unknown_priv_protocol():
    cfg = {"snmp_credentials": [{"name": "v3", "version": "3", "user": "u", "auth_pass": "a",
                                 "priv_pass": "p", "priv_protocol": "3DES"}]}
    with pytest.raises(ValueError, match="priv_protocol '3DES'"):
        cli.build_interface({"ip": "10.0.0.1", "interface": "snmp", "snmp_cred": "v3"}, cfg, None)


def test_host_community_macro_is_secret():
    cfg = {"snmp_credentials": [{"name": "c", "version": "2c", "community": "other"}]}
    _, macros = cli.build_interface({"ip": "10.0.0.1", "interface": "snmp", "snmp_cred": "c"}, cfg, "public")
    assert macros == [{"macro": "{$SNMP_COMMUNITY}", "value": "other", "type": 1}]


# ---------------------------------------------------------------- secret global macro

def _bare_api(answers):
    api = ZabbixAPI.__new__(ZabbixAPI)
    fake = FakeAPI(answers)
    api.call = fake.call
    return api, fake


def test_global_community_macro_created_as_secret():
    api, fake = _bare_api({"usermacro.get": []})
    assert api.ensure_global_macro("{$SNMP_COMMUNITY}", "pub", secret=True) == "pub"
    assert ("usermacro.createglobal", {"macro": "{$SNMP_COMMUNITY}", "value": "pub", "type": 1}) in fake.calls


def test_plain_macro_with_same_value_becomes_secret_and_other_value_is_kept():
    api, fake = _bare_api({"usermacro.get": [{"globalmacroid": "9", "value": "pub", "type": "0"}]})
    assert api.ensure_global_macro("{$SNMP_COMMUNITY}", "pub", secret=True) == "pub"
    assert fake.calls[-1] == ("usermacro.updateglobal", {"globalmacroid": "9", "type": 1, "value": "pub"})
    api, fake = _bare_api({"usermacro.get": [{"globalmacroid": "9", "value": "old", "type": "0"}]})
    assert api.ensure_global_macro("{$SNMP_COMMUNITY}", "pub", secret=True) == "old"
    assert "usermacro.updateglobal" not in fake.methods()
    api, _ = _bare_api({"usermacro.get": [{"globalmacroid": "9", "type": "1"}]})
    assert api.global_macro("{$SNMP_COMMUNITY}") == SECRET


# ---------------------------------------------------------------- Grafana role

def test_grafana_role_uses_an_allow_list():
    api = FakeAPI({"role.create": {"roleids": ["5"]}, "usergroup.create": {"usrgrpids": ["6"]},
                   "user.create": {"userids": ["7"]}})
    provision.setup_grafana_user(api, {"grafana_user": {"username": "g", "password": "p"}}, log=lambda *_: None)
    params = next(p for m, p in api.calls if m == "role.create")
    assert params["rules"]["api.mode"] == 1
    assert "*.get" in params["rules"]["api"] and "apiinfo.version" in params["rules"]["api"]
    assert not any(m.endswith((".create", ".update", ".delete")) for m in params["rules"]["api"])


# ---------------------------------------------------------------- native discovery actions

def test_native_discovery_updates_before_deleting_stale_actions():
    actions = [{"actionid": "1", "name": "AutoDiscovery - fortigate"},
               {"actionid": "2", "name": "AutoDiscovery - removed-rule"}]
    api = FakeAPI({
        "drule.get": lambda p: [{"druleid": "3", "dchecks": [{"dcheckid": "4", "key_": scanner.SYS_OBJECTID}]}]
        if "druleids" in p else [],
        "drule.create": {"druleids": ["3"]},
        "action.get": actions,
        "action.create": {"actionids": ["8"]},
        "hostgroup.get": [{"groupid": "10"}],
    })
    api.ensure_hostgroup = lambda name: "10"
    api.template_ids = lambda: {}
    cfg = {"scan": {"networks": ["10.0.0.0/24"]},
           "snmp_credentials": [{"name": "c", "version": "2c", "community": "pub"}],
           "rules": [{"name": "fortigate", "category": "firewall", "action": "add",
                      "match": {"sysobjectid_prefix": ["1.3.6.1.4.1.12356"]}},
                     {"name": "cisco", "category": "switch", "action": "add",
                      "match": {"sysobjectid_prefix": ["1.3.6.1.4.1.9"]}},
                     {"name": "no-action", "category": "x", "match": {"sysobjectid_prefix": ["1.2"]}}]}
    provision.setup_native_discovery(api, cfg, log=lambda *_: None)
    methods = api.methods()
    assert methods.index("action.delete") > max(methods.index("action.update"), methods.index("action.create"))
    assert ("action.delete", ["2"]) in api.calls
    assert methods.count("action.create") == 1          # 'no-action' defaults to review: no action


# ---------------------------------------------------------------- check: discovery rule overlap

@pytest.mark.parametrize("iprange, expected", [
    ("192.168.1.1-254", True), ("192.168.1.0/24", True), ("192.168.10.0/24", False),
    ("10.0.0.1,192.168.1.50", True), ("192.168.0-3.1-254", True), ("192.168.11.1-254", False),
])
def test_ranges_overlap(iprange, expected):
    assert cli.ranges_overlap(["192.168.1.0/24"], iprange) is expected


def test_ranges_overlap_no_substring_false_positive():
    # "10.0.1" is a substring of "10.0.10.0/24" but the networks do not overlap
    assert not cli.ranges_overlap(["10.0.1.0/24"], "10.0.10.0/24")


# ---------------------------------------------------------------- scan size limit

def test_huge_networks_are_refused_unless_forced():
    assert scanner.count_targets(["10.0.0.0/16", "10.1.0.1-10.1.0.10", "10.2.0.1"]) == 65534 + 10 + 1
    with pytest.raises(ValueError, match="max_targets"):
        scanner.check_scan_size({"networks": ["10.0.0.0/8"]})
    assert scanner.check_scan_size({"networks": ["10.0.0.0/8"]}, force=True) == 2 ** 24 - 2
    with pytest.raises(ValueError):
        scanner.check_scan_size({"networks": ["10.0.0.0/24"], "max_targets": 100})


def test_cmd_scan_reports_size_error(tmp_path):
    cfg = {"scan": {"networks": ["10.0.0.0/8"]}, "_sites": []}
    args = argparse.Namespace(output=str(tmp_path / "x.csv"), delimiter=";", network=None, site=None)
    with pytest.raises(SystemExit, match="Scan not started"):
        cli.cmd_scan(cfg, args)


# ---------------------------------------------------------------- dependencies

def _host(hostid, name, category):
    return {"hostid": hostid, "name": name, "host": name, "tags": [{"tag": "type", "value": category}],
            "interfaces": [{"ip": f"10.0.0.{hostid}"}], "parentTemplates": [], "groups": []}


def test_dependencies_skip_redundant_gateways():
    hosts = [_host("1", "fw-a", "firewall"), _host("2", "fw-b", "firewall"), _host("3", "sw", "switch"),
             _host("4", "printer", "printer")]
    pairs, warnings = noc.infer_site_dependencies(hosts)
    assert pairs == [] and "redundantes" in warnings[0]


def test_dependencies_only_switch_to_single_gateway():
    hosts = [_host("1", "fw", "firewall"), _host("3", "sw1", "switch"), _host("4", "sw2", "switch"),
             _host("5", "printer", "printer"), _host("6", "idrac", "server-hardware"),
             _host("7", "vm", "server-linux")]
    pairs, warnings = noc.infer_site_dependencies(hosts)
    assert [(c["name"], p["name"]) for c, p in pairs] == [("sw1", "fw"), ("sw2", "fw")] and not warnings


def test_dependencies_never_stack_a_second_parent():
    hosts = [_host("1", "fw", "firewall"), _host("3", "sw", "switch")]
    triggers = {"1": [{"triggerid": "t1", "description": "Unavailable by ICMP ping"}],
                "3": [{"triggerid": "t3", "description": "Unavailable by ICMP ping"}]}

    def trigger_get(p):
        if "triggerids" in p:
            return [{"triggerid": "t3", "dependencies": [{"triggerid": "other"}]}]
        return triggers[p["hostids"]]

    api = FakeAPI({"host.get": hosts, "trigger.get": trigger_get})
    stats = noc.link_trigger_dependencies(api, {"_sites": [{"site": "A", "network": "10.0.0.0/24"}]},
                                          log=lambda *_: None)
    assert stats["linked"] == 0 and "trigger.update" not in api.methods()


def test_cmd_dependencies_requires_yes(capsys):
    args = argparse.Namespace(dry_run=False, yes=False)
    with pytest.raises(SystemExit, match="--yes"):
        cli.cmd_dependencies({}, args)
    assert "SUPRIMEM" in capsys.readouterr().out


def test_sla_timezone_is_configurable():
    api = FakeAPI({"service.create": {"serviceids": ["1"]}, "sla.create": {"slaids": ["1"]}})
    noc.setup_noc_services(api, {"_sites": [], "noc": {"sla_timezone": "UTC"}}, log=lambda *_: None)
    assert next(p for m, p in api.calls if m == "sla.create")["timezone"] == "UTC"
    api = FakeAPI({"service.create": {"serviceids": ["1"]}, "sla.create": {"slaids": ["1"]}})
    noc.setup_noc_services(api, {"_sites": []}, log=lambda *_: None)
    assert next(p for m, p in api.calls if m == "sla.create")["timezone"] == "America/Sao_Paulo"


# ---------------------------------------------------------------- agent-sync

def test_agent_sync_continues_after_an_error_and_keeps_visible_name(monkeypatch, capsys):
    hosts = [{"hostid": str(i), "host": f"10.0.0.{i}", "name": f"Visible {i}",
              "interfaces": [{"interfaceid": "1", "type": "2", "ip": f"10.0.0.{i}", "main": "1"}],
              "parentTemplates": [], "tags": [{"tag": "agent", "value": "missing"}], "items": []}
             for i in (1, 2)]
    updates = []

    def host_update(p):
        updates.append(p)
        if p["hostid"] == "1":
            raise ZabbixError("host.update: No permissions to referred object")
        return {"hostids": [p["hostid"]]}

    api = FakeAPI({"host.get": lambda p: [] if "filter" in p else hosts, "host.update": host_update,
                   "hostinterface.create": {"interfaceids": ["9"]}})
    api.template_ids = lambda: {"Linux by Zabbix agent": "50"}
    monkeypatch.setattr(cli, "connect", lambda cfg: api)

    async def agent_get(ip, key, timeout):
        return {"system.uname": "Linux srv 6.1", "agent.hostname": f"srv-{ip[-1]}"}[key]

    monkeypatch.setattr(scanner, "agent_get", agent_get)
    cfg = {"scan": {"timeout": 1}, "rules": [{"name": "linux", "category": "server-linux", "interface": "agent",
                                               "templates": ["Linux by Zabbix agent"], "action": "add",
                                               "match": {"agent_uname_regex": "Linux"}}]}
    cli.cmd_agent_sync(cfg, argparse.Namespace(dry_run=False))
    out = capsys.readouterr().out
    assert "x 10.0.0.1" in out and "+ 10.0.0.2" in out and "error=1" in out
    second = [u for u in updates if u["hostid"] == "2"][0]
    assert second["host"] == "srv-2" and second["name"] == "Visible 2"


def test_probe_agents_bounded(monkeypatch):
    running = peak = 0

    async def agent_get(ip, key, timeout):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return ""

    monkeypatch.setattr(scanner, "agent_get", agent_get)
    result = asyncio.run(cli.probe_agents([f"10.0.0.{i}" for i in range(30)], 1, limit=5))
    assert len(result) == 30 and peak <= 5


# ---------------------------------------------------------------- web / .env

def test_cmd_web_with_null_sections():
    args = argparse.Namespace(input=None, dry_run=True)
    with pytest.raises(SystemExit, match="Nothing to do"):
        cli.cmd_web({"web": {"certificates": None, "domains": None}}, args)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_env_file_created_private(tmp_path):
    write_private(tmp_path / ".env", "A=1\n")
    assert (os.stat(tmp_path / ".env").st_mode & 0o777) == 0o600


def test_init_writes_env(tmp_path):
    cli.cmd_init(argparse.Namespace(config=str(tmp_path / "config.yaml"), force=False))
    assert "ZABBIX_TOKEN=" in (tmp_path / ".env").read_text("utf-8")


# ---------------------------------------------------------------- Zabbix frontend map module

def test_map_module_enabled_on_7_and_tolerant():
    from zabbix_autodiscovery import maps
    api = FakeAPI({"module.get": [{"moduleid": "3", "status": "0"}]})
    assert maps.enable_map_module(api, log=lambda *_: None)
    assert ("module.update", {"moduleid": "3", "status": 1}) in api.calls

    def refuse(params):
        raise ZabbixError("module.create: directory not found")

    api = FakeAPI({"module.get": [], "module.create": refuse})
    assert maps.enable_map_module(api, log=lambda *_: None) is False

    api = FakeAPI()
    api.version = (6, 0)
    assert maps.enable_map_module(api, log=lambda *_: None) is False and api.calls == []
