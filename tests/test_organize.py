from zabbix_autodiscovery import organize


class HostsAPI:
    def __init__(self, hosts):
        self.hosts, self.calls, self.version = hosts, [], (8, 0)

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "host.get":
            return self.hosts
        if method == "hostgroup.get":
            return [{"groupid": "9", "name": "Network"}]
        return {}

    def ensure_hostgroup(self, name):
        return f"id:{name}"


def _host(hostid, name, ip, templates=(), groups=("Network",), tags=()):
    return {"hostid": hostid, "host": name, "name": name, "status": "0",
            "interfaces": [{"type": "2", "ip": ip, "available": "1", "error": ""}],
            "parentTemplates": [{"templateid": t, "name": t} for t in templates],
            "hostgroups": [{"groupid": g, "name": g} for g in groups],
            "tags": [{"tag": k, "value": v} for k, v in tags]}


def test_plan_puts_existing_hosts_in_type_and_site_groups(example_config):
    api = HostsAPI([
        _host("1", "FW-HQ", "192.168.0.4", ["FortiGate by SNMP"]),
        _host("2", "idrac-old", "192.168.10.14", ["Dell iDRAC by SNMP"]),
        _host("3", "WIN-SRV", "192.168.0.8", ["Windows by Zabbix agent"], groups=("Zabbix servers",)),
        _host("4", "outside", "10.99.0.1", ["FortiGate by SNMP"]),
        _host("5", "done", "192.168.0.9", ["FortiGate by SNMP"], groups=("Network/Firewalls", "Sites/HQ"),
              tags=[("type", "firewall"), ("site", "HQ")]),
    ])
    plan = {h["name"]: (cat, groups, tags) for h, cat, groups, tags in organize.plan(api, example_config)}
    assert "outside" not in plan
    assert plan["FW-HQ"] == ("firewall", ["Network/Firewalls", "Sites/HQ"], {"type": "firewall", "site": "HQ"})
    assert plan["idrac-old"] == ("server-hardware", ["Infrastructure/Server Hardware", "Sites/Branch-01"],
                                 {"type": "server-hardware", "site": "Branch-01"})
    assert plan["WIN-SRV"][0] == "server-windows"
    assert plan["done"] == ("firewall", [], {})


def test_organize_is_additive_and_keeps_tags(example_config):
    host = _host("1", "FW-HQ", "192.168.0.4", ["FortiGate by SNMP"], tags=[("owner", "it")])
    api = HostsAPI([host])
    stats = organize.organize(api, example_config, log=lambda *_: None)
    assert stats["updated"] == 1
    methods = [m for m, _ in api.calls]
    assert "host.massremove" not in methods
    update = next(p for m, p in api.calls if m == "host.update")
    assert {"tag": "owner", "value": "it"} in update["tags"] and {"tag": "type", "value": "firewall"} in update["tags"]


def test_organize_removes_only_listed_groups(example_config):
    api = HostsAPI([_host("1", "FW-HQ", "192.168.0.4", ["FortiGate by SNMP"])])
    organize.organize(api, example_config, remove_groups=["Network"], log=lambda *_: None)
    removed = next(p for m, p in api.calls if m == "host.massremove")
    assert removed == {"hostids": ["1"], "groupids": ["9"]}


def test_dry_run_changes_nothing(example_config):
    api = HostsAPI([_host("1", "FW-HQ", "192.168.0.4", ["FortiGate by SNMP"])])
    stats = organize.organize(api, example_config, dry_run=True, remove_groups=["Network"], log=lambda *_: None)
    assert stats["planned"] == 1
    assert all(m.endswith(".get") for m, _ in api.calls)          # read-only


def test_identity_issues_detect_wrong_ip_and_agent_hostname():
    hosts = [_host("1", "SRV-APP", "10.0.0.31"), _host("2", "SRV-DB", "10.0.0.31"),
             _host("3", "SRV-WEB", "10.0.0.7")]
    values = {"1": {"system.hostname": "SRV-APP", "agent.hostname": "SRV-WEB"},
              "2": {"system.hostname": "SRV-APP", "agent.hostname": "SRV-WEB"},
              "3": {"system.hostname": "SRV-WEB", "agent.hostname": "SRV-WEB"}}
    dns = {"SRV-APP": {"10.0.0.31"}, "SRV-DB": {"10.0.0.33"}, "SRV-WEB": {"10.0.0.7"}}
    same, mismatched, dns_wrong = organize.identity_issues(hosts, values, lambda n: dns.get(n, set()))
    assert [h["name"] for h in same["srv-app"]] == ["SRV-APP", "SRV-DB"]
    assert [(h["name"], a) for h, a in mismatched] == [("SRV-APP", "SRV-WEB"), ("SRV-DB", "SRV-WEB")]
    assert [(h["name"], ips, d) for h, ips, d in dns_wrong] == [("SRV-DB", ["10.0.0.31"], ["10.0.0.33"])]


class HyperVAPI(HostsAPI):
    def __init__(self, hosts, running):
        super().__init__(hosts)
        self.running = running

    def call(self, method, params):
        if method == "item.get":
            return [{"hostid": h, "lastvalue": "0"} for h in self.running]
        return super().call(method, params)


def test_hyperv_host_is_promoted_to_hypervisor(example_config):
    api = HyperVAPI([_host("1", "HV01", "192.168.0.31", ["Windows by Zabbix agent"], groups=("Servers/Windows",),
                           tags=[("type", "server-windows"), ("site", "HQ")]),
                     _host("2", "APP01", "192.168.0.33", ["Windows by Zabbix agent"])], running={"1"})
    plan = {h["name"]: (cat, groups, tags) for h, cat, groups, tags in organize.plan(api, example_config)}
    assert plan["HV01"] == ("hypervisor", ["Servers/Hypervisors", "Sites/HQ"], {"type": "hypervisor"})
    assert plan["APP01"][0] == "server-windows"
    organize.organize(api, example_config, log=lambda *_: None)
    update = next(p for m, p in api.calls if m == "host.update" and p["hostid"] == "1")
    assert {"tag": "type", "value": "hypervisor"} in update["tags"]
    assert {"tag": "type", "value": "server-windows"} not in update["tags"]
