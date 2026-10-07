import re

import pytest

from zabbix_autodiscovery import maps, templates, web
from zabbix_autodiscovery.scanner import prefer_highest_version


class FakeAPI:
    """Records create calls; enough of the Zabbix API for the template builders."""

    def __init__(self, version=(8, 0)):
        self.version = version
        self.calls = []
        self.next_id = 100

    def ensure_templategroup(self, name):
        return "1"

    def _ids(self, params):
        n = len(params) if isinstance(params, list) else 1
        ids = [str(self.next_id + i) for i in range(n)]
        self.next_id += n
        return ids

    def call(self, method, params):
        self.calls.append((method, params))
        if method.endswith(".get"):
            return []
        kind = {"template": "templateids", "item": "itemids", "discoveryrule": "itemids",
                "itemprototype": "itemids", "trigger": "triggerids", "triggerprototype": "triggerids",
                "valuemap": "valuemapids"}[method.split(".")[0]]
        return {kind: self._ids(params)}

    def created(self, method):
        out = []
        for m, p in self.calls:
            if m == method:
                out += p if isinstance(p, list) else [p]
        return out


def _check_expressions(api, template):
    keys = {i["key_"] for m in ("item.create", "itemprototype.create") for i in api.created(m)}
    triggers = api.created("trigger.create") + api.created("triggerprototype.create")
    assert triggers
    for trig in triggers:
        refs = re.findall(r"/" + re.escape(template) + r"/([^,)]+)", trig["expression"])
        assert refs, trig["expression"]
        for ref in refs:
            assert ref in keys, f"{ref} not created ({trig['description']})"


@pytest.mark.parametrize("builder, name", [
    (templates.ensure_printer_template, templates.PRINTER_TEMPLATE),
    (templates.ensure_switch_template, templates.SWITCH_TEMPLATE),
    (web.ensure_cert_template, web.CERT_TEMPLATE),
    (web.ensure_domain_template, web.DOMAIN_TEMPLATE),
])
def test_template_triggers_reference_created_items(builder, name):
    api = FakeAPI()
    builder(api, log=lambda *_: None)
    _check_expressions(api, name)


def test_printer_template_items():
    api = FakeAPI()
    templates.ensure_printer_template(api, log=lambda *_: None)
    oids = {i["key_"]: i.get("snmp_oid") for i in api.created("item.create")}
    assert oids["printer.pages.total"] == "1.3.6.1.2.1.43.10.2.1.4.1.1"
    rule = api.created("discoveryrule.create")[0]
    pattern = rule["filter"]["conditions"][0]["value"].replace("(?i)", "")
    assert rule["filter"]["conditions"][0]["operator"] == 9            # "does not match"
    assert re.search(pattern, "Waste Toner Box", re.I) and re.search(pattern, "Caixa de resíduo", re.I)
    assert not re.search(pattern, "Black Cartridge HP CE505X", re.I)
    assert rule["snmp_oid"].startswith("discovery[{#SUPPLY.NAME},1.3.6.1.2.1.43.11.1.1.6")
    pct = next(i for i in api.created("itemprototype.create") if i["key_"].startswith("printer.supply.pct"))
    assert "//printer.supply.level[{#SNMPINDEX}]" in pct["params"]


def _ports_js_in_python(walk):
    """Same regex and rules as templates.PORTS_JS, to validate the parsing logic."""
    pattern = re.compile(r"\.1\.3\.6\.1\.2\.1\.2\.2\.1\.(\d+)\.(\d+) = [^:]+: \D*(\d+)")
    t, a, o = {}, {}, {}
    for line in walk.split("\n"):
        m = pattern.search(line)
        if m:
            {"3": t, "7": a, "8": o}.get(m.group(1), {})[m.group(2)] = int(m.group(3))
    phys = [i for i, v in t.items() if v in (6, 62, 69, 117)]
    up = sum(1 for i in phys if o.get(i) == 1)
    down_enabled = sum(1 for i in phys if o.get(i) != 1 and a.get(i) == 1)
    return len(phys), up, down_enabled


def test_ports_parsing():
    assert r"= [^:]+: \D*(\d+)" in templates.PORTS_JS
    walk = "\n".join([
        ".1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 6", ".1.3.6.1.2.1.2.2.1.3.2 = INTEGER: 6",
        ".1.3.6.1.2.1.2.2.1.3.3 = INTEGER: ethernetCsmacd(6)", ".1.3.6.1.2.1.2.2.1.3.100 = INTEGER: 24",
        ".1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1", ".1.3.6.1.2.1.2.2.1.7.2 = INTEGER: 1",
        ".1.3.6.1.2.1.2.2.1.7.3 = INTEGER: 2", ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1",
        ".1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 2", ".1.3.6.1.2.1.2.2.1.8.3 = INTEGER: 2",
        ".1.3.6.1.2.1.2.2.1.8.100 = INTEGER: 1",
    ])
    assert _ports_js_in_python(walk) == (3, 1, 1)


def test_switch_addon_requires_zabbix_7():
    api = FakeAPI(version=(6, 4))
    templates.ensure_addons(api, [templates.SWITCH_TEMPLATE, templates.PRINTER_TEMPLATE], log=lambda *_: None)
    created = [p["host"] for p in api.created("template.create")]
    assert created == [templates.PRINTER_TEMPLATE]


def test_snmp_prefers_highest_version():
    creds = [{"name": "v1", "version": 1}, {"name": "a", "version": "2c"}, {"name": "v3", "version": 3},
             {"name": "b", "version": "2c"}]
    assert [c["name"] for c in prefer_highest_version(creds)] == ["v3", "a", "b", "v1"]


def _host(name, category="", groups=()):
    return {"hostid": name, "name": name, "tags": [{"tag": "type", "value": category}] if category else [],
            "hostgroups": [{"name": g} for g in groups]}


def test_map_category_and_layout():
    assert maps.category_of(_host("a", "printer")) == "printer"
    assert maps.category_of(_host("b", groups=["Network/Firewalls"])) == "firewall"
    assert maps.category_of(_host("c", groups=["Discovered hosts"])) == "other"
    for template, cat in (("FortiGate by SNMP", "firewall"), ("MikroTik CSS326-24G-2S+RM by SNMP", "switch"),
                          ("Mikrotik by SNMP", "router"), ("NHS Prime Online GII - UPS SNMP", "ups"),
                          ("HP Comware HH3C by SNMP", "switch"), ("Dell iDRAC by SNMP", "server-hardware")):
        assert maps.category_of({"tags": [], "hostgroups": [{"name": "Network"}],
                                 "parentTemplates": [{"name": template}]}) == cat, template
    hosts = [_host(f"p{i}", "printer") for i in range(10)] + [_host("fw", "firewall")]
    placed, width, height = maps.layout(hosts)
    assert placed[0][1] == "firewall"                       # firewalls on the first row
    assert {cat for _, cat, _, _ in placed} == {"firewall", "printer"}
    assert width == 2 * maps.MARGIN + maps.COLUMNS * maps.CELL_W
    assert height == maps.MARGIN + 3 * maps.CELL_H + maps.MARGIN      # 1 firewall row + 2 printer rows
    assert len({(x, y) for _, _, x, y in placed}) == len(placed)


def test_printer_guards_and_hex_text():
    api = FakeAPI()
    templates.ensure_printer_template(api, log=lambda *_: None)
    protos = {p["key_"].split("[")[0]: p for p in api.created("itemprototype.create")}
    assert "preprocessing" not in protos["printer.supply.level"]           # raw codes are kept
    pct = protos["printer.supply.pct"]["params"]
    assert pct.endswith("/(last(//printer.supply.level[{#SNMPINDEX}])>=0)"
                        "/(last(//printer.supply.max[{#SNMPINDEX}])>0)")

    def pct_of(level, maximum):     # same arithmetic; Zabbix leaves the item without value on division by 0
        try:
            return 100 * level / maximum / (level >= 0) / (maximum > 0)
        except ZeroDivisionError:
            return None

    assert pct_of(39, 100) == 39 and pct_of(1621, 12000) == pytest.approx(13.5, 0.01)
    assert pct_of(-3, -2) is None and pct_of(-2, 100) is None and pct_of(0, 100) == 0
    display = next(i for i in api.created("item.create") if i["key_"] == "printer.display")
    assert display["preprocessing"][0]["params"] == templates.HEX_TEXT_JS
    assert r"/\u0000/g" in templates.HEX_TEXT_JS
    hex_re = re.compile(r"^([0-9A-Fa-f]{2}[ :])*[0-9A-Fa-f]{2}$")
    assert hex_re.match("50 69 6C 68 61") and not hex_re.match("Ready")
