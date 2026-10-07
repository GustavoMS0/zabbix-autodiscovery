"""Add-on templates for device types that Zabbix does not cover out of the box.

- Printers: standard Printer-MIB (RFC 3805) + HOST-RESOURCES-MIB, which almost every network printer
  implements (HP, Brother, Epson, Kyocera, Ricoh, Samsung, Lexmark, Xerox...): page counter, supply
  levels (auto-discovered), status, model and serial number.
- Switches: physical port usage (ports in use / total / %), computed from one SNMP walk of the IF-MIB.

They complement the vendor templates and never redefine their item keys, so both can be linked.
"""
from .provision import PREFIX, TEMPLATE_GROUP

PRINTER_TEMPLATE = f"{PREFIX}Printer by SNMP"
SWITCH_TEMPLATE = f"{PREFIX}Switch port usage"

# Skip waste containers (they fill up instead of running out). Matched by name because the supply
# class is unreliable: HP reports toner cartridges as "receptacleThatIsFilled" (3) instead of 4.
SUPPLY_FILTER = {"evaltype": 0, "conditions": [
    {"macro": "{#SUPPLY.NAME}", "value": "(?i)waste|res[ií]duo|residual|collect|recolh", "operator": 9}]}

# Printer-MIB uses negative levels as codes (-2 unknown, -3 "some remaining") and may report an unknown
# capacity (-2). Raw values are kept; the % formula divides by the comparisons, so it becomes unsupported
# (no value) instead of showing a wrong number such as -3/-2 = 150%.
LEVEL = "last(//printer.supply.level[{#SNMPINDEX}])"
MAX = "last(//printer.supply.max[{#SNMPINDEX}])"
PCT_FORMULA = f"100*{LEVEL}/{MAX}/({LEVEL}>=0)/({MAX}>0)"
# Some printers (e.g. Brother) return the panel text as hex bytes: "50 69 6C 68 61"
HEX_TEXT_JS = r"""var v = value.trim();
if (!/^([0-9A-Fa-f]{2}[ :])*[0-9A-Fa-f]{2}$/.test(v)) { return value; }
return v.split(/[ :]/).map(function (h) { return String.fromCharCode(parseInt(h, 16)); })
    .join('').replace(/\u0000/g, '').trim();"""
DISPLAY_PREP = [{"type": 21, "params": HEX_TEXT_JS, "error_handler": 0, "error_handler_params": ""}]

# hrDeviceStatus / hrPrinterStatus
DEVICE_STATUS = {"1": "unknown", "2": "running", "3": "warning", "4": "testing", "5": "down"}
PRINTER_STATUS = {"1": "other", "2": "unknown", "3": "idle", "4": "printing", "5": "warmup"}

# Counts from an SNMP walk of ifType (.3), ifAdminStatus (.7) and ifOperStatus (.8).
# Physical ports = ethernetCsmacd (6), gigabitEthernet (117), fastEther (62, 69).
PORTS_JS = """var t = {}, a = {}, o = {};
value.split('\\n').forEach(function (line) {
    var m = line.match(/\\.1\\.3\\.6\\.1\\.2\\.1\\.2\\.2\\.1\\.(\\d+)\\.(\\d+) = [^:]+: \\D*(\\d+)/);
    if (!m) { return; }
    if (m[1] === '3') { t[m[2]] = parseInt(m[3]); }
    if (m[1] === '7') { a[m[2]] = parseInt(m[3]); }
    if (m[1] === '8') { o[m[2]] = parseInt(m[3]); }
});
var physical = [6, 62, 69, 117], total = 0, up = 0, down_enabled = 0;
Object.keys(t).forEach(function (i) {
    if (physical.indexOf(t[i]) < 0) { return; }
    total++;
    if (o[i] === 1) { up++; }
    else if (a[i] === 1) { down_enabled++; }
});
return JSON.stringify({total: total, up: up, down_enabled: down_enabled,
                       usage: total ? Math.round(1000 * up / total) / 10 : 0});"""


def _template(api, name, description, macros):
    found = api.call("template.get", {"output": ["templateid"], "filter": {"host": name}})
    if found:
        return found[0]["templateid"], False
    tid = api.call("template.create", {
        "host": name, "description": description,
        "groups": [{"groupid": api.ensure_templategroup(TEMPLATE_GROUP)}],
        "tags": [{"tag": "origin", "value": "autodiscovery"}],
        "macros": [{"macro": m, "value": v} for m, v in macros.items()],
    })["templateids"][0]
    return tid, True


def _valuemap(api, hostid, name, mapping):
    return api.call("valuemap.create", {
        "hostid": hostid, "name": name,
        "mappings": [{"value": k, "newvalue": v} for k, v in mapping.items()],
    })["valuemapids"][0]


def _snmp(tid, name, key, oid, value_type, delay, **extra):
    return {"hostid": tid, "type": 20, "name": name, "key_": key, "snmp_oid": oid,
            "value_type": value_type, "delay": delay, **extra}


def _upgrade_preprocessing(api, tid, log):
    """Add the preprocessing steps introduced after the first release to an existing template."""
    changed = 0
    for proto in api.call("itemprototype.get", {"output": ["itemid", "key_", "params"],
                                                "selectPreprocessing": ["type"], "hostids": tid}):
        if proto["key_"].startswith(("printer.supply.level[", "printer.supply.max[")) and proto["preprocessing"]:
            api.call("itemprototype.update", {"itemid": proto["itemid"], "preprocessing": []})
            changed += 1
        if proto["key_"].startswith("printer.supply.pct[") and proto["params"] != PCT_FORMULA:
            api.call("itemprototype.update", {"itemid": proto["itemid"], "params": PCT_FORMULA})
            changed += 1
    for item in api.call("item.get", {"output": ["itemid"], "selectPreprocessing": ["type"], "hostids": tid,
                                      "filter": {"key_": "printer.display"}}):
        if not item["preprocessing"]:
            api.call("item.update", {"itemid": item["itemid"], "preprocessing": DISPLAY_PREP})
            changed += 1
    if changed:
        log(f"- template '{PRINTER_TEMPLATE}': {changed} items upgraded (supply % guard / hex text)")


def ensure_printer_template(api, log=print):
    tid, created = _template(api, PRINTER_TEMPLATE,
                             "Created by zabbix-autodiscovery. Network printers through the standard Printer-MIB "
                             "(RFC 3805): page counter, supply levels, status, model and serial number.",
                             {"{$PRINTER.SUPPLY.WARN}": "10", "{$PRINTER.SUPPLY.HIGH}": "3"})
    if not created:
        # upgrade templates created by older versions (filter by supply class)
        rule = api.call("discoveryrule.get", {"output": ["itemid"], "selectFilter": "extend", "hostids": tid,
                                              "filter": {"key_": "printer.supplies.discovery"}})
        if rule and "{#SUPPLY.CLASS}" in str(rule[0].get("filter")):
            api.call("discoveryrule.update", {"itemid": rule[0]["itemid"], "filter": SUPPLY_FILTER})
            log(f"- template '{PRINTER_TEMPLATE}': supply filter updated")
        _upgrade_preprocessing(api, tid, log)
        return tid
    device_map = _valuemap(api, tid, "HOST-RESOURCES-MIB::hrDeviceStatus", DEVICE_STATUS)
    printer_map = _valuemap(api, tid, "HOST-RESOURCES-MIB::hrPrinterStatus", PRINTER_STATUS)
    tag = [{"tag": "component", "value": "printer"}]
    api.call("item.create", [
        _snmp(tid, "Printer: Total page count", "printer.pages.total", "1.3.6.1.2.1.43.10.2.1.4.1.1", 3, "1h",
              units="pages", tags=tag, description="prtMarkerLifeCount: pages printed during the printer's life."),
        _snmp(tid, "Printer: Model", "printer.model", "1.3.6.1.2.1.25.3.2.1.3.1", 1, "1d", tags=tag),
        _snmp(tid, "Printer: Serial number", "printer.serial", "1.3.6.1.2.1.43.5.1.1.17.1", 1, "1d", tags=tag,
              inventory_link=8),                                      # inventory: serialno_a
        _snmp(tid, "Printer: Device status", "printer.device.status", "1.3.6.1.2.1.25.3.2.1.5.1", 3, "5m",
              valuemapid=device_map, tags=tag),
        _snmp(tid, "Printer: Printer status", "printer.status", "1.3.6.1.2.1.25.3.5.1.1.1", 3, "5m",
              valuemapid=printer_map, tags=tag),
        _snmp(tid, "Printer: Display message", "printer.display", "1.3.6.1.2.1.43.16.5.1.2.1.1", 1, "5m", tags=tag,
              preprocessing=DISPLAY_PREP, description="Text shown on the printer panel (e.g. paper jam, toner low)."),
    ])
    t = PRINTER_TEMPLATE
    api.call("trigger.create", [
        {"description": "Printer is down", "priority": 4, "tags": tag,
         "expression": f"last(/{t}/printer.device.status)=5"},
        {"description": "Printer reports a warning", "priority": 2, "tags": tag,
         "expression": f"last(/{t}/printer.device.status)=3",
         "comments": "See the item 'Printer: Display message' for the text shown on the panel."},
    ])
    rule = api.call("discoveryrule.create", {
        "hostid": tid, "type": 20, "name": "Printer supplies discovery", "key_": "printer.supplies.discovery",
        "snmp_oid": "discovery[{#SUPPLY.NAME},1.3.6.1.2.1.43.11.1.1.6,{#SUPPLY.CLASS},1.3.6.1.2.1.43.11.1.1.4]",
        "delay": "1h", "lifetime": "7d",
        "filter": SUPPLY_FILTER,
    })["itemids"][0]
    stag = [{"tag": "component", "value": "supply"}, {"tag": "supply", "value": "{#SUPPLY.NAME}"}]
    api.call("itemprototype.create", [
        _snmp(tid, "Supply [{#SUPPLY.NAME}]: Level", "printer.supply.level[{#SNMPINDEX}]",
              "1.3.6.1.2.1.43.11.1.1.9.{#SNMPINDEX}", 0, "30m", ruleid=rule, tags=stag,
              description="prtMarkerSuppliesLevel. -2 = unknown, -3 = some remaining (no % is computed)."),
        _snmp(tid, "Supply [{#SUPPLY.NAME}]: Max capacity", "printer.supply.max[{#SNMPINDEX}]",
              "1.3.6.1.2.1.43.11.1.1.8.{#SNMPINDEX}", 0, "1d", ruleid=rule, tags=stag),
        {"hostid": tid, "ruleid": rule, "type": 15, "name": "Supply [{#SUPPLY.NAME}]: Level %",
         "key_": "printer.supply.pct[{#SNMPINDEX}]", "value_type": 0, "units": "%", "delay": "30m",
         "params": PCT_FORMULA,
         "tags": stag},
    ])
    pct = f"/{t}/printer.supply.pct[{{#SNMPINDEX}}]"
    high = api.call("triggerprototype.create", {
        "description": "Supply [{#SUPPLY.NAME}] below {$PRINTER.SUPPLY.HIGH}%", "priority": 4, "tags": stag,
        "expression": f"last({pct})<{{$PRINTER.SUPPLY.HIGH}} and last({pct})>=0",
    })["triggerids"][0]
    api.call("triggerprototype.create", {
        "description": "Supply [{#SUPPLY.NAME}] below {$PRINTER.SUPPLY.WARN}%", "priority": 2, "tags": stag,
        "expression": f"last({pct})<{{$PRINTER.SUPPLY.WARN}} and last({pct})>=0",
        "dependencies": [{"triggerid": high}],
    })
    log(f"- template '{PRINTER_TEMPLATE}' created")
    return tid


def ensure_switch_template(api, log=print):
    tid, created = _template(api, SWITCH_TEMPLATE,
                             "Created by zabbix-autodiscovery. Physical port usage of a switch (ports in use, "
                             "total, %), from one SNMP walk of the IF-MIB. Requires Zabbix 7.0+ (walk[]).",
                             {"{$SWITCH.PORT.USAGE.WARN}": "90"})
    if not created:
        return tid
    tag = [{"tag": "component", "value": "ports"}]
    master = api.call("item.create", _snmp(
        tid, "Switch: Interface table", "switch.if.walk",
        "walk[1.3.6.1.2.1.2.2.1.3,1.3.6.1.2.1.2.2.1.7,1.3.6.1.2.1.2.2.1.8]", 4, "5m", history="1h", tags=tag,
        preprocessing=[{"type": 21, "params": PORTS_JS, "error_handler": 0, "error_handler_params": ""}],
    ))["itemids"][0]

    def dep(name, key, path, units=""):
        return {"hostid": tid, "type": 18, "master_itemid": master, "name": name, "key_": key,
                "value_type": 0 if key.endswith("usage") else 3, "units": units, "tags": tag,
                "preprocessing": [{"type": 12, "params": path, "error_handler": 0, "error_handler_params": ""}]}

    api.call("item.create", [
        dep("Switch: Physical ports", "switch.ports.total", "$.total"),
        dep("Switch: Ports in use", "switch.ports.up", "$.up"),
        dep("Switch: Enabled ports without link", "switch.ports.down_enabled", "$.down_enabled"),
        dep("Switch: Port usage", "switch.ports.usage", "$.usage", "%"),
    ])
    api.call("trigger.create", {
        "description": "Switch port usage above {$SWITCH.PORT.USAGE.WARN}%", "priority": 2, "tags": tag,
        "expression": f"min(/{SWITCH_TEMPLATE}/switch.ports.usage,1h)>{{$SWITCH.PORT.USAGE.WARN}}",
        "comments": "Few free ports left: plan an expansion.",
    })
    log(f"- template '{SWITCH_TEMPLATE}' created")
    return tid


ENSURE = {PRINTER_TEMPLATE: ensure_printer_template, SWITCH_TEMPLATE: ensure_switch_template}


def ensure_addons(api, names, log=print):
    """Create the add-on templates referenced by the config (only the ones this module knows)."""
    for name in names:
        if name in ENSURE and (name != SWITCH_TEMPLATE or api.version >= (7, 0)):
            ENSURE[name](api, log)
