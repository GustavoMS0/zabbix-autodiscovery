"""What is already in Zabbix: hosts of the configured networks and their device type.

Hosts created by this tool carry a "type" tag. For hosts that existed before, the type is inferred from
the templates they use (e.g. "FortiGate by SNMP" -> firewall), then from their host group names.
Host names are never used.
"""
import re

from .config import in_networks

KNOWN_CATEGORIES = {"firewall", "router", "switch", "ap", "server-windows", "server-linux", "hypervisor",
                    "server-hardware", "storage", "ups", "pdu", "printer", "cctv", "voip", "network-generic"}
TEMPLATE_HINTS = [
    ("fortigate|pfsense|firewall|palo alto|sophos|check point|adaptive security", "firewall"),
    (r"\bups\b|nobreak|\bapc\b|eaton", "ups"),
    (r"idrac|\bilo\b|ipmi", "server-hardware"),
    ("ubiquiti|airos|unifi|access point|wireless", "ap"),
    ("printer", "printer"),
    (r"synology|qnap|storage|\bnas\b", "storage"),
    (r"vmware|esxi|hyper-v|proxmox|\bpve\b|nutanix|xenserver", "hypervisor"),
    (r"cctv|camera|câmera|hikvision|dahua|axis|nvr|dvr", "cctv"),
    (r"voip|telephony|asterisk|freepbx|grandstream|yealink|\bsip\b", "voip"),
    (r"\bpdu\b|power distribution", "pdu"),
    ("mikrotik c[rs]s|switch|comware|hh3c|procurve|aruba|cisco ios|catalyst|huawei vrp|juniper|tp-link|d-link|"
     "netgear|extreme|arista|dell force", "switch"),
    ("mikrotik|routeros|router", "router"),
    ("windows", "server-windows"),
    ("linux", "server-linux"),
]
GROUP_HINTS = [("firewall", "firewall"), ("router|roteador", "router"), ("switch", "switch"),
               (r"access point|wireless|wifi|\bap\b", "ap"), ("printer|impressora", "printer"),
               ("ups|nobreak", "ups"), (r"\bpdu\b", "pdu"), ("storage|nas", "storage"),
               ("idrac|ilo|hardware", "server-hardware"),
               (r"cctv|camera|câmera|cf-tv|nvr|dvr", "cctv"), (r"voip|telefonia|\bsip\b|\bpabx\b|\bpbx\b", "voip"),
               (r"hypervisor|hipervisor|virtualiz|vmware|proxmox", "hypervisor"),
               ("linux", "server-linux"), ("server|servidor|windows", "server-windows")]
HOST_FIELDS = {"output": ["hostid", "host", "name", "status"], "selectTags": ["tag", "value"],
               "selectHostGroups": ["groupid", "name"], "selectParentTemplates": ["templateid", "name"],
               "selectInterfaces": ["type", "ip", "available", "error"]}


def hypervisor_hostids(api, hostids):
    """Windows hosts running the Hyper-V management service (vmms state 0 = running),
    read from the services the "Windows by Zabbix agent" template already discovers."""
    if not hostids:
        return set()
    items = api.call("item.get", {"output": ["hostid", "lastvalue"], "hostids": list(hostids),
                                  "search": {"key_": "vmms"}, "templated": False})
    return {i["hostid"] for i in items if i["lastvalue"] == "0"}


def tag_value(host, tag):
    return next((t["value"] for t in host.get("tags", []) if t["tag"] == tag), "")


def category_of(host, hypervisors=frozenset()):
    if host.get("hostid") in hypervisors:
        return "hypervisor"
    tag = tag_value(host, "type")
    if tag:
        return tag if tag in KNOWN_CATEGORIES else "other"
    linked = " ".join(t["name"] for t in host.get("parentTemplates", [])).lower()
    for pattern, cat in TEMPLATE_HINTS:
        if re.search(pattern, linked):
            return cat
    groups = " ".join(g["name"] for g in host.get("hostgroups", [])).lower()
    return next((cat for pattern, cat in GROUP_HINTS if re.search(pattern, groups)), "other")


def first_ip(host):
    return next((i["ip"] for i in host.get("interfaces", []) if i.get("ip") and i["ip"] != "127.0.0.1"), "")


def network_hosts(api, networks, enabled_only=True):
    """Hosts with at least one interface inside the given networks."""
    params = dict(HOST_FIELDS)
    if enabled_only:
        params["filter"] = {"status": 0}
    return [h for h in api.call("host.get", params)
            if any(i.get("ip") and in_networks(networks, i["ip"]) for i in h["interfaces"])]
