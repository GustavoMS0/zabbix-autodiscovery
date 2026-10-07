"""Classify scanned devices with the rules from the config file.

No condition uses the host name: only what the device answers (SNMP, agent, ports).
"""
import ipaddress
import re
import unicodedata

from .config import site_for

# IANA enterprise number from the sysObjectID -> vendor (tag and report only)
VENDORS = {
    "9": "Cisco", "11": "HP", "171": "D-Link", "232": "HPE", "236": "Samsung", "253": "Xerox",
    "311": "Microsoft", "318": "APC", "367": "Ricoh", "534": "Eaton", "641": "Lexmark", "674": "Dell",
    "890": "Zyxel", "1248": "Epson", "1347": "Kyocera", "1602": "Canon", "1916": "Extreme",
    "2011": "Huawei", "2385": "Sharp", "2435": "Brother", "2604": "Sophos", "2620": "Check Point",
    "2636": "Juniper", "4526": "Netgear", "6574": "Synology", "6876": "VMware", "8072": "Net-SNMP",
    "8741": "SonicWall", "10642": "Zebra", "11863": "TP-Link", "12325": "pfSense", "12356": "Fortinet",
    "14823": "Aruba", "14988": "MikroTik", "18334": "Konica Minolta", "24681": "QNAP", "25053": "Ruckus",
    "25461": "Palo Alto", "25506": "H3C/HPE Comware", "26381": "NHS", "29671": "Meraki",
    "30065": "Arista", "41112": "Ubiquiti", "47196": "Aruba",
}

CONDITIONS = {"sysobjectid_prefix", "sysdescr_regex", "agent_uname_regex", "web_server_regex",
              "ports_any", "ports_all", "ports_none", "snmp", "agent", "alive"}

# Factory-default sysName values that do not identify the device
GENERIC_NAMES = {"", "localhost", "localhost.localdomain", "(none)", "none", "unknown", "default",
                 "switch", "router", "firewall", "printer", "ap", "ubnt", "mikrotik", "routeros",
                 "openwrt", "admin", "sysname", "system name", "name", "host", "hostname"}


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def oid_matches(oid, prefix):
    oid, prefix = oid.strip("."), str(prefix).strip(".")
    return oid == prefix or oid.startswith(prefix + ".")


def vendor(oid):
    parts = oid.strip(".").split(".")
    if parts[:6] == ["1", "3", "6", "1", "4", "1"] and len(parts) > 6:
        return VENDORS.get(parts[6], f"enterprise {parts[6]}")
    return ""


def _condition_matches(cond, dev):
    unknown = set(cond) - CONDITIONS
    if unknown:
        raise ValueError(f"unknown rule condition: {', '.join(sorted(unknown))}")
    ports = set(dev.ports)
    if "sysobjectid_prefix" in cond and not any(
            oid_matches(dev.sysobjectid, p) for p in as_list(cond["sysobjectid_prefix"])):
        return False
    if "sysdescr_regex" in cond and not re.search(cond["sysdescr_regex"], dev.sysdescr, re.I):
        return False
    if "agent_uname_regex" in cond and not re.search(cond["agent_uname_regex"], dev.agent_uname, re.I):
        return False
    if "web_server_regex" in cond and not re.search(cond["web_server_regex"], web_servers(dev), re.I):
        return False
    if "ports_any" in cond and not ports & set(as_list(cond["ports_any"])):
        return False
    if "ports_all" in cond and not set(as_list(cond["ports_all"])) <= ports:
        return False
    if "ports_none" in cond and ports & set(as_list(cond["ports_none"])):
        return False
    if "snmp" in cond and dev.snmp != bool(cond["snmp"]):
        return False
    if "agent" in cond and dev.agent != bool(cond["agent"]):
        return False
    if "alive" in cond and dev.responded != bool(cond["alive"]):
        return False
    return True


def rule_matches(rule, dev):
    return any(_condition_matches(c, dev) for c in as_list(rule.get("match")))


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def clean_name(name, keep_domain=False):
    name = (name or "").strip().strip(".")
    if not keep_domain and not _is_ip(name):
        name = name.split(".")[0]
    # Zabbix technical host names are ASCII only: "RECEPÇÃO" -> "RECEPCAO"
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    return re.sub(r"[^0-9A-Za-z._ -]", "_", name).strip(" _")[:120]


def _generic_sysname(dev):
    name = dev.sysname.strip().lower()
    if name in GENERIC_NAMES or _is_ip(name):
        return True
    first_word = dev.sysdescr.split()[0].lower() if dev.sysdescr.split() else ""
    return name == first_word            # sysName equal to the model (e.g. "UAP-AC-Pro")


def host_name(dev, category):
    """Pick the Zabbix host name. Returns (technical_name, visible_name, source).

    Never used for classification. Order:
      agent   - the agent's Hostname= (must match exactly for active checks to work);
                the OS host name (system.hostname) becomes the visible name
      snmp    - sysName, unless it is a factory default
      netbios - Windows/Samba computer name (UDP 137)
      dns     - reverse DNS, only when forward-confirmed (name resolves back to the same IP)
      ip      - <category>-<ip>
    """
    if dev.agent_hostname and not _is_ip(dev.agent_hostname):
        technical = clean_name(dev.agent_hostname, keep_domain=True)
        visible = clean_name(dev.system_hostname) if dev.system_hostname else ""
        return technical, ("" if visible.lower() == technical.lower() else visible), "agent"
    if dev.system_hostname:
        return clean_name(dev.system_hostname), "", "agent"
    if dev.sysname and not _generic_sysname(dev):
        return clean_name(dev.sysname), "", "snmp"
    if dev.netbios:
        return clean_name(dev.netbios), "", "netbios"
    # On Windows a reverse lookup without a domain (e.g. "NPI123ABC") comes from NetBIOS/LLMNR,
    # i.e. the device itself answered with its name
    if dev.dns and "." not in dev.dns and not _is_ip(dev.dns):
        return clean_name(dev.dns), "", "netbios"
    if dev.dns and dev.dns_confirmed:
        return clean_name(dev.dns), "", "dns"
    fallback = f"{category}-{dev.ip}"
    # Unconfirmed DNS or a model-like sysName only become a visible-name hint for the review
    hint = dev.dns or (dev.sysname if dev.sysname.strip().lower() not in GENERIC_NAMES else "")
    return fallback, (f"{clean_name(hint)} ({dev.ip})" if hint else ""), "ip"


def web_servers(dev):
    """'443=nginx/1.24; 80=Microsoft-IIS/10.0' (ports without a Server header show as '?')."""
    return "; ".join(f"{w['port']}={w['server'] or '?'}" for w in dev.web)


def certificate_columns(dev):
    """Inventory columns for the certificate that expires first among the device's TLS ports."""
    certs = sorted((w for w in dev.web if w.get("cert")), key=lambda w: w["cert"]["not_after"])
    if not certs:
        return {"cert_names": "", "cert_expires": "", "cert_issuer": "", "cert_self_signed": ""}
    cert = certs[0]["cert"]
    names = cert["names"] or ([cert["cn"]] if cert["cn"] else [])
    return {"cert_names": ",".join(names[:5]), "cert_expires": cert["not_after"],
            "cert_issuer": cert["issuer"], "cert_self_signed": "yes" if cert["self_signed"] else "no"}


def format_tags(tags):
    return ",".join(f"{k}={v}" for k, v in (tags or {}).items())


def classify(dev, cfg):
    """Return the dict that becomes one inventory row."""
    row = {
        "ip": dev.ip,
        "site": site_for(cfg, dev.ip).get("site", ""),
        "ping": "yes" if dev.alive else "no",
        "dns": dev.dns,
        "dns_confirmed": "yes" if dev.dns_confirmed else ("no" if dev.dns else ""),
        "sysname": dev.sysname,
        "sysdescr": dev.sysdescr[:250],
        "sysobjectid": dev.sysobjectid,
        "vendor": vendor(dev.sysobjectid),
        "snmp_cred": dev.snmp_cred,
        "ports": ",".join(str(p) for p in dev.ports),
        "agent_hostname": dev.agent_hostname,
        "system_hostname": dev.system_hostname,
        "agent_uname": dev.agent_uname[:200],
        "netbios": dev.netbios,
        "web_servers": web_servers(dev),
        **certificate_columns(dev),
    }
    rule = next((r for r in cfg.get("rules", []) if rule_matches(r, dev)), None)
    if rule is None:
        row.update(category="unknown", rule="-", group="", templates="", interface="", tags="",
                   action="ignore")
    else:
        row.update(category=rule["category"], rule=rule["name"], group=rule.get("group", ""),
                   templates=",".join(as_list(rule.get("templates"))),
                   interface=rule.get("interface", "snmp"), tags=format_tags(rule.get("tags")),
                   action=rule.get("action", "review"))
    row["hostname"], row["visible_name"], row["name_source"] = host_name(dev, row["category"])
    return row
