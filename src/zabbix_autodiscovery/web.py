"""SSL/TLS certificate and domain expiration monitoring.

- Certificates: one Zabbix host per site, checked by a Zabbix agent 2 (web.certificate.get).
- Domains: one Zabbix host per domain, checked by the Zabbix server through RDAP (the successor of
  WHOIS, covering .com, .net, .br and most TLDs) using an HTTP agent item. No external scripts.

Both templates use fixed item names, so dashboards can sort hosts by days until expiration.
"""
import re
from urllib.parse import urlsplit

import requests

from . import __version__
from .provision import PREFIX, TEMPLATE_GROUP
from .zabbix_api import ZabbixError

CERT_TEMPLATE = f"{PREFIX}SSL certificate"
DOMAIN_TEMPLATE = f"{PREFIX}Domain expiration"
CERT_DAYS_ITEM = "Certificate: Days until expiration"
DOMAIN_DAYS_ITEM = "Domain: Days until expiration"
DASHBOARD = f"{PREFIX}Certificates and domains"

IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = "https://rdap.org/domain/"
# rdap.org and some registries reject requests without a User-Agent (HTTP 403)
USER_AGENT = f"zabbix-autodiscovery/{__version__} (+https://github.com/GustavoMS0/zabbix-autodiscovery)"
CERT_KEY = "web.certificate.get[{$CERT.WEBSITE.HOSTNAME},{$CERT.WEBSITE.PORT},{$CERT.WEBSITE.IP}]"
DAYS_JS = "return Math.floor(({expr} - Date.now() / 1000) / 86400);"
RDAP_EXPIRES_JS = """var data = JSON.parse(value);
var events = data.events || [];
for (var i = 0; i < events.length; i++) {
    if (events[i].eventAction === 'expiration') {
        return Math.floor(Date.parse(events[i].eventDate) / 1000);
    }
}
throw 'RDAP response has no expiration event';"""


# ---------------------------------------------------------------- templates

def _jsonpath(path):
    return [{"type": 12, "params": path, "error_handler": 0, "error_handler_params": ""}]


def _js(code):
    return [{"type": 21, "params": code, "error_handler": 0, "error_handler_params": ""}]


def _template(api, name, description, macros):
    found = api.call("template.get", {"output": ["templateid"], "filter": {"host": name}})
    if found:
        return found[0]["templateid"], False
    tid = api.call("template.create", {
        "host": name,
        "groups": [{"groupid": api.ensure_templategroup(TEMPLATE_GROUP)}],
        "description": description,
        "tags": [{"tag": "origin", "value": "autodiscovery"}],
        "macros": [{"macro": m, "value": v} for m, v in macros.items()],
    })["templateids"][0]
    return tid, True


def _expiry_triggers(api, tpl, days_key, label, warn_macro, high_macro, nodata_key, nodata_period, tag):
    tags = [{"tag": "scope", "value": "expiration"}, {"tag": "type", "value": tag}]
    high = api.call("trigger.create", {
        "description": f"{label} expires in less than {{{high_macro}}} days",
        "expression": f"last(/{tpl}/{days_key})<{{{high_macro}}}",
        "priority": 4, "tags": tags,
        "comments": "Value of the last check: {ITEM.LASTVALUE1} days.",
    })["triggerids"][0]
    api.call("trigger.create", {
        "description": f"{label} expires in less than {{{warn_macro}}} days",
        "expression": f"last(/{tpl}/{days_key})<{{{warn_macro}}}",
        "priority": 2, "tags": tags, "dependencies": [{"triggerid": high}],
        "comments": "Value of the last check: {ITEM.LASTVALUE1} days.",
    })
    api.call("trigger.create", {
        "description": f"{label}: expiration check is failing",
        "expression": f"nodata(/{tpl}/{nodata_key},{nodata_period})=1",
        "priority": 1, "tags": tags,
    })


def ensure_cert_template(api, log=print):
    tid, created = _template(api, CERT_TEMPLATE,
                             "Created by zabbix-autodiscovery. TLS certificate of one website, read by a "
                             "Zabbix agent 2 (WebCertificate plugin). Set {$CERT.WEBSITE.HOSTNAME} on the host.",
                             {"{$CERT.WEBSITE.HOSTNAME}": "", "{$CERT.WEBSITE.PORT}": "443",
                              "{$CERT.WEBSITE.IP}": "", "{$CERT.EXPIRY.WARN}": "30", "{$CERT.EXPIRY.HIGH}": "7"})
    if not created:
        return tid
    master = api.call("item.create", {
        "hostid": tid, "name": "Certificate: Get", "key_": CERT_KEY, "type": 0, "value_type": 4,
        "delay": "1h", "history": "7d", "tags": [{"tag": "component", "value": "certificate"}],
    })["itemids"][0]
    common = {"hostid": tid, "type": 18, "master_itemid": master, "history": "90d",
              "tags": [{"tag": "component", "value": "certificate"}]}
    api.call("item.create", [
        {**common, "name": CERT_DAYS_ITEM, "key_": "cert.days", "value_type": 0, "units": "days",
         "preprocessing": _js(DAYS_JS.format(expr="JSON.parse(value).x509.not_after.timestamp"))},
        {**common, "name": "Certificate: Expires on", "key_": "cert.not_after", "value_type": 3,
         "units": "unixtime", "preprocessing": _jsonpath("$.x509.not_after.timestamp")},
        {**common, "name": "Certificate: Validation result", "key_": "cert.validation", "value_type": 1,
         "preprocessing": _jsonpath("$.result.value")},
        {**common, "name": "Certificate: Validation message", "key_": "cert.message", "value_type": 4,
         "preprocessing": _jsonpath("$.result.message")},
        {**common, "name": "Certificate: Issuer", "key_": "cert.issuer", "value_type": 4,
         "preprocessing": _jsonpath("$.x509.issuer")},
        {**common, "name": "Certificate: Subject alternative names", "key_": "cert.alternative_names",
         "value_type": 4, "preprocessing": _jsonpath("$.x509.alternative_names")},
    ])
    tpl = CERT_TEMPLATE
    _expiry_triggers(api, tpl, "cert.days", "SSL certificate of {$CERT.WEBSITE.HOSTNAME}",
                     "$CERT.EXPIRY.WARN", "$CERT.EXPIRY.HIGH", "cert.days", "3h", "certificate")
    api.call("trigger.create", {
        "description": "SSL certificate of {$CERT.WEBSITE.HOSTNAME} is invalid",
        "expression": f'find(/{tpl}/cert.validation,,"like","invalid")=1',
        "priority": 4, "tags": [{"tag": "type", "value": "certificate"}],
        "comments": "Validation message: see the item 'Certificate: Validation message'.",
    })
    log(f"- template '{CERT_TEMPLATE}' created")
    return tid


def ensure_domain_template(api, log=print):
    tid, created = _template(api, DOMAIN_TEMPLATE,
                             "Created by zabbix-autodiscovery. Domain expiration through RDAP, queried at the "
                             "registry of each TLD (e.g. registro.br, Verisign; set per host in {$DOMAIN.RDAP.URL}). "
                             "Needs internet access from the Zabbix server or proxy. Set {$DOMAIN.NAME} on the host.",
                             {"{$DOMAIN.NAME}": "", "{$DOMAIN.EXPIRY.WARN}": "30", "{$DOMAIN.EXPIRY.HIGH}": "7",
                              "{$DOMAIN.RDAP.URL}": RDAP_FALLBACK})
    headers = [{"name": "Accept", "value": "application/rdap+json"}, {"name": "User-Agent", "value": USER_AGENT}]
    if api.version < (7, 0):
        headers = {h["name"]: h["value"] for h in headers}
    if not created:
        # upgrade templates created by older versions (missing User-Agent)
        master = api.call("item.get", {"output": ["itemid", "headers"], "hostids": tid, "filter": {"key_": "rdap.get"}})
        if master and "User-Agent" not in str(master[0]["headers"]):
            api.call("item.update", {"itemid": master[0]["itemid"], "headers": headers})
            log(f"- template '{DOMAIN_TEMPLATE}': User-Agent header added")
        return tid
    master = api.call("item.create", {
        "hostid": tid, "name": "Domain: RDAP data", "key_": "rdap.get", "type": 19, "value_type": 4,
        "url": "{$DOMAIN.RDAP.URL}{$DOMAIN.NAME}", "headers": headers, "follow_redirects": 1,
        "timeout": "15s", "status_codes": "200", "delay": "12h", "history": "7d",
        "tags": [{"tag": "component", "value": "domain"}],
    })["itemids"][0]
    common = {"hostid": tid, "type": 18, "master_itemid": master, "history": "365d",
              "tags": [{"tag": "component", "value": "domain"}]}
    api.call("item.create", [
        {**common, "name": DOMAIN_DAYS_ITEM, "key_": "rdap.days", "value_type": 0, "units": "days",
         "preprocessing": _js(RDAP_EXPIRES_JS.replace(
             "return Math.floor(Date.parse(events[i].eventDate) / 1000);",
             "return Math.floor((Date.parse(events[i].eventDate) / 1000 - Date.now() / 1000) / 86400);"))},
        {**common, "name": "Domain: Expires on", "key_": "rdap.expires", "value_type": 3, "units": "unixtime",
         "preprocessing": _js(RDAP_EXPIRES_JS)},
        {**common, "name": "Domain: Status", "key_": "rdap.status", "value_type": 4,
         "preprocessing": _js("return (JSON.parse(value).status || []).join(', ');")},
    ])
    _expiry_triggers(api, DOMAIN_TEMPLATE, "rdap.days", "Domain {$DOMAIN.NAME}",
                     "$DOMAIN.EXPIRY.WARN", "$DOMAIN.EXPIRY.HIGH", "rdap.days", "2d", "domain")
    log(f"- template '{DOMAIN_TEMPLATE}' created")
    return tid


# ---------------------------------------------------------------- targets

def parse_site(text):
    """'https://www.example.com/', 'example.com:8443' -> ('www.example.com', 443)."""
    text = str(text).strip()
    parts = urlsplit(text if "//" in text else f"//{text}")
    if not parts.hostname:
        raise ValueError(f"invalid site: {text}")
    return parts.hostname.lower(), parts.port or 443


def rdap_bootstrap():
    """TLD -> RDAP base URL from IANA's official bootstrap file ({} when offline)."""
    try:
        data = requests.get(IANA_RDAP_BOOTSTRAP, timeout=15, headers={"User-Agent": USER_AGENT}).json()
    except (requests.RequestException, ValueError):
        return {}
    return {tld: urls[0] for tlds, urls in data.get("services", []) for tld in tlds if urls}


def rdap_url(domain, bootstrap):
    """RDAP 'domain/' endpoint of the registry for this domain (longest matching suffix)."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        base = bootstrap.get(".".join(labels[i + 1:]))
        if base:
            return base.rstrip("/") + "/domain/"
    return RDAP_FALLBACK


def clean_domain(text):
    domain = str(text).strip().lower().rstrip(".")
    if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z0-9-]{2,}", domain):
        raise ValueError(f"invalid domain: {text}")
    return domain


def sites_from_inventory(rows):
    """Publicly trusted certificates found by the scan (self-signed ones are skipped)."""
    sites = []
    for row in rows:
        if row.get("cert_self_signed") != "no" or not row.get("cert_names"):
            continue
        name = next((n for n in row["cert_names"].split(",") if n and not n.startswith("*")), "")
        port = next((int(p.split("=")[0]) for p in row.get("web_servers", "").split("; ")
                     if p.split("=")[0] in ("443", "8443")), 443)
        if name:
            sites.append((name.lower(), port, row["ip"]))
    return sites


# ---------------------------------------------------------------- provisioning

def _agent2_interface(api, host_name):
    found = api.call("host.get", {"output": ["hostid"], "filter": {"host": host_name},
                                  "selectInterfaces": ["type", "main", "useip", "ip", "dns", "port"]})
    if not found:
        raise SystemExit(f"web.certificates.agent2_host '{host_name}' not found in Zabbix")
    iface = next((i for i in found[0]["interfaces"] if i["type"] == "1" and i["main"] == "1"), None)
    if not iface:
        raise SystemExit(f"host '{host_name}' has no Zabbix agent interface")
    return {k: iface[k] for k in ("useip", "ip", "dns", "port")} | {"type": 1, "main": 1}


def _technical(prefix, name, port=None):
    base = f"{prefix}-{name}" + (f"-{port}" if port and port != 443 else "")
    return re.sub(r"[^0-9A-Za-z._-]", "_", base)[:128]


def provision(api, cfg, extra_sites=(), dry_run=False, log=print):
    web = cfg.get("web") or {}
    certs, domains = web.get("certificates") or {}, web.get("domains") or {}
    existing = {h["host"] for h in api.call("host.get", {"output": ["host"]})}
    stats = {"planned" if dry_run else "created": 0, "existing": 0}

    sites = [(*parse_site(s), "") for s in certs.get("sites") or []] + list(extra_sites)
    if sites and not dry_run:
        cert_tid = ensure_cert_template(api, log)
        iface = _agent2_interface(api, certs.get("agent2_host", "Zabbix server"))
        cert_group = api.ensure_hostgroup(certs.get("group", "Web/Certificates"))
    seen = set()
    for hostname, port, ip in sites:
        tech = _technical("cert", hostname, port)
        if tech in seen:
            continue
        seen.add(tech)
        visible = certs.get("name_format", "SSL certificate: {host}").format(
            host=hostname if port == 443 else f"{hostname}:{port}")
        if tech in existing:
            log(f"  = {visible}: already monitored")
            stats["existing"] += 1
            continue
        if dry_run:
            log(f"  + {visible}  [{certs.get('group', 'Web/Certificates')}]  (dry-run)")
            stats["planned"] += 1
            continue
        macros = [{"macro": "{$CERT.WEBSITE.HOSTNAME}", "value": hostname},
                  {"macro": "{$CERT.WEBSITE.PORT}", "value": str(port)},
                  {"macro": "{$CERT.WEBSITE.IP}", "value": ip}]
        for key, macro in (("warn_days", "{$CERT.EXPIRY.WARN}"), ("high_days", "{$CERT.EXPIRY.HIGH}")):
            if certs.get(key):
                macros.append({"macro": macro, "value": str(certs[key])})
        api.call("host.create", {
            "host": tech, "name": visible, "groups": [{"groupid": cert_group}],
            "templates": [{"templateid": cert_tid}], "interfaces": [iface], "macros": macros,
            "tags": [{"tag": "type", "value": "certificate"}, {"tag": "origin", "value": "autodiscovery"}],
        })
        log(f"  + {visible}")
        stats["created"] += 1

    names = [clean_domain(d) for d in domains.get("list") or []]
    bootstrap = rdap_bootstrap() if names else {}
    if names and not dry_run:
        domain_tid = ensure_domain_template(api, log)
        domain_group = api.ensure_hostgroup(domains.get("group", "Web/Domains"))
        domain_hosts = {h["host"]: h for h in api.call("host.get", {
            "output": ["hostid", "host"], "selectMacros": ["hostmacroid", "macro", "value"],
            "tags": [{"tag": "type", "value": "domain", "operator": 1}]})}
    for domain in dict.fromkeys(names):
        tech = _technical("domain", domain)
        visible = domains.get("name_format", "Domain: {domain}").format(domain=domain)
        url = rdap_url(domain, bootstrap)
        if tech in existing:
            current = domain_hosts.get(tech) if not dry_run else None
            macro = next((m for m in (current or {}).get("macros", []) if m["macro"] == "{$DOMAIN.RDAP.URL}"), None)
            if current and (macro or {}).get("value") != url:      # keep the RDAP endpoint up to date
                if macro:
                    api.call("usermacro.update", {"hostmacroid": macro["hostmacroid"], "value": url})
                else:
                    api.call("usermacro.create", {"hostid": current["hostid"], "macro": "{$DOMAIN.RDAP.URL}",
                                                  "value": url})
                log(f"  ~ {visible}: RDAP endpoint set to {url}")
                stats["updated"] = stats.get("updated", 0) + 1
            else:
                log(f"  = {visible}: already monitored")
                stats["existing"] += 1
            continue
        if dry_run:
            log(f"  + {visible}  [{domains.get('group', 'Web/Domains')}]  RDAP {url}  (dry-run)")
            stats["planned"] += 1
            continue
        macros = [{"macro": "{$DOMAIN.NAME}", "value": domain}, {"macro": "{$DOMAIN.RDAP.URL}", "value": url}]
        for key, macro in (("warn_days", "{$DOMAIN.EXPIRY.WARN}"), ("high_days", "{$DOMAIN.EXPIRY.HIGH}")):
            if domains.get(key):
                macros.append({"macro": macro, "value": str(domains[key])})
        api.call("host.create", {
            "host": tech, "name": visible, "groups": [{"groupid": domain_group}],
            "templates": [{"templateid": domain_tid}], "interfaces": [], "macros": macros,
            "tags": [{"tag": "type", "value": "domain"}, {"tag": "origin", "value": "autodiscovery"}],
        })
        log(f"  + {visible}")
        stats["created"] += 1

    if not dry_run and (sites or names):
        ensure_dashboard(api, cfg, log)
    return stats


def ensure_dashboard(api, cfg, log=print):
    if api.call("dashboard.get", {"output": ["dashboardid"], "filter": {"name": DASHBOARD}}):
        return
    web = cfg.get("web") or {}
    groups = {"cert": (web.get("certificates") or {}).get("group", "Web/Certificates"),
              "domain": (web.get("domains") or {}).get("group", "Web/Domains")}
    ids = {k: api.ensure_hostgroup(v) for k, v in groups.items()}
    full = 72 if api.version >= (7, 0) else 24
    half = full // 2

    def f(t, n, v):
        return {"type": t, "name": n, "value": v}

    def expiring(title, groupid, days_item, extra_item, extra_title, x):
        return {"type": "tophosts", "name": title, "x": x, "y": 5, "width": half, "height": 10, "fields": [
            f(2, "groupids.0", groupid),
            f(1, "columns.0.name", "Host"), f(0, "columns.0.data", 2),
            f(1, "columns.1.name", "Days left"), f(0, "columns.1.data", 1), f(1, "columns.1.item", days_item),
            f(1, "columnsthresholds.1.color.0", "FF4000"), f(1, "columnsthresholds.1.threshold.0", "0"),
            f(1, "columnsthresholds.1.color.1", "FFA726"), f(1, "columnsthresholds.1.threshold.1", "7"),
            f(1, "columnsthresholds.1.color.2", "4CAF50"), f(1, "columnsthresholds.1.threshold.2", "30"),
            f(1, "columns.2.name", extra_title), f(0, "columns.2.data", 1), f(1, "columns.2.item", extra_item),
            f(0, "column", 1), f(0, "order", 3), f(0, "count", 100)]}

    widgets = [
        {"type": "problems", "name": "Expiring or invalid certificates and domains", "x": 0, "y": 0,
         "width": full, "height": 5,
         "fields": [f(2, "groupids.0", ids["cert"]), f(2, "groupids.1", ids["domain"]), f(0, "show_lines", 25)]},
        expiring("SSL certificates", ids["cert"], CERT_DAYS_ITEM, "Certificate: Validation result", "Validation", 0),
        expiring("Domains", ids["domain"], DOMAIN_DAYS_ITEM, "Domain: Status", "Status", half),
    ]
    params = {"name": DASHBOARD, "display_period": 30, "auto_start": 1, "pages": [{"widgets": widgets}]}
    try:
        api.call("dashboard.create", params)
    except ZabbixError as exc:
        params["pages"] = [{"widgets": widgets[:1]}]
        api.call("dashboard.create", params)
        log(f"  ! '{DASHBOARD}': created with problems only ({exc})")
        return
    log(f"- dashboard '{DASHBOARD}' created")
