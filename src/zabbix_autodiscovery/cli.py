"""zabbix-autodiscovery: discover network devices and onboard them into Zabbix (6.0 to 8.0).

Typical flow:
  zabbix-autodiscovery init                                # write config.yaml (+ .env) in the current folder
  zabbix-autodiscovery check                               # read-only: token, permissions, templates, what would change
  zabbix-autodiscovery scan  -o inventory.csv              # scan + classify, writes a CSV (Zabbix is not touched)
  (review the CSV: column "action" = add | review | ignore)
  zabbix-autodiscovery apply -i inventory.csv --dry-run
  zabbix-autodiscovery setup                               # groups, agent-missing template, dashboards
  zabbix-autodiscovery apply -i inventory.csv
  zabbix-autodiscovery agent-sync                          # switch servers that got an agent to agent templates
  zabbix-autodiscovery web [--dry-run]                     # SSL certificate and domain expiration monitoring
  zabbix-autodiscovery update-templates [--dry-run]        # link category add-on templates to existing hosts
  zabbix-autodiscovery maps [--rebuild]                    # one Zabbix map per site, icon per device type
  zabbix-autodiscovery grafana-dashboards -o ./dashboards  # optional: Grafana JSON per device type
"""
import argparse
import asyncio
import csv
import json
import sys
from collections import Counter
from importlib import resources
from pathlib import Path

from . import __version__, classifier, dashboards, maps, provision, scanner, templates, web
from .config import ConfigError, credentials_by_name, default_community, in_networks, load_config, site_for
from .zabbix_api import ZabbixAPI, ZabbixError

CSV_FIELDS = ["action", "site", "category", "hostname", "visible_name", "name_source", "ip", "group",
              "templates", "interface", "tags", "rule", "vendor", "sysname", "netbios", "dns",
              "dns_confirmed", "agent_hostname", "system_hostname", "sysobjectid", "sysdescr",
              "snmp_cred", "ports", "web_servers", "cert_names", "cert_expires", "cert_issuer",
              "cert_self_signed", "ping", "agent_uname"]
SNMP_AUTH = {"MD5": 0, "SHA": 1, "SHA256": 3, "SHA512": 5}
SNMP_PRIV = {"DES": 0, "AES": 1, "AES256": 3}
ENV_TEMPLATE = """# Local secrets for zabbix-autodiscovery (never commit this file)
ZABBIX_TOKEN=
SNMP_COMMUNITY=
# ZABBIX_GRAFANA_USER=grafana
# ZABBIX_GRAFANA_PASSWORD=
"""


def connect(cfg):
    z = cfg["zabbix"]
    try:
        api = ZabbixAPI(z["url"], token=z.get("token"), user=z.get("user"),
                        password=z.get("password"), verify_tls=z.get("verify_tls", True))
    except Exception as exc:
        raise SystemExit(f"Could not connect to Zabbix: {exc}")
    print(f"Connected to Zabbix {api.version_str}")
    return api


def parse_tags(text):
    tags = []
    for part in filter(None, (p.strip() for p in (text or "").split(","))):
        key, _, value = part.partition("=")
        tags.append({"tag": key.strip(), "value": value.strip()})
    return tags


# ---------------------------------------------------------------- init

def cmd_init(args):
    target = Path(args.config)
    if target.exists() and not args.force:
        raise SystemExit(f"{target} already exists (use --force to overwrite)")
    example = resources.files("zabbix_autodiscovery").joinpath("data/config.example.yaml")
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    env = target.resolve().parent / ".env"
    if not env.exists():
        env.write_text(ENV_TEMPLATE, encoding="utf-8")
    print(f"Created {target} and {env.name}. Edit zabbix.url and scan.networks, put secrets in {env.name},"
          " then run: zabbix-autodiscovery check")


# ---------------------------------------------------------------- scan

def cmd_scan(cfg, args):
    def progress(done, total, found, phase="first pass"):
        if done == total or done % 25 == 0:
            print(f"  {phase}: {done}/{total} IPs probed, {found} responding", flush=True)

    print("Scanning:", ", ".join(cfg["scan"]["networks"]))
    devices = asyncio.run(scanner.scan(cfg["scan"], cfg.get("snmp_credentials", []), progress))
    rows = [classifier.classify(d, cfg) for d in devices]

    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, delimiter=args.delimiter, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nInventory written to {args.output}\n")
    print(f"  {'category':<20}{'action':<10}count")
    for (cat, action), n in sorted(Counter((r["category"], r["action"]) for r in rows).items()):
        print(f"  {cat:<20}{action:<10}{n}")
    sources = Counter(r["name_source"] for r in rows if r["action"] != "ignore")
    print("\n  Host name sources (add/review): " + ", ".join(f"{k}={v}" for k, v in sorted(sources.items())))
    missing = [r for r in rows if "agent=missing" in r.get("tags", "")]
    if missing:
        print(f"\n  {len(missing)} server(s) without Zabbix agent: "
              + ", ".join(f"{r['hostname']} ({r['ip']})" for r in missing[:15]))
    print(f"\nReview the CSV (especially 'review' and 'unknown'), then run: "
          f"zabbix-autodiscovery apply -i {args.output} --dry-run")


# ---------------------------------------------------------------- apply

def build_interface(row, cfg, global_community):
    kind = (row.get("interface") or "snmp").strip()
    base = {"main": 1, "useip": 1, "ip": row["ip"], "dns": ""}
    macros = []
    if kind != "snmp":
        return {**base, "type": 1, "port": "10050"}, macros

    cred = credentials_by_name(cfg).get(row.get("snmp_cred", ""))
    if not cred:
        raise ValueError("SNMP interface without a valid SNMP credential (column snmp_cred)")
    version = str(cred.get("version", "2c"))
    if version in ("1", "2", "2c"):
        details = {"version": 1 if version == "1" else 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}
        if cred["community"] != global_community:
            macros.append({"macro": "{$SNMP_COMMUNITY}", "value": cred["community"]})
    else:
        level = 2 if cred.get("priv_pass") else 1 if cred.get("auth_pass") else 0
        details = {"version": 3, "bulk": 1, "contextname": "", "securityname": cred["user"],
                   "securitylevel": level}
        if level >= 1:
            details["authprotocol"] = SNMP_AUTH[cred.get("auth_protocol", "SHA").upper()]
            details["authpassphrase"] = cred["auth_pass"]
        if level == 2:
            details["privprotocol"] = SNMP_PRIV[cred.get("priv_protocol", "AES").upper()]
            details["privpassphrase"] = cred["priv_pass"]
    return {**base, "type": 2, "port": "161", "details": details}, macros


class ProxyResolver:
    def __init__(self, api):
        self.api, self.cache = api, {}

    def params(self, name):
        """host.create parameters to monitor through a proxy (empty = the server itself)."""
        if not name:
            return {}
        if name not in self.cache:
            field = "name" if self.api.version >= (7, 0) else "host"
            found = self.api.call("proxy.get", {"output": ["proxyid"], "filter": {field: name}})
            if not found:
                raise SystemExit(f"Zabbix proxy '{name}' not found")
            pid = found[0]["proxyid"]
            self.cache[name] = ({"monitored_by": 1, "proxyid": pid} if self.api.version >= (7, 0)
                                else {"proxy_hostid": pid})
        return self.cache[name]


def read_inventory(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        delimiter = ";" if sample.count(";") >= sample.count(",") else ","
        return list(csv.DictReader(f, delimiter=delimiter))


def addon_templates(cfg, category):
    """Add-on templates linked to every host of a category (config: category_templates)."""
    return list((cfg.get("category_templates") or {}).get(category) or [])


def all_addons(cfg):
    return sorted({t for names in (cfg.get("category_templates") or {}).values() for t in names or []})


def cmd_apply(cfg, args):
    rows = [r for r in read_inventory(args.input) if r.get("action", "").strip().lower() == "add"]
    if not rows:
        raise SystemExit("No rows with action=add in the CSV.")

    api = connect(cfg)
    if not args.dry_run and any(provision.AGENT_TEMPLATE in r.get("templates", "") for r in rows):
        provision.ensure_agent_template(api)
    if not args.dry_run:
        templates.ensure_addons(api, all_addons(cfg))
    tmpl_map = api.template_ids()
    tmpl_names = {v: k for k, v in tmpl_map.items()}
    interfaces = api.call("hostinterface.get", {"output": ["ip", "dns"]})
    existing_ips = {i["ip"] for i in interfaces if i["ip"]}
    existing_dns = {i["dns"].lower() for i in interfaces if i["dns"]}
    all_hosts = api.call("host.get", {"output": ["host", "name"]})
    existing_names = {h["host"].lower() for h in all_hosts}
    existing_visible = {h["name"].lower() for h in all_hosts}
    global_community = api.global_macro("{$SNMP_COMMUNITY}")
    site_group = cfg.get("site_group", "Sites/{site}")
    proxies = ProxyResolver(api)
    stats = Counter()

    for row in rows:
        ip = row["ip"].strip()
        label = f"{ip:<16}{row['category']:<18}"
        if ip in existing_ips:
            print(f"  = {label}IP already monitored, skipped")
            stats["existing"] += 1
            continue
        if row.get("dns") and row["dns"].lower() in existing_dns:
            print(f"  = {label}already monitored by DNS {row['dns']}, skipped")
            stats["existing"] += 1
            continue

        name = row["hostname"].strip() or f"{row['category']}-{ip}"
        if name.lower() in existing_names or name.lower() in existing_visible:
            # Same name, different IP: most likely the same device monitored through another address
            if not args.allow_duplicate_names:
                print(f"  ~ {label}'{name}' already exists in Zabbix with another IP: possible duplicate, "
                      "skipped (use --allow-duplicate-names to create it as name-IP)")
                stats["possible duplicate"] += 1
                continue
            print(f"  ! {label}name '{name}' already used; creating as '{name}-{ip}'")
            name = f"{name}-{ip}"
        visible = (row.get("visible_name") or "").strip()
        if visible and visible.lower() in existing_visible | existing_names:
            visible = f"{visible} ({ip})"
        spec = ",".join(filter(None, [row.get("templates", "")] + (
            addon_templates(cfg, row["category"]) if row.get("interface", "snmp") == "snmp" else [])))
        template_ids, missing = provision.resolve_templates(spec, tmpl_map)
        for m in missing:
            created_later = m == provision.AGENT_TEMPLATE or m in templates.ENSURE
            if not (args.dry_run and created_later):                    # created by setup / real apply
                print(f"  ! {label}template not found: {m}")
        try:
            interface, macros = build_interface(row, cfg, global_community)
        except ValueError as exc:
            print(f"  x {label}{exc}")
            stats["error"] += 1
            continue

        tags = [{"tag": "type", "value": row["category"]}, {"tag": "origin", "value": "autodiscovery"}]
        if row.get("vendor"):
            tags.append({"tag": "vendor", "value": row["vendor"]})
        tags += parse_tags(row.get("tags"))
        site = site_for(cfg, ip)
        site_name = (row.get("site") or site.get("site") or "").strip()
        if site_name:
            tags.append({"tag": "site", "value": site_name})
        groups = [row.get("group") or "Discovered/Unassigned"]
        if site_name and site_group:
            groups.append(site_group.format(site=site_name))
        proxy = proxies.params(site.get("proxy") or cfg["zabbix"].get("proxy"))

        if args.dry_run:
            used = [tmpl_names[t] for t in template_ids] + [
                m for m in missing if m == provision.AGENT_TEMPLATE or m in templates.ENSURE]
            print(f"  + {label}{name:<28} [{' + '.join(groups)}]  name via {row.get('name_source') or '?'}\n"
                  f"      templates: {', '.join(used) or '(none)'}")
            stats["planned"] += 1
            continue
        params = {
            "host": name,
            **({"name": visible} if visible else {}),
            "groups": [{"groupid": api.ensure_hostgroup(g)} for g in groups],
            "templates": [{"templateid": t} for t in template_ids],
            "interfaces": [interface],
            "tags": tags,
            "macros": macros,
            "inventory_mode": 1,
            **proxy,
        }
        try:
            api.call("host.create", params)
        except ZabbixError as exc:
            print(f"  x {label}{name}: {exc}")
            stats["error"] += 1
            continue
        existing_ips.add(ip)
        existing_names.add(name.lower())
        existing_visible.add((visible or name).lower())
        print(f"  + {label}{name}  [{' + '.join(groups)}]")
        stats["created"] += 1

    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))


# ---------------------------------------------------------------- agent-sync

def cmd_agent_sync(cfg, args):
    """Hosts tagged agent=missing: when the agent now answers, link the agent templates."""
    api = connect(cfg)
    hosts = api.call("host.get", {
        "output": ["hostid", "host"],
        "tags": [{"tag": "agent", "value": "missing", "operator": 1}],
        "selectInterfaces": ["interfaceid", "type", "ip", "main"],
        "selectParentTemplates": ["templateid", "host"],
        "selectTags": ["tag", "value"],
    })
    if not hosts:
        print("No hosts tagged agent=missing.")
        return
    tmpl_map = api.template_ids()
    timeout = float(cfg["scan"].get("timeout", 2))
    pending = []
    for h in hosts:
        ip = next((i["ip"] for i in h["interfaces"] if i["ip"]), None)
        if not ip:
            continue
        uname = asyncio.run(scanner.agent_get(ip, "system.uname", timeout))
        if not uname:
            pending.append(f"{h['host']} ({ip})")
            continue
        dev = scanner.Device(ip, alive=True, ports=[scanner.AGENT_PORT], agent_uname=uname,
                             agent_hostname=asyncio.run(scanner.agent_get(ip, "agent.hostname", timeout)))
        row = classifier.classify(dev, cfg)
        if row["interface"] != "agent" or row["action"] == "ignore":
            print(f"  ? {h['host']} ({ip}): agent answers, but rule '{row['rule']}' is not a server rule")
            continue
        new_ids, _ = provision.resolve_templates(row["templates"], tmpl_map)
        agent_tid = tmpl_map.get(provision.AGENT_TEMPLATE)
        current = [t["templateid"] for t in h["parentTemplates"] if t["templateid"] != agent_tid]
        tags = [t for t in h["tags"] if t["tag"] != "agent"] + [{"tag": "agent", "value": "installed"}]

        if args.dry_run:
            print(f"  + {h['host']} ({ip}): would link {row['templates']} (dry-run)")
            continue
        if not any(i["type"] == "1" for i in h["interfaces"]):
            api.call("hostinterface.create", {"hostid": h["hostid"], "type": 1, "main": 1, "useip": 1,
                                              "ip": ip, "dns": "", "port": "10050"})
        update = {"hostid": h["hostid"], "tags": tags,
                  "templates_clear": [{"templateid": agent_tid}] if agent_tid else []}
        # Active checks require the technical host name to equal the agent's Hostname=
        if dev.agent_hostname and dev.agent_hostname != h["host"]:
            if api.call("host.get", {"output": ["hostid"], "filter": {"host": dev.agent_hostname}}):
                print(f"  ! {h['host']}: agent Hostname= ('{dev.agent_hostname}') is used by another host")
            else:
                update["host"] = dev.agent_hostname
                update["name"] = h["host"]
        try:
            api.call("host.update", {**update, "templates": [{"templateid": t} for t in current + new_ids]})
        except ZabbixError:
            # duplicate item key (e.g. ICMP already comes from an SNMP template): retry without it
            ids = [t for t in new_ids if t != tmpl_map.get("ICMP Ping")]
            api.call("host.update", {**update, "templates": [{"templateid": t} for t in current + ids]})
        print(f"  + {h['host']} ({ip}): agent detected, agent templates linked")
    if pending:
        print(f"\nStill without agent ({len(pending)}): " + ", ".join(pending))


# ---------------------------------------------------------------- check (read-only)

def cmd_check(cfg, args):
    """Validate connection, permissions and what setup/apply would do, without changing anything."""
    api = connect(cfg)
    ok = True
    try:
        hosts = api.call("host.get", {"countOutput": True})
        groups = api.call("hostgroup.get", {"output": ["name"]})
        print(f"- read access OK: {hosts} hosts and {len(groups)} host groups visible")
    except ZabbixError as exc:
        raise SystemExit(f"  x no read access: {exc}")

    if cfg["zabbix"].get("token"):
        try:
            user = api.call("user.checkAuthentication", {"token": cfg["zabbix"]["token"]}, auth=False)
            role = api.call("role.get", {"roleids": user.get("roleid"), "output": ["name", "type"]})
            rtype = {"1": "User", "2": "Admin", "3": "Super admin"}.get(role[0]["type"], "?") if role else "?"
            print(f"- token of user '{user.get('username')}' "
                  f"(role '{role[0]['name'] if role else '?'}', type {rtype})")
            if rtype != "Super admin":
                print("  ! setup needs a Super admin (creates template, role and groups); apply needs Admin")
                ok = False
        except ZabbixError as exc:
            print(f"  ! could not read the token's role ({exc})")

    existing = {g["name"] for g in groups}
    wanted = sorted({r["group"] for r in cfg.get("rules", [])
                     if r.get("group") and r.get("action") in ("add", "review")})
    new_groups = [g for g in wanted if g not in existing]
    print(f"- host groups: {len(wanted) - len(new_groups)} exist, {len(new_groups)} would be created"
          + (f": {', '.join(new_groups)}" if new_groups else ""))

    tmpl_map = api.template_ids()
    missing = set()
    for r in cfg.get("rules", []):
        if r.get("action") != "ignore":
            _, miss = provision.resolve_templates(",".join(classifier.as_list(r.get("templates"))), tmpl_map)
            missing.update(m for m in miss if m != provision.AGENT_TEMPLATE)
    if missing:
        print("- templates with no available alternative on this Zabbix (adjust the rules):")
        for m in sorted(missing):
            print(f"    {m}")
    else:
        print("- templates: every rule has at least one available option")
    print(f"- template '{provision.AGENT_TEMPLATE}': "
          + ("exists" if provision.AGENT_TEMPLATE in tmpl_map else "would be created by setup"))

    macro = api.global_macro("{$SNMP_COMMUNITY}")
    if macro is None:
        print("- macro {$SNMP_COMMUNITY}: missing, setup would create it")
    elif macro == default_community(cfg):
        print("- macro {$SNMP_COMMUNITY}: exists with the same value as the config")
    else:
        print("- macro {$SNMP_COMMUNITY}: exists with another value -> kept; new hosts get a host macro")

    networks = cfg["scan"]["networks"]
    in_range = {i["ip"] for i in api.call("hostinterface.get", {"output": ["ip"]})
                if i["ip"] and in_networks(networks, i["ip"])}
    print(f"- {len(in_range)} IPs in these networks are already monitored (apply will skip them)")
    drules = api.call("drule.get", {"output": ["name", "iprange"]})
    overlapping = [d["name"] for d in drules if any(n.split("/")[0].rsplit(".", 1)[0] in d["iprange"]
                                                    for n in networks)]
    if overlapping:
        print(f"- existing discovery rules covering these networks: {', '.join(overlapping)} "
              "(avoid also enabling --native-discovery on the same ranges)")
    webcfg = cfg.get("web") or {}
    sites = (webcfg.get("certificates") or {}).get("sites") or []
    domains = (webcfg.get("domains") or {}).get("list") or []
    if sites or domains:
        agent2 = (webcfg.get("certificates") or {}).get("agent2_host", "Zabbix server")
        found = api.call("host.get", {"output": ["host"], "filter": {"host": agent2}}) if sites else True
        print(f"- web: {len(sites)} certificate(s), {len(domains)} domain(s) configured"
              + ("" if found else f"; ! agent2_host '{agent2}' not found"))
    names = {d["name"] for d in api.call("dashboard.get", {"output": ["name"]})}
    ours = [s for s in dashboards.SPECS if dashboards.groups_for(s, cfg)]
    exist = sum(1 for s in ours if f"{dashboards.PREFIX}{s['title']}" in names)
    print(f"- AutoDiscovery dashboards: {exist} of {len(ours)} already exist")
    print("\nNothing was changed." + ("" if ok else " Fix the warnings (!) before running setup."))


# ---------------------------------------------------------------- setup / grafana

def cmd_update_templates(cfg, args):
    """Link the category add-on templates to hosts created earlier (only SNMP-monitored hosts)."""
    wanted = cfg.get("category_templates") or {}
    if not wanted:
        raise SystemExit("Nothing to do: category_templates is empty in the config")
    api = connect(cfg)
    if not args.dry_run:
        templates.ensure_addons(api, all_addons(cfg))
    tmpl_map = api.template_ids()
    hosts = api.call("host.get", {
        "output": ["hostid", "host", "name"], "selectTags": ["tag", "value"],
        "selectInterfaces": ["type"], "selectParentTemplates": ["templateid"],
        "tags": [{"tag": "origin", "value": "autodiscovery", "operator": 1}]})
    stats = Counter()
    for h in sorted(hosts, key=lambda h: h["name"].lower()):
        category = next((t["value"] for t in h["tags"] if t["tag"] == "type"), "")
        names = wanted.get(category) or []
        if not names or not any(i["type"] == "2" for i in h["interfaces"]):
            continue
        current = {t["templateid"] for t in h["parentTemplates"]}
        ids, missing = provision.resolve_templates(",".join(names), tmpl_map)
        new = [t for t in ids if t not in current]
        if args.dry_run:
            todo = [n for n in names if tmpl_map.get(n) not in current]
            if todo:
                print(f"  + {h['name']:<32} would link: {', '.join(todo)}")
                stats["planned"] += 1
            continue
        for m in missing:
            print(f"  ! {h['name']}: template not found: {m}")
        if not new:
            stats["up to date"] += 1
            continue
        try:
            api.call("host.update", {"hostid": h["hostid"],
                                     "templates": [{"templateid": t} for t in sorted(current) + new]})
            print(f"  + {h['name']:<32} linked: {', '.join(n for n in names if tmpl_map.get(n) in new)}")
            stats["updated"] += 1
        except ZabbixError as exc:
            print(f"  x {h['name']}: {exc}")
            stats["error"] += 1
    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in sorted(stats.items())) or "nothing to do")


def cmd_maps(cfg, args):
    api = connect(cfg)
    maps.provision(api, cfg, Path(args.config).resolve().parent, rebuild=args.rebuild, dry_run=args.dry_run)


def cmd_setup(cfg, args):
    api = connect(cfg)
    templates.ensure_addons(api, all_addons(cfg))
    provision.setup(api, cfg, native_discovery=args.native_discovery, force=args.force,
                    zabbix_dashboards=not args.no_dashboards)


def cmd_web(cfg, args):
    if not (cfg.get("web") or {}).get("certificates", {}).get("sites") and \
            not (cfg.get("web") or {}).get("domains", {}).get("list") and not args.input:
        raise SystemExit("Nothing to do: add web.certificates.sites and/or web.domains.list to the config")
    extra = web.sites_from_inventory(read_inventory(args.input)) if args.input else []
    api = connect(cfg)
    stats = web.provision(api, cfg, extra_sites=extra, dry_run=args.dry_run)
    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in stats.items()))


def cmd_grafana_dashboards(cfg, args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("autodiscovery-*.json"):
        old.unlink()
    for spec in dashboards.SPECS:
        if not dashboards.groups_for(spec, cfg):
            continue
        path = out / f"autodiscovery-{spec['key']}.json"
        path.write_text(json.dumps(dashboards.grafana_dashboard(spec, cfg, args.datasource_uid),
                                   ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"written {path}")


# ---------------------------------------------------------------- main

def build_parser():
    parser = argparse.ArgumentParser(prog="zabbix-autodiscovery", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-V", "--version", action="version", version=f"zabbix-autodiscovery {__version__}")
    parser.add_argument("-c", "--config", default="config.yaml", help="config file (default: config.yaml)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="write a starter config.yaml and .env")
    p.add_argument("--force", action="store_true", help="overwrite an existing config")
    sub.add_parser("check", help="read-only: validate token, permissions, templates and planned changes")
    p = sub.add_parser("scan", help="scan the networks and write the inventory CSV")
    p.add_argument("-o", "--output", default="inventory.csv")
    p.add_argument("--delimiter", default=";", help="CSV delimiter (default ';', Excel-friendly in most locales)")
    p = sub.add_parser("apply", help="create the CSV rows with action=add in Zabbix")
    p.add_argument("-i", "--input", default="inventory.csv")
    p.add_argument("--dry-run", action="store_true", help="only show what would be done")
    p.add_argument("--allow-duplicate-names", action="store_true",
                   help="create hosts whose name already exists in Zabbix (as name-IP) instead of skipping them")
    p = sub.add_parser("setup", help="host groups, SNMP macro, agent-missing template, dashboards, Grafana user")
    p.add_argument("--native-discovery", action="store_true",
                   help="also create a Zabbix discovery rule + actions from rules with sysobjectid_prefix")
    p.add_argument("--force", action="store_true",
                   help="create native discovery even when monitored hosts are inside the ranges")
    p.add_argument("--no-dashboards", action="store_true", help="do not create native Zabbix dashboards")
    p = sub.add_parser("agent-sync", help="link agent templates to servers that now have an agent")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("update-templates", help="link the category add-on templates to existing hosts")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("maps", help="one Zabbix map per site with an icon per device type, plus a dashboard")
    p.add_argument("--rebuild", action="store_true", help="refresh existing AutoDiscovery maps with the current hosts")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("web", help="monitor SSL certificates and domain expiration (web section of the config)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("-i", "--input", help="also add the publicly trusted certificates found in this inventory CSV")
    p = sub.add_parser("grafana-dashboards", help="write Grafana dashboard JSON files (one per device type)")
    p.add_argument("-o", "--output", default="grafana-dashboards")
    p.add_argument("--datasource-uid", default="zabbix",
                   help="default Zabbix datasource UID (each dashboard also has a datasource selector)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "init":
        return cmd_init(args)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        raise SystemExit(f"Config error: {exc}")
    commands = {"check": cmd_check, "scan": cmd_scan, "apply": cmd_apply, "setup": cmd_setup,
                "agent-sync": cmd_agent_sync, "web": cmd_web, "update-templates": cmd_update_templates,
                "maps": cmd_maps, "grafana-dashboards": cmd_grafana_dashboards}
    try:
        commands[args.cmd](cfg, args)
    except ZabbixError as exc:
        hint = " Create a new API token and update your .env." if "expired" in str(exc).lower() else ""
        raise SystemExit(f"\nZabbix API error: {exc}.{hint}")
    except KeyboardInterrupt:
        raise SystemExit("\nInterrupted.")


if __name__ == "__main__":
    sys.exit(main())
