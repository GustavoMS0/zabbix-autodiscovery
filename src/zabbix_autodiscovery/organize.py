"""Bring the hosts that already existed in Zabbix into the same organization as discovered ones.

- organize: every host of the configured networks joins the host group of its device type and of its
  site, and gets the "type" / "site" tags. Additive: nothing is removed unless --remove-groups lists it.
- audit: read-only report of what organize would change plus common problems (duplicate IPs, agent
  templates without an agent, unsupported items, hosts outside the configured networks).
"""
import re
import socket
from collections import Counter, defaultdict

from .config import category_groups, site_for
from .inventory import category_of, first_ip, network_hosts, tag_value


def plan(api, cfg):
    """[(host, category, groups_to_add, tags_to_add)] for every host of the configured networks."""
    groups_by_cat = category_groups(cfg)
    site_group = cfg.get("site_group", "Sites/{site}")
    out = []
    for h in network_hosts(api, cfg["scan"]["networks"]):
        cat = category_of(h)
        site = site_for(cfg, first_ip(h)).get("site", "")
        wanted = [g for g in (groups_by_cat.get(cat), site_group.format(site=site) if site and site_group else None)
                  if g]
        have = {g["name"] for g in h["hostgroups"]}
        tags = {}
        if cat != "other" and not tag_value(h, "type"):
            tags["type"] = cat
        if site and not tag_value(h, "site"):
            tags["site"] = site
        out.append((h, cat, [g for g in wanted if g not in have], tags))
    return out


def organize(api, cfg, dry_run=False, remove_groups=(), log=print):
    stats = Counter()
    remove_groups = [g.strip() for g in remove_groups if g.strip()]
    remove_ids = {}
    if remove_groups and not dry_run:
        found = api.call("hostgroup.get", {"output": ["groupid", "name"], "filter": {"name": remove_groups}})
        remove_ids = {g["name"]: g["groupid"] for g in found}
    for h, cat, add_groups, add_tags in sorted(plan(api, cfg), key=lambda p: p[0]["name"].lower()):
        have = {g["name"] for g in h["hostgroups"]}
        drop = [g for g in remove_groups if g in have]
        # only drop a legacy group when the host ends up in its type group
        if drop and cat == "other":
            drop = []
        if not (add_groups or add_tags or drop):
            stats["already organized"] += 1
            continue
        changes = ([f"+group {g}" for g in add_groups] + [f"+tag {k}={v}" for k, v in add_tags.items()]
                   + [f"-group {g}" for g in drop])
        log(f"  {'~' if dry_run else '+'} {h['name']:<34} [{cat}] {'; '.join(changes)}")
        stats["planned" if dry_run else "updated"] += 1
        if dry_run:
            continue
        if add_groups:
            api.call("host.massadd", {"hosts": [{"hostid": h["hostid"]}],
                                      "groups": [{"groupid": api.ensure_hostgroup(g)} for g in add_groups]})
        if add_tags:
            tags = [{"tag": t["tag"], "value": t["value"]} for t in h["tags"]]
            tags += [{"tag": k, "value": v} for k, v in add_tags.items()]
            api.call("host.update", {"hostid": h["hostid"], "tags": tags})
        ids = [remove_ids[g] for g in drop if g in remove_ids]
        if ids:
            api.call("host.massremove", {"hostids": [h["hostid"]], "groupids": ids})
    return stats


def identity_issues(hosts, values, resolve=None):
    """Same machine on several hosts, agent Hostname= mismatches and IPs that disagree with DNS.

    values: {hostid: {item_key: lastvalue}} for system.hostname and agent.hostname.
    resolve: callable(name) -> set of IPs (DNS A records); None skips the DNS check.
    """
    by_machine = defaultdict(list)
    mismatched, dns_wrong = [], []
    for h in hosts:
        v = values.get(h["hostid"], {})
        machine = (v.get("system.hostname") or "").strip().lower()
        if machine:
            by_machine[machine].append(h)
        agent_name = (v.get("agent.hostname") or "").strip()
        if agent_name and agent_name != h["host"]:
            mismatched.append((h, agent_name))
        ips = {i["ip"] for i in h["interfaces"] if i.get("ip") and i["ip"] != "127.0.0.1"}
        if resolve and ips and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", h["host"]):
            dns_ips = resolve(h["host"])
            if dns_ips and not ips & dns_ips:
                dns_wrong.append((h, sorted(ips), sorted(dns_ips)))
    same = {m: hs for m, hs in by_machine.items() if len(hs) > 1}
    return same, mismatched, dns_wrong


def dns_lookup(name):
    try:
        return {info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)}
    except OSError:
        return set()


def audit(api, cfg, log=print):
    networks = cfg["scan"]["networks"]
    hosts = api.call("host.get", {
        "output": ["hostid", "host", "name", "status"], "selectInterfaces": ["type", "ip", "available"],
        "selectParentTemplates": ["name"], "selectHostGroups": ["name"], "selectTags": ["tag", "value"]})
    items = api.call("item.get", {"output": ["hostid", "state", "status"], "templated": False,
                                  "filter": {"state": 1, "status": 0}})
    unsupported = Counter(i["hostid"] for i in items)

    log("\n== Organization (what 'organize' would change) ==")
    pending = [(h, cat, g, t) for h, cat, g, t in plan(api, cfg) if g or t]
    for h, cat, groups, tags in sorted(pending, key=lambda p: p[0]["name"].lower()):
        log(f"  {h['name']:<34} [{cat}] " + "; ".join([f"+{g}" for g in groups] +
                                                         [f"+tag {k}={v}" for k, v in tags.items()]))
    if not pending:
        log("  every host is in its type and site groups")
    unknown = [h for h, cat, _, _ in plan(api, cfg) if cat == "other"]
    if unknown:
        log("  type not identified (add a template or a 'type' tag): " + ", ".join(h["name"] for h in unknown))

    log("\n== Same IP on more than one host (possible duplicates) ==")
    by_ip = defaultdict(set)
    for h in hosts:
        for i in h["interfaces"]:
            if i["ip"] and i["ip"] != "127.0.0.1":
                by_ip[i["ip"]].add(h["name"])
    dups = {ip: sorted(n) for ip, n in by_ip.items() if len(n) > 1}
    for ip, names in sorted(dups.items()):
        log(f"  {ip}: {', '.join(names)}")
    if not dups:
        log("  none")

    values = defaultdict(dict)
    for i in api.call("item.get", {"output": ["hostid", "key_", "lastvalue"], "templated": False,
                                   "filter": {"key_": ["system.hostname", "agent.hostname"]}}):
        values[i["hostid"]][i["key_"]] = i["lastvalue"]
    enabled = [h for h in hosts if h["status"] == "0"]
    same, mismatched, dns_wrong = identity_issues(enabled, values, dns_lookup)

    log("\n== Same machine monitored by more than one host (system.hostname) ==")
    for machine, hs in sorted(same.items()):
        log(f"  {machine}: " + ", ".join(f"{h['name']} ({next((i['ip'] for i in h['interfaces'] if i['ip']), '-')})"
                                        for h in hs))
    if not same:
        log("  none")

    log("\n== Host IP different from the DNS record of its name ==")
    for h, ips, dns_ips in dns_wrong:
        log(f"  {h['name']}: Zabbix uses {', '.join(ips)}, DNS says {', '.join(dns_ips)}")
    if not dns_wrong:
        log("  none (or names not resolvable)")

    log("\n== Agent Hostname= different from the Zabbix host name (active checks go to the wrong host) ==")
    for h, agent_name in mismatched:
        log(f"  {h['name']}: agent reports Hostname={agent_name}")
    if not mismatched:
        log("  none")

    log("\n== Agent templates on hosts whose agent is unavailable ==")
    found = False
    for h in hosts:
        agent_tpl = any("by zabbix agent" in t["name"].lower() for t in h["parentTemplates"])
        agent_down = any(i["type"] == "1" and i["available"] == "2" for i in h["interfaces"])
        if agent_tpl and agent_down and h["status"] == "0":
            log(f"  {h['name']}: {', '.join(t['name'] for t in h['parentTemplates'] if 'agent' in t['name'].lower())}")
            found = True
    if not found:
        log("  none")

    log("\n== Hosts with the most unsupported items ==")
    names = {h["hostid"]: h["name"] for h in hosts}
    for hostid, n in unsupported.most_common(8):
        log(f"  {names.get(hostid, hostid)}: {n}")

    outside = [h["name"] for h in hosts if h["status"] == "0" and h["interfaces"]
               and not any(i["ip"] and site_for(cfg, i["ip"]) for i in h["interfaces"])
               and not any(i["ip"] == "127.0.0.1" for i in h["interfaces"])
               and networks and cfg.get("_sites")]
    if outside:
        log("\n== Hosts outside the configured networks ==\n  " + ", ".join(sorted(outside)))
    log("\nNothing was changed.")
