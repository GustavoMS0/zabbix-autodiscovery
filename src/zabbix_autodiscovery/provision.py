"""Objects zabbix-autodiscovery creates in Zabbix: host groups, the agent-missing template, dashboards,
the optional continuous discovery rule and the optional read-only Grafana user.

Everything is idempotent and prefixed with "AutoDiscovery - "; existing objects are never overwritten.
"""
import string
from itertools import product

from . import dashboards, scanner
from .classifier import as_list
from .config import category_groups, default_community, in_networks
from .zabbix_api import ZabbixError

PREFIX = "AutoDiscovery - "
AGENT_TEMPLATE = f"{PREFIX}Zabbix agent missing"
AGENT_PORT_KEY = "net.tcp.service[tcp,,10050]"
AGENT_PING_KEY = "icmpping[,2]"      # differs from "icmpping" so it never clashes with other templates
TEMPLATE_GROUP = "Templates/AutoDiscovery"


def resolve_templates(spec, tmpl_map):
    """'A|B,C' -> ids of (first existing of A/B) + C. Returns (ids, missing)."""
    ids, missing = [], []
    for entry in filter(None, (e.strip() for e in spec.split(","))):
        options = [o.strip() for o in entry.split("|")]
        tid = next((tmpl_map[o] for o in options if o in tmpl_map), None)
        if tid:
            if tid not in ids:
                ids.append(tid)
        else:
            missing.append(entry)
    return ids, missing


def ensure_agent_template(api, log=print):
    """Template that checks port 10050 from the Zabbix server and raises a problem when no agent answers.

    The trigger only fires while the host answers ping, so it never duplicates "host down" alerts.
    Once the agent is installed (port opens) the problem resolves by itself.
    """
    found = api.call("template.get", {"output": ["templateid"], "filter": {"host": AGENT_TEMPLATE}})
    if found:
        return found[0]["templateid"]
    groupid = api.ensure_templategroup(TEMPLATE_GROUP)
    tid = api.call("template.create", {
        "host": AGENT_TEMPLATE,
        "groups": [{"groupid": groupid}],
        "description": "Created by zabbix-autodiscovery. Flags monitored servers that have no Zabbix agent.",
        "tags": [{"tag": "origin", "value": "autodiscovery"}],
    })["templateids"][0]
    common = {"hostid": tid, "type": 3, "value_type": 3, "delay": "5m", "history": "7d",
              "tags": [{"tag": "component", "value": "agent"}]}
    api.call("item.create", [
        {**common, "name": dashboards.AGENT_PORT_ITEM, "key_": AGENT_PORT_KEY,
         "description": "1 = agent port open, 0 = agent missing or blocked."},
        {**common, "name": "AutoDiscovery: helper ping", "key_": AGENT_PING_KEY},
    ])
    t = f"/{AGENT_TEMPLATE}/"
    api.call("trigger.create", {
        "description": "Zabbix agent missing on {HOST.NAME}",
        "expression": f"max({t}{AGENT_PORT_KEY},#3)=0 and last({t}{AGENT_PING_KEY})=1",
        "priority": 2,
        "manual_close": 0,
        "comments": "The server answers ping but port 10050 is closed. Install Zabbix agent 2 "
                    "(Server= pointing to Zabbix) and run 'zabbix-autodiscovery agent-sync'.",
        "tags": [{"tag": "agent", "value": "missing"}, {"tag": "origin", "value": "autodiscovery"}],
    })
    log(f"- template '{AGENT_TEMPLATE}' created")
    return tid


def ensure_groups(api, cfg):
    groups = sorted(set(category_groups(cfg).values()))
    for g in groups:
        api.ensure_hostgroup(g)
    return groups


def setup_zabbix_dashboards(api, cfg, rebuild=False, log=print):
    """One native dashboard per device type (only for types with a host group in the rules).

    rebuild=True refreshes existing AutoDiscovery dashboards, e.g. after new hosts were added
    (graphs list the hosts of the type's groups)."""
    created = kept = refreshed = 0
    for spec in dashboards.SPECS:
        groups = dashboards.groups_for(spec, cfg)
        if not groups:
            continue
        name = f"{PREFIX}{spec['title']}"
        found = api.call("dashboard.get", {"output": ["dashboardid"], "filter": {"name": name}})
        if found and not rebuild:
            kept += 1
            continue
        groupids = [api.ensure_hostgroup(g) for g in groups]
        hostnames = [h["name"] for h in api.call("host.get", {"output": ["name"], "groupids": groupids,
                                                              "filter": {"status": 0}})]
        widgets = dashboards.zabbix_widgets(spec, groupids, api.version, hostnames)
        if found:
            try:
                api.call("dashboard.update", {"dashboardid": found[0]["dashboardid"], "pages": [{"widgets": widgets}]})
                refreshed += 1
            except ZabbixError as exc:
                log(f"  ! '{name}' not refreshed: {exc}")
            continue
        params = {"name": name, "display_period": 30, "auto_start": 1, "pages": [{"widgets": widgets}]}
        try:
            api.call("dashboard.create", params)
        except ZabbixError as exc:
            # Widget fields change between versions: fall back to the problems widget only
            params["pages"] = [{"widgets": [w for w in widgets if w["type"] == "problems"]}]
            try:
                api.call("dashboard.create", params)
                log(f"  ! '{name}': created with problems only ({exc})")
            except ZabbixError as exc2:
                log(f"  ! '{name}' not created: {exc2}")
                continue
        created += 1
    log(f"- Zabbix dashboards: {created} created, {refreshed} refreshed, {kept} already existed (kept as they are"
        + ("; use --rebuild-dashboards to refresh them)" if kept else ")"))


def setup_grafana_user(api, cfg, log=print):
    g = cfg.get("grafana_user") or {}
    if not g.get("username") or not g.get("password"):
        log("- grafana_user not configured, skipped")
        return
    # Own role with API access: on Zabbix 8.0 new roles have API access disabled by default
    role_name = f"{PREFIX}Grafana read-only"
    rules = {"api.access": 1, "api.mode": 0, "api": []}
    role = api.call("role.get", {"output": ["roleid"], "filter": {"name": role_name}})
    if role:
        roleid = role[0]["roleid"]
        api.call("role.update", {"roleid": roleid, "rules": rules})
    else:
        roleid = api.call("role.create", {"name": role_name, "type": 1, "rules": rules})["roleids"][0]

    group_name = f"{PREFIX}Grafana read-only"
    rights = [{"id": h["groupid"], "permission": 2} for h in api.call("hostgroup.get", {"output": ["groupid"]})]
    rights_key = "hostgroup_rights" if api.version >= (6, 2) else "rights"
    found = api.call("usergroup.get", {"output": ["usrgrpid"], "filter": {"name": group_name}})
    if found:
        usrgrpid = found[0]["usrgrpid"]
        api.call("usergroup.update", {"usrgrpid": usrgrpid, rights_key: rights})
    else:
        usrgrpid = api.call("usergroup.create", {"name": group_name, rights_key: rights})["usrgrpids"][0]
    if api.call("user.get", {"output": ["userid"], "filter": {"username": g["username"]}}):
        log(f"- user '{g['username']}' already exists and was not changed "
            f"('{group_name}' refreshed with read access to every host group)")
    else:
        api.call("user.create", {"username": g["username"], "passwd": g["password"],
                                 "roleid": roleid, "usrgrps": [{"usrgrpid": usrgrpid}]})
        log(f"- read-only user '{g['username']}' (with API access) created for Grafana")


def zabbix_iprange(item):
    """Convert 'a.b.c.d-a.b.c.e' to Zabbix's 'a.b.c.d-e' format."""
    item = str(item).strip()
    if "-" not in item:
        return item
    start, end = (p.strip() for p in item.split("-", 1))
    if "." not in end:
        return item
    s, e = start.split("."), end.split(".")
    if s[:3] != e[:3]:
        raise ValueError(f"range '{item}' crosses a /24; use CIDR for native discovery")
    return f"{start}-{e[3]}"


def _formula_ids():
    for size in (1, 2):
        for letters in product(string.ascii_uppercase, repeat=size):
            yield "".join(letters)


def setup_native_discovery(api, cfg, force=False, log=print):
    community = default_community(cfg)
    if not community:
        raise SystemExit("native discovery needs an SNMP v2c credential in snmp_credentials")
    networks = cfg["scan"]["networks"]
    already = [i["ip"] for i in api.call("hostinterface.get", {"output": ["ip"]})
               if i["ip"] and in_networks(networks, i["ip"])]
    if already and not force:
        log(f"  ! {len(already)} monitored hosts are inside the discovery ranges (e.g. {', '.join(already[:5])}).\n"
            "    Zabbix would apply the actions' groups/templates to them too. Native discovery was NOT created.\n"
            "    Use --force if you are sure, or narrow scan.networks / scan.exclude.")
        return

    nd = cfg.get("native_discovery") or {}
    name = nd.get("name", f"{PREFIX}Continuous discovery")
    iprange = ",".join(zabbix_iprange(n) for n in networks)
    dchecks = [
        {"type": 11, "key_": scanner.SYS_OBJECTID, "snmp_community": community, "ports": "161",
         "uniq": 0, "host_source": 1, "name_source": 0},
        {"type": 11, "key_": scanner.SYS_NAME, "snmp_community": community, "ports": "161",
         "uniq": 0, "host_source": 1, "name_source": 3},
    ]
    found = api.call("drule.get", {"output": ["druleid"], "filter": {"name": name}})
    params = {"name": name, "iprange": iprange, "delay": nd.get("delay", "1h"), "dchecks": dchecks}
    if found:
        druleid = found[0]["druleid"]
        api.call("drule.update", {"druleid": druleid, **params})
    else:
        druleid = api.call("drule.create", params)["druleids"][0]
    rule = api.call("drule.get", {"druleids": druleid, "selectDChecks": "extend"})[0]
    dcheckid = next(d["dcheckid"] for d in rule["dchecks"] if d["key_"] == scanner.SYS_OBJECTID)
    log(f"- discovery rule '{name}' ({iprange}) ready")

    old = api.call("action.get", {"output": ["actionid"], "filter": {"eventsource": 1},
                                  "search": {"name": PREFIX}, "startSearch": True})
    if old:
        api.call("action.delete", [a["actionid"] for a in old])

    excludes = [zabbix_iprange(e) for e in cfg["scan"].get("exclude", [])]
    tmpl_map = api.template_ids()
    created = 0
    for r in cfg.get("rules", []):
        prefixes = [p for c in as_list(r["match"]) for p in as_list(c.get("sysobjectid_prefix"))]
        if not prefixes or r.get("action") != "add":
            continue
        ids = _formula_ids()
        conds, fixed, alts = [], [], []

        def add(ctype, op, value, bucket):
            fid = next(ids)
            conds.append({"conditiontype": ctype, "operator": op, "value": str(value), "formulaid": fid})
            bucket.append(fid)

        add(18, 0, druleid, fixed)          # discovery rule
        add(19, 0, dcheckid, fixed)         # sysObjectID check
        add(10, 0, 0, fixed)                # status: up
        for ex in excludes:
            add(7, 1, ex, fixed)            # IP outside the exclusions
        for p in prefixes:
            add(12, 2, str(p).strip(".") + ".", alts)   # received value contains the prefix
        formula = " and ".join(fixed + [f"({' or '.join(alts)})"])

        template_ids, missing = resolve_templates(",".join(as_list(r.get("templates"))), tmpl_map)
        for m in missing:
            log(f"  ! rule {r['name']}: template not found: {m}")
        ops = [{"operationtype": 2},
               {"operationtype": 4, "opgroup": [{"groupid": api.ensure_hostgroup(
                   r.get("group") or "Discovered/Unassigned")}]},
               {"operationtype": 10, "opinventory": {"inventory_mode": 1}}]
        if template_ids:
            ops.append({"operationtype": 6, "optemplate": [{"templateid": t} for t in template_ids]})
        api.call("action.create", {
            "name": PREFIX + r["name"], "eventsource": 1, "status": 0,
            "filter": {"evaltype": 3, "formula": formula, "conditions": conds},
            "operations": ops,
        })
        created += 1
    log(f"- {created} discovery actions created (prefix '{PREFIX}')")


def setup(api, cfg, native_discovery=False, force=False, zabbix_dashboards=True, rebuild_dashboards=False,
          log=print):
    groups = ensure_groups(api, cfg)
    log(f"- {len(groups)} host groups ensured (existing ones are not changed)")

    community = default_community(cfg)
    if community:
        current = api.ensure_global_macro("{$SNMP_COMMUNITY}", community)
        if current == community:
            log("- global macro {$SNMP_COMMUNITY} ok")
        else:
            log("- global macro {$SNMP_COMMUNITY} already exists with another value: kept; "
                "new hosts get the community as a host macro")

    ensure_agent_template(api, log)
    if zabbix_dashboards:
        setup_zabbix_dashboards(api, cfg, rebuild=rebuild_dashboards, log=log)
    setup_grafana_user(api, cfg, log)
    if native_discovery:
        setup_native_discovery(api, cfg, force, log)
