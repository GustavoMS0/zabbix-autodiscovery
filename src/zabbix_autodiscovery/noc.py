"""NOC Advanced Automation for Zabbix:
- Root Cause Analysis (Trigger Dependencies to prevent alert storms)
- Business Service Monitoring & SLA (SLO 99.5% availability reporting)
- Zombie / Unsupported Item Cleanup (keeps database and pollers healthy)
- Rogue Device Detection
"""

from .inventory import network_hosts
from .maps import infer_links, layout
from .zabbix_api import ZabbixError


def primary_down_trigger(api, hostid):
    """Find the primary ping/availability trigger for a given host."""
    triggers = api.call("trigger.get", {
        "output": ["triggerid", "description", "priority"],
        "hostids": hostid,
        "filter": {"status": 0}
    })
    for pattern in ["Unavailable by ICMP ping", "No SNMP data collection", "is not available"]:
        for t in triggers:
            if pattern.lower() in t["description"].lower():
                return t["triggerid"]
    return None


def link_trigger_dependencies(api, cfg, dry_run=False, log=print):
    """Automatically build trigger dependencies based on network topology.

    Endpoints -> depend on their closest Switch.
    VMs -> depend on their physical Host / iDRAC.
    Switches -> depend on their Gateway / Firewall.

    Prevents alert storms during outages.
    """
    sites = cfg.get("_sites") or []
    if not sites:
        log("Nenhuma filial configurada em scan.networks.")
        return {"linked": 0, "skipped": 0, "errors": 0}

    stats = {"linked": 0, "skipped": 0, "errors": 0}
    by_site = {}
    for s in sites:
        by_site.setdefault(s.get("site") or s["network"], []).append(s["network"])

    for site_name, networks in by_site.items():
        hosts = network_hosts(api, networks)
        if not hosts:
            continue

        placed, _, _ = layout(hosts)
        selements = [{"selementid": str(i + 1), "hostid": h["hostid"]} for i, (h, _, _, _) in enumerate(placed)]
        links = infer_links(placed, selements)

        sid_to_hostid = {s["selementid"]: s["hostid"] for s in selements}
        hostid_to_name = {h["hostid"]: h["name"] for h in hosts}

        log(f"\n--- Filial {site_name}: {len(links)} conexões mapeadas ---")
        for link in links:
            parent_hid = sid_to_hostid.get(link["selementid1"])
            child_hid = sid_to_hostid.get(link["selementid2"])
            if not parent_hid or not child_hid or parent_hid == child_hid:
                continue

            child_trig = primary_down_trigger(api, child_hid)
            parent_trig = primary_down_trigger(api, parent_hid)

            if not child_trig or not parent_trig:
                stats["skipped"] += 1
                continue

            # Check if dependency already exists
            current = api.call("trigger.get", {
                "triggerids": child_trig,
                "selectDependencies": ["triggerid"]
            })
            existing_dep_ids = {d["triggerid"] for d in current[0].get("dependencies", [])} if current else set()

            if parent_trig in existing_dep_ids:
                stats["skipped"] += 1
                continue

            child_name = hostid_to_name.get(child_hid, child_hid)
            parent_name = hostid_to_name.get(parent_hid, parent_hid)

            if dry_run:
                log(f"  [dry-run] {child_name} passará a depender de {parent_name}")
                stats["linked"] += 1
                continue

            try:
                new_deps = [{"triggerid": d} for d in existing_dep_ids] + [{"triggerid": parent_trig}]
                api.call("trigger.update", {
                    "triggerid": child_trig,
                    "dependencies": new_deps
                })
                log(f"  + {child_name} -> depende de {parent_name}")
                stats["linked"] += 1
            except ZabbixError as exc:
                log(f"  x Erro em {child_name}: {exc}")
                stats["errors"] += 1

    return stats


def setup_noc_services(api, cfg, dry_run=False, log=print):
    """Create Business Services & Global 99.5% SLA in Zabbix 8."""
    sites = cfg.get("_sites") or []
    site_names = sorted({s.get("site") for s in sites if s.get("site")})

    if dry_run:
        log(f"[dry-run] Seriam criados: Root NOC Service, {len(site_names)} serviços de filiais e SLA Global 99.5%.")
        return {"created": len(site_names) + 4, "existing": 0}

    stats = {"created": 0, "existing": 0}

    # 1. Root NOC Service
    root = api.call("service.get", {"filter": {"name": "AutoDiscovery - NOC Services"}})
    if not root:
        res = api.call("service.create", {
            "name": "AutoDiscovery - NOC Services",
            "algorithm": 1,  # Most critical of children
            "sortorder": 0,
            "tags": [{"tag": "origin", "value": "autodiscovery"}]
        })
        root_id = res["serviceids"][0]
        stats["created"] += 1
        log("  + Serviço Criado: AutoDiscovery - NOC Services")
    else:
        root_id = root[0]["serviceid"]
        stats["existing"] += 1

    # 2. Child Services by Site
    for sname in site_names:
        name = f"Filial {sname}"
        found = api.call("service.get", {"filter": {"name": name}})
        if not found:
            api.call("service.create", {
                "name": name,
                "algorithm": 1,
                "sortorder": 1,
                "parents": [{"serviceid": root_id}],
                "problem_tags": [{"tag": "site", "operator": 0, "value": sname}],
                "tags": [{"tag": "site", "value": sname}, {"tag": "origin", "value": "autodiscovery"}]
            })
            stats["created"] += 1
            log(f"  + Serviço Criado: {name} (tag site={sname})")
        else:
            stats["existing"] += 1

    # 3. Child Services by Infrastructure Role
    roles = [
        ("Segurança & Borda (Firewalls)", "firewall"),
        ("Rede Local (Switches)", "switch"),
        ("Datacenter & Servidores", "server-hardware"),
        ("Serviços Web & Domínios", "domain")
    ]
    for rname, rtag in roles:
        found = api.call("service.get", {"filter": {"name": rname}})
        if not found:
            api.call("service.create", {
                "name": rname,
                "algorithm": 1,
                "sortorder": 2,
                "parents": [{"serviceid": root_id}],
                "problem_tags": [{"tag": "type", "operator": 0, "value": rtag}],
                "tags": [{"tag": "type", "value": rtag}, {"tag": "origin", "value": "autodiscovery"}]
            })
            stats["created"] += 1
            log(f"  + Serviço Criado: {rname} (tag type={rtag})")
        else:
            stats["existing"] += 1

    # 4. Global SLA (99.5%, Monthly, 24x7)
    sla_name = "NOC - SLA Infraestrutura Global"
    sla = api.call("sla.get", {"filter": {"name": sla_name}})
    if not sla:
        api.call("sla.create", {
            "name": sla_name,
            "period": 2,  # Monthly
            "slo": 99.5,
            "effective_date": 1704067200,  # 2024-01-01
            "timezone": "America/Sao_Paulo",
            "service_tags": [{"tag": "origin", "operator": 0, "value": "autodiscovery"}],
            "schedule": [{"period_from": 0, "period_to": 604800}]  # 24x7
        })
        stats["created"] += 1
        log(f"  + SLA Criado: {sla_name} (Meta: 99.5%)")
    else:
        stats["existing"] += 1

    return stats


def clean_unsupported_items(api, dry_run=False, log=print):
    """Disable inactive internal collector items on Zabbix Server and dead orphan items."""
    stats = {"cleaned": 0}

    # Clean Zabbix server internal pollers
    hosts = api.call("host.get", {"filter": {"host": "Zabbix server"}}) or \
            api.call("host.get", {"filter": {"name": "Zabbix server"}})
    if hosts:
        unsupported = api.call("item.get", {
            "hostids": hosts[0]["hostid"],
            "filter": {"state": 1},
            "output": ["itemid", "name", "key_"]
        })
        for it in unsupported:
            if dry_run:
                log(f"  [dry-run] Desativaria: Zabbix server - {it['name']}")
                stats["cleaned"] += 1
            else:
                api.call("item.update", {"itemid": it["itemid"], "status": 1})
                log(f"  - Desativado: Zabbix server - {it['name']}")
                stats["cleaned"] += 1

    return stats

