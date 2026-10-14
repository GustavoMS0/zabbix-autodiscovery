"""NOC Advanced Automation for Zabbix:
- Root Cause Analysis (Trigger Dependencies to prevent alert storms)
- Business Service Monitoring & SLA (SLO 99.5% availability reporting)
- Zombie / Unsupported Item Cleanup (keeps database and pollers healthy)
- Rogue Device Detection
"""

from .inventory import category_of, network_hosts
from .zabbix_api import ZabbixError

DEFAULT_SLA_TIMEZONE = "America/Sao_Paulo"
GATEWAY_CATEGORIES = ("firewall", "router")

DEPENDENCIES_WARNING = (
    "ATENÇÃO: dependências de trigger SUPRIMEM alertas. Se um host-pai estiver em problema, os alertas de\n"
    "indisponibilidade dos hosts dependentes deixam de aparecer. Uma dependência errada esconde quedas reais.\n"
    "Inferência automática: somente switch -> gateway quando a filial tem UM único firewall/roteador.\n"
    "Demais vínculos (servidores, VMs, endpoints, gateways redundantes/HA) só via noc.dependencies no config."
)


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


def infer_site_dependencies(hosts):
    """[(child, parent)] inferred for one site, plus warnings.

    Only switch -> gateway, and only when the site has exactly ONE gateway (firewall/router): a trigger
    with several dependencies is suppressed when ANY parent is down, so with an HA pair one firewall down
    would hide every switch alert. Endpoints, VMs and servers are never inferred (map positions say
    nothing about real cabling or virtualization); declare them in noc.dependencies.
    """
    gateways = [h for h in hosts if category_of(h) in GATEWAY_CATEGORIES]
    switches = [h for h in hosts if category_of(h) == "switch"]
    if not gateways or not switches:
        return [], []
    if len(gateways) > 1:
        names = ", ".join(sorted(h["name"] for h in gateways))
        return [], [f"{len(gateways)} gateways ({names}) - possivelmente redundantes (HA): dependências "
                    "switch -> gateway NÃO criadas; declare-as em noc.dependencies se for o caso"]
    return [(sw, gateways[0]) for sw in switches], []


def explicit_dependencies(api, cfg):
    """noc.dependencies: [{host: <child>, depends_on: <parent>}] matched by technical or visible name."""
    entries = (cfg.get("noc") or {}).get("dependencies") or []
    pairs, warnings, by_child = [], [], {}
    cache = {}

    def find(name):
        if name not in cache:
            found = api.call("host.get", {"output": ["hostid", "host", "name"], "filter": {"host": [name]}}) or \
                api.call("host.get", {"output": ["hostid", "host", "name"], "filter": {"name": [name]}})
            cache[name] = found[0] if len(found) == 1 else None
        return cache[name]

    for e in entries:
        child_name, parent_name = str(e.get("host") or "").strip(), str(e.get("depends_on") or "").strip()
        if not child_name or not parent_name:
            warnings.append(f"noc.dependencies: entrada inválida (use host e depends_on): {e}")
            continue
        by_child.setdefault(child_name, []).append(parent_name)
    for child_name, parents in by_child.items():
        if len(parents) > 1:
            warnings.append(f"{child_name}: {len(parents)} pais em noc.dependencies ({', '.join(parents)}) - "
                            "um alerta com vários pais some quando QUALQUER pai cai; ignorado")
            continue
        child, parent = find(child_name), find(parents[0])
        if not child or not parent:
            warnings.append(f"noc.dependencies: host não encontrado (ou ambíguo): "
                            f"{child_name if not child else parents[0]}")
            continue
        pairs.append((child, parent))
    return pairs, warnings


def link_trigger_dependencies(api, cfg, dry_run=False, log=print):
    """Create trigger dependencies (child availability trigger depends on the parent's).

    Sources: noc.dependencies in the config (explicit, preferred) and, per site, switch -> gateway when
    the site has a single gateway. A child never gets more than one parent, and triggers that already
    have dependencies are left untouched.
    """
    stats = {"linked": 0, "skipped": 0, "errors": 0}
    pairs, warnings = explicit_dependencies(api, cfg)
    explicit_children = {c["hostid"] for c, _ in pairs}

    by_site = {}
    for s in cfg.get("_sites") or []:
        by_site.setdefault(s.get("site") or s["network"], []).append(s["network"])
    for site_name, networks in by_site.items():
        hosts = network_hosts(api, networks)
        inferred, site_warnings = infer_site_dependencies(hosts)
        warnings += [f"Filial {site_name}: {w}" for w in site_warnings]
        inferred = [(c, p) for c, p in inferred if c["hostid"] not in explicit_children]
        if inferred:
            log(f"\n--- Filial {site_name}: {len(inferred)} dependência(s) switch -> gateway ---")
        pairs += inferred

    for w in warnings:
        log(f"  ! {w}")
    if not pairs:
        log("Nenhuma dependência a criar.")
        return stats

    for child, parent in pairs:
        if child["hostid"] == parent["hostid"]:
            continue
        child_trig = primary_down_trigger(api, child["hostid"])
        parent_trig = primary_down_trigger(api, parent["hostid"])
        if not child_trig or not parent_trig:
            stats["skipped"] += 1
            continue

        current = api.call("trigger.get", {"triggerids": child_trig, "selectDependencies": ["triggerid"]})
        existing_dep_ids = {d["triggerid"] for d in current[0].get("dependencies", [])} if current else set()
        if parent_trig in existing_dep_ids:
            stats["skipped"] += 1
            continue
        if existing_dep_ids:
            # Never stack a second parent: the trigger would be hidden when ANY of them is down
            log(f"  = {child['name']}: já possui dependência(s) configurada(s), mantida(s) sem alteração")
            stats["skipped"] += 1
            continue

        if dry_run:
            log(f"  [dry-run] {child['name']} passará a depender de {parent['name']}")
            stats["linked"] += 1
            continue
        try:
            api.call("trigger.update", {"triggerid": child_trig, "dependencies": [{"triggerid": parent_trig}]})
            log(f"  + {child['name']} -> depende de {parent['name']}")
            stats["linked"] += 1
        except ZabbixError as exc:
            log(f"  x Erro em {child['name']}: {exc}")
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
            "timezone": (cfg.get("noc") or {}).get("sla_timezone") or DEFAULT_SLA_TIMEZONE,
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

