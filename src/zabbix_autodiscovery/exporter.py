"""Export discovered or monitored devices to external formats (Ansible, NetBox, JSON)."""
import json
import re

import yaml


def _safe_group_name(name):
    """Normalize a name to be valid as an Ansible group identifier."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(name).strip().lower())
    return re.sub(r"_+", "_", cleaned).strip("_") or "other"


def normalize_device(name, ip, category=None, site=None, vendor=None, tags=None):
    return {
        "name": str(name).strip(),
        "ip": str(ip).strip(),
        "category": str(category or "other").strip(),
        "site": str(site or "Default").strip(),
        "vendor": str(vendor or "").strip(),
        "tags": tags or {},
    }


def devices_from_inventory(rows):
    """Convert parsed inventory.csv rows into normalized device dicts."""
    devices = []
    for r in rows:
        name = r.get("visible_name") or r.get("hostname") or r.get("ip")
        ip = r.get("ip", "")
        if not ip:
            continue
        tags_raw = r.get("tags", "")
        tags = {}
        if isinstance(tags_raw, str):
            for part in filter(None, (p.strip() for p in tags_raw.split(","))):
                k, _, v = part.partition("=")
                tags[k.strip()] = v.strip()
        elif isinstance(tags_raw, list):
            for t in tags_raw:
                tags[t.get("tag", "")] = t.get("value", "")

        devices.append(normalize_device(
            name=name,
            ip=ip,
            category=r.get("category", "other"),
            site=r.get("site", "Default"),
            vendor=r.get("vendor", ""),
            tags=tags,
        ))
    return devices


def devices_from_zabbix(api):
    """Fetch live hosts from Zabbix and normalize them for export."""
    from .inventory import category_of, hypervisor_hostids

    hosts = api.call("host.get", {
        "output": ["hostid", "host", "name", "status"],
        "selectInterfaces": ["ip", "main", "type"],
        "selectTags": ["tag", "value"],
        "selectHostGroups": ["name"],
        "filter": {"status": "0"},
    })
    hyp_ids = hypervisor_hostids(api, [h["hostid"] for h in hosts])

    devices = []
    for h in hosts:
        ip = next((i["ip"] for i in h.get("interfaces", []) if i.get("main") == "1"), "")
        if not ip and h.get("interfaces"):
            ip = h["interfaces"][0]["ip"]
        if not ip:
            continue

        tags = {t["tag"]: t["value"] for t in h.get("tags", [])}
        cat = tags.get("type") or category_of(h, hyp_ids)
        site = tags.get("site") or "Default"
        vendor = tags.get("vendor", "")

        devices.append(normalize_device(
            name=h["name"] or h["host"],
            ip=ip,
            category=cat,
            site=site,
            vendor=vendor,
            tags=tags,
        ))
    return devices


def export_ansible(devices):
    """Generate an Ansible inventory structure in YAML format."""
    inventory = {
        "all": {
            "children": {
                "categories": {"children": {}},
                "sites": {"children": {}},
            }
        }
    }

    cat_groups = inventory["all"]["children"]["categories"]["children"]
    site_groups = inventory["all"]["children"]["sites"]["children"]

    for d in devices:
        host_key = re.sub(r"[^a-zA-Z0-9_.-]", "_", d["name"])
        cat_key = _safe_group_name(d["category"])
        site_key = _safe_group_name(d["site"])

        cat_groups.setdefault(cat_key, {"hosts": {}})
        site_groups.setdefault(site_key, {"hosts": {}})

        host_vars = {
            "ansible_host": d["ip"],
            "site": d["site"],
            "category": d["category"],
        }
        if d["vendor"]:
            host_vars["vendor"] = d["vendor"]
        if d["tags"]:
            host_vars["tags"] = d["tags"]

        cat_groups[cat_key]["hosts"][host_key] = host_vars
        site_groups[site_key]["hosts"][host_key] = {"ansible_host": d["ip"]}

    return yaml.dump(inventory, sort_keys=False, default_flow_style=False, allow_unicode=True)


def export_netbox(devices):
    """Generate a NetBox-compatible device import JSON list."""
    netbox_devices = []
    for d in devices:
        item = {
            "name": d["name"],
            "role": {"name": d["category"].capitalize()},
            "site": {"name": d["site"]},
            "status": "active",
            "primary_ip4": d["ip"],
            "tags": [{"name": k, "value": v} for k, v in d["tags"].items()] or [{"name": "autodiscovery"}],
            "comments": "Imported via zabbix-autodiscovery",
        }
        if d["vendor"]:
            item["device_type"] = {
                "model": f"{d['vendor']} Generic",
                "manufacturer": {"name": d["vendor"]},
            }
        netbox_devices.append(item)
    return json.dumps(netbox_devices, indent=2, ensure_ascii=False)


def export_json(devices):
    """Generate clean, structured JSON format."""
    return json.dumps(devices, indent=2, ensure_ascii=False)

