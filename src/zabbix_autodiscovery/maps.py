"""One Zabbix map per site, with an icon per device type, plus a dashboard showing the maps.

Icons default to the images Zabbix ships with. Each category (or a vendor, "vendor:HP") can point to
another built-in image name or to a local PNG, which is uploaded once. Product photos are not bundled
with this project; supply your own.
"""
import base64
from pathlib import Path

from .inventory import category_of, hypervisor_hostids, network_hosts
from .provision import PREFIX
from .zabbix_api import ZabbixError

DASHBOARD = f"{PREFIX}Maps"
DEFAULT_ICONS = {
    "firewall": "Firewall", "router": "Router", "switch": "Switch", "ap": "Satellite_antenna",
    "server-windows": "Server", "server-linux": "Server", "hypervisor": "Rackmountable_2U_server_2D",
    "server-hardware": "Rackmountable_2U_server_3D", "storage": "Disk_array_3D", "ups": "UPS",
    "pdu": "UPS", "printer": "Printer", "cctv": "Video_terminal", "voip": "Phone",
    "network-generic": "Network", "other": "Network",
}
ROW_ORDER = ["firewall", "router", "switch", "ap", "server-windows", "server-linux", "hypervisor",
             "server-hardware", "storage", "ups", "pdu", "printer", "cctv", "voip",
             "network-generic", "other"]
COLUMNS, CELL_W, CELL_H, MARGIN = 8, 150, 120, 40


def vendor_of(host):
    return next((t["value"] for t in host.get("tags", []) if t["tag"] == "vendor"), "")


__all__ = ["category_of", "layout", "provision"]


def layout(hosts, hypervisors=frozenset()):
    """[(host, category, x, y)] in rows by category, wrapping at COLUMNS; returns (placed, width, height)."""
    placed, y = [], MARGIN
    by_cat = {}
    for h in hosts:
        by_cat.setdefault(category_of(h, hypervisors), []).append(h)
    max_cols = 1
    for cat in ROW_ORDER:
        items = sorted(by_cat.get(cat, []), key=lambda h: h["name"].lower())
        for i, h in enumerate(items):
            col = i % COLUMNS
            if i and col == 0:
                y += CELL_H
            placed.append((h, cat, MARGIN + col * CELL_W, y))
            max_cols = max(max_cols, col + 1)
        if items:
            y += CELL_H
    return placed, MARGIN * 2 + max_cols * CELL_W, y + MARGIN


class IconResolver:
    def __init__(self, api, overrides, base_dir):
        self.api, self.overrides, self.base_dir = api, overrides or {}, Path(base_dir)
        self.images = {i["name"]: i["imageid"]
                       for i in api.call("image.get", {"output": ["name"], "filter": {"imagetype": 1}})}

    def _image(self, ref):
        if ref.lower().endswith(".png"):
            path = (self.base_dir / ref).resolve()
            name = f"{PREFIX}{path.stem}"
            if name not in self.images:
                data = base64.b64encode(path.read_bytes()).decode()
                self.images[name] = self.api.call("image.create", {"name": name, "imagetype": 1,
                                                                   "image": data})["imageids"][0]
            return self.images[name]
        for candidate in (ref, f"{ref}_(64)", f"{ref}_(96)"):
            if candidate in self.images:
                return self.images[candidate]
        return None

    def icon(self, category, vendor):
        for ref in (self.overrides.get(f"vendor:{vendor}") if vendor else None,
                    self.overrides.get(category), DEFAULT_ICONS.get(category), "Network"):
            if ref:
                iconid = self._image(ref)
                if iconid:
                    return iconid
        return next(iter(self.images.values()))


def site_hosts(api, network):
    return network_hosts(api, [network])


def provision(api, cfg, base_dir, rebuild=False, dry_run=False, log=print):
    maps_cfg = cfg.get("maps") or {}
    sites = cfg.get("_sites") or []
    if not sites:
        raise SystemExit("maps need named sites: use {network, site} entries in scan.networks")
    icons = None if dry_run else IconResolver(api, maps_cfg.get("icons"), base_dir)
    name_format = maps_cfg.get("name_format", "Site: {site}")
    existing = {m["name"]: m["sysmapid"] for m in api.call("map.get", {"output": ["name"]})}
    by_site = {}
    for site in sites:
        by_site.setdefault(site["site"] or site["network"], []).append(site["network"])

    map_ids = {}
    for site, networks in by_site.items():
        name = PREFIX + name_format.format(site=site)
        hosts = {h["hostid"]: h for n in networks for h in site_hosts(api, n)}.values()
        hosts = list(hosts)
        placed, width, height = layout(hosts, hypervisor_hostids(api, [h["hostid"] for h in hosts]))
        if not placed:
            continue
        if name in existing and not rebuild:
            log(f"  = map '{name}' already exists (use --rebuild to refresh it)")
            map_ids[site] = existing[name]
            continue
        if dry_run:
            counts = {}
            for _, cat, _, _ in placed:
                counts[cat] = counts.get(cat, 0) + 1
            log(f"  + map '{name}': {len(placed)} hosts {counts}  (dry-run)")
            continue
        selements = [{"elementtype": 0, "elements": [{"hostid": h["hostid"]}],
                      "iconid_off": icons.icon(cat, vendor_of(h)), "x": x, "y": y,
                      "label": "{HOST.NAME}\n{HOST.CONN}"} for h, cat, x, y in placed]
        params = {"name": name, "width": width, "height": height, "label_type": 0, "selements": selements}
        if name in existing:
            api.call("map.update", {"sysmapid": existing[name], **params})
            map_ids[site] = existing[name]
            log(f"  ~ map '{name}' refreshed ({len(placed)} hosts)")
        else:
            map_ids[site] = api.call("map.create", params)["sysmapids"][0]
            log(f"  + map '{name}' ({len(placed)} hosts)")
    if map_ids and not dry_run:
        ensure_dashboard(api, map_ids, rebuild, log)
    return map_ids


def ensure_dashboard(api, map_ids, rebuild, log=print):
    full = 72 if api.version >= (7, 0) else 24
    pages = [{"name": site, "widgets": [{"type": "map", "name": site, "x": 0, "y": 0, "width": full,
                                         "height": 12 if api.version >= (7, 0) else 10,
                                         "fields": [{"type": 8, "name": "sysmapid.0", "value": mid}]}]}
             for site, mid in map_ids.items()]
    found = api.call("dashboard.get", {"output": ["dashboardid"], "filter": {"name": DASHBOARD}})
    try:
        if found and rebuild:
            api.call("dashboard.update", {"dashboardid": found[0]["dashboardid"], "pages": pages})
            log(f"- dashboard '{DASHBOARD}' refreshed")
        elif not found:
            api.call("dashboard.create", {"name": DASHBOARD, "display_period": 60, "auto_start": 1,
                                          "pages": pages})
            log(f"- dashboard '{DASHBOARD}' created ({len(pages)} pages)")
    except ZabbixError as exc:
        log(f"  ! dashboard '{DASHBOARD}' not created: {exc}")
