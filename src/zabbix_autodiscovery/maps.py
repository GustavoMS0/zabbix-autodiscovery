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
COLUMNS, CELL_W, CELL_H, MARGIN = 6, 180, 220, 60


def vendor_of(host):
    return next((t["value"] for t in host.get("tags", []) if t["tag"] == "vendor"), "")


__all__ = ["category_of", "infer_links", "layout", "provision"]


def infer_links(placed, selements):
    """Automatically build visual network links between map elements without crossing.

    Hierarchy:
      Gateway (firewall, router) ===[uplink, green]===> Switches
      Switch ---[LAN, blue]---> Tier 2 (server-hardware, APs, peripherals)
      Server-hardware (iDRAC) ---[virtualization, blue]---> VMs (Windows, Linux, Hypervisors)
    """
    coords = {s["selementid"]: (x, y) for (h, cat, x, y), s in zip(placed, selements, strict=False)}
    cat_map = {s["selementid"]: cat for (h, cat, x, y), s in zip(placed, selements, strict=False)}

    gateways = [s["selementid"] for s in selements if cat_map[s["selementid"]] in ("firewall", "router")]
    switches = [s["selementid"] for s in selements if cat_map[s["selementid"]] == "switch"]

    hw_nodes = [s["selementid"] for s in selements if cat_map[s["selementid"]] == "server-hardware"]
    vm_cats = ("server-windows", "server-linux", "hypervisor")
    vm_nodes = [s["selementid"] for s in selements if cat_map[s["selementid"]] in vm_cats]

    if hw_nodes:
        tier2_endpoints = [s["selementid"] for s in selements
                           if cat_map[s["selementid"]] not in ("firewall", "router", "switch")
                           and s["selementid"] not in vm_nodes]
    else:
        tier2_endpoints = [s["selementid"] for s in selements
                           if cat_map[s["selementid"]] not in ("firewall", "router", "switch")]

    links = []
    # 1. Gateways -> Switches
    if gateways and switches:
        for gw in gateways:
            for sw in switches:
                links.append({"selementid1": gw, "selementid2": sw, "drawtype": 2, "color": "00AA00"})
    elif gateways and not switches:
        for gw in gateways:
            for ep in tier2_endpoints:
                links.append({"selementid1": gw, "selementid2": ep, "drawtype": 0, "color": "2774A4"})

    # 2. Switches -> Tier 2 Endpoints (nearest switch horizontally)
    if switches:
        for ep in tier2_endpoints:
            ep_x, ep_y = coords[ep]
            best_sw = min(switches, key=lambda sw: abs(coords[sw][0] - ep_x))
            links.append({"selementid1": best_sw, "selementid2": ep, "drawtype": 0, "color": "2774A4"})

    # 3. Hardware (iDRAC) -> Virtualizations (VMs)
    # Virtual machines live INSIDE the physical hardware host!
    for vm in vm_nodes:
        vm_x, _ = coords[vm]
        if hw_nodes:
            parent_hw = min(hw_nodes, key=lambda h: abs(coords[h][0] - vm_x))
            links.append({"selementid1": parent_hw, "selementid2": vm, "drawtype": 0, "color": "2774A4"})
        elif switches:
            best_sw = min(switches, key=lambda sw: abs(coords[sw][0] - vm_x))
            links.append({"selementid1": best_sw, "selementid2": vm, "drawtype": 0, "color": "2774A4"})

    return links


def layout(hosts, hypervisors=frozenset()):
    """[(host, category, x, y)] structured into 4 logical tiers:
      Tier 0: Perimeter / Gateways (firewall, router)
      Tier 1: Distribution (switches)
      Tier 2: Physical hardware & endpoints (server-hardware/iDRAC, APs, UPS, printers...)
      Tier 3: Virtualization layer (VMs placed directly below physical hardware)
    """
    by_cat = {}
    for h in hosts:
        by_cat.setdefault(category_of(h, hypervisors), []).append(h)

    tier0 = sorted(by_cat.get("firewall", []) + by_cat.get("router", []), key=lambda h: h["name"].lower())
    tier1 = sorted(by_cat.get("switch", []), key=lambda h: h["name"].lower())
    t2_hw = sorted(by_cat.get("server-hardware", []), key=lambda h: h["name"].lower())
    t2_ap = sorted(by_cat.get("ap", []), key=lambda h: h["name"].lower())

    periph_cats = ["ups", "pdu", "storage", "printer", "cctv", "voip", "network-generic", "other"]
    t2_periph = []
    for c in periph_cats:
        t2_periph.extend(by_cat.get(c, []))
    t2_periph.sort(key=lambda h: h["name"].lower())

    vm_cats = ["server-windows", "server-linux", "hypervisor"]
    raw_vms = []
    for c in vm_cats:
        raw_vms.extend(by_cat.get(c, []))
    raw_vms.sort(key=lambda h: h["name"].lower())

    # If physical server-hardware (iDRAC) exists, VMs live in Tier 3 under hardware.
    # If no server-hardware exists at all, standalone servers become physical Tier 2 servers.
    if t2_hw:
        tier3_vms = raw_vms
    else:
        t2_hw = raw_vms
        tier3_vms = []

    # If simple site (e.g. only firewall + printers, or only switches)
    has_complex_zones = bool((t2_ap and (t2_hw or tier3_vms or t2_periph)) or (t2_hw and t2_periph))

    if not has_complex_zones:
        placed = []
        all_groups = [
            (tier0, "firewall"), (tier1, "switch"), (t2_hw, "server-hardware"),
            (tier3_vms, "vm"), (t2_ap, "ap"), (t2_periph, "peripheral")
        ]
        active_groups = [(items, cat) for items, cat in all_groups if items]
        max_c = max((min(COLUMNS, len(items)) for items, _ in active_groups), default=1)
        cols = min(COLUMNS, max_c)
        total_w = MARGIN * 2 + cols * CELL_W

        y = MARGIN
        for items, _default_cat in active_groups:
            num_rows = (len(items) - 1) // cols + 1
            for r in range(num_rows):
                row_items = items[r * cols: (r + 1) * cols]
                row_start = MARGIN + ((cols - len(row_items)) * CELL_W) // 2
                for c, h in enumerate(row_items):
                    placed.append((h, category_of(h, hypervisors), row_start + c * CELL_W, y))
                y += CELL_H
        return placed, total_w, y + MARGIN

    left_cols = len(t2_ap)
    center_cols = max(len(t2_hw), (len(tier3_vms) + 1) // 2 if tier3_vms else 0, 1)
    right_cols = len(t2_periph)
    total_cols = max(left_cols + center_cols + right_cols, len(tier1), len(tier0), 1)
    total_width = MARGIN * 2 + total_cols * CELL_W

    placed = []

    # Tier 0: Gateways (centered at top)
    y0 = MARGIN
    gw_start_x = MARGIN + ((total_cols - len(tier0)) * CELL_W) // 2
    for i, h in enumerate(tier0):
        placed.append((h, category_of(h, hypervisors), gw_start_x + i * CELL_W + CELL_W // 2, y0))

    # Tier 1: Switches (distributed across width)
    y1 = y0 + (CELL_H if tier0 else 0)
    sw_spacing = (total_width - MARGIN * 2) // max(len(tier1), 1)
    for i, h in enumerate(tier1):
        sx = MARGIN + i * sw_spacing + sw_spacing // 2
        placed.append((h, "switch", sx, y1))

    # Tier 2:
    y2 = y1 + (CELL_H if tier1 else (CELL_H if tier0 else 0))

    # Left Zone: APs
    left_start_x = MARGIN
    for i, h in enumerate(t2_ap):
        placed.append((h, "ap", left_start_x + i * CELL_W + CELL_W // 2, y2))

    # Center Zone: Physical Hardware / iDRAC
    center_start_x = MARGIN + (left_cols * CELL_W)
    hw_offset = ((center_cols - len(t2_hw)) * CELL_W) // 2 if len(t2_hw) < center_cols else 0
    for i, h in enumerate(t2_hw):
        hx = center_start_x + hw_offset + i * CELL_W + CELL_W // 2
        placed.append((h, category_of(h, hypervisors), hx, y2))

    # Tier 3: VMs (directly below physical hardware in Center Zone!)
    vm_start_y = y2 + (CELL_H if t2_hw else 0)
    max_vm_y = y2
    for i, h in enumerate(tier3_vms):
        c = i % center_cols
        r = i // center_cols
        vx = center_start_x + c * CELL_W + CELL_W // 2
        vy = vm_start_y + r * CELL_H
        placed.append((h, category_of(h, hypervisors), vx, vy))
        if vy > max_vm_y:
            max_vm_y = vy

    # Right Zone: Peripherals (Printers, UPS, etc.)
    right_start_x = MARGIN + (left_cols + center_cols) * CELL_W
    for i, h in enumerate(t2_periph):
        placed.append((h, category_of(h, hypervisors), right_start_x + i * CELL_W + CELL_W // 2, y2))

    total_height = max(max_vm_y, y2) + CELL_H
    return placed, total_width, total_height


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
        selements = [{"selementid": str(i + 1), "elementtype": 0, "elements": [{"hostid": h["hostid"]}],
                      "iconid_off": icons.icon(cat, vendor_of(h)), "x": x, "y": y,
                      "label": "{HOST.NAME}\n{HOST.CONN}"} for i, (h, cat, x, y) in enumerate(placed)]
        links = infer_links(placed, selements)
        params = {
            "name": name, "width": width, "height": height, "label_type": 0,
            "highlight": 1, "expandproblem": 1, "markelements": 1, "show_unack": 0, "label_location": 0,
            "selements": selements, "links": links,
        }
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
