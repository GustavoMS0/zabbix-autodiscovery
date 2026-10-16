"""Mapas de Rede v3: Topologia Corporativa Multifilial & Responsiva ao Filtro.

Apresenta a arquitetura de rede completa com:
1. Links de Internet (Multi-WAN) dedicados acima de cada firewall de filial.
2. Interconexão direta via túneis VPN IPsec / SD-WAN entre os firewalls com enlaces curvados e partículas de fluxo.
3. Hierarquia física e lógica completa com 0 colisões de nós/rótulos.
4. Telemetria em tempo real para todos os Access Points (Wi-Fi), incluindo clientes conectados e disponibilidade.
5. Responsividade 100% ao filtro $site (isolamento e expansão da filial selecionada).
"""
import copy
import json
import re

true, false, null = True, False, None

KEY = "site_maps"
UID = "autodiscovery-maps-v3"
TITLE = "AutoDiscovery v3 - Mapas de Rede (Zabbix Maps)"

ICONS = {
    "internet": '<path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8zm-1-15.93a8 8 0 0 0-5.93 5.93h3.07a12.8 12.8 0 0 1 2.86-5.93zm2 0a12.8 12.8 0 0 1 2.86 5.93h3.07A8 8 0 0 0 13 4.07zM4.07 11a8.1 8.1 0 0 0 0 2h3.93a15.7 15.7 0 0 1 0-2zm5.93 7.93a12.8 12.8 0 0 1-2.86-5.93H4.07a8 8 0 0 0 5.93 5.93zm4 0a8 8 0 0 0 5.93-5.93h-3.07a12.8 12.8 0 0 1-2.86 5.93zM16 13h3.93a8.1 8.1 0 0 0 0-2H16a15.7 15.7 0 0 1 0 2zm-6-2v2h4v-2z"/>',
    "firewall": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9.3h18M3 14.7h18M9 4v5.3M15 4v5.3M12 9.3v5.4M7 14.7V20M17 14.7V20"/>',
    "switch": '<rect x="2" y="7" width="20" height="10" rx="2"/><circle cx="6" cy="12" r="1.5"/><circle cx="10" cy="12" r="1.5"/><circle cx="14" cy="12" r="1.5"/><circle cx="18" cy="12" r="1.5"/>',
    "server": '<rect x="3" y="3.5" width="18" height="7.5" rx="2"/><rect x="3" y="13" width="18" height="7.5" rx="2"/><circle cx="7" cy="7.25" r="1"/><circle cx="7" cy="16.75" r="1"/><path d="M11 7.25h6M11 16.75h6"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "battery": '<rect x="2" y="7" width="17" height="10" rx="2"/><path d="M22 10.5v3M11 9l-2.5 3.2h3.4L9.5 15.2"/>',
    "wifi": '<path d="M2.5 9.2a14 14 0 0 1 19 0M5.6 12.6a9.5 9.5 0 0 1 12.8 0M8.8 16a4.8 4.8 0 0 1 6.4 0M12 19.6h.01"/>',
    "printer": '<path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>'
}


def clean_label(hname):
    """Shortens label for clean map presentation without collisions."""
    if " - " in hname:
        parts = hname.split(" - ")
        hname = parts[0].strip()
    if hname.startswith("switch-192.168.0."):
        return f"SW-{hname.split('.')[-1]}"
    if "Aruba" in hname:
        return "SW-Aruba"
    if "MikroTi" in hname:
        return "SW-MikroTik"
    if hname.startswith("GEQ10-"):
        return hname.replace("GEQ10-", "")
    if hname.startswith("Filial1-"):
        return hname.replace("Filial1-", "")
    if hname.startswith("AP-GALPAO1FRENTE"):
        return "AP-GALP1-FR"
    if hname.startswith("AP-GALPAO1FUNDO"):
        return "AP-GALP1-FD"
    if hname.startswith("AP-GALPAO3"):
        return "AP-GALP3"
    if hname.startswith("AP-BALANCA"):
        return "AP-BALANÇA"
    if "AP EXPEDI" in hname:
        return "AP-EXPED"
    if "AP ARMAZ" in hname:
        return "AP-ARMAZ"
    if "AP FABRIC" in hname:
        return "AP-FABRICA"
    if "AP LENTIL" in hname:
        return "AP-LENTILHA"
    if "AP RESERV" in hname:
        return "AP-RESERVA"
    if "66FC" in hname:
        return "iDRAC-01"
    if "6VW0" in hname:
        return "iDRAC-02"
    if "6VW2" in hname:
        return "iDRAC-03"
    if "6VW4" in hname:
        return "iDRAC-04"
    if "8LK3" in hname or "8LK" in hname:
        return "iDRAC-05"
    if "JXH2" in hname or "filial01" in hname:
        return "iDRAC-RJ"
    if "i-DRAC" in hname:
        return "iDRAC-BA"
    if hname.startswith("BRN001BA9F"):
        return "Brother-PR"
    if hname.startswith("HP5FFB5E"):
        return "HP-PR"
    if hname.startswith("NXE3841CF"):
        return "Xerox-RJ"
    if hname.startswith("NPIA9A017"):
        return "HP-Lab-RJ"
    if hname.startswith("NPI5695D5"):
        return "HP-569-SP"
    if hname.startswith("NPI5D37FB"):
        return "HP-5D3-SP"
    if hname.startswith("HPA9D24F"):
        return "HP-A9D-BA"
    if hname.startswith("HPE1206C"):
        return "HP-E12-BA"
    if hname.startswith("NPI301581"):
        return "HP-301-BA"
    if hname.startswith("NPI30A61D"):
        return "HP-30A-BA"
    if hname.startswith("NPI5645C9"):
        return "HP-564-BA"
    if len(hname) > 11:
        return hname[:10] + "…"
    return hname


def build_site_maps_data(api, cfg):
    """Builds node and link structures for individual sites and the unified multi-filial map."""
    maps_by_site = {}

    def call_api(method, params):
        if not api:
            return None
        try:
            if callable(api):
                return api(method, params)
            elif hasattr(api, "call"):
                return api.call(method, params)
        except Exception:
            return None
        return None

    z_maps = []
    if api:
        try:
            z_maps = call_api("map.get", {"selectSelements": "extend", "selectLinks": "extend"}) or []
        except Exception:
            z_maps = []

    hosts = {}
    if z_maps:
        all_hostids = set()
        for m in z_maps:
            for s in m.get("selements", []):
                for el in s.get("elements", []):
                    if el.get("hostid"):
                        all_hostids.add(el["hostid"])
        if all_hostids:
            hlist = call_api("host.get", {
                "hostids": list(all_hostids),
                "output": ["hostid", "host", "name"],
                "selectHostGroups": ["name"],
                "selectInterfaces": ["ip", "main"]
            }) or []
            hosts = {h["hostid"]: h for h in hlist}

    def classify_host(h):
        h_name = h.get("name", "")
        h_tech = h.get("host", "")
        groups = [g["name"] for g in h.get("hostgroups", [])]
        h_low = (h_name + " " + h_tech).lower()
        if any("firewall" in g.lower() for g in groups) or h_tech.startswith("FW-") or "firewall" in h_low or "fortigate" in h_low:
            return "Firewall", "firewall", 36, "#e879f9"
        if any(w in g.lower() for g in groups for w in ["nobreak", "ups", "pdu", "energia"]) or "nobreak" in h_low or "ups" in h_low:
            return "Nobreak UPS", "battery", 26, "#f59e0b"
        if any(w in g.lower() for g in groups for w in ["hardware servidor", "idrac", "ilo", "ipmi", "bmc"]) or "idrac" in h_low or "rac_" in h_low:
            return "Hardware Servidor", "chip", 25, "#a855f7"
        if any("switch" in g.lower() for g in groups) or "switch" in h_low or "sw-" in h_low or "sw_" in h_low:
            return "Switch", "switch", 32, "#38bdf8"
        if any(w in g.lower() for g in groups for w in ["access point", "wireless", "wi-fi"]) or h_tech.startswith("AP-") or h_tech.startswith("AP") or "unifi" in h_low:
            return "Access Point", "wifi", 25, "#f43f5e"
        if any("impressora" in g.lower() or "printer" in g.lower() for g in groups) or any(h_tech.startswith(p) for p in ["GEQ", "NPI", "HP", "NXE", "BRN"]):
            return "Impressora", "printer", 22, "#06b6d4"
        if any(w in g.lower() for g in groups for w in ["hypervisor", "vmware", "hyper-v"]):
            return "Virtualização / Hypervisor", "server", 28, "#8b5cf6"
        return "Servidor / VM", "server", 26, "#8b5cf6"

    # If maps found in Zabbix
    valid_z_maps = [m for m in z_maps if m["name"].startswith("AutoDiscovery - Filial ")]
    if valid_z_maps:
        for m in valid_z_maps:
            site_key = m["name"].replace("AutoDiscovery - Filial ", "").strip()
            mw = int(m["width"])
            mh = int(m["height"])
            selem_map = {}
            nodes = []
            for s in m.get("selements", []):
                sid = str(s["selementid"])
                x = int(s["x"])
                y = int(s["y"])
                hid = s["elements"][0]["hostid"] if s.get("elements") else None
                hinfo = hosts.get(hid, {})
                hname = hinfo.get("name", f"Device-{sid}")
                htech = hinfo.get("host", hname)
                ip = next((i["ip"] for i in hinfo.get("interfaces", []) if i.get("main") == "1"), "DHCP/IP")
                cat, icon, r, col = classify_host(hinfo)
                short_lbl = clean_label(hname)
                node_obj = {
                    "id": sid,
                    "name": hname,
                    "label": short_lbl,
                    "host": htech,
                    "ip": ip,
                    "category": cat,
                    "icon": icon,
                    "x": x,
                    "y": y,
                    "r": r,
                    "color": col,
                    "core": cat in ["Firewall", "Switch"],
                    "siteKey": site_key
                }
                nodes.append(node_obj)
                selem_map[sid] = node_obj

            links = []
            for l in m.get("links", []):
                s1 = str(l["selementid1"])
                s2 = str(l["selementid2"])
                if s1 in selem_map and s2 in selem_map:
                    n1 = selem_map[s1]
                    n2 = selem_map[s2]
                    if n1["category"] == "Firewall" or n2["category"] == "Firewall":
                        lcol, lw, lg = "#10b981", 3.2, 10
                    elif n1["category"] == "Switch" and n2["category"] == "Switch":
                        lcol, lw, lg = "#38bdf8", 3.0, 8
                    elif n1["category"] == "Hardware Servidor" or n2["category"] == "Hardware Servidor":
                        lcol, lw, lg = "#a855f7", 2.2, 6
                    elif n1["category"] == "Access Point" or n2["category"] == "Access Point":
                        lcol, lw, lg = "#f43f5e", 2.2, 6
                    else:
                        lcol, lw, lg = "#64748b", 1.8, 0

                    links.append({
                        "source": s1,
                        "target": s2,
                        "color": lcol,
                        "width": lw,
                        "glow": lg,
                        "curveness": 0.05
                    })

            # Add Internet links to each single site map with guaranteed non-overlapping clearance
            fw_node = next((n for n in nodes if n["category"] == "Firewall"), None)
            if fw_node and fw_node["y"] < 150:
                fw_node["y"] = 150
            if fw_node:
                fw_x = fw_node["x"]
                fw_y = fw_node["y"]
                inet_defs = {
                    "Matriz": [("inet-sp-1", "Link Redundante 50M", "wan2", fw_x - 180, 50),
                                ("inet-sp-2", "Link Primário 50M", "wan1", fw_x + 180, 50)],
                    "RJ": [("inet-rj-1", "Operadora A 50M", "wan2", fw_x - 180, 50),
                           ("inet-rj-2", "Operadora B 50M", "wan1", fw_x + 180, 50)],
                    "BA": [("inet-ba-1", "NET FIBER 30M", "wan2", fw_x - 180, 50),
                           ("inet-ba-2", "Link Rádio 40M", "wan1", fw_x + 180, 50)],
                    "PR": [("inet-pr-1", "WAN 2", "wan2", fw_x - 140, 50),
                           ("inet-pr-2", "SD-WAN", "wan1", fw_x + 140, 50)]
                }.get(site_key, [])

                for iid, iname, iwan, ix, iy in inet_defs:
                    nodes.append({
                        "id": iid,
                        "name": iname,
                        "label": iname,
                        "host": fw_node["host"],
                        "ip": iwan,
                        "category": "Internet",
                        "icon": "internet",
                        "x": ix,
                        "y": iy,
                        "r": 28,
                        "color": "#38bdf8",
                        "core": True,
                        "siteKey": site_key
                    })
                    links.append({
                        "source": iid,
                        "target": fw_node["id"],
                        "color": "#38bdf8",
                        "width": 2.5,
                        "glow": 10,
                        "curveness": 0.05
                    })

            maps_by_site[site_key] = {
                "siteKey": site_key,
                "title": f"Filial {site_key}",
                "width": mw,
                "height": mh,
                "nodes": nodes,
                "links": links
            }

    # =========================================================================
    # MULTI-FILIAL UNIFIED COORDINATED ARCHITECTURE (3600 x 950)
    # =========================================================================
    multi_nodes = []
    multi_links = []

    # 1. Filial 1 (se houver) - x: 60 -> 780, center: 420
    rj_map = maps_by_site.get("RJ", {})
    rj_coords = {
        "432": (420, 210),  # FW-RJ
        "433": (420, 320),  # SW-MikroTik
        "434": (120, 440),  # AP-ADM
        "435": (230, 530),  # AP-BALANÇA
        "436": (340, 440),  # AP-GALP1-FR
        "437": (450, 530),  # AP-GALP1-FD
        "438": (560, 440),  # AP-GALP3
        "439": (710, 440),  # iDRAC-RJ
        "440": (710, 560),  # SRV-DC01
        "441": (140, 700),  # IMPADM
        "443": (280, 700),  # IMPBAL
        "445": (420, 700),  # IMPRH
        "447": (560, 700),  # Xerox-RJ
        "442": (700, 700),  # IMPALMOX
        "444": (350, 800),  # IMPLAB
        "446": (490, 800),  # HP-Lab-RJ
    }
    for n in rj_map.get("nodes", []):
        nid = str(n["id"])
        if nid.startswith("inet-"):
            continue  # Re-placed precisely in coordinated multi-system
        node = dict(n)
        if nid in rj_coords:
            node["x"], node["y"] = rj_coords[nid]
        node["siteKey"] = "RJ"
        multi_nodes.append(node)
    for l in rj_map.get("links", []):
        if not str(l["source"]).startswith("inet-") and not str(l["target"]).startswith("inet-"):
            multi_links.append(dict(l))

    # Internet Links RJ
    multi_nodes.append({"id": "inet-rj-1", "name": "Operadora A 50M", "label": "Operadora A 50M", "host": "FW-RJ", "ip": "wan2 (50M)", "category": "Internet", "icon": "internet", "x": 330, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "RJ"})
    multi_nodes.append({"id": "inet-rj-2", "name": "Operadora B 50M", "label": "Operadora B 50M", "host": "FW-RJ", "ip": "wan1 (50M)", "category": "Internet", "icon": "internet", "x": 510, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "RJ"})
    multi_links.append({"source": "inet-rj-1", "target": "432", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": 0.05, "label": ""})
    multi_links.append({"source": "inet-rj-2", "target": "432", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": -0.05, "label": ""})

    # 2. Matriz · Matriz SP - x: 840 -> 2400, center: 1620
    sp_map = maps_by_site.get("Matriz", {})
    sp_coords = {
        "382": (1620, 210), # FW-SP
        "383": (980, 310),  # SW-17
        "384": (1300, 310), # SW-19
        "385": (1620, 310), # SW-20
        "386": (1940, 310), # SW-21
        "387": (2260, 310), # SW-Aruba
        "388": (900, 430),  # AP01
        "389": (980, 510),  # AP02
        "390": (1060, 430), # AP03
        "391": (1230, 430), # AP04
        "392": (1330, 510), # AP05
        "393": (1460, 430), # iDRAC-01
        "394": (1540, 510), # iDRAC-02
        "395": (1620, 430), # iDRAC-03
        "396": (1700, 510), # iDRAC-04
        "397": (1780, 430), # iDRAC-05
        "409": (1910, 430), # IMPDIR
        "410": (2010, 510), # IMPFIN
        "411": (2120, 430), # Nobreak-Matriz
        "412": (2230, 510), # HP-569-SP
        "413": (2330, 430), # HP-5D3-SP
        "398": (1220, 650), # ASSEMBLY
        "399": (1380, 650), # CLIPPER
        "400": (1540, 650), # DELPHI
        "401": (1700, 650), # JAVASCRIPT
        "402": (1860, 650), # NGINX-SRV
        "403": (2020, 650), # PASCAL
        "404": (1300, 790), # PHP
        "405": (1460, 790), # srv-cs01
        "406": (1580, 790), # SRV-AD01
        "407": (1740, 790), # SRV-AD02
        "408": (1900, 790), # srv-dc02
    }
    for n in sp_map.get("nodes", []):
        nid = str(n["id"])
        if nid.startswith("inet-"):
            continue
        node = dict(n)
        if nid in sp_coords:
            node["x"], node["y"] = sp_coords[nid]
        node["siteKey"] = "Matriz"
        multi_nodes.append(node)
    for l in sp_map.get("links", []):
        if not str(l["source"]).startswith("inet-") and not str(l["target"]).startswith("inet-"):
            multi_links.append(dict(l))

    # Internet Links Matriz
    multi_nodes.append({"id": "inet-sp-1", "name": "Link Redundante 50M", "label": "Link Redundante 50M", "host": "FW-SP", "ip": "wan2 (50M)", "category": "Internet", "icon": "internet", "x": 1510, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "Matriz"})
    multi_nodes.append({"id": "inet-sp-2", "name": "Link Primário 50M", "label": "Link Primário 50M", "host": "FW-SP", "ip": "wan1 (50M)", "category": "Internet", "icon": "internet", "x": 1730, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "Matriz"})
    multi_links.append({"source": "inet-sp-1", "target": "382", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": 0.05, "label": ""})
    multi_links.append({"source": "inet-sp-2", "target": "382", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": -0.05, "label": ""})

    # 3. Filial 2 (se houver) - x: 2460 -> 3180, center: 2820
    ba_map = maps_by_site.get("BA", {})
    ba_coords = {
        "417": (2820, 210), # FW-BA
        "418": (2820, 310), # SW-Core-Filial2
        "419": (2490, 440), # AP ADM
        "420": (2590, 530), # AP ARMAZEM
        "421": (2690, 440), # AP EXPEDICAO
        "422": (2790, 530), # AP FABRICA
        "423": (2890, 440), # AP LENTILHA
        "424": (2990, 530), # AP RESERVA
        "425": (3120, 440), # iDRAC-BA
        "426": (3120, 560), # SRV-AD03
        "427": (2540, 700), # HP-A9D-BA
        "429": (2720, 700), # HP-301-BA
        "431": (2900, 700), # HP-564-BA
        "428": (2630, 800), # HP-E12-BA
        "430": (2810, 800), # HP-30A-BA
    }
    for n in ba_map.get("nodes", []):
        nid = str(n["id"])
        if nid.startswith("inet-"):
            continue
        node = dict(n)
        if nid in ba_coords:
            node["x"], node["y"] = ba_coords[nid]
        node["siteKey"] = "BA"
        multi_nodes.append(node)
    for l in ba_map.get("links", []):
        if not str(l["source"]).startswith("inet-") and not str(l["target"]).startswith("inet-"):
            multi_links.append(dict(l))

    # Internet Links Bahia
    multi_nodes.append({"id": "inet-ba-1", "name": "NET FIBER 30M", "label": "NET FIBER 30M", "host": "FW-BA", "ip": "wan2 (30M)", "category": "Internet", "icon": "internet", "x": 2730, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "BA"})
    multi_nodes.append({"id": "inet-ba-2", "name": "Link Rádio 40M", "label": "Link Rádio 40M", "host": "FW-BA", "ip": "wan1 (40M)", "category": "Internet", "icon": "internet", "x": 2910, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "BA"})
    multi_links.append({"source": "inet-ba-1", "target": "417", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": 0.05, "label": ""})
    multi_links.append({"source": "inet-ba-2", "target": "417", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": -0.05, "label": ""})

    # 4. Filial 3 (se houver) - x: 3240 -> 3560, center: 3400
    pr_map = maps_by_site.get("PR", {})
    pr_coords = {
        "414": (3400, 210), # FW-PR
        "415": (3310, 360), # Brother-PR
        "416": (3490, 360), # HP-PR
    }
    for n in pr_map.get("nodes", []):
        nid = str(n["id"])
        if nid.startswith("inet-"):
            continue
        node = dict(n)
        if nid in pr_coords:
            node["x"], node["y"] = pr_coords[nid]
        node["siteKey"] = "PR"
        multi_nodes.append(node)
    for l in pr_map.get("links", []):
        if not str(l["source"]).startswith("inet-") and not str(l["target"]).startswith("inet-"):
            multi_links.append(dict(l))

    # Internet Links Paraná
    multi_nodes.append({"id": "inet-pr-1", "name": "WAN 2", "label": "WAN 2", "host": "FW-PR", "ip": "wan2", "category": "Internet", "icon": "internet", "x": 3330, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "PR"})
    multi_nodes.append({"id": "inet-pr-2", "name": "SD-WAN", "label": "SD-WAN", "host": "FW-PR", "ip": "wan1", "category": "Internet", "icon": "internet", "x": 3470, "y": 85, "r": 28, "color": "#38bdf8", "core": True, "siteKey": "PR"})
    multi_links.append({"source": "inet-pr-1", "target": "414", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": 0.05, "label": ""})
    multi_links.append({"source": "inet-pr-2", "target": "414", "color": "#38bdf8", "width": 2.5, "glow": 10, "curveness": -0.05, "label": ""})

    # =========================================================================
    # DIRECT VPN / SD-WAN MESH LINKS BETWEEN FIREWALLS (ARCS OVER THE PODS)
    # =========================================================================
    gw_targets = {"RJ": "432", "Matriz": "382", "BA": "417", "PR": "414"}
    if not valid_z_maps:
        gw_targets = {"RJ": "fw-RJ", "Matriz": "fw-Matriz", "BA": "fw-BA", "PR": "fw-PR"}

    vpn_mesh = [
        {"source": gw_targets["Matriz"], "target": gw_targets["RJ"], "color": "#00ffd5", "width": 3.8, "glow": 18, "curveness": -0.22},
        {"source": gw_targets["Matriz"], "target": gw_targets["BA"], "color": "#00ffd5", "width": 3.8, "glow": 18, "curveness": -0.20},
        {"source": gw_targets["Matriz"], "target": gw_targets["PR"], "color": "#00ffd5", "width": 3.2, "glow": 16, "curveness": -0.32},
        {"source": gw_targets["BA"], "target": gw_targets["PR"], "color": "#00e5ff", "width": 2.5, "glow": 12, "curveness": -0.15},
        {"source": gw_targets["RJ"], "target": gw_targets["BA"], "color": "#38bdf8", "width": 2.2, "glow": 10, "curveness": -0.38},
    ]
    multi_links.extend(vpn_mesh)

    site_pods = [
        [
            {"name": "FILIAL RIO DE JANEIRO · RJ (16 Ativos + 2 Links WAN)", "coord": [50, 40],
             "itemStyle": {"color": "rgba(56, 189, 248, 0.03)", "borderColor": "rgba(56, 189, 248, 0.35)", "borderWidth": 1.5, "borderType": "dashed"},
             "label": {"show": True, "position": "top", "color": "#38bdf8", "fontSize": 12, "fontWeight": "bold", "padding": [5, 10], "backgroundColor": "rgba(15, 23, 42, 0.85)", "borderRadius": 4, "borderColor": "rgba(56, 189, 248, 0.5)", "borderWidth": 1}},
            {"coord": [780, 880]}
        ],
        [
            {"name": "FILIAL BARUERI · MATRIZ SP (32 Ativos + 2 Links WAN)", "coord": [840, 40],
             "itemStyle": {"color": "rgba(16, 185, 129, 0.03)", "borderColor": "rgba(16, 185, 129, 0.35)", "borderWidth": 1.5, "borderType": "dashed"},
             "label": {"show": True, "position": "top", "color": "#10b981", "fontSize": 12, "fontWeight": "bold", "padding": [5, 10], "backgroundColor": "rgba(15, 23, 42, 0.85)", "borderRadius": 4, "borderColor": "rgba(16, 185, 129, 0.5)", "borderWidth": 1}},
            {"coord": [2400, 880]}
        ],
        [
            {"name": "FILIAL BAHIA · BA (15 Ativos + 2 Links WAN)", "coord": [2460, 40],
             "itemStyle": {"color": "rgba(232, 121, 249, 0.03)", "borderColor": "rgba(232, 121, 249, 0.35)", "borderWidth": 1.5, "borderType": "dashed"},
             "label": {"show": True, "position": "top", "color": "#e879f9", "fontSize": 12, "fontWeight": "bold", "padding": [5, 10], "backgroundColor": "rgba(15, 23, 42, 0.85)", "borderRadius": 4, "borderColor": "rgba(232, 121, 249, 0.5)", "borderWidth": 1}},
            {"coord": [3180, 880]}
        ],
        [
            {"name": "FILIAL PARANÁ · PR (3 Ativos + 2 Links WAN)", "coord": [3240, 40],
             "itemStyle": {"color": "rgba(245, 158, 11, 0.03)", "borderColor": "rgba(245, 158, 11, 0.35)", "borderWidth": 1.5, "borderType": "dashed"},
             "label": {"show": True, "position": "top", "color": "#f59e0b", "fontSize": 12, "fontWeight": "bold", "padding": [5, 10], "backgroundColor": "rgba(15, 23, 42, 0.85)", "borderRadius": 4, "borderColor": "rgba(245, 158, 11, 0.5)", "borderWidth": 1}},
            {"coord": [3560, 880]}
        ]
    ]

    maps_by_site["__all__"] = {
        "siteKey": "__all__",
        "title": "Topologia Corporativa Multifilial",
        "width": 3600,
        "height": 950,
        "nodes": multi_nodes,
        "links": multi_links,
        "pods": site_pods
    }

    return maps_by_site


_ECHARTS_JS = r"""
const seriesData = (context && context.panel && context.panel.data && context.panel.data.series) || [];

const ICONS = {
  internet: '<path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8zm-1-15.93a8 8 0 0 0-5.93 5.93h3.07a12.8 12.8 0 0 1 2.86-5.93zm2 0a12.8 12.8 0 0 1 2.86 5.93h3.07A8 8 0 0 0 13 4.07zM4.07 11a8.1 8.1 0 0 0 0 2h3.93a15.7 15.7 0 0 1 0-2zm5.93 7.93a12.8 12.8 0 0 1-2.86-5.93H4.07a8 8 0 0 0 5.93 5.93zm4 0a8 8 0 0 0 5.93-5.93h-3.07a12.8 12.8 0 0 1-2.86 5.93zM16 13h3.93a8.1 8.1 0 0 0 0-2H16a15.7 15.7 0 0 1 0 2zm-6-2v2h4v-2z"/>',
  firewall: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9.3h18M3 14.7h18M9 4v5.3M15 4v5.3M12 9.3v5.4M7 14.7V20M17 14.7V20"/>',
  switch: '<rect x="2" y="7" width="20" height="10" rx="2"/><circle cx="6" cy="12" r="1.5"/><circle cx="10" cy="12" r="1.5"/><circle cx="14" cy="12" r="1.5"/><circle cx="18" cy="12" r="1.5"/>',
  server: '<rect x="3" y="3.5" width="18" height="7.5" rx="2"/><rect x="3" y="13" width="18" height="7.5" rx="2"/><circle cx="7" cy="7.25" r="1"/><circle cx="7" cy="16.75" r="1"/><path d="M11 7.25h6M11 16.75h6"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  battery: '<rect x="2" y="7" width="17" height="10" rx="2"/><path d="M22 10.5v3M11 9l-2.5 3.2h3.4L9.5 15.2"/>',
  wifi: '<path d="M2.5 9.2a14 14 0 0 1 19 0M5.6 12.6a9.5 9.5 0 0 1 12.8 0M8.8 16a4.8 4.8 0 0 1 6.4 0M12 19.6h.01"/>',
  printer: '<path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>'
};

const iconUri = (name, color) => 'image://data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="' + color +
  '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + (ICONS[name] || ICONS.server) + '</svg>');

const MAPS = __MAPS_DATA__;

let selectedSite = '$__all';
try {
  if (context && context.grafana && typeof context.grafana.replaceVariables === 'function') {
    const rawSite = context.grafana.replaceVariables('$site');
    if (rawSite && rawSite !== '.*' && rawSite !== '$site' && rawSite !== '$__all' && rawSite !== 'Todas' && rawSite !== 'All') {
      for (const k of Object.keys(MAPS)) {
        if (k !== '__all__' && (rawSite === k || rawSite.indexOf(k) >= 0)) {
          selectedSite = k;
          break;
        }
      }
    }
  }
} catch (e) { selectedSite = '$__all'; }

const isMulti = (selectedSite === '$__all' || selectedSite === '.*' || !selectedSite || selectedSite === 'Todas' || selectedSite === 'All');
const activeMap = isMulti ? (MAPS['__all__'] || Object.values(MAPS)[0]) : (MAPS[selectedSite] || MAPS['__all__']);
const allNodes = activeMap.nodes || [];
const allLinks = activeMap.links || [];
const sitePods = activeMap.pods || [];

const COLORS = { up: '#10b981', down: '#ef4444', partial: '#f59e0b', unknown: '#64748b' };
const LABELS = { up: 'ONLINE', down: 'OFFLINE', partial: 'PARCIAL', unknown: 'SEM DADOS' };

const lastValue = (field) => {
  const raw = field && field.values ? field.values : [];
  const vals = typeof raw.toArray === 'function' ? raw.toArray() : raw;
  for (let i = vals.length - 1; i >= 0; i--) {
    if (vals[i] !== null && vals[i] !== undefined) return Number(vals[i]);
  }
  return null;
};

// Robust normalizer for matching visible names, technical names, and unaccented names
const norm = (s) => (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');

const hostChecks = {};
const mergeOk = (prev, ok) => (prev === undefined || prev === null || ok === false ? ok : prev);

for (const frame of seriesData) {
  const valueField = (frame.fields || []).find((f) => f.type === 'number');
  if (!valueField) continue;
  
  let host = (valueField.labels && valueField.labels.host) || '';
  if (!host && frame.name && frame.name.indexOf(':') > 0) {
    host = frame.name.split(':')[0].trim();
  }
  if (!host) continue;

  const key = (valueField.labels && valueField.labels.item_key) || '';
  const item = (valueField.labels && valueField.labels.item) || frame.name || key;
  const last = lastValue(valueField);

  const ok = last === null ? null : (key === 'icmpping' || item.indexOf('ICMP ping') >= 0 ? last === 1 : (last === 1 ? true : last === 0 ? false : null));
  const kind = (key === 'icmpping' || item.indexOf('ICMP ping') >= 0) ? 'ping'
    : (key.indexOf(',agent,') >= 0 || item === 'Zabbix agent availability' ? 'agent' : 'snmp');

  const c = hostChecks[host] = hostChecks[host] || {};
  hostChecks[norm(host)] = c;
  if (host.indexOf(' - ') >= 0) {
    hostChecks[norm(host.split(' - ')[0])] = c;
  }

  if (item.indexOf('Connected clients') >= 0 || key.indexOf('clients.total') >= 0) {
    c.clients = last;
  } else {
    c[kind] = mergeOk(c[kind], ok);
  }
}

const hostStatus = (n) => {
  const c = hostChecks[n.host] ||
            hostChecks[n.name] ||
            hostChecks[norm(n.host)] ||
            hostChecks[norm(n.name)] ||
            (n.name && hostChecks[norm(n.name.split(' - ')[0])]) ||
            (n.host && hostChecks[norm(n.host.split(' - ')[0])]) ||
            {};

  const hasPing = c.ping !== undefined && c.ping !== null;
  const reach = hasPing ? c.ping : (c.snmp === undefined ? null : c.snmp);
  const agentDown = c.agent === false || (hasPing && c.snmp === false);
  let state = 'unknown';
  if (reach === false) state = 'down';
  else if (reach === true) state = agentDown ? 'partial' : 'up';
  else if (c.agent === true) state = 'up';
  else if (c.agent === false) state = 'down';
  return { state, clients: c.clients };
};

const byId = {};
const discs = [], alarms = [], iconItems = [], textItems = [];
const linesStatic = [], linesFlowing = [];

allNodes.forEach((n) => {
  const isInet = n.category === 'Internet';
  const check = isInet ? { state: 'up' } : hostStatus(n);
  const st = check.state;
  const col = isInet ? '#38bdf8' : (COLORS[st] || COLORS.up);
  const isDown = st === 'down';
  const isLoud = isDown || (n.core && st === 'up');

  const nodeObj = Object.assign({}, n, { state: st, color: col, clients: check.clients });
  byId[n.id] = nodeObj;

  if (isLoud) {
    alarms.push({
      value: [n.x, n.y],
      symbolSize: Math.round(n.r * (isDown ? 1.6 : 1.35)),
      itemStyle: {
        color: isDown ? 'rgba(239, 68, 68, 0.4)' : (isInet ? 'rgba(56, 189, 248, 0.22)' : 'rgba(16, 185, 129, 0.22)'),
        shadowBlur: isDown ? 24 : 14,
        shadowColor: col
      },
      tipData: nodeObj
    });
  }

  const shortName = n.label || (n.name.length > 11 ? n.name.slice(0, 10) + '…' : n.name);
  const isAp = n.category === 'Access Point';
  const showSub = !isMulti || isAp || isInet;
  const subText = isAp && check.clients !== undefined && check.clients !== null
    ? check.clients + ' cli'
    : (isInet ? n.ip : (!isMulti ? (n.ip || '') : ''));

  discs.push({
    value: [n.x, n.y],
    symbolSize: n.r,
    itemStyle: {
      color: isDown ? 'rgba(38, 12, 18, 0.95)' : (st === 'up' ? 'rgba(10, 25, 22, 0.92)' : 'rgba(20, 24, 39, 0.92)'),
      borderColor: col,
      borderWidth: isDown ? 3 : 2,
      shadowBlur: isDown ? 24 : 12,
      shadowColor: col
    },
    label: {
      show: true,
      position: 'bottom',
      distance: 6,
      formatter: showSub && subText
        ? ['{name|' + shortName + '}', '{sub|' + subText + '}'].join(String.fromCharCode(10))
        : '{name|' + shortName + '}',
      rich: {
        name: {
          color: '#f8fafc',
          fontSize: isMulti ? 8.5 : 10,
          fontWeight: 'bold',
          lineHeight: isMulti ? 10 : 13,
          align: 'center',
          textBorderColor: 'rgba(0,0,0,0.85)',
          textBorderWidth: 2
        },
        sub: {
          color: isAp ? '#f43f5e' : (isInet ? '#38bdf8' : '#94a3b8'),
          fontSize: isMulti ? 8 : 9,
          fontFamily: isAp ? 'sans-serif' : 'monospace',
          fontWeight: isAp ? 'bold' : 'normal',
          lineHeight: isMulti ? 10 : 12,
          align: 'center',
          textBorderColor: 'rgba(0,0,0,0.85)',
          textBorderWidth: 2
        }
      }
    },
    tipData: nodeObj
  });

  iconItems.push({
    value: [n.x, n.y],
    symbol: iconUri(n.icon || (isInet ? 'internet' : 'server'), col),
    symbolSize: Math.round(n.r * (isInet ? 0.60 : 0.52)),
    silent: true
  });
});

allLinks.forEach((l) => {
  const n1 = byId[l.source];
  const n2 = byId[l.target];
  if (!n1 || !n2) return;

  const isDown = n1.state === 'down' || n2.state === 'down';
  const linkColor = isDown ? '#ef4444' : (l.color || '#38bdf8');
  const curve = l.curveness || 0;

  linesStatic.push({
    coords: [[n1.x, n1.y], [n2.x, n2.y]],
    lineStyle: {
      color: linkColor,
      width: l.width || (isDown ? 3 : 2),
      opacity: isDown ? 0.9 : 0.75,
      curveness: curve,
      type: l.type || 'solid',
      shadowBlur: l.glow || 0,
      shadowColor: linkColor
    },
    label: { show: false }
  });

  if (!isDown) {
    linesFlowing.push({
      coords: [[n1.x, n1.y], [n2.x, n2.y]],
      lineStyle: {
        curveness: curve
      }
    });
  }
});

return {
  backgroundColor: 'transparent',
  grid: { left: 10, right: 10, top: 10, bottom: 10, containLabel: false },
  dataZoom: [
    {
      type: 'inside',
      xAxisIndex: [0],
      filterMode: 'none',
      zoomOnMouseWheel: true,
      moveOnMouseMove: true,
      preventDefaultMouseMove: false
    },
    {
      type: 'inside',
      yAxisIndex: [0],
      filterMode: 'none',
      zoomOnMouseWheel: true,
      moveOnMouseMove: true,
      preventDefaultMouseMove: false
    }
  ],
  toolbox: {
    show: true,
    right: 20,
    top: 15,
    itemSize: 14,
    itemGap: 10,
    iconStyle: {
      borderColor: '#94a3b8'
    },
    emphasis: {
      iconStyle: {
        borderColor: '#38bdf8'
      }
    },
    feature: {
      restore: { title: 'Resetar Zoom' },
      saveAsImage: { title: 'Salvar Topologia', pixelRatio: 2 }
    }
  },
  xAxis: {
    type: 'value',
    min: 0,
    max: activeMap.width || 3600,
    show: false
  },
  yAxis: {
    type: 'value',
    min: 0,
    max: activeMap.height || 950,
    inverse: true,
    show: false
  },
  tooltip: {
    trigger: 'item',
    backgroundColor: 'rgba(15, 23, 42, 0.96)',
    borderColor: '#38bdf8',
    borderWidth: 1.5,
    padding: [10, 14],
    textStyle: { color: '#f8fafc', fontSize: 12 },
    formatter: (params) => {
      const d = params.data && params.data.tipData;
      if (!d) return '';
      const col = COLORS[d.state] || COLORS.up;
      const lbl = LABELS[d.state] || 'ONLINE';
      let rows = `
        <div style="font-weight:bold;font-size:14px;color:#38bdf8;margin-bottom:6px;">${d.name}</div>
        <table style="font-size:11px;line-height:1.6;border-collapse:collapse;">
          <tr><td><b>Categoria:</b></td><td style="padding-left:10px;">${d.category}</td></tr>
          <tr><td><b>IP:</b></td><td style="padding-left:10px;font-family:monospace;color:#00ffd5;">${d.ip || 'DHCP'}</td></tr>
          <tr><td><b>Filial:</b></td><td style="padding-left:10px;">${d.siteKey}</td></tr>
          <tr><td><b>Status:</b></td><td style="padding-left:10px;"><span style="color:${col};font-weight:bold;">● ${lbl}</span></td></tr>
      `;
      if (d.clients !== undefined && d.clients !== null) {
        rows += `<tr><td><b>Clientes Wi-Fi:</b></td><td style="padding-left:10px;color:#f43f5e;font-weight:bold;">📶 ${d.clients} conectados</td></tr>`;
      }
      if (d.role) {
        rows += `<tr><td><b>Papel:</b></td><td style="padding-left:10px;">${d.role}</td></tr>`;
      }
      rows += `</table>`;
      if (isMulti) {
        rows += `<div style="margin-top:8px;font-size:10px;color:#38bdf8;border-top:1px solid #334155;padding-top:4px;">🖱️ Clique para filtrar esta filial</div>`;
      }
      return rows;
    }
  },
  series: [
    {
      name: 'pods',
      type: 'scatter',
      data: [],
      markArea: {
        silent: true,
        data: sitePods
      }
    },
    {
      name: 'alarms',
      type: 'scatter',
      coordinateSystem: 'cartesian2d',
      data: alarms,
      silent: false
    },
    {
      name: 'discs',
      type: 'scatter',
      coordinateSystem: 'cartesian2d',
      data: discs,
      silent: false
    },
    {
      name: 'icons',
      type: 'scatter',
      coordinateSystem: 'cartesian2d',
      data: iconItems,
      silent: true
    },

    {
      name: 'linesStatic',
      type: 'lines',
      coordinateSystem: 'cartesian2d',
      polyline: false,
      data: linesStatic,
      silent: true
    },
    {
      name: 'linesFlowing',
      type: 'lines',
      coordinateSystem: 'cartesian2d',
      polyline: false,
      effect: {
        show: true,
        period: 4.5,
        trailLength: 0.25,
        symbol: 'circle',
        symbolSize: isMulti ? 4 : 5,
        color: '#00ffd5'
      },
      lineStyle: {
        color: 'transparent',
        width: 2,
        opacity: 0
      },
      data: linesFlowing,
      silent: true
    }
  ]
};
"""


def build(cfg, datasource_uid="zabbix", api=None):
    """Builds the complete AutoDiscovery Maps v3 dashboard."""
    maps_by_site = build_site_maps_data(api, cfg)
    sites_list = sorted([k for k in maps_by_site.keys() if k != "__all__"])

    echarts_code = _ECHARTS_JS.replace("__MAPS_DATA__", json.dumps(maps_by_site, ensure_ascii=False))

    # Click interaction for drill-down into site
    click_code = r"""
const ecInst = (typeof echartsInstance !== 'undefined' ? echartsInstance : (context && context.echartsInstance));
if (ecInst && !window.__autodiscovery_maps_click_bound) {
  window.__autodiscovery_maps_click_bound = true;
  ecInst.on('click', (params) => {
    if (params && params.data && params.data.tipData) {
      const d = params.data.tipData;
      if (d.siteKey && d.siteKey !== 'ALL' && typeof locationService !== 'undefined') {
        locationService.partial({ 'var-site': d.siteKey }, true);
      }
    }
  });
}
"""
    echarts_code = click_code + "\n" + echarts_code

    # Stat Cards (Online, Total, Offline, Gateways)
    card_online = {
        "id": 101,
        "title": "HOSTS ONLINE (FILIAIS)",
        "type": "stat",
        "gridPos": {"x": 0, "y": 0, "w": 6, "h": 3},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "fixed", "fixedColor": "#10b981"},
                "decimals": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": "#10b981", "value": 0}]},
                "unit": "short"
            },
            "overrides": []
        },
        "options": {
            "colorMode": "value", "graphMode": "none", "justifyMode": "center", "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": false},
            "textMode": "value_and_name", "wideLayout": True,
            "text": {"valueSize": 38, "titleSize": 12}
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Aggregate", "defaultParams": [], "name": "sumSeries", "params": []}, "params": [], "text": "sumSeries()"},
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["Disponíveis"], "text": "setAlias(Disponíveis)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "ICMP ping"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            }
        ]
    }

    card_total = {
        "id": 102,
        "title": "TOTAL DISPOSITIVOS MAPEADOS",
        "type": "stat",
        "gridPos": {"x": 6, "y": 0, "w": 6, "h": 3},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "fixed", "fixedColor": "#00e5ff"},
                "decimals": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": "#00e5ff", "value": 0}]},
                "unit": "short"
            },
            "overrides": []
        },
        "options": {
            "colorMode": "value", "graphMode": "none", "justifyMode": "center", "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": false},
            "textMode": "value_and_name", "wideLayout": True,
            "text": {"valueSize": 38, "titleSize": 12}
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Transform", "defaultParams": [100], "name": "scale", "params": [{"name": "factor", "type": "float"}]}, "params": [0], "text": "scale(0)"},
                    {"def": {"category": "Transform", "defaultParams": [100], "name": "offset", "params": [{"name": "delta", "type": "float"}]}, "params": [1], "text": "offset(1)"},
                    {"def": {"category": "Aggregate", "defaultParams": [], "name": "sumSeries", "params": []}, "params": [], "text": "sumSeries()"},
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["Ativos no Mapa"], "text": "setAlias(Ativos no Mapa)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "ICMP ping"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            }
        ]
    }

    card_offline = {
        "id": 103,
        "title": "HOSTS OFFLINE / ALARME",
        "type": "stat",
        "gridPos": {"x": 12, "y": 0, "w": 6, "h": 3},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "decimals": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": "#10b981", "value": 0}, {"color": "#ef4444", "value": 1}]},
                "unit": "short"
            },
            "overrides": []
        },
        "options": {
            "colorMode": "value", "graphMode": "none", "justifyMode": "center", "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": false},
            "textMode": "value_and_name", "wideLayout": True,
            "text": {"valueSize": 38, "titleSize": 12}
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Transform", "defaultParams": [100], "name": "scale", "params": [{"name": "factor", "type": "float"}]}, "params": [-1], "text": "scale(-1)"},
                    {"def": {"category": "Transform", "defaultParams": [100], "name": "offset", "params": [{"name": "delta", "type": "float"}]}, "params": [1], "text": "offset(1)"},
                    {"def": {"category": "Aggregate", "defaultParams": [], "name": "sumSeries", "params": []}, "params": [], "text": "sumSeries()"},
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["Indisponíveis"], "text": "setAlias(Indisponíveis)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "ICMP ping"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            }
        ]
    }

    card_gateway = {
        "id": 104,
        "title": "STATUS DOS GATEWAYS / BORDA",
        "type": "stat",
        "gridPos": {"x": 18, "y": 0, "w": 6, "h": 3},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "decimals": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": "#ef4444", "value": 0}, {"color": "#10b981", "value": 1}]},
                "unit": "short",
                "mappings": [
                    {"type": "value", "options": {"1": {"text": "ONLINE", "color": "#10b981"}, "0": {"text": "OFFLINE", "color": "#ef4444"}}}
                ]
            },
            "overrides": []
        },
        "options": {
            "colorMode": "value", "graphMode": "none", "justifyMode": "center", "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": false},
            "textMode": "value_and_name", "wideLayout": True,
            "text": {"valueSize": 38, "titleSize": 12}
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["$__zbx_host_name"], "text": "setAlias($__zbx_host_name)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/^FW-/i"},
                "item": {"filter": "ICMP ping"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            }
        ]
    }

    # Preserving user adjusted layout: Map w: 19, Side panels w: 5
    map_panel = {
        "id": 4,
        "title": "TOPOLOGIA DE REDE MULTIFILIAL (INTERCONEXÃO WAN & MAPAS DAS FILIAIS)",
        "type": "volkovlabs-echarts-panel",
        "gridPos": {"x": 0, "y": 3, "w": 19, "h": 16},
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {
                        "def": {
                            "category": "Transform", "defaultParams": ["1m", "avg"], "name": "groupBy",
                            "params": [{"name": "interval", "type": "string"}, {"name": "function", "options": ["avg", "min", "max", "sum", "count", "median", "first", "last"], "type": "string"}]
                        },
                        "params": ["1h", "last"],
                        "text": "groupBy(1h, last)"
                    }
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "/^(ICMP ping|SNMP agent availability|Zabbix agent availability|Wireless: Connected clients)$/"},
                "itemTag": {"filter": ""},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            }
        ],
        "options": {
            "getOption": echarts_code,
            "renderer": "canvas"
        }
    }

    table_inventory = {
        "id": 5,
        "title": "INVENTÁRIO DE ATIVOS",
        "type": "table",
        "gridPos": {"x": 19, "y": 3, "w": 5, "h": 8},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "displayMode": "auto", "inspect": False},
                "color": {"mode": "thresholds"},
                "thresholds": {"mode": "absolute", "steps": [{"color": "#10b981", "value": 0}]}
            },
            "overrides": [
                {
                    "matcher": {"id": "byRegexp", "options": "Last.*|Value"},
                    "properties": [
                        {"id": "displayName", "value": "Status"},
                        {"id": "custom.width", "value": 90},
                        {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
                        {"id": "mappings", "value": [
                            {"type": "value", "options": {"1": {"text": "ONLINE", "color": "#10b981", "index": 0}, "0": {"text": "OFFLINE", "color": "#ef4444", "index": 1}}}
                        ]}
                    ]
                },
                {
                    "matcher": {"id": "byRegexp", "options": "Field|Metric|Servidor"},
                    "properties": [
                        {"id": "displayName", "value": "Dispositivo"},
                        {"id": "custom.width", "value": 180}
                    ]
                }
            ]
        },
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "enablePagination": False, "fields": "", "reducer": ["sum"], "show": False},
            "showHeader": True,
            "sortBy": [{"displayName": "Dispositivo", "desc": False}]
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["$__zbx_host_name"], "text": "setAlias($__zbx_host_name)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "/^(Zabbix agent availability|ICMP ping)$/"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            }
        ],
        "transformations": [{"id": "reduce", "options": {"reducers": ["lastNotNull"]}}]
    }

    timeseries_wan = {
        "id": 6,
        "title": "TRÁFEGO DE REDE WAN (LIVE BPS)",
        "type": "timeseries",
        "gridPos": {"x": 19, "y": 11, "w": 5, "h": 8},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "fieldConfig": {
            "defaults": {
                "custom": {
                    "drawStyle": "line", "lineInterpolation": "smooth", "lineWidth": 1.8,
                    "fillOpacity": 8, "gradientMode": "opacity", "spanNulls": True
                },
                "unit": "bps"
            },
            "overrides": []
        },
        "options": {
            "legend": {"calcs": ["mean", "max"], "displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"}
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["$__zbx_host: Download"], "text": "setAlias($__zbx_host: Download)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/^FW-/i"},
                "item": {"filter": "/Bits received/i"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "A"
            },
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {"def": {"category": "Alias", "defaultParams": [], "name": "setAlias", "params": [{"name": "alias", "type": "string"}]}, "params": ["$__zbx_host: Upload"], "text": "setAlias($__zbx_host: Upload)"}
                ],
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/^FW-/i"},
                "item": {"filter": "/Bits sent/i"},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0", "refId": "B"
            }
        ]
    }

    panel_triggers = {
        "id": 8,
        "title": "FEED DE ALARMES NOC (TEMPO REAL)",
        "type": "alexanderzobnin-zabbix-triggers-panel",
        "gridPos": {"x": 0, "y": 19, "w": 24, "h": 6},
        "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
        "options": {
            "ageField": True, "countBadge": True, "customLastChangeFormat": True, "dailyRibbon": True,
            "descriptionAtOk": False, "descriptionAtProblem": True, "fontSize": "100%", "highlightBackground": False,
            "highlightSeverity": True, "hostField": True, "hostProxy": False, "hostTechNameField": False,
            "lastChangeFormat": "DD/MM HH:mm", "layout": "table", "limit": 15, "markAckEvents": True,
            "opdataField": False, "order": 1, "page": 1, "pageSize": 10, "problemField": True,
            "resizedColumns": [], "severityField": True, "showAck": True, "showAge": True,
            "showCountBadge": True, "showDescription": True, "showDuration": True, "showEscalations": True,
            "showEventId": False, "showHost": True, "showHostGroups": True, "showLastChange": True,
            "showOpdata": False, "showProxy": False, "showSeverity": True, "showStatus": True,
            "showTags": True, "showTechName": False, "showTimeline": True, "sortProblems": "default",
            "statusField": True, "tagsField": True, "timeline": True
        },
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "group": {"filter": r"/^Filiais\/$site$/"},
                "host": {"filter": "/.*/"},
                "options": {"acknowledged": 2, "minSeverity": 2, "sortProblems": "default"},
                "proxy": {"filter": ""},
                "queryType": "5", "refId": "A", "tags": {"filter": ""}
            }
        ]
    }

    panels = [card_online, card_total, card_offline, card_gateway, map_panel, table_inventory, timeseries_wan, panel_triggers]

    site_options = [{"text": f"Filial {s}", "value": s, "selected": False} for s in sites_list]
    query_str = ", ".join(f"Filial {s} : {s}" for s in sites_list)

    variables = [
        {
            "name": "datasource",
            "type": "datasource",
            "label": "Data Source",
            "query": "alexanderzobnin-zabbix-datasource",
            "current": {"selected": True, "text": datasource_uid, "value": datasource_uid},
            "hide": 0
        },
        {
            "name": "site",
            "type": "custom",
            "label": "Filial / Unidade",
            "query": query_str,
            "options": [{"text": "All", "value": "$__all", "selected": True}] + site_options,
            "current": {"selected": True, "text": "All", "value": "$__all"},
            "includeAll": True,
            "allValue": ".*",
            "multi": False,
            "hide": 0
        },
        {
            "name": "site_hosts",
            "type": "query",
            "label": "Hosts da Filial",
            "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
            "query": {
                "application": "",
                "group": r"/^Filiais\/$site$/",
                "host": "/.*/",
                "item": "",
                "itemTag": "",
                "queryType": "host"
            },
            "includeAll": True,
            "multi": True,
            "hide": 2,
            "refresh": 1,
            "sort": 1
        }
    ]

    return {
        "annotations": {"list": []},
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "liveNow": False,
        "panels": panels,
        "refresh": "1m",
        "schemaVersion": 39,
        "tags": ["autodiscovery", "autodiscovery-v3", "noc", "maps", "topology"],
        "templating": {"list": variables},
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"]},
        "timezone": "browser",
        "title": TITLE,
        "uid": UID,
        "version": 1
    }
