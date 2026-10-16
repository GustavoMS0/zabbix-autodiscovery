"""Topologia da rede, protótipo A: painel Canvas nativo do Grafana (TV 1920x1080, uma tela, sem rolagem).

Layout (TV_HEIGHT = 27 grid units):
  y0  h4   banner | hosts online | offline | links offline | túneis offline | problemas por severidade
  y4  h23  mapa Canvas: provedores -> FortiGate -> core -> distribuição/servidores/APs/impressoras por filial,
           e a malha SD-WAN (um par de filiais por linha) sob o Paraná

The map is global (every site, no $site filter): a TV wall shows the whole network, and a filter would turn
the other sites grey, which in NOC language reads as "monitoring broken".

How the map gets its data. Canvas binds an element to a field by name, so the queries are shaped into ONE
row whose fields are the map elements:
  A  availability of the mapped hosts (ICMP | SNMP | agent, unknown removed): replaceAlias maps each host
     to its node, e.g. {"n":"_fw-sp","h":"FW-SP"}
  B  operational status of the 8 internet links, 1 = up, anything else = 0 (removeAboveValue + transformNull)
  C  IPsec tunnel status (FortiGate 1 down / 2 up, offset -1 -> 0/1) per pair of sites and per END
  F  the same tunnels, every one = 1: the number of tunnels configured at each end
  D  the nobreak, which has no availability item: alive while its sysUpTime item reports...
  G  ...and no "Sem dados SNMP" problem is open on it (its template's nodata trigger, 10 min)
  E  open problems >= Média (frontend query): max severity per host -> a severity tag on the card
Frontend transforms (each pipeline filtered by refId): problems -> one field per host; metrics -> series
to rows (last value), JSON alias -> columns n/h, max per (n, h) (a host counts once, by its best check, as
in style.health_transforms), sum per n, rows -> fields; then all frames are concatenated into one row and
every element field is (re)built from the raw "_" fields:
  - links and tunnels are gated by their firewall's availability (SNMP stops when the FortiGate dies and
    the last good status would stay "up" for the whole window);
  - a pair of sites counts TUNNELS, not ends: up = min(up at A, up at B), total = max(configured at A, at B);
    a tunnel configured at one end only is flagged with "⚠";
  - each element's status field colours its text/icon, and two copies colour the card fill (·bg) and the
    border/line (·ln): healthy recedes (deep green fill, dim green border), failure pops (red/amber fill,
    neon border); the copies run after a filter that drops the raw fields (refresh cost, see below).
  - iDRACs are out-of-band: a dotted line to the server they manage, never a hop on the LAN path.

Host names come from topology.NODES (verified with host.get); printers, tunnels and links were verified on
2026-10-15 (host.get / item.get / ds/query). Element positions are in a virtual 1872x850 px space (the
panel's inner size at 1920x1080) and published as percentages (constraint "scale"); font sizes are fixed
px, so the map is designed for 1920x1080 (smaller screens shrink the boxes, not the text).
"""
import json
import re
from urllib.parse import quote

from .. import topology as v1
from . import style as S

KEY = "topology-canvas"
MAP_ID = 20                 # canvas panel: the WAN and SD-WAN KPI tiles reuse its transformed data
HEALTH_ID = 2               # hosts online: OFFLINE reuses its raw data
MAP_HEIGHT = S.TV_HEIGHT - 4
W, H = 1872, 850            # virtual canvas (px): inner size of the map panel at 1920x1080

# ------------------------------------------------------------------------------------------- inventory
_V1 = {n["id"]: n for n in v1.NODES}


def _hosts(*ids):
    return [h for i in ids for h in _V1[i]["hosts"]]


# Printers are not on the v1 map: names checked with host.get (group Rede/Impressoras, per Filiais/*).
PRINTERS = {
    "SP": ["GEQ10-IMPDIR", "GEQ10-IMPFIN", "NPI5695D5", "NPI5D37FB"],
    "RJ": ["BRA30-IMPADM", "BRA30-IMPALMOX", "BRA30-IMPBAL", "BRA30-IMPLAB", "BRA30-IMPRH", "NPIA9A017",
           "NXE3841CF"],
    "BA": ["HPA9D24F", "HPE1206C", "NPI301581", "NPI30A61D", "NPI5645C9"],
    "PR": ["BRN001BA9F4C5A5", "HP5FFB5E"],
}

# Zones (site columns) of the virtual canvas: x0, x1, bottom, title, subtitle.
TOP = 12                    # room above the zone titles for the panel's hover header
ZONES = {
    "SP": (0, 630, 838, "BARUERI (SP)", "MATRIZ · HUB SD-WAN · 192.168.0.0/24"),
    "RJ": (646, 1106, 838, "RIO DE JANEIRO", "FILIAL · 192.168.3.0/24"),
    "BA": (1122, 1582, 838, "BAHIA", "FILIAL · 192.168.2.0/24"),
    "PR": (1598, W, 496, "PARANÁ", "FILIAL · 192.168.1.0/24"),
}
# Rows: top y and card height. Cards have three lines (name / status / IP or speed).
CARD_H = 78
ROWS = {"isp": 90, "fw": 244, "core": 400, "r4": 560, "r5": 720}

ICON = {"isp": "cloud", "fw": "shield-check", "switch": "sitemap", "ups": "battery-bolt", "idrac": "processor",
        "hyperv": "layer-group", "servers": "servers", "server": "server", "wifi": "wifi", "printer": "print"}

# Map nodes: id, centre x, row, width, title, icon, member hosts, caption (IP of single devices), v2 dashboard.
NODES = [
    # Barueri (SP): FW, core, nobreak, distribution, Dell hardware -> Hyper-V -> VMs, Wi-Fi, printers
    dict(id="fw-sp", cx=315, row="fw", w=220, title="FW-SP", icon="fw", hosts=_hosts("fw-sp"),
         sub=_V1["fw-sp"]["ip"], dash="firewalls"),
    dict(id="core-sp", cx=315, row="core", w=210, title="Core Aruba", icon="switch", hosts=_hosts("sw-core-sp"),
         sub=_V1["sw-core-sp"]["ip"], dash="switches"),
    dict(id="ups-sp", cx=94, row="core", w=164, title="Nobreak", icon="ups", hosts=_hosts("ups-sp"),
         sub=_V1["ups-sp"]["ip"], dash="ups"),
    dict(id="hw-sp", cx=536, row="core", w=164, title="iDRAC Dell", icon="idrac",
         hosts=_hosts("hw-sp-1", "hw-sp-2", "hw-sp-3", "hw-sp-4", "hw-sp-5"), dash="server-hardware"),
    dict(id="dist-sp", cx=315, row="r4", w=184, title="Switches", icon="switch",
         hosts=_hosts("sw-sp-17", "sw-sp-19", "sw-sp-20", "sw-sp-21"), dash="switches"),
    dict(id="hv-sp", cx=536, row="r4", w=164, title="Hyper-V", icon="hyperv", hosts=_hosts("vm-cluster-sp"),
         dash="servers"),
    dict(id="ap-sp", cx=94, row="r5", w=164, title="Wi-Fi", icon="wifi", hosts=_hosts("ap-sp"),
         dash="access-points"),
    dict(id="prn-sp", cx=315, row="r5", w=184, title="Impressoras", icon="printer", hosts=PRINTERS["SP"],
         dash="printers"),
    dict(id="srv-sp", cx=536, row="r5", w=164, title="Servidores", icon="servers", hosts=_hosts("srv-sp"),
         dash="servers"),
    # Rio de Janeiro
    dict(id="fw-rj", cx=876, row="fw", w=220, title="FW-RJ", icon="fw", hosts=_hosts("fw-rj"),
         sub=_V1["fw-rj"]["ip"], dash="firewalls"),
    dict(id="core-rj", cx=876, row="core", w=220, title="Core MikroTik", icon="switch",
         hosts=_hosts("sw-core-rj"), sub=_V1["sw-core-rj"]["ip"], dash="switches"),
    dict(id="hw-rj", cx=725, row="r5", w=146, title="iDRAC Dell", icon="idrac", hosts=_hosts("hw-rj-1"),
         dash="server-hardware"),
    dict(id="ap-rj", cx=876, row="r4", w=146, title="Wi-Fi", icon="wifi", hosts=_hosts("ap-rj"),
         dash="access-points"),
    dict(id="prn-rj", cx=1027, row="r4", w=146, title="Impressoras", icon="printer", hosts=PRINTERS["RJ"],
         dash="printers"),
    dict(id="srv-rj", cx=725, row="r4", w=146, title="SRV-DC01", icon="server", hosts=_hosts("vm-rj-1"),
         dash="servers"),
    # Bahia
    dict(id="fw-ba", cx=1352, row="fw", w=220, title="FW-BA", icon="fw", hosts=_hosts("fw-ba"),
         sub=_V1["fw-ba"]["ip"], dash="firewalls"),
    dict(id="core-ba", cx=1352, row="core", w=220, title="Core BA", icon="switch", hosts=_hosts("sw-core-ba"),
         sub=_V1["sw-core-ba"]["ip"], dash="switches"),
    dict(id="hw-ba", cx=1201, row="r5", w=146, title="iDRAC Dell", icon="idrac", hosts=_hosts("hw-ba-1"),
         dash="server-hardware"),
    dict(id="ap-ba", cx=1352, row="r4", w=146, title="Wi-Fi", icon="wifi", hosts=_hosts("ap-ba"),
         dash="access-points"),
    dict(id="prn-ba", cx=1503, row="r4", w=146, title="Impressoras", icon="printer", hosts=PRINTERS["BA"],
         dash="printers"),
    dict(id="srv-ba", cx=1201, row="r4", w=146, title="SRV-AD03", icon="server", hosts=_hosts("vm-ba-1"),
         dash="servers"),
    # Paraná: only the firewall and printers are monitored there
    dict(id="fw-pr", cx=1735, row="fw", w=220, title="FW-PR", icon="fw", hosts=_hosts("fw-pr"),
         sub=_V1["fw-pr"]["ip"], dash="firewalls"),
    dict(id="prn-pr", cx=1735, row="core", w=184, title="Impressoras", icon="printer", hosts=PRINTERS["PR"],
         dash="printers"),
]
for _n in NODES:
    _n["site"] = _n["id"][-2:].upper()
    # element names show up in Canvas tooltips/editor: human and unique ("Wi-Fi (RJ)")
    _n["label"] = _n["title"] if _n["site"] in _n["title"] else f"{_n['title']} ({_n['site']})"

# Internet links (FortiGate WAN interfaces, WAN_STATUS_RE): field "<FW> <interface>", provider, speed.
WAN_LINKS = [
    dict(fw="fw-sp", iface="wan1", name="Megatelecom", speed="50 Mbps", cx=219, w=184),
    dict(fw="fw-sp", iface="wan2", name="AmericaNet", speed="50 Mbps", cx=411, w=184),
    dict(fw="fw-rj", iface="a", name="Internet10", speed="50 Mbps", cx=778, w=184),
    dict(fw="fw-rj", iface="wan", name="Easy Net", speed="50 Mbps", cx=974, w=184),
    dict(fw="fw-ba", iface="a", name="NET Fiber", speed="30 Mbps", cx=1254, w=184),
    dict(fw="fw-ba", iface="wan", name="ITS", speed="40 Mbps", cx=1450, w=184),
    # the PR interfaces carry no speed (and the second no provider) in their alias: "wan(LIGGA)", "a(wan2)"
    dict(fw="fw-pr", iface="wan", name="LIGGA", speed="wan · n/d", cx=1667, w=128),
    dict(fw="fw-pr", iface="a", name="Link 2", speed="wan2 · n/d", cx=1803, w=128),
]
for _l in WAN_LINKS:
    _l["field"] = f"{_l['fw'].upper()} {_l['iface']}"

# SD-WAN: IPsec tunnels named "<remote site>-<local ISP>-<remote ISP>" (BAR = Barueri/SP, VIT = Paraná),
# so every tunnel shows up once at each end. "n" = tunnels per pair on 2026-10-15 (item.get; management
# tunnels VPN-FGFM_* left out); BA-PR exists only on FW-PR. The per-pair totals on the map come from the
# data (query F); n only sets the green threshold of the KPI tile.
TUNNEL_PREFIX = {"SP": "BAR", "RJ": "RJ", "BA": "BAH", "PR": "VIT"}
VPN_PAIRS = [("SP", "RJ", 4), ("SP", "BA", 4), ("SP", "PR", 2), ("RJ", "BA", 2), ("RJ", "PR", 1), ("BA", "PR", 1)]
VPN_ITEM_RE = "/^VPN (BAR|RJ|BAH|VIT)-.*: Tunnel Status$/"
UPS_ALIVE_RE = r"/^UPS: Disponibilidade \(ICMP ping via agente\)$/"
UPS_NODATA_TRIGGER = "/Sem dados SNMP/"

ZONE_BG = "#22D3EE08"
ZONE_BORDER = "#22D3EE38"
CAPTION = "#E6EDF7A6"       # white at 65%: muted on the dark fill, still legible on a red/amber fill
BADGE_TEXT = "#0B0F14"
LAN_WIDTH, WAN_WIDTH, MESH_WIDTH = 3, 4, 6
RAW = "_"                   # prefix of the raw per-element fields (see _map_transforms)
FG, BG, LN = "·fg", "·bg", "·ln"
# Colours of a status. Healthy recedes, failure pops: OK is a deep green fill with a dim border; WARN/CRIT
# are saturated fills (white text) with a neon border and neon lines. The status field itself carries the
# text/icon colours (_FG); ·bg and ·ln are copies (Canvas takes one colour per field). Pairs of sites keep
# a ·fg field: their colour is the up/total ratio, not the count.
_FG = {S.OK: S.OK, S.WARN: S.TEXT, S.CRIT: S.TEXT, S.UNKNOWN: S.MUTED}
_BG = {S.OK: "#0E3326", S.WARN: S.FILL_WARN, S.CRIT: S.FILL_CRIT, S.UNKNOWN: "#252B35"}
_LN = {S.OK: "#22E58A70", S.WARN: S.WARN, S.CRIT: S.CRIT, S.UNKNOWN: "#7B879499"}
SEV_MIN = 3                 # severity tag on the cards from "Média" up (Atenção would tag half the map)


def _pair_field(a, b):
    return f"vpn {a}-{b}"


def _re_escape(text):
    return re.sub(r"([.^$*+?()\[\]{}|\\/])", r"\\\1", text)


def _recolor(obj, table):
    text = json.dumps(obj)
    for neon, other in table.items():
        text = text.replace(f'"{neon}"', f'"{other}"')
    return json.loads(text)


# ----------------------------------------------------------------------------------------- canvas JSON


def _place(x, y, w, h):
    """Virtual px -> "scale" constraint placement (percent of the panel), so the map scales with it."""
    return {"left": round(x / W * 100, 3), "right": round((W - x - w) / W * 100, 3),
            "top": round(y / H * 100, 3), "bottom": round((H - y - h) / H * 100, 3), "rotation": 0}


def _color(fixed, field=None):
    c = {"fixed": fixed}
    if field:
        c["field"] = field
    return c


def _el(type_, name, box, config=None, background=None, border=None, connections=None, link=None):
    """Canvas element. link: one-click data link (Grafana 11.4+ per-link flag), put on every element of a
    card, because the text/icon elements sit on top of the rectangle and would swallow the click."""
    bg = background if isinstance(background, dict) else _color(background or "transparent")
    return {"type": type_, "name": name, "config": config or {},
            "constraint": {"horizontal": "scale", "vertical": "scale"}, "placement": _place(*box),
            "background": {"color": bg},
            "border": border or {"color": _color("transparent"), "width": 0},
            "connections": connections or [], "links": [dict(link, oneClick=True)] if link else []}


def _text(name, box, text, *, color=S.TEXT, size=14, align="left", valign="middle", field=None,
          color_field=None, link=None, background=None):
    """Fixed text, or the formatted value of `field` (metric-value) coloured by `color_field` (default:
    the field itself)."""
    if field:
        cfg = {"text": {"mode": "field", "field": field, "fixed": text},
               "color": _color(color, color_field or field), "size": size, "align": align, "valign": valign}
        return _el("metric-value", name, box, cfg, link=link, background=background)
    cfg = {"text": {"mode": "fixed", "fixed": text}, "color": _color(color), "size": size, "align": align,
           "valign": valign}
    return _el("text", name, box, cfg, link=link, background=background)


def _icon(name, box, icon, field, link=None):
    return _el("icon", name, box, {"path": {"mode": "fixed", "fixed": f"img/icons/unicons/{ICON[icon]}.svg"},
                                   "fill": _color(S.UNKNOWN, field)}, link=link)


def _conn(target, src, dst, field, *, width=LAN_WIDTH, style="solid", animate=False, vertices=None,
          color=S.UNKNOWN):
    """Connection to element `target`. src/dst: anchors in [-1, 1] on each element (x right, y UP: 1 = top
    edge, -1 = bottom). vertices are relative to the segment: x = 0 at the source, 1 at the target."""
    c = {"targetName": target, "source": {"x": src[0], "y": src[1]}, "target": {"x": dst[0], "y": dst[1]},
         "path": "straight", "color": _color(color, field),
         "size": {"fixed": width, "min": 1, "max": 10}, "direction": {"mode": "fixed", "fixed": "none"},
         "lineStyle": {"style": style, "animate": animate}}
    if vertices:
        # sharp corners: with a radius Grafana 13 draws a hook on the first vertex
        c["vertices"] = [{"x": x, "y": y} for x, y in vertices]
    return c


def _card(label, cx, row, w, title, icon, field, *, sub=None, link=None, connections=None, sev=None):
    """Device card: status fill + border, status-coloured icon, name, status value, optional caption
    (IP / speed) and a severity tag on the top-right corner (open problems >= Média of its hosts).
    The rectangle (named `label`) carries the connections; every element carries the link."""
    y, h = ROWS[row], CARD_H
    x = cx - w / 2
    narrow = w < 150
    # narrow cards: smaller icon so a 16 px "Impressoras" / "SEM DADOS" keeps a margin
    pad, icon_px = (8, 24) if narrow else (14, 32)
    tx = x + pad + icon_px + (6 if narrow else 11)
    tw = x + w - tx - 4
    top = y + (7 if sub else 15)        # without a caption the name/status pair is centred
    els = [_el("rectangle", label, (x, y, w, h), {"align": "center", "valign": "middle", "color": _color(S.TEXT)},
               background=_color(_BG[S.UNKNOWN], field + BG),
               border={"color": _color(S.UNKNOWN, field + LN), "width": 2, "radius": 10},
               connections=connections, link=link),
           _icon(f"{label} · ícone", (x + pad, y + (h - icon_px) / 2, icon_px, icon_px), icon, field, link),
           _text(f"{label} · nome", (tx, top, tw, 25), title, size=16 if narrow else 18, link=link),
           _text(f"{label} · estado", (tx, top + 25, tw, 22), "", size=(15 if w < 135 else 16) if narrow else 17,
                 field=field, link=link)]
    if sub:
        els.append(_text(f"{label} · info", (tx, top + 47, tw, 19), sub, color=CAPTION, size=14, link=link))
    if sev:
        els.append(_text(f"{label} · alerta", (x + w - 90, y - 11, 82, 21), "", size=13, align="center",
                         field=sev, color=BADGE_TEXT, color_field="__none__", link=link,
                         background=_color("transparent", sev)))
    return els


def _zone(key):
    x0, x1, bottom, title, sub = ZONES[key]
    tw = len(title) * 14 + 12           # ~14 px per 20 px capital
    return [_el("rectangle", f"zona {key}", (x0 + 2, TOP, x1 - x0 - 4, bottom - TOP), {}, background=ZONE_BG,
                border={"color": _color(ZONE_BORDER), "width": 1, "radius": 14}),
            _text(f"zona {key} · título", (x0 + 18, TOP + 12, tw, 26), title, size=20),
            _text(f"zona {key} · problemas", (x0 + 18 + tw, TOP + 12, x1 - x0 - 36 - tw, 26), "", size=15,
                  align="right", field=f"zona {key}·n", color_field=f"zona {key}·sev"),
            _text(f"zona {key} · sub", (x0 + 18, TOP + 39, x1 - x0 - 36, 20), sub, color=S.MUTED, size=14)]


def _node_by_id():
    return {n["id"]: n for n in NODES}


def _lan_connections():
    """Connections per source node id (drawn from the parent). Colour = the child's status (·ln)."""
    conns = {}
    label = {n["id"]: n["label"] for n in NODES}

    def add(src, *items):
        conns.setdefault(src, []).extend(items)

    def c(dst, src_anchor, dst_anchor, **kw):
        return _conn(label[dst], src_anchor, dst_anchor, dst + LN, **kw)

    for site in ("sp", "rj", "ba"):
        add(f"fw-{site}", c(f"core-{site}", (0, -1), (0, 1), width=WAN_WIDTH))
    add("fw-pr", c("prn-pr", (0, -1), (0, 1)))
    # SP: power feed (dotted), core -> Hyper-V hosts -> VMs on the right, access switches in the middle.
    # The iDRACs are out-of-band controllers, not a network hop: a dotted line to the hosts they manage
    # (if an iDRAC dies the servers are not cut off, and the map must not suggest they are).
    add("ups-sp", c("core-sp", (1, 0), (-1, 0), style="dotted"))
    add("ups-sp", _conn(label["fw-sp"], (0, 1), (-1, 0), "ups-sp" + LN, style="dotted", vertices=[(0, 1)]))
    add("core-sp", c("dist-sp", (0, -1), (0, 1)),
        c("hv-sp", (0.6, -1), (-0.55, 1), vertices=[(0, 0.5), (1, 0.5)]))
    add("hw-sp", _conn(label["hv-sp"], (0.55, -1), (0.55, 1), "hw-sp" + LN, style="dotted"))
    add("hv-sp", c("srv-sp", (0, -1), (0, 1)))
    add("dist-sp", c("prn-sp", (0, -1), (0, 1)), c("ap-sp", (-1, 0), (0, 1), vertices=[(1, 0)]))
    # RJ / BA: core -> server | Wi-Fi | printers as a bus; the server's iDRAC under it, out-of-band (dotted)
    for site in ("rj", "ba"):
        add(f"core-{site}",
            c(f"srv-{site}", (-0.55, -1), (0, 1), vertices=[(0, 0.5), (1, 0.5)]),
            c(f"ap-{site}", (0, -1), (0, 1)),
            c(f"prn-{site}", (0.55, -1), (0, 1), vertices=[(0, 0.5), (1, 0.5)]))
        add(f"srv-{site}", c(f"hw-{site}", (0, -1), (0, 1), style="dotted"))
    return conns


def _host_link(dash, hosts, text):
    """Card drill-down: the category dashboard filtered on the card's hosts, same time range."""
    url = S.dashboard_url(dash) + "".join(f"&var-host={quote(h)}" for h in hosts)
    return S.data_link(text, url)


def _wan_cards():
    nodes = _node_by_id()
    els = []
    for link in WAN_LINKS:
        fw = nodes[link["fw"]]
        anchor = round((link["cx"] - fw["cx"]) / (fw["w"] / 2), 3)
        drill = _host_link("firewalls", fw["hosts"], f"Abrir {fw['title']}")
        els += _card(link["name"], link["cx"], "isp", link["w"], link["name"], "isp", link["field"],
                     sub=link["speed"], link=drill,
                     connections=[_conn(fw["label"], (0, -1), (anchor, 1), link["field"] + LN, width=WAN_WIDTH,
                                        style="dashed", animate=True)])
    return els


def _mesh():
    """SD-WAN box below Paraná: one row per pair of sites, in zone order: [A] - - - [B]  up / total ⚠.
    Site chips take their firewall's colours; the line and the count take the pair's."""
    x0, x1, y0, y1 = 1598, W, 512, 838
    nodes = _node_by_id()
    els = [_el("rectangle", "malha", (x0 + 2, y0, x1 - x0 - 4, y1 - y0), {}, background=ZONE_BG,
               border={"color": _color(ZONE_BORDER), "width": 1, "radius": 14}),
           _text("malha · título", (x0 + 18, y0 + 12, 240, 26), "MALHA SD-WAN", size=20),
           _text("malha · sub", (x0 + 18, y0 + 39, 240, 20), "TÚNEIS IPSEC ATIVOS / TOTAL", color=S.MUTED,
                 size=14)]
    chip_w, chip_h, gap = 46, 30, 50
    for i, (a, b, _n) in enumerate(VPN_PAIRS):
        y = y0 + 76 + i * 41
        f = _pair_field(a, b)
        xa, xb = x0 + 16, x0 + 16 + chip_w + gap
        for site, x, conns in ((a, xa, [_conn(f"malha {b} ({a}-{b})", (1, 0), (-1, 0), f + LN, width=MESH_WIDTH,
                                              style="dashed", animate=True)]),
                               (b, xb, None)):
            fw = nodes[f"fw-{site.lower()}"]
            cfg = {"text": {"mode": "fixed", "fixed": site}, "color": _color(S.TEXT), "size": 16,
                   "align": "center", "valign": "middle"}
            els.append(_el("rectangle", f"malha {site} ({a}-{b})", (x, y, chip_w, chip_h), cfg,
                           background=_color(_BG[S.UNKNOWN], fw["id"] + BG),
                           border={"color": _color(S.UNKNOWN, fw["id"] + LN), "width": 2, "radius": 8},
                           connections=conns, link=_host_link("firewalls", fw["hosts"], f"Abrir {fw['title']}")))
        xc = xb + chip_w + 6
        els += [_text(f"malha {a}-{b} · ativos", (xc, y, 34, chip_h), "", size=20, align="right", field=f,
                      color_field=f + FG),
                _text(f"malha {a}-{b} · total", (xc + 36, y, 42, chip_h), "", size=20, field=f + "·total",
                      color=S.MUTED, color_field="__none__"),
                _text(f"malha {a}-{b} · ponta", (xc + 78, y, 22, chip_h), "", size=18, field=f + "·ponta")]
    return els


def _legend(x, y):
    """Line legend drawn with real connections (between invisible 1 px anchors), so it matches the map."""
    rows = [("Rede local (cor = destino)", dict(width=LAN_WIDTH)),
            ("Internet / SD-WAN", dict(width=WAN_WIDTH, style="dashed", animate=True)),
            ("Alimentação · gerência iDRAC", dict(style="dotted"))]
    els = [_text("legenda · título", (x, y, 260, 20), "LIGAÇÕES", color=S.MUTED, size=14)]
    for i, (label, kw) in enumerate(rows):
        ly = y + 34 + i * 25
        a, b = f"legenda {i} · a", f"legenda {i} · b"
        els += [_el("rectangle", a, (x, ly, 1, 1), {}, connections=[_conn(b, (1, 0), (-1, 0), None,
                                                                         color=S.MUTED, **kw)]),
                _el("rectangle", b, (x + 52, ly, 1, 1), {}),
                _text(f"legenda {i} · texto", (x + 64, ly - 11, 210, 22), label, color=S.MUTED, size=14)]
    return els


def _tags_legend(x, y):
    """What the small marks mean: severity tag on a card, "x / y" counts, one-ended tunnels."""
    sev = S.SEVERITY_COLOR
    return [_text("selos · título", (x, y, 260, 20), "SELOS", color=S.MUTED, size=14),
            _text("selos · média", (x, y + 26, 58, 20), "MÉDIA", color=BADGE_TEXT, size=12, align="center",
                  background=sev[3]),
            _text("selos · alta", (x + 62, y + 26, 46, 20), "ALTA", color=BADGE_TEXT, size=12, align="center",
                  background=sev[4]),
            _text("selos · alerta texto", (x + 116, y + 25, 170, 22), "problema ativo", color=S.MUTED, size=14),
            _text("selos · contagem", (x, y + 51, 290, 22), "4 / 5  membros online / total", color=S.MUTED,
                  size=14),
            _text("selos · ponta", (x, y + 76, 290, 22), "⚠  túnel em uma só ponta", color=S.MUTED, size=14)]


def canvas_root():
    conns = _lan_connections()
    els = []
    for key in ZONES:
        els += _zone(key)
    els += _mesh()
    for n in NODES:
        els += _card(n["label"], n["cx"], n["row"], n["w"], n["title"], n["icon"], n["id"], sub=n.get("sub"),
                     link=_host_link(n["dash"], n["hosts"], f"Abrir {n['label']}"),
                     connections=conns.get(n["id"]), sev=n["id"] + "·sev")
    els += _wan_cards()
    els += _legend(818, 726) + _tags_legend(1294, 726)
    return {"type": "frame", "name": "mapa", "elements": els,
            "background": {"color": {"fixed": "transparent"}}, "border": {"color": {"fixed": "transparent"}},
            "constraint": {"horizontal": "left", "vertical": "top"},
            "placement": {"left": 0, "top": 0, "width": 100, "height": 100, "rotation": 0}}


# ------------------------------------------------------------------------------------------- map data


def _replace_json(pattern, n, h="$1"):
    return S.replace_alias(pattern, json.dumps({"n": RAW + n, "h": h}))


def _pair_end_fns(prefix):
    """replaceAlias per pair and END: "FW-SP|VPN RJ-..." -> {"n": "<prefix>vpn SP-RJ@SP", "h": tunnel}."""
    fns = []
    for a, b, _n in VPN_PAIRS:
        for end, remote in ((a, b), (b, a)):
            pattern = f"/^(FW-{end}\\|VPN {TUNNEL_PREFIX[remote]}-[^:]*): Tunnel Status$/"
            fns.append(_replace_json(pattern, f"{prefix}{_pair_field(a, b)}@{end}"))
    return fns


def _fn_transform_null():
    return S._fn("transformNull", "Transform", [0], [{"name": "number", "type": "float"}], [0])


def _fn_offset(delta):
    return S._fn("offset", "Transform", [delta], [{"name": "delta", "type": "float"}], [100])


def _fn_scale(factor):
    return S._fn("scale", "Transform", [factor], [{"name": "factor", "type": "float"}], [100])


def _map_targets(cfg):
    """Queries A-G (module docstring). Every query covers all sites: the map is global."""
    all_sites = S.site_group_re(cfg, ".*", raw=True)
    all_hosts = [h for n in NODES for h in n["hosts"]]
    host_re = "/^(" + "|".join(_re_escape(h) for h in all_hosts) + ")$/"
    nodes_fns = {n["id"]: _replace_json("/^(" + "|".join(_re_escape(h) for h in n["hosts"]) + ")$/", n["id"])
                 for n in NODES}
    avail = S.target(S.AVAIL_RE, S.group_by("1h", "last"), S.remove_above(1), S.alias("$__zbx_host_name"),
                     *nodes_fns.values(), ref="A", group=all_sites, host=host_re)
    wan = S.target(S.WAN_STATUS_RE, S.group_by("1h", "last"), S.remove_above(1), _fn_transform_null(),
                   S.alias("$__zbx_host_name|$__zbx_item"),
                   S.replace_alias(r"/^(FW-[A-Z]+)\|Interface ([^(]+)\(.*$/", '{"n":"%s$1 $2","h":"$1 $2"}' % RAW),
                   ref="B", group=all_sites, host="/^FW-/")
    vpn = S.target(VPN_ITEM_RE, S.group_by("1h", "last"), _fn_offset(-1),
                   S.alias("$__zbx_host_name|$__zbx_item"), *_pair_end_fns(""), ref="C", group=all_sites,
                   host="/^FW-/")
    # the same tunnels, each one = 1 (scale 0 + offset 1): tunnels configured at each end
    vpn_n = S.target(VPN_ITEM_RE, S.group_by("1h", "last"), _fn_scale(0), _fn_offset(1),
                     S.alias("$__zbx_host_name|$__zbx_item"), *_pair_end_fns("n "), ref="F", group=all_sites,
                     host="/^FW-/")
    # The nobreak has no ICMP/SNMP availability item: its sysUpTime item (1 min polling, named
    # "Disponibilidade (ICMP ping via agente)" by the template, as in ups.py) reporting = 1...
    ups_ids = [n["id"] for n in NODES if n["icon"] == "ups"]
    ups_hosts = [h for n in NODES if n["icon"] == "ups" for h in n["hosts"]]
    ups = S.target(UPS_ALIVE_RE, S.group_by("1h", "last"), _fn_scale(0), _fn_offset(1), S.alias("$__zbx_host_name"),
                   *[nodes_fns[i] for i in ups_ids], ref="D", group=all_sites, host=host_re)
    # ...unless its "Sem dados SNMP há 10 minutos" trigger fires: the last uptime value stays in the window
    nodata = S.problems_target(group=all_sites, host="/^(" + "|".join(_re_escape(h) for h in ups_hosts) + ")$/",
                               min_severity=0, ref="G")
    nodata["trigger"] = {"filter": UPS_NODATA_TRIGGER}
    problems = S.problems_target(group=all_sites, host="/.*/", min_severity=SEV_MIN, ref="E")
    # metrics first: the merged frame of the metrics pipeline is named after its last refId (F)
    return [avail, wan, vpn, ups, vpn_n, problems, nodata]


def _on(refs, transform):
    """Apply a transform only to the frames of some queries (Grafana's per-transformation filter).
    Transforms prefix refIds ("reduce-A-B-..."), so match the end."""
    return dict(transform, filter={"id": "byRefId", "options": f"/[{refs}]$/"})


def _seed(alias, include, reducer="lastNotNull", nulls=None):
    """Row-reduce `include` into a new field. A missing input field gives null ("SEM DADOS") instead of
    Canvas' "Field not found". nulls="null as zero": missing -> 0 (sum, counts)."""
    reduce = {"include": list(include), "reducer": reducer}
    if nulls:
        reduce["nullValueMode"] = nulls
    return S.tf("calculateField", mode="reduceRow", alias=alias, reduce=reduce, replaceFields=False)


def _colour_copies(field):
    return [_seed(field + suffix, [field]) for suffix in (BG, LN)]


def _site_hosts(site):
    return [h for n in NODES if n["site"] == site for h in n["hosts"]]


def _map_transforms():
    best = "Last * (max)"
    zero = "null as zero"
    problems = [
        S.tf("extractFields", source="Problems", format="auto", replace=True, keepTime=False),
        # host = the first host of the trigger expression "max(/HOST/key,#3)=0"
        S.tf("extractFields", source="expression", format="regexp", regExp=r"/^[^/]*\/(?<host>[^/]+)\//",
             replace=False, keepTime=False),
        S.tf("convertFieldType", fields={}, conversions=[{"targetField": "severity", "destinationType": "number"}]),
        S.tf("groupBy", fields={"host": {"operation": "groupby", "aggregations": []},
                                "severity": {"operation": "aggregate", "aggregations": ["max"]}}),
        S.tf("rowsToFields", mappings=[{"fieldName": "host", "handlerKey": "field.name"},
                                       {"fieldName": "severity (max)", "handlerKey": "field.value"}]),
    ]
    nodata = [
        S.tf("extractFields", source="Problems", format="auto", replace=True, keepTime=False),
        S.tf("convertFieldType", fields={}, conversions=[{"targetField": "value", "destinationType": "number"}]),
        S.filter_fields("^value$"),
        S.organize(rename={"value": RAW + "ups-sp·semdados"}),
    ]
    metrics = [
        S.reduce_rows(),
        S.tf("extractFields", source="Field", format="json", replace=False, keepTime=False),
        S.tf("groupBy", fields={"n": {"operation": "groupby", "aggregations": []},
                                "h": {"operation": "groupby", "aggregations": []},
                                "Last *": {"operation": "aggregate", "aggregations": ["max"]}}),
        S.tf("groupBy", fields={"n": {"operation": "groupby", "aggregations": []},
                                best: {"operation": "aggregate", "aggregations": ["sum"]}}),
        S.tf("rowsToFields", mappings=[{"fieldName": "n", "handlerKey": "field.name"},
                                       {"fieldName": f"{best} (sum)", "handlerKey": "field.value"}]),
    ]
    seeds, copies = [], []
    fws = {}
    for n in NODES:
        i = n["id"]
        if n["icon"] == "ups":
            seeds += [_seed(i + "·v", [RAW + i]),
                      _seed(i + "·semdados", [RAW + i + "·semdados"], "sum", zero),
                      S.calc_binary(i + "·v", "-", i + "·semdados", i)]
        else:
            seeds.append(_seed(i, [RAW + i]))
        if n["icon"] == "fw":
            fws[n["site"]] = i + "·gate"
            seeds.append(_seed(i + "·gate", [RAW + i], "sum", zero))     # 0/1, never null
        copies += _colour_copies(i)
        seeds.append(_seed(i + "·sev", n["hosts"], "max"))
    for link in WAN_LINKS:
        f = link["field"]
        seeds += [_seed(f + "·v", [RAW + f]), S.calc_binary(f + "·v", "*", link["fw"] + "·gate", f)]
        copies += _colour_copies(f)
    for a, b, _n in VPN_PAIRS:
        f = _pair_field(a, b)
        for end in (a, b):
            seeds += [_seed(f"{f}@{end}", [f"{RAW}{f}@{end}"], "sum", zero),
                      _seed(f"{f}@{end}·n", [f"{RAW}n {f}@{end}"], "sum", zero),
                      S.calc_binary(f"{f}@{end}", "*", fws[end], f"{f}@{end}·ok")]
        seeds += [_seed(f, [f"{f}@{a}·ok", f"{f}@{b}·ok"], "min"),
                  _seed(f + "·total", [f"{f}@{a}·n", f"{f}@{b}·n"], "max"),
                  S.calc_binary(f"{f}@{a}·n", "-", f"{f}@{b}·n", f + "·ponta")]
        copies += [S.calc_binary(f, "/", f + "·total", f + FG), S.calc_binary(f, "/", f + "·total", f + LN)]
    for site in ZONES:
        seeds += [_seed(f"zona {site}·n", _site_hosts(site), "count", "connected"),
                  _seed(f"zona {site}·sev", _site_hosts(site), "max")]
    # Every calculateField clones the frame and matches names over all of its fields, so ~200 of them on
    # a ~350-field frame cost ~1 s per refresh. Dropping the raw "_", helper and per-host problem fields
    # (one filter) before the colour copies keeps the frame at ~100 fields for the second half.
    keep = ([n["id"] for n in NODES] + [n["id"] + "·sev" for n in NODES] + [link["field"] for link in WAN_LINKS]
            + [_pair_field(a, b) + s for a, b, _n in VPN_PAIRS for s in ("", "·total", "·ponta")]
            + [f"zona {site}{s}" for site in ZONES for s in ("·n", "·sev")])
    return [*[_on("E", t) for t in problems], *[_on("G", t) for t in nodata], *[_on("A-DF", t) for t in metrics],
            S.tf("concatenate", frameNameMode="drop"),
            *seeds,
            S.filter_fields("^(" + "|".join(re.escape(f) for f in keep) + ")$"),
            *copies]


def _status_props(total, count=False):
    """One member: ONLINE / OFFLINE (count=True: "1 / 1"). Several: "up / total", green all, amber some,
    red none."""
    if total == 1 and not count:
        return {"mappings": S.value_map({"0": ("OFFLINE", S.CRIT), "1": ("ONLINE", S.OK)}) + S.no_data_map(),
                "thresholds": {"mode": "absolute", "steps": S.steps(S.CRIT, (1, S.OK))}}
    # Grafana puts a space before a unit suffix: "4 / 5"
    return {"unit": f"suffix:/ {total}", "mappings": S.no_data_map(),
            "thresholds": {"mode": "absolute", "steps": S.steps(S.CRIT, (1, S.WARN), (total, S.OK))}}


def _status_overrides(field, props):
    return [S.col_props(field, **_recolor(props, _FG)), S.col_props(field + BG, **_recolor(props, _BG)),
            S.col_props(field + LN, **_recolor(props, _LN))]


def _sev_props():
    """Severity tag: max severity of the card's open problems, "" (transparent) when none."""
    names = {p: S.SEVERITY_NAME[p].upper() for p in range(SEV_MIN, 6)}
    return {"mappings": S.value_map({str(p): (names[p], S.SEVERITY_COLOR[p]) for p in names})
            + [{"type": "range", "options": {"from": -1, "to": SEV_MIN - 0.5,
                                             "result": {"text": " ", "color": "transparent", "index": 20}}}]
            + S.no_data_map(" ", "transparent"),
            "thresholds": {"mode": "absolute", "steps": S.steps("transparent")}}


def _zone_props():
    """Zone header: number of the site's hosts with an open problem >= Média ("3 com problema"; short, so it
    fits the Paraná zone), coloured by the worst."""
    count = {"mappings": [{"type": "value", "options": {
                              "0": {"text": "sem problemas", "index": 0}}}]
             + S.no_data_map("sem problemas", S.MUTED),
             "unit": "suffix: com problema", "decimals": 0}
    sev = {"mappings": S.value_map({str(p): (str(p), S.SEVERITY_COLOR[p]) for p in range(SEV_MIN, 6)})
           + S.no_data_map(" ", S.MUTED),
           "thresholds": {"mode": "absolute", "steps": S.steps(S.MUTED)}}
    return count, sev


def _pair_props():
    ratio = {"mappings": S.no_data_map(), "thresholds": {"mode": "absolute",
                                                         "steps": S.steps(S.CRIT, (0.01, S.WARN), (1, S.OK))}}
    edge = {"mappings": [{"type": "range", "options": {"from": -99, "to": -0.5, "result": {"text": "⚠", "index": 0}}},
                         {"type": "range", "options": {"from": 0.5, "to": 99, "result": {"text": "⚠", "index": 1}}},
                         {"type": "value", "options": {"0": {"text": " ", "index": 2}}}] + S.no_data_map(" "),
            "thresholds": {"mode": "absolute", "steps": S.steps(S.WARN)}}
    return ratio, edge


def map_panel(cfg):
    overrides = []
    for n in NODES:
        overrides += _status_overrides(n["id"], _status_props(len(n["hosts"])))
        overrides.append(S.col_props(n["id"] + "·sev", **_sev_props()))
    for link in WAN_LINKS:
        overrides += _status_overrides(link["field"], _status_props(1))
    ratio, edge = _pair_props()
    for a, b, _n in VPN_PAIRS:
        f = _pair_field(a, b)
        overrides += [S.col_props(f + FG, **_recolor(ratio, _FG)), S.col_props(f + LN, **_recolor(ratio, _LN)),
                      S.col_props(f + "·total", unit="prefix:/ "), S.col_props(f + "·ponta", **edge)]
    count, sev = _zone_props()
    for site in ZONES:
        overrides += [S.col_props(f"zona {site}·n", **count), S.col_props(f"zona {site}·sev", **sev)]
    p = S.panel("canvas", "", _map_targets(cfg), id=MAP_ID, decimals=0, steps=S.steps(S.UNKNOWN),
                overrides=overrides, transformations=_map_transforms(), time_from=S.HEALTH_WINDOW, mdp=20,
                options={"inlineEditing": False, "showAdvancedTypes": True, "panZoom": False, "infinitePan": False,
                         # one click opens the card's dashboard; no hover tooltip on a TV wall
                         "tooltip": {"mode": "none", "disableForOneClick": True},
                         "root": canvas_root()},
                description="Mapa da rede (todas as filiais), estado atual no Zabbix. Cards: preenchimento "
                            "verde escuro = todos online, âmbar = parte, vermelho = nenhum, cinza = sem dados; "
                            "selo MÉDIA/ALTA/DESASTRE = problema ativo nos hosts do card; '4 / 5' = online / "
                            "total. Links de internet e túneis valem só com o FortiGate online. Malha SD-WAN: "
                            "túneis ativos / configurados por par (⚠ = túnel configurado só numa ponta). "
                            "Pontilhado: alimentação do nobreak e gerência fora de banda (iDRAC -> servidor). "
                            "Clique num card para abrir o painel da categoria. Feito só para TV 1920x1080; no "
                            "desktop use a Visão Geral ou os painéis por categoria.")
    return p


# --------------------------------------------------------------------------------------------- KPI strip


def _caption(p):
    p["options"].update(textMode="value_and_name", wideLayout=False)
    p["options"]["text"]["titleSize"] = 14
    return p


def _health_kpi(cfg):
    """Hosts online in every site, every host once by its best check (style health pipeline)."""
    group = S.site_group_re(cfg, ".*", raw=True)
    p = S.kpi("HOSTS ONLINE", S.health_targets([{"name": "Rede", "group": group}]), id=HEALTH_ID,
              transformations=[*S.health_transforms(), S.filter_fields("^(Online|Total)$"), S.as_text("Total")],
              steps=S.steps(S.OK), decimals=0, value_size=56, time_from=S.HEALTH_WINDOW, mdp=20, values=True,
              overrides=[S.col_props("Online", displayName="${__data.fields.Total} monitorados")],
              description="Hosts das filiais alcançáveis agora (ping, SNMP ou agente).")
    return _caption(p)


def _offline_kpi():
    # same caption line as its neighbours, so the big numbers of the strip share one baseline
    p = S.kpi("HOSTS OFFLINE", [S.dashboard_target(HEALTH_ID, with_transforms=False)],
              datasource=dict(S.DASHBOARD_DS),
              transformations=[*S.health_transforms(), S.filter_fields("^(Offline|Total)$"), S.as_text("Total")],
              steps=S.COUNT_BAD, decimals=0, value_size=56, time_from=None, mdp=None, values=True,
              overrides=[S.col_props("Offline", displayName="de ${__data.fields.Total} hosts")],
              description="Hosts das filiais sem nenhuma verificação de disponibilidade OK.")
    return _caption(p)


def _offline_sum_kpi(title, fields, total_fields, expected, noun, description):
    """Members DOWN = total - members up, summed over map fields (the canvas panel's transformed data, no
    extra query). Counts what is offline, like HOSTS OFFLINE and prototype B, so a quiet strip is all zeros
    and any red number is a fault. The total comes from the data when total_fields is given, else it is
    `expected`."""
    calcs = [S.tf("calculateField", mode="reduceRow", reduce={"include": list(fields), "reducer": "sum"},
                  alias="Ativos", replaceFields=False)]
    if total_fields:
        calcs.append(S.tf("calculateField", mode="reduceRow",
                          reduce={"include": list(total_fields), "reducer": "sum"}, alias="Total",
                          replaceFields=False))
        calcs.append(S.calc_binary("Total", "-", "Ativos", "Offline"))
        keep = [S.filter_fields("^(Offline|Total)$"), S.as_text("Total")]
        name = f"de ${{__data.fields.Total}} {noun}"
    else:
        calcs.append(S.calc_binary(expected, "-", "Ativos", "Offline"))
        keep = [S.filter_fields("^Offline$")]
        name = f"de {expected} {noun}"
    # caption through an override: a calculated field ignores the default displayName (style notes)
    p = S.kpi(title, [S.dashboard_target(MAP_ID, with_transforms=True)], datasource=dict(S.DASHBOARD_DS),
              transformations=[*calcs, *keep], decimals=0, value_size=56, time_from=None, values=True,
              mdp=None, steps=S.COUNT_BAD, no_value="—", mappings=S.no_data_map("—"),
              overrides=[S.col_props("Offline", displayName=name)], description=description)
    return _caption(p)


def kpi_strip(cfg):
    all_sites = S.site_group_re(cfg, ".*", raw=True)
    problems = S.stat("PROBLEMAS ATIVOS POR SEVERIDADE", [S.triggers_target(group=all_sites, min_severity=2)],
                      transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
                      text_mode="value_and_name", color_mode="value", value_size=46, title_size=13,
                      steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None,
                      description="Triggers em problema agora nos hosts das filiais, por severidade.")
    internet = _offline_sum_kpi(
        "LINKS OFFLINE", [link["field"] for link in WAN_LINKS], None, len(WAN_LINKS), "links WAN",
        "Links de internet (interfaces WAN dos FortiGate) fora do ar agora; um link só conta como ativo com o "
        "seu FortiGate online.")
    pairs = [_pair_field(a, b) for a, b, _n in VPN_PAIRS]
    tunnels = _offline_sum_kpi(
        "TÚNEIS OFFLINE", pairs, [f + "·total" for f in pairs], sum(n for _a, _b, n in VPN_PAIRS),
        "túneis entre filiais",
        "Túneis IPsec entre filiais fora do ar (configurados - ativos nas duas pontas). Conta TÚNEIS (pares de "
        "pontas), não pontas: cada túnel aparece nos dois FortiGate e vale uma vez, por isso o total é menor que "
        "o do protótipo B e o do painel Firewalls, que contam pontas. Sem os túneis de gerência FortiManager.")
    banner = S.banner("TOPOLOGIA", "NOC · protótipo A · Canvas", links=S.tv_links())
    return [banner, _health_kpi(cfg), _offline_kpi(), internet, tunnels, problems]


def build(cfg, datasource_uid="zabbix"):
    banner, online, offline, internet, tunnels, problems = kpi_strip(cfg)
    panels = S.grid(
        (4, [(banner, 5), (online, 3), (offline, 3), (internet, 3), (tunnels, 3), (problems, 7)]),
        (MAP_HEIGHT, [(map_panel(cfg), 24)]),
    )
    return S.dashboard(KEY, "Topologia (Canvas)", panels, datasource_uid=datasource_uid, tv=True,
                       time_from="now-6h", range_cap="2d",
                       description="Protótipo A da topologia (painel Canvas nativo) para TV 1920x1080: "
                                   "provedores, firewalls, core e equipamentos de todas as filiais, com o estado "
                                   "real do Zabbix. Feito só para TV 1920x1080 (texto em px fixos): no desktop "
                                   "use a Visão Geral ou os painéis por categoria.")


if __name__ == "__main__":      # python -m zabbix_autodiscovery.grafana_v2.topology_canvas config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
