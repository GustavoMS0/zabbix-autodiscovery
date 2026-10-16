"""Topologia, protótipo B: Business Charts (Apache ECharts) on the NOC TV wall (1920x1080 kiosk, no scroll).

Layout (TV_HEIGHT = 27 grid units):
  y0  h4   banner (+ map legend) | hosts online | hosts offline | links WAN offline | túneis VPN offline |
           problemas por severidade
  y4  h23  topology map (ECharts) | problemas ativos, Média or worse (list)

URL parameters (kiosk shows no variable bar): ?var-site=BA shows one site, with host names instead of
status squares; ?var-simular=FW-RJ,SD-WAN,BAR-INT-MEGA paints those hosts / WAN links / tunnels as down on
the map only (to rehearse what a failure looks like on the TV; marked "SIMULAÇÃO" on the map).

The map is data driven, nothing about the hosts is hardcoded:
- one column per site (Filiais/*), biggest site first; rows are tiers: Internet backbone, WAN links,
  firewall, switches, then the leaf tiers (servers, iDRAC, UPS, APs, printers) hanging off a bus. Every
  tier has one fixed row across all sites, so the wall reads in rows (an empty slot stays blank);
- which host belongs to which site/tier comes from hidden query variables (one host.get per site and per
  category group, run once on load), read in the panel code with replaceVariables('${var:json}');
- host state comes from the availability items (ICMP ping / SNMP / Zabbix agent, the verified v1 logic of
  topology.py), WAN links from the interface operational status, the SD-WAN overlay from the FortiGate
  "VPN <tunnel>: Tunnel Status" items (arcs between the sites, coloured by their tunnels);
- the ring colour is reachability; active problems (frontend-only problems query P) add a severity badge
  with the count, so a reachable host with a link-down trigger does not look healthy next to the feed;
- colours follow the rule of the whole v2 set: amber = part of a group down, red = all of it down; the
  ripple only marks a down firewall / switch / WAN link (site impact), a down leaf tier is a still red ring.

Every other panel reuses the map's data through the "-- Dashboard --" datasource (filterByRefId), so the
whole dashboard costs four kinds of Zabbix history queries per refresh: availability (A..D, one per site),
WAN (W), VPN (V) and nobreak uptime (U), plus the problems/trigger queries that run in the browser.
"""
import json
import re

from . import style as S
from .topology_canvas import UPS_ALIVE_RE  # nobreak liveness item, verified for Prototype A

KEY = "topology-echarts"
MAP_ID = 20                 # source of every other panel (dashboard_target)
WAN_REF, VPN_REF, PROBLEMS_REF, UPS_REF = "W", "V", "P", "U"
# Tunnel names start with the peer site ("RJ-AMER-INT" on FW-SP goes to RJ). FortiGate phase-1 names as
# found in Zabbix (2026-10); a prefix missing here still counts in the firewall badge, it only gets no arc.
VPN_PEERS = {"BAR": "Matriz", "RJ": "RJ", "BAH": "BA", "VIT": "PR"}
# Short site code used wherever space is tight (SD-WAN arcs, WAN tiles): the firewalls are named FW-<code>.
SITE_CODES = {"Matriz": "SP"}
# FortiManager management tunnels (VPN-FGFM_MGMT*) are not site links: MGMT2 is down on every firewall.
VPN_RE = r"/^VPN (?!VPN-FGFM).*: Tunnel Status$/"
# Map window: the iDRAC availability keeps only changes with a 6h heartbeat (see topology.py), so 7h;
# groupBy(1h, last) keeps ~8 points per item.
MAP_WINDOW = "7h"

# Category key (style.categories) -> role on the map and icon. Order = order of the leaf rows.
TIERS = [
    ("firewalls", "fw", "firewall"),
    ("switches", "sw", "switch"),
    ("servers", "leaf", "server"),
    ("server-hardware", "leaf", "chip"),
    ("ups", "leaf", "battery"),
    ("access-points", "leaf", "wifi"),
    ("printers", "leaf", "printer"),
]

# Line icons (24x24, stroke): drawn in the node's status colour inside the status ring.
ICONS = {
    "firewall": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9.3h18M3 14.7h18M9 4v5.3M15 4v5.3'
                'M12 9.3v5.4M7 14.7V20M17 14.7V20"/>',
    "switch": '<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11v2M9.5 11v2M13 11v2M16.5 11v2"/>',
    "server": '<rect x="3" y="3.5" width="18" height="7.5" rx="2"/><rect x="3" y="13" width="18" height="7.5" rx="2"/>'
              '<path d="M7 7.25h.01M7 16.75h.01M11 7.25h6M11 16.75h6"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5"/>'
            '<path d="M9.5 2.5V6M14.5 2.5V6M9.5 18v3.5M14.5 18v3.5M2.5 9.5H6M2.5 14.5H6M18 9.5h3.5M18 14.5h3.5"/>',
    "battery": '<rect x="2" y="7" width="17" height="10" rx="2"/><path d="M22 10.5v3M11.5 9l-2.5 3.2h3.4L10 15.2"/>',
    "wifi": '<path d="M2.5 9.2a14 14 0 0 1 19 0M5.6 12.6a9.5 9.5 0 0 1 12.8 0M8.8 16a4.8 4.8 0 0 1 6.4 0'
            'M12 19.6h.01"/>',
    "printer": '<path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>',
    "host": '<circle cx="12" cy="12" r="5"/>',
}
SUBTEXT = "#C9D1DC"         # host names / link names on the map: brighter than MUTED, read from 3 m


def _var_name(prefix, key):
    return f"{prefix}_{re.sub(r'[^A-Za-z0-9]', '_', key)}"


def _hosts_var(name, group, label):
    """Hidden multi-value host variable without allValue: '${name:json}' then expands to the host list."""
    return {"name": name, "label": label, "type": "query", "datasource": dict(S.DSV),
            "query": {"queryType": "host", "group": group, "host": "/.*/", "application": "", "itemTag": "",
                      "item": ""},
            "multi": True, "includeAll": True, "refresh": 1, "sort": 1, "hide": 2,
            "current": {"text": "All", "value": "$__all"}}


def _site_only(cfg, key):
    """Group regex of one site that only matches while $site is All or this site: the per-site queries
    then follow the Filial variable without an extra query (lookahead, supported by the plugin's regex)."""
    escaped = re.escape(key).replace("/", "\\/")
    return S.site_group_re(cfg, f"(?=$site$){escaped}", raw=True)


def _map_config(cfg, sites, cats):
    """Static part of the map handed to the panel code as JSON. Links carry no ${__url_time_range}: the
    panel code navigates itself (locationService) and appends the interpolated range and kiosk flag."""
    by_key = {c["key"]: c for c in cats}
    tiers = []
    for key, role, icon in TIERS:
        c = by_key.get(key)
        if c:
            tiers.append({"key": key, "title": c["title"], "role": role, "icon": icon,
                          "var": _var_name("tier", key), "link": S.dashboard_url(key, keep_time=False)})
    return {
        "sites": [{"key": s["key"], "label": s["label"], "code": SITE_CODES.get(s["key"], s["key"]),
                   "var": _var_name("site", s["key"]), "ref": S._ref(i),
                   "link": S.dashboard_url(KEY, keep_time=False, site=s["key"])} for i, s in enumerate(sites)],
        "tiers": tiers,
        "peers": VPN_PEERS,
        "wanRef": WAN_REF, "vpnRef": VPN_REF, "problemsRef": PROBLEMS_REF,
        "selfLink": S.dashboard_url(KEY, keep_time=False),
        "icons": ICONS,
        "sev": {str(p): [n, c] for p, n, c in S.SEVERITIES},
        "c": {"ok": S.OK, "warn": S.WARN, "crit": S.CRIT, "unk": S.UNKNOWN, "accent": S.ACCENT,
              "text": S.TEXT, "muted": S.MUTED, "sub": SUBTEXT},
    }


# Panel code (volkovlabs-echarts-panel 7: getOption body, gets `context`). Plain ES2017, no template
# literals so Grafana-style ${...} never appears by accident.
_JS = r"""
const C = __CONFIG__;
const K = C.c;
const series = (context.panel && context.panel.data && context.panel.data.series) || [];
const chart = context.panel && context.panel.chart;
const W = (chart && chart.getWidth && chart.getWidth()) || 1250;
const H = (chart && chart.getHeight && chart.getHeight()) || 850;
const rv = (s) => { try { return context.grafana.replaceVariables(s); } catch (e) { return s; } };
// '${var:json}' of a multi-value variable is a JSON array (a single value is a JSON string)
const listVar = (name) => {
  const raw = rv('${' + name + ':json}');
  try { const v = JSON.parse(raw); return Array.isArray(v) ? v : (v ? [String(v)] : []); } catch (e) { return []; }
};
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
const esc = (s) => String(s).replace(/[&<>"]/g, (ch) => ESC[ch]);
const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const plain = (s) => String(s).replace(/[{}|]/g, '');
const alpha = (hex, a) => {
  const n = parseInt(hex.slice(1), 16);
  return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
};
// One rule for every v2 dashboard: amber = part of a group is down ('degraded') or a reachable host has a
// failing check ('partial'); red only when every member is down. The down hosts of a degraded group are
// still named in red under the node, so the amber ring says "partial", the red line says "which one".
const COL = { up: K.ok, partial: K.warn, degraded: K.warn, down: K.crit, unknown: K.unk };
const TXT = { up: 'ONLINE', partial: 'PARCIAL', degraded: 'PARCIAL', down: 'OFFLINE', unknown: 'SEM DADOS' };
const RICH_STATE = { up: 'ok', partial: 'warn', degraded: 'warn', down: 'crit', unknown: 'unk' };
const BG = '#111217';
// Edges between tiers are inferred (no link is measured there), so they stay cyan unless the child tier
// is entirely down (red dashed) or has no data (grey dashed). WAN drops are measured: same rule.
const edgeBad = (st) => st === 'down' || st === 'unknown';

// ---- data ------------------------------------------------------------------------------------------
const valuesOf = (field) => {
  const raw = field && field.values ? field.values : [];
  return typeof raw.toArray === 'function' ? raw.toArray() : raw;
};
const lastValue = (field) => {
  const vals = valuesOf(field);
  for (let i = vals.length - 1; i >= 0; i--) {
    if (vals[i] !== null && vals[i] !== undefined && !Number.isNaN(vals[i])) return Number(vals[i]);
  }
  return null;
};
// checks per host: ping / snmp / agent, each true (up), false (down) or null (unknown)
const hostChecks = {};
const wan = {};
const vpn = {};
// a known value beats null, down beats up (same as topology.py)
const mergeOk = (prev, ok) => (prev === undefined || prev === null || ok === false ? ok : prev);
// Fields are classified by their item labels, not by refId: the plugin may hand over one merged "wide"
// frame (see the Python side), where every query's field sits in a single frame.
const AVAIL_KEY = /^(icmpping|zabbix\[host,\w+,available\])$/;
const VPN_ITEM = /^VPN .*: Tunnel Status$/;
// The nobreak has no ping/SNMP availability item: its uptime item (polled every minute) reporting
// recently = reachable; its "Sem dados SNMP" trigger (problems query P) = down. Same signal as Canvas.
const UPS_ITEM = /^UPS: Disponibilidade/;
const UPS_FRESH_MS = 45 * 60000;              // 15m buckets + polling delay
const fields = [].concat(...series.map((fr) => {
  const time = (fr.fields || []).find((x) => x.type === 'time');
  return (fr.fields || []).filter((x) => x.type === 'number').map((x) => ({ f: x, refId: fr.refId, time: time }));
}));
// time of the last non-null value of a field (its frame's time field; also right in a merged wide frame)
// A time field that does not line up with the values (a merged frame) cannot date them: a value in the
// window then counts as reporting (the "Sem dados SNMP" trigger still turns the nobreak red).
const lastTime = (field, timeField) => {
  const vals = valuesOf(field), times = valuesOf(timeField);
  for (let i = vals.length - 1; i >= 0; i--) {
    if (vals[i] !== null && vals[i] !== undefined && !Number.isNaN(vals[i])) {
      return times.length === vals.length ? (Number(times[i]) || null) : Date.now();
    }
  }
  return null;
};
for (const it of fields) {
  const f = it.f;
  if (!f.labels || !f.labels.host) continue;
  const host = f.labels.host;
  const key = f.labels.item_key || '';
  const item = f.labels.item || key;
  const last = lastValue(f);
  if (key === 'ups.snmp.uptime' || UPS_ITEM.test(item)) {
    const t = it.time ? lastTime(f, it.time) : null;
    const c = hostChecks[host] = hostChecks[host] || {};
    c.ups = mergeOk(c.ups, t !== null && Date.now() - t < UPS_FRESH_MS ? true : null);
  } else if (AVAIL_KEY.test(key)) {
    // icmpping 1 up / 0 down; zabbix[host,*,available] 1 up / 0 down / 2 unknown (removed upstream)
    const ok = last === null ? null : (last === 1 ? true : (last === 0 ? false : null));
    const kind = key === 'icmpping' ? 'ping' : (key.indexOf(',agent,') >= 0 ? 'agent' : 'snmp');
    const c = hostChecks[host] = hostChecks[host] || {};
    c[kind] = mergeOk(c[kind], ok);
  } else if (VPN_ITEM.test(item)) {
    // FortiGate tunnel status 2 = up, 1 = down
    const name = item.replace(/^VPN\s+/, '').replace(/: Tunnel Status$/, '');
    const peer = C.peers[name.split('-')[0]] || null;
    const state = last === null ? 'unknown' : (last === 2 ? 'up' : 'down');
    (vpn[host] = vpn[host] || []).push({ name: name, peer: peer, state: state });
  } else if (it.refId === C.wanRef || /operational status/i.test(item)) {
    // ifOperStatus 1 = up; the link name is the text in parentheses ("wan1(Link Primário 50Mbps)")
    const m = /\(([^)]*)\)/.exec(item);
    const raw = (m ? m[1] : item.replace(/^Interface\s+/i, '').replace(/:.*$/, '')).replace(/Mbps/i, 'M');
    // an alias that is just the port ("a(wan2)" on FW-PR) reads as "WAN 2", as on the Canvas prototype
    const name = raw.replace(/^wan\s*(\d*)$/i, (x, n) => 'WAN' + (n ? ' ' + n : ''));
    (wan[host] = wan[host] || []).push({ name: name, state: last === null ? 'unknown' : (last === 1 ? 'up' : 'down') });
  }
}
// active problems (frontend query P: one "other" field holding the plugin's problem objects) per host
const probs = {};
series.forEach((fr) => (fr.fields || []).forEach((f) => {
  const isProblems = f.name === 'Problems' || (f.config && f.config.custom && f.config.custom.type === 'problems');
  if (!isProblems) return;
  valuesOf(f).forEach((p) => {
    if (!p || p.value === '0') return;
    const sev = Number(p.severity !== undefined ? p.severity : p.priority) || 0;
    const hosts = (p.hosts && p.hosts.length ? p.hosts.map((h) => h.name || h.host) : [p.host]).filter(Boolean);
    hosts.forEach((h) => (probs[h] = probs[h] || []).push({ sev: sev, name: p.description || p.name || '',
                                                           ts: Number(p.timestamp) || 0 }));
  });
}));
Object.keys(probs).forEach((h) => {
  const c = hostChecks[h];
  if (c && c.ups !== undefined && probs[h].some((p) => /Sem dados SNMP/i.test(p.name))) c.ups = false;
});
const probsOf = (members) => [].concat(...members.map((m) => (probs[m.name] || [])
  .map((p) => Object.assign({ host: m.name }, p)))).sort((a, b) => b.sev - a.sev || b.ts - a.ts);
const sevColor = (p) => (C.sev[String(p)] || C.sev['0'])[1];
const sevName = (p) => (C.sev[String(p)] || C.sev['0'])[0];

// ?var-simular=FW-RJ,SD-WAN,BAR-INT-MEGA: shows those hosts / WAN links / tunnels as down on this map only
// (rehearse what a failure looks like on the TV; the KPI tiles keep the real data)
const simRaw = rv('$simular');
const sim = simRaw && simRaw !== '$simular' ? simRaw.split(',').map((x) => x.trim()).filter(Boolean) : [];
sim.forEach((name) => {
  if (hostChecks[name]) hostChecks[name] = { ping: false };
  Object.keys(wan).forEach((h) => wan[h].forEach((l) => { if (l.name === name) l.state = 'down'; }));
  Object.keys(vpn).forEach((h) => vpn[h].forEach((t) => { if (t.name === name) t.state = 'down'; }));
});
// host state: reachability (ping, else SNMP) decides up/down; a down agent on a reachable host is partial
const CHECK_NAMES = { ping: 'ping', snmp: 'SNMP', agent: 'agente', ups: 'SNMP (uptime)' };
const isKnown = (v) => v !== undefined && v !== null;
const hostState = (h) => {
  const c = hostChecks[h] || {};
  const hasPing = isKnown(c.ping);
  const reach = hasPing ? c.ping : (isKnown(c.snmp) ? c.snmp : (isKnown(c.ups) ? c.ups : null));
  const agentDown = c.agent === false || (hasPing && c.snmp === false);
  let state = 'unknown';
  if (reach === false) state = 'down';
  else if (reach === true) state = agentDown ? 'partial' : 'up';
  else if (c.agent === true) state = 'up';
  else if (c.agent === false) state = 'down';
  const checks = Object.keys(CHECK_NAMES).filter((k) => c[k] !== undefined)
    .map((k) => ({ name: CHECK_NAMES[k], state: c[k] === null ? 'unknown' : (c[k] ? 'up' : 'down') }));
  return { name: h, state: state, checks: checks };
};
// all known up = up, all known down = down, some down = degraded (alarm), else partial; nothing known = unknown
const groupState = (members) => {
  const known = members.filter((m) => m.state !== 'unknown');
  const up = known.filter((m) => m.state === 'up').length;
  const down = known.filter((m) => m.state === 'down').length;
  const state = !known.length ? 'unknown' : (up === known.length ? 'up' : (down === known.length ? 'down'
    : (down ? 'degraded' : 'partial')));
  return { state: state, up: up, down: down, known: known.length, total: members.length };
};

// ---- membership (hidden variables) --------------------------------------------------------------------
const tierOf = {};
C.tiers.forEach((t) => listVar(t.var).forEach((h) => { if (!tierOf[h]) tierOf[h] = t.key; }));
const site = rv('$site');
const allSites = !site || site === '.*' || site === '$site' || site === '$__all';
const sites = C.sites.filter((s) => allSites || s.key === site).map((s) => {
  const hosts = listVar(s.var);
  const tiers = C.tiers.map((t) => {
    // The plugin's host query also lists disabled hosts (no items, no frames): keep only hosts with
    // availability data, unless no host of the tier has any (e.g. a UPS without a ping item: grey node).
    const inTier = hosts.filter((h) => tierOf[h] === t.key);
    const withData = inTier.filter((h) => hostChecks[h]);
    const members = (withData.length ? withData : inTier).map(hostState);
    return Object.assign({}, t, { members: members }, groupState(members));
  }).filter((t) => t.members.length);
  const links = [].concat(...hosts.map((h) => (wan[h] || []).map((w) => Object.assign({ host: h }, w))));
  const tunnels = [].concat(...hosts.map((h) => (vpn[h] || []).map((v) => Object.assign({ host: h }, v))));
  const all = [].concat(...tiers.map((t) => t.members));
  return Object.assign({}, s, { tiers: tiers, links: links, tunnels: tunnels, hosts: all }, groupState(all));
}).filter((s) => s.hosts.length).sort((a, b) => b.hosts.length - a.hosts.length);

// ---- layout (pixels of the panel; the cartesian axes map 1:1, so resizing scales everything) ----------
const single = sites.length === 1;
// single site: more room, bigger text (a short chain like Paraná's firewall + printers, bigger still)
let FS = single ? (sites[0].tiers.length <= 3 ? 1.55 : 1.3) : 1;   // may shrink below (narrow panel)
const PAD = 8, GAP = 10;
const RS = single ? FS * 0.93 : 1;
const R = { fw: Math.round(48 * RS), sw: Math.round(44 * RS), leaf: Math.round(40 * RS) };
// Text width estimate, em per char measured on the wall's screenshots: header caps + digits ~0.6, tier
// titles ~0.58 ("Impressoras 2/2" 137px at 17px), host / link names ~0.62, bold caps (down host names,
// "BRN001BA9F4C5A5" at 14px ~9.5px/char) 0.68. Sizes the columns, truncates labels from their real x.
const EM = { head: 0.56, title: 0.58, name: 0.62, caps: 0.68 };
const tw = (chars, size, em) => chars * size * FS * em;
const charsIn = (width, size, em) => Math.max(6, Math.floor(width / (size * FS * em)));
const countLen = (g) => (g.known === 0 ? 9 : (String(g.up) + '/' + String(g.known)).length);
// Only a down core node (firewall, switch) gets the ripple; its label moves out past the ripple.
const ripple = (level, st) => st === 'down' && level === 'core';
const labelDist = (level, st, r) => (ripple(level, st) ? 12 + r * 0.42 : 12);
const CHAIN_X = 38, LEAF_DX = 42;                // chain x and leaf x (beside the bus) from the card's left
const roleLevel = (role) => (role === 'leaf' ? 'leaf' : 'core');
const labelOffset = (t) => CHAIN_X + (t.role === 'leaf' ? LEAF_DX : 0) + R[t.role] / 2 +
  labelDist(roleLevel(t.role), groupState(t.members).state, R[t.role]);
// Width a column needs for its longest label (tier "Impressoras 2/2", its single host name, the first
// down host, the WAN link names), so a small site never cuts the one alarm on the wall.
const need = (s) => {
  let n = 24 + tw(s.code.length + 2 + countLen(s), 22, EM.head);   // header (site code when narrow)
  s.tiers.forEach((t) => {
    const one = t.members.length === 1;
    const title = t.role === 'fw' && one ? t.members[0].name : t.title;
    let w = tw(title.length + 1 + countLen(groupState(t.members)), 17, EM.title);
    if (one) w = Math.max(w, tw(t.members[0].name.length, 14, EM.name));
    const down = t.members.filter((m) => m.state === 'down');
    if (down.length && !one) w = Math.max(w, tw(Math.min(20, down[0].name.length) + 2, 14, EM.caps));
    n = Math.max(n, labelOffset(t) + w + 14);
  });
  s.links.forEach((l) => { n = Math.max(n, CHAIN_X + 20 + tw(l.name.length + 2, 14, EM.name) + 14); });
  return n;
};
// base share by size, then every column gets at least what it needs (the others shrink in proportion)
const weight = (s) => Math.min(1.3, 0.55 + 0.11 * s.tiers.length);
const usable = W - 2 * PAD - GAP * Math.max(0, sites.length - 1);
const fixed = {};
sites.forEach((s) => { s.need = single ? usable : need(s); });
// A narrow panel (a 1440px desktop) cannot give every column what it needs: shrink the map text instead
// of cutting labels at the card edge (needs are mostly text, so they scale with FS).
const needSum = sites.reduce((a, s) => a + s.need, 0);
if (!single && needSum > usable) {
  FS = Math.max(0.78, usable / needSum);
  sites.forEach((s) => { s.need = need(s); });
}
for (let pass = 0; pass < sites.length; pass++) {
  const free = sites.filter((s) => !fixed[s.key]);
  const room = usable - sites.reduce((a, s) => a + (fixed[s.key] || 0), 0);
  const ws = free.reduce((a, s) => a + weight(s), 0) || 1;
  let changed = false;
  free.forEach((s) => { if (room * weight(s) / ws < s.need) { fixed[s.key] = s.need; changed = true; } });
  if (!changed) {
    free.forEach((s) => { s.w = room * weight(s) / ws; });
    break;
  }
}
sites.forEach((s) => { if (fixed[s.key]) s.w = fixed[s.key]; });
const total = sites.reduce((a, s) => a + (s.w || 0), 0);
let cursor = PAD;
sites.forEach((s) => {
  s.w = (s.w || 0) * Math.min(1, usable / (total || 1));   // needs larger than the panel: labels truncate
  s.x0 = cursor; cursor += s.w + GAP;
  // single site with a short chain (e.g. Paraná: firewall + printers): centre it in the card
  s.cx = s.x0 + (!single ? CHAIN_X : (s.tiers.length <= 2 ? Math.round(s.w / 2 - 170) : Math.round(s.w * 0.06) + 40));
  // header: full name when it fits the column, else the site code ("RJ 16/16")
  const head = s.label.toUpperCase();
  s.head = 22 + tw(head.length + 2 + countLen(s), 22, EM.head) <= s.w ? head : s.code;
});
// The SD-WAN arcs need headroom over the backbone; without arcs (one site shown) the bone moves up.
const hasArcs = !single && sites.some((s) => s.tunnels.some((t) => t.peer && t.peer !== s.key &&
  sites.some((x) => x.key === t.peer)));
const Y = { head: single ? 34 : 30, bone: hasArcs ? 134 : 84 };
const maxLinks = Math.max(0, ...sites.map((s) => s.links.length));
Y.fw = Y.bone + Math.max(106, 50 + maxLinks * 21 * FS + 40);
Y.sw = Y.fw + (single ? 124 : 100);
// Leaf tiers: one global row per tier key (present in any shown site), so the rows line up across the
// wall; a site without a tier leaves its slot blank, a site without a switch runs its bus through it.
const leafKeys = C.tiers.filter((t) => t.role === 'leaf' && sites.some((s) => s.tiers.some((x) => x.key === t.key)))
  .map((t) => t.key);
const hasSw = sites.some((s) => s.tiers.some((t) => t.role === 'sw'));
const LEAF_TOP = (single && !hasSw ? Y.fw : Y.sw) + (single ? 124 : 90);
// single site: two leaf columns (room for host chips) whenever there is more than one leaf tier
const leafCols = single && leafKeys.length > 1 ? 2 : 1;
const perCol = Math.ceil(leafKeys.length / leafCols);
const LEAF_STEP = Math.min(single ? 210 : 104, (H - (single ? 90 : 58) - LEAF_TOP) / Math.max(1, perCol - 1));

const icon = (name, color) => 'image://data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="' + color +
  '" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' + (C.icons[name] || C.icons.host) + '</svg>');

// ---- rich text (TV: nothing important below 14px) --------------------------------------------------
const fz = (n) => Math.round(n * FS * 10) / 10;
const rich = {
  t: { color: K.text, fontSize: fz(17), fontWeight: 700, lineHeight: fz(23) },
  s: { color: K.sub, fontSize: fz(14), lineHeight: fz(19) },
  w: { color: K.sub, fontSize: fz(14), lineHeight: fz(20) },
  h: { color: K.text, fontSize: fz(22), fontWeight: 800, letterSpacing: 0.5 },
  arc: { color: K.text, fontSize: 14, fontWeight: 700 },
  sm: { color: K.muted, fontSize: fz(12), fontWeight: 700, letterSpacing: 1 },
  g: { width: 4, height: 12 },
  gc: { width: 6, height: 10 },
};
Object.keys(RICH_STATE).forEach((st) => {
  const r = RICH_STATE[st];
  rich[r] = { color: COL[st], fontSize: fz(17), fontWeight: 800, lineHeight: fz(23) };
  rich['h' + r] = { color: COL[st], fontSize: fz(22), fontWeight: 800 };
  rich['d' + r] = { color: COL[st], fontSize: fz(14), fontWeight: 800, lineHeight: fz(20) };
  rich['p' + r] = { backgroundColor: COL[st], width: 12, height: 12, borderRadius: 2 };
  rich['c' + r] = { color: COL[st], fontSize: fz(13.5), fontWeight: 700, backgroundColor: alpha(COL[st], 0.12),
                    borderColor: alpha(COL[st], 0.5), borderWidth: 1, borderRadius: 4, padding: [3, 7],
                    lineHeight: fz(28) };
});
// count of a group: "6/7" in the state colour; a tier without any availability item says so in words
const count = (g, small) => (g.known === 0 ? '{' + (small ? 'dunk' : 'unk') + '|sem dados}'
  : '{' + (small ? 'd' : '') + RICH_STATE[g.state] + '|' + g.up + '/' + g.known + '}');
// one square per host, wrapped to the label width
const pips = (members, width) => {
  const per = Math.max(4, Math.floor(width / 16));
  return members.map((m, i) => (i && i % per === 0 ? '\n' : (i ? '{g| }' : '')) +
    '{p' + RICH_STATE[m.state] + '| }').join('');
};
// single-site view: host names as chips, wrapped to the label width
const chips = (members, width) => {
  let line = 0, out = '';
  members.forEach((m) => {
    const label = short(m.name, 26);
    const w = label.length * 8.4 * FS + 22;
    if (line && line + w > width) { out += '\n'; line = 0; } else if (line) { out += '{gc| }'; }
    out += '{c' + RICH_STATE[m.state] + '|' + plain(label) + '}';
    line += w + 6;
  });
  return out;
};
// red line naming the down members (all-sites view: the squares alone do not say which host it is; a
// single-member tier already shows its host name)
const downLine = (members, width) => {
  const down = members.filter((m) => m.state === 'down').map((m) => m.name);
  if (!down.length || single || members.length < 2) return '';
  const names = down.slice(0, 2).join(', ') + (down.length > 2 ? ' +' + (down.length - 2) : '');
  return '\n{dcrit|▼ ' + plain(short(names, charsIn(width, 14, EM.caps) - 2)) + '}';
};

// ---- tooltips -------------------------------------------------------------------------------------------
const dot = (color) => '<span style="color:' + color + ';">●</span>';
const tipBox = (title, st, body) => '<div style="min-width:240px;max-width:460px;">' +
  '<div style="font-weight:700;font-size:15px;color:' + COL[st] + ';margin-bottom:4px;">' + esc(title) + '</div>' +
  body + '</div>';
const probRows = (list, max) => list.slice(0, max).map((p) => '<div style="white-space:nowrap;overflow:hidden;' +
  'text-overflow:ellipsis;max-width:440px;">' + dot(sevColor(p.sev)) + ' <b style="color:' + sevColor(p.sev) + ';">' +
  sevName(p.sev) + '</b> ' + esc(p.host) + ' · ' + esc(p.name) + '</div>').join('') +
  (list.length > max ? '<div style="color:' + K.muted + ';">+' + (list.length - max) + ' problemas</div>' : '');
const memberRows = (members) => members.map((m) => {
  const checks = (m.checks || []).map((c) => '<span style="color:' + COL[c.state] + ';">' + c.name + '</span>')
    .join(' · ');
  const n = (probs[m.name] || []).length;
  return '<div style="white-space:nowrap;">' + dot(COL[m.state]) + ' ' + esc(m.name) +
    (checks ? ' <span style="color:' + K.muted + ';font-size:11px;">(' + checks + ')</span>' : '') +
    (n ? ' <span style="color:' + sevColor(Math.max(...probs[m.name].map((p) => p.sev))) + ';font-size:11px;">· ' +
      n + (n > 1 ? ' problemas' : ' problema') + '</span>' : '') + '</div>';
}).join('') || '<div style="color:' + K.muted + ';">Sem item de disponibilidade no Zabbix</div>';
const stateLine = (g) => (g.known === 0 ? '<b style="color:' + K.unk + ';">SEM DADOS</b> · sem item de ' +
  'disponibilidade no Zabbix' : '<b style="color:' + COL[g.state] + ';">' + TXT[g.state] + '</b> · ' + g.up + '/' +
  g.known + ' online' + (g.down ? ' · <b style="color:' + K.crit + ';">' + g.down + ' offline</b>' : ''));
const nodeTip = (title, s, g, members, hint) => {
  const pl = probsOf(members);
  return tipBox(title, g.state,
    '<div style="color:' + K.muted + ';font-size:12px;margin-bottom:6px;">' + esc(s.label) + ' · ' + stateLine(g) +
    (pl.length ? ' · ' + pl.length + (pl.length > 1 ? ' problemas' : ' problema') : '') + '</div>' +
    '<div style="font-size:12px;line-height:1.55;border-top:1px solid #2a3140;padding-top:5px;">' +
    memberRows(members) + '</div>' +
    (pl.length ? '<div style="font-size:12px;line-height:1.55;border-top:1px solid #2a3140;margin-top:6px;' +
      'padding-top:5px;">' + probRows(pl, 6) + '</div>' : '') +
    (hint ? '<div style="color:' + K.muted + ';font-size:11px;margin-top:6px;">' + hint + '</div>' : ''));
};

// Single site: leaf rows packed by their label height (host chips wrap to several lines) with the spare
// height spread between them, starting under the switch label (its chips wrap too). All sites: fixed
// global rows (LEAF_TOP + slot * LEAF_STEP), so the wall reads in rows.
const leafY = {};
let BUS_Y = LEAF_TOP - 46;                       // where a second leaf column's bus branches off
if (single && sites.length) {
  const s = sites[0];
  const right = s.x0 + s.w - 10;
  const lines = (t, width) => (t.members.length === 1 ? 1 : chips(t.members, width).split('\n').length);
  const labelH = (t, width) => fz(23) + lines(t, width) * fz(28);
  const sw = s.tiers.find((t) => t.role === 'sw');
  const chainH = sw ? labelH(sw, right - (s.cx + R.sw / 2 + 12)) : fz(46);
  const top = (sw ? Y.sw : Y.fw) + Math.max(sw ? R.sw : R.fw, chainH) / 2 + 40;
  BUS_Y = top - 20;
  const colW = (s.x0 + s.w - s.cx) / leafCols;
  for (let col = 0; col < leafCols; col++) {
    const keys = leafKeys.slice(col * perCol, (col + 1) * perCol);
    const lx = s.cx + col * colW + LEAF_DX;
    const width = (col + 1 < leafCols ? s.cx + (col + 1) * colW - 16 : right) - (lx + R.leaf / 2 + 12);
    const hs = keys.map((k) => Math.max(R.leaf + 16, labelH(s.tiers.find((t) => t.key === k), width)));
    const spare = Math.max(0, H - 30 - top - hs.reduce((a, b) => a + b, 0));
    const gap = Math.min(keys.length <= 1 ? 240 : 110, spare / Math.max(1, keys.length));   // lone row: further down
    let y = top + gap / 2;
    keys.forEach((k, i) => { leafY[k] = y + hs[i] / 2; y += hs[i] + gap; });
  }
}

// ---- build ----------------------------------------------------------------------------------------------
const discs = [], alarms = [], icons = [], badges = [], texts = [], edgesOk = [], edgesBad = [];
const arcsOk = [], arcsBad = [], areas = [];
// A status ring with its icon. Alarm weight follows what the device is (NOC wall: motion = site impact):
// a down firewall / switch gets the red ripple and glow; a down leaf tier (printers, APs, UPS...) a solid
// red ring without motion; a degraded tier an amber ring (its down hosts named in red below the label).
const PLATE = 'rgba(17,18,23,0.88)';
const node = (x, y, r, st, iconName, label, tip, link, members, level) => {
  const loud = ripple(level, st);
  const down = st === 'down';
  const fill = alpha(COL[st], down ? 0.3 : (st === 'up' ? 0.14 : 0.2));
  const d = {
    value: [x, y], symbolSize: r, tip: tip, link: link,
    itemStyle: { color: fill, borderColor: COL[st], borderWidth: down ? 3.5 : 2.5,
                 shadowBlur: loud ? 26 : (down ? 16 : 12),
                 shadowColor: alpha(COL[st], loud ? 0.95 : (down ? 0.8 : 0.55)) },
    // ripple: it grows past the ring, so the label moves out (labelDist); down labels get a dark plate
    label: { show: !!label, position: 'right', distance: labelDist(level, st, r), formatter: label, rich: rich,
             backgroundColor: down ? PLATE : 'transparent', padding: down ? [2, 5] : 0, borderRadius: 4 },
  };
  (loud ? alarms : discs).push(d);
  icons.push({ value: [x, y], symbol: icon(iconName, COL[st]), symbolSize: Math.round(r * 0.52) });
  // problem badge (top-right of the ring): worst severity colour, number of active problems
  const pl = members ? probsOf(members) : [];
  if (pl.length) {
    badges.push({ value: [x + r * 0.38, y - r * 0.38], symbolSize: 22, tip: tip, link: link,
      itemStyle: { color: sevColor(pl[0].sev), borderColor: BG, borderWidth: 2 },
      label: { show: true, position: 'inside', formatter: String(pl.length), color: '#0b0e13', fontSize: 12,
               fontWeight: 800 } });
  }
};
const edge = (coords, st, tip, width) => {
  const bad = edgeBad(st);
  (bad ? edgesBad : edgesOk).push({
    coords: coords, tip: tip,
    lineStyle: { color: bad ? COL[st] : alpha(K.accent, 0.5), width: width || 2,
                 type: bad ? 'dashed' : 'solid', shadowBlur: st === 'down' ? 10 : 0, shadowColor: COL[st] },
  });
};

sites.forEach((s) => {
  const card = { color: 'rgba(148,163,184,0.035)', borderColor: alpha(K.accent, 0.14), borderWidth: 1 };
  areas.push([{ coord: [s.x0, 4], itemStyle: card }, { coord: [s.x0 + s.w, H - 4] }]);
  const right = s.x0 + s.w - 10;               // labels end here
  // site header
  const sp = probsOf(s.hosts);
  texts.push({ value: [s.x0 + 14, Y.head], link: single ? C.selfLink : s.link,
    tip: tipBox(s.label, s.state, '<div style="font-size:12px;color:' + K.muted + ';">' + stateLine(s) +
      (s.total > s.known ? ' · ' + (s.total - s.known) + ' sem dados' : '') +
      (sp.length ? ' · ' + sp.length + ' problemas' : '') + '<br>' +
      (single ? 'Clique para ver todas as filiais' : 'Clique para abrir só esta filial') + '</div>'),
    label: { show: true, position: 'right', distance: 0, rich: rich,
             formatter: '{h|' + plain(s.head) + '}  {h' + RICH_STATE[s.state] + '|' + s.up + '/' +
               (s.known || s.total) + '}' } });

  const fw = s.tiers.find((t) => t.role === 'fw');
  const sw = s.tiers.find((t) => t.role === 'sw');

  // WAN links: drops from the backbone into the firewall, one per link, named beside them
  const lk = s.links;
  const target = fw ? Y.fw : (sw ? Y.sw : Y.fw);
  lk.forEach((l, i) => {
    const dx = (i - (lk.length - 1) / 2) * 9;
    edge([[s.cx + dx, Y.bone], [s.cx + dx, target - 38], [s.cx, target - R.fw / 2]], l.state,
      tipBox('Link WAN · ' + l.name, l.state, '<div style="font-size:12px;color:' + K.muted + ';">' + esc(l.host) +
        ' · <b style="color:' + COL[l.state] + ';">' + TXT[l.state] + '</b></div>'), 2.2);
    // a measured outage (link down): ripple where the link leaves the backbone
    if (l.state === 'down') {
      alarms.push({ value: [s.cx + dx, Y.bone], symbolSize: 12, tip: null,
                    itemStyle: { color: K.crit, shadowBlur: 14, shadowColor: K.crit } });
    }
    texts.push({ value: [s.cx + 20, Y.bone + 24 + i * 21 * FS], tip: null,
      label: { show: true, position: 'right', distance: 0, rich: rich,
               formatter: '{d' + RICH_STATE[l.state] + '|●} {' + (l.state === 'up' ? 'w' : 'd' + RICH_STATE[l.state]) +
                 '|' + plain(short(l.name, charsIn(right - s.cx - 40, 14, l.state === 'up' ? EM.name : EM.caps))) +
                 '}' } });
  });

  let parent = null;
  // label line 1 "{Tier} N/M" for every node; line 2 the host name (one member) or squares / chips
  const second = (t, width) => (t.members.length === 1 ? '{s|' + plain(short(t.members[0].name,
    charsIn(width, 14, EM.name))) + '}' : (single ? chips(t.members, width) : pips(t.members, width)));
  if (fw) {
    const g = groupState(fw.members);
    const tun = groupState(s.tunnels);
    const one = fw.members.length === 1;
    const name = one ? fw.members[0].name : fw.title;
    const width = right - (s.cx + R.fw / 2 + labelDist('core', g.state, R.fw));
    // single site: the arcs to the other sites are not drawn, so list the tunnels per peer site
    const peers = {};
    s.tunnels.forEach((t) => { if (t.peer && t.peer !== s.key) (peers[t.peer] = peers[t.peer] || []).push(t); });
    const peerTxt = !single ? '' : Object.keys(peers).map((k) => {
      const ps = C.sites.find((x) => x.key === k);
      return '   {s|' + (ps ? ps.code : k) + '} ' + count(groupState(peers[k]), true);
    }).join('');
    const vpnTxt = s.tunnels.length ? '{s|VPN }' + count(tun, true) + peerTxt : '{s|' + fw.title + '}';
    node(s.cx, Y.fw, R.fw, g.state, fw.icon,
      '{t|' + plain(short(name, 16)) + '}' + (one ? '' : ' ' + count(g)) + '\n' + vpnTxt +
        downLine(fw.members, width),
      nodeTip(name, s, g, fw.members, s.tunnels.length ? 'Túneis VPN: ' + tun.up + '/' + tun.total + ' online' : ''),
      { url: fw.link, hosts: fw.members }, fw.members, 'core');
    parent = { y: Y.fw, r: R.fw };
  }
  if (sw) {
    const g = groupState(sw.members);
    const width = right - (s.cx + R.sw / 2 + labelDist('core', g.state, R.sw));
    if (parent) edge([[s.cx, parent.y + parent.r / 2], [s.cx, Y.sw - R.sw / 2]], g.state, null, 2.4);
    node(s.cx, Y.sw, R.sw, g.state, sw.icon,
      '{t|' + sw.title + '} ' + count(g) + '\n' + second(sw, width) + downLine(sw.members, width),
      nodeTip(sw.title, s, g, sw.members), { url: sw.link, hosts: sw.members }, sw.members, 'core');
    parent = { y: Y.sw, r: R.sw };
  }
  if (!parent) parent = { y: Y.bone, r: 0 };
  // leaf tiers on a bus under the last chain node (fixed global rows; two columns in the single view)
  const colW = (s.x0 + s.w - s.cx) / leafCols;
  const order = s.tiers.filter((t) => t.role === 'leaf').map((t) => {
    const slot = leafKeys.indexOf(t.key);
    const col = Math.floor(slot / perCol);
    const busX = s.cx + col * colW;
    const y = leafY[t.key] !== undefined ? leafY[t.key] : LEAF_TOP + (slot % perCol) * LEAF_STEP;
    return { t: t, g: groupState(t.members), y: y, busX: busX, lx: busX + LEAF_DX,
             right: col + 1 < leafCols ? busX + colW - 16 : right };
  });
  const busY = BUS_Y;
  // The bus is shared: it stays healthy down to the last healthy tier; only the stub into a failing tier
  // (and the bus below the last healthy one) takes the failing colour, so one bad tier does not paint the
  // whole trunk red.
  const buses = {};
  order.forEach((o) => (buses[o.busX] = buses[o.busX] || []).push(o));
  Object.keys(buses).forEach((k) => {
    const list = buses[k].sort((a, b) => a.y - b.y);
    const bx = list[0].busX;
    const head = bx === s.cx ? [[s.cx, parent.y + parent.r / 2]]
      : [[s.cx, parent.y + parent.r / 2], [s.cx, busY], [bx, busY]];
    let lastUp = -1;
    list.forEach((o, i) => { if (!edgeBad(o.g.state)) lastUp = i; });
    if (lastUp >= 0) edge(head.concat([[bx, list[lastUp].y]]), 'up', null, 2);
    list.forEach((o, i) => {
      const stub = [[bx, o.y], [o.lx - R.leaf / 2, o.y]];
      edge(i > lastUp ? (i ? [[bx, list[i - 1].y]] : head).concat(stub) : stub, o.g.state, null, 2);
    });
  });
  order.forEach((o) => {
    const t = o.t, g = o.g;
    const width = o.right - (o.lx + R.leaf / 2 + labelDist('leaf', g.state, R.leaf));
    node(o.lx, o.y, R.leaf, g.state, t.icon,
      '{t|' + t.title + '} ' + count(g) + '\n' + second(t, width) + downLine(t.members, width),
      nodeTip(t.title, s, g, t.members, 'Clique para abrir o dashboard ' + esc(t.title) + ' desta filial'),
      { url: t.link, hosts: t.members }, t.members, 'leaf');
  });
});

// SD-WAN overlay: one arc per pair of sites over the backbone, coloured by all tunnels between them.
// Healthy pairs are quiet hairlines; broken ones are drawn on top, labelled at their apex.
const bySite = {};
sites.forEach((s) => { bySite[s.key] = s; });
const pairs = {};
sites.forEach((s) => s.tunnels.forEach((t) => {
  if (!t.peer || t.peer === s.key || !bySite[t.peer]) return;
  const k = [s.key, t.peer].sort().join('|');
  (pairs[k] = pairs[k] || []).push(Object.assign({ from: s.key }, t));
}));
const pairList = Object.keys(pairs).map((k) => {
  const ends = k.split('|').map((x) => bySite[x]).sort((a, b) => a.cx - b.cx);
  return { k: k, ends: ends, list: pairs[k], span: ends[1].cx - ends[0].cx, mid: (ends[0].cx + ends[1].cx) / 2 };
}).sort((a, b) => a.span - b.span || a.mid - b.mid);
// one height per pair (by span rank): no two arcs share a curve
pairList.forEach((p, rank) => {
  const g = groupState(p.list);
  const h = 18 + rank * 11;
  const sides = Array.from(new Set(p.list.map((t) => t.from)));
  // a tunnel configured on one firewall only: name the direction ("PR → BA") and say so in the tooltip
  const oneSided = sides.length === 1 ? bySite[sides[0]] : null;
  const other = oneSided ? p.ends.find((e) => e.key !== oneSided.key) : null;
  const pairName = oneSided ? oneSided.code + ' → ' + other.code : p.ends[0].code + ' ↔ ' + p.ends[1].code;
  const rows = p.list.map((t) => '<div style="white-space:nowrap;">' + dot(COL[t.state]) + ' ' + esc(t.host) + ' · ' +
    esc(t.name) + '</div>').join('');
  const bad = g.state !== 'up';
  const tip = tipBox('SD-WAN · ' + p.ends[0].label + ' ↔ ' + p.ends[1].label, g.state,
      '<div style="font-size:12px;color:' + K.muted + ';margin-bottom:4px;">' + g.up + '/' + g.total +
      ' túneis online' + (oneSided ? ' · túnel configurado só no ' + esc(p.list[0].host) : '') + '</div>' +
      '<div style="font-size:12px;line-height:1.5;">' + rows + '</div>');
  (bad ? arcsBad : arcsOk).push({ coords: [[p.ends[0].cx, Y.bone], [p.ends[1].cx, Y.bone]], tip: tip,
    lineStyle: { color: bad ? COL[g.state] : alpha(K.accent, 0.3), width: bad ? 2.5 : 1.2,
                 type: bad ? [7, 5] : 'solid', curveness: 2 * h / p.span, opacity: 1,
                 shadowBlur: bad ? 8 : 0, shadowColor: COL[g.state] } });
  if (bad) {
    texts.push({ value: [p.mid, Y.bone - h], tip: tip,
      label: { show: true, position: 'inside', rich: rich, backgroundColor: PLATE,
               borderColor: COL[g.state], borderWidth: 1, borderRadius: 4, padding: [3, 7],
               formatter: '{arc|' + pairName + '}  {d' + RICH_STATE[g.state] + '|' + g.up + '/' + g.total + '}' } });
  }
});

const empty = !sites.length;
const xAxis = { type: 'value', min: 0, max: W, show: false };
const yAxis = { type: 'value', min: 0, max: H, show: false, inverse: true };
const lineBase = { type: 'lines', coordinateSystem: 'cartesian2d', polyline: true, z: 2 };
const option = {
  backgroundColor: 'transparent',
  animation: false,
  grid: { left: 0, right: 0, top: 0, bottom: 0 },
  xAxis: xAxis, yAxis: yAxis,
  tooltip: {
    trigger: 'item', confine: true, backgroundColor: 'rgba(13,17,23,0.96)', borderColor: '#2a3140', borderWidth: 1,
    padding: [10, 12], textStyle: { color: K.text, fontSize: 12 },
    extraCssText: 'box-shadow:0 8px 24px rgba(0,0,0,.5);',
    formatter: (p) => (p.data && p.data.tip) || '',
  },
  // the line legend lives in the banner (dashboard header), not on the map
  graphic: empty ? [{ type: 'text', left: 'center', top: 'middle',
    style: { text: 'SEM DADOS DE TOPOLOGIA', fill: K.muted, fontSize: 18, fontWeight: 700 } }] : [
    { type: 'text', right: 16, top: Y.bone - 24, silent: true,
      style: { text: 'INTERNET · SD-WAN', fill: alpha(K.accent, 0.85), fontSize: 13, fontWeight: 700,
               letterSpacing: 2 } },
  ].concat(sim.length ? [{ type: 'text', left: 16, bottom: 10, silent: true, style: {
    text: 'SIMULAÇÃO: ' + sim.join(', '), fill: K.warn, fontSize: 14, fontWeight: 800, letterSpacing: 1,
    backgroundColor: 'rgba(17,18,23,0.9)', padding: [4, 8] } }] : []),
  series: [
    { type: 'scatter', name: 'areas', data: [], silent: true, markArea: { silent: true, data: areas } },
    // backbone: the Internet / SD-WAN bus all sites hang from. Static: on the wall, motion means alarm.
    Object.assign({}, lineBase, { name: 'bone', silent: true, z: 1,
      data: empty ? [] : [{ coords: [[PAD + 6, Y.bone], [W - PAD - 6, Y.bone]] }],
      lineStyle: { color: alpha(K.accent, 0.9), width: 3, shadowBlur: 12, shadowColor: alpha(K.accent, 0.6) } }),
    { type: 'lines', coordinateSystem: 'cartesian2d', name: 'vpn', z: 2, data: arcsOk },
    { type: 'lines', coordinateSystem: 'cartesian2d', name: 'vpnBad', z: 3, data: arcsBad },
    Object.assign({}, lineBase, { name: 'ok', data: edgesOk }),
    Object.assign({}, lineBase, { name: 'bad', z: 3, data: edgesBad }),
    { type: 'scatter', name: 'nodes', z: 5, data: discs, symbol: 'circle', cursor: 'pointer' },
    { type: 'effectScatter', name: 'alarms', z: 5, data: alarms, symbol: 'circle', cursor: 'pointer',
      rippleEffect: { brushType: 'stroke', scale: 1.7, period: 2.6, color: K.crit } },
    { type: 'scatter', name: 'icons', z: 6, data: icons, silent: true },
    { type: 'scatter', name: 'badges', z: 7, data: badges, symbol: 'circle', cursor: 'pointer' },
    // label-only points: a transparent colour, not opacity 0 (labels inherit the item opacity)
    { type: 'scatter', name: 'text', z: 8, data: texts, symbolSize: 1, itemStyle: { color: 'transparent' },
      cursor: 'pointer' },
  ],
};

// drill-down: a node opens its category dashboard filtered to that node's hosts, a site header filters
// the map to that site. The range macro is interpolated here and kiosk mode is carried over.
const go = (link) => {
  let url = typeof link === 'string' ? link : link.url + (link.url.indexOf('?') < 0 ? '?' : '&') +
    link.hosts.map((m) => 'var-host=' + encodeURIComponent(m.name)).join('&');
  const add = (q) => { if (q) url += (url.indexOf('?') < 0 ? '?' : '&') + q; };
  const range = rv('${__url_time_range}');
  add(range && range.indexOf('__url_time_range') < 0 ? range : '');
  try { if (/[?&]kiosk(=|&|$)/.test(window.location.search)) add('kiosk'); } catch (e) { /* no window */ }
  context.grafana.locationService.push(url);
};
if (chart && chart.off) {
  chart.off('click');
  chart.on('click', (p) => {
    const link = p && p.data && p.data.link;
    if (link && context.grafana.locationService) go(link);
  });
}
return option;
"""


def _echarts_code(cfg, sites, cats):
    return _JS.strip().replace("__CONFIG__", json.dumps(_map_config(cfg, sites, cats), ensure_ascii=False))


def _map_panel(cfg, sites, cats):
    # A..D: availability per site (health pipeline: the KPI tiles reuse it), W: WAN links, V: VPN tunnels,
    # U: nobreak uptime (its liveness; it has no ping/SNMP availability item), P: active problems
    # (frontend-only: severity badges on the nodes and the nobreak's "Sem dados SNMP" trigger).
    dims = [{"name": s["label"], "group": _site_only(cfg, s["key"])} for s in sites]
    site_re = S.site_group_re(cfg, "$site")
    # The plugin frontend merges every frame into ONE "wide" frame (refId of a single query, the W/V
    # frames' refIds lost) whenever all frames share their first two timestamps, which hourly buckets
    # do on most refreshes. Different bucket sizes for W (30m) and V (20m) keep the frames apart, so the
    # Dashboard-datasource panels can still filterByRefId (U: 15m, for the same reason). The panel code
    # copes with a wide frame anyway.
    targets = [*S.health_targets(dims),
               S.target(S.WAN_STATUS_RE, S.group_by("30m", "last"), ref=WAN_REF, group=site_re, host="/.*/"),
               S.target(VPN_RE, S.group_by("20m", "last"), ref=VPN_REF, group=site_re, host="/.*/"),
               S.target(UPS_ALIVE_RE, S.group_by("15m", "last"), ref=UPS_REF, group=site_re, host="/.*/"),
               S.problems_target(group=site_re, host="/.*/", min_severity=2, ref=PROBLEMS_REF)]
    return S.panel("volkovlabs-echarts-panel", "", targets, id=MAP_ID, time_from=MAP_WINDOW, mdp=30,
                   transparent=True,
                   options={"renderer": "canvas", "editorMode": "code", "map": "none",
                            "editor": {"height": 600, "format": "auto"},
                            "getOption": _echarts_code(cfg, sites, cats)})


def _banner():
    """S.banner layout plus the map's own legend. Line 1: the status words of the map (amber = PARCIAL,
    as in its tooltips); lines 2-3: the line samples, the problem badge and the one-sided tunnel arrow,
    in the same caps as the chips."""
    def chip(color, label):
        return (f'<span style="display:inline-block;margin-right:9px;color:{S.MUTED};font-size:11.5px;">'
                f'<span style="color:{color};font-size:13px;">&#9679;</span> {label}</span>')

    def line(style, label):
        return (f'<span style="display:inline-block;margin-right:9px;color:{S.MUTED};font-size:11px;">'
                f'<span style="display:inline-block;width:16px;vertical-align:middle;border-top:{style};"></span>'
                f' {label}</span>')
    badge = (f'<span style="display:inline-block;margin-right:9px;color:{S.MUTED};font-size:11px;">'
             f'<span style="display:inline-block;width:14px;height:14px;line-height:14px;border-radius:50%;'
             f'background:{S.SEVERITY_COLOR[3]};color:#0b0e13;font-size:9.5px;font-weight:800;text-align:center;">'
             f'2</span> PROBLEMAS</span>')
    arrow = (f'<span style="display:inline-block;color:{S.MUTED};font-size:11px;">'
             f'<b style="color:{S.TEXT};">A &#8594; B</b> TÚNEL SÓ NO FIREWALL A</span>')
    html = (f'<div style="border-left:4px solid {S.ACCENT};padding:2px 0 2px 14px;">'
            f'<div style="color:{S.MUTED};font-size:12px;letter-spacing:3px;">NOC · PROTÓTIPO B · ECHARTS</div>'
            f'<div style="color:{S.TEXT};font-size:26px;font-weight:700;letter-spacing:1px;line-height:1.2;">'
            f'TOPOLOGIA</div>'
            f'<div style="margin-top:3px;line-height:1.45;white-space:nowrap;">'
            + chip(S.OK, "ONLINE") + chip(S.WARN, "PARCIAL") + chip(S.CRIT, "OFFLINE") + chip(S.UNKNOWN, "S/ DADOS")
            + '<br>' + line(f"2px solid {S.ACCENT}", "ENLACE") + line(f"2px dashed {S.CRIT}", "FORA DO AR")
            + badge + '<br>' + arrow + '</div></div>')
    # Ways to the other v2 dashboards: panel links (an icon in the banner's header on hover). Not dashboard
    # links: Grafana 13 kiosk still draws them as a control bar that pushes the grid off the 1080px screen.
    p = S.text(html, mode="html")
    p["links"] = S.tv_links()            # panel links (not S.panel(links=), which sets field data links)
    return p


def _from_map(refs):
    return dict(datasource=dict(S.DASHBOARD_DS), targets=[S.dashboard_target(MAP_ID, with_transforms=False)],
                time_from=None, mdp=None,
                transformations=[S.tf("filterByRefId", include="|".join(refs))])


def _kpi(title, transforms, *, refs, field, steps, caption=None, description=None):
    """Big number from the map's data. caption: name template under the number (fields of the same row,
    e.g. "de ${__data.fields.Total} links"; Total then stays as text, not drawn)."""
    src = _from_map(refs)
    keep = S.filter_fields(f"^({field}|Total)$" if caption else f"^{field}$")
    src["transformations"] += [*transforms, keep, *([S.as_text("Total")] if caption else [])]
    # no data yet / map query failed: a grey dash, not a blank tile (a blank wall reads as "all clear")
    p = S.kpi(title, src.pop("targets"), calcs=("lastNotNull",), steps=steps, decimals=0, value_size=60,
              values=bool(caption), description=description, no_value="—", mappings=S.no_data_map("—"),
              overrides=[S.col_props(field, displayName=caption)] if caption else None, **src)
    if caption:
        p["options"].update(textMode="value_and_name", wideLayout=False)
        p["options"]["text"]["titleSize"] = 14
    return p


def _status_counts(online):
    """Rows of reduced status items -> one row Online / Total / Offline. online: transform giving each row
    1 (up) or 0 (down) in the field "Online"."""
    last = S.CALC_NAMES["lastNotNull"]
    return [S.reduce_rows(), *online, S.calc_binary(last, "/", last, "Total"),
            S.reduce_fields(("sum",)), S.calc_binary("Total", "-", "Online", "Offline")]


def build(cfg, datasource_uid="zabbix"):
    sites = S.sites(cfg)
    cats = S.categories(cfg)
    site_re = S.site_group_re(cfg, "$site")
    last = S.CALC_NAMES["lastNotNull"]

    # --- KPI strip (all from the map's data, no extra Zabbix query) --------------------------------------
    # Same polarity on the three status tiles: each counts what is OFFLINE, the caption gives the total.
    site_refs = [S._ref(i) for i in range(len(sites))]
    online = _kpi("HOSTS ONLINE", [*S.health_transforms(), S.reduce_fields(("sum",))], refs=site_refs,
                  field="Online", steps=S.steps(S.OK), caption="${__data.fields.Total} monitorados",
                  description="Hosts das filiais alcançáveis agora (ping, SNMP ou agente).")
    offline = _kpi("HOSTS OFFLINE", [*S.health_transforms(), S.reduce_fields(("sum",))], refs=site_refs,
                   field="Offline", steps=S.COUNT_BAD, caption="de ${__data.fields.Total} hosts",
                   description="Hosts das filiais sem nenhuma verificação de disponibilidade OK.")
    # ifOperStatus 1 = up, anything else down: floor(1 / status) is 1 only for up
    wan_kpi = _kpi("LINKS OFFLINE", _status_counts([
        S.calc_binary(1, "/", last, "inv"),
        S.tf("calculateField", mode="unary", alias="Online", replaceFields=False,
             unary={"operator": "floor", "fieldName": "inv"})]),
        refs=[WAN_REF], field="Offline", steps=S.COUNT_BAD, caption="de ${__data.fields.Total} links WAN",
        description="Links de internet dos firewalls com status operacional diferente de UP.")
    # FortiGate tunnel status 2 = up, 1 = down: status - 1. Red from 1: the smallest site pair has a
    # single tunnel, so one tunnel down can already cut two sites apart (the map's arcs say which).
    vpn_kpi = _kpi("TÚNEIS OFFLINE", _status_counts([S.calc_binary(last, "-", 1, "Online")]),
                   refs=[VPN_REF], field="Offline", steps=S.COUNT_BAD,
                   caption="de ${__data.fields.Total} túneis VPN",
                   description="Túneis IPsec entre filiais (SD-WAN) fora do ar. No mapa, arco vermelho = par "
                               "de filiais sem túnel; âmbar = redundância reduzida.")
    problems_kpi = S.stat("PROBLEMAS ATIVOS POR SEVERIDADE", [S.triggers_target(group=site_re, min_severity=2)],
                          transformations=S.severity_transforms(2), overrides=S.severity_overrides(2),
                          text_mode="value_and_name", color_mode="value", value_size=46, title_size=13,
                          steps=S.steps(S.UNKNOWN), decimals=0, time_from=None, mdp=None,
                          description="Triggers em problema agora nos hosts das filiais, por severidade.")

    # --- right column: the problem feed ------------------------------------------------------------------
    # The WAN link list that used to sit here repeated the map (every link is a named drop under the
    # backbone) and the LINKS WAN KPI; the feed gets the whole column instead, at a size read from the
    # room. Média and up: the feed matches "mais graves"; 8 per page is what h23 holds at 110% with
    # two-line names, so a page is never cut mid-item (a TV cannot scroll; more than 8 shows the pager);
    # the severity KPI still counts Atenção. List layout: in 8 columns the table layout truncates the
    # problem names (the useful part, "...: Link down", is at the end); the list wraps them.
    feed = S.problems("PROBLEMAS ATIVOS · MÉDIA OU MAIOR",
                      [S.problems_target(group=site_re, host="/.*/", min_severity=3)],
                      page_size=8, font_size="110%", layout="list", age=False,
                      description="Problemas de severidade Média ou maior nos hosts das filiais, mais graves "
                                  "primeiro. Os de severidade Atenção entram na contagem do quadro PROBLEMAS "
                                  "ATIVOS e nos selos do mapa.")
    # the default "07 Oct 2026 10:19:57" collides with long problem names in the list layout; Age is off
    # (the plugin writes it in English), the timeline / new-event blink are off (nobody clicks a TV)
    feed["options"].update(customLastChangeFormat=True, lastChangeFormat="DD/MM HH:mm", problemTimeline=False,
                           highlightNewEvents=False)

    panels = S.grid(
        (4, [(_banner(), 5), (online, 3), (offline, 3), (wan_kpi, 3), (vpn_kpi, 3), (problems_kpi, 7)]),
        (23, [(_map_panel(cfg, sites, cats), 16), (feed, 8)]),
    )
    # hidden textbox read by the map only: ?var-simular=FW-RJ,SD-WAN rehearses failures (see the panel code)
    simulate = {"name": "simular", "label": "Simular falha", "type": "textbox", "hide": 2, "query": "",
                "current": {"text": "", "value": ""}}
    variables = [S.site_var(cfg, hide=2),       # kiosk: no variable bar; ?var-site=BA still works
                 simulate,
                 *[_hosts_var(_var_name("site", s["key"]), s["group"], f"Hosts {s['label']}") for s in sites],
                 *[_hosts_var(_var_name("tier", c["key"]), c["group"], f"Hosts {c['title']}") for c in cats]]
    return S.dashboard(KEY, "Topologia (ECharts)", panels, datasource_uid=datasource_uid, tv=True,
                       variables=variables, time_from="now-6h", range_cap="2d",
                       description="Protótipo B da topologia (Business Charts / ECharts) para TV 1920x1080: "
                                   "filiais em colunas, camadas de rede, links WAN, túneis VPN e problemas "
                                   "ao vivo.")


if __name__ == "__main__":         # python -m zabbix_autodiscovery.grafana_v2.topology_echarts config.yaml
    import sys

    from ..config import load_config
    print(json.dumps(build(load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")),
                     ensure_ascii=False, indent=2))
