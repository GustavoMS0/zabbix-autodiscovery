"""Generates an executive Network Topology & NOC command-center dashboard for Grafana.

Inspired by top-tier NOC topology dashboards (ECharts graph + WAN links + Infrastructure
health + Live alerts ticker). Uses the volkovlabs-echarts-panel plugin for interactive
path tracing and hardware hierarchy.

The dashboard only has the variables `datasource`, `site` and the hidden `site_hosts`, so
every target sets its own group/host filters (there is no $group/$host here):
- items that only exist on one device type (ICMP ping, WAN status) use the site group;
- items shared by several device types (CPU, temperatures) use the category group plus
  the hosts of the chosen site.
"""
import json

from .dashboards import (
    DS,
    MAX_RANGE,
    OPER_STATUS_MAP,
    OPER_STATUS_STEPS,
    WAN_IN,
    WAN_OUT,
    WAN_STATUS,
    _alias,
    _replace_alias,
    _target,
    quick_ranges,
)

# $site is "Matriz", "Filial1", "Filial2", "Filial3" or the All value ".*", matching the Filiais/* groups.
SITE_GROUP = r"/^Filiais\/$site$/"
SITE_HOSTS = "/^$site_hosts$/"
# Availability items present on the infrastructure hosts (ICMP: 1=up, 0=down;
# zabbix[host,*,available]: 0=not available, 1=available, 2=unknown).
AVAIL_RE = r"/^(ICMP ping|SNMP agent availability|Zabbix agent availability)$/"
SITES = [("Matriz - Sede Principal", "Matriz"), ("Filial 1 (se houver)", "Filial1"),
         ("Filial 2 (se houver)", "Filial2"), ("Filial 3 (se houver)", "Filial3")]
# Availability value map shared by ICMP and zabbix[host,*,available].
AVAIL_MAP = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red", "index": 0},
                                           "1": {"text": "UP", "color": "green", "index": 1},
                                           "2": {"text": "UNKNOWN", "color": "#64748b", "index": 2}}}]
AVAIL_STEPS = [{"color": "red", "value": None}, {"color": "green", "value": 1}, {"color": "#64748b", "value": 2}]

# Map nodes. `hosts` are exact Zabbix host names (checked with host.get); the map colours each
# node from their availability. `wan: True` nodes use the WAN operational status of those hosts.
NODES = [
    # --- TIER 0: Provedores / Internet (Y: 60) ---
    {"id": "inet-sp", "name": "Internet Matriz\n(Link 1 / Link 2)", "category": "Internet", "x": 500, "y": 60,
     "symbolSize": 52, "ip": "BGP / Multi-WAN", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Link Primário 50M | Link Redundante 50M", "hosts": ["FW-SP"], "wan": True},
    {"id": "inet-rj", "name": "Internet Filial 1\n(Link 1 / Link 2)", "category": "Internet", "x": 160, "y": 60,
     "symbolSize": 45, "ip": "Multi-WAN", "site": "Filial 1 (se houver)", "siteKey": "Filial1",
     "role": "Operadora A 50M | Operadora B 50M", "hosts": ["FW-RJ"], "wan": True},
    {"id": "inet-ba", "name": "Internet Filial 2\n(Fibra / Rádio)", "category": "Internet", "x": 840, "y": 60,
     "symbolSize": 45, "ip": "Multi-WAN", "site": "Filial 2 (se houver)", "siteKey": "Filial2",
     "role": "Link Fibra 30M | Link Rádio 40M", "hosts": ["FW-BA"], "wan": True},
    {"id": "inet-pr", "name": "Internet Filial 3\n(SD-WAN)", "category": "Internet", "x": 1080, "y": 60,
     "symbolSize": 45, "ip": "Multi-WAN", "site": "Filial 3 (se houver)", "siteKey": "Filial3",
     "role": "Link Dedicado SD-WAN | wan2", "hosts": ["FW-PR"], "wan": True},

    # --- TIER 1: Firewalls FortiGate (Y: 180) ---
    {"id": "fw-sp", "name": "FW-Matriz (FortiGate)", "category": "Firewall", "x": 500, "y": 180, "symbolSize": 58,
     "ip": "192.168.0.4", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Firewall Core / Hub SD-WAN", "hosts": ["FW-SP"]},
    {"id": "fw-rj", "name": "FW-Filial1 (FortiGate)", "category": "Firewall", "x": 160, "y": 180, "symbolSize": 48,
     "ip": "192.168.3.21", "site": "Filial 1 (se houver)", "siteKey": "Filial1",
     "role": "Firewall Filial / SD-WAN Spoke", "hosts": ["FW-RJ"]},
    {"id": "fw-ba", "name": "FW-Filial2 (FortiGate)", "category": "Firewall", "x": 840, "y": 180, "symbolSize": 48,
     "ip": "192.168.2.244", "site": "Filial 2 (se houver)", "siteKey": "Filial2",
     "role": "Firewall Filial / SD-WAN Spoke", "hosts": ["FW-BA"]},
    {"id": "fw-pr", "name": "FW-Filial3 (FortiGate)", "category": "Firewall", "x": 1080, "y": 180, "symbolSize": 48,
     "ip": "192.168.1.2", "site": "Filial 3 (se houver)", "siteKey": "Filial3",
     "role": "Firewall Filial / SD-WAN Spoke", "hosts": ["FW-PR"]},

    # --- TIER 2: Switches Core & Distribuição (Y: 310) ---
    {"id": "sw-core-sp", "name": "Switch-Core\n192.168.0.22", "category": "Switch", "x": 500, "y": 310,
     "symbolSize": 52, "ip": "192.168.0.22", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Core Switch / VLT Stacking", "hosts": ["Switch-Aruba 192.168.0.22"]},
    {"id": "sw-sp-17", "name": "SW-17 (Dist)", "category": "Switch", "x": 380, "y": 410, "symbolSize": 36,
     "ip": "192.168.0.17", "site": "Matriz - Sede Principal", "siteKey": "Matriz", "role": "Switch Acesso",
     "hosts": ["switch-192.168.0.17"]},
    {"id": "sw-sp-19", "name": "SW-19 (Dist)", "category": "Switch", "x": 440, "y": 410, "symbolSize": 36,
     "ip": "192.168.0.19", "site": "Matriz - Sede Principal", "siteKey": "Matriz", "role": "Switch Acesso",
     "hosts": ["switch-192.168.0.19"]},
    {"id": "sw-sp-20", "name": "SW-20 (Dist)", "category": "Switch", "x": 560, "y": 410, "symbolSize": 36,
     "ip": "192.168.0.20", "site": "Matriz - Sede Principal", "siteKey": "Matriz", "role": "Switch Acesso",
     "hosts": ["switch-192.168.0.20"]},
    {"id": "sw-sp-21", "name": "SW-21 (Dist)", "category": "Switch", "x": 620, "y": 410, "symbolSize": 36,
     "ip": "192.168.0.21", "site": "Matriz - Sede Principal", "siteKey": "Matriz", "role": "Switch Acesso",
     "hosts": ["switch-192.168.0.21"]},
    {"id": "sw-core-rj", "name": "SW-Core-Filial1", "category": "Switch", "x": 160, "y": 310, "symbolSize": 42,
     "ip": "192.168.3.19", "site": "Filial 1 (se houver)", "siteKey": "Filial1", "role": "Core Switch Filial 1",
     "hosts": ["SW-Core-Filial1"]},
    {"id": "sw-core-ba", "name": "SW-Core-Filial2", "category": "Switch", "x": 840, "y": 310, "symbolSize": 42,
     "ip": "192.168.2.144", "site": "Filial 2 (se houver)", "siteKey": "Filial2", "role": "Core Switch Filial 2",
     "hosts": ["SW-Core-Filial2"]},

    # --- TIER 3: Infraestrutura, Nobreak & Hardware Dell (Y: 490) ---
    {"id": "ups-sp", "name": "Nobreak-Matriz", "category": "Nobreak UPS", "x": 320, "y": 310, "symbolSize": 40,
     "ip": "192.168.0.3", "site": "Matriz - Sede Principal", "siteKey": "Matriz", "role": "Nobreak Senoidal",
     "hosts": ["Nobreak-Matriz"]},
    {"id": "hw-sp-1", "name": "iDRAC-Host-01", "category": "Hardware Servidor", "x": 380, "y": 500,
     "symbolSize": 32, "ip": "192.168.0.224", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-srv01"]},
    {"id": "hw-sp-2", "name": "iDRAC-Host-02", "category": "Hardware Servidor", "x": 440, "y": 500,
     "symbolSize": 32, "ip": "192.168.0.228", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-srv02"]},
    {"id": "hw-sp-3", "name": "iDRAC-Host-03", "category": "Hardware Servidor", "x": 500, "y": 500,
     "symbolSize": 32, "ip": "192.168.0.226", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-srv03"]},
    {"id": "hw-sp-4", "name": "iDRAC-Host-04", "category": "Hardware Servidor", "x": 560, "y": 500,
     "symbolSize": 32, "ip": "192.168.0.225", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-srv04"]},
    {"id": "hw-sp-5", "name": "iDRAC-Host-05", "category": "Hardware Servidor", "x": 620, "y": 500,
     "symbolSize": 32, "ip": "192.168.0.227", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-srv05"]},
    {"id": "hw-rj-1", "name": "iDRAC-Filial1", "category": "Hardware Servidor", "x": 160, "y": 440,
     "symbolSize": 32, "ip": "192.168.3.22", "site": "Filial 1 (se houver)", "siteKey": "Filial1",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-filial01"]},
    {"id": "hw-ba-1", "name": "iDRAC-Filial2", "category": "Hardware Servidor", "x": 840, "y": 440,
     "symbolSize": 32, "ip": "192.168.2.14", "site": "Filial 2 (se houver)", "siteKey": "Filial2",
     "role": "Dell iDRAC Enterprise", "hosts": ["idrac-filial02"]},

    # --- TIER 4: Hypervisors & Servidores (Y: 620) ---
    {"id": "vm-cluster-sp", "name": "Cluster Hypervisors\n(5 hosts Hyper-V)", "category": "Virtualização / Servidor",
     "x": 500, "y": 620, "symbolSize": 45, "ip": "192.168.0.x", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "Cluster de Virtualização Hyper-V",
     "hosts": ["PHP", "CLIPPER", "DELPHI", "PASCAL", "ASSEMBLY"]},
    {"id": "srv-sp", "name": "Servidores Aplicação\n(AD / DC / NGINX)", "category": "Virtualização / Servidor",
     "x": 660, "y": 620, "symbolSize": 40, "ip": "192.168.0.x", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "VMs e serviços essenciais",
     "hosts": ["SRV-AD01", "SRV-AD02", "srv-dc02", "srv-cs01", "NGINX-SRV", "JAVASCRIPT"]},
    {"id": "vm-rj-1", "name": "SRV-DC01 (Filial 1)", "category": "Virtualização / Servidor", "x": 160, "y": 540,
     "symbolSize": 34, "ip": "192.168.3.1", "site": "Filial 1 (se houver)", "siteKey": "Filial1",
     "role": "Domain Controller Filial", "hosts": ["SRV-DC01"]},
    {"id": "vm-ba-1", "name": "SRV-AD03 (Filial 2)", "category": "Virtualização / Servidor", "x": 840, "y": 540,
     "symbolSize": 34, "ip": "192.168.2.4", "site": "Filial 2 (se houver)", "siteKey": "Filial2",
     "role": "Domain Controller Filial", "hosts": ["SRV-AD03"]},

    # --- TIER 5: Access Points Wi-Fi (Y: 740) ---
    {"id": "ap-sp", "name": "5x APs Wi-Fi Matriz\n(Corp/Adm/TI)", "category": "Access Point", "x": 500, "y": 740,
     "symbolSize": 40, "ip": "192.168.0.40-44", "site": "Matriz - Sede Principal", "siteKey": "Matriz",
     "role": "5x APs Corporativos",
     "hosts": ["AP01 - FINANCEIRO", "AP02 - DIRETORIA", "AP03 - RECEPÇÃO", "AP04 - COMERCIAL", "AP05 - TI"]},
    {"id": "ap-rj", "name": "5x APs Wi-Fi Filial 1\n(Operação/Adm)", "category": "Access Point", "x": 160, "y": 660,
     "symbolSize": 38, "ip": "192.168.3.107-116", "site": "Filial 1 (se houver)", "siteKey": "Filial1",
     "role": "5x APs Operação & Escritório",
     "hosts": ["AP01 - ADM", "AP02 - BALANÇA", "AP03 - GALPÃO 1", "AP04 - GALPÃO 2", "AP05 - LOGÍSTICA"]},
    {"id": "ap-ba", "name": "6x APs Wi-Fi Filial 2\n(Operação/Estoque)", "category": "Access Point", "x": 840, "y": 660,
     "symbolSize": 40, "ip": "192.168.2.47-52", "site": "Filial 2 (se houver)", "siteKey": "Filial2",
     "role": "6x APs Operação & Armazém",
     "hosts": [
         "AP01 - ADM", "AP02 - ARMAZÉM", "AP03 - EXPEDIÇÃO",
         "AP04 - FÁBRICA", "AP05 - ESTOQUE", "AP06 - RESERVA",
     ]},
]


def _link(source, target, color, width, text=None, **style):
    label = {"show": True, "formatter": text} if text else {"show": False}
    return {"source": source, "target": target, "label": label,
            "lineStyle": {"width": width, "color": color, **style}}


LINKS = [
    # Links de Internet -> Firewalls
    _link("inet-sp", "fw-sp", "#10b981", 3.5, "wan1(50M) / wan2(50M)"),
    _link("inet-rj", "fw-rj", "#10b981", 3, "Link 1 / Link 2(50M)"),
    _link("inet-ba", "fw-ba", "#10b981", 3, "Fibra(30M) / Rádio(40M)"),
    _link("inet-pr", "fw-pr", "#10b981", 2.5, "SD-WAN / wan2"),
    # Malha SD-WAN VPN Inter-filiais (linhas tracejadas)
    _link("fw-sp", "fw-rj", "#06b6d4", 2.5, type="dashed", curveness=0.22),
    _link("fw-sp", "fw-ba", "#06b6d4", 2.5, type="dashed", curveness=-0.22),
    _link("fw-sp", "fw-pr", "#06b6d4", 2, type="dashed", curveness=-0.35),
    # Firewalls -> Switches Core
    _link("fw-sp", "sw-core-sp", "#3b82f6", 4, "10 Gbps Trunk"),
    _link("fw-rj", "sw-core-rj", "#3b82f6", 3, "1 Gbps Uplink"),
    _link("fw-ba", "sw-core-ba", "#3b82f6", 3, "1 Gbps Uplink"),
    # Nobreak alimentando infra de Core SP
    _link("ups-sp", "sw-core-sp", "#eab308", 2, type="dotted"),
    _link("ups-sp", "fw-sp", "#eab308", 2, type="dotted"),
    # Core SP -> Switches de Distribuição
    *[_link("sw-core-sp", f"sw-sp-{n}", "#60a5fa", 2.5) for n in (17, 19, 20, 21)],
    # Switches -> Servidores Físicos Dell iDRAC
    *[_link("sw-core-sp", f"hw-sp-{n}", "#a855f7", 2) for n in range(1, 6)],
    _link("sw-core-rj", "hw-rj-1", "#a855f7", 2),
    _link("sw-core-ba", "hw-ba-1", "#a855f7", 2),
    # Servidores Físicos -> Hypervisors / VMs
    _link("hw-sp-3", "vm-cluster-sp", "#8b5cf6", 3, "Hyper-V"),
    _link("vm-cluster-sp", "srv-sp", "#8b5cf6", 2, "VMs"),
    _link("hw-rj-1", "vm-rj-1", "#8b5cf6", 2),
    _link("hw-ba-1", "vm-ba-1", "#8b5cf6", 2),
    # Switches -> Access Points Wi-Fi
    _link("sw-sp-20", "ap-sp", "#ec4899", 2.5, "PoE+"),
    _link("sw-core-rj", "ap-rj", "#ec4899", 2.5, "PoE+"),
    _link("sw-core-ba", "ap-ba", "#ec4899", 2.5, "PoE+"),
]


def _echarts_get_option():
    """JavaScript code string executed by volkovlabs-echarts-panel.

    The panel query returns A = availability per host (labels.host / labels.item_key) and
    B = WAN operational status; each node is coloured from the hosts it lists.
    """
    code = r"""
// Apache ECharts Network Topology & Path Tracing for AutoDiscovery NOC
const seriesData = (context && context.panel && context.panel.data && context.panel.data.series) || [];

// Node definitions (Coordinates system 0-1200 x, 0-800 y); hosts = Zabbix host names
const allNodes = __NODES__;
const allLinks = __LINKS__;

const COLORS = { up: '#22c55e', down: '#ef4444', partial: '#f97316', unknown: '#64748b' };
const LABELS = { up: 'ONLINE', down: 'OFFLINE', partial: 'PARCIAL', unknown: 'SEM DADOS' };
const CATEGORY_COLORS = {
  'Internet': '#38bdf8', 'Firewall': '#e879f9', 'Switch': '#3b82f6', 'Hardware Servidor': '#a855f7',
  'Virtualização / Servidor': '#8b5cf6', 'Access Point': '#ec4899', 'Nobreak UPS': '#eab308'
};

// Last non-null value of a field (Grafana may hand over a Vector or a plain array)
const lastValue = (field) => {
  const raw = field && field.values ? field.values : [];
  const vals = typeof raw.toArray === 'function' ? raw.toArray() : raw;
  for (let i = vals.length - 1; i >= 0; i--) {
    if (vals[i] !== null && vals[i] !== undefined) return Number(vals[i]);
  }
  return null;
};

// Checks per host: reach = ICMP ping / SNMP availability, agent = Zabbix agent availability.
// Each check: true = up, false = down, null = unknown.
// icmpping: 1 = up, 0 = down. zabbix[host,*,available]: 1 = up, 0 = down, 2 = unknown.
const hostChecks = {};
const wanStatus = {};
// Merge two readings of the same check: a known value beats null, down beats up
const mergeOk = (prev, ok) => (prev === undefined || prev === null || ok === false ? ok : prev);
for (const frame of seriesData) {
  const valueField = (frame.fields || []).find((f) => f.type === 'number');
  if (!valueField || !valueField.labels || !valueField.labels.host) continue;
  const host = valueField.labels.host;
  const key = valueField.labels.item_key || '';
  const item = valueField.labels.item || key;
  const last = lastValue(valueField);
  if (frame.refId === 'B') {
    // WAN interface operational status: 1 = up
    (wanStatus[host] = wanStatus[host] || []).push({ name: item, ok: last === null ? null : last === 1 });
    continue;
  }
  const ok = last === null ? null : (key === 'icmpping' ? last === 1 : (last === 1 ? true : last === 0 ? false : null));
  const kind = key === 'icmpping' ? 'ping'
    : (key.indexOf(',agent,') >= 0 || item === 'Zabbix agent availability' ? 'agent' : 'snmp');
  const c = hostChecks[host] = hostChecks[host] || {};
  c[kind] = mergeOk(c[kind], ok);
}

// Host state: reachability (ping, else SNMP) decides up/down; a down agent (Zabbix or
// SNMP) on a host that answers ping is 'partial'. Without ping/SNMP the agent alone decides.
const CHECK_NAMES = { ping: 'ping', snmp: 'SNMP', agent: 'agente' };
const hostMember = (h) => {
  const c = hostChecks[h] || {};
  const hasPing = c.ping !== undefined && c.ping !== null;
  const reach = hasPing ? c.ping : (c.snmp === undefined ? null : c.snmp);
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

// Branch filter: $site is a regex fragment (".*" for all)
let site = '.*';
try {
  if (context && context.grafana && typeof context.grafana.replaceVariables === 'function') {
    site = context.grafana.replaceVariables('$site');
  }
} catch (e) { site = '.*'; }
const allSites = !site || site === '.*' || site === '$site' || site === '$__all';

const nodes = allNodes.filter((n) => allSites || n.siteKey === site).map((n) => {
  const members = n.wan
    ? n.hosts.flatMap((h) => (wanStatus[h] || []).map((w) => ({
        name: h + ': ' + w.name, state: w.ok === null ? 'unknown' : (w.ok ? 'up' : 'down'), checks: [] })))
    : n.hosts.map(hostMember);
  // Node: all known members up = up, all down = down, anything else (incl. a partial host) = partial
  const known = members.filter((m) => m.state !== 'unknown');
  const up = known.filter((m) => m.state === 'up').length;
  const down = known.filter((m) => m.state === 'down').length;
  let state = 'unknown';
  if (known.length) state = up === known.length ? 'up' : (down === known.length ? 'down' : 'partial');
  const catColor = CATEGORY_COLORS[n.category] || '#94a3b8';
  return Object.assign({}, n, {
    members: members,
    state: state,
    up: up,
    total: members.length,
    itemStyle: {
      color: COLORS[state], borderColor: catColor, borderWidth: 3,
      shadowBlur: state === 'down' ? 18 : 8, shadowColor: COLORS[state]
    }
  });
});
const byId = {};
nodes.forEach((n) => { byId[n.id] = n; });

// Links touching a down node take the down colour
const links = allLinks.filter((l) => byId[l.source] && byId[l.target]).map((l) => {
  const down = byId[l.source].state === 'down' || byId[l.target].state === 'down';
  if (!down) return l;
  return Object.assign({}, l, { lineStyle: Object.assign({}, l.lineStyle, { color: COLORS.down, type: 'dashed' }) });
});

return {
  backgroundColor: 'transparent',
  tooltip: {
    trigger: 'item',
    backgroundColor: 'rgba(15, 23, 42, 0.95)',
    borderColor: '#334155',
    borderWidth: 1,
    padding: [10, 14],
    textStyle: { color: '#f8fafc', fontSize: 12 },
    formatter: function(params) {
      if (params.dataType === 'node') {
        const d = params.data;
        // One row per host, with each availability check (ping / SNMP / agente) so the cause is visible
        const rows = (d.members || []).map((m) => {
          const checks = (m.checks || []).map((c) =>
            `<span style="color:${COLORS[c.state]};">${c.name} ●</span>`).join(', ');
          return `<div><span style="color:${COLORS[m.state]};">●</span> ${m.name}` +
            (checks ? ` <span style="color:#94a3b8;">(${checks})</span>` : '') + `</div>`;
        }).join('') || '<div style="color:#94a3b8;">Sem item de disponibilidade no Zabbix</div>';
        return `
          <div style="font-weight:bold;font-size:14px;color:${COLORS[d.state]};margin-bottom:6px;">
            ${d.name.replace('\n', ' ')}
          </div>
          <table style="font-size:12px;line-height:1.6;color:#cbd5e1;">
            <tr><td><b>Categoria:</b></td><td style="padding-left:8px;">${d.category}</td></tr>
            <tr><td><b>Endereço IP:</b></td>
                <td style="padding-left:8px;font-family:monospace;color:#38bdf8;">${d.ip}</td></tr>
            <tr><td><b>Localidade:</b></td><td style="padding-left:8px;">${d.site}</td></tr>
            <tr><td><b>Papel / Detalhe:</b></td><td style="padding-left:8px;">${d.role}</td></tr>
            <tr><td><b>Status:</b></td>
                <td style="padding-left:8px;"><span style="color:${COLORS[d.state]};font-weight:bold;">
                  ● ${LABELS[d.state]}</span> (${d.up}/${d.total} online)</td></tr>
          </table>
          <div style="margin-top:6px;font-size:11px;line-height:1.5;border-top:1px solid #334155;padding-top:4px;">
            ${rows}
          </div>
        `;
      } else if (params.dataType === 'edge') {
        const d = params.data;
        return `
          <div style="font-weight:bold;margin-bottom:4px;color:#38bdf8;">Conexão de Enlace</div>
          <div><b>Origem:</b> ${d.source}</div>
          <div><b>Destino:</b> ${d.target}</div>
          <div><b>Info:</b> ${(d.label && d.label.formatter) || 'Enlace LAN/WAN'}</div>
        `;
      }
      return '';
    }
  },
  legend: [{
    data: Object.keys(CATEGORY_COLORS),
    textStyle: { color: '#cbd5e1', fontSize: 11 },
    top: 6,
    left: 'center',
    itemGap: 16
  }],
  series: [{
    type: 'graph',
    layout: 'none',
    roam: true,
    draggable: true,
    edgeSymbol: ['none', 'none'],
    label: {
      show: true,
      position: 'bottom',
      color: '#e2e8f0',
      fontSize: 11,
      fontWeight: 'bold',
      distance: 6
    },
    emphasis: {
      focus: 'adjacency',
      lineStyle: {
        width: 5,
        color: '#00ffd5',
        shadowColor: 'rgba(0, 255, 213, 0.8)',
        shadowBlur: 14
      },
      label: {
        fontSize: 12,
        fontWeight: 'bolder',
        color: '#00ffd5'
      }
    },
    lineStyle: {
      curveness: 0.08,
      opacity: 0.85
    },
    categories: Object.keys(CATEGORY_COLORS).map((name) => ({
      name: name,
      itemStyle: { color: CATEGORY_COLORS[name] }
    })),
    nodes: nodes,
    links: links
  }]
};
""".strip()
    return (code.replace("__NODES__", json.dumps(NODES, ensure_ascii=False))
                .replace("__LINKS__", json.dumps(LINKS, ensure_ascii=False)))


def _q(item, functions=(), ref="A", group=SITE_GROUP, host="/.*/"):
    """Target with explicit group/host filters (this dashboard has no $group/$host)."""
    t = _target(item, functions, ref=ref)
    t["datasource"] = {"type": DS["type"], "uid": "${datasource}"}
    t["group"] = {"filter": group}
    t["host"] = {"filter": host}
    # trend.get of plugin 6.9.1 is rejected by Zabbix 8.0, so history only.
    t["options"] = {**t.get("options", {}), "showDisabledItems": False, "skipEmptyValues": True,
                    "disableDataAlignment": True, "useTrends": "false"}
    return t


# Parameter definitions of the Zabbix datasource functions used here.
_FN_PARAMS = {"scale": [{"name": "factor", "type": "float", "options": [100, 0.01, 10, -1]}],
              "offset": [{"name": "delta", "type": "float", "options": [-100, 100]}],
              "groupBy": [{"name": "interval", "type": "string"},
                          {"name": "function", "type": "string",
                           "options": ["avg", "min", "max", "sum", "count", "median", "first", "last"]}]}
_FN_DEFAULTS = {"scale": [100], "offset": [100], "groupBy": ["1m", "avg"]}


def _fn(name, category, params=()):
    """Zabbix datasource function (sumSeries, scale, offset...)."""
    return {
        "def": {"name": name, "category": category, "params": _FN_PARAMS.get(name, []),
                "defaultParams": _FN_DEFAULTS.get(name, [])},
        "params": list(params),
        "text": f"{name}({', '.join(str(p) for p in params)})",
    }


def _stat_options(calcs=("lastNotNull",)):
    return {
        "reduceOptions": {"calcs": list(calcs), "values": False, "fields": ""},
        "orientation": "horizontal",
        "textMode": "value_and_name",
        "colorMode": "background",
        "graphMode": "none",
        "wideLayout": False,
    }


def _last_only(panel, window, points=10):
    """Stat panels only show the last value, so they fetch a short window."""
    panel.update({"timeFrom": window, "hideTimeOverride": True, "maxDataPoints": points})
    return panel


def build_topology_dashboard(datasource_uid="zabbix"):
    """Constructs the complete AutoDiscovery Topologia & NOC dashboard."""
    ds = {"type": DS["type"], "uid": "${datasource}"}

    # Top KPI Row (y=0, h=3): ICMP hosts of the site, summed into Online / Total / Offline
    kpi_summary = _last_only({
        "id": 1,
        "type": "stat",
        "title": "Infraestrutura Global - Visão Executiva",
        "gridPos": {"x": 0, "y": 0, "w": 24, "h": 3},
        "datasource": ds,
        "targets": [
            _q("ICMP ping", [_fn("sumSeries", "Aggregate"), _alias("Online")], ref="A"),
            _q("ICMP ping", [_fn("scale", "Transform", [0]), _fn("offset", "Transform", [1]),
                             _fn("sumSeries", "Aggregate"), _alias("Total")], ref="B"),
            _q("ICMP ping", [_fn("scale", "Transform", [-1]), _fn("offset", "Transform", [1]),
                             _fn("sumSeries", "Aggregate"), _alias("Offline")], ref="C"),
        ],
        "options": _stat_options(),
        "fieldConfig": {
            "defaults": {
                "unit": "none",
                "decimals": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]},
            },
            "overrides": [
                {"matcher": {"id": "byFrameRefID", "options": "B"},
                 "properties": [{"id": "thresholds", "value": {"mode": "absolute",
                                                               "steps": [{"color": "blue", "value": None}]}}]},
                {"matcher": {"id": "byFrameRefID", "options": "C"},
                 "properties": [{"id": "thresholds", "value": {"mode": "absolute", "steps": [
                     {"color": "green", "value": None}, {"color": "red", "value": 1}]}}]},
            ],
        },
    }, "5m")

    # Left Column: Links WAN & Conectividade (x=0, y=3, w=5, h=21)
    # WAN items only exist on the FortiGates, so the site group is enough.
    # replaceAlias sees the setAlias output ("host: item"), so its regex is not anchored with ^.
    wan_status_panel = _last_only({
        "id": 2,
        "type": "stat",
        "title": "Links de Internet & Provedores",
        "gridPos": {"x": 0, "y": 3, "w": 5, "h": 11},
        "datasource": ds,
        "targets": [
            _q(
                WAN_STATUS["re"],
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/: (?:Interface\s+)?([^:]+):\s+Operational status$/i", " - $1"),
                ],
            )
        ],
        "options": _stat_options(),
        "fieldConfig": {
            "defaults": {
                "mappings": OPER_STATUS_MAP,
                "thresholds": {"mode": "absolute", "steps": OPER_STATUS_STEPS},
            },
            "overrides": [],
        },
    }, "10m")

    # Only 8 WAN links: no top(), so In and Out show every link.
    wan_traffic_panel = {
        "id": 3,
        "type": "timeseries",
        "title": "Tráfego Internet WAN",
        "gridPos": {"x": 0, "y": 14, "w": 5, "h": 10},
        "datasource": ds,
        "maxDataPoints": 500,
        "targets": [
            _q(
                WAN_IN["re"],
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/: (?:Interface\s+)?([^:]+):\s+Bits received$/i", " - $1 (In)"),
                ],
                ref="A",
            ),
            _q(
                WAN_OUT["re"],
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/: (?:Interface\s+)?([^:]+):\s+Bits sent$/i", " - $1 (Out)"),
                ],
                ref="B",
            ),
        ],
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "calcs": ["mean", "max"]},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "fieldConfig": {"defaults": {"unit": "bps"}, "overrides": []},
    }

    # Center Column: Apache ECharts Topology Graph (x=5, y=3, w=14, h=21)
    # A = availability of every host of the site, B = WAN status (Internet nodes).
    # The iDRAC availability items "discard unchanged" with a 6h heartbeat, so the window is 7h;
    # groupBy(1h, last) keeps the latest value while sending ~8 points per host.
    # timeFrom is per panel, so ping/agent cannot use a shorter window: the 7 iDRACs only have
    # SNMP availability (no ICMP ping) and vanish from a 5m window. Measured all sites: 7h ~860 ms
    # (112 frames) vs 5m ~345 ms (105 frames, iDRACs missing).
    latest = [_fn("groupBy", "Transform", ["1h", "last"])]
    echarts_panel = _last_only({
        "id": 4,
        "type": "volkovlabs-echarts-panel",
        "title": "Mapa de Topologia e Conectividade de Rede",
        "gridPos": {"x": 5, "y": 3, "w": 14, "h": 21},
        "datasource": ds,
        "targets": [
            _q(AVAIL_RE, latest, ref="A"),
            _q(WAN_STATUS["re"], latest, ref="B"),
        ],
        "options": {
            "renderer": "canvas",
            "editor": {"height": 600, "format": "auto"},
            "getOption": _echarts_get_option(),
        },
    }, "7h")

    # Right Column: Infraestrutura, Computação & Virtualização (x=19, y=3, w=5, h=21)
    virt_panel = _last_only({
        "id": 5,
        "type": "stat",
        "title": "Virtualização & Servidores",
        "gridPos": {"x": 19, "y": 3, "w": 5, "h": 7},
        "datasource": ds,
        "targets": [
            _q(
                r"/^(Zabbix agent availability|ICMP ping)$/",
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/: Zabbix agent availability$/", " (agente)"),
                    _replace_alias(r"/: ICMP ping$/", " (ping)"),
                ],
                ref="A",
                group=r"/^Servidores\/.*$/",
                host=SITE_HOSTS,
            )
        ],
        "options": _stat_options(),
        "fieldConfig": {
            "defaults": {
                "mappings": AVAIL_MAP,
                "thresholds": {"mode": "absolute", "steps": AVAIL_STEPS},
            },
            "overrides": [],
        },
    }, "5m")

    firewall_health_panel = _last_only({
        "id": 6,
        "type": "stat",
        "title": "Firewalls FortiGate - CPU & Sessões",
        "gridPos": {"x": 19, "y": 10, "w": 5, "h": 7},
        "datasource": ds,
        "targets": [
            _q(r"/^CPU utilization$/", [_alias("$__zbx_host_name: CPU")], ref="A",
               group=r"/^Rede\/Firewalls$/", host=SITE_HOSTS),
            _q(r"/^IPv4 Active sessions$/", [_alias("$__zbx_host_name: Sessões")], ref="B",
               group=r"/^Rede\/Firewalls$/", host=SITE_HOSTS),
        ],
        "options": _stat_options(),
        "fieldConfig": {
            "defaults": {
                "unit": "percent",
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "orange", "value": 70},
                        {"color": "red", "value": 85},
                    ],
                },
            },
            "overrides": [
                # Sessions are a count, not a percentage.
                {"matcher": {"id": "byFrameRefID", "options": "B"},
                 "properties": [{"id": "unit", "value": "short"},
                                {"id": "thresholds", "value": {"mode": "absolute",
                                                               "steps": [{"color": "blue", "value": None}]}}]},
            ],
        },
    }, "10m")

    # iDRAC probes use "discard unchanged" with a 6h heartbeat, so the window is a bit over 6h.
    hardware_panel = _last_only({
        "id": 7,
        "type": "stat",
        "title": "Hardware Físico (Dell iDRAC & UPS)",
        "gridPos": {"x": 19, "y": 17, "w": 5, "h": 7},
        "datasource": ds,
        "targets": [
            _q(
                r"/^(Probe \[(System Board )?Inlet Temp\]: Value|Bateria: Temperatura)$/",
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/: Probe \[.*Inlet Temp\]: Value$/", ": Inlet"),
                    _replace_alias(r"/: Bateria: Temperatura$/", ": Bateria"),
                ],
                ref="A",
                group=r"/^Infra\/.*$/",
                host=SITE_HOSTS,
            ),
        ],
        "options": _stat_options(),
        "fieldConfig": {
            "defaults": {
                "unit": "celsius",
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "orange", "value": 27},
                        {"color": "red", "value": 32},
                    ],
                },
            },
            "overrides": [
                # UPS battery runs warmer than a server inlet.
                {"matcher": {"id": "byRegexp", "options": ".*Bateria.*"},
                 "properties": [{"id": "thresholds", "value": {"mode": "absolute", "steps": [
                     {"color": "green", "value": None}, {"color": "orange", "value": 40},
                     {"color": "red", "value": 45}]}}]},
            ],
        },
    }, "7h", points=100)

    # Bottom Row: Alertas Ativos / NOC Feed (x=0, y=24, w=24, h=7)
    alerts_ticker = {
        "id": 8,
        "type": "alexanderzobnin-zabbix-triggers-panel",
        "title": "Alertas Ativos em Tempo Real (NOC Feed)",
        "gridPos": {"x": 0, "y": 24, "w": 24, "h": 7},
        "datasource": ds,
        "targets": [
            {
                "refId": "A",
                "queryType": "5",
                "datasource": ds,
                "group": {"filter": SITE_GROUP},
                "host": {"filter": "/.*/"},
                "application": {"filter": ""},
                "proxy": {"filter": ""},
                "trigger": {"filter": ""},
                "tags": {"filter": ""},
                "showProblems": "problems",
                "options": {
                    "minSeverity": 2,
                    "acknowledged": 2,
                    "sortProblems": "priority",
                    "hostsInMaintenance": False,
                    "limit": 100,
                },
            }
        ],
        "options": {
            "hostField": True,
            "hostGroups": True,
            "severityField": True,
            "ageField": True,
            "showTags": True,
            "pageSize": 10,
        },
    }

    panels = [
        kpi_summary,
        wan_status_panel,
        wan_traffic_panel,
        echarts_panel,
        virt_panel,
        firewall_health_panel,
        hardware_panel,
        alerts_ticker,
    ]

    variables = [
        {
            "name": "datasource",
            "label": "Zabbix",
            "type": "datasource",
            "query": DS["type"],
            "current": {"text": datasource_uid, "value": datasource_uid},
            "hide": 0,
        },
        {
            # Values are regex fragments for /^Filiais\/$site$/; All = ".*" (a custom allValue
            # is inserted unescaped by Grafana).
            "name": "site",
            "label": "Filial / Sede",
            "type": "custom",
            "options": [{"text": "Todas as Filiais (Global)", "value": "$__all", "selected": True}]
            + [{"text": text, "value": value, "selected": False} for text, value in SITES],
            "current": {"text": "Todas as Filiais (Global)", "value": "$__all"},
            "query": ", ".join(f"{text} : {value}" for text, value in SITES),
            "multi": False,
            "includeAll": True,
            "allValue": ".*",
            "hide": 0,
        },
        {
            # Hosts of the chosen site, for panels whose item exists on several device types.
            "name": "site_hosts",
            "label": "Hosts da filial",
            "type": "query",
            "datasource": ds,
            "query": {"queryType": "host", "group": SITE_GROUP, "host": "/.*/", "application": "",
                      "itemTag": "", "item": ""},
            "multi": True,
            "includeAll": True,
            "refresh": 2,
            "sort": 1,
            "current": {"text": "All", "value": "$__all"},
            "hide": 2,
        },
    ]

    return {
        "uid": "autodiscovery-topology",
        "title": "AutoDiscovery - Topologia de Rede & Infraestrutura",
        "tags": ["autodiscovery", "topologia", "noc", "zabbix"],
        "timezone": "browser",
        "refresh": "1m",
        "schemaVersion": 39,
        "editable": True,
        "time": {"from": "now-6h", "to": "now"},
        # WAN traffic reads raw history (trends off): slow at 7d, HTTP 500 at 30d
        "timepicker": {"quick_ranges": quick_ranges(MAX_RANGE)},
        "links": [
            {
                "title": "AutoDiscovery dashboards",
                "type": "dashboards",
                "tags": ["autodiscovery"],
                "asDropdown": True,
                "includeVars": False,
                "keepTime": True,
            }
        ],
        "templating": {"list": variables},
        "panels": panels,
    }
