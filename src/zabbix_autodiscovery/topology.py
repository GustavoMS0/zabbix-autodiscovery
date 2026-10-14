"""Generates an executive Network Topology & NOC command-center dashboard for Grafana.

Inspired by top-tier NOC topology dashboards (ECharts graph + WAN links + Infrastructure
health + Live alerts ticker). Uses the volkovlabs-echarts-panel plugin for interactive
path tracing and hardware hierarchy.
"""
import json

from .dashboards import (
    CPU,
    DS,
    MEM,
    OPER_STATUS_MAP,
    OPER_STATUS_STEPS,
    SDWAN_LATENCY,
    SDWAN_LOSS,
    TEMP,
    UPTIME,
    WAN_IN,
    WAN_OUT,
    WAN_STATUS,
    _alias,
    _replace_alias,
    _target,
    _top,
)


def _echarts_get_option():
    """JavaScript code string executed by volkovlabs-echarts-panel."""
    return r"""
// Apache ECharts Network Topology & Path Tracing for AutoDiscovery NOC
const seriesData = data.series || [];

// Node definitions (Coordinates system 0-1200 x, 0-800 y)
const nodes = [
  // --- TIER 0: Provedores / Internet (Y: 60) ---
  { id: 'inet-sp', name: 'Internet SP\n(Mega / America)', category: 'Internet', x: 500, y: 60, symbolSize: 52,
    itemStyle: { color: '#10b981', borderColor: '#34d399', borderWidth: 3, shadowBlur: 15, shadowColor: '#10b981' },
    ip: 'BGP / Multi-WAN', site: 'Matriz - Sede Principal', role: 'Link Primário 50M | Link Redundante 50M' },
  { id: 'inet-rj', name: 'Internet RJ\n(Easy / Int10)', category: 'Internet', x: 160, y: 60, symbolSize: 45,
    itemStyle: { color: '#10b981', borderColor: '#34d399', borderWidth: 2, shadowBlur: 10, shadowColor: '#10b981' },
    ip: 'Multi-WAN', site: 'Filial 1 (se houver)', role: 'Operadora A 50M | Operadora B 50M' },
  { id: 'inet-ba', name: 'Internet BA\n(Link Rádio / NetFiber)', category: 'Internet', x: 840, y: 60, symbolSize: 45,
    itemStyle: { color: '#10b981', borderColor: '#34d399', borderWidth: 2, shadowBlur: 10, shadowColor: '#10b981' },
    ip: 'Multi-WAN', site: 'Filial 2 (se houver)', role: 'Link Fibra 30M | Link Rádio 40M' },
  { id: 'inet-pr', name: 'Internet PR\n(SD-WAN)', category: 'Internet', x: 1080, y: 60, symbolSize: 45,
    itemStyle: { color: '#10b981', borderColor: '#34d399', borderWidth: 2, shadowBlur: 10, shadowColor: '#10b981' },
    ip: 'Multi-WAN', site: 'Filial 3 (se houver)', role: 'Link Dedicado SD-WAN | wan2' },

  // --- TIER 1: Firewalls FortiGate (Y: 180) ---
  { id: 'fw-sp', name: 'FW-SP (FortiGate)', category: 'Firewall', x: 500, y: 180, symbolSize: 58,
    itemStyle: { color: '#ef4444', borderColor: '#f87171', borderWidth: 3, shadowBlur: 18, shadowColor: '#ef4444' },
    ip: '192.168.0.4', site: 'Matriz - Sede Principal', role: 'Firewall Core / Hub SD-WAN' },
  { id: 'fw-rj', name: 'FW-RJ (FortiGate)', category: 'Firewall', x: 160, y: 180, symbolSize: 48,
    itemStyle: { color: '#ef4444', borderColor: '#f87171', borderWidth: 2, shadowBlur: 10, shadowColor: '#ef4444' },
    ip: '192.168.3.21', site: 'Filial 1 (se houver)', role: 'Firewall Filial / SD-WAN Spoke' },
  { id: 'fw-ba', name: 'FW-BA (FortiGate)', category: 'Firewall', x: 840, y: 180, symbolSize: 48,
    itemStyle: { color: '#ef4444', borderColor: '#f87171', borderWidth: 2, shadowBlur: 10, shadowColor: '#ef4444' },
    ip: '192.168.2.244', site: 'Filial 2 (se houver)', role: 'Firewall Filial / SD-WAN Spoke' },
  { id: 'fw-pr', name: 'FW-PR (FortiGate)', category: 'Firewall', x: 1080, y: 180, symbolSize: 48,
    itemStyle: { color: '#ef4444', borderColor: '#f87171', borderWidth: 2, shadowBlur: 10, shadowColor: '#ef4444' },
    ip: '192.168.1.2', site: 'Filial 3 (se houver)', role: 'Firewall Filial / SD-WAN Spoke' },

  // --- TIER 2: Switches Core & Distribuição (Y: 310) ---
  { id: 'sw-core-sp', name: 'Switch-Aruba\n192.168.0.22', category: 'Switch', x: 500, y: 310, symbolSize: 52,
    itemStyle: { color: '#3b82f6', borderColor: '#60a5fa', borderWidth: 3, shadowBlur: 15, shadowColor: '#3b82f6' },
    ip: '192.168.0.22', site: 'Matriz - Sede Principal', role: 'Core Switch / VLT Stacking' },
  { id: 'sw-sp-17', name: 'SW-17 (Dist)', category: 'Switch', x: 380, y: 410, symbolSize: 36,
    itemStyle: { color: '#2563eb' }, ip: '192.168.0.17', site: 'Matriz - Sede Principal', role: 'Switch Acesso' },
  { id: 'sw-sp-19', name: 'SW-19 (Dist)', category: 'Switch', x: 440, y: 410, symbolSize: 36,
    itemStyle: { color: '#2563eb' }, ip: '192.168.0.19', site: 'Matriz - Sede Principal', role: 'Switch Acesso' },
  { id: 'sw-sp-20', name: 'SW-20 (Dist)', category: 'Switch', x: 560, y: 410, symbolSize: 36,
    itemStyle: { color: '#2563eb' }, ip: '192.168.0.20', site: 'Matriz - Sede Principal', role: 'Switch Acesso' },
  { id: 'sw-sp-21', name: 'SW-21 (Dist)', category: 'Switch', x: 620, y: 410, symbolSize: 36,
    itemStyle: { color: '#2563eb' }, ip: '192.168.0.21', site: 'Matriz - Sede Principal', role: 'Switch Acesso' },
  { id: 'sw-core-rj', name: 'SW-Filial1-MikroTik', category: 'Switch', x: 160, y: 310, symbolSize: 42,
    itemStyle: { color: '#3b82f6' }, ip: '192.168.3.19', site: 'Filial 1 (se houver)', role: 'Core Switch RJ' },
  { id: 'sw-core-ba', name: 'SW-Core-Filial2', category: 'Switch', x: 840, y: 310, symbolSize: 42,
    itemStyle: { color: '#3b82f6' }, ip: '192.168.2.144', site: 'Filial 2 (se houver)', role: 'Core Switch BA' },

  // --- TIER 3: Infraestrutura, Nobreak & Hardware Dell (Y: 490) ---
  { id: 'ups-sp', name: 'Nobreak-Matriz', category: 'Nobreak UPS', x: 320, y: 310, symbolSize: 40,
    itemStyle: { color: '#eab308', borderColor: '#fde047', borderWidth: 2 },
    ip: '192.168.0.3', site: 'Matriz - Sede Principal', role: 'Nobreak Nobreak NHS Laser Senoidal' },
  { id: 'hw-sp-1', name: 'idrac-srv01', category: 'Hardware Servidor', x: 380, y: 500, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.0.224', site: 'Matriz - Sede Principal', role: 'Dell iDRAC Enterprise' },
  { id: 'hw-sp-2', name: 'idrac-srv02', category: 'Hardware Servidor', x: 440, y: 500, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.0.228', site: 'Matriz - Sede Principal', role: 'Dell iDRAC Enterprise' },
  { id: 'hw-sp-3', name: 'idrac-srv03', category: 'Hardware Servidor', x: 500, y: 500, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.0.226', site: 'Matriz - Sede Principal', role: 'Dell iDRAC Enterprise' },
  { id: 'hw-sp-4', name: 'idrac-srv04', category: 'Hardware Servidor', x: 560, y: 500, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.0.225', site: 'Matriz - Sede Principal', role: 'Dell iDRAC Enterprise' },
  { id: 'hw-sp-5', name: 'idrac-srv05', category: 'Hardware Servidor', x: 620, y: 500, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.0.227', site: 'Matriz - Sede Principal', role: 'Dell iDRAC Enterprise' },
  { id: 'hw-rj-1', name: 'idrac-filial01', category: 'Hardware Servidor', x: 160, y: 440, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.3.22', site: 'Filial 1 (se houver)', role: 'Dell iDRAC Enterprise' },
  { id: 'hw-ba-1', name: 'idrac-filial02', category: 'Hardware Servidor', x: 840, y: 440, symbolSize: 32,
    itemStyle: { color: '#a855f7' }, ip: '192.168.2.14', site: 'Filial 2 (se houver)', role: 'Dell iDRAC Enterprise' },

  // --- TIER 4: Hypervisors & Servidores (Y: 620) ---
  { id: 'vm-cluster-sp', name: 'Cluster Hypervisors SP\n(ASSEMBLY/DELPHI/CLIPPER)', category: 'Virtualização / Servidor', x: 500, y: 620, symbolSize: 45,
    itemStyle: { color: '#8b5cf6', borderColor: '#c4b5fd', borderWidth: 2 },
    ip: '192.168.0.x', site: 'Matriz - Sede Principal', role: '5 Hypervisors | VMs: NGINX, CS01, AD01/02' },
  { id: 'vm-rj-1', name: 'SRV-DC01 (RJ)', category: 'Virtualização / Servidor', x: 160, y: 540, symbolSize: 34,
    itemStyle: { color: '#8b5cf6' }, ip: '192.168.3.1', site: 'Filial 1 (se houver)', role: 'Domain Controller Filial' },
  { id: 'vm-ba-1', name: 'SRV-AD03 (BA)', category: 'Virtualização / Servidor', x: 840, y: 540, symbolSize: 34,
    itemStyle: { color: '#8b5cf6' }, ip: '192.168.2.4', site: 'Filial 2 (se houver)', role: 'Domain Controller Filial' },

  // --- TIER 5: Access Points Wi-Fi (Y: 740) ---
  { id: 'ap-sp', name: '5x APs Wi-Fi SP\n(TI/Com/Fin/Rec)', category: 'Access Point', x: 500, y: 740, symbolSize: 40,
    itemStyle: { color: '#f97316' }, ip: '192.168.0.40-44', site: 'Matriz - Sede Principal', role: '5x UniFi APs Corporativos' },
  { id: 'ap-rj', name: '5x APs Wi-Fi RJ\n(Galpões/Adm)', category: 'Access Point', x: 160, y: 660, symbolSize: 38,
    itemStyle: { color: '#f97316' }, ip: '192.168.3.107-116', site: 'Filial 1 (se houver)', role: '5x APs Galpão & Escritório' },
  { id: 'ap-ba', name: '6x APs Wi-Fi BA\n(Fábrica/Adm)', category: 'Access Point', x: 840, y: 660, symbolSize: 40,
    itemStyle: { color: '#f97316' }, ip: '192.168.2.47-52', site: 'Filial 2 (se houver)', role: '6x APs Fábrica & Armazém' }
];

// Connection links between elements
const links = [
  // Links de Internet -> Firewalls
  { source: 'inet-sp', target: 'fw-sp', label: { show: true, formatter: 'wan1(50M) / wan2(50M)' }, lineStyle: { width: 3.5, color: '#10b981' } },
  { source: 'inet-rj', target: 'fw-rj', label: { show: true, formatter: 'Int10 / Easy(50M)' }, lineStyle: { width: 3, color: '#10b981' } },
  { source: 'inet-ba', target: 'fw-ba', label: { show: true, formatter: 'Link Rádio(40M) / Net(30M)' }, lineStyle: { width: 3, color: '#10b981' } },
  { source: 'inet-pr', target: 'fw-pr', label: { show: true, formatter: 'SD-WAN / wan2' }, lineStyle: { width: 2.5, color: '#10b981' } },

  // Malha SD-WAN VPN Inter-filiais (linhas tracejadas com brilho)
  { source: 'fw-sp', target: 'fw-rj', label: { show: false }, lineStyle: { type: 'dashed', curveness: 0.22, color: '#06b6d4', width: 2.5 } },
  { source: 'fw-sp', target: 'fw-ba', label: { show: false }, lineStyle: { type: 'dashed', curveness: -0.22, color: '#06b6d4', width: 2.5 } },
  { source: 'fw-sp', target: 'fw-pr', label: { show: false }, lineStyle: { type: 'dashed', curveness: -0.35, color: '#06b6d4', width: 2 } },

  // Firewalls -> Switches Core
  { source: 'fw-sp', target: 'sw-core-sp', label: { show: true, formatter: '10 Gbps Trunk' }, lineStyle: { width: 4, color: '#3b82f6' } },
  { source: 'fw-rj', target: 'sw-core-rj', label: { show: true, formatter: '1 Gbps Uplink' }, lineStyle: { width: 3, color: '#3b82f6' } },
  { source: 'fw-ba', target: 'sw-core-ba', label: { show: true, formatter: '1 Gbps Uplink' }, lineStyle: { width: 3, color: '#3b82f6' } },

  // Nobreak alimentando infra de Core SP
  { source: 'ups-sp', target: 'sw-core-sp', label: { show: false }, lineStyle: { type: 'dotted', color: '#eab308', width: 2 } },
  { source: 'ups-sp', target: 'fw-sp', label: { show: false }, lineStyle: { type: 'dotted', color: '#eab308', width: 2 } },

  // Core SP -> Switches de Distribuição
  { source: 'sw-core-sp', target: 'sw-sp-17', lineStyle: { width: 2.5, color: '#60a5fa' } },
  { source: 'sw-core-sp', target: 'sw-sp-19', lineStyle: { width: 2.5, color: '#60a5fa' } },
  { source: 'sw-core-sp', target: 'sw-sp-20', lineStyle: { width: 2.5, color: '#60a5fa' } },
  { source: 'sw-core-sp', target: 'sw-sp-21', lineStyle: { width: 2.5, color: '#60a5fa' } },

  // Switches -> Servidores Físicos Dell iDRAC
  { source: 'sw-core-sp', target: 'hw-sp-1', lineStyle: { width: 2, color: '#a855f7' } },
  { source: 'sw-core-sp', target: 'hw-sp-2', lineStyle: { width: 2, color: '#a855f7' } },
  { source: 'sw-core-sp', target: 'hw-sp-3', lineStyle: { width: 2, color: '#a855f7' } },
  { source: 'sw-core-sp', target: 'hw-sp-4', lineStyle: { width: 2, color: '#a855f7' } },
  { source: 'sw-core-sp', target: 'hw-sp-5', lineStyle: { width: 2, color: '#a855f7' } },
  { source: 'sw-core-rj', target: 'hw-rj-1', lineStyle: { width: 2, color: '#a855f7' } },
  { source: 'sw-core-ba', target: 'hw-ba-1', lineStyle: { width: 2, color: '#a855f7' } },

  // Servidores Físicos -> Hypervisors / VMs
  { source: 'hw-sp-3', target: 'vm-cluster-sp', label: { show: true, formatter: 'VMware ESXi' }, lineStyle: { width: 3, color: '#8b5cf6' } },
  { source: 'hw-rj-1', target: 'vm-rj-1', lineStyle: { width: 2, color: '#8b5cf6' } },
  { source: 'hw-ba-1', target: 'vm-ba-1', lineStyle: { width: 2, color: '#8b5cf6' } },

  // Switches -> Access Points Wi-Fi
  { source: 'sw-sp-20', target: 'ap-sp', label: { show: true, formatter: 'PoE+' }, lineStyle: { width: 2.5, color: '#f97316' } },
  { source: 'sw-core-rj', target: 'ap-rj', label: { show: true, formatter: 'PoE+' }, lineStyle: { width: 2.5, color: '#f97316' } },
  { source: 'sw-core-ba', target: 'ap-ba', label: { show: true, formatter: 'PoE+' }, lineStyle: { width: 2.5, color: '#f97316' } }
];

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
        return `
          <div style="font-weight:bold;font-size:14px;color:${d.itemStyle?.color || '#38bdf8'};margin-bottom:6px;">
            ${d.name.replace('\n', ' ')}
          </div>
          <table style="font-size:12px;line-height:1.6;color:#cbd5e1;">
            <tr><td><b>Categoria:</b></td><td style="padding-left:8px;">${d.category}</td></tr>
            <tr><td><b>Endereço IP:</b></td><td style="padding-left:8px;font-family:monospace;color:#38bdf8;">${d.ip}</td></tr>
            <tr><td><b>Localidade:</b></td><td style="padding-left:8px;">${d.site}</td></tr>
            <tr><td><b>Papel / Detalhe:</b></td><td style="padding-left:8px;">${d.role}</td></tr>
            <tr><td><b>Status:</b></td><td style="padding-left:8px;"><span style="color:#22c55e;font-weight:bold;">● ONLINE</span></td></tr>
          </table>
          <div style="margin-top:6px;font-size:10px;color:#94a3b8;border-top:1px solid #334155;padding-top:4px;">
            Dica: Passe o mouse para destacar o caminho completo até a borda
          </div>
        `;
      } else if (params.dataType === 'edge') {
        const d = params.data;
        return `
          <div style="font-weight:bold;margin-bottom:4px;color:#38bdf8;">Conexão de Enlace</div>
          <div><b>Origem:</b> ${d.source}</div>
          <div><b>Destino:</b> ${d.target}</div>
          <div><b>Info:</b> ${d.label?.formatter || 'Enlace LAN/WAN Ativo'}</div>
        `;
      }
    }
  },
  legend: [{
    data: ['Internet', 'Firewall', 'Switch', 'Hardware Servidor', 'Virtualização / Servidor', 'Access Point', 'Nobreak UPS'],
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
    categories: [
      { name: 'Internet', itemStyle: { color: '#10b981' } },
      { name: 'Firewall', itemStyle: { color: '#ef4444' } },
      { name: 'Switch', itemStyle: { color: '#3b82f6' } },
      { name: 'Hardware Servidor', itemStyle: { color: '#a855f7' } },
      { name: 'Virtualização / Servidor', itemStyle: { color: '#8b5cf6' } },
      { name: 'Access Point', itemStyle: { color: '#f97316' } },
      { name: 'Nobreak UPS', itemStyle: { color: '#eab308' } }
    ],
    nodes: nodes,
    links: links
  }]
};
""".strip()


def build_topology_dashboard(datasource_uid="zabbix"):
    """Constructs the complete AutoDiscovery Topologia & NOC dashboard."""
    ds = {"type": DS["type"], "uid": "${datasource}"}

    # Top KPI Row (y=0, h=3)
    kpi_summary = {
        "id": 1,
        "type": "stat",
        "title": "Infraestrutura Global - Visão Executiva",
        "gridPos": {"x": 0, "y": 0, "w": 24, "h": 3},
        "datasource": ds,
        "targets": [_target("ICMP ping", [_alias("$__zbx_host_name")])],
        "options": {
            "reduceOptions": {"calcs": ["count"], "values": False, "fields": ""},
            "orientation": "horizontal",
            "textMode": "value_and_name",
            "colorMode": "background",
            "graphMode": "none",
            "wideLayout": False,
        },
        "fieldConfig": {
            "defaults": {
                "unit": "none",
                "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]},
            },
            "overrides": [],
        },
    }

    # Left Column: Links WAN & Conectividade (x=0, y=3, w=5, h=21)
    wan_status_panel = {
        "id": 2,
        "type": "stat",
        "title": "Links de Internet & Provedores",
        "gridPos": {"x": 0, "y": 3, "w": 5, "h": 11},
        "datasource": ds,
        "targets": [
            _target(
                WAN_STATUS["re"],
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/^(?:Interface\s+)?([^:]+):\s+Operational status$/i", "$__zbx_host_name - $1"),
                ],
            )
        ],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
            "orientation": "horizontal",
            "textMode": "value_and_name",
            "colorMode": "background",
            "graphMode": "none",
            "wideLayout": False,
        },
        "fieldConfig": {
            "defaults": {
                "mappings": OPER_STATUS_MAP,
                "thresholds": {"mode": "absolute", "steps": OPER_STATUS_STEPS},
            },
            "overrides": [],
        },
    }

    wan_traffic_panel = {
        "id": 3,
        "type": "timeseries",
        "title": "Tráfego Internet WAN (Top Links)",
        "gridPos": {"x": 0, "y": 14, "w": 5, "h": 10},
        "datasource": ds,
        "targets": [
            _target(
                WAN_IN["re"],
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/^(?:Interface\s+)?([^:]+):\s+Bits received$/i", "$__zbx_host_name: $1 (In)"),
                    _top(5),
                ],
                ref="A",
            ),
            _target(
                WAN_OUT["re"],
                [
                    _alias("$__zbx_host_name: $__zbx_item"),
                    _replace_alias(r"/^(?:Interface\s+)?([^:]+):\s+Bits sent$/i", "$__zbx_host_name: $1 (Out)"),
                    _top(5),
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
    echarts_panel = {
        "id": 4,
        "type": "volkovlabs-echarts-panel",
        "title": "Mapa de Topologia e Conectividade de Rede",
        "gridPos": {"x": 5, "y": 3, "w": 14, "h": 21},
        "datasource": ds,
        "targets": [
            _target("ICMP ping", [_alias("$__zbx_host_name")]),
        ],
        "options": {
            "renderer": "canvas",
            "editor": {"height": 600, "format": "auto"},
            "getOption": _echarts_get_option(),
        },
    }

    # Right Column: Infraestrutura, Computação & Virtualização (x=19, y=3, w=5, h=21)
    virt_panel = {
        "id": 5,
        "type": "stat",
        "title": "Virtualização & Servidores",
        "gridPos": {"x": 19, "y": 3, "w": 5, "h": 7},
        "datasource": ds,
        "targets": [
            _target(
                r"/ICMP ping/",
                [_alias("$__zbx_host_name")],
                ref="A",
            )
        ],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
            "orientation": "horizontal",
            "textMode": "value_and_name",
            "colorMode": "background",
            "graphMode": "none",
            "wideLayout": False,
        },
        "fieldConfig": {
            "defaults": {
                "mappings": [
                    {"type": "value", "options": {"0": {"text": "OFF", "color": "red"}, "1": {"text": "ON", "color": "green"}}}
                ],
                "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]},
            },
            "overrides": [],
        },
    }

    firewall_health_panel = {
        "id": 6,
        "type": "stat",
        "title": "Firewalls FortiGate - CPU & Sessões",
        "gridPos": {"x": 19, "y": 10, "w": 5, "h": 7},
        "datasource": ds,
        "targets": [
            _target(
                r"/((cpu|processor).*(utilization|usage)|utiliza[cç][aã]o.*cpu)/i",
                [_alias("$__zbx_host_name: CPU")],
                ref="A",
            ),
            _target(
                r"/session/i",
                [_alias("$__zbx_host_name: Sessões")],
                ref="B",
            ),
        ],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
            "orientation": "horizontal",
            "textMode": "value_and_name",
            "colorMode": "background",
            "graphMode": "none",
            "wideLayout": False,
        },
        "fieldConfig": {
            "defaults": {
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "orange", "value": 70},
                        {"color": "red", "value": 85},
                    ],
                }
            },
            "overrides": [],
        },
    }

    hardware_panel = {
        "id": 7,
        "type": "stat",
        "title": "Hardware Físico (Dell iDRAC & UPS)",
        "gridPos": {"x": 19, "y": 17, "w": 5, "h": 7},
        "datasource": ds,
        "targets": [
            _target(
                TEMP["re"],
                [_alias("$__zbx_host_name: Temp"), _top(3)],
                ref="A",
            ),
        ],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "values": False, "fields": ""},
            "orientation": "horizontal",
            "textMode": "value_and_name",
            "colorMode": "background",
            "graphMode": "none",
            "wideLayout": False,
        },
        "fieldConfig": {
            "defaults": {
                "unit": "celsius",
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "orange", "value": 45},
                        {"color": "red", "value": 60},
                    ],
                },
            },
            "overrides": [],
        },
    }

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
                "group": {"filter": "/.*/"},
                "host": {"filter": "/.*/"},
                "application": {"filter": ""},
                "proxy": {"filter": ""},
                "trigger": {"filter": ""},
                "tags": {"filter": ""},
                "showProblems": "problems",
                "options": {
                    "minSeverity": 1,
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
            "pageSize": 5,
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
            "name": "site",
            "label": "Filial / Sede",
            "type": "custom",
            "options": [
                {"text": "Todas as Filiais (Global)", "value": "all", "selected": True},
                {"text": "Matriz - Sede Principal", "value": "Matriz", "selected": False},
                {"text": "Filial 1 (se houver)", "value": "RJ", "selected": False},
                {"text": "Filial 2 (se houver)", "value": "BA", "selected": False},
                {"text": "Filial 3 (se houver)", "value": "PR", "selected": False},
            ],
            "current": {"text": "Todas as Filiais (Global)", "value": "all"},
            "query": "Todas as Filiais (Global) : all, Matriz - Sede Principal : Matriz, Filial 1 (se houver) : RJ, Filial 2 (se houver) : BA, Filial 3 (se houver) : PR",
            "multi": False,
            "includeAll": False,
            "hide": 0,
        },
    ]

    return {
        "uid": "autodiscovery-topology",
        "title": "AutoDiscovery - Topologia de Rede & Infraestrutura",
        "tags": ["autodiscovery", "topologia", "noc", "zabbix"],
        "timezone": "browser",
        "refresh": "30s",
        "schemaVersion": 39,
        "editable": True,
        "time": {"from": "now-6h", "to": "now"},
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
