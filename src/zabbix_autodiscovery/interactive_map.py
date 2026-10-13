"""Interactive HTML5 network topology map with zoom, pan, search and NOC inspection.

Generates a standalone, responsive web application powered by Vis-Network:
- Smooth continuous mouse-wheel zoom & canvas pan
- Multi-site filtering (all sites or individual branch)
- Real-time search with camera auto-focus & zoom
- Category filtering (switches, firewalls, servers, APs, peripherals)
- Slide-out details drawer with active Zabbix triggers and direct deep links
- Dual layout mode: Fixed 4-Tier NOC Layout vs. Dynamic Physics Force Simulation
- Embedded dark NOC theme ready for wallboards or local browser inspection
"""
import http.server
import json
import socketserver
import threading
import webbrowser
from collections import Counter
from pathlib import Path

from .inventory import hypervisor_hostids, network_hosts
from .maps import infer_links, layout, vendor_of


def get_active_problems_by_host(api):
    """Map hostid -> list of active triggers with priority."""
    try:
        triggers = api.call("trigger.get", {
            "filter": {"value": 1},
            "output": ["triggerid", "description", "priority"],
            "selectHosts": ["hostid"],
            "monitored": True,
            "skipDependent": True,
        })
    except Exception:
        return {}

    problems = {}
    for t in triggers:
        for h in t.get("hosts", []):
            hid = h["hostid"]
            problems.setdefault(hid, []).append({
                "triggerid": t["triggerid"],
                "description": t["description"],
                "priority": int(t.get("priority", 0)),
            })
    return problems


def build_topology_dataset(api, cfg, selected_site=None):
    """Build nodes and edges compatible with Vis-Network from Zabbix inventory."""
    sites_cfg = cfg.get("_sites") or []
    if not sites_cfg:
        sites_cfg = [{"network": n, "site": n} for n in cfg.get("scan", {}).get("networks", [])]

    if selected_site:
        sites_cfg = [s for s in sites_cfg if s.get("site", "").lower() == selected_site.lower()]

    problems_map = get_active_problems_by_host(api)

    all_nodes = []
    all_edges = []
    seen_nodes = set()
    site_names = []

    # Category styling metadata
    cat_badges = {
        "firewall": ("🛡️", "#dc2626"),
        "router": ("🧭", "#ea580c"),
        "switch": ("🔀", "#2563eb"),
        "ap": ("📶", "#0284c7"),
        "server-hardware": ("🖥️", "#7c3aed"),
        "server-windows": ("🪟", "#0284c7"),
        "server-linux": ("🐧", "#059669"),
        "hypervisor": ("📦", "#9333ea"),
        "storage": ("💾", "#0891b2"),
        "ups": ("🔋", "#d97706"),
        "pdu": ("⚡", "#ca8a04"),
        "printer": ("🖨️", "#64748b"),
        "cctv": ("📷", "#475569"),
        "voip": ("📞", "#0d9488"),
        "network-generic": ("🌐", "#4b5563"),
        "other": ("⚙️", "#4b5563"),
    }

    # Offset each site horizontally in global view so sites don't overlap
    global_x_offset = 0

    for site_info in sites_cfg:
        site_name = site_info.get("site") or site_info.get("network")
        network = site_info.get("network")
        site_names.append(site_name)

        hosts = site_hosts_list(api, network)
        if not hosts:
            continue

        hyp_ids = hypervisor_hostids(api, [h["hostid"] for h in hosts])
        placed, width, height = layout(hosts, hyp_ids)
        if not placed:
            continue

        selements = [{"selementid": str(i + 1), "elements": [{"hostid": p[0]["hostid"]}]}
                     for i, p in enumerate(placed)]
        links = infer_links(placed, selements)

        selem_to_host = {s["selementid"]: s["elements"][0]["hostid"] for s in selements}

        # Add Nodes
        for h, cat, lx, ly in placed:
            hid = str(h["hostid"])
            if hid in seen_nodes:
                continue
            seen_nodes.add(hid)

            ip = next((iface["ip"] for iface in h.get("interfaces", []) if iface.get("ip")), "")
            probs = problems_map.get(hid, [])
            max_priority = max((p["priority"] for p in probs), default=-1)

            # Severity: 0=Not classified, 1=Info, 2=Warn, 3=Avg, 4=High, 5=Disaster
            if max_priority >= 4:
                status_color = "#ef4444"
                status_label = "CRÍTICO"
            elif max_priority >= 2:
                status_color = "#f59e0b"
                status_label = "ALERTA"
            elif max_priority >= 0:
                status_color = "#3b82f6"
                status_label = "INFO"
            else:
                status_color = "#10b981"
                status_label = "OPERACIONAL"

            icon, badge_col = cat_badges.get(cat, ("💻", "#4b5563"))

            all_nodes.append({
                "id": hid,
                "label": f"{h['name']}\n{ip}",
                "name": h["name"],
                "ip": ip,
                "site": site_name,
                "category": cat,
                "vendor": vendor_of(h) or "Desconhecido",
                "status": status_label,
                "status_color": status_color,
                "max_priority": max_priority,
                "problems": [p["description"] for p in probs],
                "x": lx + global_x_offset,
                "y": ly,
                "icon": icon,
                "badge_col": badge_col,
            })

        # Add Edges
        for link in links:
            source_hid = selem_to_host.get(link["selementid1"])
            target_hid = selem_to_host.get(link["selementid2"])
            if not source_hid or not target_hid:
                continue

            hex_col = "#" + link.get("color", "3b82f6").lstrip("#")
            drawtype = link.get("drawtype", 0)
            all_edges.append({
                "from": source_hid,
                "to": target_hid,
                "color": hex_col,
                "width": 3 if drawtype == 2 else 2,
                "dashes": drawtype == 1,
            })

        global_x_offset += width + 200

    stats = {
        "total": len(all_nodes),
        "ok": sum(1 for n in all_nodes if n["status"] == "OPERACIONAL"),
        "warning": sum(1 for n in all_nodes if n["status"] in ("ALERTA", "INFO")),
        "disaster": sum(1 for n in all_nodes if n["status"] == "CRÍTICO"),
        "categories": dict(Counter(n["category"] for n in all_nodes)),
        "sites": site_names,
    }

    return {
        "nodes": all_nodes,
        "edges": all_edges,
        "stats": stats,
    }


def site_hosts_list(api, network):
    return network_hosts(api, [network])


def generate_interactive_html(dataset, zabbix_url):
    """Return self-contained HTML page with interactive Vis-Network visualization."""
    data_json = json.dumps(dataset, ensure_ascii=False)
    zabbix_base = zabbix_url.rstrip("/")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AutoDiscovery NOC - Topologia de Rede Interativa</title>
  <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {{
      --bg-main: #0b0f19;
      --bg-panel: rgba(17, 24, 39, 0.88);
      --border-panel: rgba(55, 65, 81, 0.6);
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --color-green: #10b981;
      --color-yellow: #f59e0b;
      --color-red: #ef4444;
      --color-blue: #3b82f6;
      --color-accent: #6366f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      overflow: hidden;
      width: 100vw;
      height: 100vh;
    }}
    #network-canvas {{
      width: 100vw;
      height: 100vh;
      position: absolute;
      top: 0;
      left: 0;
      z-index: 1;
    }}
    /* Top Bar */
    .top-bar {{
      position: absolute;
      top: 16px;
      left: 20px;
      right: 20px;
      z-index: 10;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      pointer-events: none;
    }}
    .panel-card {{
      background: var(--bg-panel);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border-panel);
      border-radius: 12px;
      padding: 10px 16px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
      pointer-events: auto;
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .brand-title {{
      font-weight: 700;
      font-size: 15px;
      letter-spacing: 0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .brand-title span {{
      color: var(--color-green);
    }}
    select, input, button {{
      background: #1f2937;
      color: #fff;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 13px;
      outline: none;
      transition: all 0.2s ease;
    }}
    select:hover, input:hover, button:hover {{
      border-color: #60a5fa;
    }}
    button {{
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 500;
    }}
    button:active {{
      transform: scale(0.97);
    }}
    .btn-primary {{
      background: #3b82f6;
      border-color: #2563eb;
    }}
    .btn-primary:hover {{
      background: #2563eb;
    }}
    /* Search Box */
    .search-wrapper {{
      position: relative;
    }}
    .search-input {{
      width: 220px;
    }}
    .search-results {{
      position: absolute;
      top: 110%;
      left: 0;
      width: 100%;
      background: #1f2937;
      border: 1px solid #374151;
      border-radius: 8px;
      max-height: 240px;
      overflow-y: auto;
      display: none;
      box-shadow: 0 8px 16px rgba(0,0,0,0.5);
      z-index: 50;
    }}
    .search-item {{
      padding: 8px 12px;
      font-size: 12px;
      cursor: pointer;
      border-bottom: 1px solid #374151;
    }}
    .search-item:hover {{
      background: #374151;
    }}
    /* Floating Zoom Controls */
    .zoom-controls {{
      position: absolute;
      bottom: 24px;
      left: 20px;
      z-index: 10;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .zoom-btn {{
      width: 40px;
      height: 40px;
      border-radius: 10px;
      justify-content: center;
      font-size: 18px;
      padding: 0;
    }}
    /* Bottom Stats Pill */
    .bottom-stats {{
      position: absolute;
      bottom: 24px;
      right: 20px;
      z-index: 10;
      font-size: 12px;
    }}
    .stat-badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin-right: 10px;
    }}
    .dot {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }}
    .dot-green {{ background: var(--color-green); }}
    .dot-yellow {{ background: var(--color-yellow); }}
    .dot-red {{ background: var(--color-red); animation: pulse 1.5s infinite; }}
    @keyframes pulse {{
      0% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }}
      70% {{ box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); }}
      100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
    }}
    /* Sidebar Details Drawer */
    .drawer {{
      position: absolute;
      top: 16px;
      right: 20px;
      bottom: 80px;
      width: 360px;
      background: var(--bg-panel);
      backdrop-filter: blur(14px);
      border: 1px solid var(--border-panel);
      border-radius: 14px;
      z-index: 20;
      padding: 20px;
      display: none;
      flex-direction: column;
      box-shadow: -10px 0 30px rgba(0, 0, 0, 0.6);
      transform: translateX(380px);
      transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .drawer.open {{
      display: flex;
      transform: translateX(0);
    }}
    .drawer-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid #374151;
      padding-bottom: 12px;
      margin-bottom: 16px;
    }}
    .drawer-title {{
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      word-break: break-all;
    }}
    .drawer-close {{
      background: none;
      border: none;
      font-size: 18px;
      cursor: pointer;
      color: var(--text-muted);
      padding: 2px 6px;
    }}
    .drawer-close:hover {{
      color: #fff;
    }}
    .info-row {{
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      font-size: 13px;
      border-bottom: 1px dashed rgba(55, 65, 81, 0.5);
    }}
    .info-label {{
      color: var(--text-muted);
    }}
    .info-val {{
      font-weight: 600;
    }}
    .problem-box {{
      margin-top: 16px;
      flex: 1;
      overflow-y: auto;
    }}
    .problem-title {{
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: #f87171;
      margin-bottom: 8px;
    }}
    .problem-item {{
      background: rgba(239, 68, 68, 0.12);
      border-left: 3px solid var(--color-red);
      padding: 8px 10px;
      font-size: 12px;
      margin-bottom: 6px;
      border-radius: 4px;
    }}
    .drawer-actions {{
      margin-top: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .drawer-actions a {{
      text-decoration: none;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 9px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 8px;
      text-align: center;
      transition: background 0.2s;
    }}
    .btn-zabbix {{
      background: #dc2626;
      color: #fff;
    }}
    .btn-zabbix:hover {{
      background: #b91c1c;
    }}
    .btn-charts {{
      background: #2563eb;
      color: #fff;
    }}
    .btn-charts:hover {{
      background: #1d4ed8;
    }}
  </style>
</head>
<body>
  <div id="network-canvas"></div>

  <!-- Top Controls -->
  <div class="top-bar">
    <div class="panel-card">
      <div class="brand-title">🌐 AutoDiscovery <span>NOC</span></div>

      <!-- Site Filter -->
      <select id="site-select">
        <option value="all">Todas as Filiais</option>
      </select>

      <!-- Category Filter -->
      <select id="cat-select">
        <option value="all">Todas as Categorias</option>
        <option value="switch">Switches</option>
        <option value="firewall">Firewalls</option>
        <option value="router">Roteadores</option>
        <option value="server">Servidores & VMs</option>
        <option value="ap">Access Points</option>
        <option value="periph">Periféricos & Outros</option>
      </select>

      <!-- Layout Mode -->
      <select id="layout-select">
        <option value="fixed">📐 Layout Hierárquico NOC</option>
        <option value="physics">⚛️ Física Dinâmica (Livre)</option>
      </select>
    </div>

    <div class="panel-card">
      <!-- Search -->
      <div class="search-wrapper">
        <input type="text" id="search-input" class="search-input"
               placeholder="🔍 Buscar Host ou IP..." autocomplete="off">
        <div id="search-results" class="search-results"></div>
      </div>
      <button id="btn-fullscreen" title="Tela Cheia">⛶ Tela Cheia</button>
    </div>
  </div>

  <!-- Floating Zoom Controls -->
  <div class="zoom-controls">
    <button class="zoom-btn" id="btn-zoom-in" title="Aproximar">+</button>
    <button class="zoom-btn" id="btn-zoom-out" title="Afastar">-</button>
    <button class="zoom-btn" id="btn-fit" title="Ajustar à Tela">🎯</button>
    <button class="zoom-btn" id="btn-reset" title="Centralizar Origem">🔄</button>
  </div>

  <!-- Bottom Stats -->
  <div class="bottom-stats panel-card">
    <div class="stat-badge"><span class="dot dot-green"></span> <span id="stat-ok">0</span> Operacionais</div>
    <div class="stat-badge"><span class="dot dot-yellow"></span> <span id="stat-warn">0</span> Alertas</div>
    <div class="stat-badge"><span class="dot dot-red"></span> <span id="stat-disaster">0</span> Críticos</div>
    <div class="stat-badge" style="color: var(--text-muted); margin-left: 8px;">
      Total: <strong id="stat-total" style="color:#fff;">0</strong> hosts
    </div>
  </div>

  <!-- Drawer Details -->
  <div class="drawer" id="device-drawer">
    <div class="drawer-header">
      <div>
        <div id="drawer-name" class="drawer-title">Host Name</div>
        <div id="drawer-category" style="font-size: 12px; color: #9ca3af; margin-top: 2px;">Categoria</div>
      </div>
      <button class="drawer-close" id="drawer-close-btn">&times;</button>
    </div>

    <div class="info-row">
      <span class="info-label">Endereço IP</span>
      <span class="info-val" id="drawer-ip">-</span>
    </div>
    <div class="info-row">
      <span class="info-label">Filial / Site</span>
      <span class="info-val" id="drawer-site">-</span>
    </div>
    <div class="info-row">
      <span class="info-label">Fabricante</span>
      <span class="info-val" id="drawer-vendor">-</span>
    </div>
    <div class="info-row">
      <span class="info-label">Status NOC</span>
      <span class="info-val" id="drawer-status">-</span>
    </div>

    <div class="problem-box">
      <div class="problem-title" id="problem-header">Alarmes Ativos</div>
      <div id="problem-list">
        <div style="color: #6b7280; font-size: 12px;">Nenhum alarme ativo. Dispositivo saudável.</div>
      </div>
    </div>

    <div class="drawer-actions">
      <a id="btn-open-zabbix" href="#" target="_blank" class="btn-zabbix">🚨 Abrir Problemas no Zabbix</a>
      <a id="btn-open-charts" href="#" target="_blank" class="btn-charts">📊 Visualizar Gráficos de Tráfego</a>
    </div>
  </div>

  <script id="topology-data" type="application/json">
    {data_json}
  </script>

  <script>
    const dataset = JSON.parse(document.getElementById('topology-data').textContent);
    const zabbixBase = "{zabbix_base}";

    let network = null;
    let rawNodes = dataset.nodes || [];
    let rawEdges = dataset.edges || [];
    let visNodes = new vis.DataSet();
    let visEdges = new vis.DataSet();

    // Populate sites in dropdown
    const siteSelect = document.getElementById('site-select');
    (dataset.stats.sites || []).forEach(site => {{
      const opt = document.createElement('option');
      opt.value = site;
      opt.textContent = site;
      siteSelect.appendChild(opt);
    }});

    // Populate Stats
    document.getElementById('stat-ok').textContent = dataset.stats.ok || 0;
    document.getElementById('stat-warn').textContent = dataset.stats.warning || 0;
    document.getElementById('stat-disaster').textContent = dataset.stats.disaster || 0;
    document.getElementById('stat-total').textContent = dataset.stats.total || 0;

    function buildVisNodes(filterSite = 'all', filterCat = 'all') {{
      const filtered = rawNodes.filter(n => {{
        if (filterSite !== 'all' && n.site !== filterSite) return false;
        if (filterCat !== 'all') {{
          const srvCats = ['server-windows', 'server-linux', 'hypervisor', 'server-hardware'];
          if (filterCat === 'server' && !srvCats.includes(n.category)) return false;
          const coreCats = ['switch', 'firewall', 'router', 'ap', ...srvCats];
          if (filterCat === 'periph' && coreCats.includes(n.category)) return false;
          if (filterCat !== 'server' && filterCat !== 'periph' && n.category !== filterCat) return false;
        }}
        return true;
      }});

      const nodes = filtered.map(n => {{
        return {{
          id: n.id,
          label: `<b>${{n.name}}</b>\\n${{n.ip}}`,
          x: n.x,
          y: n.y,
          shape: 'box',
          margin: {{ top: 10, bottom: 10, left: 14, right: 14 }},
          borderWidth: n.status === 'CRÍTICO' ? 3 : (n.status === 'ALERTA' ? 2 : 1.5),
          color: {{
            background: '#111827',
            border: n.status_color,
            highlight: {{ background: '#1f2937', border: '#38bdf8' }},
            hover: {{ background: '#1f2937', border: '#60a5fa' }}
          }},
          font: {{
            color: '#f9fafb',
            size: 12,
            face: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif',
            multi: 'html'
          }},
          shadow: {{
            enabled: true,
            color: n.status === 'CRÍTICO' ? 'rgba(239, 68, 68, 0.6)' : 'rgba(0, 0, 0, 0.4)',
            size: n.status === 'CRÍTICO' ? 14 : 6,
            x: 0,
            y: 3
          }},
          data: n
        }};
      }});

      const nodeIds = new Set(nodes.map(n => n.id));
      const edges = rawEdges.filter(e => nodeIds.has(e.from) && nodeIds.has(e.to)).map((e, idx) => {{
        return {{
          id: 'edge_' + idx,
          from: e.from,
          to: e.to,
          color: {{ color: e.color, highlight: '#38bdf8', hover: '#60a5fa' }},
          width: e.width,
          dashes: e.dashes,
          smooth: {{ type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.25 }}
        }};
      }});

      visNodes.clear();
      visNodes.add(nodes);
      visEdges.clear();
      visEdges.add(edges);
    }}

    function initNetwork(physicsEnabled = false) {{
      const container = document.getElementById('network-canvas');
      const data = {{ nodes: visNodes, edges: visEdges }};
      const options = {{
        physics: {{
          enabled: physicsEnabled,
          solver: 'forceAtlas2Based',
          forceAtlas2Based: {{
            gravitationalConstant: -70,
            centralGravity: 0.01,
            springLength: 120,
            springConstant: 0.08
          }}
        }},
        interaction: {{
          hover: true,
          tooltipDelay: 150,
          navigationButtons: false,
          keyboard: true,
          zoomView: true,
          dragView: true
        }}
      }};

      network = new vis.Network(container, data, options);

      network.on('click', function(params) {{
        if (params.nodes.length > 0) {{
          const nodeId = params.nodes[0];
          const node = visNodes.get(nodeId);
          if (node && node.data) {{
            showDrawer(node.data);
          }}
        }} else {{
          hideDrawer();
        }}
      }});
    }}

    // Initial setup
    buildVisNodes('all', 'all');
    initNetwork(false);
    setTimeout(() => network.fit({{ animation: {{ duration: 600 }} }}), 300);

    // Filter Listeners
    siteSelect.addEventListener('change', () => {{
      buildVisNodes(siteSelect.value, document.getElementById('cat-select').value);
      setTimeout(() => network.fit({{ animation: {{ duration: 500 }} }}), 100);
    }});

    document.getElementById('cat-select').addEventListener('change', () => {{
      buildVisNodes(siteSelect.value, document.getElementById('cat-select').value);
      setTimeout(() => network.fit({{ animation: {{ duration: 500 }} }}), 100);
    }});

    document.getElementById('layout-select').addEventListener('change', (e) => {{
      const usePhysics = (e.target.value === 'physics');
      network.setOptions({{ physics: {{ enabled: usePhysics }} }});
      if (!usePhysics) {{
        // Reset fixed positions
        visNodes.forEach(n => {{
          if (n.data) {{
            visNodes.update({{ id: n.id, x: n.data.x, y: n.data.y }});
          }}
        }});
        network.fit();
      }}
    }});

    // Drawer Controls
    const drawer = document.getElementById('device-drawer');
    function showDrawer(data) {{
      document.getElementById('drawer-name').textContent = data.name;
      document.getElementById('drawer-category').textContent = data.icon + ' ' + data.category.toUpperCase();
      document.getElementById('drawer-ip').textContent = data.ip || 'Sem IP';
      document.getElementById('drawer-site').textContent = data.site;
      document.getElementById('drawer-vendor').textContent = data.vendor;

      const stEl = document.getElementById('drawer-status');
      stEl.textContent = data.status;
      stEl.style.color = data.status_color;

      const pList = document.getElementById('problem-list');
      pList.innerHTML = '';
      if (data.problems && data.problems.length > 0) {{
        document.getElementById('problem-header').textContent = `Alarmes Ativos (${{data.problems.length}})`;
        data.problems.forEach(p => {{
          const div = document.createElement('div');
          div.className = 'problem-item';
          div.textContent = '⚠️ ' + p;
          pList.appendChild(div);
        }});
      }} else {{
        document.getElementById('problem-header').textContent = 'Alarmes Ativos (0)';
        pList.innerHTML = '<div style="color: #10b981; font-size: 12px;">' +
                          '✅ Nenhum alarme ativo. Dispositivo saudável.</div>';
      }}

      // Zabbix Links
      const zbxProb = `${{zabbixBase}}/zabbix.php?action=problem.view&hostids[]=${{data.id}}`;
      const zbxChart = `${{zabbixBase}}/zabbix.php?action=charts.view&filter_hostids[]=${{data.id}}`;
      document.getElementById('btn-open-zabbix').href = zbxProb;
      document.getElementById('btn-open-charts').href = zbxChart;

      drawer.classList.add('open');
    }}

    function hideDrawer() {{
      drawer.classList.remove('open');
    }}
    document.getElementById('drawer-close-btn').addEventListener('click', hideDrawer);

    // Zoom and Pan Handlers
    document.getElementById('btn-zoom-in').addEventListener('click', () => {{
      const scale = network.getScale() * 1.35;
      network.moveTo({{ scale: scale, animation: {{ duration: 250 }} }});
    }});
    document.getElementById('btn-zoom-out').addEventListener('click', () => {{
      const scale = network.getScale() / 1.35;
      network.moveTo({{ scale: scale, animation: {{ duration: 250 }} }});
    }});
    document.getElementById('btn-fit').addEventListener('click', () => {{
      network.fit({{ animation: {{ duration: 400 }} }});
    }});
    document.getElementById('btn-reset').addEventListener('click', () => {{
      visNodes.forEach(n => {{
        if (n.data) visNodes.update({{ id: n.id, x: n.data.x, y: n.data.y }});
      }});
      network.fit({{ animation: {{ duration: 400 }} }});
    }});

    // Fullscreen Toggle
    document.getElementById('btn-fullscreen').addEventListener('click', () => {{
      if (!document.fullscreenElement) {{
        document.documentElement.requestFullscreen().catch(() => {{}});
      }} else {{
        document.exitFullscreen();
      }}
    }});

    // Search Autocomplete & Focus
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');

    searchInput.addEventListener('input', (e) => {{
      const q = e.target.value.toLowerCase().trim();
      searchResults.innerHTML = '';
      if (!q) {{
        searchResults.style.display = 'none';
        return;
      }}
      const matches = rawNodes.filter(n => n.name.toLowerCase().includes(q) || n.ip.includes(q)).slice(0, 8);
      if (matches.length === 0) {{
        searchResults.style.display = 'none';
        return;
      }}
      matches.forEach(m => {{
        const item = document.createElement('div');
        item.className = 'search-item';
        item.innerHTML = `<strong>${{m.name}}</strong> <span style="color:#9ca3af">(${{m.ip}})</span>`;
        item.addEventListener('click', () => {{
          searchResults.style.display = 'none';
          searchInput.value = m.name;
          focusNode(m.id);
        }});
        searchResults.appendChild(item);
      }});
      searchResults.style.display = 'block';
    }});

    function focusNode(id) {{
      network.selectNodes([id]);
      network.focus(id, {{
        scale: 1.4,
        animation: {{ duration: 700, easingFunction: 'easeInOutQuad' }}
      }});
      const node = visNodes.get(id);
      if (node && node.data) {{
        showDrawer(node.data);
      }}
    }}

    document.addEventListener('click', (e) => {{
      if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {{
        searchResults.style.display = 'none';
      }}
    }});
  </script>
</body>
</html>"""
    return html


def export_interactive_map(api, cfg, output_file="topology.html", selected_site=None, log=print):
    """Generate and write standalone interactive HTML map to disk."""
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dataset = build_topology_dataset(api, cfg, selected_site=selected_site)
    zabbix_url = cfg.get("zabbix", {}).get("url", "http://localhost:8080")
    html = generate_interactive_html(dataset, zabbix_url)
    out_path.write_text(html, encoding="utf-8")
    log(f"Mapa interativo gerado com sucesso em: {out_path.resolve()}")
    log(f"  - Total de nós: {dataset['stats']['total']}")
    log(f"  - Operacionais: {dataset['stats']['ok']}")
    log(f"  - Em alerta/críticos: {dataset['stats']['warning'] + dataset['stats']['disaster']}")
    return out_path


def serve_interactive_map(html_file, port=8088, open_browser=True, log=print):
    """Serve the interactive map file via lightweight local HTTP server."""
    file_path = Path(html_file).resolve()
    directory = str(file_path.parent)
    filename = file_path.name

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def log_message(self, format, *args):
            pass

    with socketserver.TCPServer(("", port), Handler) as httpd:
        url = f"http://localhost:{port}/{filename}"
        log(f"Servidor Web de Topologia Interativa iniciado em: {url}")
        log("Pressione Ctrl+C para encerrar o servidor.")

        if open_browser:
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            log("\nServidor encerrado.")
