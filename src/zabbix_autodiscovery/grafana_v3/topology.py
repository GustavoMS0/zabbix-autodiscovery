"""Topologia da Rede v3: Arquitetura Multi-Site Hierárquica em Apache ECharts.

Mapeamento dinâmico e portátil de sites, firewalls, switches, servidores,
hardware de gestão OOB (iDRAC) e access points sem sobreposição de nós.
"""
import copy
import json

true, false, null = True, False, None

KEY = "topology"
UID = "autodiscovery-topology-v3"
TITLE = "AutoDiscovery v3 - Topologia da Rede"

ECHARTS_TEMPLATE = "\nconst seriesData = (context && context.panel && context.panel.data && context.panel.data.series) || [];\n\nconst ICONS = {\n  internet: '<path d=\"M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8zm-1-15.93a8 8 0 0 0-5.93 5.93h3.07a12.8 12.8 0 0 1 2.86-5.93zm2 0a12.8 12.8 0 0 1 2.86 5.93h3.07A8 8 0 0 0 13 4.07zM4.07 11a8.1 8.1 0 0 0 0 2h3.93a15.7 15.7 0 0 1 0-2zm5.93 7.93a12.8 12.8 0 0 1-2.86-5.93H4.07a8 8 0 0 0 5.93 5.93zm4 0a8 8 0 0 0 5.93-5.93h-3.07a12.8 12.8 0 0 1-2.86 5.93zM16 13h3.93a8.1 8.1 0 0 0 0-2H16a15.7 15.7 0 0 1 0 2zm-6-2v2h4v-2z\"/>',\n  firewall: '<rect x=\"3\" y=\"4\" width=\"18\" height=\"16\" rx=\"2\"/><path d=\"M3 9.3h18M3 14.7h18M9 4v5.3M15 4v5.3M12 9.3v5.4M7 14.7V20M17 14.7V20\"/>',\n  switch: '<rect x=\"2\" y=\"7\" width=\"20\" height=\"10\" rx=\"2\"/><circle cx=\"6\" cy=\"12\" r=\"1.5\"/><circle cx=\"10\" cy=\"12\" r=\"1.5\"/><circle cx=\"14\" cy=\"12\" r=\"1.5\"/><circle cx=\"18\" cy=\"12\" r=\"1.5\"/>',\n  server: '<rect x=\"3\" y=\"3.5\" width=\"18\" height=\"7.5\" rx=\"2\"/><rect x=\"3\" y=\"13\" width=\"18\" height=\"7.5\" rx=\"2\"/><circle cx=\"7\" cy=\"7.25\" r=\"1\"/><circle cx=\"7\" cy=\"16.75\" r=\"1\"/><path d=\"M11 7.25h6M11 16.75h6\"/>',\n  chip: '<rect x=\"6\" y=\"6\" width=\"12\" height=\"12\" rx=\"2\"/><circle cx=\"12\" cy=\"12\" r=\"2.5\"/><path d=\"M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4\"/>',\n  battery: '<rect x=\"2\" y=\"7\" width=\"17\" height=\"10\" rx=\"2\"/><path d=\"M22 10.5v3M11 9l-2.5 3.2h3.4L9.5 15.2\"/>',\n  wifi: '<path d=\"M2.5 9.2a14 14 0 0 1 19 0M5.6 12.6a9.5 9.5 0 0 1 12.8 0M8.8 16a4.8 4.8 0 0 1 6.4 0M12 19.6h.01\"/>'\n};\n\nconst iconUri = (name, color) => 'image://data:image/svg+xml;charset=utf-8,' + encodeURIComponent(\n  '<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"' + color +\n  '\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">' + (ICONS[name] || ICONS.server) + '</svg>');\n\n// Mathematical coordinate system: min: 0, max: __CANVAS_WIDTH__, y: 0 to 780\n// Site 1 (RJ):      center = 130  (range: 20 to 240)\n// Site 2 (Matriz): center = 510  (range: 260 to 760)\n// Site 3 (Bahia):   center = 865  (range: 780 to 950)\n// Site 4 (Paraná):  center = 1055 (range: 970 to 1140)\n\nconst allNodes = __ALL_NODES__;\n\nconst allLinks = __ALL_LINKS__;\n\nconst COLORS = { up: '#10b981', down: '#ef4444', partial: '#f59e0b', unknown: '#64748b' };\nconst LABELS = { up: 'ONLINE', down: 'OFFLINE', partial: 'PARCIAL', unknown: 'SEM DADOS' };\nconst CATEGORY_COLORS = {\n  'Internet': '#38bdf8', 'Firewall': '#e879f9', 'Switch': '#3b82f6', 'Hardware Servidor': '#a855f7',\n  'Virtualização / Servidor': '#8b5cf6', 'Access Point': '#f43f5e', 'Nobreak UPS': '#f59e0b'\n};\n\nconst lastValue = (field) => {\n  const raw = field && field.values ? field.values : [];\n  const vals = typeof raw.toArray === 'function' ? raw.toArray() : raw;\n  for (let i = vals.length - 1; i >= 0; i--) {\n    if (vals[i] !== null && vals[i] !== undefined) return Number(vals[i]);\n  }\n  return null;\n};\n\nconst hostChecks = {};\nconst wanStatus = {};\nconst mergeOk = (prev, ok) => (prev === undefined || prev === null || ok === false ? ok : prev);\n\nfor (const frame of seriesData) {\n  const valueField = (frame.fields || []).find((f) => f.type === 'number');\n  if (!valueField || !valueField.labels || !valueField.labels.host) continue;\n  const host = valueField.labels.host;\n  const key = valueField.labels.item_key || '';\n  const item = valueField.labels.item || key;\n  const last = lastValue(valueField);\n  if (frame.refId === 'B') {\n    (wanStatus[host] = wanStatus[host] || []).push({ name: item, ok: last === null ? null : last === 1 });\n    continue;\n  }\n  const ok = last === null ? null : (key === 'icmpping' ? last === 1 : (last === 1 ? true : last === 0 ? false : null));\n  const kind = key === 'icmpping' ? 'ping'\n    : (key.indexOf(',agent,') >= 0 || item === 'Zabbix agent availability' ? 'agent' : 'snmp');\n  const c = hostChecks[host] = hostChecks[host] || {};\n  c[kind] = mergeOk(c[kind], ok);\n}\n\nconst CHECK_NAMES = { ping: 'ping', snmp: 'SNMP', agent: 'agente' };\nconst hostMember = (h) => {\n  const c = hostChecks[h] || {};\n  const hasPing = c.ping !== undefined && c.ping !== null;\n  const reach = hasPing ? c.ping : (c.snmp === undefined ? null : c.snmp);\n  const agentDown = c.agent === false || (hasPing && c.snmp === false);\n  let state = 'unknown';\n  if (reach === false) state = 'down';\n  else if (reach === true) state = agentDown ? 'partial' : 'up';\n  else if (c.agent === true) state = 'up';\n  else if (c.agent === false) state = 'down';\n  const checks = Object.keys(CHECK_NAMES).filter((k) => c[k] !== undefined)\n    .map((k) => ({ name: CHECK_NAMES[k], state: c[k] === null ? 'unknown' : (c[k] ? 'up' : 'down') }));\n  return { name: h, state: state, checks: checks };\n};\n\nlet site = '.*';\ntry {\n  if (context && context.grafana && typeof context.grafana.replaceVariables === 'function') {\n    site = context.grafana.replaceVariables('$site');\n  }\n} catch (e) { site = '.*'; }\nconst allSites = !site || site === '.*' || site === '$site' || site === '$__all';\n\nconst byId = {};\nconst activeNodes = allNodes.filter((n) => allSites || n.siteKey === site).map((n) => {\n  const members = n.wan\n    ? n.hosts.flatMap((h) => (wanStatus[h] || []).map((w) => ({\n        name: h + ': ' + w.name, state: w.ok === null ? 'unknown' : (w.ok ? 'up' : 'down'), checks: [] })))\n    : n.hosts.map(hostMember);\n\n  const known = members.filter((m) => m.state !== 'unknown');\n  const up = known.filter((m) => m.state === 'up').length;\n  const down = known.filter((m) => m.state === 'down').length;\n  let state = 'unknown';\n  if (known.length) state = up === known.length ? 'up' : (down === known.length ? 'down' : 'partial');\n\n  const nodeObj = Object.assign({}, n, {\n    members: members,\n    state: state,\n    up: up,\n    total: members.length\n  });\n  byId[n.id] = nodeObj;\n  return nodeObj;\n});\n\nconst discs = [], alarms = [], iconItems = [], textItems = [];\nconst linesStatic = [], linesFlowing = [];\n\nactiveNodes.forEach((n) => {\n  const st = n.state;\n  const col = COLORS[st];\n  const isDown = st === 'down';\n  const isLoud = isDown || (n.core && st === 'up');\n\n  // Pulse effect\n  if (isLoud) {\n    alarms.push({\n      value: [n.x, n.y],\n      symbolSize: n.r * (isDown ? 1.6 : 1.35),\n      itemStyle: {\n        color: isDown ? 'rgba(239, 68, 68, 0.4)' : 'rgba(0, 229, 255, 0.25)',\n        shadowBlur: isDown ? 24 : 14,\n        shadowColor: col\n      },\n      tipData: n\n    });\n  }\n\n  // Neon Glass Disc\n  discs.push({\n    value: [n.x, n.y],\n    symbolSize: n.r,\n    itemStyle: {\n      color: isDown ? 'rgba(38, 12, 18, 0.95)' : (st === 'up' ? 'rgba(10, 25, 22, 0.92)' : 'rgba(36, 24, 10, 0.92)'),\n      borderColor: col,\n      borderWidth: isDown ? 3.5 : 2.5,\n      shadowBlur: isDown ? 28 : (st === 'up' ? 16 : 12),\n      shadowColor: col\n    },\n    tipData: n\n  });\n\n  // SVG Line Icon centered\n  iconItems.push({\n    value: [n.x, n.y],\n    symbol: iconUri(n.icon || 'server', col),\n    symbolSize: Math.round(n.r * 0.52),\n    silent: true\n  });\n\n  // Compact Non-overlapping Label Plate\n  textItems.push({\n    value: [n.x, n.y + n.r / 2 + 12],\n    tipData: n,\n    label: {\n      show: true,\n      position: 'inside',\n      formatter: '{pip|●} {name|' + n.name + '}\\n{sub|' + (n.sub || '') + '}',\n      rich: {\n        pip: { color: col, fontSize: 9.5, fontWeight: 900 },\n        name: { color: '#f8fafc', fontSize: 10, fontWeight: 700, lineHeight: 13 },\n        sub: { color: '#38bdf8', fontSize: 9, fontWeight: 600, lineHeight: 12 }\n      },\n      backgroundColor: 'rgba(15, 23, 42, 0.92)',\n      borderColor: col,\n      borderWidth: 1,\n      borderRadius: 4,\n      padding: [3, 6],\n      shadowBlur: 6,\n      shadowColor: 'rgba(0,0,0,0.6)'\n    }\n  });\n});\n\nallLinks.forEach((l) => {\n  const src = byId[l.source];\n  const tgt = byId[l.target];\n  if (!src || !tgt) return;\n\n  const isBad = src.state === 'down' || tgt.state === 'down';\n  const edgeColor = isBad ? COLORS.down : l.color;\n  const curveness = l.curveness || 0;\n\n  const coords = [[src.x, src.y], [tgt.x, tgt.y]];\n  const tipText = '<b>' + src.name + '</b> ➔ <b>' + tgt.name + '</b>' +\n    (l.label ? '<br><span style=\"color:#38bdf8;\">' + l.label + '</span>' : '');\n\n  linesStatic.push({\n    coords: coords,\n    lineStyle: {\n      color: edgeColor,\n      width: isBad ? 2.8 : l.width,\n      type: isBad ? 'dashed' : (l.dashed ? [6, 4] : (l.dotted ? [3, 3] : 'solid')),\n      curveness: curveness,\n      shadowBlur: isBad ? 16 : l.glow,\n      shadowColor: edgeColor\n    },\n    tipText: tipText\n  });\n\n  if (!isBad) {\n    linesFlowing.push({\n      coords: coords,\n      lineStyle: {\n        curveness: curveness,\n        opacity: 0,\n        width: 1\n      }\n    });\n  }\n});\n\n// Perfectly centered Site Pods using markArea labels (100% responsive and coordinate-pinned)\nconst siteAreas = __SITE_AREAS__;\n\nreturn {\n  backgroundColor: 'transparent',\n  animation: false,\n  grid: { left: 0, right: 0, top: 0, bottom: 0 },\n  xAxis: { type: 'value', min: 0, max: __CANVAS_WIDTH__, show: false },\n  yAxis: { type: 'value', min: 0, max: __CANVAS_HEIGHT__, show: false, inverse: true },\n  tooltip: {\n    trigger: 'item',\n    backgroundColor: 'rgba(13, 17, 23, 0.96)',\n    borderColor: '#334155',\n    borderWidth: 1,\n    padding: [10, 14],\n    textStyle: { color: '#f8fafc', fontSize: 12 },\n    extraCssText: 'box-shadow: 0 10px 30px rgba(0,0,0,0.7); backdrop-filter: blur(8px);',\n    formatter: function(params) {\n      if (params.data && params.data.tipData) {\n        const d = params.data.tipData;\n        const rows = (d.members || []).map((m) => {\n          const checks = (m.checks || []).map((c) =>\n            `<span style=\\\"color:${COLORS[c.state]};\\\">${c.name} ●</span>`).join(', ');\n          return `<div><span style=\\\"color:${COLORS[m.state]};\\\">●</span> <b>${m.name}</b>` +\n            (checks ? ` <span style=\\\"color:#94a3b8;\\\">(${checks})</span>` : '') + `</div>`;\n        }).join('') || '<div style=\\\"color:#94a3b8;\\\">Sem item de disponibilidade no Zabbix</div>';\n        return `\n          <div style=\\\"font-weight:bold;font-size:14px;color:${COLORS[d.state]};margin-bottom:6px;border-bottom:1px solid #334155;padding-bottom:4px;\\\">\n            ${d.name} (${d.sub || ''})\n          </div>\n          <table style=\\\"font-size:12px;line-height:1.6;color:#cbd5e1;margin-bottom:6px;\\\">\n            <tr><td><b>Categoria:</b></td><td style=\\\"padding-left:8px;\\\"><span style=\\\"color:${CATEGORY_COLORS[d.category] || '#94a3b8'};font-weight:700;\\\">● ${d.category}</span></td></tr>\n            <tr><td><b>Endereço IP:</b></td><td style=\\\"padding-left:8px;font-family:monospace;color:#38bdf8;\\\">${d.ip}</td></tr>\n            <tr><td><b>Localidade:</b></td><td style=\\\"padding-left:8px;\\\">${d.site}</td></tr>\n            <tr><td><b>Papel / Detalhe:</b></td><td style=\\\"padding-left:8px;\\\">${d.role}</td></tr>\n            <tr><td><b>Status:</b></td><td style=\\\"padding-left:8px;\\\"><span style=\\\"color:${COLORS[d.state]};font-weight:bold;\\\">● ${LABELS[d.state]}</span> (${d.up}/${d.total} online)</td></tr>\n          </table>\n          <div style=\\\"font-size:11px;line-height:1.5;border-top:1px solid #334155;padding-top:4px;\\\">${rows}</div>\n        `;\n      } else if (params.data && params.data.tipText) {\n        return params.data.tipText;\n      }\n      return '';\n    }\n  },\n  series: [\n    // Static Lines\n    {\n      type: 'lines',\n      coordinateSystem: 'cartesian2d',\n      z: 2,\n      data: linesStatic,\n      markArea: {\n        silent: true,\n        data: siteAreas\n      }\n    },\n    // Animated Packet Flow\n    {\n      type: 'lines',\n      coordinateSystem: 'cartesian2d',\n      z: 3,\n      effect: {\n        show: true,\n        period: 4.5,\n        trailLength: 0.25,\n        symbol: 'circle',\n        symbolSize: 4.5,\n        color: '#00ffd5'\n      },\n      data: linesFlowing,\n      silent: true\n    },\n    // Radar Pulse on Active Nodes\n    {\n      type: 'effectScatter',\n      coordinateSystem: 'cartesian2d',\n      z: 4,\n      rippleEffect: { scale: 1.7, brushType: 'stroke', period: 3 },\n      data: alarms,\n      silent: false\n    },\n    // Glowing Node Discs\n    {\n      type: 'scatter',\n      coordinateSystem: 'cartesian2d',\n      z: 5,\n      data: discs,\n      silent: false\n    },\n    // Device Icons\n    {\n      type: 'scatter',\n      coordinateSystem: 'cartesian2d',\n      z: 6,\n      data: iconItems,\n      silent: true\n    },\n    // Name Plates\n    {\n      type: 'scatter',\n      coordinateSystem: 'cartesian2d',\n      z: 7,\n      data: textItems,\n      silent: false\n    }\n  ]\n};\n"

PANEL_1_DEF = {
    "id": 1,
    "title": "HOSTS ONLINE",
    "type": "stat",
    "gridPos": {
        "x": 0,
        "y": 0,
        "w": 6,
        "h": 3
    },
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "color": {
                "mode": "fixed",
                "fixedColor": "#10b981"
            },
            "decimals": 0,
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#10b981",
                        "value": 0
                    }
                ]
            },
            "unit": "short"
        },
        "overrides": []
    },
    "options": {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "horizontal",
        "reduceOptions": {
            "calcs": [
                "lastNotNull"
            ],
            "fields": "",
            "values": false
        },
        "textMode": "value_and_name",
        "wideLayout": true,
        "text": {
            "valueSize": 38,
            "titleSize": 12
        }
    },
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Aggregate",
                        "defaultParams": [],
                        "name": "sumSeries",
                        "params": []
                    },
                    "params": [],
                    "text": "sumSeries()"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "Disponíveis"
                    ],
                    "text": "setAlias(Disponíveis)"
                }
            ],
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "ICMP ping"
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ]
}
PANEL_102_DEF = {
    "id": 102,
    "title": "TOTAL MONITORADOS",
    "type": "stat",
    "gridPos": {
        "x": 6,
        "y": 0,
        "w": 6,
        "h": 3
    },
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "color": {
                "mode": "fixed",
                "fixedColor": "#00e5ff"
            },
            "decimals": 0,
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#00e5ff",
                        "value": 0
                    }
                ]
            },
            "unit": "short"
        },
        "overrides": []
    },
    "options": {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "horizontal",
        "reduceOptions": {
            "calcs": [
                "lastNotNull"
            ],
            "fields": "",
            "values": false
        },
        "textMode": "value_and_name",
        "wideLayout": true,
        "text": {
            "valueSize": 38,
            "titleSize": 12
        }
    },
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Transform",
                        "defaultParams": [
                            100
                        ],
                        "name": "scale",
                        "params": [
                            {
                                "name": "factor",
                                "type": "float"
                            }
                        ]
                    },
                    "params": [
                        0
                    ],
                    "text": "scale(0)"
                },
                {
                    "def": {
                        "category": "Transform",
                        "defaultParams": [
                            100
                        ],
                        "name": "offset",
                        "params": [
                            {
                                "name": "delta",
                                "type": "float"
                            }
                        ]
                    },
                    "params": [
                        1
                    ],
                    "text": "offset(1)"
                },
                {
                    "def": {
                        "category": "Aggregate",
                        "defaultParams": [],
                        "name": "sumSeries",
                        "params": []
                    },
                    "params": [],
                    "text": "sumSeries()"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "Inventário"
                    ],
                    "text": "setAlias(Inventário)"
                }
            ],
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "ICMP ping"
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ]
}
PANEL_103_DEF = {
    "id": 103,
    "title": "HOSTS OFFLINE",
    "type": "stat",
    "gridPos": {
        "x": 12,
        "y": 0,
        "w": 6,
        "h": 3
    },
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "color": {
                "mode": "thresholds"
            },
            "decimals": 0,
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#10b981",
                        "value": 0
                    },
                    {
                        "color": "#ef4444",
                        "value": 1
                    }
                ]
            },
            "unit": "short"
        },
        "overrides": []
    },
    "options": {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "horizontal",
        "reduceOptions": {
            "calcs": [
                "lastNotNull"
            ],
            "fields": "",
            "values": false
        },
        "textMode": "value_and_name",
        "wideLayout": true,
        "text": {
            "valueSize": 38,
            "titleSize": 12
        }
    },
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Transform",
                        "defaultParams": [
                            100
                        ],
                        "name": "scale",
                        "params": [
                            {
                                "name": "factor",
                                "type": "float"
                            }
                        ]
                    },
                    "params": [
                        -1
                    ],
                    "text": "scale(-1)"
                },
                {
                    "def": {
                        "category": "Transform",
                        "defaultParams": [
                            100
                        ],
                        "name": "offset",
                        "params": [
                            {
                                "name": "delta",
                                "type": "float"
                            }
                        ]
                    },
                    "params": [
                        1
                    ],
                    "text": "offset(1)"
                },
                {
                    "def": {
                        "category": "Aggregate",
                        "defaultParams": [],
                        "name": "sumSeries",
                        "params": []
                    },
                    "params": [],
                    "text": "sumSeries()"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "Indisponíveis"
                    ],
                    "text": "setAlias(Indisponíveis)"
                }
            ],
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "ICMP ping"
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ]
}
PANEL_104_DEF = {
    "id": 104,
    "title": "SITES CONECTADOS (SD-WAN)",
    "type": "stat",
    "gridPos": {
        "x": 18,
        "y": 0,
        "w": 6,
        "h": 3
    },
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "color": {
                "mode": "thresholds"
            },
            "decimals": 0,
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#ef4444",
                        "value": 0
                    },
                    {
                        "color": "#10b981",
                        "value": 4
                    }
                ]
            },
            "unit": "short"
        },
        "overrides": []
    },
    "options": {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "horizontal",
        "reduceOptions": {
            "calcs": [
                "lastNotNull"
            ],
            "fields": "",
            "values": false
        },
        "textMode": "value_and_name",
        "wideLayout": true,
        "text": {
            "valueSize": 38,
            "titleSize": 12
        }
    },
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Aggregate",
                        "defaultParams": [],
                        "name": "sumSeries",
                        "params": []
                    },
                    "params": [],
                    "text": "sumSeries()"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "Filiais Ativas"
                    ],
                    "text": "setAlias(Filiais Ativas)"
                }
            ],
            "group": {
                "filter": "Rede/Firewalls"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "ICMP ping"
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ]
}
PANEL_2_DEF = {
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "mappings": [
                {
                    "options": {
                        "1": {
                            "color": "#10b981",
                            "index": 0,
                            "text": "● ONLINE"
                        },
                        "2": {
                            "color": "#ef4444",
                            "index": 1,
                            "text": "▲ FORA DO AR"
                        },
                        "3": {
                            "color": "#f59e0b",
                            "index": 2,
                            "text": "TESTE"
                        },
                        "4": {
                            "color": "#64748b",
                            "index": 3,
                            "text": "SEM DADOS"
                        },
                        "5": {
                            "color": "#00e5ff",
                            "index": 4,
                            "text": "DORMENTE"
                        },
                        "6": {
                            "color": "#475569",
                            "index": 5,
                            "text": "AUSENTE"
                        },
                        "7": {
                            "color": "#ef4444",
                            "index": 6,
                            "text": "OFFLINE"
                        }
                    },
                    "type": "value"
                }
            ],
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "red",
                        "value": 0
                    },
                    {
                        "color": "green",
                        "value": 1
                    },
                    {
                        "color": "red",
                        "value": 2
                    }
                ]
            }
        }
    },
    "gridPos": {
        "x": 0,
        "y": 3,
        "w": 5,
        "h": 8
    },
    "hideTimeOverride": true,
    "id": 2,
    "maxDataPoints": 10,
    "options": {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "auto",
        "orientation": "horizontal",
        "percentChangeColorMode": "standard",
        "reduceOptions": {
            "calcs": [
                "lastNotNull"
            ],
            "fields": "",
            "values": false
        },
        "showPercentChange": false,
        "text": {
            "titleSize": 11,
            "valueSize": 15
        },
        "textMode": "value_and_name",
        "wideLayout": false
    },
    "pluginVersion": "13.2.3",
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: $__zbx_item"
                    ],
                    "text": "setAlias($__zbx_host_name: $__zbx_item)"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: (?:Interface\\s+)?([^:]+):\\s+Operational status$/i",
                        " - $1"
                    ],
                    "text": "replaceAlias(/: (?:Interface\\s+)?([^:]+):\\s+Operational status$/i,  - $1)"
                }
            ],
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "/interface\\s+(?!fortilink|loopback)(wan\\d*|uplink\\d*|internet\\d*|a\\([^)]*(wan|internet|net\\s*fiber|mbps|ligga|its|easy|america|mega)[^)]*\\)).*: operational status/i"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ],
    "timeFrom": "10m",
    "title": "LINKS DE INTERNET (MULTI-WAN)",
    "type": "stat"
}
PANEL_3_DEF = {
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "color": {
                "mode": "palette-classic"
            },
            "custom": {
                "axisBorderShow": false,
                "axisCenteredZero": false,
                "axisColorMode": "text",
                "axisLabel": "",
                "axisPlacement": "auto",
                "barAlignment": 0,
                "barWidthFactor": 0.6,
                "drawStyle": "line",
                "fillOpacity": 18,
                "gradientMode": "opacity",
                "hideFrom": {
                    "legend": false,
                    "tooltip": false,
                    "viz": false
                },
                "insertNulls": false,
                "lineInterpolation": "smooth",
                "lineWidth": 1.8,
                "pointSize": 5,
                "scaleDistribution": {
                    "type": "linear"
                },
                "showPoints": "never",
                "showValues": false,
                "spanNulls": true,
                "stacking": {
                    "group": "A",
                    "mode": "none"
                },
                "thresholdsStyle": {
                    "mode": "off"
                }
            },
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "green",
                        "value": 0
                    },
                    {
                        "color": "red",
                        "value": 80
                    }
                ]
            },
            "unit": "bps"
        },
        "overrides": [
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": ".*\\(In\\)$"
                },
                "properties": [
                    {
                        "id": "color",
                        "value": {
                            "fixedColor": "#00ffd5",
                            "mode": "fixed"
                        }
                    }
                ]
            },
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": ".*\\(Out\\)$"
                },
                "properties": [
                    {
                        "id": "color",
                        "value": {
                            "fixedColor": "#d946ef",
                            "mode": "fixed"
                        }
                    }
                ]
            }
        ]
    },
    "gridPos": {
        "x": 0,
        "y": 11,
        "w": 5,
        "h": 8
    },
    "id": 3,
    "maxDataPoints": 500,
    "options": {
        "legend": {
            "calcs": [
                "mean",
                "max"
            ],
            "displayMode": "list",
            "placement": "bottom",
            "showLegend": true
        },
        "tooltip": {
            "hideZeros": false,
            "mode": "multi",
            "sort": "desc"
        }
    },
    "pluginVersion": "13.2.3",
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: $__zbx_item"
                    ],
                    "text": "setAlias($__zbx_host_name: $__zbx_item)"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: (?:Interface\\s+)?([^:]+):\\s+Bits received$/i",
                        " - $1 (In)"
                    ],
                    "text": "replaceAlias(/: (?:Interface\\s+)?([^:]+):\\s+Bits received$/i,  - $1 (In))"
                }
            ],
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "/interface\\s+(?!fortilink|loopback)(wan\\d*|uplink\\d*|internet\\d*|a\\([^)]*(wan|internet|net\\s*fiber|mbps|ligga|its|easy|america|mega)[^)]*\\)).*: bits received/i"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        },
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: $__zbx_item"
                    ],
                    "text": "setAlias($__zbx_host_name: $__zbx_item)"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: (?:Interface\\s+)?([^:]+):\\s+Bits sent$/i",
                        " - $1 (Out)"
                    ],
                    "text": "replaceAlias(/: (?:Interface\\s+)?([^:]+):\\s+Bits sent$/i,  - $1 (Out))"
                }
            ],
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "item": {
                "filter": "/interface\\s+(?!fortilink|loopback)(wan\\d*|uplink\\d*|internet\\d*|a\\([^)]*(wan|internet|net\\s*fiber|mbps|ligga|its|easy|america|mega)[^)]*\\)).*: bits sent/i"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "B"
        }
    ],
    "title": "TRÁFEGO INTERNET WAN (LIVE BPS)",
    "type": "timeseries"
}
PANEL_5_DEF = {
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "custom": {
                "align": "auto",
                "displayMode": "auto",
                "inspect": false
            },
            "color": {
                "mode": "thresholds"
            },
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#10b981",
                        "value": 0
                    }
                ]
            }
        },
        "overrides": [
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "Last.*|Value"
                },
                "properties": [
                    {
                        "id": "displayName",
                        "value": "Status"
                    },
                    {
                        "id": "custom.width",
                        "value": 95
                    },
                    {
                        "id": "custom.cellOptions",
                        "value": {
                            "type": "color-background",
                            "mode": "basic"
                        }
                    },
                    {
                        "id": "mappings",
                        "value": [
                            {
                                "type": "value",
                                "options": {
                                    "1": {
                                        "text": "ONLINE",
                                        "color": "#10b981",
                                        "index": 0
                                    },
                                    "0": {
                                        "text": "OFFLINE",
                                        "color": "#ef4444",
                                        "index": 1
                                    },
                                    "2": {
                                        "text": "DESCONHECIDO",
                                        "color": "#64748b",
                                        "index": 2
                                    }
                                }
                            }
                        ]
                    }
                ]
            },
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "Field|Metric|Servidor"
                },
                "properties": [
                    {
                        "id": "displayName",
                        "value": "Servidor / VM"
                    },
                    {
                        "id": "custom.width",
                        "value": 235
                    }
                ]
            }
        ]
    },
    "gridPos": {
        "x": 19,
        "y": 3,
        "w": 5,
        "h": 5
    },
    "hideTimeOverride": true,
    "id": 5,
    "maxDataPoints": 10,
    "options": {
        "cellHeight": "sm",
        "footer": {
            "countRows": false,
            "enablePagination": false,
            "fields": "",
            "reducer": [
                "sum"
            ],
            "show": false
        },
        "showHeader": true,
        "sortBy": [
            {
                "displayName": "Servidor / VM",
                "desc": false
            }
        ]
    },
    "pluginVersion": "13.2.3",
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: $__zbx_item"
                    ],
                    "text": "setAlias($__zbx_host_name: $__zbx_item)"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: Zabbix agent availability$/",
                        " (agente)"
                    ],
                    "text": "replaceAlias(/: Zabbix agent availability$/,  (agente))"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: ICMP ping$/",
                        " (ping)"
                    ],
                    "text": "replaceAlias(/: ICMP ping$/,  (ping))"
                }
            ],
            "group": {
                "filter": "/^Servidores\\/.*$/"
            },
            "host": {
                "filter": "/^$site_hosts$/"
            },
            "item": {
                "filter": "/^(Zabbix agent availability|ICMP ping)$/"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ],
    "timeFrom": "5m",
    "title": "COMPUTE · SERVIDORES & HYPERVISORS",
    "transformations": [
        {
            "id": "reduce",
            "options": {
                "reducers": [
                    "lastNotNull"
                ]
            }
        }
    ],
    "type": "table"
}
PANEL_6_DEF = {
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "custom": {
                "align": "auto",
                "displayMode": "auto"
            },
            "color": {
                "mode": "thresholds"
            },
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#10b981",
                        "value": 0
                    },
                    {
                        "color": "#f59e0b",
                        "value": 70
                    },
                    {
                        "color": "#ef4444",
                        "value": 85
                    }
                ]
            }
        },
        "overrides": [
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "Last.*|Value"
                },
                "properties": [
                    {
                        "id": "displayName",
                        "value": "Métrica Atual"
                    },
                    {
                        "id": "custom.cellOptions",
                        "value": {
                            "type": "color-text"
                        }
                    },
                    {
                        "id": "custom.width",
                        "value": 110
                    }
                ]
            },
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "Field|Metric"
                },
                "properties": [
                    {
                        "id": "displayName",
                        "value": "Firewall / Indicador"
                    },
                    {
                        "id": "custom.width",
                        "value": 220
                    }
                ]
            }
        ]
    },
    "gridPos": {
        "x": 19,
        "y": 8,
        "w": 5,
        "h": 5
    },
    "hideTimeOverride": true,
    "id": 6,
    "maxDataPoints": 10,
    "options": {
        "cellHeight": "sm",
        "footer": {
            "countRows": false,
            "enablePagination": false,
            "fields": "",
            "reducer": [
                "sum"
            ],
            "show": false
        },
        "showHeader": true
    },
    "pluginVersion": "13.2.3",
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: CPU"
                    ],
                    "text": "setAlias($__zbx_host_name: CPU)"
                }
            ],
            "group": {
                "filter": "/^Rede\\/Firewalls$/"
            },
            "host": {
                "filter": "/^$site_hosts$/"
            },
            "item": {
                "filter": "/^CPU utilization$/"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        },
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: Sessões"
                    ],
                    "text": "setAlias($__zbx_host_name: Sessões)"
                }
            ],
            "group": {
                "filter": "/^Rede\\/Firewalls$/"
            },
            "host": {
                "filter": "/^$site_hosts$/"
            },
            "item": {
                "filter": "/^IPv4 Active sessions$/"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "B"
        }
    ],
    "timeFrom": "10m",
    "title": "FIREWALLS · CPU & SESSÕES IPV4",
    "transformations": [
        {
            "id": "reduce",
            "options": {
                "reducers": [
                    "lastNotNull"
                ]
            }
        }
    ],
    "type": "table"
}
PANEL_7_DEF = {
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "fieldConfig": {
        "defaults": {
            "unit": "celsius",
            "custom": {
                "align": "auto",
                "displayMode": "auto"
            },
            "color": {
                "mode": "thresholds"
            },
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {
                        "color": "#10b981",
                        "value": 0
                    },
                    {
                        "color": "#f59e0b",
                        "value": 28
                    },
                    {
                        "color": "#ef4444",
                        "value": 35
                    }
                ]
            }
        },
        "overrides": [
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "Last.*|Value"
                },
                "properties": [
                    {
                        "id": "displayName",
                        "value": "Temperatura"
                    },
                    {
                        "id": "custom.cellOptions",
                        "value": {
                            "type": "color-text"
                        }
                    },
                    {
                        "id": "custom.width",
                        "value": 110
                    }
                ]
            },
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "Field|Metric"
                },
                "properties": [
                    {
                        "id": "displayName",
                        "value": "Equipamento"
                    },
                    {
                        "id": "custom.width",
                        "value": 220
                    }
                ]
            }
        ]
    },
    "gridPos": {
        "x": 19,
        "y": 13,
        "w": 5,
        "h": 6
    },
    "hideTimeOverride": true,
    "id": 7,
    "maxDataPoints": 100,
    "options": {
        "cellHeight": "sm",
        "footer": {
            "countRows": false,
            "enablePagination": false,
            "fields": "",
            "reducer": [
                "sum"
            ],
            "show": false
        },
        "showHeader": true
    },
    "pluginVersion": "13.2.3",
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "functions": [
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [],
                        "name": "setAlias",
                        "params": [
                            {
                                "name": "alias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "$__zbx_host_name: $__zbx_item"
                    ],
                    "text": "setAlias($__zbx_host_name: $__zbx_item)"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: Probe \\[.*Inlet Temp\\]: Value$/",
                        ": Inlet"
                    ],
                    "text": "replaceAlias(/: Probe \\[.*Inlet Temp\\]: Value$/, : Inlet)"
                },
                {
                    "def": {
                        "category": "Alias",
                        "defaultParams": [
                            "/(.*)/",
                            "$1"
                        ],
                        "name": "replaceAlias",
                        "params": [
                            {
                                "name": "regexp",
                                "type": "string"
                            },
                            {
                                "name": "newAlias",
                                "type": "string"
                            }
                        ]
                    },
                    "params": [
                        "/: Bateria: Temperatura$/",
                        ": Bateria"
                    ],
                    "text": "replaceAlias(/: Bateria: Temperatura$/, : Bateria)"
                }
            ],
            "group": {
                "filter": "/^Infra\\/.*$/"
            },
            "host": {
                "filter": "/^$site_hosts$/"
            },
            "item": {
                "filter": "/^(Probe \\[(System Board )?Inlet Temp\\]: Value|Bateria: Temperatura)$/"
            },
            "itemTag": {
                "filter": ""
            },
            "options": {
                "disableDataAlignment": true,
                "showDisabledItems": false,
                "skipEmptyValues": true,
                "useTrends": "false"
            },
            "queryType": "0",
            "refId": "A"
        }
    ],
    "timeFrom": "7h",
    "title": "TELEMETRIA TÉRMICA · IDRAC & UPS",
    "transformations": [
        {
            "id": "reduce",
            "options": {
                "reducers": [
                    "lastNotNull"
                ]
            }
        }
    ],
    "type": "table"
}
PANEL_8_DEF = {
    "datasource": {
        "type": "alexanderzobnin-zabbix-datasource",
        "uid": "${datasource}"
    },
    "gridPos": {
        "x": 0,
        "y": 19,
        "w": 24,
        "h": 6
    },
    "id": 8,
    "options": {
        "ackEventColor": "rgb(56, 219, 156)",
        "ackField": true,
        "ageField": true,
        "allowDangerousHTML": false,
        "customLastChangeFormat": true,
        "customTagColumns": "",
        "dataLinks": [],
        "descriptionAtNewLine": false,
        "descriptionField": true,
        "fontSize": "105%",
        "highlightBackground": false,
        "highlightNewEvents": false,
        "highlightNewerThan": "1h",
        "hostField": true,
        "hostGroups": true,
        "hostIpField": false,
        "hostProxy": false,
        "hostTechNameField": false,
        "lastChangeFormat": "DD/MM HH:mm",
        "layout": "table",
        "markAckEvents": false,
        "okEventColor": "rgb(56, 189, 113)",
        "opdataField": false,
        "pageSize": 8,
        "problemTimeline": false,
        "severityField": true,
        "showDatasourceName": false,
        "showSearchFilter": false,
        "showTags": true,
        "sortProblems": "lastchange",
        "statusField": true,
        "statusIcon": false,
        "triggerSeverity": [
            {
                "color": "rgb(108, 108, 108)",
                "priority": 0,
                "severity": "Not classified",
                "show": true
            },
            {
                "color": "rgb(120, 158, 183)",
                "priority": 1,
                "severity": "Information",
                "show": true
            },
            {
                "color": "rgb(175, 180, 36)",
                "priority": 2,
                "severity": "Warning",
                "show": true
            },
            {
                "color": "rgb(255, 137, 30)",
                "priority": 3,
                "severity": "Average",
                "show": true
            },
            {
                "color": "rgb(255, 101, 72)",
                "priority": 4,
                "severity": "High",
                "show": true
            },
            {
                "color": "rgb(215, 0, 0)",
                "priority": 5,
                "severity": "Disaster",
                "show": true
            }
        ]
    },
    "pluginVersion": "6.9.1",
    "targets": [
        {
            "application": {
                "filter": ""
            },
            "datasource": {
                "type": "alexanderzobnin-zabbix-datasource",
                "uid": "${datasource}"
            },
            "group": {
                "filter": "/^Filiais\\/$site$/"
            },
            "host": {
                "filter": "/.*/"
            },
            "options": {
                "acknowledged": 2,
                "hostsInMaintenance": false,
                "limit": 100,
                "minSeverity": 2,
                "sortProblems": "priority"
            },
            "proxy": {
                "filter": ""
            },
            "queryType": "5",
            "refId": "A",
            "showProblems": "problems",
            "tags": {
                "filter": ""
            },
            "trigger": {
                "filter": ""
            }
        }
    ],
    "title": "FEED DE ALARMES NOC · TEMPO REAL (MÉDIA OU SUPERIOR)",
    "type": "alexanderzobnin-zabbix-triggers-panel"
}


def discover_sites_and_devices(api, cfg):
    """Discovers sites and classifies host devices from Zabbix, or falls back to cfg/archetypes."""
    sites_data = []

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

    filiais_groups = []
    if api:
        for search_pat in ["Filiais*", "Sites*", "Site*"]:
            res = call_api("hostgroup.get", {
                "output": ["groupid", "name"],
                "search": {"name": search_pat},
                "searchWildcardsEnabled": True
            })
            if res:
                filiais_groups = res
                break

    if filiais_groups:
        raw_sites = []
        for g in filiais_groups:
            parts = g["name"].split("/")
            site_name = parts[-1].strip() if len(parts) > 1 else g["name"].strip()
            raw_sites.append({"groupid": g["groupid"], "key": site_name, "group": g["name"]})
    else:
        cfg_sites = cfg.get("_sites", [])
        if cfg_sites:
            raw_sites = [
                {"groupid": None, "key": s.get("site", s.get("network", "Site")), "group": f"Filiais/{s.get('site', s.get('network', 'Site'))}"}
                for s in cfg_sites if s.get("site") or s.get("network")
            ]
        else:
            raw_sites = [
                {"groupid": None, "key": "Matriz", "group": "Filiais/Matriz"},
                {"groupid": None, "key": "RJ", "group": "Filiais/RJ"},
                {"groupid": None, "key": "BA", "group": "Filiais/BA"},
                {"groupid": None, "key": "PR", "group": "Filiais/PR"}
            ]

    seen_keys = set()
    unique_sites = []
    for s in raw_sites:
        if s["key"] not in seen_keys:
            seen_keys.add(s["key"])
            unique_sites.append(s)

    for s in unique_sites:
        site_key = s["key"]
        k_lower = site_key.lower()
        if k_lower in ["barueri", "sp", "matriz"]:
            site_label = f"{site_key} · HUB MATRIZ"
        elif k_lower == "rj":
            site_label = "RIO DE JANEIRO (RJ)"
        elif k_lower == "ba":
            site_label = "BAHIA (BA)"
        elif k_lower == "pr":
            site_label = "PARANÁ (PR)"
        else:
            site_label = f"FILIAL {site_key.upper()}"

        site_info = {
            "key": site_key,
            "label": site_label,
            "group": s["group"],
            "firewalls": [],
            "switches": [],
            "ups": [],
            "idrac": [],
            "servers": [],
            "aps": []
        }

        hosts = []
        if api and s.get("groupid"):
            hosts = call_api("host.get", {
                "groupids": [s["groupid"]],
                "output": ["hostid", "host", "name"],
                "selectHostGroups": ["name"],
                "selectInterfaces": ["ip", "main"]
            }) or []

        if hosts:
            for h in hosts:
                h_name = h.get("name", "")
                h_tech = h.get("host", "")
                groups = [g["name"] for g in h.get("hostgroups", [])]
                ip = next((i["ip"] for i in h.get("interfaces", []) if i.get("main") == "1"), "DHCP/IP")
                entry = {"host": h_tech, "name": h_name, "ip": ip}

                h_low = (h_name + " " + h_tech).lower()
                is_fw = any("firewall" in g.lower() for g in groups) or h_tech.startswith("FW-") or "firewall" in h_low or "fortigate" in h_low
                is_ups = any(w in g.lower() for g in groups for w in ["nobreak", "ups", "pdu", "energia"]) or "nobreak" in h_low or "ups" in h_low
                is_idrac = any(w in g.lower() for g in groups for w in ["hardware servidor", "idrac", "ilo", "ipmi", "bmc"]) or "idrac" in h_low or "rac_" in h_low
                is_sw = any("switch" in g.lower() for g in groups) or "switch" in h_low or "sw-" in h_low or "sw_" in h_low
                is_ap = any(w in g.lower() for g in groups for w in ["access point", "wireless", "wi-fi"]) or h_tech.startswith("AP-") or h_tech.startswith("AP") or "unifi" in h_low
                is_srv = any(w in g.lower() for g in groups for w in ["servidor", "hypervisor", "virtualiza"]) or "srv-" in h_low or "server" in h_low

                if is_fw:
                    site_info["firewalls"].append(entry)
                elif is_ups:
                    site_info["ups"].append(entry)
                elif is_sw:
                    site_info["switches"].append(entry)
                elif is_idrac:
                    site_info["idrac"].append(entry)
                elif is_ap:
                    site_info["aps"].append(entry)
                elif is_srv:
                    site_info["servers"].append(entry)
                else:
                    site_info["servers"].append(entry)
        else:
            site_info["firewalls"].append({"host": f"FW-{site_key}", "name": f"FW-{site_key}", "ip": "192.168.x.1"})
            site_info["switches"].append({"host": f"SW-{site_key}", "name": f"Core Switch {site_key}", "ip": "192.168.x.2"})
            if k_lower in ["barueri", "matriz", "hub"]:
                site_info["ups"].append({"host": f"Nobreak-{site_key}", "name": f"Nobreak-{site_key}", "ip": "192.168.x.3"})
                site_info["idrac"].extend([{"host": f"iDRAC-{i+1}", "name": f"Blade {i+1:02d}", "ip": f"192.168.x.{220+i}"} for i in range(5)])
                site_info["servers"].extend([{"host": f"SRV-HV{i+1}", "name": f"Host Hyper-V {i+1}", "ip": f"192.168.x.{10+i}"} for i in range(5)])
                site_info["aps"].extend([{"host": f"AP-{i+1}", "name": f"AP {i+1:02d}", "ip": f"192.168.x.{40+i}"} for i in range(5)])

        sites_data.append(site_info)

    return sites_data


def build_topology_layout(sites_data):
    """Calculates non-colliding canvas layout coordinates for arbitrary multi-site infrastructure."""
    all_nodes = []
    all_links = []
    site_areas = []

    def site_weight(s):
        score = len(s["switches"]) * 2 + len(s["servers"]) * 2 + len(s["idrac"]) + len(s["aps"])
        k_low = s["key"].lower()
        if any(w in k_low for w in ["matriz", "hub", "sede", "central", "barueri", "sp", "headquarter", "core", "datacenter"]):
            score += 1000
        return score

    hub_site = max(sites_data, key=site_weight)
    spoke_sites = [s for s in sites_data if s != hub_site]

    is_complex_hub = (len(hub_site["switches"]) > 2 or len(hub_site["servers"]) > 2 or len(hub_site["idrac"]) > 2)
    hub_width = 500 if is_complex_hub else 340
    spoke_width = 220
    canvas_width = max(1160, hub_width + len(spoke_sites) * spoke_width + 40)
    canvas_height = 760

    ordered_sites = []
    if len(spoke_sites) == 0:
        ordered_sites = [hub_site]
    elif len(spoke_sites) == 1:
        ordered_sites = [spoke_sites[0], hub_site]
    else:
        left_count = len(spoke_sites) // 2
        ordered_sites = spoke_sites[:left_count] + [hub_site] + spoke_sites[left_count:]

    cur_x = 20
    site_fw_nodes = []

    for s in ordered_sites:
        is_hub = (s == hub_site)
        w = hub_width if is_hub else spoke_width
        x_start = cur_x
        x_end = cur_x + w - 20
        x_c = (x_start + x_end) // 2

        site_areas.append([
            {
                "name": s["label"],
                "coord": [x_start, 20],
                "label": {
                    "show": True,
                    "position": "insideTop",
                    "offset": [0, 8],
                    "color": "#00ffd5" if is_hub else "#94a3b8",
                    "fontSize": 12 if is_hub else 11,
                    "fontWeight": "bold",
                    "letterSpacing": 1.5 if is_hub else 1.2
                },
                "itemStyle": {
                    "color": "rgba(15, 23, 42, 0.52)" if is_hub else "rgba(15, 23, 42, 0.38)",
                    "borderColor": "rgba(0, 229, 255, 0.40)" if is_hub else "rgba(56, 189, 248, 0.22)",
                    "borderWidth": 1.5 if is_hub else 1,
                    "shadowBlur": 14 if is_hub else 0,
                    "shadowColor": "rgba(0, 229, 255, 0.22)" if is_hub else "transparent"
                }
            },
            {"coord": [x_end, 740]}
        ])

        inet_id = f"inet-{s['key'].lower()}"
        fw_host_names = [d["host"] for d in s["firewalls"]] or [f"FW-{s['key']}"]
        all_nodes.append({
            "id": inet_id,
            "name": f"Internet {s['key']}",
            "sub": "Multi-WAN Link",
            "category": "Internet",
            "icon": "internet",
            "x": x_c, "y": 85, "r": 50 if is_hub else 46,
            "ip": "Multi-WAN / BGP",
            "site": s["label"],
            "siteKey": s["key"],
            "role": "Internet Uplink Multi-WAN",
            "hosts": fw_host_names,
            "wan": True
        })

        fw_id = f"fw-{s['key'].lower()}"
        fw_name = s["firewalls"][0]["name"] if s["firewalls"] else f"FW-{s['key']}"
        fw_ip = s["firewalls"][0]["ip"] if s["firewalls"] else "192.168.x.1"
        all_nodes.append({
            "id": fw_id,
            "name": fw_name,
            "sub": "FortiGate Hub SD-WAN" if is_hub else "FortiGate Spoke",
            "category": "Firewall",
            "icon": "firewall",
            "x": x_c, "y": 200, "r": 56 if is_hub else 48,
            "ip": fw_ip,
            "site": s["label"],
            "siteKey": s["key"],
            "role": "Firewall Core / Hub SD-WAN" if is_hub else "Firewall Filial / SD-WAN Spoke",
            "hosts": [d["name"] for d in s["firewalls"]] or [fw_name],
            "core": True
        })
        site_fw_nodes.append((fw_id, x_c, is_hub))

        all_links.append({
            "source": inet_id, "target": fw_id,
            "label": "WAN Uplink", "color": "#10b981", "width": 3.8 if is_hub else 3.0, "glow": 12 if is_hub else 8
        })

        sw_id = f"sw-core-{s['key'].lower()}"
        sw_name = s["switches"][0]["name"] if s["switches"] else f"SW-{s['key']}"
        sw_ip = s["switches"][0]["ip"] if s["switches"] else "192.168.x.2"

        if s["switches"]:
            all_nodes.append({
                "id": sw_id,
                "name": sw_name,
                "sub": "Core VLT 10G" if is_hub else "Core Switch",
                "category": "Switch",
                "icon": "switch",
                "x": x_c, "y": 310, "r": 52 if is_hub else 44,
                "ip": sw_ip,
                "site": s["label"],
                "siteKey": s["key"],
                "role": "Core Switch / Stacking",
                "hosts": [sw_name],
                "core": True
            })
            all_links.append({
                "source": fw_id, "target": sw_id,
                "label": "Trunk 10G" if is_hub else "1 Gbps",
                "color": "#38bdf8" if is_hub else "#3b82f6",
                "width": 4.5 if is_hub else 3.0, "glow": 14 if is_hub else 8
            })

        if s["ups"]:
            ups_id = f"ups-{s['key'].lower()}"
            ups_name = s["ups"][0]["name"]
            ups_ip = s["ups"][0]["ip"]
            ups_x = x_c - 180 if is_hub else x_c - 60
            all_nodes.append({
                "id": ups_id,
                "name": ups_name,
                "sub": "Nobreak Senoidal",
                "category": "Nobreak UPS",
                "icon": "battery",
                "x": ups_x, "y": 310, "r": 42,
                "ip": ups_ip,
                "site": s["label"],
                "siteKey": s["key"],
                "role": "Nobreak Senoidal",
                "hosts": [ups_name]
            })
            all_links.append({"source": ups_id, "target": fw_id, "label": "", "color": "#f59e0b", "width": 1.8, "dotted": True, "glow": 8})
            if s["switches"]:
                all_links.append({"source": ups_id, "target": sw_id, "label": "", "color": "#f59e0b", "width": 1.8, "dotted": True, "glow": 8})

        if is_hub and is_complex_hub:
            access_switches = s["switches"][1:5] if len(s["switches"]) > 1 else []
            lane_xs = [x_start + 70, x_start + 175, x_start + 285, x_start + 395]

            sw_node_ids = []
            for idx in range(4):
                lane_x = lane_xs[idx]
                if idx < len(access_switches):
                    asw = access_switches[idx]
                    asw_id = f"sw-acc-{idx}"
                    short_n = asw["name"].split(".")[-1] if "." in asw["name"] else asw["name"]
                    all_nodes.append({
                        "id": asw_id,
                        "name": f"SW-{short_n}",
                        "sub": "Acesso Dell",
                        "category": "Switch",
                        "icon": "switch",
                        "x": lane_x, "y": 410, "r": 36,
                        "ip": asw["ip"],
                        "site": s["label"],
                        "siteKey": s["key"],
                        "role": "Switch Acesso Dell",
                        "hosts": [asw["name"]]
                    })
                    all_links.append({"source": sw_id, "target": asw_id, "label": "", "color": "#60a5fa", "width": 2.2, "glow": 6})
                    sw_node_ids.append(asw_id)
                else:
                    sw_node_ids.append(sw_id)

            blade_count = min(len(s["idrac"]), 6)
            for b_idx in range(blade_count):
                idr = s["idrac"][b_idx]
                b_id = f"blade-{b_idx}"
                bx = lane_xs[2] + (-45 if b_idx % 2 == 0 else 45)
                by = 480 + (b_idx // 2) * 64
                all_nodes.append({
                    "id": b_id,
                    "name": f"Blade {b_idx+1:02d}",
                    "sub": idr["name"][:9],
                    "category": "Hardware Servidor",
                    "icon": "chip",
                    "x": bx, "y": by, "r": 28,
                    "ip": idr["ip"],
                    "site": s["label"],
                    "siteKey": s["key"],
                    "role": "Dell iDRAC Enterprise",
                    "hosts": [idr["name"]]
                })
                all_links.append({"source": sw_node_ids[2], "target": b_id, "label": "", "color": "#a855f7", "width": 1.8, "glow": 6})

            srv_count = len(s["servers"])
            hv_hosts = [srv["name"] for srv in s["servers"][:5]] if srv_count >= 5 else [srv["name"] for srv in s["servers"]]
            all_nodes.append({
                "id": "vm-cluster-sp",
                "name": "Cluster Hyper-V",
                "sub": f"{len(hv_hosts)} Hosts HV",
                "category": "Virtualização / Servidor",
                "icon": "server",
                "x": lane_xs[0], "y": 655, "r": 46,
                "ip": "192.168.0.x",
                "site": s["label"],
                "siteKey": s["key"],
                "role": "Cluster de Virtualização Hyper-V",
                "hosts": hv_hosts or ["HV-01", "HV-02"]
            })
            all_links.append({"source": sw_node_ids[0], "target": "vm-cluster-sp", "label": "Hyper-V", "color": "#8b5cf6", "width": 2.6, "glow": 8})

            app_hosts = [srv["name"] for srv in s["servers"][5:10]] if srv_count > 5 else (["SRV-AD01", "SRV-DC01"] if srv_count == 0 else [srv["name"] for srv in s["servers"][:2]])
            all_nodes.append({
                "id": "srv-sp",
                "name": "Servidores Matriz",
                "sub": "AD / DC / NGINX",
                "category": "Virtualização / Servidor",
                "icon": "server",
                "x": lane_xs[1], "y": 655, "r": 44,
                "ip": "192.168.0.x",
                "site": s["label"],
                "siteKey": s["key"],
                "role": "Servidores de Aplicação e Serviços",
                "hosts": app_hosts
            })
            all_links.append({"source": sw_node_ids[1], "target": "srv-sp", "label": "VMs", "color": "#8b5cf6", "width": 2.6, "glow": 8})

            ap_hosts = [ap["name"] for ap in s["aps"]]
            all_nodes.append({
                "id": "ap-sp",
                "name": f"{len(ap_hosts) or 5}x APs Wi-Fi",
                "sub": "UniFi Corporativo",
                "category": "Access Point",
                "icon": "wifi",
                "x": lane_xs[3], "y": 655, "r": 42,
                "ip": "192.168.0.x",
                "site": s["label"],
                "siteKey": s["key"],
                "role": "Access Points Corporativos",
                "hosts": ap_hosts or ["AP-01", "AP-02"]
            })
            all_links.append({"source": sw_node_ids[3], "target": "ap-sp", "label": "PoE+", "color": "#f43f5e", "width": 2.4, "glow": 8})

        else:
            cur_y = 420
            parent_id = sw_id if s["switches"] else fw_id

            if s["idrac"]:
                idr = s["idrac"][0]
                idr_id = f"hw-{s['key'].lower()}"
                all_nodes.append({
                    "id": idr_id,
                    "name": idr["name"][:14],
                    "sub": "iDRAC OOB",
                    "category": "Hardware Servidor",
                    "icon": "chip",
                    "x": x_c, "y": cur_y, "r": 34,
                    "ip": idr["ip"],
                    "site": s["label"],
                    "siteKey": s["key"],
                    "role": "Dell iDRAC Enterprise",
                    "hosts": [idr["name"]]
                })
                all_links.append({"source": parent_id, "target": idr_id, "label": "", "color": "#a855f7", "width": 2.0, "glow": 6})
                cur_y += 110

            if s["servers"]:
                srv = s["servers"][0]
                srv_id = f"srv-{s['key'].lower()}"
                all_nodes.append({
                    "id": srv_id,
                    "name": srv["name"],
                    "sub": "Domain Controller",
                    "category": "Virtualização / Servidor",
                    "icon": "server",
                    "x": x_c, "y": cur_y, "r": 36,
                    "ip": srv["ip"],
                    "site": s["label"],
                    "siteKey": s["key"],
                    "role": f"Servidor {s['key']}",
                    "hosts": [srv["name"]]
                })
                all_links.append({"source": parent_id, "target": srv_id, "label": "", "color": "#8b5cf6", "width": 2.2, "glow": 6})
                cur_y += 110

            if s["aps"]:
                ap_id = f"ap-{s['key'].lower()}"
                all_nodes.append({
                    "id": ap_id,
                    "name": f"{len(s['aps'])}x APs Wi-Fi",
                    "sub": f"UniFi {s['key']}",
                    "category": "Access Point",
                    "icon": "wifi",
                    "x": x_c, "y": cur_y if cur_y <= 655 else 655, "r": 40,
                    "ip": "DHCP",
                    "site": s["label"],
                    "siteKey": s["key"],
                    "role": f"Access Points {s['key']}",
                    "hosts": [ap["name"] for ap in s["aps"]]
                })
                all_links.append({"source": parent_id, "target": ap_id, "label": "PoE+", "color": "#f43f5e", "width": 2.2, "glow": 6})

        cur_x += w

    hub_fw_info = next(((fw, xc) for fw, xc, is_h in site_fw_nodes if is_h), None)
    if hub_fw_info:
        hub_fw, hub_xc = hub_fw_info
        for idx, (spoke_fw, spoke_xc, is_h) in enumerate(site_fw_nodes):
            if not is_h:
                if spoke_xc < hub_xc:
                    curve = 0.12
                else:
                    curve = -0.12 if idx % 2 == 0 else -0.18
                all_links.append({
                    "source": hub_fw, "target": spoke_fw,
                    "label": "", "color": "#00e5ff", "width": 2.2,
                    "dashed": True, "curveness": curve, "glow": 10
                })

    return all_nodes, all_links, site_areas, canvas_width, canvas_height


def render_echarts_js(all_nodes, all_links, site_areas, cw, ch):
    """Renders the self-contained Apache ECharts JavaScript runtime with live data bindings."""
    return (
        ECHARTS_TEMPLATE
        .replace("__ALL_NODES__", json.dumps(all_nodes, ensure_ascii=False, indent=2))
        .replace("__ALL_LINKS__", json.dumps(all_links, ensure_ascii=False, indent=2))
        .replace("__SITE_AREAS__", json.dumps(site_areas, ensure_ascii=False, indent=2))
        .replace("__CANVAS_WIDTH__", str(cw))
        .replace("__CANVAS_HEIGHT__", str(ch))
    )


def build_p4(all_nodes, all_links, site_areas, cw, ch):
    """Constructs the high-end ECharts multi-site topology panel."""
    echarts_code = render_echarts_js(all_nodes, all_links, site_areas, cw, ch)
    return {
        "id": 4,
        "title": "TOPOLOGIA DA REDE · ARQUITETURA MULTI-SITE (SD-WAN & COMPUTE)",
        "type": "volkovlabs-echarts-panel",
        "gridPos": {"x": 5, "y": 3, "w": 14, "h": 16},
        "targets": [
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {
                        "def": {
                            "category": "Transform",
                            "defaultParams": ["1m", "avg"],
                            "name": "groupBy",
                            "params": [{"name": "interval", "type": "string"}, {"name": "function", "options": ["avg", "min", "max", "sum", "count", "median", "first", "last"], "type": "string"}]
                        },
                        "params": ["1h", "last"],
                        "text": "groupBy(1h, last)"
                    }
                ],
                "group": {"filter": "/^Filiais\\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "/^(ICMP ping|SNMP agent availability|Zabbix agent availability)$/"},
                "itemTag": {"filter": ""},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0",
                "refId": "A"
            },
            {
                "application": {"filter": ""},
                "datasource": {"type": "alexanderzobnin-zabbix-datasource", "uid": "${datasource}"},
                "functions": [
                    {
                        "def": {
                            "category": "Transform",
                            "defaultParams": ["1m", "avg"],
                            "name": "groupBy",
                            "params": [{"name": "interval", "type": "string"}, {"name": "function", "options": ["avg", "min", "max", "sum", "count", "median", "first", "last"], "type": "string"}]
                        },
                        "params": ["1h", "last"],
                        "text": "groupBy(1h, last)"
                    }
                ],
                "group": {"filter": "/^Filiais\\/$site$/"},
                "host": {"filter": "/.*/"},
                "item": {"filter": "/interface\\s+(?!fortilink|loopback)(wan\\d*|uplink\\d*|internet\\d*|a\\([^)]*(wan|internet|net\\s*fiber|mbps|ligga|its|easy|america|mega)[^)]*\\)).*: operational status/i"},
                "itemTag": {"filter": ""},
                "options": {"disableDataAlignment": True, "showDisabledItems": False, "skipEmptyValues": True, "useTrends": "false"},
                "queryType": "0",
                "refId": "B"
            }
        ],
        "options": {
            "getOption": echarts_code,
            "renderer": "canvas"
        }
    }


def build(cfg, datasource_uid="zabbix", api=None):
    """Builds the complete non-colliding Multi-Site Topology Dashboard (v3)."""
    sites_data = discover_sites_and_devices(api, cfg)
    all_nodes, all_links, site_areas, cw, ch = build_topology_layout(sites_data)

    p1 = copy.deepcopy(PANEL_1_DEF)
    p102 = copy.deepcopy(PANEL_102_DEF)
    p103 = copy.deepcopy(PANEL_103_DEF)
    p104 = copy.deepcopy(PANEL_104_DEF)
    p2 = copy.deepcopy(PANEL_2_DEF)
    p3 = copy.deepcopy(PANEL_3_DEF)
    p4 = build_p4(all_nodes, all_links, site_areas, cw, ch)
    p5 = copy.deepcopy(PANEL_5_DEF)
    p6 = copy.deepcopy(PANEL_6_DEF)
    p7 = copy.deepcopy(PANEL_7_DEF)
    p8 = copy.deepcopy(PANEL_8_DEF)

    panels = [p1, p102, p103, p104, p2, p3, p4, p5, p6, p7, p8]

    # Dynamic variables
    site_options = [{"text": "Todas", "value": "$__all", "selected": True}]
    for s in sites_data:
        site_options.append({"text": s["label"], "value": s["key"], "selected": False})

    query_str = ", ".join(f"{s['label']} : {s['key']}" for s in sites_data)

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
            "options": site_options,
            "current": {"selected": True, "text": "Todas", "value": "$__all"},
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
                "group": "/^Filiais\\/$site$/",
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
        "tags": ["autodiscovery", "autodiscovery-v3", "noc", "topologia"],
        "templating": {"list": variables},
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m"]},
        "timezone": "browser",
        "title": TITLE,
        "uid": UID,
        "version": 1
    }
