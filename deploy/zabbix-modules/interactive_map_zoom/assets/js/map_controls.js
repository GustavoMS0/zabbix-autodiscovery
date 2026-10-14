/**
 * NOC Interactive Map Controls for Zabbix Web UI.
 *
 * Adds mouse-wheel zoom, drag-to-pan, fit-to-view and "next problem" focus to native Zabbix maps
 * (map widget on dashboards and Monitoring -> Maps). Only SVGs rendered by Zabbix's SVGMap
 * (a direct <g class="map-container"> child) are touched: graphs, honeycomb and other widgets are
 * left alone.
 *
 * The map SVG is scaled by Zabbix through its viewBox (preserveAspectRatio xMinYMin meet), so all
 * math converts between three spaces: map units (viewBox), SVG layout pixels and wrapper pixels.
 * The HUD is built with DOM APIs and textContent only (no innerHTML).
 */
(function () {
  'use strict';

  const MIN_SCALE = 0.2;
  const MAX_SCALE = 8;
  const DRAG_THRESHOLD = 4;
  const FOCUS_SCALE = 2;
  // Default Zabbix severity colours -> rank (higher = more severe).
  const SEVERITY_RANK = {
    '#E45959': 5, '#E97659': 4, '#FFA059': 3, '#FFC859': 2, '#7499FF': 1, '#97AAB3': 0
  };
  const OK_COLOURS = ['#009900', '#00AA00', '#59DB8F'];

  const states = new WeakMap(); // wrapper element -> state
  let activeDrag = null;

  function isZabbixMap(svg) {
    return svg instanceof SVGSVGElement && svg.querySelector(':scope > g.map-container') !== null;
  }

  // Size of the drawn map inside the SVG box, in SVG layout pixels, plus px per map unit.
  function contentBox(st) {
    const svg = st.svg;
    const vb = svg.viewBox && svg.viewBox.baseVal;
    const w = svg.clientWidth;
    const h = svg.clientHeight;
    if (!vb || !vb.width || !vb.height) {
      return { k: 1, w: w, h: h };
    }
    const k = Math.min(w / vb.width, h / vb.height);
    return { k: k, w: vb.width * k, h: vb.height * k };
  }

  // Untransformed top-left of the transformed element relative to the wrapper (transform-origin
  // is 0 0, so the scale does not move the top-left corner; only the translation does).
  function svgOrigin(st) {
    const wr = st.wrapper.getBoundingClientRect();
    const tr = st.target.getBoundingClientRect();
    return { x: tr.left - wr.left - st.panX, y: tr.top - wr.top - st.panY };
  }

  // Offset of the SVG inside the transformed element, in unscaled pixels (0 when they are the same).
  function svgOffset(st) {
    if (st.target === st.svg) return { x: 0, y: 0 };
    const tr = st.target.getBoundingClientRect();
    const sr = st.svg.getBoundingClientRect();
    return { x: (sr.left - tr.left) / st.scale, y: (sr.top - tr.top) / st.scale };
  }

  function transformValue(st) {
    return `translate(${st.panX}px, ${st.panY}px) scale(${st.scale})`;
  }

  function apply(st, duration) {
    const el = st.target;
    el.style.transformOrigin = '0 0';
    el.style.transition = duration ? `transform ${duration}ms cubic-bezier(0.16, 1, 0.3, 1)` : 'none';
    st.expected = transformValue(st);
    el.style.transform = st.expected;
    updateZoomLabel(st);
  }

  // Monitoring -> Maps shows the map at full size inside a scrolling box that grows with the map:
  // limit that box to the visible part of the window so panning replaces the scrollbars.
  function sizePageWrapper(st) {
    if (!st.pageMode) return;
    const top = st.wrapper.getBoundingClientRect().top;
    st.wrapper.style.height = `${Math.max(300, window.innerHeight - top - 16)}px`;
  }

  function zoomAt(st, mx, my, newScale, duration) {
    newScale = Math.min(Math.max(newScale, MIN_SCALE), MAX_SCALE);
    const o = svgOrigin(st);
    const px = (mx - o.x - st.panX) / st.scale;
    const py = (my - o.y - st.panY) / st.scale;
    st.panX = mx - o.x - px * newScale;
    st.panY = my - o.y - py * newScale;
    st.scale = newScale;
    apply(st, duration);
  }

  function zoomCenter(st, factor) {
    st.userMoved = true;
    zoomAt(st, st.wrapper.clientWidth / 2, st.wrapper.clientHeight / 2, st.scale * factor, 200);
  }

  // Fit the whole map in the wrapper and centre it. Small maps are not enlarged past 100 %.
  function fit(st, duration) {
    const W = st.wrapper.clientWidth;
    const H = st.wrapper.clientHeight;
    const c = contentBox(st);
    if (!W || !H || !c.w || !c.h) return;
    const o = svgOrigin(st);
    const off = svgOffset(st);
    st.scale = Math.min(W / c.w, H / c.h, 1);
    st.panX = (W - c.w * st.scale) / 2 - o.x - off.x * st.scale;
    st.panY = (H - c.h * st.scale) / 2 - o.y - off.y * st.scale;
    st.userMoved = false;
    apply(st, duration);
  }

  function problemElements(st) {
    const svg = st.svg;
    const items = [];
    // Problem highlight: an unclassed ellipse filled with the severity colour behind the icon.
    svg.querySelectorAll('.map-elements ellipse:not(.selection)').forEach((el) => {
      const fill = (el.getAttribute('fill') || '').toUpperCase();
      if (!fill || fill === 'NONE') return;
      items.push({ el: el, rank: fill in SEVERITY_RANK ? SEVERITY_RANK[fill] : 0 });
    });
    // Maps without highlight: fall back to trigger status lines that are not "OK" green.
    if (items.length === 0) {
      svg.querySelectorAll('tspan[data-type="trigger"]').forEach((t) => {
        const fill = (t.getAttribute('fill') || '').toUpperCase();
        if (fill && OK_COLOURS.indexOf(fill) === -1) {
          items.push({ el: t.closest('text') || t, rank: 0 });
        }
      });
    }
    // Most severe first, then left-to-right / top-to-bottom for a stable order.
    items.forEach((it) => { it.box = it.el.getBoundingClientRect(); });
    items.sort((a, b) => (b.rank - a.rank) || (a.box.top - b.box.top) || (a.box.left - b.box.left));
    return items;
  }

  function pulse(st, el) {
    const r = el.getBoundingClientRect();
    const wr = st.wrapper.getBoundingClientRect();
    const ring = document.createElement('div');
    ring.className = 'zbx-map-pulse';
    const size = Math.max(r.width, r.height, 24) + 24;
    ring.style.width = ring.style.height = `${size}px`;
    ring.style.left = `${r.left - wr.left + r.width / 2 - size / 2}px`;
    ring.style.top = `${r.top - wr.top + r.height / 2 - size / 2}px`;
    st.wrapper.appendChild(ring);
    setTimeout(() => ring.remove(), 1600);
  }

  function focusNextProblem(st) {
    const items = problemElements(st);
    if (items.length === 0) {
      flash(st, 'Nenhum alerta neste mapa');
      return;
    }
    st.problemIdx = (st.problemIdx + 1) % items.length;
    const el = items[st.problemIdx].el;
    const r = el.getBoundingClientRect();
    const wr = st.wrapper.getBoundingClientRect();
    // Element centre in wrapper pixels, then zoom so that point ends up in the middle.
    const cx = r.left - wr.left + r.width / 2;
    const cy = r.top - wr.top + r.height / 2;
    const o = svgOrigin(st);
    const px = (cx - o.x - st.panX) / st.scale;
    const py = (cy - o.y - st.panY) / st.scale;
    const c = contentBox(st);
    // FOCUS_SCALE is relative to the map's natural size (1 map unit = 1 px).
    st.scale = Math.min(Math.max(FOCUS_SCALE / (c.k || 1), st.scale, MIN_SCALE), MAX_SCALE);
    st.panX = st.wrapper.clientWidth / 2 - o.x - px * st.scale;
    st.panY = st.wrapper.clientHeight / 2 - o.y - py * st.scale;
    st.userMoved = true;
    apply(st, 400);
    setTimeout(() => pulse(st, el), 420);
    flash(st, `Alerta ${st.problemIdx + 1} de ${items.length}`);
  }

  function updateZoomLabel(st) {
    if (!st.zoomLabel) return;
    const c = contentBox(st);
    st.zoomLabel.textContent = `${Math.round(st.scale * (c.k || 1) * 100)}%`;
  }

  function flash(st, text) {
    if (!st.message) return;
    st.message.textContent = text;
    st.message.classList.add('visible');
    clearTimeout(st.messageTimer);
    st.messageTimer = setTimeout(() => st.message.classList.remove('visible'), 2200);
  }

  function buildHud(st) {
    const hud = document.createElement('div');
    hud.className = 'zbx-map-hud';

    function addButton(label, title, extraClass, onClick) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = extraClass ? `hud-btn ${extraClass}` : 'hud-btn';
      btn.title = title;
      btn.setAttribute('aria-label', title);
      btn.textContent = label;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        onClick();
      });
      hud.appendChild(btn);
      return btn;
    }

    addButton('−', 'Afastar', 'hud-zoom-out', () => zoomCenter(st, 1 / 1.3));
    st.zoomLabel = document.createElement('span');
    st.zoomLabel.className = 'hud-zoom-label';
    hud.appendChild(st.zoomLabel);
    addButton('+', 'Aproximar', 'hud-zoom-in', () => zoomCenter(st, 1.3));
    addButton('Ajustar', 'Ajustar o mapa à área visível', 'hud-fit', () => fit(st, 300));
    addButton('Próximo alerta', 'Centralizar o próximo elemento com problema (mais grave primeiro)',
      'hud-btn-alert', () => focusNextProblem(st));

    st.message = document.createElement('div');
    st.message.className = 'zbx-map-hud-message';
    st.message.setAttribute('role', 'status');

    // Keep pointer/wheel events on the HUD from reaching the map.
    ['pointerdown', 'wheel', 'dblclick'].forEach((type) => {
      hud.addEventListener(type, (e) => e.stopPropagation());
    });

    st.wrapper.appendChild(hud);
    st.wrapper.appendChild(st.message);
    st.hud = hud;
  }

  function attachWrapperEvents(st) {
    const wrapper = st.wrapper;

    wrapper.addEventListener('wheel', (e) => {
      if (!st.svg.isConnected) return;
      e.preventDefault();
      const wr = wrapper.getBoundingClientRect();
      const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
      st.userMoved = true;
      zoomAt(st, e.clientX - wr.left, e.clientY - wr.top, st.scale * factor, 0);
    }, { passive: false });

    wrapper.addEventListener('pointerdown', (e) => {
      if (e.button !== 0 || e.target.closest('.zbx-map-hud')) return;
      activeDrag = { st: st, id: e.pointerId, x: e.clientX, y: e.clientY, panX: st.panX, panY: st.panY, moved: false };
    });

    // A drag that ends on a map element must not open the element's context menu.
    wrapper.addEventListener('click', (e) => {
      if (st.suppressClick) {
        st.suppressClick = false;
        e.preventDefault();
        e.stopPropagation();
      }
    }, true);

    wrapper.addEventListener('dblclick', (e) => {
      if (e.target.closest('.zbx-map-hud')) return;
      fit(st, 300);
    });

    if (window.ResizeObserver) {
      new ResizeObserver(() => {
        if (!st.userMoved) fit(st, 0);
        else updateZoomLabel(st);
      }).observe(wrapper);
    }
  }

  // One set of window listeners for every map (no per-map leaks).
  window.addEventListener('pointermove', (e) => {
    const d = activeDrag;
    if (!d || e.pointerId !== d.id) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    if (!d.moved) {
      if (Math.abs(dx) < DRAG_THRESHOLD && Math.abs(dy) < DRAG_THRESHOLD) return;
      d.moved = true;
      d.st.wrapper.classList.add('zbx-map-dragging');
    }
    d.st.panX = d.panX + dx;
    d.st.panY = d.panY + dy;
    d.st.userMoved = true;
    apply(d.st, 0);
  });

  function endDrag(e) {
    const d = activeDrag;
    if (!d || (e && e.pointerId !== d.id)) return;
    if (d.moved) {
      d.st.suppressClick = true;
      // If no click follows (pointer released outside an element), clear the flag.
      setTimeout(() => { d.st.suppressClick = false; }, 0);
      d.st.wrapper.classList.remove('zbx-map-dragging');
    }
    activeDrag = null;
  }
  window.addEventListener('pointerup', endDrag);
  window.addEventListener('pointercancel', endDrag);

  // Zabbix may rewrite the style attribute when it refreshes the map: keep the user's view.
  function watchTarget(st) {
    if (st.styleObserver) st.styleObserver.disconnect();
    st.styleObserver = new MutationObserver(() => {
      if (st.expected && st.target.style.transform !== st.expected) {
        st.target.style.transformOrigin = '0 0';
        st.target.style.transform = st.expected;
      }
    });
    st.styleObserver.observe(st.target, { attributes: true, attributeFilter: ['style'] });
  }

  // Dashboard map widget: the SVG fills its container and is scaled through its viewBox.
  // Monitoring -> Maps: the SVG is full size inside .flickerfreescreen (which clips its children)
  // inside .sysmap-scroll-container, so the flickerfreescreen is moved and the scroll box clips.
  function resolve(svg) {
    const scroll = svg.closest('.sysmap-scroll-container');
    if (scroll) {
      return { wrapper: scroll, target: svg.closest('.flickerfreescreen') || svg, pageMode: true };
    }
    return { wrapper: svg.parentElement, target: svg, pageMode: false };
  }

  function setup(svg) {
    if (svg.dataset.nocInteractiveMapActive === 'true') return;
    const r = resolve(svg);
    if (!r.wrapper) return;
    svg.dataset.nocInteractiveMapActive = 'true';

    let st = states.get(r.wrapper);
    if (st) {
      // Same container, new SVG (map refresh): keep zoom/pan and re-apply it.
      st.svg = svg;
      st.target = r.target;
      st.problemIdx = -1;
      watchTarget(st);
      if (st.userMoved) apply(st, 0);
      else requestAnimationFrame(() => fit(st, 0));
      return;
    }

    st = {
      svg: svg, target: r.target, wrapper: r.wrapper, pageMode: r.pageMode,
      scale: 1, panX: 0, panY: 0, problemIdx: -1, userMoved: false
    };
    states.set(r.wrapper, st);
    r.wrapper.classList.add('zbx-map-interactive');
    if (getComputedStyle(r.wrapper).position === 'static') r.wrapper.style.position = 'relative';
    if (st.pageMode) {
      sizePageWrapper(st);
      window.addEventListener('resize', () => sizePageWrapper(st));
    }

    buildHud(st);
    attachWrapperEvents(st);
    watchTarget(st);
    requestAnimationFrame(() => fit(st, 0));
  }

  function scan(root) {
    const scope = root && root.querySelectorAll ? root : document;
    if (scope instanceof SVGSVGElement) {
      if (isZabbixMap(scope)) setup(scope);
      return;
    }
    scope.querySelectorAll('svg').forEach((svg) => {
      if (isZabbixMap(svg)) setup(svg);
    });
  }

  let scheduled = false;
  const pending = new Set();
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1) pending.add(node);
      }
    }
    if (scheduled || pending.size === 0) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      const nodes = Array.from(pending);
      pending.clear();
      nodes.forEach((n) => {
        if (n.isConnected) scan(n.closest('svg') || n);
      });
    });
  });

  function start() {
    scan(document);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
