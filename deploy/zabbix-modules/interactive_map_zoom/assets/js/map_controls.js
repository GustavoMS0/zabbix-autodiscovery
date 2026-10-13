/**
 * NOC Interactive Map Controls for Zabbix Web UI.
 * Enables smooth mouse-wheel zoom, drag-to-pan, fit-to-screen and alert focusing on all native Zabbix SVG maps.
 */
(function () {
  'use strict';

  console.log('✅ [AutoDiscovery NOC] Módulo de Zoom e Interatividade de Mapas Inicializado!');

  function findMapSvgs() {
    const svgs = Array.from(document.querySelectorAll('svg'));
    return svgs.filter((svg) => {
      // Must not be an inline icon or small symbol
      const w = parseFloat(svg.getAttribute('width')) || svg.clientWidth || 0;
      const h = parseFloat(svg.getAttribute('height')) || svg.clientHeight || 0;
      if (w > 0 && w < 200 && h > 0 && h < 200) return false;

      // Identify by Zabbix map structure
      const hasMapGroup = svg.querySelector('.map-container, .map-element, g[class*="map"], image, [data-selementid]');
      const isInMapContainer = svg.closest('.flickerfreescreen, [id*="sysmap"], .dashboard-widget-map, [class*="widget-map"]');

      return hasMapGroup || isInMapContainer || w >= 400;
    });
  }

  function setupSvgInteractivity(svg) {
    if (svg.dataset.nocInteractiveMapActive === 'true') return;
    svg.dataset.nocInteractiveMapActive = 'true';

    // The wrapper that holds the SVG
    const wrapper = svg.closest('.flickerfreescreen') || svg.parentElement;
    if (!wrapper) return;

    wrapper.style.position = 'relative';
    wrapper.style.overflow = 'hidden';
    wrapper.style.cursor = 'grab';
    if (!wrapper.style.minHeight) {
      wrapper.style.minHeight = '500px';
    }

    let scale = 1;
    let panX = 0;
    let panY = 0;
    let isDragging = false;
    let startX = 0;
    let startY = 0;

    svg.style.transformOrigin = '0 0';
    svg.style.transition = 'transform 0.05s ease-out';

    function updateTransform() {
      svg.style.transform = `translate(${panX}px, ${panY}px) scale(${scale})`;
    }

    function fitToScreen() {
      const cWidth = wrapper.clientWidth || window.innerWidth;
      const cHeight = wrapper.clientHeight || (window.innerHeight - 180);
      const tWidth = parseFloat(svg.getAttribute('width')) || svg.getBoundingClientRect().width / scale || 2000;
      const tHeight = parseFloat(svg.getAttribute('height')) || svg.getBoundingClientRect().height / scale || 1000;

      const scaleX = (cWidth - 60) / tWidth;
      const scaleY = (cHeight - 60) / tHeight;
      scale = Math.min(scaleX, scaleY, 1.0);
      panX = Math.max((cWidth - tWidth * scale) / 2, 20);
      panY = 20;

      svg.style.transition = 'transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
      updateTransform();
      setTimeout(() => { svg.style.transition = 'transform 0.05s ease-out'; }, 300);
    }

    // Mouse Wheel Zoom
    wrapper.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = wrapper.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      const factor = e.deltaY < 0 ? 1.15 : 0.87;
      const newScale = Math.min(Math.max(scale * factor, 0.15), 4.5);

      panX = mouseX - (mouseX - panX) * (newScale / scale);
      panY = mouseY - (mouseY - panY) * (newScale / scale);
      scale = newScale;

      svg.style.transition = 'none';
      updateTransform();
    }, { passive: false });

    // Drag to Pan
    wrapper.addEventListener('mousedown', (e) => {
      if (e.target.closest('.zbx-map-hud') || e.button !== 0) return;
      isDragging = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
      wrapper.style.cursor = 'grabbing';
    });

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      panX = e.clientX - startX;
      panY = e.clientY - startY;
      svg.style.transition = 'none';
      updateTransform();
    });

    window.addEventListener('mouseup', () => {
      if (isDragging) {
        isDragging = false;
        wrapper.style.cursor = 'grab';
      }
    });

    // Problem Focus
    function findProblemElements() {
      return Array.from(svg.querySelectorAll(
        '.map-element-problem, [class*="problem"], [stroke="#E45959"], [stroke="#E97659"], [stroke="#FFA059"], [fill="#E45959"]'
      ));
    }

    let currentProblemIdx = -1;
    function focusNextProblem() {
      const probs = findProblemElements();
      if (probs.length === 0) {
        // Fallback search in label text
        const labels = Array.from(svg.querySelectorAll('text')).filter((t) => {
          return t.textContent && /DOWN|DISASTER|HIGH|CRÍTICO|PROBLEM|WARN/i.test(t.textContent);
        });
        if (labels.length > 0) probs.push(...labels);
      }

      if (probs.length === 0) {
        alert('Nenhum equipamento em alerta detectado neste mapa no momento.');
        return;
      }

      currentProblemIdx = (currentProblemIdx + 1) % probs.length;
      const el = probs[currentProblemIdx];
      const bbox = el.getBBox ? el.getBBox() : el.getBoundingClientRect();

      const cWidth = wrapper.clientWidth || window.innerWidth;
      const cHeight = wrapper.clientHeight || window.innerHeight;

      scale = 1.35;
      const posX = bbox.x !== undefined ? bbox.x + bbox.width / 2 : (bbox.left + bbox.width / 2);
      const posY = bbox.y !== undefined ? bbox.y + bbox.height / 2 : (bbox.top + bbox.height / 2);

      panX = cWidth / 2 - posX * scale;
      panY = cHeight / 2 - posY * scale;

      svg.style.transition = 'transform 0.4s cubic-bezier(0.16, 1, 0.3, 1)';
      updateTransform();
      setTimeout(() => { svg.style.transition = 'transform 0.05s ease-out'; }, 400);
    }

    // Avoid duplicate HUD
    let hud = wrapper.querySelector('.zbx-map-hud');
    if (!hud) {
      hud = document.createElement('div');
      hud.className = 'zbx-map-hud';
      hud.innerHTML = `
        <button class="hud-btn" id="hud-zoom-in" title="Aproximar (+)">+</button>
        <button class="hud-btn" id="hud-zoom-out" title="Afastar (−)">−</button>
        <button class="hud-btn" id="hud-fit" title="Ajustar Mapa à Tela">🎯 Ajustar</button>
        <button class="hud-btn hud-btn-alert" id="hud-alert" title="Focar Próximo Alerta Ativo">🚨 Focar Alarme</button>
      `;

      wrapper.appendChild(hud);

      hud.querySelector('#hud-zoom-in').addEventListener('click', (e) => {
        e.stopPropagation();
        scale = Math.min(scale * 1.3, 4.5);
        svg.style.transition = 'transform 0.2s ease';
        updateTransform();
      });

      hud.querySelector('#hud-zoom-out').addEventListener('click', (e) => {
        e.stopPropagation();
        scale = Math.max(scale / 1.3, 0.15);
        svg.style.transition = 'transform 0.2s ease';
        updateTransform();
      });

      hud.querySelector('#hud-fit').addEventListener('click', (e) => {
        e.stopPropagation();
        fitToScreen();
      });

      hud.querySelector('#hud-alert').addEventListener('click', (e) => {
        e.stopPropagation();
        focusNextProblem();
      });
    }

    // Initial fit
    setTimeout(fitToScreen, 200);
  }

  function scanAndInit() {
    const svgs = findMapSvgs();
    svgs.forEach(setupSvgInteractivity);
  }

  // Run on load and poll every 800ms for AJAX map loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanAndInit);
  } else {
    scanAndInit();
  }

  setInterval(scanAndInit, 800);
})();
