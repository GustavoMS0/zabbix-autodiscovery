/**
 * NOC Interactive Map Controls for Zabbix Web UI.
 * Enables smooth mouse-wheel zoom, drag-to-pan, fit-to-screen and alert focusing on all Zabbix maps.
 */
(function () {
  'use strict';

  function initMapInteractivity() {
    // Select map container on Monitoring -> Maps or Dashboard widgets
    const containers = document.querySelectorAll(
      '.sysmap-scroll-container, .map-container, [id^="sysmap_"], .dashboard-widget-map'
    );

    containers.forEach((container) => {
      if (container.dataset.zbxInteractiveMap) return;

      // Find SVG or image map element
      const target = container.querySelector('svg.sysmap, svg, img[src*="map.php"], .sysmap') ||
                     (container.children.length === 1 ? container.firstElementChild : null);

      if (!target) return;
      container.dataset.zbxInteractiveMap = 'true';

      container.style.overflow = 'hidden';
      container.style.position = 'relative';
      container.style.cursor = 'grab';

      let scale = 1;
      let panX = 0;
      let panY = 0;
      let isDragging = false;
      let startX = 0;
      let startY = 0;

      target.style.transformOrigin = '0 0';
      target.style.transition = 'transform 0.05s ease-out';

      function updateTransform() {
        target.style.transform = `translate(${panX}px, ${panY}px) scale(${scale})`;
      }

      function fitToScreen() {
        const cWidth = container.clientWidth || window.innerWidth;
        const cHeight = container.clientHeight || (window.innerHeight - 180);
        const tWidth = (target.getBoundingClientRect().width / scale) ||
                       parseFloat(target.getAttribute('width')) || 2000;
        const tHeight = (target.getBoundingClientRect().height / scale) ||
                        parseFloat(target.getAttribute('height')) || 1000;

        const scaleX = (cWidth - 60) / tWidth;
        const scaleY = (cHeight - 60) / tHeight;
        scale = Math.min(scaleX, scaleY, 1.0);
        panX = Math.max((cWidth - tWidth * scale) / 2, 20);
        panY = 20;

        target.style.transition = 'transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
        updateTransform();
        setTimeout(() => { target.style.transition = 'transform 0.05s ease-out'; }, 300);
      }

      // Mouse Wheel Zoom
      container.addEventListener('wheel', (e) => {
        e.preventDefault();
        const rect = container.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        const factor = e.deltaY < 0 ? 1.15 : 0.87;
        const newScale = Math.min(Math.max(scale * factor, 0.15), 4.0);

        panX = mouseX - (mouseX - panX) * (newScale / scale);
        panY = mouseY - (mouseY - panY) * (newScale / scale);
        scale = newScale;

        updateTransform();
      }, { passive: false });

      // Click & Drag to Pan
      container.addEventListener('mousedown', (e) => {
        if (e.target.closest('.zbx-map-hud') || e.button !== 0) return;
        isDragging = true;
        startX = e.clientX - panX;
        startY = e.clientY - panY;
        container.style.cursor = 'grabbing';
      });

      window.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        panX = e.clientX - startX;
        panY = e.clientY - startY;
        updateTransform();
      });

      window.addEventListener('mouseup', () => {
        if (isDragging) {
          isDragging = false;
          container.style.cursor = 'grab';
        }
      });

      // Find Problem Elements
      function findProblemElements() {
        return Array.from(target.querySelectorAll(
          '.map-element-problem, [class*="problem"], [stroke="#E45959"], [stroke="#E97659"], [stroke="#FFA059"], [fill="#E45959"]'
        ));
      }

      let currentProblemIdx = -1;
      function focusNextProblem() {
        const probs = findProblemElements();
        if (probs.length === 0) {
          // If no SVG problem nodes found, try finding host labels with active text
          const labels = Array.from(target.querySelectorAll('text, div, span')).filter((el) => {
            return (el.textContent && /DOWN|DISASTER|HIGH|CRÍTICO|PROBLEM|WARN/i.test(el.textContent));
          });
          if (labels.length > 0) {
            probs.push(...labels);
          }
        }

        if (probs.length === 0) {
          alert('Nenhum equipamento em alerta detectado neste mapa no momento.');
          return;
        }

        currentProblemIdx = (currentProblemIdx + 1) % probs.length;
        const el = probs[currentProblemIdx];
        const bbox = el.getBBox ? el.getBBox() : el.getBoundingClientRect();

        const cWidth = container.clientWidth || window.innerWidth;
        const cHeight = container.clientHeight || window.innerHeight;

        scale = 1.35;
        const posX = bbox.x !== undefined ? bbox.x + bbox.width / 2 : (bbox.left + bbox.width / 2);
        const posY = bbox.y !== undefined ? bbox.y + bbox.height / 2 : (bbox.top + bbox.height / 2);

        panX = cWidth / 2 - posX * scale;
        panY = cHeight / 2 - posY * scale;

        target.style.transition = 'transform 0.4s cubic-bezier(0.16, 1, 0.3, 1)';
        updateTransform();
        setTimeout(() => { target.style.transition = 'transform 0.05s ease-out'; }, 400);
      }

      // Floating HUD Bar
      const hud = document.createElement('div');
      hud.className = 'zbx-map-hud';
      hud.innerHTML = `
        <button class="hud-btn" id="hud-zoom-in" title="Aproximar (+)">+</button>
        <button class="hud-btn" id="hud-zoom-out" title="Afastar (−)">−</button>
        <button class="hud-btn" id="hud-fit" title="Ajustar Mapa à Tela">🎯 Ajustar</button>
        <button class="hud-btn hud-btn-alert" id="hud-alert" title="Focar Próximo Alerta Ativo">🚨 Focar Alarme</button>
      `;

      container.appendChild(hud);

      hud.querySelector('#hud-zoom-in').addEventListener('click', (e) => {
        e.stopPropagation();
        scale = Math.min(scale * 1.3, 4.0);
        updateTransform();
      });

      hud.querySelector('#hud-zoom-out').addEventListener('click', (e) => {
        e.stopPropagation();
        scale = Math.max(scale / 1.3, 0.15);
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

      // Auto-fit on initial render
      setTimeout(fitToScreen, 250);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMapInteractivity);
  } else {
    initMapInteractivity();
  }

  // Observe dynamically loaded widgets
  const obs = new MutationObserver(() => initMapInteractivity());
  obs.observe(document.body, { childList: true, subtree: true });
})();
