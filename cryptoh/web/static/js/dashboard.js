(function () {
  'use strict';

  const API_BASE = '';
  const feed = document.getElementById('feed');
  const statusText = document.getElementById('status-text');
  const windowCount = document.getElementById('window-count');
  const vL2 = document.getElementById('v-l2');
  const vMult = document.getElementById('v-mult');
  const vVotes = document.getElementById('v-votes');
  const mitContainer = document.getElementById('mitigation');

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function setStatus(text, kind) {
    statusText.textContent = text;
    statusText.className = 'status ' + (kind || 'normal');
  }

  function appendEvent(ev) {
    if (!feed.querySelector('.empty')) {
      const empty = feed.querySelector('.empty');
      if (empty) empty.remove();
    }
    const el = document.createElement('div');
    el.className = 'event anomaly fade-in';
    const diag = (ev.diagnosis && ev.diagnosis.diagnosis) ? ev.diagnosis.diagnosis : 'anomaly';
    const confidence = (ev.diagnosis && ev.diagnosis.confidence) ? ev.diagnosis.confidence.total : null;
    el.innerHTML = `
      <div class="event-head">
        <span>w${esc(ev.window)} · ${esc(ev.nodes ? ev.nodes.length : 0)} nodes</span>
        <span>votes ${esc(ev.signals.votes)}/3</span>
      </div>
      <div class="event-body">${esc(diag)}</div>
      ${confidence != null ? `<div class="event-body">confidence ${Number(confidence).toFixed(2)}</div>` : ''}
    `;
    feed.prepend(el);
    if (confidence != null && Number(confidence) > 0.9) {
      try { confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 }, colors: ['#00ffff', '#ff00ff'] }); } catch {}
    }
    return el;
  }

  function renderMitigation(ev) {
    if (!mitContainer) return;
    const m = (ev.diagnosis && ev.diagnosis.mitigation) || {};
    const script = m.script || '';
    if (!script) return;
    mitContainer.innerHTML = `
      <pre><code class="language-bash">${esc(script)}</code></pre>
      <div class="notice">${esc(m.explanation || 'review before applying — scripts are never applied automatically')}</div>
    `;
    try { hljs.highlightAll(); } catch {}
  }

  function renderTopologyFromEvent(ev) {
    const dot = ev.dot || '';
    if (!dot || typeof window.renderTopology !== 'function') return;
    try { window.renderTopology(dot); } catch {}
  }

  async function loadDetect() {
    try {
      const r = await fetch(API_BASE + '/api/v1/detect');
      const data = await r.json();
      if (!data || data.note === 'no telemetry analyzed yet — POST edges to /api/v1/diagnose') return;
      vL2.textContent = data.signals.lambda2 != null ? data.signals.lambda2.toFixed(3) : '—';
      vMult.textContent = data.signals.multiplicity != null ? String(data.signals.multiplicity) : '—';
      vVotes.textContent = String(data.votes ?? '—');
      windowCount.textContent = 'windows: ' + String(data.windows ?? 0);
      setStatus(data.anomaly ? 'ANOMALY' : 'normal', data.anomaly ? 'anomaly' : 'normal');
    } catch {}
  }

  function connectStream() {
    const src = new EventSource(API_BASE + '/api/v1/stream');
    src.addEventListener('open', () => setStatus('streaming', 'normal'));
    src.addEventListener('window', (e) => {
      try {
        const msg = JSON.parse(e.data);
        vL2.textContent = msg.lambda2 != null ? msg.lambda2.toFixed(3) : '—';
        vMult.textContent = String(msg.mult ?? '—');
        vVotes.textContent = String(msg.votes ?? '—');
        windowCount.textContent = 'windows: ' + String(msg.window ?? '—');
        setStatus(msg.status === 'ANOMALY' ? 'ANOMALY' : 'normal', msg.status === 'ANOMALY' ? 'anomaly' : 'normal');
      } catch {}
    });
    src.addEventListener('anomaly', (e) => {
      try {
        const msg = JSON.parse(e.data);
        const el = appendEvent(msg);
        if (el) el.classList.add('slide-in');
        setStatus('ANOMALY', 'anomaly anomaly-pulse');
        setTimeout(() => setStatus('normal', 'normal'), 1600);
        renderTopologyFromEvent(msg);
        if (msg.mitigation_id) {
          fetch(API_BASE + '/api/v1/mitigate/' + encodeURIComponent(msg.mitigation_id))
            .then(r => r.json()).then(renderMitigation).catch(() => {});
        }
      } catch {}
    });
    src.onerror = () => { src.close(); setTimeout(connectStream, 3000); };
  }

  function initBanner() {
    const banner = document.getElementById('banner');
    const lines = [
      '   ____                      _                       __   _   _',
      '  / ___|_ __ __ _ _____   _(_) __ _ _ __ __ _       / /__| | | |',
      ' | |   | \'__/ _` |_  / | | | |/ _` | \'__/ _` |    / / __| |_| |',
      ' | |___| | | (_| |/ /| |_| | | (_| | | | (_| |   / /\\__ \\  _  |',
      '  \\____|_|  \\__,_/___|\\__,_|_|\\__, |_|  \\__,_|  /_/ |___/_| |_|',
      '                              |___/',
      '    ____                      _',
      '   / ___| __ _ _ __ __ _| |_ ___  ___',
      '  | |    / _` | \'__/ _` | __/ _ \\/ __|',
      '  | |___| (_| | | | (_| | || (_) \\__ \\',
      '   \\____|\\__,_|_|  \\__,_|\\__\\___/|___/',
      '',
      ' [ Crypto-Graph Harness — Spectral Telemetry Diagnostics ]'
    ];
    banner.textContent = lines.join('\n');
    banner.classList.add('typewriter');
  }

  function initRadarPoints() {
    const g = document.getElementById('signal-points');
    if (!g) return;
    function pts() {
      const l2 = Math.random();
      const mult = Math.random();
      const votes = Math.random();
      const cx = 100, cy = 100, r = 80;
      const a1 = -Math.PI / 2;
      const a2 = a1 + (2 / 3) * Math.PI;
      const a3 = a2 + (2 / 3) * Math.PI;
      const x1 = cx + r * l2 * Math.cos(a1), y1 = cy + r * l2 * Math.sin(a1);
      const x2 = cx + r * mult * Math.cos(a2), y2 = cy + r * mult * Math.sin(a2);
      const x3 = cx + r * votes * Math.cos(a3), y3 = cy + r * votes * Math.sin(a3);
      g.innerHTML = `
        <circle cx="${x1.toFixed(2)}" cy="${y1.toFixed(2)}" r="4" fill="#00ffff" opacity=".9" />
        <circle cx="${x2.toFixed(2)}" cy="${y2.toFixed(2)}" r="4" fill="#ff00ff" opacity=".9" />
        <circle cx="${x3.toFixed(2)}" cy="${y3.toFixed(2)}" r="4" fill="#00ff00" opacity=".9" />
      `;
    }
    pts();
    setInterval(pts, 5000);
  }

  initBanner();
  initRadarPoints();
  loadDetect();
  connectStream();
})();
