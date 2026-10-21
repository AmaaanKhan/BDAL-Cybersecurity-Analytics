/* ═══════════════════════════════════════════��═══════════════════════
   BDAL Threat Ops — console logic
   Every number rendered here comes from either
   ../data/Global_Cybersecurity_Threats_2015-2024.csv  (source dataset)
   /api/status                                       (pipeline state)
   /api/analytics/<name>                             (PySpark output)
   Nothing is faked, estimated or pre-filled.
   ═══════════════════════════════════════════════════════════════════ */
(() => {
  'use strict';

  /* ── constants ─────────────────────────────────────────────────── */
  const DATA_URL = '../data/Global_Cybersecurity_Threats_2015-2024.csv';
  const STATUS_URL = '/api/status';
  const ANALYTICS_URL = '/api/analytics/';
  const PAGE_SIZE = 25;

  const TYPE_COLORS = {
    'DDoS': '#FF650A',
    'Malware': '#FF9B36',
    'Man-in-the-Middle': '#00CFFF',
    'Phishing': '#168BFF',
    'Ransomware': '#C24E12',
    'SQL Injection': '#8B5CF6',
  };
  const FALLBACK_COLORS = ['#FF650A', '#FF9B36', '#00CFFF', '#168BFF', '#8B5CF6', '#C24E12'];

  const AGGREGATIONS = [
    { key: 'attacks_by_year', title: 'Incidents by Year', kind: 'line' },
    { key: 'attacks_by_country', title: 'Incidents by Country', kind: 'bar+table' },
    { key: 'attacks_by_type', title: 'Incidents by Attack Type', kind: 'bar' },
    { key: 'attacks_by_industry', title: 'Target Industries', kind: 'bar' },
    { key: 'attacks_by_source', title: 'Attack Sources', kind: 'bar' },
    { key: 'attacks_by_vulnerability', title: 'Security Vulnerabilities', kind: 'table' },
    { key: 'attacks_by_defense', title: 'Defense Mechanisms', kind: 'table' },
  ];

  /* ── state (in memory only, never persisted) ───────────────────── */
  const state = {
    rows: [],
    filtered: [],
    filters: { year: new Set(), country: new Set(), attackType: new Set() },
    facets: { year: [], country: [], attackType: [] },
    status: null,
    statusError: null,
    analytics: {},
    screen: 'dashboard',
    recordQuery: '',
    recordPage: 0,
    charts: {},
    aggCharts: {},
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const nf = new Intl.NumberFormat('en-US');
  const fmtInt = (n) => nf.format(Math.round(n));
  const fmtFixed = (n, d = 2) => Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
  const fmtBytes = (b) => {
    if (!b) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0, v = b;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
  };
  const typeColor = (name, index = 0) => TYPE_COLORS[name] || FALLBACK_COLORS[index % FALLBACK_COLORS.length];

  /* ── toasts ────────────────────────────────────────────────────── */
  function toast(text, kind = 'info') {
    const host = $('#toasts');
    const el = document.createElement('div');
    el.className = 'toast';
    el.dataset.kind = kind;
    el.innerHTML = `<span class="toast__icon">${kind === 'error' ? 'ERR' : 'OK'}</span><span class="toast__text"></span>`;
    $('.toast__text', el).textContent = text;
    host.appendChild(el);
    setTimeout(() => {
      el.classList.add('is-leaving');
      setTimeout(() => el.remove(), 240);
    }, 4200);
  }

  /* ── data loading ──────────────────────────────────────────────── */
  async function loadStatus() {
    try {
      const res = await fetch(STATUS_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      state.status = await res.json();
      state.statusError = null;
    } catch (err) {
      state.status = null;
      state.statusError = err.message || 'Request failed';
    }
    renderStatusPill();
    renderPipeline();
    renderDiagnostics();
  }

  async function loadDataset() {
    const res = await fetch(DATA_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    state.rows = parseDataset(text);
    buildFacets();
    state.filters.year = new Set(state.facets.year);
    state.filters.country = new Set(state.facets.country);
    state.filters.attackType = new Set(state.facets.attackType);
    renderFilters();
  }

  function parseDataset(text) {
    const lines = text.split(/\r?\n/);
    const rows = [];
    for (let i = 1; i < lines.length; i += 1) {
      const line = lines[i].trim();
      if (!line) continue;
      const f = line.split(',');
      if (f.length !== 10) continue;
      const year = parseInt(f[1], 10);
      if (!Number.isFinite(year)) continue; // mirrors dropna(subset=["Year"])
      const loss = parseFloat(f[4]);
      const affected = parseInt(f[5], 10);
      const resolution = parseFloat(f[9]);
      rows.push({
        country: f[0].trim(),
        year,
        attackType: f[2].trim(),
        industry: f[3].trim(),
        loss: Number.isFinite(loss) ? loss : 0,
        affected: Number.isFinite(affected) ? affected : 0,
        source: f[6].trim(),
        vulnerability: f[7].trim(),
        defense: f[8].trim(),
        resolution: Number.isFinite(resolution) ? resolution : 0,
      });
    }
    return rows;
  }

  function buildFacets() {
    const years = new Set();
    const countries = new Set();
    const types = new Set();
    state.rows.forEach((r) => {
      years.add(r.year);
      countries.add(r.country);
      types.add(r.attackType);
    });
    state.facets.year = Array.from(years).sort((a, b) => a - b);
    state.facets.country = Array.from(countries).sort();
    state.facets.attackType = Array.from(types).sort();
  }

  /* ── filtering (AND across groups, OR inside a group) ──────────── */
  function applyFilters() {
    const { year, country, attackType } = state.filters;
    // an empty group applies no constraint at all
    const allows = (set, value) => set.size === 0 || set.has(value);
    state.filtered = state.rows.filter(
      (r) => allows(year, r.year) && allows(country, r.country) && allows(attackType, r.attackType),
    );
  }

  /* ── header status pill ────────────────────────────────────────── */
  function renderStatusPill() {
    const pill = $('#statusPill');
    const text = $('.status-pill__text', pill);
    if (!state.status) {
      pill.dataset.state = 'offline';
      text.textContent = 'API unavailable';
      return;
    }
    const s = state.status;
    const stages = [
      s.dataset_rows > 0,
      s.incoming_completed > 0,
      s.flume_files > 0 && s.flume_bytes > 0,
      s.records_ingested > 0,
      Object.keys(s.analytics || {}).length > 0,
    ];
    const done = stages.filter(Boolean).length;
    if (done === stages.length) {
      pill.dataset.state = 'online';
      text.textContent = 'Pipeline online';
    } else {
      pill.dataset.state = 'partial';
      text.textContent = `Pipeline partial · ${done}/${stages.length} stages`;
    }
  }

  /* ── dashboard: pipeline status cards ──────────────────────────── */
  function renderPipeline() {
    const host = $('#pipelineStatus');
    const s = state.status;
    const cards = [
      { label: 'Dataset rows', value: s ? fmtInt(s.dataset_rows) : null, note: s ? 'data/*.csv' : 'status API unreachable' },
      { label: 'Records ingested', value: s ? fmtInt(s.records_ingested) : null, note: s ? 'PySpark rows read' : 'status API unreachable' },
      { label: 'Flume roll files', value: s ? fmtInt(s.flume_files) : null, note: s ? fmtBytes(s.flume_bytes) : 'status API unreachable' },
      { label: 'Batches processed', value: s ? fmtInt(s.incoming_completed) : null, note: s ? 'incoming/*.COMPLETED' : 'status API unreachable' },
      { label: 'Pending batches', value: s ? fmtInt(s.incoming_pending) : null, note: s ? 'incoming/*.csv' : 'status API unreachable' },
      { label: 'Aggregations', value: s ? fmtInt(Object.keys(s.analytics || {}).length) : null, note: s ? 'output/analytics/' : 'status API unreachable' },
    ];
    host.innerHTML = '';
    cards.forEach((c) => {
      const el = document.createElement('article');
      el.className = 'stat';
      const unavailable = c.value === null;
      el.innerHTML = `
        <p class="stat__label">${c.label}</p>
        <p class="stat__value">${unavailable ? 'Unavailable' : c.value}</p>
        <p class="stat__note">${c.note}</p>`;
      if (unavailable) $('.stat__value', el).style.color = 'var(--text-muted)';
      host.appendChild(el);
    });
    $('#pipelineHint').textContent = state.status
      ? 'GET /api/status · live'
      : 'GET /api/status · unreachable';
  }

  /* ── dashboard: KPI tiles ──────────────────────────────────────── */
  function renderKpis() {
    const rows = state.filtered;
    const host = $('#kpiRow');
    const total = rows.length;
    let loss = 0, affected = 0, resSum = 0;
    const countries = new Set();
    rows.forEach((r) => {
      loss += r.loss;
      affected += r.affected;
      resSum += r.resolution;
      countries.add(r.country);
    });
    const avgRes = total ? resSum / total : 0;
    const tiles = [
      { label: 'Total incidents', value: fmtInt(total), note: 'rows in filtered dataset' },
      { label: 'Financial loss', value: `$${fmtFixed(loss / 1000)}`, unit: 'B', note: 'million $ summed → billions' },
      { label: 'Affected users', value: fmtInt(affected), note: 'sum across filtered rows' },
      { label: 'Avg resolution', value: fmtFixed(avgRes), unit: 'hrs', note: 'mean incident resolution time' },
      { label: 'Countries', value: fmtInt(countries.size), note: 'distinct countries in selection' },
    ];
    host.innerHTML = '';
    tiles.forEach((t) => {
      const el = document.createElement('article');
      el.className = 'kpi';
      el.innerHTML = `
        <p class="kpi__label">${t.label}</p>
        <p class="kpi__value">${t.value}${t.unit ? `<span class="unit">${t.unit}</span>` : ''}</p>
        <p class="kpi__note">${t.note}</p>`;
      host.appendChild(el);
    });
    $('#kpiHint').textContent = `${fmtInt(total)} of ${fmtInt(state.rows.length)} rows`;
  }

  /* ── dashboard: filters ────────────────────────────────────────── */
  const FILTER_GROUPS = [
    { key: 'year', label: 'Year' },
    { key: 'country', label: 'Country' },
    { key: 'attackType', label: 'Attack type' },
  ];
  const openGroups = new Set(FILTER_GROUPS.map((g) => g.key)); // expanded by default, survives a re-render

  function renderFilters() {
    const host = $('#filterGroups');
    host.innerHTML = '';
    FILTER_GROUPS.forEach((group) => {
      const values = state.facets[group.key];
      const counts = countBy(group.key);
      const wrap = document.createElement('details');
      wrap.className = 'fgroup';
      wrap.dataset.fgroup = group.key;
      wrap.open = openGroups.has(group.key);
      wrap.innerHTML = `
        <summary class="fgroup__head">
          <span class="fgroup__name">${group.label}</span>
          <span class="fgroup__count" data-count="${group.key}"></span>
        </summary>
        <div class="fgroup__body">
          <div class="fgroup__tools">
            <button type="button" data-all="${group.key}">All</button>
            <button type="button" data-none="${group.key}">None</button>
          </div>
          <div class="fgroup__list" role="group" aria-label="${group.label}"></div>
        </div>`;
      const list = $('.fgroup__list', wrap);
      values.forEach((v) => {
        const label = document.createElement('label');
        label.className = 'fcheck';
        const checked = state.filters[group.key].has(v);
        label.innerHTML = `
          <input type="checkbox" data-group="${group.key}" value="${v}" ${checked ? 'checked' : ''}>
          <span class="fcheck__box" aria-hidden="true"></span>
          <span class="fcheck__text"></span>
          <span class="fcheck__count">${fmtInt(counts.get(v) || 0)}</span>`;
        $('.fcheck__text', label).textContent = String(v);
        label.classList.toggle('is-off', !checked);
        list.appendChild(label);
      });
      wrap.addEventListener('toggle', () => {
        if (wrap.open) openGroups.add(group.key);
        else openGroups.delete(group.key);
      });
      host.appendChild(wrap);
    });
    updateFilterCounts();
  }

  function updateFilterCounts() {
    FILTER_GROUPS.forEach((group) => {
      const el = $(`[data-count="${group.key}"]`);
      if (!el) return;
      const selected = state.filters[group.key].size;
      el.textContent = `${selected}/${state.facets[group.key].length}`;
      el.classList.toggle('is-off', selected === 0);
    });
  }

  function countBy(key) {
    const map = new Map();
    state.rows.forEach((r) => map.set(r[key], (map.get(r[key]) || 0) + 1));
    return map;
  }

  /* ── dashboard: signal trace ───────────────────────────────────── */
  function renderSignal() {
    const series = groupCounts(state.filtered, 'year');
    const line = $('#signalLine');
    const dots = $('#signalDots');
    const grid = $('#signalGrid');
    const axis = $('#signalAxis');
    const meta = $('#signalMeta');
    const note = $('#signalNote');

    grid.innerHTML = '';
    for (let i = 1; i < 4; i += 1) {
      const l = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      l.setAttribute('x1', '0'); l.setAttribute('x2', '440');
      l.setAttribute('y1', String(i * 37.5)); l.setAttribute('y2', String(i * 37.5));
      grid.appendChild(l);
    }

    if (!series.length) {
      line.setAttribute('points', '');
      dots.innerHTML = '';
      axis.innerHTML = '';
      meta.textContent = 'no data in filter';
      note.textContent = 'No records match the selected filters.';
      return;
    }

    const w = 440, h = 150, pad = 14;
    const max = Math.max(...series.map((s) => s.count), 1);
    const step = series.length > 1 ? (w - pad * 2) / (series.length - 1) : 0;
    const pts = series.map((s, i) => {
      const x = series.length > 1 ? pad + i * step : w / 2;
      const y = h - pad - (s.count / max) * (h - pad * 2);
      return { x, y, label: s.label, count: s.count };
    });

    line.setAttribute('points', pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' '));
    dots.innerHTML = pts.map((p) => `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3.2"></circle>`).join('');
    axis.innerHTML = '';
    const stepLabel = series.length > 6 ? Math.ceil(series.length / 5) : 1;
    series.forEach((s, i) => {
      if (i % stepLabel !== 0 && i !== series.length - 1) return;
      const span = document.createElement('span');
      span.textContent = s.label;
      axis.appendChild(span);
    });

    const peak = series.reduce((a, b) => (b.count > a.count ? b : a));
    meta.textContent = `${series.length} year${series.length > 1 ? 's' : ''} in filter`;
    note.textContent = `Peak ${peak.label} · ${fmtInt(peak.count)} incidents · ${fmtInt(state.filtered.length)} rows in view`;
  }

  /* ── dashboard: charts ─────────────────────────────────────────── */
  function groupCounts(rows, key) {
    const map = new Map();
    rows.forEach((r) => map.set(r[key], (map.get(r[key]) || 0) + 1));
    return Array.from(map.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => (key === 'year' ? a.label - b.label : b.count - a.count));
  }

  function chartBase(extra = {}) {
    return Object.assign({
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 650, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(16,18,20,0.97)',
          borderColor: 'rgba(255,255,255,0.12)',
          borderWidth: 1,
          padding: 10,
          displayColors: false,
          titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
          bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.05)', drawTicks: false },
          border: { color: 'rgba(255,255,255,0.1)' },
          ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, maxRotation: 0, autoSkip: false },
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.05)', drawTicks: false },
          border: { display: false },
          ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, precision: 0 },
        },
      },
    }, extra);
  }

  function renderCharts() {
    const rows = state.filtered;
    const empty = rows.length === 0;
    $$('#chartArea .chart-card').forEach((c) => { c.hidden = empty; });
    $('#chartEmpty').hidden = !empty;

    if (empty) {
      destroyCharts(['chartYear', 'chartType', 'chartIndustry', 'chartCountry', 'chartScatter']);
      $('#metaYear').textContent = '—';
      $('#metaType').textContent = '—';
      $('#metaIndustry').textContent = '—';
      $('#metaCountry').textContent = '—';
      $('#metaScatter').textContent = '—';
      return;
    }
    if (!window.Chart) {
      $$('.chart-box').forEach((b) => {
        b.innerHTML = '<p class="agg-state__text">Chart library unavailable (offline). Data is still shown in the tables and tiles.</p>';
      });
      return;
    }

    // 1 — incidents by year (line)
    const byYear = groupCounts(rows, 'year');
    upsertLine('chartYear', byYear.map((d) => d.label), byYear.map((d) => d.count));
    $('#metaYear').textContent = `${byYear.length} years`;

    // 2 — incidents by attack type (bar, per-type colours)
    const byType = groupCounts(rows, 'attackType');
    upsertBar('chartType', byType.map((d) => d.label), byType.map((d) => d.count),
      byType.map((d, i) => typeColor(d.label, i)), 'Incidents');
    $('#metaType').textContent = `${byType.length} types`;

    // 3 — target industries (bar, descending)
    const byIndustry = groupCounts(rows, 'industry');
    upsertBar('chartIndustry', byIndustry.map((d) => d.label), byIndustry.map((d) => d.count),
      byIndustry.map((d, i) => (i % 2 ? 'rgba(255,155,54,0.72)' : 'rgba(255,101,10,0.85)')), 'Incidents');
    $('#metaIndustry').textContent = `${byIndustry.length} industries`;

    // 4 — incidents by country (bar + loss/users tooltip)
    const countryMap = new Map();
    rows.forEach((r) => {
      const e = countryMap.get(r.country) || { count: 0, loss: 0, affected: 0 };
      e.count += 1; e.loss += r.loss; e.affected += r.affected;
      countryMap.set(r.country, e);
    });
    const byCountry = Array.from(countryMap.entries())
      .map(([label, v]) => ({ label, ...v }))
      .sort((a, b) => b.count - a.count);
    upsertBar('chartCountry', byCountry.map((d) => d.label), byCountry.map((d) => d.count),
      byCountry.map(() => 'rgba(0,207,255,0.78)'), 'Incidents',
      (items) => {
        const d = byCountry[items[0].dataIndex];
        return [`${fmtInt(d.count)} incidents`, `Loss $${fmtFixed(d.loss / 1000)}B`, `${fmtInt(d.affected)} affected users`];
      });
    $('#metaCountry').textContent = `${byCountry.length} countries`;

    // 5 — loss vs affected users (scatter, one dataset per attack type)
    const types = Array.from(new Set(rows.map((r) => r.attackType))).sort();
    const datasets = types.map((t, i) => ({
      label: t,
      data: rows.filter((r) => r.attackType === t).map((r) => ({
        x: r.loss, y: r.affected, country: r.country, year: r.year, industry: r.industry,
      })),
      backgroundColor: `${typeColor(t, i)}66`,
      borderColor: typeColor(t, i),
      borderWidth: 0.6,
      pointRadius: 3.1,
      pointHoverRadius: 6,
    }));
    upsertScatter('chartScatter', datasets);
    $('#metaScatter').textContent = `${fmtInt(rows.length)} points`;
  }

  function upsertLine(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const cfg = {
      type: 'line',
      data: {
        labels,
        datasets: [{
          data,
          borderColor: '#FF650A',
          borderWidth: 2,
          tension: 0.32,
          fill: true,
          backgroundColor: (c) => {
            const { ctx: g, chartArea } = c.chart;
            if (!chartArea) return 'rgba(255,101,10,0.12)';
            const grad = g.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
            grad.addColorStop(0, 'rgba(255,101,10,0.28)');
            grad.addColorStop(1, 'rgba(255,101,10,0)');
            return grad;
          },
          pointBackgroundColor: '#050606',
          pointBorderColor: '#00CFFF',
          pointBorderWidth: 1.6,
          pointRadius: 3.4,
          pointHoverRadius: 6,
        }],
      },
      options: chartBase({
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(16,18,20,0.97)',
            borderColor: 'rgba(255,255,255,0.12)',
            borderWidth: 1, padding: 10, displayColors: false,
            titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            callbacks: { label: (i) => `${fmtInt(i.parsed.y)} incidents` },
          },
        },
      }),
    };
    swapChart(id, cfg);
  }

  function upsertBar(id, labels, data, colors, labelName, labelFn) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const cfg = {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: colors,
          hoverBackgroundColor: colors.map((c) => c.replace(/0\.\d+\)$/, '1)')),
          borderRadius: 3,
          borderSkipped: false,
          maxBarThickness: 34,
        }],
      },
      options: chartBase({
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(16,18,20,0.97)',
            borderColor: 'rgba(255,255,255,0.12)',
            borderWidth: 1, padding: 10, displayColors: false,
            titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            callbacks: labelFn
              ? { label: labelFn }
              : { label: (i) => `${fmtInt(i.parsed.y)} ${labelName}` },
          },
        },
        scales: {
          x: {
            grid: { display: false },
            border: { color: 'rgba(255,255,255,0.1)' },
            ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, maxRotation: 45, minRotation: 0, autoSkip: true, maxTicksLimit: 8 },
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255,255,255,0.05)', drawTicks: false },
            border: { display: false },
            ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, precision: 0 },
          },
        },
      }),
    };
    swapChart(id, cfg);
  }

  function upsertScatter(id, datasets) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const cfg = {
      type: 'scatter',
      data: { datasets },
      options: chartBase({
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: { color: '#A0A5AA', boxWidth: 8, boxHeight: 8, usePointStyle: true, pointStyle: 'rectRounded', font: { family: "'JetBrains Mono', monospace", size: 10 } },
          },
          tooltip: {
            backgroundColor: 'rgba(16,18,20,0.97)',
            borderColor: 'rgba(255,255,255,0.12)',
            borderWidth: 1, padding: 10,
            titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            callbacks: {
              title: (items) => items[0].raw.country,
              label: (i) => {
                const r = i.raw;
                return [
                  `${r.year} · ${r.industry}`,
                  `Loss $${fmtFixed(r.x)}M`,
                  `${fmtInt(r.y)} affected users`,
                ];
              },
            },
          },
        },
        scales: {
          x: {
            type: 'linear',
            title: { display: true, text: 'Financial loss (million $)', color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 } },
            grid: { color: 'rgba(255,255,255,0.05)', drawTicks: false },
            border: { color: 'rgba(255,255,255,0.1)' },
            ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 } },
          },
          y: {
            type: 'linear',
            title: { display: true, text: 'Affected users', color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 } },
            grid: { color: 'rgba(255,255,255,0.05)', drawTicks: false },
            border: { display: false },
            ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, callback: (v) => fmtInt(v) },
          },
        },
      }),
    };
    swapChart(id, cfg);
  }

  function swapChart(id, cfg) {
    const existing = state.charts[id];
    if (existing) {
      existing.destroy();
      delete state.charts[id];
    }
    const ctx = document.getElementById(id);
    if (!ctx) return;
    state.charts[id] = new Chart(ctx.getContext('2d'), cfg);
  }

  function destroyCharts(ids) {
    ids.forEach((id) => {
      if (state.charts[id]) {
        state.charts[id].destroy();
        delete state.charts[id];
      }
    });
  }

  /* ── threat analytics (real PySpark output) ────────────────────── */
  async function loadAnalytics(key) {
    try {
      const res = await fetch(`${ANALYTICS_URL}${key}`, { cache: 'no-store' });
      if (res.status === 404) {
        state.analytics[key] = null;
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const payload = await res.json();
      const cols = payload.columns || [];
      // safety net: drop a header row if the server ever includes it
      const rows = (payload.rows || []).filter(
        (r) => !(Array.isArray(r) && r.length === cols.length && r.every((v, i) => v === cols[i])),
      );
      state.analytics[key] = { columns: cols, rows };
    } catch (err) {
      state.analytics[key] = { error: err.message || 'Request failed' };
    }
  }

  async function loadAllAnalytics() {
    await Promise.all(AGGREGATIONS.map((agg) => loadAnalytics(agg.key)));
    if (state.screen === 'analytics') renderAnalytics();
  }

  function renderAnalytics() {
    const host = $('#analyticsGrid');
    Object.values(state.aggCharts).forEach((c) => c.destroy());
    state.aggCharts = {};
    host.innerHTML = '';
    AGGREGATIONS.forEach((agg) => {
      const data = state.analytics[agg.key];
      const card = document.createElement('article');
      card.className = 'card agg-card';

      const head = document.createElement('div');
      head.className = 'agg-card__head';
      head.innerHTML = `
        <div>
          <p class="agg-card__title">${agg.title}</p>
          <p class="agg-card__source">output/analytics/${agg.key}</p>
        </div>`;
      const badge = document.createElement('span');
      badge.className = 'badge badge--muted';
      badge.textContent = data === undefined
        ? 'loading'
        : (data && data.rows ? `${data.rows.length} rows` : 'not generated');
      head.appendChild(badge);
      card.appendChild(head);

      if (data === undefined) {
        card.appendChild(aggEmptyState('Loading PySpark output…', `GET /api/analytics/${agg.key}`));
        host.appendChild(card);
        return;
      }
      if (!data) {
        card.appendChild(aggEmptyState('PySpark output not generated yet', 'Run <code>python src\\analytics.py</code> to produce this aggregation.'));
        host.appendChild(card);
        return;
      }
      if (data.error) {
        card.appendChild(aggEmptyState('Could not read this aggregation', `GET /api/analytics/${agg.key} → ${data.error}`));
        host.appendChild(card);
        return;
      }
      if (!data.rows.length) {
        card.appendChild(aggEmptyState('Aggregation is empty', 'The file exists but contains no data rows.'));
        host.appendChild(card);
        return;
      }

      if (agg.kind === 'line' || agg.kind === 'bar' || agg.kind === 'bar+table') {
        const box = document.createElement('div');
        box.className = 'agg-card__chart';
        const canvas = document.createElement('canvas');
        box.appendChild(canvas);
        card.appendChild(box);
        drawAggChart(agg.key, canvas, data);
      }
      if (agg.kind === 'table' || agg.kind === 'bar+table') {
        card.appendChild(buildAggTable(data));
      }
      host.appendChild(card);
    });
  }

  function aggEmptyState(title, text) {
    const el = document.createElement('div');
    el.className = 'agg-state';
    el.innerHTML = `<p class="agg-state__title"></p><p class="agg-state__text"></p>`;
    $('.agg-state__title', el).textContent = title;
    $('.agg-state__text', el).innerHTML = text;
    return el;
  }

  function drawAggChart(key, canvas, data) {
    if (!window.Chart) return;
    const cols = data.columns;
    const labelCol = cols[0];
    const countIdx = cols.indexOf('Incident Count');
    const labels = data.rows.map((r) => String(r[0]));
    const counts = data.rows.map((r) => (countIdx >= 0 ? r[countIdx] : r[1]));
    const isLine = key === 'attacks_by_year';
    const cfg = {
      type: isLine ? 'line' : 'bar',
      data: {
        labels,
        datasets: [{
          data: counts,
          borderColor: isLine ? '#FF650A' : 'rgba(0,207,255,0.8)',
          backgroundColor: isLine ? 'rgba(255,101,10,0.16)' : 'rgba(0,207,255,0.55)',
          borderWidth: isLine ? 2 : 0,
          tension: 0.3,
          borderRadius: 3,
          maxBarThickness: 26,
          pointRadius: isLine ? 3 : 0,
          pointBackgroundColor: '#050606',
          pointBorderColor: '#00CFFF',
        }],
      },
      options: chartBase({
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(16,18,20,0.97)', borderColor: 'rgba(255,255,255,0.12)',
            borderWidth: 1, padding: 10, displayColors: false,
            titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            callbacks: { label: (i) => `${fmtInt(i.parsed.y)} incidents` },
          },
        },
        scales: {
          x: {
            grid: { display: false },
            border: { color: 'rgba(255,255,255,0.1)' },
            ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, autoSkip: false, maxRotation: 38 },
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255,255,255,0.05)', drawTicks: false },
            border: { display: false },
            ticks: { color: '#70767D', font: { family: "'JetBrains Mono', monospace", size: 10 }, precision: 0 },
          },
        },
      }),
    };
    if (state.aggCharts[key]) {
      state.aggCharts[key].destroy();
      delete state.aggCharts[key];
    }
    state.aggCharts[key] = new Chart(canvas.getContext('2d'), cfg);
  }

  function buildAggTable(data) {
    const wrap = document.createElement('div');
    wrap.className = 'agg-card__table';
    const table = document.createElement('table');
    table.className = 'table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    data.columns.forEach((c, i) => {
      const th = document.createElement('th');
      th.scope = 'col';
      if (i > 0) th.className = 'num';
      th.textContent = c;
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    data.rows.forEach((row) => {
      const tr = document.createElement('tr');
      row.forEach((cell, i) => {
        const td = document.createElement('td');
        if (i > 0) td.className = 'num';
        td.textContent = formatAggCell(data.columns[i], cell);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function formatAggCell(column, cell) {
    if (typeof cell !== 'number') return String(cell);
    if (/Loss/i.test(column)) return fmtFixed(cell);
    if (/Users/i.test(column)) return fmtInt(cell);
    if (/Resolution/i.test(column)) return fmtFixed(cell);
    return fmtInt(cell);
  }

  /* ── records ───────────────────────────────────────────────────── */
  function renderRecords() {
    const q = state.recordQuery.trim().toLowerCase();
    const matches = q
      ? state.rows.filter((r) => [r.country, r.attackType, r.industry, r.source, r.vulnerability, r.defense, String(r.year)]
        .some((v) => v.toLowerCase().includes(q)))
      : state.rows;

    const pages = Math.max(1, Math.ceil(matches.length / PAGE_SIZE));
    if (state.recordPage >= pages) state.recordPage = pages - 1;
    const start = state.recordPage * PAGE_SIZE;
    const slice = matches.slice(start, start + PAGE_SIZE); // capped render window

    const body = $('#recordsBody');
    body.innerHTML = '';
    slice.forEach((r, i) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${start + i + 1}</td>
        <td class="strong"></td>
        <td class="num">${r.year}</td>
        <td></td>
        <td></td>
        <td class="num">${fmtFixed(r.loss)}</td>
        <td class="num">${fmtInt(r.affected)}</td>
        <td class="num">${fmtFixed(r.resolution, 1)}</td>`;
      const cells = tr.querySelectorAll('td');
      cells[1].textContent = r.country;
      cells[3].textContent = r.attackType;
      cells[4].textContent = r.industry;
      body.appendChild(tr);
    });

    $('#recordsEmpty').hidden = matches.length !== 0;
    $('#recordCount').textContent = q
      ? `${fmtInt(matches.length)} of ${fmtInt(state.rows.length)} rows match`
      : `${fmtInt(state.rows.length)} source rows`;
    $('#pageInfo').textContent = `Page ${state.recordPage + 1} of ${pages} · showing ${matches.length ? start + 1 : 0}–${start + slice.length}`;
    $('#prevPage').disabled = state.recordPage === 0;
    $('#nextPage').disabled = state.recordPage >= pages - 1;
  }

  /* ── diagnostics ───────────────────────────────────────────────── */
  function stageStates() {
    const s = state.status;
    if (!s) {
      return [
        { name: 'Dataset', state: 'down', detail: 'status API unreachable' },
        { name: 'stream_data.py', state: 'down', detail: 'status API unreachable' },
        { name: 'Flume', state: 'down', detail: 'status API unreachable' },
        { name: 'PySpark', state: 'down', detail: 'status API unreachable' },
        { name: 'Analytics', state: 'down', detail: 'status API unreachable' },
        { name: 'Frontend', state: 'down', detail: 'cannot reach /api/status' },
      ];
    }
    const aggCount = Object.keys(s.analytics || {}).length;
    const aggRows = Object.values(s.analytics || {}).reduce((a, b) => a + b, 0);
    const mk = (ok, detail) => ({ state: ok ? 'ok' : 'pending', detail });
    return [
      { name: 'Dataset', ...mk(s.dataset_rows > 0, `${fmtInt(s.dataset_rows)} rows · data/*.csv`) },
      { name: 'stream_data.py', ...mk(s.incoming_completed > 0, `${fmtInt(s.incoming_completed)} batches · incoming/`) },
      { name: 'Flume', ...mk(s.flume_files > 0 && s.flume_bytes > 0, `${fmtInt(s.flume_files)} roll files · ${fmtBytes(s.flume_bytes)}`) },
      { name: 'PySpark', ...mk(s.records_ingested > 0, `${fmtInt(s.records_ingested)} records read`) },
      { name: 'Analytics', ...mk(aggCount > 0, `${aggCount} aggregations · ${fmtInt(aggRows)} rows`) },
      { name: 'Frontend', ...mk(true, 'status payload received · console live') },
    ];
  }

  const STATE_LABEL = { ok: 'OK', pending: 'Not run', down: 'Unavailable' };

  function renderDiagnostics() {
    const chain = $('#stageChain');
    chain.innerHTML = '';
    stageStates().forEach((st) => {
      const li = document.createElement('li');
      li.className = 'stage';
      li.dataset.state = st.state;
      li.innerHTML = `
        <span class="stage__name"></span>
        <span class="stage__state"><span class="stage__dot" aria-hidden="true"></span><span class="stage__label"></span></span>
        <span class="stage__detail"></span>`;
      $('.stage__name', li).textContent = st.name;
      $('.stage__label', li).textContent = STATE_LABEL[st.state];
      $('.stage__detail', li).textContent = st.detail;
      chain.appendChild(li);
    });

    const body = $('#terminalBody');
    const cmd = `curl -s ${window.location.origin}${STATUS_URL}`;
    if (!state.status) {
      body.innerHTML = '';
      body.appendChild(terminalLine('$ ', cmd, 'terminal__cmd'));
      body.appendChild(document.createTextNode('\n'));
      body.appendChild(terminalLine(`# request failed: ${state.statusError || 'unreachable'}`, '', 'terminal__note'));
      body.appendChild(document.createTextNode('\n\n# No log file is produced by this pipeline. The lines above are the live API response.\n'));
    } else {
      body.innerHTML = '';
      body.appendChild(terminalLine('$ ', cmd, 'terminal__cmd'));
      body.appendChild(document.createTextNode('\n'));
      body.appendChild(terminalHtml(highlightJson(state.status)));
      body.appendChild(document.createTextNode('\n\n# No log file is produced by this pipeline. The lines above are the live API response.\n'));    }

    const facts = $('#diagFacts');
    facts.innerHTML = '';
    const s = state.status;
    const rows = s
      ? [
        ['Dataset rows', fmtInt(s.dataset_rows)],
        ['Records ingested', fmtInt(s.records_ingested)],
        ['Flume roll files', `${fmtInt(s.flume_files)} · ${fmtBytes(s.flume_bytes)}`],
        ['Batches processed', fmtInt(s.incoming_completed)],
        ['Pending batches', fmtInt(s.incoming_pending)],
        ['Aggregations', Object.entries(s.analytics || {}).map(([k, v]) => `${k} (${v})`).join(', ') || 'none'],
        ['Status fetched', new Date().toLocaleTimeString('en-GB')],
      ]
      : [['Status API', `unavailable — ${state.statusError || 'request failed'}`]];
    rows.forEach(([k, v]) => {
      const row = document.createElement('div');
      row.className = 'facts__row';
      row.innerHTML = '<dt class="facts__key"></dt><dd class="facts__val"></dd>';
      $('.facts__key', row).textContent = k;
      $('.facts__val', row).textContent = v;
      facts.appendChild(row);
    });
  }

  function terminalLine(text, cls) {
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text;
    return span;
  }

  function terminalHtml(html) {
    const span = document.createElement('span');
    span.innerHTML = html;
    return span;
  }

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function highlightJson(value) {
    const json = escapeHtml(JSON.stringify(value, null, 2));
    return json.replace(
      /("(?:\\.|[^"\\])*")(\s*:)?|(\btrue\b|\bfalse\b|\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
      (match, str, colon, bool, num) => {
        if (str) {
          const cls = colon ? 'terminal__key' : 'terminal__str';
          return `<span class="${cls}">${match}</span>`;
        }
        if (bool) return `<span class="terminal__key">${match}</span>`;
        return `<span class="terminal__num">${match}</span>`;
      },
    );
  }

  /* ── footer dataset facts ──────────────────────────────────────── */
  function renderFooterFacts() {
    const el = $('#footerFacts');
    if (!el) return;
    if (!state.rows.length) {
      el.textContent = 'dataset not loaded';
      return;
    }
    const years = state.rows.map((r) => r.year);
    const countries = new Set(state.rows.map((r) => r.country)).size;
    const types = new Set(state.rows.map((r) => r.attackType)).size;
    el.textContent = [
      `${fmtInt(state.rows.length)} rows`,
      '10 columns',
      `${Math.min(...years)}–${Math.max(...years)}`,
      `${fmtInt(countries)} countries`,
      `${fmtInt(types)} attack types`,
      'file: Global_Cybersecurity_Threats_2015-2024.csv',
    ].join(' · ');
  }

  /* ── navigation ────────────────────────────────────────────────── */
  const SCREEN_TITLES = {
    dashboard: 'Dashboard',
    analytics: 'Threat Analytics',
    records: 'Records',
    diagnostics: 'Diagnostics',
  };

  function showScreen(name) {
    if (!SCREEN_TITLES[name]) name = 'dashboard';
    state.screen = name;

    $$('.screen').forEach((s) => {
      const active = s.dataset.screen === name;
      s.hidden = !active;
      s.classList.toggle('is-active', active);
    });
    $$('.nav__item').forEach((b) => {
      const active = b.dataset.nav === name;
      b.classList.toggle('is-active', active);
      if (active) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    $('#pageTitle').textContent = SCREEN_TITLES[name];

    if (name === 'analytics' && !Object.keys(state.analytics).length) {
      renderAnalytics();
      loadAllAnalytics();
    }
    if (name === 'records') renderRecords();
    if (name === 'diagnostics') renderDiagnostics();

    if (window.location.hash !== `#/${name}`) {
      window.history.replaceState(null, '', `#/${name}`);
    }
    window.scrollTo({ top: 0, behavior: motionAllowed() ? 'smooth' : 'auto' });
  }

  /* ── particles ─────────────────────────────────────────────────── */
  const particles = { ctx: null, list: [], raf: 0, running: false, dpr: 1 };

  function motionAllowed() {
    return !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function initParticles() {
    const canvas = $('#particles');
    if (!canvas) return;
    particles.ctx = canvas.getContext('2d');
    resizeParticles();
    window.addEventListener('resize', resizeParticles, { passive: true });
  }

  function resizeParticles() {
    const canvas = $('#particles');
    if (!canvas || !particles.ctx) return;
    particles.dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(window.innerWidth * particles.dpr);
    canvas.height = Math.floor(window.innerHeight * particles.dpr);
    particles.ctx.setTransform(particles.dpr, 0, 0, particles.dpr, 0, 0);
    seedParticles();
  }

  function seedParticles() {
    const count = 46;
    particles.list = Array.from({ length: count }, (_, i) => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      r: 0.6 + Math.random() * 1.8,
      vx: (Math.random() - 0.5) * 0.18,
      vy: -0.08 - Math.random() * 0.22,
      a: 0.08 + Math.random() * 0.28,
      tint: i % 3 === 0 ? '0,207,255' : (i % 3 === 1 ? '255,101,10' : '255,255,255'),
      life: 0,
      maxLife: 600 + Math.random() * 900,
    }));
  }

  function startParticles() {
    if (particles.running || !particles.ctx) return;
    if (!motionAllowed()) return;
    particles.running = true;
    particles.raf = requestAnimationFrame(stepParticles);
  }

  function stopParticles() {
    particles.running = false;
    if (particles.raf) cancelAnimationFrame(particles.raf);
    particles.raf = 0;
    if (particles.ctx) particles.ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
  }

  function stepParticles() {
    if (!particles.running) return;
    const ctx = particles.ctx;
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    particles.list.forEach((p) => {
      p.x += p.vx;
      p.y += p.vy;
      p.life += 1;
      if (p.life > p.maxLife) {
        p.x = Math.random() * window.innerWidth;
        p.y = window.innerHeight + 10;
        p.life = 0;
        p.maxLife = 600 + Math.random() * 900;
      }
      if (p.y < -12) p.y = window.innerHeight + 10;
      if (p.x < -12) p.x = window.innerWidth + 10;
      if (p.x > window.innerWidth + 12) p.x = -10;
      const fade = Math.min(p.life / 120, (p.maxLife - p.life) / 160, 1);
      ctx.beginPath();
      ctx.fillStyle = `rgba(${p.tint},${(p.a * fade).toFixed(3)})`;
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    });
    particles.raf = requestAnimationFrame(stepParticles);
  }

  /* ── wiring ────────────────────────────────────────────────────── */
  function wire() {
    $$('.nav__item').forEach((btn) => {
      btn.addEventListener('click', () => showScreen(btn.dataset.nav));
    });

    $$('[data-goto]').forEach((btn) => {
      btn.addEventListener('click', () => showScreen(btn.dataset.goto));
    });
    $$('[data-reset-filters]').forEach((btn) => btn.addEventListener('click', resetFilters));

    // keyboard: arrow navigation inside the nav list
    $('.nav__list').addEventListener('keydown', (e) => {
      const items = $$('.nav__item');
      const i = items.indexOf(document.activeElement);
      if (i < 0) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
      if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    });

    // filters
    $('#filterGroups').addEventListener('change', (e) => {
      const input = e.target.closest('input[type="checkbox"]');
      if (!input) return;
      const group = input.dataset.group;
      const value = group === 'year' ? Number(input.value) : input.value;
      if (input.checked) state.filters[group].add(value);
      else state.filters[group].delete(value);
      input.closest('.fcheck').classList.toggle('is-off', !input.checked);
      updateFilterCounts();
      refreshDashboard();
    });
    $('#filterGroups').addEventListener('click', (e) => {
      const all = e.target.closest('[data-all]');
      const none = e.target.closest('[data-none]');
      if (!all && !none) return;
      const group = (all || none).dataset.all || (all || none).dataset.none;
      const values = state.facets[group].map((v) => (group === 'year' ? Number(v) : v));
      state.filters[group] = new Set(all ? values : []);
      $$(`input[data-group="${group}"]`).forEach((input) => {
        input.checked = Boolean(all);
        input.closest('.fcheck').classList.toggle('is-off', !all);
      });
      updateFilterCounts();
      refreshDashboard();
    });
    $('#resetFilters').addEventListener('click', resetFilters);

    // records
    $('#recordSearch').addEventListener('input', (e) => {
      state.recordQuery = e.target.value;
      state.recordPage = 0;
      renderRecords();
    });
    $('#prevPage').addEventListener('click', () => {
      if (state.recordPage > 0) { state.recordPage -= 1; renderRecords(); }
    });
    $('#nextPage').addEventListener('click', () => {
      state.recordPage += 1; renderRecords();
    });

    // diagnostics
    $('#refreshStatus').addEventListener('click', async () => {
      $('#refreshStatus').disabled = true;
      await loadStatus();
      $('#refreshStatus').disabled = false;
      toast(state.status ? 'Status refreshed' : `Status API unreachable: ${state.statusError}`, state.status ? 'info' : 'error');
    });
    $('#reloadAnalytics').addEventListener('click', async () => {
      state.analytics = {};
      renderAnalytics();
      toast('Reloading PySpark aggregations', 'info');
      await loadAllAnalytics();
    });

    // tabs / visibility
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stopParticles();
      else startParticles();
      const hero = $('#heroTitle');
      if (hero) hero.classList.toggle('is-paused', document.hidden);
    });
    window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', (e) => {
      document.documentElement.dataset.motion = e.matches ? 'reduced' : 'full';
      if (e.matches) stopParticles(); else startParticles();
      toast(e.matches ? 'Reduced motion enabled (system setting)' : 'Full motion restored (system setting)', 'info');
    });
    window.addEventListener('hashchange', () => {
      const name = window.location.hash.replace('#/', '');
      if (SCREEN_TITLES[name] && name !== state.screen) showScreen(name);
    });
  }

  function resetFilters() {
    state.filters.year = new Set(state.facets.year);
    state.filters.country = new Set(state.facets.country);
    state.filters.attackType = new Set(state.facets.attackType);
    $$('#filterGroups input[type="checkbox"]').forEach((i) => {
      i.checked = true;
      i.closest('.fcheck').classList.remove('is-off');
    });
    updateFilterCounts();
    refreshDashboard();
  }

  function refreshDashboard() {
    applyFilters();
    renderKpis();
    renderSignal();
    renderCharts();
  }

  /* ── hero headline: reference per-character intro ───────────────── */
  function initHeroTitle() {
    const title = $('#heroTitle');
    if (!title) return;
    const text = title.textContent.trim();
    if (!text) return;

    const frag = document.createDocumentFragment();
    let i = 0;
    text.split(' ').forEach((word, wi) => {
      if (wi) frag.appendChild(document.createTextNode(' '));
      // one atomic inline per word: the headline then breaks on spaces only,
      // exactly like the unsplit text the ghost layers render
      const wordEl = document.createElement('span');
      wordEl.className = 'hero__word';
      Array.from(word).forEach((ch) => {
        const span = document.createElement('span');
        span.className = 'char';
        span.style.setProperty('--i', String(i));
        span.setAttribute('aria-hidden', 'true'); // the h1 carries the accessible name
        span.textContent = ch;
        wordEl.appendChild(span);
        i += 1;
      });
      frag.appendChild(wordEl);
    });
    title.textContent = '';
    title.appendChild(frag);
  }

  // reference trick: clear the animation for 200ms, then let it restart
  function replayHeroTitle() {
    const title = $('#heroTitle');
    if (!title) return;
    const chars = $$('.char', title);
    if (!chars.length) return;
    chars.forEach((c) => { c.style.animation = 'none'; });
    window.setTimeout(() => { chars.forEach((c) => { c.style.animation = ''; }); }, 200);
  }

  /* ── boot ──────────────────────────────────────────────────────── */
  async function boot() {
    document.documentElement.dataset.motion = motionAllowed() ? 'full' : 'reduced';
    wire();
    initHeroTitle();
    initParticles();
    startParticles();

    if (window.Chart) {
      Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
      Chart.defaults.font.size = 11;
      Chart.defaults.color = '#70767D';
      Chart.defaults.plugins.legend.labels.color = '#A0A5AA';
      Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(16,18,20,0.97)';
      Chart.defaults.plugins.tooltip.borderColor = 'rgba(255,255,255,0.12)';
      Chart.defaults.plugins.tooltip.borderWidth = 1;
      Chart.defaults.maintainAspectRatio = false;
    } else {
      toast('Chart.js could not be loaded — charts are unavailable offline.', 'error');
    }

    const hash = window.location.hash.replace('#/', '');
    showScreen(SCREEN_TITLES[hash] ? hash : 'dashboard');

    try {
      await loadDataset();
    } catch (err) {
      toast(`Dataset could not be loaded: ${err.message}`, 'error');
    }
    renderFooterFacts();
    await loadStatus();
    refreshDashboard();

    if (state.rows.length) {
      toast(`${fmtInt(state.rows.length)} records loaded from the source dataset`, 'info');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
