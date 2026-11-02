/* ==============================================================================
   DroidTTP · Advanced Cyber Threat Intelligence Workbench
   Application Controller & Interactive Tab Engine
   ============================================================================== */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  cases: [],
  samples: [],
  techniques: [],
  sample: null,
  sampleId: null,
  caseId: null,
  editingCase: null,
  currentTab: 'summary',
  currentPage: 'overview',
  session: null,
  analysisTimer: null,
  sampleSearchTimer: null,
  datasetSearchTimer: null,
  datasetOffset: 0,
  datasetLimit: 25,
  datasetRecords: [],
  datasetTotal: 0
};

const overviewDemo = {
  counts: { cases: 2, samples: 3, review: 2, queued: 1 },
  samples: [
    { name: 'Demo sample Alpha', packageName: 'demo.example.alpha', caseTitle: 'Example case Northstar', status: 'Demo example' },
    { name: 'Demo sample Beta', packageName: 'demo.example.beta', caseTitle: 'Example case Northstar', status: 'Demo example' },
    { name: 'Demo sample Gamma', packageName: 'demo.example.gamma', caseTitle: 'Example case Lighthouse', status: 'Demo example' },
    { name: 'Demo sample Delta', packageName: 'demo.example.delta', caseTitle: 'Example case Lighthouse', status: 'Queue example' }
  ],
  reviews: [
    { title: 'Example mapping A', sampleName: 'Demo sample Alpha', status: 'Review example' },
    { title: 'Example mapping B', sampleName: 'Demo sample Gamma', status: 'Review example' }
  ]
};

// HTML Escaper for safe rendering
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '(': '&#40;', ')': '&#41;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

let toastTimer;
function toast(message) {
  const element = $('#toast');
  if (!element) return;
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove('show'), 3200);
}

// Clipboard Helper
async function copyToClipboard(text, successMessage = 'Copied to clipboard') {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    toast(successMessage);
  } catch (err) {
    toast('Could not copy to clipboard');
  }
}

// Indicator Defanger
function defang(value, kind = '') {
  const text = String(value ?? '');
  if (kind === 'url' || text.startsWith('http://') || text.startsWith('https://')) {
    return text.replace(/(https?):\/\/([^\/\s:?#]+)([^\s]*)/ig, (_, scheme, host, rest) => {
      const s = scheme.toLowerCase() === 'https' ? 'hxxps' : 'hxxp';
      return `${s}://${host.replaceAll('.', '[.]')}${rest}`;
    });
  }
  if (kind === 'domain' || kind === 'ip') {
    return text.replaceAll('.', '[.]');
  }
  return text;
}

// Format Utilities
function formatBytes(bytes) {
  const b = Number(bytes);
  if (Number.isNaN(b) || b <= 0) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}

function shortDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.valueOf()) ? '—' : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function preciseDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.valueOf()) ? '—' : d.toLocaleString();
}

function badge(status) {
  const s = String(status || 'unknown').toLowerCase();
  const cls = ['queued', 'running', 'partial', 'completed', 'failed', 'confirmed', 'rejected', 'deferred', 'needs_review', 'suggested'].includes(s) ? s : 'neutral';
  return `<span class="status-chip ${cls}">${esc(s.replaceAll('_', ' '))}</span>`;
}

function handlingBadge(marking) {
  const m = String(marking || 'TLP:CLEAR').toUpperCase();
  let cls = 'tlp-clear';
  if (m.includes('GREEN')) cls = 'tlp-green';
  else if (m.includes('AMBER')) cls = 'tlp-amber';
  else if (m.includes('RED')) cls = 'tlp-red';
  return `<span class="handling-tag ${cls}">${esc(m)}</span>`;
}

function caseTags(value) {
  try { return Array.isArray(value) ? value : JSON.parse(value || '[]'); }
  catch { return []; }
}

function setTableEmpty(emptyId, rowsId, empty) {
  const emptyEl = $(emptyId);
  const rowsEl = $(rowsId);
  if (emptyEl) emptyEl.hidden = !empty;
  if (rowsEl) {
    const tableWrap = rowsEl.closest('.table-container');
    if (tableWrap) tableWrap.hidden = empty;
  }
}

// API Client
async function api(url, options = {}) {
  const headers = {
    ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers || {})
  };
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
  const contentType = response.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await response.json() : await response.text();

  if (response.status === 401) {
    state.session = null;
    showLogin();
    throw new Error('Session expired. Please sign in again.');
  }
  if (!response.ok) {
    throw new Error(typeof body === 'object' ? body.detail || 'Request failed.' : 'Request failed.');
  }
  return body;
}

// Navigation & Screen Control
function showLogin() {
  const loginView = $('#loginView');
  const appView = $('#appView');
  if (loginView) {
    loginView.hidden = false;
    loginView.style.display = 'flex';
  }
  if (appView) {
    appView.hidden = true;
    appView.style.display = 'none';
  }
  document.body.classList.add('unauthenticated');
  document.body.classList.remove('authenticated');
  if (state.analysisTimer) {
    clearInterval(state.analysisTimer);
    state.analysisTimer = null;
  }
  window.scrollTo(0, 0);
  const userField = $('#loginUsername');
  if (userField) {
    setTimeout(() => userField.focus(), 50);
  }
}

function showApp() {
  const loginView = $('#loginView');
  const appView = $('#appView');
  if (loginView) {
    loginView.hidden = true;
    loginView.style.display = 'none';
  }
  if (appView) {
    appView.hidden = false;
    appView.style.display = 'flex';
  }
  document.body.classList.remove('unauthenticated');
  document.body.classList.add('authenticated');
  window.scrollTo(0, 0);
}

function showPage(page, title) {
  state.currentPage = page;
  const pageId = page === 'caseWorkspace' ? 'caseWorkspacePage' : `${page}Page`;
  $$('.content-view').forEach(section => { section.hidden = section.id !== pageId; });
  $$('.nav-link').forEach(button => button.classList.toggle('active', button.dataset.page === page));

  const label = title || ({
    overview: 'Overview',
    cases: 'Cases',
    samples: 'Samples',
    analysis: 'Analysis Workspace',
    dataset: 'Dataset Lab',
    attack: 'ATT&CK Mobile',
    evidence: 'Evidence Register',
    reports: 'Intelligence Reports',
    activity: 'Audit Activity',
    settings: 'Settings'
  }[page] || 'Investigation');

  $('#breadcrumbLabel').textContent = label;
  $('#pageTitle').textContent = label;
  $('#newCaseBtn').hidden = page === 'analysis' || page === 'caseWorkspace';

  // Close mobile sidebar if open
  $('#sidebar').classList.remove('open');
  window.scrollTo(0, 0);
}

// Session Management
async function checkSession() {
  try {
    state.session = await api('/api/session');
    if (!state.session || !state.session.authenticated) {
      showLogin();
      return;
    }
    $('#sessionUsername').textContent = state.session.username;
    $('#sessionRole').textContent = `ROLE: ${String(state.session.role).toUpperCase()}`;
    showApp();
    await loadOverview();
  } catch {
    showLogin();
  }
}

$('#loginForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const errorEl = $('#loginError');
  errorEl.hidden = true;
  errorEl.textContent = '';
  const values = new FormData(form);

  try {
    await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username: values.get('username'),
        password: values.get('password')
      })
    });
    form.reset();
    state.session = await api('/api/session');
    $('#sessionUsername').textContent = state.session.username;
    $('#sessionRole').textContent = `ROLE: ${String(state.session.role).toUpperCase()}`;
    showApp();
    await loadOverview();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.hidden = false;
  }
});

$('#logoutBtn').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch (error) {
    toast(error.message);
  }
  state.session = null;
  showLogin();
});

// Mobile Sidebar Controls
$('#mobileMenuBtn').addEventListener('click', () => {
  $('#sidebar').classList.add('open');
});
$('#sidebarCloseBtn').addEventListener('click', () => {
  $('#sidebar').classList.remove('open');
});

// Navigation Dispatcher
$$('.nav-link').forEach(button => button.addEventListener('click', () => navigate(button.dataset.page)));
$$('[data-go]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.go)));

async function navigate(page) {
  showPage(page);
  try {
    if (page === 'overview') await loadOverview();
    else if (page === 'cases') await loadCases();
    else if (page === 'samples') await loadSamples();
    else if (page === 'dataset') await loadDataset();
    else if (page === 'attack') await loadTechniques();
    else if (page === 'evidence') await loadEvidence();
    else if (page === 'reports') await loadReports();
    else if (page === 'activity') await loadActivity();
    else if (page === 'settings') await loadSettings();
    else if (page === 'analysis' && state.sample) await openSample(state.sample.sample.id, false);
  } catch (error) {
    toast(error.message);
  }
}

// ==============================================================================
// VIEW 1: Overview
// ==============================================================================
async function loadOverview() {
  $('#overviewActivity').innerHTML = '<div class="skeleton-line"></div>';
  $('#overviewReviews').innerHTML = '<div class="skeleton-line"></div>';
  $('#overviewSamplesList').innerHTML = '<div class="skeleton-line"></div>';
  void loadOverviewDataset();

  const data = await api('/api/dashboard');
  state.cases = data.cases;
  const demoMode = data.counts.samples === 0
    && data.counts.review === 0
    && data.counts.queued === 0
    && data.latest_samples.length === 0
    && data.reviews.length === 0;
  const counts = demoMode ? overviewDemo.counts : data.counts;
  $('#overviewDemoNotice').hidden = !demoMode;
  $('#overviewCases').textContent = counts.cases;
  $('#overviewSamples').textContent = counts.samples;
  $('#overviewReview').textContent = counts.review;
  $('#overviewQueued').textContent = counts.queued;
  $('#overviewCasesMeta').textContent = demoMode ? 'Demo preview · illustrative cases only' : 'Authorized cases in workspace';
  $('#overviewSamplesMeta').textContent = demoMode ? 'Demo preview · no APKs uploaded or analyzed' : 'SHA-256 indexed APK packages';
  $('#overviewReviewMeta').textContent = demoMode ? 'Demo preview · placeholder mappings only' : 'Candidate TTP suggestions';
  $('#overviewQueuedMeta').textContent = demoMode ? 'Demo preview · no worker jobs are running' : 'Subprocesses currently parsing';
  $('#overviewSamplesHeading').textContent = demoMode ? 'Latest APK Submissions · Demo Preview' : 'Latest APK Submissions';
  $('#overviewSamplesSubtitle').textContent = demoMode
    ? 'Fictional examples only; no APK files or analysis results are included.'
    : 'Authorized samples intake registry; static analysis only.';
  $('#overviewReviewsSubtitle').textContent = demoMode
    ? 'Placeholder examples only; no real ATT&CK mappings or evidence.'
    : 'Candidate ATT&CK techniques requiring analyst validation.';

  // Latest Samples Feed
  $('#overviewSamplesList').innerHTML = demoMode
    ? overviewDemo.samples.map(sample => `
      <div class="compact-item-row">
        <div class="row-left-content">
          <b>${esc(sample.name)}</b>
          <small>${esc(sample.packageName)} · ${esc(sample.caseTitle)} · Example only — no APK uploaded or analyzed</small>
        </div>
        <span class="tag">${esc(sample.status)}</span>
      </div>
    `).join('')
    : data.latest_samples.length
    ? data.latest_samples.map(sample => `
      <div class="compact-item-row">
        <div class="row-left-content">
          <b>${esc(sample.original_filename)}</b>
          <small>${esc(sample.package_name || 'Package not extracted')} · Case: ${esc(sample.case_title || '—')} · ${shortDate(sample.uploaded_at)}</small>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
          ${badge(sample.analysis_status)}
          <button class="row-action-btn" data-sample-open="${esc(sample.id)}">Inspect</button>
        </div>
      </div>
    `).join('')
    : '<div class="empty-state compact"><h3>No samples analyzed yet</h3><p>Create a case and upload an authorized APK.</p></div>';

  // Review Queue Feed
  $('#overviewReviews').innerHTML = demoMode
    ? overviewDemo.reviews.map(item => `
      <div class="compact-item-row">
        <div class="row-left-content">
          <b>${esc(item.title)}</b>
          <small>${esc(item.sampleName)} · Placeholder only — no technique ID or evidence</small>
        </div>
        <span class="tag">${esc(item.status)}</span>
      </div>
    `).join('')
    : data.reviews.length
    ? data.reviews.map(item => `
      <div class="compact-item-row">
        <div class="row-left-content">
          <b>${esc(item.technique_id)} · ${esc(item.technique_name || 'TTP')}</b>
          <small>${esc(item.original_filename)} · Tactic: ${esc(item.tactic || 'Mobile')}</small>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
          <span class="tag">${esc(item.confidence)} conf</span>
          ${badge(item.status)}
          <button class="row-action-btn" data-sample-open="${esc(item.sample_id)}">Review</button>
        </div>
      </div>
    `).join('')
    : '<div class="empty-state compact"><h3>Review queue is clear</h3><p>All candidate TTP mappings have been reviewed.</p></div>';

  // Recent Activity Feed
  $('#overviewActivity').innerHTML = data.activity.length
    ? data.activity.slice(0, 6).map(act => `
      <div class="compact-item-row">
        <div class="row-left-content">
          <b>${esc(act.action.replaceAll('_', ' ').toUpperCase())}</b>
          <small>${esc(act.detail || act.object_id)} · by ${esc(act.actor)}</small>
        </div>
        <span class="tag">${preciseDate(act.occurred_at)}</span>
      </div>
    `).join('')
    : '<div class="empty-state compact"><p>No activity logged yet.</p></div>';

  $$('[data-sample-open]').forEach(btn => btn.addEventListener('click', () => openSample(btn.dataset.sampleOpen)));
}

async function loadOverviewDataset() {
  const metrics = $('#overviewDatasetMetrics');
  const labelsEl = $('#overviewDatasetLabels');
  const featuresEl = $('#overviewDatasetFeatures');
  const glance = $('#overviewDatasetGlance');
  metrics.innerHTML = '<div class="metric-card"><span class="metric-label">DATASET</span><b class="metric-val">Loading</b><span class="metric-meta">Reading bundled CSV summary</span></div>';
  labelsEl.innerHTML = '<p class="table-message">Loading source label counts...</p>';
  featuresEl.innerHTML = '<p class="table-message">Loading descriptive statistics...</p>';
  glance.innerHTML = '<div><span class="metric-label">BUNDLED DATASET · SEPARATE FROM APK COUNTS</span><b class="overview-dataset-glance-value">Loading dataset summary…</b><span class="metric-meta">Reading metadata records and source labels</span></div>';

  try {
    const summary = await api('/api/dataset');
    const labelCounts = summary.label_counts
      .map(item => `${esc(item.value)}: ${Number(item.count).toLocaleString()} (${esc(item.percentage)}%)`)
      .join(' · ');
    glance.innerHTML = `
      <div>
        <span class="metric-label">BUNDLED DATASET · SEPARATE FROM APK COUNTS</span>
        <b class="overview-dataset-glance-value">${Number(summary.record_count).toLocaleString()} metadata rows · ${Number(summary.unique_package_count).toLocaleString()} unique packages</b>
        <span class="metric-meta">Raw source labels — ${labelCounts}. These CSV records are not APK samples or analysis results.</span>
      </div>
      <button type="button" class="button secondary" data-go="dataset">Explore Dataset Lab</button>
    `;
    $('[data-go="dataset"]', glance).addEventListener('click', () => navigate('dataset'));
    metrics.innerHTML = `
      <div class="metric-card"><span class="metric-label">SOURCE ROWS</span><b class="metric-val">${Number(summary.record_count).toLocaleString()}</b><span class="metric-meta">Records in the bundled CSV</span></div>
      <div class="metric-card"><span class="metric-label">UNIQUE PACKAGES</span><b class="metric-val">${Number(summary.unique_package_count).toLocaleString()}</b><span class="metric-meta">Non-empty package names</span></div>
      <div class="metric-card"><span class="metric-label">SOURCE LABELS</span><b class="metric-val">${summary.label_counts.length}</b><span class="metric-meta">Shown exactly as supplied</span></div>
    `;

    labelsEl.innerHTML = summary.label_counts.length
      ? summary.label_counts.map(item => {
        const percentage = Math.min(100, Math.max(0, Number(item.percentage) || 0));
        return `
          <div class="dataset-label-row overview-dataset-label-row">
            <div><b>Source label ${esc(item.value)}</b><small>Meaning not asserted</small></div>
            <strong>${Number(item.count).toLocaleString()}</strong>
            <span>${esc(item.percentage)}%</span>
            <div class="overview-dataset-bar" aria-hidden="true"><span style="width:${percentage}%"></span></div>
          </div>
        `;
      }).join('')
      : '<p class="table-message">No source labels found.</p>';

    const fields = [
      ['api_call_count', 'API calls'],
      ['perm_count', 'Declared permissions'],
      ['sensitive_perm_count', 'Sensitive permissions'],
      ['vt_detection', 'VT detection count (source field)']
    ];
    const sourceLabels = Object.keys(summary.feature_summary_by_label);
    featuresEl.innerHTML = sourceLabels.length
      ? `<table class="data-table"><thead><tr><th>FEATURE MEAN</th>${sourceLabels.map(label => `<th>LABEL ${esc(label)}</th>`).join('')}</tr></thead><tbody>${fields.map(([field, title]) => `
          <tr><td>${esc(title)}</td>${sourceLabels.map(label => {
            const value = summary.feature_summary_by_label[label]?.[field]?.mean;
            return `<td>${value === null || value === undefined ? '—' : displayDatasetNumber(value)}</td>`;
          }).join('')}</tr>
        `).join('')}</tbody></table>`
      : '<p class="table-message">No descriptive feature means are available.</p>';
  } catch (error) {
    metrics.innerHTML = `<div class="panel dataset-load-error"><b>Dataset summary unavailable</b><p>${esc(error.message)}</p><button class="button secondary" type="button" id="retryOverviewDatasetBtn">Retry</button></div>`;
    labelsEl.innerHTML = '';
    featuresEl.innerHTML = '';
    glance.innerHTML = `<div><span class="metric-label">BUNDLED DATASET</span><b class="overview-dataset-glance-value">Summary unavailable</b><span class="metric-meta">${esc(error.message)}</span></div><button class="button secondary" type="button" id="retryOverviewDatasetGlanceBtn">Retry</button>`;
    $('#retryOverviewDatasetBtn').addEventListener('click', loadOverviewDataset);
    $('#retryOverviewDatasetGlanceBtn').addEventListener('click', loadOverviewDataset);
  }
}

// Quick action buttons
$('#heroNewCaseBtn').addEventListener('click', () => openCaseDialog());
$('#newCaseBtn').addEventListener('click', () => openCaseDialog());
$('#createCaseBtn').addEventListener('click', () => openCaseDialog());
$('#emptyCreateCaseBtn').addEventListener('click', () => openCaseDialog());

// ==============================================================================
// VIEW 2: Cases Management
// ==============================================================================
$('#caseSearch').addEventListener('input', () => loadCases());
$('#caseStatusFilter').addEventListener('change', () => loadCases());

async function loadCases() {
  const statusFilter = $('#caseStatusFilter').value;
  const search = encodeURIComponent($('#caseSearch').value.trim());
  const data = await api(`/api/cases?state=${encodeURIComponent(statusFilter)}&q=${search}`);
  state.cases = data.cases;

  $('#caseRows').innerHTML = data.cases.map(item => {
    const isArchived = Boolean(item.archived_at);
    return `
      <tr>
        <td>
          <button class="table-primary-link case-open" data-case-id="${esc(item.id)}">
            <b>${esc(item.title)}</b>
            <small>${esc(item.description || 'No investigation scope recorded')}</small>
          </button>
        </td>
        <td>${esc(item.owner || 'Unassigned')}</td>
        <td>${esc(item.source || '—')}</td>
        <td>${handlingBadge(item.handling)}</td>
        <td>${caseTags(item.tags).map(t => `<span class="tag">${esc(t)}</span>`).join(' ') || '—'}</td>
        <td>${badge(isArchived ? 'archived' : item.status)}</td>
        <td><b>${item.sample_count}</b></td>
        <td>${shortDate(item.created_at)}</td>
        <td class="actions-col">
          <div style="display:inline-flex;gap:6px;">
            <button class="row-action-btn case-open" data-case-id="${esc(item.id)}">Open</button>
            <button class="row-action-btn case-edit" data-case-id="${esc(item.id)}">Edit</button>
            <button class="row-action-btn case-archive" data-case-id="${esc(item.id)}" data-archived="${isArchived}">
              ${isArchived ? 'Restore' : 'Archive'}
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  setTableEmpty('#caseEmpty', '#caseRows', !data.cases.length);
  $$('.case-open').forEach(btn => btn.addEventListener('click', () => openCase(btn.dataset.caseId)));
  $$('.case-edit').forEach(btn => btn.addEventListener('click', () => openCaseEdit(btn.dataset.caseId)));
  $$('.case-archive').forEach(btn => btn.addEventListener('click', () => archiveCase(btn.dataset.caseId, btn.dataset.archived === 'true')));
}

function openCaseDialog(existingCase = null) {
  state.editingCase = existingCase;
  const form = $('#caseForm');
  form.reset();
  $('#caseError').hidden = true;

  if (existingCase) {
    $('#caseDialogEyebrow').textContent = 'EDIT INVESTIGATION';
    $('#caseDialogTitle').textContent = 'Modify Case Details';
    form.title.value = existingCase.title || '';
    form.source.value = existingCase.source || '';
    form.description.value = existingCase.description || '';
    form.owner.value = existingCase.owner || '';
    form.handling.value = existingCase.handling || 'TLP:AMBER';
    form.tags.value = caseTags(existingCase.tags).join(', ');
    $('#caseStatusField').hidden = false;
    form.status.value = existingCase.status || 'active';
  } else {
    $('#caseDialogEyebrow').textContent = 'NEW INVESTIGATION';
    $('#caseDialogTitle').textContent = 'Create Investigation Case';
    form.owner.value = state.session?.username || 'analyst';
    form.handling.value = 'TLP:AMBER';
    $('#caseStatusField').hidden = true;
  }
  $('#caseDialog').showModal();
}

async function openCaseEdit(id) {
  try {
    const data = await api(`/api/cases/${encodeURIComponent(id)}`);
    openCaseDialog(data.case);
  } catch (error) { toast(error.message); }
}

async function archiveCase(id, currentlyArchived) {
  try {
    await api(`/api/cases/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ archived: !currentlyArchived })
    });
    toast(currentlyArchived ? 'Case restored successfully' : 'Case archived');
    await loadCases();
  } catch (error) { toast(error.message); }
}

$('#caseForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    title: form.title.value.trim(),
    source: form.source.value.trim(),
    description: form.description.value.trim(),
    owner: form.owner.value.trim(),
    handling: form.handling.value,
    tags: form.tags.value.split(',').map(t => t.trim()).filter(Boolean)
  };
  if (state.editingCase) {
    payload.status = form.status.value;
  }

  try {
    if (state.editingCase) {
      const res = await api(`/api/cases/${encodeURIComponent(state.editingCase.id)}`, {
        method: 'PATCH',
        body: JSON.stringify(payload)
      });
      $('#caseDialog').close();
      toast('Case updated successfully');
      await loadCases();
      if (state.caseId === res.id) await openCase(res.id);
    } else {
      const res = await api('/api/cases', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      $('#caseDialog').close();
      toast('Investigation case created');
      await loadCases();
      await openCase(res.id);
    }
  } catch (error) {
    $('#caseError').textContent = error.message;
    $('#caseError').hidden = false;
  }
});

// Modal close button bindings
$$('[data-close]').forEach(btn => btn.addEventListener('click', () => {
  const dlg = $(`#${btn.dataset.close}`);
  if (dlg) dlg.close();
}));

// Case Workspace View
async function openCase(id) {
  try {
    const data = await api(`/api/cases/${encodeURIComponent(id)}`);
    state.caseId = id;
    $('#workspaceCaseName').textContent = data.case.title;
    $('#workspaceCaseInfo').textContent = `${data.case.source || 'No source context'} · Assigned: ${data.case.owner || 'Unassigned'} · ${data.case.handling || 'TLP:AMBER'} · Tags: ${caseTags(data.case.tags).join(', ') || 'none'}`;
    $('#caseSampleCount').textContent = data.samples.length;

    $('#caseSampleList').innerHTML = data.samples.length
      ? data.samples.map(s => `
        <div class="compact-item-row">
          <div class="row-left-content">
            <b>${esc(s.original_filename)}</b>
            <small>${esc(s.package_name || 'Package not extracted')} · ${formatBytes(s.size_bytes)} · SHA-256: ${esc(s.sha256.substring(0, 16))}... · Uploaded: ${shortDate(s.uploaded_at)}</small>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            ${badge(s.analysis_status)}
            <button class="row-action-btn case-sample-inspect" data-sample-id="${esc(s.id)}">Inspect Analysis</button>
          </div>
        </div>
      `).join('')
      : '';

    $('#caseSampleEmpty').hidden = Boolean(data.samples.length);
    $('#caseSampleList').hidden = !data.samples.length;

    $$('.case-sample-inspect').forEach(btn => btn.addEventListener('click', () => openSample(btn.dataset.sampleId)));
    $('#editCaseBtn').onclick = () => openCaseDialog(data.case);
    $('#caseWorkspaceReportBtn').onclick = () => downloadReport('case', id, 'html');
    showPage('caseWorkspace', 'Investigation Workspace');
  } catch (error) { toast(error.message); }
}

$('#backCaseList').addEventListener('click', () => navigate('cases'));

// Upload APK Handlers
$('#uploadBtn').addEventListener('click', () => $('#apkInput').click());
$('#emptyUploadBtn').addEventListener('click', () => $('#apkInput').click());

$('#addSampleBtn').addEventListener('click', openSampleUploadDialog);
$('#emptyAddSampleBtn').addEventListener('click', openSampleUploadDialog);
$('#sampleCreateCaseBtn').addEventListener('click', () => {
  $('#sampleUploadDialog').close();
  openCaseDialog();
});

async function openSampleUploadDialog() {
  const form = $('#sampleUploadForm');
  const select = $('#sampleCaseSelect');
  const error = $('#sampleUploadError');
  const submit = $('#sampleUploadSubmit');
  form.reset();
  error.hidden = true;
  submit.disabled = true;
  select.innerHTML = '<option value="">Loading cases...</option>';
  try {
    const data = await api('/api/cases?state=active');
    select.innerHTML = data.cases.length
      ? data.cases.map(item => `<option value="${esc(item.id)}">${esc(item.title)}</option>`).join('')
      : '<option value="">No active cases available</option>';
    submit.disabled = data.cases.length === 0;
    $('#sampleCreateCaseBtn').hidden = data.cases.length !== 0;
    $('#sampleUploadDialog').showModal();
  } catch (exception) {
    select.innerHTML = '<option value="">Cases could not be loaded</option>';
    error.textContent = exception.message;
    error.hidden = false;
    $('#sampleCreateCaseBtn').hidden = false;
    $('#sampleUploadDialog').showModal();
  }
}

$('#sampleUploadForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = $('#sampleUploadSubmit');
  const error = $('#sampleUploadError');
  const file = $('#sampleFileInput').files?.[0];
  if (!file) return;
  error.hidden = true;
  submit.disabled = true;
  submit.textContent = 'Validating and saving...';
  try {
    const response = await api('/api/samples', {
      method: 'POST',
      body: new FormData(form)
    });
    $('#sampleUploadDialog').close();
    form.reset();
    toast(response.duplicate ? 'This sample already exists in the selected case' : 'APK saved locally; static analysis queued');
    await loadSamples();
    await openSample(response.id);
  } catch (exception) {
    error.textContent = exception.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
    submit.textContent = 'Upload and Inspect';
  }
});

$('#apkInput').addEventListener('change', async event => {
  const file = event.target.files?.[0];
  if (!file || !state.caseId) return;
  if (!file.name.toLowerCase().endsWith('.apk')) {
    toast('Please choose a valid .apk file');
    return;
  }
  const formData = new FormData();
  formData.append('file', file);

  try {
    toast(`Uploading and validating ${file.name}...`);
    const res = await api(`/api/cases/${encodeURIComponent(state.caseId)}/samples`, {
      method: 'POST',
      body: formData
    });
    event.target.value = '';
    toast(res.duplicate ? 'Existing sample linked to this case' : 'APK uploaded; analysis scheduled');
    await openCase(state.caseId);
    await openSample(res.id);
  } catch (error) {
    event.target.value = '';
    toast(error.message);
  }
});

// ==============================================================================
// VIEW 3: Samples Inventory
// ==============================================================================
$('#sampleSearch').addEventListener('input', () => {
  clearTimeout(state.sampleSearchTimer);
  state.sampleSearchTimer = setTimeout(loadSamples, 250);
});
$('#sampleStatusFilter').addEventListener('change', loadSamples);

async function loadSamples() {
  const query = encodeURIComponent($('#sampleSearch').value.trim());
  const status = encodeURIComponent($('#sampleStatusFilter').value);
  const rows = $('#sampleRows');
  setTableEmpty('#sampleEmpty', '#sampleRows', false);
  rows.innerHTML = '<tr><td colspan="7" class="table-message">Loading samples...</td></tr>';
  try {
    const data = await api(`/api/samples?q=${query}&status=${status}`);
    state.samples = data.samples;
    rows.innerHTML = data.samples.map(s => {
      const deleteDisabled = ['queued', 'running'].includes(s.analysis_status);
      return `
      <tr>
        <td>
          <button class="table-primary-link sample-inspect-btn" data-sample-id="${esc(s.id)}">
            <b>${esc(s.original_filename)}</b>
            <small>Case: ${esc(s.case_title || '—')} · ${formatBytes(s.size_bytes)}</small>
          </button>
          ${s.duplicate_count > 1 ? `<span class="tag warning-tag">duplicate ×${s.duplicate_count}</span>` : ''}
        </td>
        <td><code>${esc(s.package_name || 'Not extracted')}</code></td>
        <td>${esc(s.version_name || '—')}</td>
        <td><code class="hash-cell">${esc(s.sha256.substring(0, 16))}...</code></td>
        <td>
          ${badge(s.analysis_status)}
          <small style="color:var(--ink-400);margin-left:6px;">${s.analysis_progress ?? 0}%</small>
        </td>
        <td>${shortDate(s.uploaded_at)}</td>
        <td class="actions-col">
          <div class="sample-row-actions">
            <button type="button" class="row-action-btn sample-inspect-btn" data-sample-id="${esc(s.id)}">Inspect</button>
            <a class="row-action-btn" href="/api/samples/${encodeURIComponent(s.id)}/file">Download</a>
            <button type="button" class="row-action-btn sample-delete-btn" data-sample-id="${esc(s.id)}" ${deleteDisabled ? 'disabled title="Wait for analysis to finish before deleting this sample."' : ''}>Delete</button>
          </div>
        </td>
      </tr>
      `;
    }).join('');

    setTableEmpty('#sampleEmpty', '#sampleRows', !data.samples.length);
    $$('.sample-inspect-btn').forEach(btn => btn.addEventListener('click', () => openSample(btn.dataset.sampleId)));
    $$('.sample-delete-btn').forEach(btn => btn.addEventListener('click', () => deleteSample(btn.dataset.sampleId)));
  } catch (exception) {
    rows.innerHTML = `<tr><td colspan="7" class="table-message error-text">${esc(exception.message)} <button type="button" class="row-action-btn" id="retrySamplesBtn">Retry</button></td></tr>`;
    setTableEmpty('#sampleEmpty', '#sampleRows', false);
    $('#retrySamplesBtn').addEventListener('click', loadSamples);
  }
}

// ==============================================================================
// Bundled Dataset Lab (CSV profiles are separate from uploaded APKs)
// ==============================================================================
$('#datasetSearch').addEventListener('input', () => {
  clearTimeout(state.datasetSearchTimer);
  state.datasetSearchTimer = setTimeout(() => {
    state.datasetOffset = 0;
    loadDatasetRecords();
  }, 250);
});
$('#datasetLabelFilter').addEventListener('change', () => {
  state.datasetOffset = 0;
  loadDatasetRecords();
});
$('#datasetPreviousBtn').addEventListener('click', () => {
  state.datasetOffset = Math.max(0, state.datasetOffset - state.datasetLimit);
  loadDatasetRecords();
});
$('#datasetNextBtn').addEventListener('click', () => {
  if (state.datasetOffset + state.datasetLimit < state.datasetTotal) {
    state.datasetOffset += state.datasetLimit;
    loadDatasetRecords();
  }
});
$('#exportDatasetBtn').addEventListener('click', () => {
  const query = encodeURIComponent($('#datasetSearch').value.trim());
  const label = encodeURIComponent($('#datasetLabelFilter').value);
  window.location.href = `/api/dataset/records.csv?q=${query}&label=${label}`;
});

async function loadDataset() {
  const cards = $('#datasetSummaryCards');
  cards.innerHTML = '<div class="metric-card"><span class="metric-label">DATASET</span><b class="metric-val">Loading</b><span class="metric-meta">Reading local archive</span></div>';
  $('#datasetLabelStats').innerHTML = '<p class="table-message">Loading dataset summary...</p>';
  $('#datasetFeatureStats').innerHTML = '<p class="table-message">Loading dataset summary...</p>';
  try {
    const summary = await api('/api/dataset');
    cards.innerHTML = `
      <div class="metric-card"><span class="metric-label">SOURCE ROWS</span><b class="metric-val">${Number(summary.record_count).toLocaleString()}</b><span class="metric-meta">Metadata records in the bundled CSV</span></div>
      <div class="metric-card"><span class="metric-label">UNIQUE PACKAGES</span><b class="metric-val">${Number(summary.unique_package_count).toLocaleString()}</b><span class="metric-meta">Non-empty package names</span></div>
      <div class="metric-card"><span class="metric-label">RAW LABEL VALUES</span><b class="metric-val">${summary.label_counts.length}</b><span class="metric-meta">Labels kept as supplied</span></div>
      <div class="metric-card"><span class="metric-label">CLASSIFIER ACCURACY</span><b class="metric-val">Not measured</b><span class="metric-meta">No trained model is included</span></div>
    `;
    $('#datasetSourceLabel').textContent = `${summary.source_file} · source archive SHA-256: ${summary.source_sha256}`;
    $('#datasetLabelStats').innerHTML = summary.label_counts.map(item => `
      <div class="dataset-label-row">
        <div><b>Source label ${esc(item.value)}</b><small>Meaning not asserted</small></div>
        <strong>${Number(item.count).toLocaleString()}</strong>
        <span>${esc(item.percentage)}%</span>
      </div>
    `).join('') || '<p class="table-message">No source labels found.</p>';

    const fields = [
      ['api_call_count', 'API calls'],
      ['perm_count', 'Declared permission count'],
      ['sensitive_perm_count', 'Sensitive permission count'],
      ['vt_detection', 'VT detection count (source field)']
    ];
    const labels = Object.keys(summary.feature_summary_by_label);
    $('#datasetFeatureStats').innerHTML = labels.length
      ? `<table class="data-table"><thead><tr><th>FEATURE MEAN</th>${labels.map(label => `<th>LABEL ${esc(label)}</th>`).join('')}</tr></thead><tbody>${fields.map(([field, title]) => `
          <tr><td>${esc(title)}</td>${labels.map(label => {
            const value = summary.feature_summary_by_label[label][field]?.mean;
            return `<td>${value === null || value === undefined ? '—' : Number(value).toLocaleString()}</td>`;
          }).join('')}</tr>
        `).join('')}</tbody></table>`
      : '<p class="table-message">No numeric feature summary is available.</p>';

    const filter = $('#datasetLabelFilter');
    const selected = filter.value;
    filter.innerHTML = `<option value="all">All source labels</option>${summary.label_counts.map(item => `<option value="${esc(item.value)}">Source label ${esc(item.value)}</option>`).join('')}`;
    filter.value = summary.label_counts.some(item => item.value === selected) ? selected : 'all';
    await loadDatasetRecords();
  } catch (exception) {
    cards.innerHTML = `<div class="panel dataset-load-error"><b>Dataset unavailable</b><p>${esc(exception.message)}</p><button class="button secondary" type="button" id="retryDatasetBtn">Retry</button></div>`;
    $('#datasetLabelStats').innerHTML = '';
    $('#datasetFeatureStats').innerHTML = '';
    $('#retryDatasetBtn').addEventListener('click', loadDataset);
  }
}

function displayDatasetNumber(value) {
  if (value === undefined || value === null || value === '') return '—';
  const number = Number(value);
  if (!Number.isFinite(number)) return String(value);
  return Number.isInteger(number) ? number.toLocaleString() : number.toLocaleString(undefined, { maximumFractionDigits: 3 });
}

async function loadDatasetRecords() {
  const rows = $('#datasetRows');
  const query = encodeURIComponent($('#datasetSearch').value.trim());
  const label = encodeURIComponent($('#datasetLabelFilter').value);
  rows.innerHTML = '<tr><td colspan="7" class="table-message">Loading dataset profiles...</td></tr>';
  $('#datasetEmpty').hidden = true;
  try {
    const data = await api(`/api/dataset/records?q=${query}&label=${label}&offset=${state.datasetOffset}&limit=${state.datasetLimit}`);
    state.datasetRecords = data.records;
    state.datasetTotal = data.total;
    rows.innerHTML = data.records.map(record => `
      <tr>
        <td><b>${esc(record.package_name || 'Package name unavailable')}</b><small><code>${esc(record.sha256 || 'SHA-256 unavailable')}</code></small></td>
        <td><span class="tag">Source label ${esc(record.label || '(missing)')}</span></td>
        <td>${displayDatasetNumber(record.features.api_call_count)}</td>
        <td>${displayDatasetNumber(record.features.perm_count)}</td>
        <td>${displayDatasetNumber(record.features.sensitive_perm_count)}</td>
        <td>${displayDatasetNumber(record.features.vt_detection)}</td>
        <td class="actions-col"><button type="button" class="row-action-btn dataset-profile-btn" data-row-id="${esc(record.row_id)}">View profile</button></td>
      </tr>
    `).join('');
    $('#datasetRecordCount').textContent = Number(data.total).toLocaleString();
    const currentPage = data.total ? Math.floor(data.offset / data.limit) + 1 : 0;
    const totalPages = Math.ceil(data.total / data.limit);
    $('#datasetPageInfo').textContent = data.total ? `Page ${currentPage} of ${totalPages}` : 'No results';
    $('#datasetPreviousBtn').disabled = data.offset === 0;
    $('#datasetNextBtn').disabled = data.offset + data.limit >= data.total;
    $('#datasetEmpty').hidden = data.records.length > 0;
    $$('.dataset-profile-btn').forEach(button => button.addEventListener('click', () => {
      showDatasetProfile(button.dataset.rowId);
    }));
  } catch (exception) {
    state.datasetRecords = [];
    rows.innerHTML = `<tr><td colspan="7" class="table-message error-text">${esc(exception.message)} <button type="button" class="row-action-btn" id="retryDatasetRecordsBtn">Retry</button></td></tr>`;
    $('#retryDatasetRecordsBtn').addEventListener('click', loadDatasetRecords);
  }
}

function showDatasetProfile(rowId) {
  const record = state.datasetRecords.find(item => item.row_id === rowId);
  if (!record) {
    toast('Dataset profile is no longer available on this page.');
    return;
  }
  $('#datasetProfileTitle').textContent = record.package_name || `CSV row ${record.row_id}`;
  const featureNames = {
    api_call_count: 'API call count',
    perm_count: 'Permission count',
    sensitive_perm_count: 'Sensitive permission count',
    cert_present: 'Certificate present (source value)',
    is_self_signed: 'Self-signed (source value)',
    valid_years: 'Certificate validity years',
    cert_algo: 'Certificate algorithm',
    cert_key_size: 'Certificate key size',
    signature_strength: 'Signature strength (source field)',
    vt_detection: 'VT detections (source field)',
    distinct_opcodes: 'Distinct opcodes',
    opcode_entropy: 'Opcode entropy',
    control_flow_ratio: 'Control-flow ratio',
    reflection_ratio: 'Reflection ratio',
    string_op_ratio: 'String-operation ratio',
    total_opcodes: 'Total opcodes',
    control_flow_count: 'Control-flow count',
    reflection_count: 'Reflection count',
    perm_send_sms: 'perm_send_sms (source value)',
    perm_receive_sms: 'perm_receive_sms (source value)',
    perm_read_sms: 'perm_read_sms (source value)',
    perm_write_sms: 'perm_write_sms (source value)',
    perm_call_phone: 'perm_call_phone (source value)',
    perm_read_phone_state: 'perm_read_phone_state (source value)',
    perm_read_call_log: 'perm_read_call_log (source value)',
    perm_read_contacts: 'perm_read_contacts (source value)',
    perm_access_fine_location: 'perm_access_fine_location (source value)',
    perm_access_coarse_location: 'perm_access_coarse_location (source value)',
    perm_camera: 'perm_camera (source value)',
    perm_record_audio: 'perm_record_audio (source value)',
    perm_request_install_packages: 'perm_request_install_packages (source value)',
    perm_system_alert_window: 'perm_system_alert_window (source value)',
    perm_write_settings: 'perm_write_settings (source value)'
  };
  const features = Object.entries(record.features).filter(([, value]) => value !== '');
  $('#datasetProfileBody').innerHTML = `
    <p class="dataset-profile-caution">This is CSV metadata (row ${esc(record.row_id)}), not an APK file. Label <b>${esc(record.label || '(missing)')}</b> is shown exactly as stored; its meaning is not asserted. These values are not results from DroidTTP's APK analyzer.</p>
    <div class="dataset-identity">
      <div><span>Package name</span><code>${esc(record.package_name || '—')}</code></div>
      <div><span>SHA-256 in source CSV</span><code>${esc(record.sha256 || '—')}</code></div>
    </div>
    <div class="table-container"><table class="data-table"><thead><tr><th>CSV FEATURE</th><th>SOURCE VALUE</th></tr></thead><tbody>
      ${features.map(([field, value]) => `<tr><td>${esc(featureNames[field] || field)}</td><td><code>${esc(value)}</code></td></tr>`).join('')}
    </tbody></table></div>
  `;
  $('#datasetProfileDialog').showModal();
}

async function deleteSample(id) {
  const sample = state.samples.find(item => item.id === id);
  const filename = sample?.original_filename || state.sample?.sample?.original_filename || 'this sample';
  if (!window.confirm(`Permanently delete ${filename} and its saved analysis findings? This cannot be undone.`)) return;
  try {
    await api(`/api/samples/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (state.sampleId === id) {
      if (state.analysisTimer) clearInterval(state.analysisTimer);
      state.analysisTimer = null;
      state.sample = null;
      state.sampleId = null;
      $('#analysisContent').hidden = true;
      $('#analysisEmpty').hidden = false;
    }
    toast('Sample and saved findings deleted');
    await loadSamples();
    if (state.caseId && state.currentPage === 'caseWorkspace') await openCase(state.caseId);
  } catch (exception) {
    toast(exception.message);
  }
}

// ==============================================================================
// VIEW 4: Sample Analysis Workspace (9 Sub-Tabs)
// ==============================================================================
async function openSample(id, switchToAnalysis = true) {
  try {
    const data = await api(`/api/samples/${encodeURIComponent(id)}`);
    state.sample = data;
    state.sampleId = id;
    renderAnalysis(data);
    if (switchToAnalysis) showPage('analysis', 'Analysis Workspace');

    if (state.analysisTimer) clearInterval(state.analysisTimer);
    if (['queued', 'running'].includes(data.sample.analysis_status)) {
      state.analysisTimer = setInterval(async () => {
        try {
          const current = await api(`/api/samples/${encodeURIComponent(id)}`);
          state.sample = current;
          renderAnalysis(current);
          if (!['queued', 'running'].includes(current.sample.analysis_status)) {
            clearInterval(state.analysisTimer);
            state.analysisTimer = null;
            toast('Static analysis complete and ready for review.');
          }
        } catch (err) {
          clearInterval(state.analysisTimer);
          state.analysisTimer = null;
        }
      }, 2000);
    }
  } catch (error) { toast(error.message); }
}

// Switch between the 9 analysis sub-tabs
function switchAnalysisTab(tabName) {
  state.currentTab = tabName;
  $$('.tab-button').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
    btn.setAttribute('aria-selected', btn.dataset.tab === tabName);
  });
  $$('.tab-pane').forEach(pane => {
    pane.hidden = pane.id !== `tabContent${tabName.charAt(0).toUpperCase() + tabName.slice(1).replace(/-([a-z])/g, g => g[1].toUpperCase())}`;
  });
}

$$('.tab-button').forEach(btn => btn.addEventListener('click', () => switchAnalysisTab(btn.dataset.tab)));

function renderAnalysis(data) {
  const sample = data.sample;
  const analysis = data.analysis || {};
  $('#analysisEmpty').hidden = true;
  $('#analysisContent').hidden = false;

  // Header and Hashes
  $('#analysisName').textContent = sample.original_filename;
  $('#analysisHash').textContent = sample.sha256;
  $('#copySampleHashBtn').onclick = () => copyToClipboard(sample.sha256, 'SHA-256 copied');
  $('#downloadSampleBtn').onclick = () => {
    window.location.href = `/api/samples/${encodeURIComponent(sample.id)}/file`;
  };
  $('#downloadSampleBtn').disabled = !sample.storage_name;
  $('#deleteSampleBtn').disabled = ['queued', 'running'].includes(sample.analysis_status);
  $('#deleteSampleBtn').title = $('#deleteSampleBtn').disabled
    ? 'Wait for analysis to finish before deleting this sample.'
    : 'Permanently delete this sample and its saved findings.';
  $('#deleteSampleBtn').onclick = () => deleteSample(sample.id);

  // Status Badge and Progress
  const statusEl = $('#analysisStatusBadge');
  statusEl.textContent = String(sample.analysis_status).replaceAll('_', ' ').toUpperCase();
  statusEl.className = `status-chip ${sample.analysis_status}`;

  $('#progressLabel').textContent = `Analysis ${sample.analysis_status.toUpperCase()}`;
  $('#progressPercent').textContent = `${sample.analysis_progress ?? 0}%`;
  $('#progressBar').style.width = `${Math.max(0, Math.min(100, sample.analysis_progress ?? 0))}%`;
  $('#analysisTiming').textContent = `Started: ${preciseDate(sample.analysis_started_at)} · Completed: ${preciseDate(sample.analysis_completed_at)}`;
  $('#analysisError').textContent = sample.analysis_error || '';

  // Tab Counts Badges
  const perms = analysis.permissions || [];
  const comps = analysis.components || [];
  const strings = analysis.strings || [];
  const netEvs = data.evidence.filter(e => ['url', 'domain', 'ip'].includes(e.kind));

  $('#tabPermCount').textContent = perms.length;
  $('#tabCompCount').textContent = comps.length;
  $('#tabStringCount').textContent = strings.length;
  $('#tabNetCount').textContent = netEvs.length;

  // TAB 1: Summary Meta
  const summaryMeta = [
    ['Package Identifier', sample.package_name || 'Not extracted'],
    ['Application Label', sample.app_name || 'Not extracted'],
    ['Version Name', sample.version_name || '—'],
    ['Min SDK Version', sample.min_sdk || '—'],
    ['Target SDK Version', sample.target_sdk || '—'],
    ['Archive File Size', formatBytes(sample.size_bytes)],
    ['Total Archive Entries', analysis.archive_entries ?? '—'],
    ['Compiled DEX Files', analysis.dex_files ?? sample.dex_count ?? 0],
    ['Native Compiled (.so) Libs', analysis.native_libraries ?? sample.native_count ?? 0],
    ['Ingestion Timestamp', preciseDate(sample.uploaded_at)]
  ];
  $('#summaryMetaGrid').innerHTML = summaryMeta.map(([label, val]) => `
    <div class="meta-field-cell">
      <span>${esc(label)}</span>
      <b>${esc(val)}</b>
    </div>
  `).join('');

  // TAB 1: Cryptographic Hashes
  const hashes = [
    ['SHA-256', sample.sha256],
    ['SHA-1', sample.sha1 || 'Calculated on upload'],
    ['MD5', sample.md5 || 'Calculated on upload']
  ];
  $('#summaryHashGrid').innerHTML = hashes.map(([alg, val]) => `
    <div class="meta-field-cell">
      <span>${esc(alg)}</span>
      <b style="font-family:var(--font-mono);font-size:0.78rem;">${esc(val)}</b>
    </div>
  `).join('');

  $('#provenanceContent').innerHTML = `
    <b>Inspection Scope &amp; Safety Bounds:</b>
    <p style="margin-top:4px;color:var(--ink-600);">Static parser inspected archive index, text XML manifest, packaged resources, and native binary references. Code was never executed. Resource limits enforced (10,000 files, 512 MiB expanded, 90-120s execution bound).</p>
  `;

  // TAB 2: Manifest
  const manifestKind = sample.manifest_kind || 'unavailable';
  $('#manifestKindChip').textContent = manifestKind === 'text-xml' ? 'PARSED TEXT XML' : 'BINARY ENCODED / AXML';
  $('#manifestKindChip').className = `status-chip ${manifestKind === 'text-xml' ? 'completed' : 'partial'}`;
  $('#manifestSummaryBlock').innerHTML = `
    <b>Manifest Declaration Overview:</b>
    <p style="margin-top:4px;">Package: <code>${esc(sample.package_name || 'Not found')}</code> · Version: <code>${esc(sample.version_name || '—')}</code> · Min SDK: <code>${esc(sample.min_sdk || '—')}</code> · Target SDK: <code>${esc(sample.target_sdk || '—')}</code></p>
  `;
  const manifestObj = {
    package: sample.package_name,
    version: sample.version_name,
    min_sdk: sample.min_sdk,
    target_sdk: sample.target_sdk,
    manifest_kind: sample.manifest_kind,
    permissions_count: perms.length,
    components_count: comps.length
  };
  $('#manifestCodeView').textContent = JSON.stringify(manifestObj, null, 2);
  $('#copyManifestJsonBtn').onclick = () => copyToClipboard(JSON.stringify(manifestObj, null, 2), 'Manifest structure copied');

  // TAB 3: Permissions
  renderPermissionsTab(perms);

  // TAB 4: Components
  renderComponentsTab(comps);

  // TAB 5: Certificates
  const certs = analysis.certificate_artifacts || [];
  $('#certificatesList').innerHTML = certs.length
    ? certs.map(c => `
      <div class="compact-item-row">
        <div class="row-left-content">
          <code>${esc(c)}</code>
          <small>Signature digest artifact inside META-INF directory</small>
        </div>
        <span class="tag">Present</span>
      </div>
    `).join('')
    : '<div class="empty-state compact"><p>No META-INF certificate artifacts detected in APK archive.</p></div>';

  // TAB 6: Strings
  renderStringsTab(strings);

  // TAB 7: Network Indicators
  renderNetworkTab(netEvs);

  // TAB 8: Files & Binaries
  const dexNames = analysis.dex_file_names || [];
  const nativeNames = analysis.native_library_names || [];
  $('#filesInventoryContent').innerHTML = `
    <div class="tab-grid-dual">
      <div class="panel">
        <div class="panel-header">
          <h4 class="panel-title">DEX Bytecode Files (${dexNames.length})</h4>
        </div>
        ${dexNames.length ? dexNames.map(d => `<div class="compact-item-row"><code>${esc(d)}</code><span class="tag">Dalvik Executable</span></div>`).join('') : '<p class="muted">No DEX files detected.</p>'}
      </div>
      <div class="panel">
        <div class="panel-header">
          <h4 class="panel-title">Native Shared Libraries (.so) (${nativeNames.length})</h4>
        </div>
        ${nativeNames.length ? nativeNames.map(n => `<div class="compact-item-row"><code>${esc(n)}</code><span class="tag">ELF Binary</span></div>`).join('') : '<p class="muted">No compiled native libraries (.so) bundled.</p>'}
      </div>
    </div>
  `;

  // TAB 9: Tool Output
  $('#rawJsonBlock').textContent = JSON.stringify(data, null, 2);
  $('#copyRawAnalysisJsonBtn').onclick = () => copyToClipboard(JSON.stringify(data, null, 2), 'Raw analysis JSON copied');
  $('#unsupportedList').innerHTML = (analysis.unsupported_data || [
    'Binary Android XML manifest decoding',
    'DEX bytecode decompilation & CFG reconstruction',
    'Cryptographic signing certificate chain verification',
    'Dynamic runtime behavioral sandboxing'
  ]).map(u => `<li>${esc(u)}</li>`).join('');

  // ATT&CK Candidate Mappings (underneath tabs)
  renderMappingCards(data.mappings);

  // Sample Evidence
  renderSampleEvidence(data.evidence);

  // Action buttons
  $('#analysisReportBtn').onclick = () => downloadReport('sample', sample.id, 'html');
  $('#analysisAddMappingBtn').onclick = openManualMapping;
  $('#addMappingBtnInline').onclick = openManualMapping;
}

// Permissions Tab Filter
function renderPermissionsTab(perms) {
  const container = $('#permissionsList');
  const searchInput = $('#permSearch');

  function update() {
    const q = (searchInput?.value || '').trim().toLowerCase();
    const filtered = perms.filter(p => !q || p.toLowerCase().includes(q));

    container.innerHTML = filtered.length
      ? filtered.map(p => {
        const isDangerous = p.includes('LOCATION') || p.includes('CAMERA') || p.includes('AUDIO') || p.includes('SMS') || p.includes('CALL_LOG') || p.includes('CONTACTS') || p.includes('PHONE_STATE');
        const isSpecial = p.includes('ACCESSIBILITY') || p.includes('ALERT_WINDOW') || p.includes('NOTIFICATION') || p.includes('DEVICE_ADMIN') || p.includes('MANAGE_EXTERNAL_STORAGE');
        const classification = isDangerous ? 'Dangerous' : (isSpecial ? 'Special Access' : 'Normal / System');
        const tagCls = isDangerous ? 'warning-tag' : 'tag';

        return `
          <div class="perm-item-card">
            <div class="perm-left">
              <code>${esc(p)}</code>
            </div>
            <div class="perm-right">
              <span class="${tagCls}">${classification}</span>
              <button class="icon-text-btn" data-copy-perm="${esc(p)}">Copy</button>
            </div>
          </div>
        `;
      }).join('')
      : '<div class="empty-state compact"><p>No permissions match filter.</p></div>';

    $$('[data-copy-perm]').forEach(btn => btn.addEventListener('click', () => copyToClipboard(btn.dataset.copyPerm, 'Permission string copied')));
  }

  if (searchInput) searchInput.oninput = update;
  update();
}

// Components Tab Filter
function renderComponentsTab(comps) {
  const container = $('#componentsList');
  const searchInput = $('#compSearch');

  function update() {
    const q = (searchInput?.value || '').trim().toLowerCase();
    const filtered = comps.filter(c => !q || (c.name || '').toLowerCase().includes(q) || (c.type || '').toLowerCase().includes(q));

    container.innerHTML = filtered.length
      ? filtered.map(c => `
        <div class="comp-item-card">
          <div class="comp-left">
            <code>${esc(c.type?.toUpperCase())} · ${esc(c.name || 'unnamed')}</code>
          </div>
          <div class="comp-right">
            <span class="tag ${c.exported === 'true' ? 'warning-tag' : ''}">exported: ${esc(c.exported || 'unspecified')}</span>
            <button class="icon-text-btn" data-copy-comp="${esc(c.name || '')}">Copy</button>
          </div>
        </div>
      `).join('')
      : '<div class="empty-state compact"><p>No components match filter.</p></div>';

    $$('[data-copy-comp]').forEach(btn => btn.addEventListener('click', () => copyToClipboard(btn.dataset.copyComp, 'Component name copied')));
  }

  if (searchInput) searchInput.oninput = update;
  update();
}

// Strings Tab Filter
function renderStringsTab(strings) {
  const container = $('#stringsList');
  const searchInput = $('#stringSearch');

  function update() {
    const q = (searchInput?.value || '').trim().toLowerCase();
    const filtered = strings.filter(s => !q || (s.value || '').toLowerCase().includes(q) || (s.location || '').toLowerCase().includes(q));

    container.innerHTML = filtered.length
      ? `
        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>EXTRACTED STRING</th>
                <th>ORIGIN LOCATION</th>
                <th class="actions-col"></th>
              </tr>
            </thead>
            <tbody>
              ${filtered.slice(0, 150).map(s => `
                <tr>
                  <td><code>${esc(s.value)}</code></td>
                  <td><small style="color:var(--ink-500);">${esc(s.location)}</small></td>
                  <td class="actions-col">
                    <button class="icon-text-btn" data-copy-str="${esc(s.value)}">Copy</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
        ${filtered.length > 150 ? `<p style="font-size:0.75rem;color:var(--ink-400);margin-top:8px;">Showing first 150 of ${filtered.length} matching strings.</p>` : ''}
      `
      : '<div class="empty-state compact"><p>No strings match filter.</p></div>';

    $$('[data-copy-str]').forEach(btn => btn.addEventListener('click', () => copyToClipboard(btn.dataset.copyStr, 'String copied')));
  }

  if (searchInput) searchInput.oninput = update;
  update();
}

// Network Indicators Tab Filter
function renderNetworkTab(netEvs) {
  const tbody = $('#networkIndicatorRows');
  if (!tbody) return;

  tbody.innerHTML = netEvs.length
    ? netEvs.map(e => `
      <tr>
        <td><span class="tag">${esc(e.kind.toUpperCase())}</span></td>
        <td><code>${esc(defang(e.value, e.kind))}</code></td>
        <td><small style="color:var(--ink-500);">${esc(e.location || 'Packaged resource')}</small></td>
        <td class="actions-col">
          <div style="display:inline-flex;gap:6px;">
            <button class="icon-text-btn" data-copy-defanged="${esc(defang(e.value, e.kind))}">Copy Defanged</button>
            <button class="icon-text-btn" data-copy-raw="${esc(e.value)}">Copy Raw</button>
          </div>
        </td>
      </tr>
    `).join('')
    : '<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--ink-400);">No network indicators extracted.</td></tr>';

  $$('[data-copy-defanged]').forEach(btn => btn.addEventListener('click', () => copyToClipboard(btn.dataset.copyDefanged, 'Defanged indicator copied')));
  $$('[data-copy-raw]').forEach(btn => btn.addEventListener('click', () => copyToClipboard(btn.dataset.copyRaw, 'Raw indicator copied (use with caution)')));
}

// ATT&CK Mapping Cards
function renderMappingCards(mappings) {
  const container = $('#sampleMappings');
  if (!container) return;

  container.innerHTML = mappings.length
    ? mappings.map(m => `
      <div class="mapping-card">
        <div class="mapping-card-top">
          <div class="mapping-title-block">
            <b>${esc(m.technique_id)} · ${esc(m.name)}</b>
            <small>Tactic: ${esc(m.tactic)} · Taxonomy: ${esc(m.taxonomy_version || 'MITRE Android catalogue')}</small>
          </div>
          <div style="display:flex;align-items:center;gap:6px;">
            <span class="tag">${esc(m.confidence)} conf</span>
            ${badge(m.status)}
          </div>
        </div>

        <div class="mapping-rationale-box">
          <b>Analyst Rationale:</b>
          <p>${esc(m.rationale || 'No rationale recorded.')}</p>
        </div>

        ${m.evidence && m.evidence.length ? `
          <div class="mapping-evidence-chips">
            ${m.evidence.map(e => `<span class="tag">Evidence: ${esc(e.kind)} (${esc(defang(e.value, e.kind).substring(0, 30))})</span>`).join('')}
          </div>
        ` : ''}

        <div class="mapping-actions-row">
          <div class="action-btn-group">
            <button class="btn-confirm" data-update-mapping="${esc(m.id)}" data-status="confirmed" data-conf="${esc(m.confidence)}">Confirm</button>
            <button class="btn-reject" data-update-mapping="${esc(m.id)}" data-status="rejected" data-conf="${esc(m.confidence)}">Reject</button>
            <button class="row-action-btn" data-update-mapping="${esc(m.id)}" data-status="deferred" data-conf="${esc(m.confidence)}">Defer</button>
          </div>
          <button class="row-action-btn" data-edit-mapping-rationale="${esc(m.id)}" data-rationale="${esc(m.rationale)}" data-conf="${esc(m.confidence)}" data-status="${esc(m.status)}">Edit Note</button>
        </div>
      </div>
    `).join('')
    : '<div class="empty-state compact"><p>No candidate ATT&amp;CK mappings for this sample. Use "+ Add Manual Mapping" to author one.</p></div>';

  $$('[data-update-mapping]').forEach(btn => btn.addEventListener('click', async () => {
    try {
      await api(`/api/mappings/${encodeURIComponent(btn.dataset.updateMapping)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: btn.dataset.status,
          confidence: btn.dataset.conf
        })
      });
      toast(`Mapping marked as ${btn.dataset.status}`);
      await openSample(state.sampleId, false);
    } catch (error) { toast(error.message); }
  }));

  $$('[data-edit-mapping-rationale]').forEach(btn => btn.addEventListener('click', async () => {
    const newRationale = prompt('Update Analyst Rationale:', btn.dataset.rationale);
    if (newRationale === null) return;
    try {
      await api(`/api/mappings/${encodeURIComponent(btn.dataset.editMappingRationale)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: btn.dataset.status,
          confidence: btn.dataset.conf,
          rationale: newRationale.trim()
        })
      });
      toast('Rationale updated');
      await openSample(state.sampleId, false);
    } catch (error) { toast(error.message); }
  }));
}

// Sample Evidence Table
function renderSampleEvidence(evidence) {
  const tbody = $('#sampleEvidenceRows');
  const countEl = $('#sampleEvidenceCount');
  const searchInput = $('#sampleEvidenceSearch');
  if (!tbody) return;

  async function editEvidence(button) {
    const note = window.prompt('Edit analyst note for this finding:', button.dataset.note || '');
    if (note === null) return;
    if (note.length > 1000) {
      toast('Analyst notes must be 1,000 characters or fewer');
      return;
    }
    const confidence = window.prompt('Confidence: low, moderate, or high', button.dataset.confidence || 'low');
    if (confidence === null) return;
    const normalizedConfidence = confidence.trim().toLowerCase();
    if (!['low', 'moderate', 'high'].includes(normalizedConfidence)) {
      toast('Choose low, moderate, or high confidence');
      return;
    }
    try {
      await api(`/api/evidence/${encodeURIComponent(button.dataset.editEvidence)}`, {
        method: 'PATCH',
        body: JSON.stringify({ note: note.trim(), confidence: normalizedConfidence })
      });
      toast('Finding note saved');
      await openSample(state.sampleId, false);
    } catch (exception) {
      toast(exception.message);
    }
  }

  function update() {
    const q = (searchInput?.value || '').trim().toLowerCase();
    const filtered = evidence.filter(e => !q || (e.value || '').toLowerCase().includes(q) || (e.kind || '').toLowerCase().includes(q) || (e.note || '').toLowerCase().includes(q));

    if (countEl) countEl.textContent = filtered.length;

    tbody.innerHTML = filtered.length
      ? filtered.map(e => `
        <tr>
          <td><span class="tag">${esc(e.kind.toUpperCase())}</span></td>
          <td><code>${esc(defang(e.value, e.kind))}</code></td>
          <td><small style="color:var(--ink-500);">${esc(e.source)} · ${esc(e.location || '—')}</small></td>
          <td><span class="tag">${esc(e.confidence || 'low')}</span></td>
          <td><small style="color:var(--ink-600);">${esc(e.note || '—')}</small></td>
          <td><button type="button" class="row-action-btn" data-edit-evidence="${esc(e.id)}" data-note="${esc(e.note || '')}" data-confidence="${esc(e.confidence || 'low')}">Edit</button></td>
        </tr>
      `).join('')
      : '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--ink-400);">No evidence items matching query.</td></tr>';
    $$('[data-edit-evidence]', tbody).forEach(button => {
      button.onclick = () => editEvidence(button);
    });
  }

  if (searchInput) searchInput.oninput = update;
  update();
}

// Manual Mapping Modal
async function openManualMapping() {
  if (!state.sampleId) return;
  const form = $('#mappingForm');
  form.reset();
  $('#mappingError').hidden = true;

  try {
    const techData = await api('/api/techniques');
    const select = form.technique_id;
    select.innerHTML = techData.techniques.map(t => `
      <option value="${esc(t.id)}">${esc(t.id)} · ${esc(t.name)} (${esc(t.tactic)})</option>
    `).join('');
    $('#mappingDialog').showModal();
  } catch (error) { toast(error.message); }
}

$('#mappingForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    technique_id: form.technique_id.value,
    confidence: form.confidence.value,
    rationale: form.rationale.value.trim()
  };

  try {
    await api(`/api/samples/${encodeURIComponent(state.sampleId)}/mappings`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    $('#mappingDialog').close();
    toast('Manual mapping attached to sample');
    await openSample(state.sampleId, false);
  } catch (error) {
    $('#mappingError').textContent = error.message;
    $('#mappingError').hidden = false;
  }
});

// ==============================================================================
// VIEW 5: ATT&CK Mobile Catalogue
// ==============================================================================
$('#techniqueSearch').addEventListener('input', () => loadTechniques());

async function loadTechniques() {
  const query = encodeURIComponent($('#techniqueSearch').value.trim());
  const data = await api(`/api/techniques?q=${query}`);
  state.techniques = data.techniques;

  $('#taxonomyMeta').textContent = `Framework: ${data.version || 'MITRE Android catalogue'} · Source: ${data.source || 'MITRE ATT&CK Mobile'}`;

  // Group by tactic
  const grouped = {};
  data.techniques.forEach(t => {
    const tactic = t.tactic || 'General';
    grouped[tactic] = grouped[tactic] || [];
    grouped[tactic].push(t);
  });

  const container = $('#techniqueGroups');
  container.innerHTML = Object.entries(grouped).map(([tactic, items]) => `
    <div class="tactic-group-card">
      <div class="tactic-group-header">
        <h3>${esc(tactic)}</h3>
        <span class="tag">${items.length} techniques</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${items.map(t => `
          <div class="compact-item-row" style="cursor:default;">
            <div class="row-left-content">
              <b>${esc(t.id)} · ${esc(t.name)}</b>
              <small>${esc(t.description)}</small>
            </div>
            ${t.mapping_status !== 'unmapped' ? badge(t.mapping_status) : '<span class="tag">Unmapped</span>'}
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

// ==============================================================================
// VIEW 6: Evidence Register
// ==============================================================================
$('#evidenceSearch').addEventListener('input', () => loadEvidence());
$('#evidenceKindFilter').addEventListener('change', () => loadEvidence());

async function loadEvidence() {
  const query = encodeURIComponent($('#evidenceSearch').value.trim());
  const kind = encodeURIComponent($('#evidenceKindFilter').value);
  const data = await api(`/api/evidence?q=${query}&kind=${kind}`);

  $('#evidenceRows').innerHTML = data.evidence.map(e => `
    <tr>
      <td><span class="tag">${esc(e.kind.toUpperCase())}</span></td>
      <td><code>${esc(defang(e.value, e.kind))}</code></td>
      <td>${esc(e.source)}</td>
      <td><small style="color:var(--ink-500);">${esc(e.location || '—')}</small></td>
      <td>${shortDate(e.created_at)}</td>
      <td><span class="tag">${esc(e.confidence || 'low')}</span></td>
      <td><small style="color:var(--ink-600);">${esc(e.note || '—')}</small></td>
      <td>${e.mapping_techniques ? `<span class="ttp-link-pill">${esc(e.mapping_techniques)}</span>` : '—'}</td>
    </tr>
  `).join('');

  setTableEmpty('#evidenceEmpty', '#evidenceRows', !data.evidence.length);
}

// ==============================================================================
// VIEW 7: Reports
// ==============================================================================
async function loadReports() {
  const container = $('#reportList');
  const caseData = await api('/api/cases?state=all');

  container.innerHTML = caseData.cases.map(c => `
    <div class="panel">
      <div class="panel-header">
        <div>
          <span class="panel-eyebrow">CASE REPORT</span>
          <h3 class="panel-title">${esc(c.title)}</h3>
          <p class="panel-subtitle">Handling: ${esc(c.handling)} · Samples: ${c.sample_count} · Created: ${shortDate(c.created_at)}</p>
        </div>
      </div>
      <div style="display:flex;gap:10px;margin-top:16px;">
        <button class="button primary" onclick="downloadReport('case', '${esc(c.id)}', 'html')">
          Download HTML Report
        </button>
        <button class="button secondary" onclick="downloadReport('case', '${esc(c.id)}', 'json')">
          Structured CTI JSON
        </button>
      </div>
    </div>
  `).join('') || '<div class="empty-state"><h3>No reports available</h3><p>Create a case and analyze samples to generate intelligence reports.</p></div>';
}

function downloadReport(type, id, format) {
  const url = type === 'case'
    ? `/api/cases/${encodeURIComponent(id)}/report.${format}`
    : `/api/samples/${encodeURIComponent(id)}/report.${format}`;
  window.open(url, '_blank');
}

// ==============================================================================
// VIEW 8: Activity Log
// ==============================================================================
$('#refreshActivityBtn').addEventListener('click', () => loadActivity());

async function loadActivity() {
  const data = await api('/api/activity');
  const container = $('#activityTimeline');

  container.innerHTML = data.activity.length
    ? data.activity.map(a => `
      <div class="compact-item-row" style="cursor:default;">
        <div class="row-left-content">
          <b>${esc(a.action.replaceAll('_', ' ').toUpperCase())}</b>
          <small>Target: <code>${esc(a.object_id)}</code> · Detail: ${esc(a.detail || 'None')} · Actor: <b>${esc(a.actor)}</b></small>
        </div>
        <span class="tag">${preciseDate(a.occurred_at)}</span>
      </div>
    `).join('')
    : '<div class="empty-state compact"><p>No activity log entries found.</p></div>';
}

// ==============================================================================
// VIEW 9: Settings
// ==============================================================================
async function loadSettings() {
  const settings = await api('/api/settings');

  $('#settingsValues').innerHTML = `
    <div class="meta-field-cell"><span>Max APK Upload Size</span><b>${settings.max_upload_mb} MB</b></div>
    <div class="meta-field-cell"><span>Worker Timeout Limit</span><b>${settings.analysis_timeout_seconds} seconds</b></div>
    <div class="meta-field-cell"><span>Configured Retention</span><b>${settings.retention_days > 0 ? `${settings.retention_days} days` : 'Disabled'}</b></div>
  `;
  $('#retentionDays').value = settings.retention_days;

  $('#integrationStatus').innerHTML = `
    <div class="meta-field-cell"><span>Dynamic Execution Sandbox</span><b>${esc(settings.dynamic_analysis)}</b></div>
    <div class="meta-field-cell"><span>External Intelligence Lookups</span><b>${esc(settings.external_integrations)}</b></div>
  `;

  $('#taxonomySettings').innerHTML = `
    <div class="meta-field-cell"><span>ATT&amp;CK Version Tag</span><b>${esc(settings.taxonomy_version)}</b></div>
    <div class="meta-field-cell"><span>Framework Source</span><b>${esc(settings.taxonomy_source)}</b></div>
  `;

  $('#accessSettings').innerHTML = `
    <div class="meta-field-cell"><span>Session User Role</span><b style="text-transform:uppercase;">${esc(settings.role)}</b></div>
    <div class="meta-field-cell"><span>Secrets Display Policy</span><b>Never exposed</b></div>
  `;
}

$('#retentionForm').addEventListener('submit', async event => {
  event.preventDefault();
  const days = parseInt($('#retentionDays').value, 10);
  try {
    await api('/api/settings', {
      method: 'PATCH',
      body: JSON.stringify({ retention_days: days })
    });
    toast('Retention policy updated');
    await loadSettings();
  } catch (error) { toast(error.message); }
});

// ==============================================================================
// App Initialization
// ==============================================================================
window.addEventListener('DOMContentLoaded', () => {
  checkSession();
});
