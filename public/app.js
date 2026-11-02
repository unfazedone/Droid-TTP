const app = document.querySelector("#app");
const iconPaths = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
  folder: '<path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H10l2 2h7.5A1.5 1.5 0 0 1 21 9.5v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/><path d="M3 10h18"/>',
  shield: '<path d="M12 3 20 6v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6z"/><path d="m9 12 2 2 4-4"/>',
  search: '<circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.5 4.5"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.7 2.9-.2-.1a1.7 1.7 0 0 0-1.9.3l-.2.2h-3.4l-.1-.2a1.7 1.7 0 0 0-1.7-1l-.2.1-2.9-1.7.1-.2a1.7 1.7 0 0 0-.3-1.9l-.2-.2v-3.4l.2-.1a1.7 1.7 0 0 0 .3-1.9l-.1-.2L9 6.7l.2.1a1.7 1.7 0 0 0 1.9-.3l.2-.2h3.4l.1.2a1.7 1.7 0 0 0 1.9.3l.2-.1 2.9 1.7-.1.2a1.7 1.7 0 0 0 .3 1.9l.2.2v3.4z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  upload: '<path d="M12 16V4m0 0L7 9m5-5 5 5"/><path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m18 6-12 12M6 6l12 12"/>',
  arrow: '<path d="M5 12h14m-6-6 6 6-6 6"/>',
  download: '<path d="M12 4v11m0 0 4-4m-4 4-4-4"/><path d="M5 19h14"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M5 21a7 7 0 0 1 14 0"/>',
  alert: '<path d="m10.3 4.3-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3l-8-14a2 2 0 0 0-3.4 0z"/><path d="M12 9v4m0 4h.01"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  report: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>',
  logout: '<path d="M10 17l5-5-5-5m5 5H3"/><path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.1 0l3-3A5 5 0 0 0 13 2.9l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.1 0l-3 3A5 5 0 0 0 11 21.1l1.7-1.7"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M20 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>'
};
const ico = (name, cls = "") => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[name] || iconPaths.file}</svg>`;
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
const dateLabel = (value) => value ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
const shortDate = (value) => value ? new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "—";
const pretty = (value) => String(value || "").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
const state = { user: null, csrf: "", cases: [], view: "dashboard", caseId: null, detail: null, caseTab: "overview", settings: null, users: [], indicators: [], searchTimer: null, uploadLimitMb: 50, taxonomyVersion: "" };

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof ArrayBuffer) && !(options.body instanceof Blob)) headers.set("Content-Type", "application/json");
  if (state.csrf && options.method && options.method !== "GET") headers.set("X-CSRF-Token", state.csrf);
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  const data = response.status === 204 ? {} : await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function toast(message, error = false) {
  let region = document.querySelector(".toast-region");
  if (!region) {
    region = document.createElement("div");
    region.className = "toast-region";
    region.setAttribute("aria-live", "polite");
    document.body.append(region);
  }
  const item = document.createElement("div");
  item.className = `toast${error ? " error" : ""}`;
  item.textContent = message;
  region.append(item);
  setTimeout(() => item.remove(), 4200);
}

function setLoading() {
  app.innerHTML = `<main class="boot-screen" aria-live="polite"><div class="brand-mark brand-mark-large">D</div><p>Opening analyst workspace…</p></main>`;
}

async function initialize() {
  try {
    const status = await api("/api/auth/status");
    if (status.setupRequired) return renderAuth(true);
    try {
      const session = await api("/api/session");
      state.user = session.user;
      state.csrf = session.csrf;
      await loadWorkspace();
    } catch (error) {
      if (error.message !== "Sign in to continue.") throw error;
      renderAuth(false);
    }
  } catch (error) {
    app.innerHTML = `<main class="auth-shell"><section class="auth-aside"><div class="brand-lockup"><div class="brand-mark">D</div><div><div class="brand-name">DroidTTP</div><div class="brand-caption">Android threat intelligence</div></div></div><div class="auth-intro"><span class="eyebrow">Local analyst workspace</span><h1>Analysis, with evidence at the center.</h1><p>Inspect Android packages, organize findings, and review ATT&amp;CK mappings in a private local workspace.</p></div><div class="auth-note">APK parsing runs in a separate worker. Uploaded samples remain in private local storage and are never executed by this application.</div></section><section class="auth-main"><div class="auth-card"><h2>Application unavailable</h2><p>${esc(error.message)}</p><button class="button button-secondary" id="retry-startup">Try again</button></div></section></main>`;
    document.querySelector("#retry-startup").addEventListener("click", initialize);
  }
}

function renderAuth(setup) {
  state.user = null;
  const heading = setup ? "Set up your workspace" : "Welcome back";
  const intro = setup ? "Create the first administrator account. Additional accounts and roles can be managed later." : "Sign in to your private DroidTTP workspace.";
  app.innerHTML = `
    <main class="auth-shell">
      <section class="auth-aside">
        <div class="brand-lockup"><div class="brand-mark">D</div><div><div class="brand-name">DroidTTP</div><div class="brand-caption">Android threat intelligence</div></div></div>
        <div class="auth-intro"><span class="eyebrow">Local analyst workspace</span><h1>Analysis, with evidence at the center.</h1><p>Inspect Android packages, organize findings, and review ATT&amp;CK mappings in a private, case-oriented workspace.</p></div>
        <div class="auth-note">APK contents are untrusted input. Static parsing runs in a separate worker; this application never executes uploaded APKs. Files and case data stay on this server.</div>
      </section>
      <section class="auth-main"><div class="auth-card">
        <span class="eyebrow">${setup ? "First-time setup" : "Secure sign in"}</span><h2>${heading}</h2><p>${intro}</p>
        <form class="auth-form" id="auth-form">
          ${setup ? `<div class="field"><label for="auth-name">Full name</label><input class="input" id="auth-name" name="name" autocomplete="name" required maxlength="100"></div>` : ""}
          <div class="field"><label for="auth-email">Email address</label><input class="input" id="auth-email" name="email" type="email" autocomplete="username" required maxlength="254"></div>
          <div class="field"><label for="auth-password">Password</label><input class="input" id="auth-password" name="password" type="password" autocomplete="${setup ? "new-password" : "current-password"}" required minlength="${setup ? "12" : "1"}" maxlength="256">${setup ? `<span class="field-hint">Use at least 12 characters. Passwords are hashed before storage.</span>` : ""}</div>
          <button class="button button-primary" type="submit">${setup ? "Create administrator" : "Sign in"} ${ico("arrow")}</button>
        </form>
        <div class="auth-foot">Local single-team deployment · No subscriptions, billing, or sample-sharing service. Dynamic execution is unavailable unless an isolated provider is separately configured.</div>
      </div></section>
    </main>`;
  document.querySelector("#auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    button.disabled = true;
    try {
      const form = new FormData(event.currentTarget);
      const data = Object.fromEntries(form.entries());
      const session = await api(setup ? "/api/setup" : "/api/login", { method: "POST", body: JSON.stringify(data) });
      state.user = session.user;
      state.csrf = session.csrf;
      await loadWorkspace();
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  });
}

async function loadWorkspace() {
  const [cases, settings] = await Promise.all([api("/api/cases"), api("/api/settings")]);
  state.cases = cases.cases;
  state.settings = settings;
  state.taxonomyVersion = settings.taxonomyVersion || "";
  state.uploadLimitMb = settings.uploadLimitMb || 50;
  if (state.view === "case" && state.caseId) await loadCase(state.caseId, false);
  render();
}

function activeCases() {
  return state.cases.filter((item) => !["complete", "archived"].includes(item.status));
}
function pendingReview() {
  return state.cases.filter((item) => item.status === "review" && item.reviewState !== "approved").length;
}

function navigation() {
  const nav = [
    { id: "dashboard", label: "Overview", icon: "grid" },
    { id: "cases", label: "Cases", icon: "folder", count: state.cases.length },
    { id: "mappings", label: "ATT&CK review", icon: "shield", count: pendingReview() },
    { id: "indicators", label: "Indicators", icon: "search" },
    { id: "reports", label: "Reports", icon: "report" }
  ];
  if (state.user.role === "administrator") nav.push({ id: "settings", label: "Administration", icon: "settings" });
  return nav.map((item) => `<button class="nav-item ${state.view === item.id ? "active" : ""}" data-view="${item.id}">${ico(item.icon)}<span>${item.label}</span>${item.count ? `<span class="nav-count">${item.count}</span>` : ""}</button>`).join("");
}

function shell(content) {
  const labels = { dashboard: "Overview", cases: "Cases", mappings: "ATT&CK review", indicators: "Indicators", reports: "Reports", settings: "Administration", case: state.detail?.case.title || "Case workspace" };
  const taxonomyLabel = state.taxonomyVersion
    ? (/^ATT&CK\b/i.test(state.taxonomyVersion) ? state.taxonomyVersion : `ATT&CK ${state.taxonomyVersion}`)
    : "Taxonomy not synced";
  app.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="sidebar-brand"><div class="brand-mark">D</div><div><div class="brand-name">DroidTTP</div><div class="brand-caption">Analyst workspace</div></div></div>
        <div class="nav-label">Workspace</div><nav class="nav-list" aria-label="Main navigation">${navigation()}</nav>
        <div class="sidebar-bottom">
          <div class="sidebar-status"><span class="status-dot"></span> Local instance <span class="mono" style="margin-left:auto;color:#83919e">PRIVATE</span></div>
          <div class="user-card"><div class="avatar">${esc((state.user.name || "A").split(/\s+/).map((part) => part[0]).slice(0, 2).join("").toUpperCase())}</div><div class="user-meta"><strong>${esc(state.user.name)}</strong><span>${esc(state.user.role)}</span></div><button class="logout-button" data-action="logout" aria-label="Sign out" title="Sign out">${ico("logout")}</button></div>
        </div>
      </aside>
      <section class="workspace">
        <header class="topbar"><div class="breadcrumbs"><span>DroidTTP</span><span aria-hidden="true">/</span><strong>${esc(labels[state.view] || "Workspace")}</strong></div>
          <div class="topbar-tools"><label class="search-wrap">${ico("search")}<input type="search" id="global-search" placeholder="Search indicators, hashes…" aria-label="Search cases and indicators"></label><span class="topbar-divider"></span><div class="taxonomy-indicator"><span class="status-dot"></span>${esc(taxonomyLabel)}</div></div>
        </header>
        <main class="content" id="main-content">${content}</main>
      </section>
    </div>
    <div id="modal-root"></div><div class="toast-region" aria-live="polite"></div>`;
  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => navigate(button.dataset.view)));
  document.querySelector("#global-search").addEventListener("input", (event) => {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(() => {
      state.indicatorQuery = event.target.value;
      if (event.target.value.trim().length >= 2) {
        state.view = "indicators";
        loadIndicators(event.target.value.trim()).then(() => render()).catch((error) => toast(error.message, true));
      }
    }, 350);
  });
}

function navigate(view) {
  state.view = view;
  state.caseId = null;
  state.detail = null;
  if (view === "indicators") state.indicatorQuery = "";
  if (view === "mappings") {
    render();
    loadMappingCases();
    return;
  }
  if (view === "settings") {
    render();
    loadAdminData();
    return;
  }
  render();
}

function statusBadge(status) {
  return `<span class="status-badge ${esc(String(status).toLowerCase())}">${esc(pretty(status))}</span>`;
}

function pageHeading(eyebrow, title, description, actions = "") {
  return `<div class="page-heading"><div><span class="eyebrow">${esc(eyebrow)}</span><h1>${esc(title)}</h1><p>${esc(description)}</p></div>${actions ? `<div class="heading-actions">${actions}</div>` : ""}</div>`;
}

function renderDashboard() {
  const openCount = state.cases.filter((item) => !["complete", "archived", "failed"].includes(item.status)).length;
  const awaiting = pendingReview();
  const latest = [...state.cases].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 5);
  const newCase = `<button class="button button-primary" data-action="new-case">${ico("plus")} New case</button>`;
  const casesMarkup = latest.length ? `<div class="case-list">${latest.map((item) => caseRow(item)).join("")}</div>` :
    `<div class="empty-state"><div class="empty-icon">${ico("folder")}</div><h3>No investigations yet</h3><p>Create a case to record provenance, add an APK, and start a static analysis run.</p><button class="button button-primary button-small" data-action="new-case">${ico("plus")} Create first case</button></div>`;
  return `${pageHeading("Analyst workspace", `Good ${greeting()}, ${state.user.name.split(" ")[0]}`, "A clear view of your Android application investigations and the evidence that supports them.", newCase)}
    <section class="grid metric-grid">
      ${metricCard("Active cases", openCount, "Cases currently in progress", "folder")}
      ${metricCard("Samples analyzed", state.cases.reduce((count, item) => count + (item.analyzedCount || 0), 0), "APK samples across accessible cases", "file")}
      ${metricCard("Awaiting review", awaiting, "Cases ready for analyst review", "clock")}
      ${metricCard("ATT&CK taxonomy", state.taxonomyVersion ? esc(state.taxonomyVersion) : "Not synced", state.taxonomyVersion ? "Version is recorded for new mappings" : "Configure a version before mapping", "shield", true)}
    </section>
    <section class="grid dashboard-grid">
      <div class="panel"><div class="panel-header"><div><h2>Recent investigations</h2><p>Cases you can access</p></div><button class="panel-link" data-view="cases">View all</button></div>${casesMarkup}</div>
      <div class="grid">
        <div class="panel"><div class="panel-header"><div><h2>Analyst shortcuts</h2><p>Common tasks</p></div></div><div class="panel-body"><div class="quick-actions">
          <button class="quick-action" data-action="new-case"><span class="quick-action-icon">${ico("plus")}</span><span><strong>Create an investigation</strong><span>Record context and handling marking.</span></span></button>
          <button class="quick-action" data-view="mappings"><span class="quick-action-icon">${ico("shield")}</span><span><strong>Review technique mappings</strong><span>Inspect evidence-linked ATT&amp;CK decisions.</span></span></button>
          <button class="quick-action" data-view="indicators"><span class="quick-action-icon">${ico("search")}</span><span><strong>Search indicators</strong><span>Query authorized cases and samples.</span></span></button>
        </div></div></div>
        <div class="notice info">${ico("alert")}<span><strong>Evidence before conclusions.</strong> Manifest permissions show potential capability, not proof of behavior. Dynamic execution is never started automatically.</span></div>
      </div>
    </section>`;
}
function greeting() {
  const hour = new Date().getHours();
  return hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening";
}
function metricCard(label, value, note, icon, textValue = false) {
  return `<div class="metric-card"><div class="metric-top"><span>${esc(label)}</span><span class="metric-icon">${ico(icon)}</span></div><div class="metric-number ${textValue ? "" : "mono"}" style="${textValue ? "font-size:19px" : ""}">${value}</div><div class="metric-note">${esc(note)}</div></div>`;
}
function caseRow(item) {
  return `<div class="case-row" tabindex="0" role="button" data-open-case="${item.id}">
    <div class="case-name"><strong>${esc(item.title)}</strong><span>${esc(item.ownerName || "—")} · ${shortDate(item.updatedAt)}</span></div>
    <div class="case-status">${statusBadge(item.status)}</div>
    <div class="case-owner"><span class="row-label">Samples</span><span class="row-subtle">${item.sampleCount || 0} ${item.sampleCount === 1 ? "sample" : "samples"}</span></div>
    <div><span class="row-label">Review</span><span class="row-subtle">${esc(pretty(item.reviewState || "not requested"))}</span></div>
    <span>${ico("arrow")}</span>
  </div>`;
}

function renderCases() {
  return `${pageHeading("Investigation index", "Cases", "Search and manage authorized investigations, APK samples, and review status.", `<button class="button button-primary" data-action="new-case">${ico("plus")} New case</button>`)}
    <div class="toolbar"><div class="filter-row"><input class="input input-search" id="case-search" type="search" placeholder="Filter by title, source or owner"><select class="select" id="case-status-filter" aria-label="Filter by status"><option value="">All statuses</option>${["draft", "analyzing", "review", "complete", "archived", "failed"].map((item) => `<option value="${item}">${pretty(item)}</option>`).join("")}</select></div><span class="row-subtle">${state.cases.length} accessible ${state.cases.length === 1 ? "case" : "cases"}</span></div>
    <div class="table-panel"><div class="table-wrap"><table><thead><tr><th>Investigation</th><th>Status</th><th>Samples</th><th>Owner</th><th>Last updated</th><th>Review state</th></tr></thead><tbody id="cases-body">${state.cases.map((item) => caseTableRow(item)).join("")}</tbody></table></div>${state.cases.length ? "" : `<div class="empty-state"><div class="empty-icon">${ico("folder")}</div><h3>No cases found</h3><p>Create a case to begin a documented analysis.</p></div>`}</div>`;
}
function caseTableRow(item) {
  return `<tr tabindex="0" role="button" data-open-case="${item.id}"><td><span class="cell-primary">${esc(item.title)}</span><span class="cell-secondary">${esc(item.source || "No source recorded")}</span></td><td>${statusBadge(item.status)}</td><td>${item.sampleCount || 0}</td><td>${esc(item.ownerName || "—")}</td><td>${dateLabel(item.updatedAt)}</td><td>${esc(pretty(item.reviewState || "not requested"))}</td></tr>`;
}

function renderCaseWorkspace() {
  const detail = state.detail;
  if (!detail) return `<div class="empty-state"><h3>Loading case…</h3></div>`;
  const c = detail.case;
  const tabs = [
    ["overview", "Overview", detail.samples.length],
    ["evidence", "Evidence", detail.evidence.length],
    ["mappings", "ATT&CK mappings", detail.mappings.length],
    ["runs", "Analysis runs", detail.runs.length],
    ["review", "Review", c.reviewState === "approved" ? "✓" : ""]
  ];
  return `${pageHeading("Case workspace", c.title, c.description || "No investigation context has been recorded.", `<button class="button button-secondary" data-action="case-status">${ico("activity")} Update status</button>`)}
    <section class="case-overview"><div>
      <span class="status-badge ${esc(c.status)}">${esc(pretty(c.status))}</span><h2>${esc(c.title)}</h2><p>${esc(c.description || "No investigation context recorded.")}</p>
      <div class="overview-meta"><span>Owner <strong>${esc(c.ownerName)}</strong></span><span>Source <strong>${esc(c.source || "Not recorded")}</strong></span><span>Handling <strong>${esc(c.handlingMarking)}</strong></span><span>Updated <strong>${dateLabel(c.updatedAt)}</strong></span></div>
    </div><div class="heading-actions"><button class="button button-secondary" data-action="edit-case">${ico("settings")} Edit details</button><button class="button button-primary" data-action="upload-apk">${ico("upload")} Add APK</button></div></section>
    <div class="tab-bar" role="tablist">${tabs.map(([id, label, count]) => `<button class="tab-button ${state.caseTab === id ? "active" : ""}" role="tab" aria-selected="${state.caseTab === id}" data-case-tab="${id}">${label}<span class="tab-count">${count === "" ? "" : count}</span></button>`).join("")}</div>
    ${renderCaseTab(detail)}`;
}

function renderCaseTab(detail) {
  if (state.caseTab === "overview") return renderCaseOverview(detail);
  if (state.caseTab === "evidence") return renderEvidenceTab(detail);
  if (state.caseTab === "mappings") return renderMappingsTab(detail);
  if (state.caseTab === "runs") return renderRunsTab(detail);
  return renderReviewTab(detail);
}

function renderCaseOverview(detail) {
  const samples = detail.samples.length ? detail.samples.map((sample) => sampleCard(sample, detail)).join("") : `<div class="empty-state"><div class="empty-icon">${ico("upload")}</div><h3>No APK samples attached</h3><p>Add an authorized APK to calculate its cryptographic hashes and queue a static analysis.</p><button class="button button-primary button-small" data-action="upload-apk">${ico("upload")} Upload APK</button></div>`;
  const review = detail.case.reviewState === "approved" ? `<div class="notice success">${ico("check")}<span><strong>Review approved.</strong> ${esc(detail.case.reviewNote || "No reviewer note was added.")}</span></div>` :
    detail.case.reviewState === "returned" ? `<div class="notice">${ico("alert")}<span><strong>Returned for changes.</strong> ${esc(detail.case.reviewNote || "No reviewer note was added.")}</span></div>` : "";
  return `<div class="grid" style="gap:13px"><div class="panel"><div class="panel-header"><div><h2>APK samples</h2><p>Files are stored outside the public web root. No sample is executed.</p></div><button class="button button-secondary button-small" data-action="upload-apk">${ico("plus")} Add sample</button></div><div class="panel-body"><div class="grid">${samples}</div></div></div>
    ${review}<div class="notice info">${ico("alert")}<span>Static results are observations or potential capabilities only. The parser does not verify signing certificates, resolve resources, infer malware verdicts, or execute code.</span></div></div>`;
}
function sampleCard(sample, detail) {
  const metadata = [
    ["Package", sample.packageName || "Unavailable"],
    ["App label", sample.appName || "Unavailable"],
    ["Version", sample.versionName || sample.versionCode || "Unavailable"],
    ["Min / target SDK", `${sample.minSdk || "—"} / ${sample.targetSdk || "—"}`]
  ];
  const evidenceCount = detail.evidence.filter((entry) => entry.sampleId === sample.id).length;
  const mappingCount = detail.mappings.filter((entry) => entry.sampleId === sample.id).length;
  return `<article class="sample-card"><div class="sample-header"><div class="sample-title"><h3>${esc(sample.filename)}</h3><p>${formatBytes(sample.fileSize)} · Uploaded ${dateLabel(sample.uploadedAt)}</p></div>${statusBadge(sample.status)}</div>
    <div class="hash-row"><span>SHA-256</span><code>${esc(sample.sha256)}</code><button data-copy="${esc(sample.sha256)}">Copy</button></div>
    <div class="metadata-grid">${metadata.map(([label, value]) => `<div class="metadata-item"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join("")}</div>
    <div class="overview-meta"><span>Uploaded by <strong>${esc(sample.uploadedBy || "—")}</strong></span><span>Evidence <strong>${evidenceCount}</strong></span><span>Mappings <strong>${mappingCount}</strong></span><span>MD5 <strong class="mono">${esc(sample.md5)}</strong></span><span>SHA-1 <strong class="mono">${esc(sample.sha1)}</strong></span></div>
    <div class="mapping-actions"><button class="button button-secondary button-small" data-action="add-evidence" data-sample-id="${sample.id}">${ico("plus")} Add evidence</button><button class="button button-secondary button-small" data-action="add-mapping" data-sample-id="${sample.id}">${ico("shield")} Add mapping</button></div>
  </article>`;
}
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
}

function renderEvidenceTab(detail) {
  const evidence = detail.evidence;
  return `<div class="toolbar"><div><h2 class="section-title">Evidence register</h2><span class="row-subtle">Source and evidence classification are preserved for every item.</span></div><button class="button button-primary button-small" data-action="select-sample-evidence" ${detail.samples.length ? "" : "disabled"}>${ico("plus")} Add analyst note</button></div>
    ${evidence.length ? `<div class="table-panel"><div class="table-wrap"><table><thead><tr><th>Evidence</th><th>Sample</th><th>Classification</th><th>Source / location</th><th>Confidence</th></tr></thead><tbody>${evidence.map((entry) => `<tr><td><span class="cell-primary">${esc(pretty(entry.type))}</span><span class="evidence-value">${esc(defang(entry.value))}</span>${entry.details ? `<span class="evidence-details">${esc(entry.details)}</span>` : ""}</td><td>${esc(detail.samples.find((sample) => sample.id === entry.sampleId)?.filename || "—")}</td><td><span class="tag classification ${esc(entry.classification)}">${esc(pretty(entry.classification))}</span></td><td><span class="cell-primary">${esc(pretty(entry.source))}</span><span class="cell-secondary">${esc(entry.location || "No location")}</span></td><td><span class="tag confidence">${esc(pretty(entry.confidence))}</span></td></tr>`).join("")}</tbody></table></div></div>` : `<div class="panel"><div class="empty-state"><div class="empty-icon">${ico("file")}</div><h3>No evidence yet</h3><p>Upload an APK for static findings or add a clearly labeled analyst note.</p></div></div>`}`;
}
function defang(value) {
  return String(value || "").replace(/https?:\/\//gi, (match) => match.replace("://", "[:]//")).replace(/([a-z0-9])\.([a-z]{2,})/gi, "$1[.]$2");
}

function renderMappingsTab(detail) {
  const mappings = detail.mappings;
  return `<div class="toolbar"><div><h2 class="section-title">Technique mappings</h2><span class="row-subtle">No mappings are auto-confirmed. Link evidence and record an analyst rationale.</span></div><button class="button button-primary button-small" data-action="select-sample-mapping" ${detail.samples.length && state.taxonomyVersion ? "" : "disabled"}>${ico("plus")} Add mapping</button></div>
    ${!state.taxonomyVersion ? `<div class="notice" style="margin-bottom:13px">${ico("alert")}<span>An administrator must configure an ATT&amp;CK taxonomy version before a mapping can be recorded.</span></div>` : ""}
    ${mappings.length ? mappings.map((mapping) => mappingCard(mapping, detail)).join("") : `<div class="panel"><div class="empty-state"><div class="empty-icon">${ico("shield")}</div><h3>No ATT&amp;CK mappings</h3><p>Add a candidate technique, record its rationale, and attach supporting or contradicting evidence.</p></div></div>`}`;
}
function mappingCard(mapping, detail) {
  const linked = mapping.evidenceIds.map((id) => detail.evidence.find((item) => item.id === id)).filter(Boolean);
  const canReview = state.user.role === "administrator" || state.user.role === "reviewer" || detail.case.createdBy === state.user.id;
  return `<article class="mapping-card"><div class="mapping-header"><div><span class="technique-code">${esc(mapping.techniqueId)}</span><h3>${esc(mapping.techniqueName)}</h3><span class="cell-secondary">${esc(mapping.tactic || "Tactic not specified")}</span></div>${statusBadge(mapping.status)}</div>
    <p>${esc(mapping.rationale || "No rationale recorded.")}</p><div class="mapping-meta"><span class="tag">${esc(mapping.taxonomyVersion)}</span><span class="tag confidence">${esc(pretty(mapping.confidence))} confidence</span><span class="tag">${linked.length} linked ${linked.length === 1 ? "item" : "items"}</span></div>
    ${linked.length ? `<div class="mapping-meta">${linked.map((item) => `<span class="tag">${esc(pretty(item.type))}: ${esc(defang(item.value).slice(0, 90))}</span>`).join("")}</div>` : ""}
    <div class="mapping-actions">${canReview ? `<button class="button button-secondary button-small" data-action="edit-mapping" data-mapping-id="${mapping.id}">Edit / review</button>` : ""}<span class="row-subtle">Updated ${dateLabel(mapping.reviewedAt || mapping.createdAt)}</span></div>
    ${mapping.history.length > 1 ? `<details style="margin-top:11px"><summary class="link-button">Review history (${mapping.history.length})</summary><div style="display:grid;gap:6px;margin-top:8px">${mapping.history.map((item) => `<div class="review-block"><strong>${esc(pretty(item.status))} · ${esc(item.userName)}</strong><p>${dateLabel(item.occurredAt)}${item.rationale ? ` — ${esc(item.rationale)}` : ""}</p></div>`).join("")}</div></details>` : ""}
  </article>`;
}

function renderRunsTab(detail) {
  return `<div class="toolbar"><div><h2 class="section-title">Analysis provenance</h2><span class="row-subtle">Each run records its mode, tool, completion state, and known limitations.</span></div>${state.settings?.dynamicProvider ? `<button class="button button-secondary button-small" data-action="import-observations">${ico("download")} Import observations</button>` : ""}</div>
    ${detail.runs.length ? `<div class="table-panel"><div class="table-wrap"><table><thead><tr><th>Sample</th><th>Mode</th><th>Tool</th><th>Status</th><th>Started</th><th>Limitations / errors</th></tr></thead><tbody>${detail.runs.map((run) => `<tr><td>${esc(detail.samples.find((sample) => sample.id === run.sampleId)?.filename || "—")}</td><td>${esc(pretty(run.mode))}</td><td><span class="cell-primary">${esc(run.toolName)}</span><span class="cell-secondary">v${esc(run.toolVersion)}</span></td><td>${statusBadge(run.status)}</td><td>${dateLabel(run.startedAt)}</td><td>${esc(run.errorSummary || run.limitations.join(" ") || "No known limitations reported.")}</td></tr>`).join("")}</tbody></table></div></div>` : `<div class="panel"><div class="empty-state"><div class="empty-icon">${ico("activity")}</div><h3>No analysis runs</h3><p>Upload an APK to queue a static scan in an isolated worker.</p></div></div>`}
    ${state.settings?.dynamicProvider ? `<div class="notice info" style="margin-top:13px">${ico("alert")}<span>Configured import source: <strong>${esc(state.settings.dynamicProvider)}</strong>. DroidTTP does not execute APKs or connect to a sandbox; imported observations must be supplied by an authorized external analysis process.</span></div>` : `<div class="notice" style="margin-top:13px">${ico("alert")}<span>Dynamic analysis is unavailable. This deployment has no configured isolation provider and does not execute APKs.</span></div>`}`;
}

function renderReviewTab(detail) {
  const canReview = ["administrator", "reviewer"].includes(state.user.role);
  const stateLabel = detail.case.reviewState || "not requested";
  return `<div class="grid" style="gap:13px"><div class="panel"><div class="panel-header"><div><h2>Peer review</h2><p>Reviewer decisions do not alter original analysis provenance.</p></div>${statusBadge(stateLabel)}</div><div class="panel-body">
      ${detail.case.reviewNote ? `<div class="review-block"><strong>Latest reviewer note</strong><p>${esc(detail.case.reviewNote)}</p></div>` : `<p class="row-subtle">No review note has been recorded.</p>`}
      ${canReview ? `<div class="mapping-actions"><button class="button button-primary button-small" data-action="review-case" data-review-state="approved">${ico("check")} Approve analysis</button><button class="button button-secondary button-small" data-action="review-case" data-review-state="returned">Return for changes</button></div>` : `<p class="field-hint" style="margin-top:12px">Only a reviewer or administrator can approve or return this analysis.</p>`}
    </div></div><div class="panel"><div class="panel-header"><div><h2>Case audit trail</h2><p>Recent access, uploads, edits, and decisions</p></div></div><div class="panel-body">${detail.audit.length ? `<div class="activity-list">${detail.audit.slice(0, 12).map((event) => `<div class="activity-item"><div class="activity-line"><span class="activity-dot"></span></div><div class="activity-text"><strong>${esc(pretty(event.action))}</strong> · ${esc(event.userName)}<span>${dateLabel(event.occurredAt)}</span></div></div>`).join("")}</div>` : `<p class="row-subtle">No audit events.</p>`}</div></div></div>`;
}

function renderMappings() {
  return `${pageHeading("Review queue", "ATT&CK mapping review", "Review technique candidates with linked evidence, analyst rationale, and a traceable decision history.", `<button class="button button-secondary" data-view="cases">${ico("folder")} Browse cases</button>`)}
    <div class="notice info" style="margin-bottom:14px">${ico("alert")}<span>DroidTTP does not infer mappings or treat permissions as behavior. Analysts create candidate mappings against a configured taxonomy version; every decision remains editable and auditable.</span></div>
    <div id="mapping-queue"><div class="panel"><div class="empty-state"><div class="empty-icon">${ico("clock")}</div><h3>Loading review queue</h3><p>Gathering technique decisions from accessible cases.</p></div></div></div>`;
}
function renderIndicators() {
  return `${pageHeading("Authorized case search", "Indicators", "Search extracted evidence across cases you are permitted to access. Values are defanged and never opened automatically.")}
    <div class="toolbar"><div class="filter-row"><input class="input input-search" id="indicator-search" type="search" value="${esc(state.indicatorQuery || "")}" placeholder="Hash, package, domain, URL, IP or evidence…" autofocus></div><span class="row-subtle">Search is local to this instance.</span></div>
    <div class="table-panel" id="indicator-results">${state.indicators.length ? indicatorsTable(state.indicators) : `<div class="empty-state"><div class="empty-icon">${ico("search")}</div><h3>${state.indicatorQuery ? "No matching indicators" : "Search your case evidence"}</h3><p>Enter at least two characters to find matching evidence, filenames, package names, or hashes.</p></div>`}</div>`;
}
function indicatorsTable(items) {
  return `<div class="table-wrap"><table><thead><tr><th>Indicator / evidence</th><th>Type</th><th>Classification</th><th>Sample / case</th><th>Confidence</th></tr></thead><tbody>${items.map((item) => `<tr><td><span class="mono-cell">${esc(defang(item.value))}</span>${item.location ? `<span class="cell-secondary">${esc(item.location)}</span>` : ""}</td><td>${esc(pretty(item.type))}</td><td><span class="tag classification ${esc(item.classification)}">${esc(pretty(item.classification))}</span></td><td><button class="link-button" data-open-case="${item.caseId}">${esc(item.caseTitle)}</button><span class="cell-secondary">${esc(item.filename)}</span></td><td><span class="tag confidence">${esc(pretty(item.confidence))}</span></td></tr>`).join("")}</tbody></table></div>`;
}

function renderReports() {
  return `${pageHeading("Export and provenance", "Reports", "Generate a print-ready HTML report or structured JSON export for a case.", `<button class="button button-secondary" data-view="cases">${ico("folder")} View cases</button>`)}
    ${state.cases.length ? `<div class="settings-card" style="max-width:700px"><h2>Select a case</h2><p>Reports distinguish extracted observations, potential capabilities, analyst conclusions, and mapping review status.</p>
      <div class="field"><label for="report-case-select">Investigation</label><select class="select" id="report-case-select"><option value="">Choose a case…</option>${state.cases.map((item) => `<option value="${item.id}">${esc(item.title)} · ${pretty(item.status)}</option>`).join("")}</select></div>
      <div id="report-preview" style="margin-top:15px"></div></div>` : `<div class="panel"><div class="empty-state"><div class="empty-icon">${ico("report")}</div><h3>No cases to report</h3><p>Create a case and record sample evidence before exporting a report.</p><button class="button button-primary button-small" data-action="new-case">${ico("plus")} Create case</button></div></div>`}`;
}

function renderSettings() {
  const isAdmin = state.user.role === "administrator";
  return `${pageHeading("Workspace configuration", "Administration", "Manage access, taxonomy provenance, import labels, and audit history. All processing remains local to this deployment.")}
    ${!isAdmin ? `<div class="notice info" style="margin-bottom:14px">${ico("alert")}<span>Read-only settings are shown below. An administrator is required to change system configuration or manage accounts.</span></div>` : ""}
    <div class="settings-layout">
      <section class="settings-card"><h2>Analysis and provenance</h2><p>Static analysis runs asynchronously in a worker. Dynamic execution is not installed in this application.</p>
        ${isAdmin ? `<form id="settings-form" class="grid" style="gap:13px"><div class="field"><label for="taxonomy-version">ATT&amp;CK taxonomy version</label><input id="taxonomy-version" name="taxonomyVersion" class="input" value="${esc(state.settings?.taxonomyVersion || "")}" placeholder="e.g. ATT&amp;CK Mobile vX.Y"><span class="field-hint">Record the exact local taxonomy release used for new mappings. No taxonomy feed is fetched automatically.</span></div>
          <div class="field"><label for="dynamic-provider">Verified observation import source (optional)</label><input id="dynamic-provider" name="dynamicProvider" class="input" value="${esc(state.settings?.dynamicProvider || "")}" placeholder="Name of approved isolated sandbox"><span class="field-hint">Enables importing externally generated observations only. DroidTTP does not submit or execute APKs.</span></div>
          <label class="checkbox-row"><input type="checkbox" name="dynamicVerified" ${state.settings?.dynamicVerified ? "checked" : ""}><span>I have verified that the named environment is isolated, disposable, and follows our approved egress policy.</span></label>
          <button class="button button-primary" type="submit">Save configuration</button></form>` :
          `<div class="setting-row"><div><strong>ATT&amp;CK taxonomy version</strong><span>${esc(state.settings?.taxonomyVersion || "Not configured")}</span></div><span class="role-chip">Read only</span></div>
           <div class="setting-row"><div><strong>Observation import source</strong><span>${esc(state.settings?.dynamicProvider || "Not configured")}</span></div><span class="role-chip">Read only</span></div>`}
        <div class="setting-row"><div><strong>Maximum APK upload size</strong><span>Files above the configured limit are rejected. Current server limit: ${state.uploadLimitMb} MB.</span></div><span class="role-chip">Local config</span></div>
        <div class="setting-row"><div><strong>Sample storage</strong><span>Private local directory, outside the public web root. Uploads are never served back as executable content.</span></div><span class="role-chip">Private</span></div>
      </section>
      <div class="grid" style="gap:14px">
        <section class="settings-card"><h2>Access and accounts</h2><p>Local password accounts use scrypt hashes. Sessions are HTTP-only, same-site, and expire after eight hours.</p>
          ${isAdmin ? `<div class="heading-actions" style="margin-bottom:12px"><button class="button button-secondary button-small" data-action="new-user">${ico("user")} Add account</button></div><div id="user-list"><span class="row-subtle">Loading accounts…</span></div>` : `<div class="setting-row"><div><strong>Your role</strong><span>${esc(state.user.role)}</span></div><span class="role-chip">${esc(state.user.role)}</span></div>`}
        </section>
        ${isAdmin ? `<section class="settings-card"><h2>Recent audit events</h2><p>Access, exports, review decisions, and settings changes.</p><div id="audit-list"><span class="row-subtle">Loading audit history…</span></div></section>` : ""}
      </div>
    </div>`;
}

function render() {
  if (!state.user) return;
  if (state.view === "dashboard") return shell(renderDashboard());
  if (state.view === "cases") return shell(renderCases());
  if (state.view === "case") return shell(renderCaseWorkspace());
  if (state.view === "mappings") return shell(renderMappings());
  if (state.view === "indicators") return shell(renderIndicators());
  if (state.view === "reports") return shell(renderReports());
  if (state.view === "settings") return shell(renderSettings());
  state.view = "dashboard";
  render();
}

async function loadCase(id, redraw = true) {
  const detail = await api(`/api/cases/${id}${redraw ? "" : "?poll=1"}`);
  state.detail = detail;
  state.caseId = Number(id);
  if (redraw) render();
}
async function openCase(id) {
  state.view = "case";
  state.caseId = Number(id);
  state.caseTab = "overview";
  state.detail = null;
  render();
  try {
    await loadCase(id);
  } catch (error) {
    toast(error.message, true);
    navigate("cases");
  }
}
async function refreshCases() {
  state.cases = (await api("/api/cases")).cases;
}
async function loadIndicators(query) {
  state.indicatorQuery = query;
  state.indicators = (await api(`/api/indicators?q=${encodeURIComponent(query)}`)).indicators;
}
async function loadMappingCases() {
  const container = document.querySelector("#mapping-queue");
  if (!container) return;
  try {
    const details = await Promise.all(state.cases.map((item) => api(`/api/cases/${item.id}`)));
    if (!document.querySelector("#mapping-queue")) return;
    const mappings = details.flatMap((detail) => detail.mappings.map((mapping) => ({ ...mapping, caseTitle: detail.case.title, sampleName: detail.samples.find((sample) => sample.id === mapping.sampleId)?.filename || "Unknown sample", caseId: detail.case.id })));
    const items = mappings.filter((item) => item.status === "suggested" || item.status === "needs_review");
    container.innerHTML = items.length ? `<div class="grid" style="gap:10px">${items.map((item) => `<div class="mapping-card"><div class="mapping-header"><div><span class="technique-code">${esc(item.techniqueId)}</span><h3>${esc(item.techniqueName)}</h3><span class="cell-secondary">${esc(item.caseTitle)} · ${esc(item.sampleName)}</span></div>${statusBadge(item.status)}</div><p>${esc(item.rationale || "No rationale recorded.")}</p><div class="mapping-actions"><button class="button button-secondary button-small" data-open-case="${item.caseId}" data-open-tab="mappings">Open mapping</button></div></div>`).join("")}</div>` : `<div class="panel"><div class="empty-state"><div class="empty-icon">${ico("check")}</div><h3>No pending technique decisions</h3><p>Create a candidate mapping from a case to begin an evidence-linked review. Confirmed and rejected decisions remain visible in that case.</p><button class="button button-secondary button-small" data-view="cases">Browse cases</button></div></div>`;
  } catch (error) {
    container.innerHTML = `<div class="notice">${ico("alert")}<span>${esc(error.message)}</span></div>`;
  }
}

function openModal({ title, description = "", body, submitLabel = "Save", onSubmit, wide = false, hideSubmit = false }) {
  const root = document.querySelector("#modal-root");
  root.innerHTML = `<div class="modal-backdrop" role="presentation"><section class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <header class="modal-header"><div><h2 id="modal-title">${esc(title)}</h2>${description ? `<p>${esc(description)}</p>` : ""}</div><button class="modal-close" type="button" data-action="close-modal" aria-label="Close dialog">${ico("close")}</button></header>
    <form id="modal-form"><div class="modal-body">${body}</div>${hideSubmit ? "" : `<footer class="modal-footer"><button class="button button-secondary" type="button" data-action="close-modal">Cancel</button><button class="button button-primary" type="submit">${esc(submitLabel)}</button></footer>`}</form>
  </section></div>`;
  root.querySelector(".modal-backdrop").addEventListener("click", (event) => { if (event.target.classList.contains("modal-backdrop")) closeModal(); });
  root.querySelectorAll('[data-action="close-modal"]').forEach((button) => button.addEventListener("click", closeModal));
  const first = root.querySelector("input,select,textarea,button");
  first?.focus();
  if (!hideSubmit) root.querySelector("#modal-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.currentTarget.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      await onSubmit(new FormData(event.currentTarget), event.currentTarget);
    } catch (error) {
      toast(error.message, true);
      submit.disabled = false;
    }
  });
}
function closeModal() {
  const root = document.querySelector("#modal-root");
  if (root) root.innerHTML = "";
}

function newCaseModal(existing = null) {
  const isEdit = Boolean(existing);
  openModal({
    title: isEdit ? "Edit investigation details" : "Create an investigation",
    description: "Capture source and handling context before adding samples.",
    body: `<div class="form-grid"><div class="field span-2"><label for="case-title">Case title *</label><input class="input" id="case-title" name="title" required maxlength="180" value="${esc(existing?.title || "")}" placeholder="e.g. Mobile app review — 2026-014"></div>
      <div class="field span-2"><label for="case-description">Investigation context</label><textarea class="textarea" id="case-description" name="description" maxlength="5000" placeholder="Scope, question, and relevant context">${esc(existing?.description || "")}</textarea></div>
      <div class="field"><label for="case-source">Source / acquisition context</label><input class="input" id="case-source" name="source" maxlength="500" value="${esc(existing?.source || "")}" placeholder="How was the APK obtained?"></div>
      <div class="field"><label for="case-marking">Handling marking</label><select class="select" id="case-marking" name="handlingMarking">${["internal", "confidential", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"].map((value) => `<option ${existing?.handlingMarking === value ? "selected" : ""}>${esc(value)}</option>`).join("")}</select></div></div>`,
    submitLabel: isEdit ? "Save changes" : "Create case",
    onSubmit: async (form) => {
      const values = Object.fromEntries(form.entries());
      if (isEdit) {
        await api(`/api/cases/${state.caseId}`, { method: "PATCH", body: JSON.stringify(values) });
        await refreshCases();
        await loadCase(state.caseId);
        toast("Case details updated.");
      } else {
        const created = await api("/api/cases", { method: "POST", body: JSON.stringify(values) });
        closeModal();
        await refreshCases();
        state.view = "case";
        await openCase(created.case.id);
        toast("Investigation created.");
      }
      closeModal();
    }
  });
}

function uploadModal() {
  openModal({
    title: "Add APK sample",
    description: `APK files are stored privately and scanned asynchronously. Maximum upload size: ${state.uploadLimitMb} MB.`,
    body: `<div class="grid" style="gap:13px"><label class="drop-zone" id="apk-drop-zone"><input id="apk-file" type="file" accept=".apk,application/vnd.android.package-archive" required><span>${ico("upload")}</span><strong>Choose an APK to upload</strong><span>APK only · no automatic execution</span></label><div id="upload-selected" class="field-hint">No file selected.</div><div class="notice info">${ico("alert")}<span>Analysis computes SHA-256, MD5, and SHA-1, and inspects manifest metadata and selected DEX strings. It does not determine whether an app is malicious.</span></div></div>`,
    submitLabel: "Upload and analyze",
    onSubmit: async (_form, form) => {
      const input = form.querySelector("#apk-file");
      const file = input.files[0];
      if (!file) throw new Error("Choose an APK file first.");
      if (!file.name.toLowerCase().endsWith(".apk")) throw new Error("Only .apk files are accepted.");
      if (file.size > state.uploadLimitMb * 1024 * 1024) throw new Error(`The selected file exceeds the ${state.uploadLimitMb} MB limit.`);
      const fileBytes = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", fileBytes);
      const sha256 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      const duplicates = (await api(`/api/duplicates?sha256=${sha256}`)).samples;
      if (duplicates.length) {
        const match = duplicates[0];
        const reuse = window.confirm(`This APK matches ${duplicates.length} accessible existing sample(s).\n\n${match.filename}\nCase: ${match.caseTitle}\n\nOpen the existing sample and continue its analysis instead of uploading another copy?`);
        if (reuse) {
          closeModal();
          await openCase(match.caseId);
          toast("Opened the accessible existing sample. Your current case is unchanged.");
          return;
        }
      }
      const button = form.querySelector('button[type="submit"]');
      button.textContent = "Uploading…";
      const result = await api(`/api/cases/${state.caseId}/samples`, { method: "POST", headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(file.name) }, body: fileBytes });
      closeModal();
      await refreshCases();
      await loadCase(state.caseId);
      toast(`Upload received. SHA-256: ${result.sample.sha256.slice(0, 16)}… Static analysis is running.`);
      if (result.duplicates?.length) toast(`Duplicate content hash found in ${result.duplicates.length} accessible sample(s).`);
      pollAnalysis(state.caseId);
    }
  });
  const input = document.querySelector("#apk-file");
  input.addEventListener("change", () => {
    const file = input.files[0];
    document.querySelector("#upload-selected").textContent = file ? `${file.name} · ${formatBytes(file.size)}` : "No file selected.";
  });
  const dropZone = document.querySelector("#apk-drop-zone");
  dropZone.addEventListener("dragover", (event) => { event.preventDefault(); dropZone.classList.add("dragging"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));
  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
    if (event.dataTransfer.files[0]) {
      const transfer = new DataTransfer();
      transfer.items.add(event.dataTransfer.files[0]);
      input.files = transfer.files;
      input.dispatchEvent(new Event("change"));
    }
  });
}
function pollAnalysis(caseId) {
  let attempts = 0;
  const timer = setInterval(async () => {
    attempts += 1;
    if (state.view !== "case" || state.caseId !== caseId || attempts > 30) return clearInterval(timer);
    try {
      await loadCase(caseId, false);
      const running = state.detail.runs.some((run) => ["running", "queued"].includes(run.status));
      if (!running) {
        clearInterval(timer);
        await refreshCases();
        render();
        toast("Static analysis finished. Review the evidence and limitations.");
      } else if (state.detail) render();
    } catch { clearInterval(timer); }
  }, 2000);
}

function addEvidenceModal(sampleId) {
  openModal({
    title: "Add analyst evidence",
    description: "Analyst-entered material is labeled separately from tool output.",
    body: `<div class="form-grid"><div class="field"><label for="evidence-type">Evidence type *</label><input class="input" id="evidence-type" name="type" required maxlength="80" placeholder="e.g. analyst note"></div>
      <div class="field"><label for="evidence-classification">Classification</label><select class="select" id="evidence-classification" name="classification"><option value="analyst">Analyst conclusion</option><option value="observation">Direct observation</option><option value="inference">Inference</option><option value="capability">Potential capability</option></select></div>
      <div class="field span-2"><label for="evidence-value">Finding / value *</label><textarea class="textarea" id="evidence-value" name="value" required maxlength="3000" placeholder="Record the finding or observation"></textarea></div>
      <div class="field"><label for="evidence-location">Source location</label><input class="input" id="evidence-location" name="location" maxlength="500" placeholder="File, class, method, or report page"></div>
      <div class="field"><label for="evidence-confidence">Observation confidence</label><select class="select" id="evidence-confidence" name="confidence"><option>low</option><option selected>moderate</option><option>high</option></select></div>
      <div class="field span-2"><label for="evidence-details">Context and limitations</label><textarea class="textarea" id="evidence-details" name="details" maxlength="3000" placeholder="What supports this finding? What remains uncertain?"></textarea></div></div>`,
    submitLabel: "Add evidence",
    onSubmit: async (form) => {
      await api(`/api/samples/${sampleId}/evidence`, { method: "POST", body: JSON.stringify(Object.fromEntries(form.entries())) });
      closeModal();
      await refreshCases();
      await loadCase(state.caseId);
      state.caseTab = "evidence";
      render();
      toast("Analyst evidence added.");
    }
  });
}

function addMappingModal(sampleId, existing = null) {
  if (!state.taxonomyVersion && !existing) return toast("Configure an ATT&CK taxonomy version in Administration before creating a mapping.", true);
  const current = existing || {};
  const evidence = state.detail.evidence.filter((item) => item.sampleId === sampleId);
  openModal({
    title: existing ? "Edit technique mapping" : "Add ATT&CK mapping",
    description: "A mapping is an analyst decision. Link relevant evidence and explain any uncertainty.",
    wide: true,
    submitLabel: existing ? "Save review decision" : "Save candidate mapping",
    body: `<div class="form-grid"><div class="field"><label for="mapping-id">Technique ID *</label><input class="input mono" id="mapping-id" name="techniqueId" required maxlength="40" pattern="T[0-9]{4}(\\.[0-9]{3})?" placeholder="T1430" value="${esc(current.techniqueId || "")}"></div>
      <div class="field"><label for="mapping-name">Technique name *</label><input class="input" id="mapping-name" name="techniqueName" required maxlength="180" value="${esc(current.techniqueName || "")}" placeholder="Use the name from your ATT&amp;CK release"></div>
      <div class="field"><label for="mapping-tactic">Tactic (optional)</label><input class="input" id="mapping-tactic" name="tactic" maxlength="120" value="${esc(current.tactic || "")}"></div>
      <div class="field"><label for="mapping-taxonomy">Taxonomy version *</label><input class="input" id="mapping-taxonomy" name="taxonomyVersion" required maxlength="80" value="${esc(current.taxonomyVersion || state.taxonomyVersion)}"></div>
      <div class="field"><label for="mapping-status">Review status</label><select class="select" id="mapping-status" name="status">${["suggested", "needs_review", "confirmed", "rejected"].map((value) => `<option value="${value}" ${current.status === value ? "selected" : ""}>${pretty(value)}</option>`).join("")}</select></div>
      <div class="field"><label for="mapping-confidence">Mapping confidence</label><select class="select" id="mapping-confidence" name="confidence">${["low", "moderate", "high"].map((value) => `<option value="${value}" ${current.confidence === value ? "selected" : ""}>${pretty(value)}</option>`).join("")}</select></div>
      <div class="field span-2"><label for="mapping-rationale">Analyst rationale</label><textarea class="textarea" id="mapping-rationale" name="rationale" maxlength="3000" placeholder="Explain how the evidence supports or contradicts this technique. Distinguish observed behavior from capability.">${esc(current.rationale || "")}</textarea></div>
      <div class="field span-2"><label>Linked supporting evidence</label>${evidence.length ? `<div class="evidence-picker">${evidence.map((item) => `<label class="checkbox-row"><input type="checkbox" name="evidenceIds" value="${item.id}" ${current.evidenceIds?.includes(item.id) ? "checked" : ""}><span><strong>${esc(pretty(item.type))}</strong> · ${esc(defang(item.value).slice(0, 180))} <span class="cell-secondary">${esc(pretty(item.classification))} · ${esc(item.location || "No location")}</span></span></label>`).join("")}</div>` : `<span class="field-hint">No evidence is available for this sample yet. A mapping can still be recorded with a rationale.</span>`}</div></div>
      ${existing ? `<div class="notice info" style="margin-top:13px">${ico("activity")}<span>Every save appends a review-history entry. Changing a mapping does not alter source evidence.</span></div>` : ""}`,
    onSubmit: async (form) => {
      const values = Object.fromEntries(form.entries());
      values.evidenceIds = form.getAll("evidenceIds").map(Number);
      const url = existing ? `/api/mappings/${existing.id}` : `/api/samples/${sampleId}/mappings`;
      await api(url, { method: existing ? "PATCH" : "POST", body: JSON.stringify(values) });
      closeModal();
      await refreshCases();
      await loadCase(state.caseId);
      state.caseTab = "mappings";
      render();
      toast(existing ? "Mapping review decision saved." : "ATT&CK mapping recorded.");
    }
  });
}

function importObservationsModal() {
  if (!state.settings?.dynamicProvider) return toast("An administrator must configure a verified source before importing observations.", true);
  const samples = state.detail.samples;
  if (!samples.length) return toast("Add a sample before importing its observations.", true);
  openModal({
    title: "Import external observations",
    description: `Source: ${state.settings.dynamicProvider}. This imports supplied records only; DroidTTP does not submit or execute an APK.`,
    wide: true,
    submitLabel: "Import observations",
    body: `<div class="grid" style="gap:13px"><div class="field"><label for="import-sample">Associated APK sample</label><select class="select" id="import-sample" name="sampleId">${samples.map((sample) => `<option value="${sample.id}">${esc(sample.filename)}</option>`).join("")}</select></div>
      <div class="field"><label for="observations-json">Observations JSON *</label><textarea class="textarea mono" id="observations-json" name="observations" required style="min-height:180px" placeholder='[{"type":"network event","value":"example.test","location":"event 14","confidence":"moderate"}]'></textarea><span class="field-hint">Each item requires type and value. Optional fields: location, confidence, details. Limit: 500 items.</span></div></div>`,
    onSubmit: async (form) => {
      let observations;
      try {
        observations = JSON.parse(form.get("observations"));
      } catch {
        throw new Error("Observations must be valid JSON.");
      }
      if (!Array.isArray(observations)) throw new Error("Provide a JSON array of observations.");
      const sampleId = Number(form.get("sampleId"));
      const result = await api(`/api/cases/${state.caseId}/import-observations`, { method: "POST", body: JSON.stringify({ sampleId, observations }) });
      closeModal();
      await loadCase(state.caseId);
      state.caseTab = "evidence";
      render();
      toast(`${result.count} imported observation(s) added with source provenance.`);
    }
  });
}

function reviewCaseModal(reviewState) {
  const approve = reviewState === "approved";
  openModal({
    title: approve ? "Approve analysis" : "Return for changes",
    description: approve ? "Record your reviewer decision and optional note." : "Explain what should be clarified or corrected.",
    submitLabel: approve ? "Approve case" : "Return to analyst",
    body: `<div class="field"><label for="review-note">Reviewer note ${approve ? "(optional)" : "*"}</label><textarea class="textarea" id="review-note" name="note" maxlength="3000" ${approve ? "" : "required"} placeholder="Summarize review scope, limitations, or requested updates">${esc(state.detail.case.reviewNote || "")}</textarea></div>`,
    onSubmit: async (form) => {
      await api(`/api/cases/${state.caseId}/review`, { method: "POST", body: JSON.stringify({ state: reviewState, note: form.get("note") }) });
      closeModal();
      await refreshCases();
      await loadCase(state.caseId);
      state.caseTab = "review";
      render();
      toast(approve ? "Case review approved." : "Case returned for changes.");
    }
  });
}

function caseStatusModal() {
  const statuses = ["draft", "analyzing", "review", "complete", "archived", "failed"];
  openModal({
    title: "Update case status",
    description: "Status changes are recorded in the audit history.",
    submitLabel: "Update status",
    body: `<div class="field"><label for="case-status">Status</label><select class="select" id="case-status" name="status">${statuses.map((status) => `<option value="${status}" ${state.detail.case.status === status ? "selected" : ""}>${pretty(status)}</option>`).join("")}</select></div>`,
    onSubmit: async (form) => {
      await api(`/api/cases/${state.caseId}`, { method: "PATCH", body: JSON.stringify({ status: form.get("status") }) });
      closeModal();
      await refreshCases();
      await loadCase(state.caseId);
      toast("Case status updated.");
    }
  });
}

async function loadAdminData() {
  if (state.user.role !== "administrator") return;
  try {
    const [users, audit] = await Promise.all([api("/api/users"), api("/api/audit")]);
    state.users = users.users;
    const userList = document.querySelector("#user-list");
    const auditList = document.querySelector("#audit-list");
    if (userList) userList.innerHTML = state.users.map((user) => `<div class="setting-row"><div><strong>${esc(user.name)} ${user.id === state.user.id ? "(you)" : ""}</strong><span>${esc(user.email)} · ${user.isActive ? "Active" : "Disabled"}</span></div><div style="display:flex;align-items:center;gap:6px">${user.id !== state.user.id ? `<select class="select" data-user-role="${user.id}" aria-label="Role for ${esc(user.name)}" style="min-width:110px;width:auto;min-height:29px;font-size:9px">${["analyst", "reviewer", "administrator"].map((role) => `<option value="${role}" ${user.role === role ? "selected" : ""}>${pretty(role)}</option>`).join("")}</select><button class="button button-secondary button-small" data-save-role="${user.id}">Save role</button><button class="button button-secondary button-small" data-toggle-user="${user.id}" data-active="${user.isActive}">${user.isActive ? "Disable" : "Enable"}</button>` : `<span class="role-chip">${esc(user.role)}</span>`}</div></div>`).join("") || `<span class="row-subtle">No accounts.</span>`;
    if (auditList) auditList.innerHTML = audit.audit.slice(0, 12).map((item) => `<div class="audit-row"><strong>${esc(pretty(item.action))}</strong><span>${esc(item.userName)}</span><span>${esc(JSON.stringify(item.details))}</span><span>${dateLabel(item.occurredAt)}</span></div>`).join("") || `<span class="row-subtle">No audit events.</span>`;
  } catch (error) {
    toast(error.message, true);
  }
}

function newUserModal() {
  openModal({
    title: "Add an account",
    description: "Accounts are local to this server. Use a unique email and a strong password.",
    submitLabel: "Create account",
    body: `<div class="form-grid"><div class="field span-2"><label for="user-name">Full name *</label><input class="input" id="user-name" name="name" required maxlength="100"></div>
      <div class="field span-2"><label for="user-email">Email *</label><input class="input" id="user-email" name="email" type="email" required maxlength="254"></div>
      <div class="field span-2"><label for="user-password">Initial password *</label><input class="input" id="user-password" name="password" type="password" required minlength="12" maxlength="256"><span class="field-hint">At least 12 characters. Share credentials securely.</span></div>
      <div class="field span-2"><label for="user-role">Role</label><select class="select" id="user-role" name="role"><option value="analyst">Analyst — manage own cases</option><option value="reviewer">Reviewer — view and review cases</option><option value="administrator">Administrator — full access</option></select></div></div>`,
    onSubmit: async (form) => {
      await api("/api/users", { method: "POST", body: JSON.stringify(Object.fromEntries(form.entries())) });
      closeModal();
      await loadAdminData();
      toast("Account created.");
    }
  });
}

function reportDocument(detail) {
  const c = detail.case;
  const mappings = detail.mappings;
  const groupedEvidence = {
    "Direct observations": detail.evidence.filter((item) => item.classification === "observation"),
    "Potential capabilities": detail.evidence.filter((item) => item.classification === "capability"),
    "Inferences": detail.evidence.filter((item) => item.classification === "inference"),
    "Analyst conclusions / notes": detail.evidence.filter((item) => item.classification === "analyst")
  };
  return `<article class="report-page" id="report-print">
    <span class="eyebrow">DroidTTP · Defensive analysis report</span><h1>${esc(c.title)}</h1><p>${esc(c.description || "No investigation context was recorded.")}</p>
    <p><strong>Handling:</strong> ${esc(c.handlingMarking)} &nbsp; <strong>Generated:</strong> ${dateLabel(new Date().toISOString())} &nbsp; <strong>Review:</strong> ${esc(pretty(c.reviewState))}</p>
    <h2>Investigation and methodology</h2><p><strong>Source:</strong> ${esc(c.source || "Not recorded")}<br><strong>Owner:</strong> ${esc(c.ownerName)}<br><strong>Taxonomy reference:</strong> ${esc(state.taxonomyVersion || "Not configured")}<br>Static parsing inspects supported APK ZIP entries without executing the application. Imported observations remain attributed to their declared external source. Findings are not a malware verdict.</p>
    <h2>Samples</h2>${detail.samples.length ? detail.samples.map((sample) => `<div style="padding:9px 0;border-bottom:1px solid #e4e9ed"><strong>${esc(sample.filename)}</strong><p>SHA-256: <span class="mono">${esc(sample.sha256)}</span><br>Package: ${esc(sample.packageName || "Unavailable")} · Version: ${esc(sample.versionName || sample.versionCode || "Unavailable")} · Analysis: ${esc(pretty(sample.status))}<br>Uploaded by ${esc(sample.uploadedBy || "Unknown")} at ${dateLabel(sample.uploadedAt)}</p></div>`).join("") : "<p>No APK samples are attached.</p>"}
    <h2>Evidence</h2>${Object.entries(groupedEvidence).map(([label, items]) => `<h3 style="margin:14px 0 5px;font-size:11px">${esc(label)} (${items.length})</h3>${items.length ? `<ul>${items.map((item) => `<li><strong>${esc(pretty(item.type))}:</strong> ${esc(defang(item.value))} — ${esc(pretty(item.source))}, ${esc(item.location || "location unavailable")}, confidence ${esc(item.confidence)}. ${esc(item.details)}</li>`).join("")}</ul>` : `<p>No ${label.toLowerCase()} recorded.</p>`}`).join("")}
    <h2>ATT&amp;CK Mobile mappings</h2>${mappings.length ? `<table><thead><tr><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale / linked evidence</th></tr></thead><tbody>${mappings.map((mapping) => {
      const linked = mapping.evidenceIds.map((id) => detail.evidence.find((item) => item.id === id)).filter(Boolean);
      return `<tr><td><strong>${esc(mapping.techniqueId)} · ${esc(mapping.techniqueName)}</strong><span class="cell-secondary">${esc(mapping.taxonomyVersion)} · ${esc(mapping.tactic)}</span></td><td>${esc(pretty(mapping.status))}</td><td>${esc(pretty(mapping.confidence))}</td><td>${esc(mapping.rationale || "No rationale.")}${linked.length ? `<br><span class="cell-secondary">Evidence: ${linked.map((item) => `${esc(pretty(item.type))}: ${esc(defang(item.value))}`).join("; ")}</span>` : "<br><span class=\"cell-secondary\">No linked evidence</span>"}</td></tr>`;
    }).join("")}</tbody></table>` : "<p>No technique mappings have been recorded.</p>"}
    <h2>Analysis runs and limitations</h2>${detail.runs.length ? `<ul>${detail.runs.map((run) => `<li>${esc(pretty(run.mode))} · ${esc(run.toolName)} v${esc(run.toolVersion)} · ${esc(pretty(run.status))} · ${dateLabel(run.completedAt || run.startedAt)}. ${esc(run.errorSummary || run.limitations.join(" ") || "No known limitations reported.")}</li>`).join("")}</ul>` : "<p>No analysis runs are available.</p>"}
    <h2>Reviewer note</h2><p>${esc(c.reviewNote || "No reviewer note.")}</p>
    <div class="report-footer">Generated by DroidTTP on ${dateLabel(new Date().toISOString())}. Handle according to the case marking. A permission, static string, or inferred capability does not alone establish observed behavior.</div>
  </article>`;
}

async function showReport(caseId) {
  await loadCase(caseId, false);
  await api(`/api/cases/${caseId}/export`, { method: "POST", body: JSON.stringify({ format: "html" }) });
  const detail = state.detail;
  const container = document.querySelector("#report-preview");
  if (!container) return;
  container.innerHTML = `<div class="heading-actions no-print" style="margin-bottom:12px"><button class="button button-secondary button-small" data-action="export-json">${ico("download")} Export JSON</button><button class="button button-primary button-small" data-action="print-report">${ico("report")} Print / Save as PDF</button></div>${reportDocument(detail)}`;
}
async function downloadJSON() {
  if (!state.detail) return;
  await api(`/api/cases/${state.caseId}/export`, { method: "POST", body: JSON.stringify({ format: "json" }) });
  const report = {
    generatedAt: new Date().toISOString(),
    case: state.detail.case,
    taxonomyVersion: state.taxonomyVersion || null,
    samples: state.detail.samples,
    analysisRuns: state.detail.runs,
    evidence: state.detail.evidence,
    techniqueMappings: state.detail.mappings,
    limitations: ["Static analysis is not a malware verdict.", "Manifest permissions indicate capability, not observed behavior.", "Uploaded APKs are not executed by DroidTTP."]
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `droidttp-case-${state.detail.case.id}-report.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  toast("JSON report exported.");
}

async function handleClick(event) {
  const viewButton = event.target.closest("[data-view]");
  if (viewButton) return navigate(viewButton.dataset.view);
  const open = event.target.closest("[data-open-case]");
  if (open) {
    await openCase(Number(open.dataset.openCase));
    if (open.dataset.openTab) {
      state.caseTab = open.dataset.openTab;
      render();
    }
    return;
  }
  const tab = event.target.closest("[data-case-tab]");
  if (tab) {
    state.caseTab = tab.dataset.caseTab;
    return render();
  }
  const copy = event.target.closest("[data-copy]");
  if (copy) {
    try { await navigator.clipboard.writeText(copy.dataset.copy); toast("Copied to clipboard."); }
    catch { toast("Clipboard access was unavailable.", true); }
    return;
  }
  const toggle = event.target.closest("[data-toggle-user]");
  if (toggle) {
    try {
      await api(`/api/users/${toggle.dataset.toggleUser}`, { method: "PATCH", body: JSON.stringify({ isActive: toggle.dataset.active !== "true" }) });
      await loadAdminData();
      toast(toggle.dataset.active === "true" ? "Account disabled." : "Account enabled.");
    } catch (error) { toast(error.message, true); }
    return;
  }
  const saveRole = event.target.closest("[data-save-role]");
  if (saveRole) {
    try {
      const target = document.querySelector(`[data-user-role="${saveRole.dataset.saveRole}"]`);
      await api(`/api/users/${saveRole.dataset.saveRole}`, { method: "PATCH", body: JSON.stringify({ role: target.value }) });
      await loadAdminData();
      toast("Account role updated.");
    } catch (error) { toast(error.message, true); }
    return;
  }
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "close-modal") return closeModal();
  if (action === "logout") {
    try { await api("/api/logout", { method: "POST", body: "{}" }); }
    catch (error) { toast(`Server sign-out failed: ${error.message}`, true); }
    state.user = null; state.csrf = ""; state.cases = []; renderAuth(false); return;
  }
  if (action === "new-case") return newCaseModal();
  if (action === "upload-apk") return uploadModal();
  if (action === "edit-case") return newCaseModal(state.detail.case);
  if (action === "case-status") return caseStatusModal();
  if (action === "add-evidence") return addEvidenceModal(Number(button.dataset.sampleId));
  if (action === "add-mapping") return addMappingModal(Number(button.dataset.sampleId));
  if (action === "select-sample-evidence") return chooseSample("Add evidence", (id) => addEvidenceModal(id));
  if (action === "select-sample-mapping") return chooseSample("Add ATT&CK mapping", (id) => addMappingModal(id));
  if (action === "edit-mapping") {
    const mapping = state.detail.mappings.find((item) => item.id === Number(button.dataset.mappingId));
    if (mapping) return addMappingModal(mapping.sampleId, mapping);
  }
  if (action === "review-case") return reviewCaseModal(button.dataset.reviewState);
  if (action === "import-observations") return importObservationsModal();
  if (action === "new-user") return newUserModal();
  if (action === "print-report") return window.print();
  if (action === "export-json") return downloadJSON();
}

function chooseSample(title, onChoose) {
  const samples = state.detail?.samples || [];
  if (!samples.length) return toast("Add an APK sample first.", true);
  if (samples.length === 1) return onChoose(samples[0].id);
  openModal({
    title,
    description: "Select the sample associated with this item.",
    submitLabel: "Continue",
    body: `<div class="field"><label for="choose-sample">Sample</label><select class="select" name="sampleId" id="choose-sample">${samples.map((sample) => `<option value="${sample.id}">${esc(sample.filename)}</option>`).join("")}</select></div>`,
    onSubmit: async (form) => { const id = Number(form.get("sampleId")); closeModal(); onChoose(id); }
  });
}

document.addEventListener("click", (event) => { handleClick(event).catch((error) => toast(error.message, true)); });
document.addEventListener("submit", async (event) => {
  if (event.target.id === "settings-form") {
    event.preventDefault();
    try {
      const form = new FormData(event.target);
      const dynamicProvider = String(form.get("dynamicProvider") || "").trim();
      const dynamicVerified = form.has("dynamicVerified");
      if (dynamicProvider && !dynamicVerified) throw new Error("Confirm the provider's isolation controls before enabling observation imports.");
      if (!dynamicProvider && dynamicVerified) throw new Error("Enter a provider name before confirming its isolation.");
      await api("/api/settings", { method: "PATCH", body: JSON.stringify({ taxonomyVersion: form.get("taxonomyVersion"), dynamicProvider, dynamicVerified }) });
      await loadWorkspace();
      await loadAdminData();
      toast("Workspace settings saved.");
    } catch (error) { toast(error.message, true); }
  }
  if (event.target.id === "indicator-search") {
    event.preventDefault();
  }
});
document.addEventListener("input", (event) => {
  if (event.target.id === "case-search" || event.target.id === "case-status-filter") {
    const needle = document.querySelector("#case-search")?.value.toLowerCase().trim() || "";
    const status = document.querySelector("#case-status-filter")?.value || "";
    const visible = state.cases.filter((item) => (!status || item.status === status) && `${item.title} ${item.source} ${item.ownerName}`.toLowerCase().includes(needle));
    document.querySelector("#cases-body").innerHTML = visible.map(caseTableRow).join("") || `<tr><td colspan="6"><div class="empty-state"><h3>No matching cases</h3><p>Change the filters and try again.</p></div></td></tr>`;
  }
  if (event.target.id === "indicator-search") {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(async () => {
      try {
        await loadIndicators(event.target.value.trim());
        const results = document.querySelector("#indicator-results");
        if (results) results.innerHTML = state.indicators.length ? indicatorsTable(state.indicators) : `<div class="empty-state"><div class="empty-icon">${ico("search")}</div><h3>No matching indicators</h3><p>Try a different hash, package name, domain, or value.</p></div>`;
      } catch (error) { toast(error.message, true); }
    }, 250);
  }
  if (event.target.id === "report-case-select") {
    if (event.target.value) showReport(Number(event.target.value)).catch((error) => toast(error.message, true));
    else document.querySelector("#report-preview").innerHTML = "";
  }
});
document.addEventListener("keydown", (event) => {
  const open = event.target.closest("[data-open-case]");
  if (open && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    openCase(Number(open.dataset.openCase)).catch((error) => toast(error.message, true));
  }
  if (event.key === "Escape") closeModal();
});

initialize();
