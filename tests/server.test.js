const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const zlib = require("node:zlib");

const ROOT = path.join(__dirname, "..");

function createApk() {
  const entries = {
    "AndroidManifest.xml": Buffer.from(`<manifest package="org.example.smoke" android:versionName="1.2"><uses-permission android:name="android.permission.RECORD_AUDIO"/><application><activity android:name=".MainActivity" android:exported="true"/></application></manifest>`),
    "classes.dex": Buffer.from("endpoint https://updates.example.org/check 198.51.100.42")
  };
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const [name, plain] of Object.entries(entries)) {
    const nameBytes = Buffer.from(name);
    const method = name.endsWith(".dex") ? 8 : 0;
    const compressed = method === 8 ? zlib.deflateRawSync(plain) : plain;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(plain.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    localParts.push(local, nameBytes, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(plain.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, nameBytes);
    localOffset += local.length + nameBytes.length + compressed.length;
  }
  const directory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, directory, end]);
}

async function startServer(dataDir) {
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: ROOT,
    env: { ...process.env, HOST: "127.0.0.1", PORT: "0", DROIDTTP_DATA_DIR: dataDir, MAX_UPLOAD_MB: "1" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  let errors = "";
  child.stdout.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr.on("data", (chunk) => { errors += chunk.toString(); });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const match = output.match(/DroidTTP is available at (http:\/\/127\.0\.0\.1:\d+)/);
    if (match) return { child, base: match[1], output: () => output, errors: () => errors };
    if (child.exitCode !== null) throw new Error(`Server exited during startup.\n${output}\n${errors}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  child.kill();
  throw new Error(`Server did not start in time.\n${output}\n${errors}`);
}

function client(base) {
  let cookie = "";
  let csrf = "";
  return {
    async request(route, options = {}) {
      const method = options.method || "GET";
      const headers = new Headers(options.headers || {});
      if (method !== "GET") {
        headers.set("Origin", base);
        if (csrf) headers.set("X-CSRF-Token", csrf);
      }
      if (cookie) headers.set("Cookie", cookie);
      const response = await fetch(`${base}${route}`, { ...options, method, headers });
      if (response.headers.getSetCookie) {
        const setCookie = response.headers.getSetCookie().find((value) => value.startsWith("droidttp_session="));
        if (setCookie) cookie = setCookie.split(";")[0];
      }
      const data = await response.json().catch(() => ({}));
      if (data.csrf) csrf = data.csrf;
      return { response, data };
    }
  };
}

test("local workflow authenticates, analyzes APKs, reviews evidence, and exports", { timeout: 60000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "droidttp-test-"));
  const instance = await startServer(tempDir);
  t.after(async () => {
    instance.child.kill("SIGTERM");
    await Promise.race([once(instance.child, "exit"), new Promise((resolve) => setTimeout(resolve, 3000))]);
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const admin = client(instance.base);
  const unauthorized = await admin.request("/api/cases");
  assert.equal(unauthorized.response.status, 401);

  const setup = await admin.request("/api/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Smoke Admin", email: "admin@example.test", password: "local-test-password-123" })
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.data.user.role, "administrator");

  const created = await admin.request("/api/cases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: "APK parser smoke test", description: "Isolated end-to-end fixture.", source: "Automated test", handlingMarking: "internal" })
  });
  assert.equal(created.response.status, 201);
  const caseId = created.data.case.id;

  const prematureComplete = await admin.request(`/api/cases/${caseId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: "complete" })
  });
  assert.equal(prematureComplete.response.status, 400);

  const apk = createApk();
  const wrongExtension = await admin.request(`/api/cases/${caseId}/samples`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-Filename": "not-an-apk.txt" },
    body: apk
  });
  assert.equal(wrongExtension.response.status, 415);

  const upload = await admin.request(`/api/cases/${caseId}/samples`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent("fixture.apk") },
    body: apk
  });
  assert.equal(upload.response.status, 202);
  assert.equal(upload.data.sample.sha256, crypto.createHash("sha256").update(apk).digest("hex"));
  const sampleId = upload.data.sample.id;
  const duplicateMatches = await admin.request(`/api/duplicates?sha256=${upload.data.sample.sha256}`);
  assert.equal(duplicateMatches.data.samples.length, 1);
  assert.equal(duplicateMatches.data.samples[0].caseId, caseId);

  let detail;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const result = await admin.request(`/api/cases/${caseId}`);
    detail = result.data;
    if (detail.samples[0]?.status === "completed" || detail.samples[0]?.status === "failed") break;
  }
  assert.equal(detail.samples[0].status, "completed", JSON.stringify(detail.runs));
  assert.equal(detail.samples[0].packageName, "org.example.smoke");
  assert.ok(detail.evidence.some((item) => item.type === "permission" && item.classification === "capability"));
  assert.ok(detail.evidence.some((item) => item.value === "https://updates.example.org/check"));
  const evidenceId = detail.evidence.find((item) => item.type === "permission").id;

  const settings = await admin.request("/api/settings", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ taxonomyVersion: "ATT&CK Mobile test release", dynamicProvider: "Approved fixture source", dynamicVerified: true })
  });
  assert.equal(settings.response.status, 200);

  const mapping = await admin.request(`/api/samples/${sampleId}/mappings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      techniqueId: "T1430",
      techniqueName: "Location Tracking",
      taxonomyVersion: "ATT&CK Mobile test release",
      status: "needs_review",
      confidence: "low",
      rationale: "Candidate entered by an analyst for workflow verification.",
      evidenceIds: [evidenceId]
    })
  });
  assert.equal(mapping.response.status, 201);

  const imported = await admin.request(`/api/cases/${caseId}/import-observations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sampleId, observations: [{ type: "network event", value: "example.test" }] })
  });
  assert.equal(imported.response.status, 201);

  const approval = await admin.request(`/api/cases/${caseId}/review`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state: "approved", note: "Evidence and analysis provenance reviewed." })
  });
  assert.equal(approval.response.status, 200);
  const approvedCase = await admin.request(`/api/cases/${caseId}`);
  assert.equal(approvedCase.data.case.status, "complete");
  assert.equal(approvedCase.data.case.reviewState, "approved");
  assert.ok(approvedCase.data.evidence.some((item) => item.source === "imported"));

  const report = await admin.request(`/api/cases/${caseId}/export`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ format: "json" })
  });
  assert.equal(report.response.status, 200);

  const createdUser = await admin.request("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Second Analyst", email: "analyst@example.test", password: "second-local-password-123", role: "analyst" })
  });
  assert.equal(createdUser.response.status, 201);
  const analyst = client(instance.base);
  const login = await analyst.request("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "analyst@example.test", password: "second-local-password-123" })
  });
  assert.equal(login.response.status, 200);
  const hiddenCase = await analyst.request(`/api/cases/${caseId}`);
  assert.equal(hiddenCase.response.status, 403);
  const hiddenDuplicate = await analyst.request(`/api/duplicates?sha256=${upload.data.sample.sha256}`);
  assert.equal(hiddenDuplicate.data.samples.length, 0);
});
