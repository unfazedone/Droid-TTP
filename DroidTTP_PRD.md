# Product Requirements Document (PRD)
# DroidTTP: Mapping Android Applications to TTPs for Cyber Threat Intelligence

**Status:** Draft  
**Version:** 1.0  
**Last updated:** 2026-11-02

## 1. Overview

DroidTTP is a defensive cyber threat intelligence application that helps analysts examine Android application packages (APKs), organize technical evidence, and map observed behavior to MITRE ATT&CK Mobile techniques relevant to Android. It combines automated static analysis with optional dynamic-analysis evidence and analyst review in one case-oriented workflow.

The product is intended to accelerate and standardize analysis, not to make definitive malware verdicts. Every suggested TTP mapping must link to supporting evidence, show its source and confidence, and remain editable or rejectable by an analyst. Reports should distinguish observed behavior from inferred behavior and from permissions or code that merely indicate potential capability.

**Working assumptions for this draft:**

- The first release is a web-based analyst application for a small CTI or mobile-security team.
- APK analysis is defensive and limited to files the analyst is authorized to examine.
- The initial analysis mode is static. Dynamic analysis is an optional integration with an isolated Android emulator/sandbox and may be deferred if the environment is unavailable.
- ATT&CK Mobile is the mapping taxonomy; the product will filter to Android-relevant techniques and retain the framework version used for each analysis. MITRE defines Mobile as covering Android and iOS, and maintains an Android-specific matrix. [MITRE ATT&CK Mobile Matrix](https://attack.mitre.org/matrices/mobile/) · [Android Matrix](https://attack.mitre.org/matrices/mobile/android/)
- This PRD does not assume a public malware-submission service, a commercial threat-intelligence feed, or a particular sandbox vendor.

## 2. Goals

- Let an analyst create an investigation and upload one or more APKs with clear file validation and status feedback.
- Extract useful APK metadata and static indicators, including package identity, signing details, manifest permissions/components, strings, URLs/domains/IPs, hashes, and selected code or library indicators.
- Optionally ingest dynamic-analysis observations from an isolated Android environment, keeping them separate from static findings.
- Suggest candidate ATT&CK Mobile technique mappings and show the exact evidence and rationale behind each suggestion.
- Let an analyst confirm, reject, edit, and annotate mappings, including confidence and evidence references.
- Produce a concise, shareable CTI report with methodology, findings, indicators, ATT&CK mappings, limitations, and provenance.
- Maintain a searchable history of cases and APK samples, with role-based access and auditability.
- Make taxonomy updates traceable so a report can be reproduced against the ATT&CK version used at analysis time.
- Keep the interface practical for repeated analyst use on desktop and tablet screens.

## 3. Non-Goals

- Automatically declaring an APK malicious or benign with no analyst review.
- Replacing a full reverse-engineering suite, mobile device forensics platform, or enterprise malware sandbox.
- Executing uploaded APKs on the host server or on an analyst's personal device.
- Automatically attributing an app to a threat actor or campaign without sourced intelligence and analyst approval.
- Providing offensive tooling, malware development features, or instructions to deploy analyzed applications against victims.
- Publicly sharing uploaded APKs, extracted indicators, or reports by default.

## 4. Users and Roles

| Role | Needs | Permissions |
|---|---|---|
| CTI / malware analyst | Inspect APKs, review evidence, curate mappings, export reports | Create and manage assigned cases; view approved shared cases |
| Senior analyst / reviewer | Validate methodology and conclusions | Review, comment on, approve, or return analyses |
| Administrator | Manage users, taxonomy synchronization, integrations, retention, and system settings | Full configuration and access management |

A single-user local deployment may use an administrator account, but authentication remains required because APKs and reports can contain sensitive information.

## 5. Proposed Technology Stack

| Layer | Proposed choice |
|---|---|
| Web frontend | React with TypeScript |
| UI styling | Tailwind CSS or an equivalent utility-based design system |
| Backend API | Python with FastAPI |
| APK inspection | Isolated worker processes using maintained Android/APK inspection utilities; exact tools selected during implementation review |
| Database | PostgreSQL for multi-user deployments; SQLite may be used for a single-user prototype |
| File storage | Private local object/file storage for the prototype; configurable private object storage for larger deployments |
| Task processing | Background job queue for scans, report generation, and taxonomy refresh |
| Authentication | Secure session or token-based authentication with role checks |
| Reporting | HTML report with PDF and structured JSON export; STIX 2.1 export is a later-phase option |
| Deployment | Docker Compose for a self-hosted MVP; cloud deployment is deployment-specific |

These choices are a starting point, not a strict implementation requirement. APK parsing and any dynamic execution must run outside the web request process with resource limits and isolation.

## 6. High-Level Structure (Conceptual)

```text
/droidttp
  /frontend                 # analyst workspace and admin UI
  /backend                  # API, authentication, case and report services
  /workers                  # isolated static analysis and integration workers
  /integrations             # optional sandbox and intelligence adapters
  /taxonomy                 # versioned ATT&CK Mobile data/cache
  /storage                  # private APKs, evidence artifacts, report files
  /database                 # migrations and development schema
  /tests                    # automated checks and sample fixtures
  docker-compose.yml
  .env.example
  README.md
  PRD.md
```

The structure is conceptual. Production secrets must be provided through a secret manager or protected environment variables, not committed to source control.

## 7. Core Workflow

1. Analyst creates a case and records its title, source, handling marking, and optional context.
2. Analyst uploads an APK. DroidTTP validates the file, calculates cryptographic hashes, records provenance, and stores it privately.
3. A static-analysis job extracts metadata and indicators, then reports progress and any tool errors.
4. If configured, the analyst requests dynamic analysis in an isolated emulator/sandbox and imports the resulting observations.
5. DroidTTP presents findings grouped by source and suggests candidate ATT&CK Mobile mappings, each linked to evidence and a rationale.
6. Analyst reviews each suggestion, sets confidence, adds notes, and confirms or rejects it. Analyst can also add a mapping manually.
7. A reviewer may comment on or approve the completed analysis.
8. Analyst exports a report and/or structured findings. Case, sample, evidence, taxonomy version, and mapping decisions remain linked for later review.

## 8. Data Model (Conceptual)

### Table: users

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique user identifier |
| email | TEXT | Unique login identifier |
| password_hash / identity_subject | TEXT | Local credential hash or external identity reference |
| role | TEXT | analyst, reviewer, administrator |
| is_active | BOOLEAN | Disabled accounts cannot sign in |
| created_at | DATETIME | Account creation time |
| last_login_at | DATETIME | Optional audit field |

### Table: cases

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique case identifier |
| title | TEXT | Required analyst-provided title |
| description | TEXT | Optional investigation context |
| source | TEXT | Origin or acquisition context; avoid unsupported attribution claims |
| handling_marking | TEXT | e.g. internal, confidential, TLP marking if adopted by the organization |
| status | TEXT | draft, analyzing, review, complete, archived, failed |
| created_by | FK -> users.id | Case owner |
| created_at / updated_at | DATETIME | Timestamps |

### Table: samples

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique sample identifier |
| case_id | FK -> cases.id | Parent case |
| original_filename | TEXT | Sanitized display name; never used as a storage path |
| sha256 | TEXT | Primary content identity; indexed |
| md5 / sha1 | TEXT | Optional compatibility hashes |
| file_size_bytes | INTEGER | Upload size |
| package_name | TEXT | Extracted Android package identifier |
| app_name / version_name / version_code | TEXT | Extracted metadata where available |
| signing_certificate | JSON/TEXT | Certificate subject, digest, and validation notes |
| storage_key | TEXT | Private storage reference, not a public URL |
| uploaded_by | FK -> users.id | Provenance |
| uploaded_at | DATETIME | Timestamp |

### Table: analysis_runs

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique analysis run |
| sample_id | FK -> samples.id | Analyzed sample |
| mode | TEXT | static, dynamic, imported |
| tool_name / tool_version | TEXT | Provenance and reproducibility |
| status | TEXT | queued, running, completed, partial, failed, cancelled |
| started_at / completed_at | DATETIME | Timing |
| configuration | JSON/TEXT | Non-secret analysis settings |
| error_summary | TEXT | Sanitized error details |

### Table: evidence_items

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique finding/evidence identifier |
| analysis_run_id | FK -> analysis_runs.id | Source analysis |
| evidence_type | TEXT | permission, manifest component, string, network indicator, behavior, code reference, sandbox event, analyst note |
| value | TEXT/JSON | Normalized indicator or finding |
| location | TEXT | File, class, method, manifest path, event, or artifact reference |
| source | TEXT | Static tool, sandbox, imported report, or analyst |
| observed_at | DATETIME | When applicable |
| confidence | TEXT/NUMBER | Confidence in the observation, distinct from mapping confidence |
| details | JSON/TEXT | Supporting context and redaction metadata |

### Table: technique_mappings

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique mapping decision |
| sample_id | FK -> samples.id | Associated APK |
| technique_id | TEXT | ATT&CK ID, including sub-technique when applicable |
| taxonomy_version | TEXT | Version or release identifier used |
| status | TEXT | suggested, confirmed, rejected, needs_review |
| rationale | TEXT | Analyst-readable reason for the mapping |
| confidence | TEXT | low, moderate, high; calibrated guidance defined in UI |
| reviewed_by | FK -> users.id | Analyst/reviewer decision owner |
| reviewed_at | DATETIME | Review timestamp |

### Table: mapping_evidence

| Field | Type | Notes |
|---|---|---|
| mapping_id | FK -> technique_mappings.id | Mapping decision |
| evidence_item_id | FK -> evidence_items.id | Evidence supporting or contradicting it |
| relationship | TEXT | supports, contradicts, contextual |

### Table: audit_events

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Unique event |
| user_id | FK -> users.id | Actor, nullable for system events |
| case_id | FK -> cases.id | Related case, if applicable |
| action | TEXT | Upload, view, export, edit, delete, approve, login, settings change |
| details | JSON/TEXT | Minimal event details; do not store secrets |
| occurred_at | DATETIME | Timestamp |

## 9. Application Pages and Features

### 9.1 Sign In

- Secure sign-in for approved users, with sign-out and session expiry.
- Clear error messages that do not reveal whether an account exists.
- Account creation is administrator-controlled or connected to the organization's identity provider.

### 9.2 Analyst Dashboard

- List recent and assigned cases with status, owner, and last update.
- Show counts for active cases, analyses in progress, and items awaiting review.
- Search cases by title, package name, hash, or indicator, subject to user access.
- Provide a clear action to create a case or continue an analysis.

### 9.3 Case Workspace

- Display case context, handling marking, APK samples, analysis status, and review history.
- Support multiple APKs in one case while keeping per-sample results distinct.
- Preserve source and provenance notes.
- Allow status progression through draft, analysis, review, complete, and archive.

### 9.4 APK Upload and Sample Details

- Accept APK files only in the MVP; enforce configurable size limits and validation.
- Show filename, file size, SHA-256, upload time, uploader, and analysis status.
- Detect duplicate hashes and offer to link an existing sample if access policy permits.
- Reject malformed, unsupported, or over-limit uploads with actionable explanations.
- Store files outside the public web root and serve no uploaded file as executable content.

### 9.5 Static Analysis Results

- Present app identity, signing certificate information, manifest permissions, exported components, intents, SDK metadata, and extracted indicators when available.
- Show URLs, domains, IP addresses, file paths, and suspicious strings as data; neutralize active links by default.
- Separate direct observations from heuristics and inferred capability.
- Include tool name/version and extraction limitations.
- Allow an analyst to hide irrelevant findings from the report without deleting the underlying evidence.

### 9.6 Dynamic Analysis (Optional Integration)

- Submit a sample only to an explicitly configured isolated environment.
- Require an analyst action to start a run; do not execute APKs automatically on upload.
- Display sandbox name, image/device profile, run duration, network policy, and run status.
- Import supported observations such as process/activity events, network connections, file changes, and permission prompts.
- Clearly mark unavailable telemetry and failed or incomplete runs.
- Dynamic execution remains disabled unless an administrator configures and verifies an isolation provider.

### 9.7 ATT&CK Mapping Review

- Show candidate Android-relevant ATT&CK Mobile techniques with ID, name, tactic, framework version, rationale, and evidence links.
- Distinguish technique-level mappings from sub-technique mappings.
- Let analysts confirm, reject, or defer suggestions; add manual mappings; edit rationale; set confidence; and attach supporting or contradictory evidence.
- Do not treat a manifest permission alone as proof that a behavior occurred. Indicate whether evidence is capability-based, code-based, or behaviorally observed.
- Provide a compact ATT&CK matrix view with confirmed, suggested, and rejected states that are visually distinct and accessible.
- Preserve rejected suggestions and review history for auditability.

### 9.8 Indicators and Search

- Search across authorized cases by hash, package name, domain, URL, IP, certificate digest, technique ID, and filename.
- Normalize indicators for matching while preserving the original extracted value.
- Defang potentially dangerous URLs in report views and make copying the raw value an explicit action.
- Avoid automatic external lookups unless the user or administrator enables the relevant integration.

### 9.9 Report and Export

- Generate an HTML report and downloadable PDF containing case summary, sample metadata, hashes, methodology, tool versions, key evidence, confirmed ATT&CK mappings, analyst rationale, confidence, limitations, and timestamps.
- Clearly separate confirmed mappings from unreviewed suggestions and rejected candidates.
- Include a taxonomy/version reference and preserve evidence-to-mapping links.
- Support a structured JSON export for integration; STIX 2.1 export is an optional later phase after schema and interoperability requirements are confirmed.
- Apply case handling markings and access controls to generated reports.

### 9.10 Administration

- Manage users and roles, upload limits, retention settings, analysis worker settings, and enabled integrations.
- Configure the ATT&CK Mobile data source and refresh policy; show last successful sync and taxonomy version.
- View operational status, job failures, and storage usage without exposing sample contents to unauthorized administrators.
- Record all security-relevant configuration changes in the audit log.

## 10. Functional Requirements

- **FR-1:** The system shall require authentication before displaying cases, samples, evidence, or reports.
- **FR-2:** The system shall validate uploaded files, compute hashes, and record upload provenance before scheduling analysis.
- **FR-3:** Static analysis shall run in a separate worker with configurable CPU, memory, time, and file-size limits.
- **FR-4:** Each extracted finding shall record its analysis source and, where available, its location in the APK or run artifact.
- **FR-5:** Each suggested TTP mapping shall include a rationale, linked evidence, confidence, and taxonomy version.
- **FR-6:** Analysts shall be able to confirm, reject, defer, or manually add mappings, with decisions recorded in the audit history.
- **FR-7:** The system shall support incomplete results and report which analysis steps failed or were unavailable.
- **FR-8:** Reports shall preserve the distinction between observation, inference, and analyst conclusion.
- **FR-9:** Case access shall follow role and assignment rules; exports shall enforce the same permissions as the case.
- **FR-10:** Taxonomy updates shall not silently rewrite historical analyst decisions; prior reports retain their original version reference.

## 11. UI / UX Requirements

- Clean, information-dense analyst workspace with clear hierarchy and readable evidence tables.
- Use neutral visual language for observations and distinct states for suggested, confirmed, rejected, and incomplete results.
- No decorative gradients or emoji in the application UI.
- Keyboard-accessible navigation, visible focus states, meaningful labels, and sufficient contrast.
- Desktop-first layout that remains usable on tablet and smaller screens; complex evidence tables may scroll horizontally with clear column labels.
- Long-running jobs must show status, elapsed time, cancellation where supported, and useful failure states.
- Dangerous indicators and active links must be handled carefully; raw URLs are not opened automatically.
- Every report should identify its generation time, sample hash, analysis runs, taxonomy version, and reviewer state.

## 12. Security, Privacy, and Safety Requirements

- Uploaded APKs are untrusted input. Parsing and any execution must occur in isolated, least-privilege workers with no access to application secrets.
- Dynamic analysis must use a disposable, network-restricted emulator or sandbox with an explicit egress policy and reset between runs.
- Store APKs and artifacts privately; encrypt data in transit and at rest where supported by the deployment.
- Enforce authentication, role-based authorization, CSRF/session protections as applicable, secure password hashing, and rate limits.
- Validate and sanitize filenames and metadata; prevent path traversal, archive bombs, oversized input, and unsafe report rendering.
- Keep credentials and integration secrets out of source control, logs, analysis artifacts, and exported reports.
- Provide configurable retention and secure deletion for samples, artifacts, and cases, subject to organizational policy.
- Record access, export, review, and deletion events in an audit trail.
- Do not transmit samples or indicators to external services unless the organization has configured the integration and the analyst is informed.
- Use least-data logging: logs should capture operational events without copying APK contents or sensitive report text.

## 13. Non-Functional Requirements

- Analysis tasks shall be asynchronous; uploading or opening a case must not wait for full analysis completion.
- The UI shall remain responsive while scans and report generation run.
- The system shall show partial results when a tool fails, without presenting missing telemetry as a negative finding.
- Case search and dashboard lists should return within 2 seconds for a typical deployment with up to 10,000 samples, excluding analysis time.
- The MVP shall support configurable upload and retention limits and communicate them to users.
- All analysis output must include enough provenance to reproduce or review how it was generated.
- The system shall support backup and restore of database metadata and private artifacts.
- Deployment documentation shall describe required services, storage, secrets, network controls, backup, and upgrade steps.
- ATT&CK data should be locally cached for reliable operation; taxonomy refreshes must be versioned and logged.

## 14. Out of Scope for MVP

- iOS application analysis.
- Automated threat-actor attribution, campaign clustering, or verdict guarantees.
- Public sample submission, community sharing, or a multi-tenant public portal.
- Automatic execution of APKs on a physical device.
- Full decompilation/reverse-engineering IDE or interactive debugger.
- Paid intelligence feeds and automatic submission to public scanning services.
- Advanced collaborative editing, live co-browsing, or granular custom permission policies.
- STIX/TAXII publishing unless prioritized after the first report/export workflow.

## 15. Success Criteria and Acceptance Criteria

The MVP is successful when:

- An authenticated analyst can create a case, upload a valid APK, and see its SHA-256 and provenance.
- An invalid or oversized file is rejected safely with a clear explanation.
- Static analysis completes asynchronously and presents metadata, indicators, and findings with source and limitations.
- Candidate ATT&CK Mobile mappings link to evidence and identify the taxonomy version used.
- An analyst can confirm, reject, defer, and manually add a mapping; every decision is retained in history.
- The report clearly separates observed facts, inferred capabilities, suggestions, and analyst conclusions.
- An authorized analyst can export a report, and an unauthorized user cannot access that case or its export.
- A failed or partial analysis is visible as such and is never represented as evidence that the APK is clean.
- Dynamic analysis cannot run unless an administrator has enabled a configured isolated environment and the analyst explicitly starts the run.
- A reviewer can inspect a case and its evidence without losing the original analysis provenance.

## 16. Open Decisions for Implementation Planning

- Is DroidTTP intended first as a local research prototype, a single-team self-hosted service, or a centrally hosted product?
- Which static-analysis engines and dynamic sandbox, if any, are already available to the project?
- What upload sizes, sample retention period, and case handling markings are required?
- Should analyst accounts use local credentials or an existing identity provider?
- Is the primary export PDF, JSON, STIX 2.1, or a combination?
- Are there required data-source, privacy, or regulatory constraints for uploaded APKs and extracted indicators?

---

**Framework reference:** [MITRE ATT&CK Mobile Matrix](https://attack.mitre.org/matrices/mobile/) · [MITRE ATT&CK Android Matrix](https://attack.mitre.org/matrices/mobile/android/)
