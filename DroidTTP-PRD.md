# Product Requirements Document (PRD)
# DroidTTP: Mapping Android Applications to TTPs for Cyber Threat Intelligence

**Version:** 1.0  
**Status:** Draft for review  
**Product type:** Web-based Android application analysis and CTI platform

## 1. Overview

DroidTTP is a web application for security analysts and researchers to examine Android application packages (APKs), collect observable evidence about their capabilities and behavior, and map that evidence to relevant MITRE ATT&CK Mobile techniques and sub-techniques. The product presents a reviewable analysis rather than treating requested permissions or isolated code indicators as proof of malicious activity.

The first release focuses on safe APK intake, static analysis, analyst review, and exportable reports. Dynamic execution of samples is excluded from the initial release and may be introduced later through a separately isolated analysis environment. ATT&CK mappings are versioned so reports can be interpreted against the framework version used when they were created. MITRE describes its Mobile matrix as covering Android and iOS, and its Android matrix as techniques known to target Android devices. [MITRE ATT&CK Mobile Matrix](https://attack.mitre.org/matrices/mobile/) [MITRE ATT&CK Android Matrix](https://attack.mitre.org/matrices/mobile/android/)

**Working assumptions:** The project is intended for a small team or individual CTI analysts; the first release is a private analyst tool, not a public APK scanning service; APK samples and reports are confidential; the initial release performs static analysis only. Hosting, team size, and the preferred implementation language remain configurable project decisions.

## 2. Goals

- Let an analyst submit an APK and obtain a repeatable, structured static analysis.
- Extract package metadata, manifest declarations, permissions, components, SDK targets, signing certificate details, hashes, URLs/domains/IPs, and selected code or resource indicators where tooling supports them.
- Help analysts map evidence to Android-relevant ATT&CK Mobile tactics, techniques, and sub-techniques.
- Show the evidence, rationale, confidence, and analyst status behind every proposed mapping.
- Support manual additions, corrections, and rejection of suggested mappings.
- Produce clear reports in JSON and a human-readable format, with hashes and framework/tool versions for reproducibility.
- Protect uploaded samples and analysis results through authentication, access controls, safe processing, and retention settings.
- Keep the analyst workflow understandable, responsive, and usable without requiring ATT&CK expertise for every operation.

## 3. Tech Stack (Proposed)

| Layer | Proposed choice |
|---|---|
| User interface | HTML/CSS with a lightweight JavaScript frontend (framework may be selected during implementation) |
| Backend API | Python with FastAPI, or another framework selected by the project team |
| Analysis workers | Isolated worker process/container for parsing and static analysis; do not run APKs on the web server |
| Android package inspection | Established static-analysis tools and Android SDK utilities, invoked with timeouts and resource limits |
| Database | PostgreSQL for users, jobs, findings, mappings, and audit records |
| Sample storage | Private object storage or restricted local storage, outside the public web root |
| ATT&CK data | Versioned local snapshot or controlled import of MITRE ATT&CK STIX data |
| Authentication | Organization SSO if available; otherwise secure local accounts with MFA support |
| Deployment | Container-based deployment with separate web/API and analysis-worker roles |

The toolchain is a proposal, not a requirement. The implementation should document exact tool names, versions, licenses, and enabled analyzers before release. ATT&CK publishes data and tools for working with ATT&CK; DroidTTP should retain the source version and identifiers used for each mapping. [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)

## 4. Folder Structure (High-level, conceptual)

```text
/droidttp
  /web                 # analyst interface
  /api                 # authenticated application API
  /worker              # isolated APK parsing and analysis jobs
  /analysis            # analyzer adapters and normalization
  /attack_data         # versioned ATT&CK Mobile data/import utilities
  /reports             # report templates and serializers
  /database            # migrations and schema
  /tests               # automated checks
  /deployment          # container and environment configuration
  config.example.yaml  # non-secret defaults and limits
  README.md
  PRD.md
```

Structural guideline only. Secrets, uploaded APKs, and generated reports must not be committed to source control or served as public static files.

## 5. Data Model (Conceptual)

### Table: users

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Stable user identifier |
| email / username | TEXT | Unique login identity |
| role | TEXT | Analyst or administrator |
| created_at | DATETIME | Account creation time |
| is_active | BOOLEAN | Account access state |

### Table: analysis_jobs

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Analysis identifier |
| submitted_by | FK -> users.id | Submitter |
| original_filename | TEXT | Untrusted display name; sanitized |
| sha256 | TEXT | Primary sample identifier |
| file_size | INTEGER | Bytes |
| status | TEXT | queued, running, complete, failed, deleted |
| submitted_at | DATETIME | Submission time |
| completed_at | DATETIME | Completion time, nullable |
| tool_versions | JSON/TEXT | Analyzer and ATT&CK data versions |
| retention_until | DATETIME | Retention policy date |

### Table: findings

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Finding identifier |
| analysis_id | FK -> analysis_jobs.id | Parent analysis |
| category | TEXT | permission, component, string, network indicator, code pattern, etc. |
| value | TEXT/JSON | Normalized evidence value |
| source | TEXT | Manifest, DEX, resource, analyzer, or analyst |
| location | TEXT | File/path/class/method reference when available |
| severity | TEXT | Informational, low, medium, high; not a verdict |
| created_at | DATETIME | Finding timestamp |

### Table: technique_mappings

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Mapping identifier |
| analysis_id | FK -> analysis_jobs.id | Parent analysis |
| technique_id | TEXT | ATT&CK technique/sub-technique ID |
| framework_version | TEXT | ATT&CK release used |
| rationale | TEXT | Why evidence supports the mapping |
| confidence | TEXT / score | Low, medium, high or calibrated score |
| status | TEXT | suggested, accepted, rejected, needs_review |
| reviewed_by | FK -> users.id | Analyst reviewer, nullable |
| reviewed_at | DATETIME | Review timestamp |

### Table: mapping_evidence

| Field | Type | Notes |
|---|---|---|
| mapping_id | FK -> technique_mappings.id | Mapping |
| finding_id | FK -> findings.id | Supporting evidence |

### Table: audit_events

| Field | Type | Notes |
|---|---|---|
| id | UUID / INTEGER PK | Event identifier |
| user_id | FK -> users.id | Actor, nullable for system events |
| analysis_id | FK -> analysis_jobs.id | Related analysis, nullable |
| action | TEXT | Upload, view, export, delete, mapping edit, etc. |
| occurred_at | DATETIME | Event time |

## 6. Analyst Workflow and Pages

### 6.1 Sign-in and Workspace

- Require authentication for all project data and uploaded samples.
- Show recent analyses, processing status, sample hash, submission date, and analyst.
- Allow analysts to search by package name, hash, application label, or date.
- Display concise operational status and useful failure reasons without exposing secrets or internal paths.

### 6.2 Submit APK

- Drag-and-drop or file-picker upload for APK files.
- Validate file extension and content signature; calculate SHA-256 on receipt.
- Apply configurable file-size, job-concurrency, and rate limits.
- Check for an existing analysis with the same hash and offer to open it or request a new run.
- Require the submitter to confirm they are authorized to analyze the sample.
- Show queue and processing status; support cancellation while queued.

### 6.3 Analysis Summary

- Show application label, package name, version, min/target SDK, file size, hashes, signer/certificate metadata, and analysis timestamps where available.
- Show findings grouped by type and severity, with source and location details.
- Clearly separate observed facts, tool-derived interpretations, and analyst conclusions.
- Show processing warnings, unsupported formats, and analyzer coverage limitations.

Android permissions are declarations in the app manifest; a permission request alone must not be presented as proof that a behavior occurred. [Android Developers: Declare app permissions](https://developer.android.com/training/permissions/declaring)

### 6.4 ATT&CK Mapping Review

- Display proposed mappings grouped by tactic, including technique ID/name, confidence, rationale, and linked evidence.
- Let analysts accept, reject, or mark a mapping for further review, with optional notes.
- Let analysts add a mapping manually by searching ATT&CK Mobile techniques.
- Require evidence and rationale for accepted mappings; preserve rejected suggestions for auditability.
- Show the ATT&CK framework version and Android platform applicability.
- Warn when a mapping is based on weak or indirect indicators.

### 6.5 Indicators and Relationships

- Extract and display supported indicators such as URLs, domains, IP addresses, certificate fingerprints, package identifiers, and file hashes.
- Deduplicate and normalize indicators while retaining the original observed value and source.
- Allow an analyst to tag indicators and add context; do not automatically publish or share them.
- Network lookups to third-party intelligence sources are disabled by default and must be explicitly configured.

### 6.6 Reports and Export

- Generate a human-readable report (HTML/PDF) and machine-readable JSON.
- Include sample hashes, package metadata, findings, ATT&CK mappings, evidence references, confidence, analyst decisions, tool versions, ATT&CK version, timestamps, and limitations.
- Support export of ATT&CK Navigator-compatible layer JSON where mappings are present.
- Include a clear statement that automated mappings are triage assistance and require analyst validation.
- Record report export in the audit log.

### 6.7 Administration

- Manage users, roles, account access, retention limits, upload limits, worker capacity, and enabled analysis modules.
- Manage ATT&CK data imports and view the currently active dataset version.
- View job health, errors, storage usage, audit events, and basic usage metrics.
- Configure branding and operational settings without editing source files where practical.
- Do not expose raw samples or sensitive report content in broad administrative dashboards.

## 7. Analysis and Mapping Requirements

- Static analysis is the initial release boundary; submitted APKs are parsed as data and never launched by the web application or worker.
- Findings must retain provenance: which analyzer or source produced them and where they were found.
- Mapping logic may use rules or analyst-authored heuristics, but each suggested mapping must explain its evidence and rule/version.
- Permission-only or string-only matches should generally have low confidence unless corroborated by stronger evidence.
- A technique may have multiple supporting findings; mappings must preserve those relationships.
- ATT&CK changes must not silently rewrite historical reports. New analyses use the selected current dataset; old analyses retain their original framework version unless explicitly migrated.
- The product must not label an application “malicious” solely because it has risky permissions or a technique suggestion. Any risk summary must be evidence-based and explain its limitations.

## 8. Configuration

Use environment-specific configuration plus a checked-in example file. Secrets must come from a secret manager or environment variables and must not be stored in committed configuration.

```yaml
app:
  name: DroidTTP
  environment: production
  max_upload_mb: 200
  analysis_timeout_seconds: 900
  max_concurrent_jobs: 2
storage:
  sample_retention_days: 30
  report_retention_days: 90
  private_storage_path: /var/lib/droidttp/samples
analysis:
  static_analysis_enabled: true
  dynamic_analysis_enabled: false
  enabled_modules:
    - manifest
    - package_metadata
    - certificate
    - strings_and_indicators
attack:
  domain: mobile
  platform: android
  dataset_version: "configured-release"
security:
  require_authentication: true
  require_mfa_for_admins: true
```

- Validate configuration at startup and fail safely on invalid values.
- Allow approved settings to be changed by administrators where appropriate.
- Never include API keys, signing secrets, or production credentials in the example file.

## 9. Security, Privacy, and Safety Requirements

- Treat every APK as untrusted input; enforce file limits, timeouts, CPU/memory limits, and least-privilege worker permissions.
- Run parsing in an isolated worker/container with no access to application secrets or host filesystem beyond its assigned sample and output areas.
- Disable outbound network access from analysis workers by default.
- Store samples and reports privately; encrypt transport and storage where supported.
- Enforce role-based access and record sample access, exports, changes, and deletion in audit logs.
- Sanitize filenames and all extracted values before display or export.
- Provide configurable retention and deletion, including deletion of the stored sample and associated artifacts.
- Do not execute APKs in the initial release. If dynamic analysis is later approved, it requires a separate disposable emulator environment, controlled networking, reset between jobs, and an explicit risk review.

## 10. UI / UX Requirements

- Design for analyst clarity: neutral colors, readable typography, compact but scannable evidence panels, and strong hierarchy.
- Use explicit labels for observed evidence, inferred behavior, suggested mapping, and analyst-confirmed mapping.
- Provide filters for tactic, confidence, finding type, and review status.
- Every technique mapping should be traceable to its evidence without navigating through unrelated screens.
- Use accessible contrast, keyboard navigation, visible focus states, and responsive layouts.
- Provide progress, empty, error, and partial-analysis states.
- Avoid sensational labels and unsupported claims about app intent.

## 11. Non-Functional Requirements

- Analysis jobs must be asynchronous and recover safely from worker restarts.
- APIs must authenticate and authorize every access to samples, analyses, and reports.
- The system must keep an audit trail for access and analyst decisions.
- Results must be reproducible enough to identify the sample, toolchain, rules, and ATT&CK data version used.
- Provide configurable resource limits and operational health checks.
- Support backup and restoration of database metadata and private sample storage according to the retention policy.
- Handle malformed, encrypted, split, or unsupported APK content with a clear status and no server crash.
- Keep personal data collection to the minimum required for user accounts and auditability.

## 12. Out of Scope (Initial Release)

- Executing APKs on analyst workstations or production application servers.
- Dynamic behavior analysis, live-device monitoring, or emulator orchestration.
- Automatic malware verdicts or guaranteed detection coverage.
- iOS, Windows, or non-Android application analysis.
- Public submission portal or public sample search engine.
- Automatic sharing of samples or indicators with third parties.
- Threat actor attribution or campaign-level conclusions.
- Multi-tenant customer billing, subscriptions, and monetization.
- Full case management, incident response, or SIEM replacement.

## 13. Success Criteria

- An authenticated analyst can upload an APK, view its hash and metadata, and receive a completed or clearly failed analysis without running the sample.
- Each finding shown in a report has a source and, where available, a location in the package.
- Each suggested ATT&CK mapping displays its technique ID, framework version, rationale, confidence, and supporting evidence.
- Analysts can accept, reject, or add mappings, and those decisions are preserved in the report and audit trail.
- Reports can be exported as human-readable output and JSON, with sample hashes and tool/framework versions.
- Unauthorized users cannot access samples, findings, or reports.
- Malformed input is contained by the analysis worker and produces an actionable error rather than affecting the application service.
- Sample retention and deletion follow the configured policy.

## 14. Open Decisions

- Is DroidTTP a single-analyst research prototype or a multi-user internal service?
- Which analysis engine(s) and exact versions should be integrated for the first milestone?
- Should reports include PDF, HTML, JSON, and/or ATT&CK Navigator layer export at launch?
- What are the required sample retention period and maximum APK size?
- Will the deployment environment support containers, private object storage, and SSO?
- Should the system support importing prior analyses or analyst-curated mapping rules?

## References

- [MITRE ATT&CK Mobile Matrix](https://attack.mitre.org/matrices/mobile/)
- [MITRE ATT&CK Android Matrix](https://attack.mitre.org/matrices/mobile/android/)
- [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- [Android Developers: Declare app permissions](https://developer.android.com/training/permissions/declaring)
