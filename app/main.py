from __future__ import annotations

import csv
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import sqlite3
import sys
import time
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections.abc import Generator

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent
PROCESS_ROLE = os.getenv("DROIDTTP_PROCESS_ROLE", "web")
if PROCESS_ROLE != "worker":
    load_dotenv(ROOT / ".env")
DATA_DIR = Path(os.getenv("DROIDTTP_DATA_DIR", str(ROOT / "data"))).resolve()
UPLOAD_DIR = DATA_DIR / "samples"
DB_PATH = DATA_DIR / "droidttp.sqlite3"
def bounded_int_env(name: str, default: str, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a whole number from {minimum} to {maximum}.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be a whole number from {minimum} to {maximum}.")
    return value


MAX_UPLOAD_MB = bounded_int_env("DROIDTTP_MAX_UPLOAD_MB", "200", 1, 250)
MAX_UPLOAD = MAX_UPLOAD_MB * 1024 * 1024
DROIDTTP_ANALYSIS_TIMEOUT = bounded_int_env("DROIDTTP_ANALYSIS_TIMEOUT_SECONDS", "90", 10, 300)
ROLE = os.getenv("DROIDTTP_ROLE", "analyst").lower()
USERNAME = os.getenv("DROIDTTP_USERNAME", "analyst")
PASSWORD = os.getenv("DROIDTTP_PASSWORD", "")
SECRET = os.getenv("DROIDTTP_SECRET", "")
COOKIE_SECURE = os.getenv("DROIDTTP_COOKIE_SECURE", "false").lower() == "true"
COOKIE_NAME = "droidttp_session"
SESSION_SECONDS = 8 * 60 * 60

app = FastAPI(title="TTP Console", docs_url=None, redoc_url=None)

from app.taxonomy import ATTACK_MOBILE_ANDROID, HEURISTIC_RULES, TAXONOMY_VERSION, TAXONOMY_SOURCE
from app.analyzer import analyze_apk, parse_manifest, validate_apk_archive
from app.dataset import DatasetUnavailableError, filter_dataset_records, load_bundled_dataset

TECHNIQUES = {k: (v.name, v.tactic, v.description) for k, v in ATTACK_MOBILE_ANDROID.items()}
RULES = [(needle, tid, rationale) for needle, tid, rationale, _ in HEURISTIC_RULES]
RULE_CONFIDENCES = {needle.lower(): conf for needle, _, _, conf in HEURISTIC_RULES}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=30000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def initialize() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.touch(exist_ok=True)
    try:
        DATA_DIR.chmod(0o700)
        UPLOAD_DIR.chmod(0o700)
        DB_PATH.chmod(0o600)
    except OSError:
        pass
    with connect() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL, created_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS samples (
            id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            package_name TEXT NOT NULL DEFAULT '', app_name TEXT NOT NULL DEFAULT '',
            version_name TEXT NOT NULL DEFAULT '', min_sdk TEXT NOT NULL DEFAULT '',
            target_sdk TEXT NOT NULL DEFAULT '', manifest_kind TEXT NOT NULL DEFAULT 'unavailable',
            dex_count INTEGER NOT NULL DEFAULT 0, native_count INTEGER NOT NULL DEFAULT 0,
            storage_name TEXT NOT NULL, uploaded_at TEXT NOT NULL, UNIQUE(case_id, sha256)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
            kind TEXT NOT NULL, value TEXT NOT NULL, location TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mappings (
            id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
            technique_id TEXT NOT NULL, taxonomy_version TEXT NOT NULL DEFAULT 'starter-catalogue-2026-11',
            status TEXT NOT NULL DEFAULT 'suggested', confidence TEXT NOT NULL DEFAULT 'low',
            rationale TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            UNIQUE(sample_id, technique_id)
        );
        CREATE TABLE IF NOT EXISTS mapping_evidence (
            mapping_id TEXT NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            PRIMARY KEY(mapping_id, evidence_id)
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, object_id TEXT NOT NULL,
            actor TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_samples_hash ON samples(sha256);
        CREATE INDEX IF NOT EXISTS idx_evidence_sample ON evidence(sample_id);
        CREATE TABLE IF NOT EXISTS mapping_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, mapping_id TEXT NOT NULL,
            actor TEXT NOT NULL, old_status TEXT NOT NULL, new_status TEXT NOT NULL,
            old_confidence TEXT NOT NULL, new_confidence TEXT NOT NULL,
            old_rationale TEXT NOT NULL, new_rationale TEXT NOT NULL, occurred_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        """)
        migrations = {
            "cases": {
                "owner": "TEXT NOT NULL DEFAULT ''",
                "handling": "TEXT NOT NULL DEFAULT 'TLP:CLEAR'",
                "tags": "TEXT NOT NULL DEFAULT '[]'",
                "archived_at": "TEXT",
            },
            "samples": {
                "analysis_status": "TEXT NOT NULL DEFAULT 'completed'",
                "analysis_progress": "INTEGER NOT NULL DEFAULT 100",
                "analysis_started_at": "TEXT",
                "analysis_completed_at": "TEXT",
                "analysis_error": "TEXT NOT NULL DEFAULT ''",
                "analysis_json": "TEXT NOT NULL DEFAULT '{}'",
                "md5": "TEXT NOT NULL DEFAULT ''",
                "sha1": "TEXT NOT NULL DEFAULT ''",
            },
            "evidence": {
                "confidence": "TEXT NOT NULL DEFAULT 'low'",
            },
        }
        for table, columns in migrations.items():
            existing = {row["name"] for row in con.execute(f"PRAGMA table_info({table})")}
            for name, definition in columns.items():
                if name not in existing:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        con.execute("CREATE INDEX IF NOT EXISTS idx_samples_analysis ON samples(analysis_status)")
        legacy_mappings = con.execute(
            "SELECT * FROM mappings WHERE taxonomy_version <> ?", (TAXONOMY_VERSION,)
        ).fetchall()
        for mapping in legacy_mappings:
            new_status = "needs_review" if mapping["status"] != "rejected" else "rejected"
            note = "Prior catalogue mapping needs review against the corrected MITRE Android catalogue."
            rationale = (mapping["rationale"].strip() + " " + note).strip()[:4000]
            con.execute(
                "UPDATE mappings SET taxonomy_version=?,status=?,confidence='low',rationale=?,updated_at=? WHERE id=?",
                (TAXONOMY_VERSION, new_status, rationale, now(), mapping["id"]),
            )
            con.execute(
                "INSERT INTO mapping_history(mapping_id,actor,old_status,new_status,old_confidence,new_confidence,old_rationale,new_rationale,occurred_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (mapping["id"], "system", mapping["status"], new_status, mapping["confidence"], "low", mapping["rationale"], rationale, now()),
            )


def session_token() -> str:
    return f"{int(time.time())}:{secrets.token_urlsafe(24)}"


def sign(value: str) -> str:
    return hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def is_authenticated(request: Request) -> bool:
    raw = request.cookies.get(COOKIE_NAME, "")
    try:
        payload, signature = raw.split(".", 1)
        issued, nonce = payload.split(":", 1)
        payload = f"{issued}:{nonce}"
        expected = sign(payload)
        return bool(SECRET) and int(issued) + SESSION_SECONDS > int(time.time()) and hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False


def require_auth(request: Request) -> None:
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Please sign in to continue.")


def require_admin(request: Request) -> None:
    require_auth(request)
    if ROLE != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")


def audit(action: str, object_id: str, detail: str = "") -> None:
    with connect() as con:
        con.execute("INSERT INTO audit(action,object_id,actor,detail,occurred_at) VALUES(?,?,?,?,?)",
                    (action, object_id, "system" if PROCESS_ROLE == "worker" else USERNAME, detail[:500], now()))


async def process_analysis(sample_id: str) -> None:
    with connect() as con:
        row = con.execute("SELECT storage_name FROM samples WHERE id=? AND analysis_status='queued'", (sample_id,)).fetchone()
        if not row:
            return
        path = UPLOAD_DIR / row["storage_name"]
        claimed = con.execute(
            "UPDATE samples SET analysis_status='running',analysis_progress=5,analysis_started_at=?,analysis_error='' WHERE id=? AND analysis_status='queued'",
            (now(), sample_id),
        )
        if claimed.rowcount != 1:
            return
    audit("analysis_started", sample_id)
    try:
        worker_environment = {
            key: value for key, value in os.environ.items()
            if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"}
        }
        worker_environment.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(ROOT / "app" / "analysis_worker.py"),
            str(path),
            env=worker_environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=DROIDTTP_ANALYSIS_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError(f"Static analysis exceeded the {DROIDTTP_ANALYSIS_TIMEOUT}-second time limit.")
        if process.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise ValueError(detail[:400] or "The isolated parser could not inspect this APK.")
        result = json.loads(stdout.decode("utf-8"))
        manifest, findings = result["manifest"], result["findings"]
        with connect() as con:
            con.execute(
                "UPDATE samples SET analysis_progress=85 WHERE id=?",
                (sample_id,),
            )
            for finding in findings:
                con.execute(
                    "INSERT INTO evidence(id,sample_id,kind,value,location,source,note,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        secrets.token_hex(12), sample_id, finding["kind"],
                        str(finding["value"])[:2000], str(finding["location"])[:1000],
                        str(finding["source"])[:300], str(finding["note"])[:1000],
                        "low", now(),
                    ),
                )
            con.execute(
                "UPDATE samples SET analysis_status=?,analysis_progress=100,analysis_completed_at=?,analysis_json=?,manifest_kind=?,package_name=?,app_name=?,version_name=?,min_sdk=?,target_sdk=?,dex_count=?,native_count=? WHERE id=?",
                (
                    "completed" if manifest["manifest_kind"] == "text-xml" else "partial",
                    now(), json.dumps(manifest, ensure_ascii=False),
                    manifest["manifest_kind"], manifest["package_name"], manifest["app_name"],
                    manifest["version_name"], manifest["min_sdk"], manifest["target_sdk"],
                    manifest["dex_files"], manifest["native_libraries"], sample_id,
                ),
            )
        with connect() as con:
            evidence = [dict(item) for item in con.execute("SELECT * FROM evidence WHERE sample_id=?", (sample_id,))]
        create_suggestions(sample_id, evidence)
        audit("analysis_completed", sample_id, "partial" if manifest["manifest_kind"] != "text-xml" else "completed")
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError, sqlite3.Error, KeyError, TypeError, UnicodeDecodeError) as exc:
        message = str(exc)[:500] or "Static analysis failed."
        with connect() as con:
            con.execute(
                "UPDATE samples SET analysis_status='failed',analysis_progress=100,analysis_completed_at=?,analysis_error=? WHERE id=?",
                (now(), message, sample_id),
            )
        audit("analysis_failed", sample_id, message)


def recover_interrupted_analysis() -> None:
    """Return abandoned jobs to the durable queue after a worker restart."""
    with connect() as con:
        con.execute(
            "UPDATE samples SET analysis_status='queued',analysis_progress=0,analysis_error='Worker restarted; analysis re-queued.' WHERE analysis_status='running'"
        )


def purge_expired_samples() -> int:
    """Apply the configured retention period to sample files and derived records."""
    with connect() as con:
        configured = con.execute("SELECT value FROM settings WHERE key='retention_days'").fetchone()
        days = int(configured["value"]) if configured else 0
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        expired = [dict(row) for row in con.execute(
            "SELECT id,storage_name FROM samples WHERE uploaded_at < ? ORDER BY uploaded_at LIMIT 200", (cutoff,)
        )]
    deleted = 0
    for sample in expired:
        try:
            (UPLOAD_DIR / sample["storage_name"]).unlink(missing_ok=True)
        except OSError:
            continue
        with connect() as con:
            con.execute("DELETE FROM mapping_history WHERE mapping_id IN (SELECT id FROM mappings WHERE sample_id=?)", (sample["id"],))
            result = con.execute("DELETE FROM samples WHERE id=? AND uploaded_at < ?", (sample["id"], cutoff))
            deleted += result.rowcount
        if result.rowcount:
            audit("sample_retention_deleted", sample["id"], f"Retention period: {days} days")
    return deleted


def create_suggestions(sample_id: str, findings: list[dict]) -> None:
    matched: dict[str, list[str]] = {}
    matched_conf: dict[str, str] = {}
    for finding in findings:
        value = str(finding.get("value", "")).lower()
        for needle, tid, _ in RULES:
            if needle.lower() in value:
                matched.setdefault(tid, []).append(finding["id"])
                conf = RULE_CONFIDENCES.get(needle.lower(), "low")
                if conf == "moderate" or tid not in matched_conf:
                    matched_conf[tid] = conf
    with connect() as con:
        for tid, ev_ids in matched.items():
            mid = secrets.token_hex(12)
            conf = matched_conf.get(tid, "low")
            con.execute(
                "INSERT OR IGNORE INTO mappings(id,sample_id,technique_id,taxonomy_version,status,confidence,rationale,created_at,updated_at) VALUES(?,?,?,?,'suggested',?,?,?,?)",
                (mid, sample_id, tid, TAXONOMY_VERSION, conf, "Automated rule matched one or more static indicators. This is a candidate capability mapping and requires analyst validation.", now(), now()),
            )
            row = con.execute("SELECT id FROM mappings WHERE sample_id=? AND technique_id=?", (sample_id, tid)).fetchone()
            if row:
                for eid in ev_ids:
                    con.execute("INSERT OR IGNORE INTO mapping_evidence(mapping_id,evidence_id) VALUES(?,?)", (row["id"], eid))


def sample_view(sample_id: str) -> dict:
    with connect() as con:
        sample = con.execute("SELECT * FROM samples WHERE id=?", (sample_id,)).fetchone()
        if not sample:
            raise HTTPException(404, "Sample not found.")
        ev = [dict(r) for r in con.execute("SELECT * FROM evidence WHERE sample_id=? ORDER BY kind,value", (sample_id,))]
        mappings = []
        for row in con.execute("SELECT * FROM mappings WHERE sample_id=? ORDER BY technique_id", (sample_id,)):
            m = dict(row)
            title, tactic, description = TECHNIQUES.get(m["technique_id"], ("Unknown technique", "Unknown", "Not present in the starter catalogue."))
            m.update({"name": title, "tactic": tactic, "description": description})
            m["evidence"] = [dict(e) for e in con.execute("SELECT e.* FROM evidence e JOIN mapping_evidence me ON me.evidence_id=e.id WHERE me.mapping_id=?", (m["id"],))]
            m["history"] = [dict(h) for h in con.execute("SELECT actor,old_status,new_status,old_confidence,new_confidence,old_rationale,new_rationale,occurred_at FROM mapping_history WHERE mapping_id=? ORDER BY occurred_at DESC", (m["id"],))]
            mappings.append(m)
        sample_data = dict(sample)
        try:
            analysis = json.loads(sample_data.pop("analysis_json") or "{}")
        except json.JSONDecodeError:
            analysis = {}
        return {
            "sample": sample_data,
            "analysis": analysis,
            "evidence": ev,
            "mappings": mappings,
            "techniques": TECHNIQUES,
            "observed_facts": ev,
            "inferred_capabilities": [m for m in mappings if m["status"] == "confirmed"],
            "analyst_conclusions": [m for m in mappings if m["status"] == "confirmed" and m["rationale"]],
            "unreviewed_suggestions": [m for m in mappings if m["status"] in ("suggested", "needs_review", "deferred")],
            "rejected_mappings": [m for m in mappings if m["status"] == "rejected"],
        }


@app.on_event("startup")
def startup() -> None:
    initialize()
    remove_legacy_dataset_placeholders()


def remove_legacy_dataset_placeholders() -> None:
    """Remove old CSV-derived sample rows that never had an uploaded APK file."""
    with connect() as con:
        rows = [dict(row) for row in con.execute(
            """SELECT id,case_id,storage_name FROM samples
               WHERE manifest_kind='dataset-derived'
                 AND analysis_json LIKE '%"source": "TTP Dataset"%'"""
        )]
    removed_cases: set[str] = set()
    upload_root = UPLOAD_DIR.resolve()
    for row in rows:
        sample_path = (UPLOAD_DIR / row["storage_name"]).resolve()
        if sample_path.parent != upload_root or sample_path.is_file():
            continue
        with connect() as con:
            mapping_ids = [item["id"] for item in con.execute(
                "SELECT id FROM mappings WHERE sample_id=?", (row["id"],)
            )]
            for mapping_id in mapping_ids:
                con.execute("DELETE FROM mapping_history WHERE mapping_id=?", (mapping_id,))
            con.execute("DELETE FROM audit WHERE action='dataset_seeded' AND object_id=?", (row["id"],))
            con.execute("DELETE FROM samples WHERE id=?", (row["id"],))
        removed_cases.add(row["case_id"])

    for case_id in removed_cases:
        with connect() as con:
            case = con.execute(
                "SELECT title,source FROM cases WHERE id=?", (case_id,)
            ).fetchone()
            if (
                case
                and case["source"] == "TTP Dataset"
                and case["title"].startswith("Dataset Review ")
                and not con.execute("SELECT 1 FROM samples WHERE case_id=?", (case_id,)).fetchone()
            ):
                con.execute("DELETE FROM cases WHERE id=?", (case_id,))


@app.get("/healthz", tags=["Operations"])
def healthz():
    """Liveness probe for container orchestrators and reverse proxies."""
    return {"status": "ok", "service": "droidttp", "timestamp": now()}


@app.get("/readyz", tags=["Operations"])
def readyz():
    """Readiness probe verifying database and sample storage availability."""
    db_ok = False
    storage_ok = False
    details = {}
    try:
        with connect() as con:
            con.execute("SELECT 1").fetchone()
            db_ok = True
    except Exception as exc:
        details["database_error"] = str(exc)

    try:
        test_file = UPLOAD_DIR / ".readyz_probe"
        test_file.touch()
        test_file.unlink(missing_ok=True)
        storage_ok = True
    except Exception as exc:
        details["storage_error"] = str(exc)

    status_code = 200 if (db_ok and storage_ok) else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if (db_ok and storage_ok) else "not_ready",
            "database": "ok" if db_ok else "error",
            "storage": "ok" if storage_ok else "error",
            "timestamp": now(),
            **details,
        },
    )


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(ROOT / "app" / "static" / "index.html")


@app.get("/api/session")
def get_session(request: Request):
    authenticated = is_authenticated(request)
    return {"authenticated": authenticated, "username": USERNAME if authenticated else None, "role": ROLE if authenticated else None}


@app.post("/api/login")
async def login(request: Request):
    if len(PASSWORD) < 16 or len(SECRET) < 32 or SECRET in {
        "replace-with-a-long-random-secret-at-least-32-characters",
        "REPLACE_WITH_LONG_RANDOM_SECRET_AT_LEAST_32_CHARACTERS_ABC123",
    }:
        raise HTTPException(503, "Set a unique password of at least 16 characters and a random DROIDTTP_SECRET of at least 32 characters.")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid sign-in payload.")
    if not hmac.compare_digest(str(body.get("username", "")), USERNAME) or not hmac.compare_digest(str(body.get("password", "")), PASSWORD):
        raise HTTPException(401, "Incorrect username or password.")
    issued = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    payload = f"{issued}:{nonce}"
    signature = sign(payload)
    response = JSONResponse({"ok": True, "username": USERNAME})
    response.set_cookie(COOKIE_NAME, f"{payload}.{signature}", httponly=True, samesite="strict", secure=COOKIE_SECURE, max_age=SESSION_SECONDS, path="/")
    audit("login", USERNAME)
    return response


@app.get("/api/cases")
def list_cases(request: Request, state: str = "active", q: str = ""):
    require_auth(request)
    if state not in ("active", "closed", "archived", "all"):
        raise HTTPException(400, "Invalid case state filter.")
    query = f"%{q.strip()[:120]}%"
    with connect() as con:
        rows = [dict(r) for r in con.execute(
            """SELECT c.*,COUNT(s.id) sample_count FROM cases c LEFT JOIN samples s ON s.case_id=c.id
               WHERE (?='all' OR (?='archived' AND c.archived_at IS NOT NULL) OR
                      (?='active' AND c.archived_at IS NULL AND c.status='active') OR
                      (?='closed' AND c.archived_at IS NULL AND c.status='closed'))
                 AND (?='' OR c.title LIKE ? OR c.description LIKE ? OR c.source LIKE ? OR c.owner LIKE ? OR c.tags LIKE ?)
               GROUP BY c.id ORDER BY c.created_at DESC LIMIT 500""",
            (state, state, state, state, q.strip(), query, query, query, query, query),
        )]
    return {"cases": rows}


@app.post("/api/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.get("/api/dashboard")
def dashboard(request: Request):
    require_auth(request)
    with connect() as con:
        cases = [dict(r) for r in con.execute("SELECT c.*,COUNT(s.id) sample_count FROM cases c LEFT JOIN samples s ON s.case_id=c.id WHERE c.archived_at IS NULL GROUP BY c.id ORDER BY c.created_at DESC")]
        counts = {
            "cases": con.execute("SELECT COUNT(*) FROM cases WHERE archived_at IS NULL").fetchone()[0],
            "samples": con.execute("SELECT COUNT(*) FROM samples").fetchone()[0],
            "review": con.execute("SELECT COUNT(*) FROM mappings WHERE status IN ('suggested','needs_review','deferred')").fetchone()[0],
            "queued": con.execute("SELECT COUNT(*) FROM samples WHERE analysis_status IN ('queued','running')").fetchone()[0],
        }
        recent_activity = [dict(r) for r in con.execute("SELECT action,object_id,actor,detail,occurred_at FROM audit ORDER BY id DESC LIMIT 8")]
        latest_samples = [dict(r) for r in con.execute("SELECT s.id,s.original_filename,s.package_name,s.sha256,s.uploaded_at,s.analysis_status,s.case_id,c.title case_title FROM samples s JOIN cases c ON c.id=s.case_id ORDER BY s.uploaded_at DESC LIMIT 8")]
        raw_reviews = [dict(r) for r in con.execute("SELECT m.id,m.technique_id,m.status,m.confidence,m.updated_at,s.id sample_id,s.original_filename FROM mappings m JOIN samples s ON s.id=m.sample_id WHERE m.status IN ('suggested','needs_review','deferred') ORDER BY m.updated_at DESC LIMIT 8")]
        reviews = []
        for r in raw_reviews:
            tech = TECHNIQUES.get(r["technique_id"])
            r["technique_name"] = tech[0] if tech else "Unknown"
            r["tactic"] = tech[1] if tech else "Mobile"
            reviews.append(r)
    return {"cases": cases, "counts": counts, "activity": recent_activity, "latest_samples": latest_samples, "reviews": reviews}


@app.post("/api/cases")
async def create_case(request: Request):
    require_auth(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid case payload.")
    title = str(body.get("title", "")).strip()[:160]
    if not title:
        raise HTTPException(400, "Case title is required.")
    tags = body.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 20 or any(not isinstance(tag, str) or not tag.strip() or len(tag) > 40 for tag in tags):
        raise HTTPException(400, "Provide up to 20 tags of at most 40 characters.")
    handling = body.get("handling", "TLP:CLEAR")
    if handling not in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"):
        raise HTTPException(400, "Invalid handling marking.")
    cid = secrets.token_hex(12)
    with connect() as con:
        con.execute("INSERT INTO cases(id,title,description,source,created_at,created_by,owner,handling,tags) VALUES(?,?,?,?,?,?,?,?,?)",
                    (cid, title, str(body.get("description", ""))[:4000], str(body.get("source", ""))[:500], now(), USERNAME, str(body.get("owner", USERNAME))[:120], handling, json.dumps(list(dict.fromkeys(tag.strip() for tag in tags)), ensure_ascii=False)))
    audit("case_created", cid, title)
    return {"id": cid}


@app.post("/api/samples")
async def upload_sample_to_case(
    request: Request,
    case_id: str = Form(...),
    file: UploadFile = File(...),
):
    return await upload_sample(case_id, request, file)


@app.post("/api/cases/{case_id}/samples")
async def upload_sample(case_id: str, request: Request, file: UploadFile = File(...)):
    require_auth(request)
    with connect() as con:
        case = con.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        raise HTTPException(404, "Case not found.")
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Choose an .apk file.")
    if not file.filename or len(file.filename) > 255:
        raise HTTPException(400, "Invalid APK filename.")
    sample_id = secrets.token_hex(12)
    storage_name = f"{sample_id}.apk"
    path = UPLOAD_DIR / storage_name
    temporary_path = UPLOAD_DIR / f".{sample_id}.part"
    sha256_digest = hashlib.sha256()
    sha1_digest = hashlib.sha1()
    md5_digest = hashlib.md5()
    total_size = 0
    try:
        with temporary_path.open("xb") as output:
            while chunk := await file.read(1024 * 1024):
                total_size += len(chunk)
                if total_size > MAX_UPLOAD:
                    raise HTTPException(413, f"File exceeds the {MAX_UPLOAD_MB} MB upload limit.")
                sha256_digest.update(chunk)
                sha1_digest.update(chunk)
                md5_digest.update(chunk)
                output.write(chunk)
        if total_size == 0:
            raise HTTPException(400, "The uploaded APK is empty.")
        try:
            temporary_path.chmod(0o600)
        except OSError:
            pass
        try:
            validate_apk_archive(temporary_path)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        sha = sha256_digest.hexdigest()
        with connect() as con:
            duplicate = con.execute("SELECT id FROM samples WHERE case_id=? AND sha256=?", (case_id, sha)).fetchone()
        if duplicate:
            temporary_path.unlink(missing_ok=True)
            await file.close()
            return {"id": duplicate["id"], "duplicate": True, "analysis_status": "existing"}
        temporary_path.replace(path)
        with connect() as con:
            con.execute(
                "INSERT INTO samples(id,case_id,original_filename,sha256,md5,sha1,size_bytes,storage_name,uploaded_at,analysis_status,analysis_progress) VALUES(?,?,?,?,?,?,?,?,?,'queued',0)",
                (sample_id, case_id, Path(file.filename).name[:255], sha, md5_digest.hexdigest(), sha1_digest.hexdigest(), total_size, storage_name, now()),
            )
    except OSError as exc:
        temporary_path.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        await file.close()
        raise HTTPException(500, "Could not securely store the uploaded APK.") from exc
    except sqlite3.Error as exc:
        temporary_path.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        await file.close()
        raise HTTPException(409, "The sample could not be queued. Please retry the upload.") from exc
    except HTTPException:
        temporary_path.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        await file.close()
        raise
    await file.close()
    audit("sample_uploaded", sample_id, sha)
    return {"id": sample_id, "duplicate": False, "analysis_status": "queued"}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, request: Request):
    require_auth(request)
    with connect() as con:
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found.")
        samples = [dict(r) for r in con.execute("SELECT * FROM samples WHERE case_id=? ORDER BY uploaded_at DESC", (case_id,))]
    return {"case": dict(case), "samples": samples}


@app.get("/api/dataset")
def get_dataset_summary(request: Request):
    require_auth(request)
    try:
        summary, _ = load_bundled_dataset()
    except DatasetUnavailableError as exc:
        raise HTTPException(503, str(exc)) from exc
    return summary


@app.get("/api/dataset/records")
def list_dataset_records(
    request: Request,
    q: str = "",
    label: str = "all",
    offset: int = 0,
    limit: int = 25,
):
    require_auth(request)
    if offset < 0:
        raise HTTPException(400, "Offset must be zero or greater.")
    if not 1 <= limit <= 100:
        raise HTTPException(400, "Page size must be from 1 to 100.")
    try:
        _, rows = load_bundled_dataset()
    except DatasetUnavailableError as exc:
        raise HTTPException(503, str(exc)) from exc
    available_labels = {row["label"] for row in rows}
    if label != "all" and label not in available_labels:
        raise HTTPException(400, "Choose an available source label.")
    matching = filter_dataset_records(rows, q, label)
    return {
        "records": [
            {
                "row_id": row["row_id"],
                "package_name": row["package_name"],
                "sha256": row["sha256"],
                "label": row["label"],
                "features": {
                    key: value for key, value in row.items()
                    if key not in {"row_id", "package_name", "sha256", "label"}
                },
            }
            for row in matching[offset:offset + limit]
        ],
        "total": len(matching),
        "offset": offset,
        "limit": limit,
        "labels": sorted(available_labels),
    }


@app.get("/api/dataset/records.csv")
def export_dataset_records(request: Request, q: str = "", label: str = "all"):
    require_auth(request)
    try:
        summary, rows = load_bundled_dataset()
    except DatasetUnavailableError as exc:
        raise HTTPException(503, str(exc)) from exc
    available_labels = {row["label"] for row in rows}
    if label != "all" and label not in available_labels:
        raise HTTPException(400, "Choose an available source label.")
    matching = filter_dataset_records(rows, q, label)
    fields = ("row_id", "package_name", "sha256", "label", *(
        key for key in matching[0] if key not in {"row_id", "package_name", "sha256", "label"}
    )) if matching else ("row_id", "package_name", "sha256", "label")
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in matching:
        safe_row = {
            key: "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
            for key, value in row.items()
        }
        writer.writerow(safe_row)
    audit("dataset_profiles_exported", summary["source_sha256"], f"{len(matching)} profiles")
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="droidttp-dataset-profiles.csv"'},
    )


@app.patch("/api/cases/{case_id}")
async def update_case(case_id: str, request: Request):
    require_auth(request)
    body = await request.json()
    allowed = {"title", "description", "source", "status", "owner", "handling", "tags", "archived"}
    if not isinstance(body, dict) or set(body) - allowed:
        raise HTTPException(400, "Invalid case fields.")
    with connect() as con:
        row = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Case not found.")
        values = dict(row)
        if "title" in body:
            title = str(body["title"]).strip()
            if not title or len(title) > 160:
                raise HTTPException(400, "Case title must be between 1 and 160 characters.")
            values["title"] = title
        for field, limit in (("description", 4000), ("source", 500), ("owner", 120)):
            if field in body:
                values[field] = str(body[field]).strip()[:limit]
        if "status" in body:
            if body["status"] not in ("active", "closed"):
                raise HTTPException(400, "Case status must be active or closed.")
            values["status"] = body["status"]
        if "handling" in body:
            if body["handling"] not in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"):
                raise HTTPException(400, "Invalid handling marking.")
            values["handling"] = body["handling"]
        if "tags" in body:
            if not isinstance(body["tags"], list) or len(body["tags"]) > 20 or any(not isinstance(tag, str) or not tag.strip() or len(tag) > 40 for tag in body["tags"]):
                raise HTTPException(400, "Provide up to 20 tags of at most 40 characters.")
            values["tags"] = json.dumps(list(dict.fromkeys(tag.strip() for tag in body["tags"])), ensure_ascii=False)
        if "archived" in body:
            if not isinstance(body["archived"], bool):
                raise HTTPException(400, "Archived must be true or false.")
            values["archived_at"] = now() if body["archived"] else None
        con.execute(
            "UPDATE cases SET title=?,description=?,source=?,status=?,owner=?,handling=?,tags=?,archived_at=? WHERE id=?",
            (values["title"], values["description"], values["source"], values["status"], values["owner"], values["handling"], values["tags"], values["archived_at"], case_id),
        )
    audit("case_updated", case_id, "archive" if body.get("archived") else "updated")
    return {"id": case_id}


@app.get("/api/samples/export.csv")
def export_samples_csv(request: Request, q: str = "", status: str = "all"):
    require_auth(request)
    if status not in ("all", "queued", "running", "partial", "completed", "failed"):
        raise HTTPException(400, "Invalid analysis status filter.")
    query = f"%{q.strip()[:120]}%"
    with connect() as con:
        rows = con.execute(
            """SELECT s.id,s.original_filename,s.sha256,s.sha1,s.md5,s.size_bytes,s.package_name,
                      s.app_name,s.version_name,s.analysis_status,s.uploaded_at,c.id case_id,c.title case_title
               FROM samples s JOIN cases c ON c.id=s.case_id
               WHERE (?='all' OR s.analysis_status=?) AND
                     (?='' OR s.original_filename LIKE ? OR s.package_name LIKE ? OR s.sha256 LIKE ? OR c.title LIKE ?)
               ORDER BY s.uploaded_at DESC""",
            (status, status, q.strip()[:120], query, query, query, query),
        ).fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow((
        "sample_id", "filename", "sha256", "sha1", "md5", "size_bytes",
        "package_name", "app_name", "version", "analysis_status", "uploaded_at",
        "case_id", "case_title",
    ))
    for row in rows:
        values = []
        for value in row:
            text = str(value if value is not None else "")
            values.append("'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text)
        writer.writerow(values)
    audit("sample_inventory_exported", "inventory", f"{len(rows)} samples")
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="droidttp-samples.csv"'},
    )


@app.get("/api/samples/{sample_id}")
def get_sample(sample_id: str, request: Request):
    require_auth(request)
    return sample_view(sample_id)


@app.get("/api/samples/{sample_id}/file")
def download_sample_file(sample_id: str, request: Request):
    require_auth(request)
    with connect() as con:
        sample = con.execute(
            "SELECT original_filename,storage_name FROM samples WHERE id=?", (sample_id,)
        ).fetchone()
    if not sample:
        raise HTTPException(404, "Sample not found.")
    path = (UPLOAD_DIR / sample["storage_name"]).resolve()
    if path.parent != UPLOAD_DIR.resolve():
        raise HTTPException(500, "The stored sample path is invalid.")
    if not path.is_file():
        raise HTTPException(404, "The original APK file is not available in local storage.")
    audit("sample_downloaded", sample_id)
    return FileResponse(
        path,
        media_type="application/vnd.android.package-archive",
        filename=sample["original_filename"],
    )


@app.delete("/api/samples/{sample_id}")
def delete_sample(sample_id: str, request: Request):
    require_auth(request)
    with connect() as con:
        sample = con.execute(
            "SELECT storage_name,analysis_status FROM samples WHERE id=?", (sample_id,)
        ).fetchone()
    if not sample:
        raise HTTPException(404, "Sample not found.")
    if sample["analysis_status"] in ("queued", "running"):
        raise HTTPException(409, "Wait for analysis to finish before deleting this sample.")
    path = (UPLOAD_DIR / sample["storage_name"]).resolve()
    if path.parent != UPLOAD_DIR.resolve():
        raise HTTPException(500, "The stored sample path is invalid.")
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise HTTPException(500, "Could not remove the locally stored APK.") from exc
    with connect() as con:
        mapping_ids = [row["id"] for row in con.execute(
            "SELECT id FROM mappings WHERE sample_id=?", (sample_id,)
        )]
        for mapping_id in mapping_ids:
            con.execute("DELETE FROM mapping_history WHERE mapping_id=?", (mapping_id,))
        con.execute("DELETE FROM samples WHERE id=?", (sample_id,))
    audit("sample_deleted", sample_id)
    return {"id": sample_id, "deleted": True}


@app.get("/api/samples")
def list_samples(request: Request, q: str = "", status: str = "all"):
    require_auth(request)
    if status not in ("all", "queued", "running", "partial", "completed", "failed"):
        raise HTTPException(400, "Invalid analysis status filter.")
    query = f"%{q.strip()[:120]}%"
    with connect() as con:
        rows = [dict(r) for r in con.execute(
            """SELECT s.id,s.case_id,s.original_filename,s.sha256,s.md5,s.sha1,s.size_bytes,s.package_name,s.app_name,
                      s.version_name,s.uploaded_at,s.analysis_status,s.analysis_progress,s.analysis_error,
                      s.analysis_started_at,s.analysis_completed_at,c.title case_title,
                      (SELECT COUNT(*) FROM samples duplicate WHERE duplicate.sha256=s.sha256) duplicate_count
               FROM samples s JOIN cases c ON c.id=s.case_id
               WHERE (?='all' OR s.analysis_status=?) AND
                     (?='' OR s.original_filename LIKE ? OR s.package_name LIKE ? OR s.sha256 LIKE ? OR c.title LIKE ?)
               ORDER BY s.uploaded_at DESC LIMIT 500""",
            (status, status, q.strip(), query, query, query, query),
        )]
    return {"samples": rows}


@app.get("/api/evidence")
def list_evidence(request: Request, q: str = "", kind: str = "all"):
    require_auth(request)
    query = f"%{q.strip()[:120]}%"
    with connect() as con:
        rows = [dict(r) for r in con.execute(
            """SELECT e.*,s.id sample_id,s.original_filename,c.id case_id,c.title case_title,
                      (SELECT GROUP_CONCAT(m.id || '|' || m.technique_id, ',')
                       FROM mappings m JOIN mapping_evidence me ON me.mapping_id=m.id
                       WHERE me.evidence_id=e.id AND m.status!='rejected') mapping_refs
               FROM evidence e JOIN samples s ON s.id=e.sample_id JOIN cases c ON c.id=s.case_id
               WHERE (?='all' OR e.kind=?) AND
                     (?='' OR e.value LIKE ? OR e.source LIKE ? OR e.location LIKE ? OR e.note LIKE ?)
               ORDER BY e.created_at DESC LIMIT 1000""",
            (kind, kind, q.strip(), query, query, query, query),
        )]
    return {"evidence": rows}


@app.patch("/api/evidence/{evidence_id}")
async def update_evidence(evidence_id: str, request: Request):
    require_auth(request)
    body = await request.json()
    if not isinstance(body, dict) or set(body) - {"note", "confidence"}:
        raise HTTPException(400, "Invalid evidence fields.")
    with connect() as con:
        existing = con.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not existing:
            raise HTTPException(404, "Evidence not found.")
        note = str(body.get("note", existing["note"]))[:1000]
        confidence = body.get("confidence", existing["confidence"])
        if confidence not in ("low", "moderate", "high"):
            raise HTTPException(400, "Invalid evidence confidence.")
        con.execute("UPDATE evidence SET note=?,confidence=? WHERE id=?", (note, confidence, evidence_id))
        row = con.execute("SELECT sample_id FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    audit("evidence_updated", evidence_id, confidence)
    return {"sample_id": row["sample_id"]}


@app.get("/api/techniques")
def techniques(request: Request, q: str = ""):
    require_auth(request)
    needle = q.strip().casefold()
    with connect() as con:
        mapped = {r["technique_id"]: r["status"] for r in con.execute(
            "SELECT technique_id,status FROM mappings WHERE status!='rejected' GROUP BY technique_id,status"
        )}
    items = []
    for tid, (name, tactic, description) in TECHNIQUES.items():
        if needle and needle not in f"{tid} {name} {tactic} {description}".casefold():
            continue
        items.append({"id": tid, "name": name, "tactic": tactic, "description": description, "mapping_status": mapped.get(tid, "unmapped")})
    return {"version": TAXONOMY_VERSION, "source": TAXONOMY_SOURCE, "techniques": items}


@app.get("/api/activity")
def activity(request: Request):
    require_auth(request)
    with connect() as con:
        rows = [dict(r) for r in con.execute("SELECT id,action,object_id,actor,detail,occurred_at FROM audit ORDER BY id DESC LIMIT 500")]
    return {"activity": rows}


@app.get("/api/settings")
def get_settings(request: Request):
    require_auth(request)
    with connect() as con:
        configured = {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM settings")}
    return {
        "role": ROLE,
        "max_upload_mb": MAX_UPLOAD // (1024 * 1024),
        "analysis_timeout_seconds": DROIDTTP_ANALYSIS_TIMEOUT,
        "retention_days": int(configured.get("retention_days", "0")),
        "taxonomy_version": TAXONOMY_VERSION,
        "taxonomy_source": TAXONOMY_SOURCE,
        "dynamic_analysis": "Not configured. Dynamic analysis is disabled and no results are simulated.",
        "external_integrations": "None configured. No samples or indicators are sent externally.",
        "secrets_displayed": False,
    }


@app.patch("/api/settings")
async def update_settings(request: Request):
    require_admin(request)
    body = await request.json()
    if not isinstance(body, dict) or set(body) != {"retention_days"}:
        raise HTTPException(400, "Only retention_days can be configured here.")
    try:
        days = int(body["retention_days"])
    except (TypeError, ValueError):
        raise HTTPException(400, "Retention must be a whole number from 0 to 3650 days.")
    if not 0 <= days <= 3650:
        raise HTTPException(400, "Retention must be a whole number from 0 to 3650 days.")
    with connect() as con:
        con.execute("INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES('retention_days',?,?)", (str(days), now()))
    audit("settings_updated", "retention_days", str(days))
    return {"retention_days": days}


@app.patch("/api/mappings/{mapping_id}")
async def update_mapping(mapping_id: str, request: Request):
    require_auth(request)
    body = await request.json()
    if not isinstance(body, dict) or set(body) - {"status", "confidence", "rationale"}:
        raise HTTPException(400, "Invalid mapping review fields.")
    status = body.get("status")
    confidence = body.get("confidence")
    if status not in ("suggested", "confirmed", "rejected", "needs_review", "deferred"):
        raise HTTPException(400, "Invalid mapping status.")
    if confidence not in ("low", "moderate", "high"):
        raise HTTPException(400, "Invalid confidence.")
    with connect() as con:
        existing = con.execute("SELECT * FROM mappings WHERE id=?", (mapping_id,)).fetchone()
        if not existing:
            raise HTTPException(404, "Mapping not found.")
        rationale = str(body.get("rationale", ""))[:4000]
        con.execute("UPDATE mappings SET status=?,confidence=?,rationale=?,updated_at=? WHERE id=?", (status, confidence, rationale, now(), mapping_id))
        con.execute(
            "INSERT INTO mapping_history(mapping_id,actor,old_status,new_status,old_confidence,new_confidence,old_rationale,new_rationale,occurred_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (mapping_id, USERNAME, existing["status"], status, existing["confidence"], confidence, existing["rationale"], rationale, now()),
        )
        row = con.execute("SELECT sample_id FROM mappings WHERE id=?", (mapping_id,)).fetchone()
    audit("mapping_updated", mapping_id, status)
    return sample_view(row["sample_id"])


@app.post("/api/samples/{sample_id}/mappings")
async def create_manual_mapping(sample_id: str, request: Request):
    require_auth(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid mapping payload.")
    technique_id = str(body.get("technique_id", "")).strip()
    if technique_id not in TECHNIQUES:
        raise HTTPException(400, "Choose a technique in the local Android catalogue.")
    rationale = str(body.get("rationale", "")).strip()[:4000]
    if not rationale:
        raise HTTPException(400, "A rationale is required for a manual mapping.")
    confidence = body.get("confidence", "moderate")
    if confidence not in ("low", "moderate", "high"):
        raise HTTPException(400, "Invalid confidence.")
    with connect() as con:
        if not con.execute("SELECT 1 FROM samples WHERE id=?", (sample_id,)).fetchone():
            raise HTTPException(404, "Sample not found.")
        mapping_id = secrets.token_hex(12)
        try:
            con.execute(
                "INSERT INTO mappings(id,sample_id,technique_id,taxonomy_version,status,confidence,rationale,created_at,updated_at) VALUES(?,?,?,?,'needs_review',?,?,?,?)",
                (mapping_id, sample_id, technique_id, TAXONOMY_VERSION, confidence, rationale, now(), now()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "A mapping for this technique already exists for the sample.")
        con.execute(
            "INSERT INTO mapping_history(mapping_id,actor,old_status,new_status,old_confidence,new_confidence,old_rationale,new_rationale,occurred_at) VALUES(?,?,?,'needs_review',?,?,? ,?,?)",
            (mapping_id, USERNAME, "new", confidence, confidence, "", rationale, now()),
        )
    audit("mapping_created", mapping_id, technique_id)
    return sample_view(sample_id)


def case_report_payload(case_id: str) -> dict:
    with connect() as con:
        case_row = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case_row:
            raise HTTPException(404, "Case not found.")
        sample_ids = [r["id"] for r in con.execute("SELECT id FROM samples WHERE case_id=? ORDER BY uploaded_at DESC", (case_id,))]
    reports = [sample_view(sample_id) for sample_id in sample_ids]
    return {
        "case": dict(case_row),
        "samples": reports,
        "report_generated_at": now(),
        "taxonomy_version": TAXONOMY_VERSION,
        "taxonomy_source": TAXONOMY_SOURCE,
        "limitations": [
            "Static indicators do not prove execution or malicious intent.",
            "Binary Android XML and DEX bytecode are not decoded by the current analyzer.",
            "Signing artifacts are inventoried but not cryptographically verified.",
            "Dynamic analysis and external intelligence integrations are not configured.",
        ],
    }


@app.get("/api/cases/{case_id}/report.json")
def case_report_json(case_id: str, request: Request):
    require_auth(request)
    payload = case_report_payload(case_id)
    audit("case_report_json_exported", case_id)
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="TTPConsole-case-{case_id}.json"'})


@app.get("/api/cases/{case_id}/report.html")
def case_report_html(case_id: str, request: Request):
    require_auth(request)
    payload = case_report_payload(case_id)
    escape = lambda value: html.escape(str(value or ""), quote=True)
    sample_sections = []
    for report in payload["samples"]:
        sample = report["sample"]
        ev_rows = "".join(
            f"<tr><td>{escape(item['kind'])}</td><td>{escape(item['value'])}</td><td>{escape(item['source'])}</td><td>{escape(item['location'])}</td><td>{escape(item['note'])}</td></tr>"
            for item in report["observed_facts"]
        ) or '<tr><td colspan="5">No parsed evidence.</td></tr>'
        mappings = report["mappings"]

        def mapping_rows(items):
            return "".join(
                f"<tr><td>{escape(item['technique_id'])}</td><td>{escape(item['name'])}</td><td>{escape(item['status'])}</td><td>{escape(item['confidence'])}</td><td>{escape(item['rationale'])}</td></tr>"
                for item in items
            ) or '<tr><td colspan="5">None.</td></tr>'

        sample_sections.append(
            f"<section><h2>{escape(sample['original_filename'])}</h2><p>SHA-256: <code>{escape(sample['sha256'])}</code> · Status: <b>{escape(sample['analysis_status'])}</b></p>"
            f"<h3>Observed static facts</h3><table><tr><th>Type</th><th>Value</th><th>Source</th><th>Location</th><th>Notes</th></tr>{ev_rows}</table>"
            f"<h3>Inferred capabilities (reviewed mappings, not observed runtime)</h3><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(report['inferred_capabilities'])}</table>"
            f"<h3>Analyst conclusions</h3><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(report['analyst_conclusions'])}</table>"
            f"<h3>Unreviewed suggestions</h3><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(report['unreviewed_suggestions'])}</table>"
            f"<h3>Rejected mappings</h3><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(report['rejected_mappings'])}</table></section>"
        )
    doc = (
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">"
        f"<title>TTP Console case report - {escape(payload['case']['title'])}</title>"
        "<style>body{font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:1100px;margin:32px auto;padding:0 24px;color:#17383b}"
        "h1{color:#0d2e2b;border-bottom:2px solid #0d2e2b;padding-bottom:8px}h2,h3{color:#174643}code{background:#f0f4f4;padding:2px 6px;border-radius:3px;font-family:monospace}"
        "table{width:100%;border-collapse:collapse;margin:12px 0 24px}th,td{border:1px solid #d5dfdd;padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf4f1;font-weight:600}section{border-top:1px solid #d5dfdd;padding-top:20px;margin-top:24px}"
        ".meta-box{background:#f4f8f7;border:1px solid #d5dfdd;border-radius:6px;padding:14px;margin-bottom:20px}"
        "@media print{.no-print{display:none !important}@page{margin:15mm}body{max-width:100%;margin:0;padding:0}table{page-break-inside:auto}tr{page-break-inside:avoid;page-break-after:auto}}"
        "</style></head><body>"
        "<div style=\"margin-bottom:16px;display:flex;justify-content:flex-end\" class=\"no-print\"><button onclick=\"window.print()\" style=\"padding:9px 18px;background:#123b3b;color:#fff;border:none;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer\">Download PDF / Print Report</button></div>"
        f"<h1>TTP Console Investigation Report</h1>"
        f"<div class=\"meta-box\"><p><b>Case:</b> {escape(payload['case']['title'])}<br><b>Handling Marking:</b> {escape(payload['case']['handling'])}<br><b>Generated:</b> {escape(payload['report_generated_at'])}<br><b>ATT&amp;CK Taxonomy:</b> {escape(payload['taxonomy_version'])} ({escape(payload.get('taxonomy_source', ''))})</p></div>"
        "<p><em>Methodology note:</em> Observed static facts are distinct from inferred capabilities. Neither static indicators nor declared permissions alone establish runtime behavior or malicious intent.</p>"
        f"{''.join(sample_sections)}"
        "<h2>Limitations &amp; Provenance</h2><ul>" + "".join(f"<li>{escape(item)}</li>" for item in payload["limitations"]) + "</ul></body></html>"
    )
    audit("case_report_html_exported", case_id)
    return HTMLResponse(doc, headers={"Content-Disposition": f'attachment; filename="TTPConsole-case-{case_id}.html"'})


@app.get("/api/samples/{sample_id}/report.json")
def report_json(sample_id: str, request: Request):
    require_auth(request)
    payload = sample_view(sample_id)
    with connect() as con:
        payload["case"] = dict(con.execute("SELECT c.* FROM cases c JOIN samples s ON s.case_id=c.id WHERE s.id=?", (sample_id,)).fetchone())
    payload["report_generated_at"] = now()
    payload["taxonomy_version"] = TAXONOMY_VERSION
    payload["taxonomy_source"] = TAXONOMY_SOURCE
    payload["limitations"] = [
        "Static indicators do not prove execution or malicious intent.",
        "Binary Android XML and DEX bytecode are not decoded by the current analyzer.",
        "Signing artifacts are inventoried but not cryptographically verified.",
        "Dynamic analysis and external intelligence integrations are not configured.",
    ]
    audit("report_json_exported", sample_id)
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="TTPConsole-{sample_id}.json"'})


@app.get("/api/samples/{sample_id}/report.html")
def report_html(sample_id: str, request: Request):
    require_auth(request)
    payload = sample_view(sample_id)
    payload["report_generated_at"] = now()
    payload["taxonomy_version"] = TAXONOMY_VERSION
    payload["taxonomy_source"] = TAXONOMY_SOURCE
    payload["limitations"] = [
        "Static indicators do not prove execution or malicious intent.",
        "Binary Android XML and DEX bytecode are not decoded by the current analyzer.",
        "Signing artifacts are inventoried but not cryptographically verified.",
        "Dynamic analysis and external intelligence integrations are not configured.",
    ]
    with connect() as con:
        case = dict(con.execute("SELECT c.* FROM cases c JOIN samples s ON s.case_id=c.id WHERE s.id=?", (sample_id,)).fetchone())
    s = payload["sample"]
    esc = lambda x: html.escape(str(x or ""))
    evidence_rows = "".join(f"<tr><td>{esc(item['kind'])}</td><td>{esc(item['value'])}</td><td>{esc(item['source'])}</td><td>{esc(item['location'])}</td><td>{esc(item['note'])}</td></tr>" for item in payload["observed_facts"])

    def mapping_rows(items):
        return "".join(f"<tr><td>{esc(item['technique_id'])}</td><td>{esc(item['name'])}</td><td>{esc(item['status'])}</td><td>{esc(item['confidence'])}</td><td>{esc(item['rationale'])}</td></tr>" for item in items) or '<tr><td colspan="5">None.</td></tr>'

    doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>TTP Console Report - {esc(s['original_filename'])}</title><style>body{{font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:1000px;margin:36px auto;padding:0 24px;color:#17232b}}h1{{color:#0d2e2b;border-bottom:2px solid #0d2e2b;padding-bottom:8px}}h2,h3{{color:#123b43}}code{{background:#f0f4f4;padding:2px 6px;border-radius:3px;font-family:monospace}}table{{width:100%;border-collapse:collapse;margin:12px 0 24px}}th,td{{border:1px solid #d5dfe0;padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{background:#eef4f3;font-weight:600}}.note{{padding:12px 14px;background:#fff8e6;border-left:4px solid #d9a32e;border-radius:4px;margin-bottom:20px}}.meta-box{{background:#f4f8f7;border:1px solid #d5dfdd;border-radius:6px;padding:14px;margin-bottom:20px}}@media print{{.no-print{{display:none !important}}@page{{margin:15mm}}body{{max-width:100%;margin:0;padding:0}}table{{page-break-inside:auto}}tr{{page-break-inside:avoid;page-break-after:auto}}}}</style></head><body><div style="margin-bottom:16px;display:flex;justify-content:flex-end" class="no-print"><button onclick="window.print()" style="padding:9px 18px;background:#123b3b;color:#fff;border:none;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer">Download PDF / Print Report</button></div><h1>TTP Console Analysis Report</h1><div class="meta-box"><p><b>Case:</b> {esc(case['title'])}<br><b>Generated:</b> {esc(payload['report_generated_at'])}<br><b>Taxonomy:</b> {esc(payload['taxonomy_version'])} ({esc(payload['taxonomy_source'])})</p></div><h2>Sample Metadata</h2><div class="meta-box"><p><b>File:</b> {esc(s['original_filename'])}<br><b>SHA-256:</b> <code>{esc(s['sha256'])}</code><br><b>SHA-1:</b> <code>{esc(s.get('sha1') or '—')}</code><br><b>MD5:</b> <code>{esc(s.get('md5') or '—')}</code><br><b>Package:</b> {esc(s['package_name']) or 'Not extracted'}<br><b>Manifest:</b> {esc(s['manifest_kind'])}<br><b>Analysis Status:</b> {esc(s['analysis_status'])}</p></div><div class="note"><b>Analyst Notice:</b> Static indicators and candidate mappings do not prove runtime behavior or establish malicious intent.</div><h2>Observed static facts</h2><table><tr><th>Type</th><th>Value</th><th>Source</th><th>Location</th><th>Notes</th></tr>{evidence_rows or '<tr><td colspan="5">No evidence items.</td></tr>'}</table><h2>Inferred capabilities (reviewed mappings; not observed runtime)</h2><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(payload['inferred_capabilities'])}</table><h2>Analyst conclusions</h2><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(payload['analyst_conclusions'])}</table><h2>Unreviewed suggestions</h2><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(payload['unreviewed_suggestions'])}</table><h2>Rejected mappings</h2><table><tr><th>ID</th><th>Technique</th><th>Status</th><th>Confidence</th><th>Rationale</th></tr>{mapping_rows(payload['rejected_mappings'])}</table><h2>Limitations</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in payload['limitations'])}</ul><p>Verify ATT&amp;CK IDs and descriptions against the official <a href="https://attack.mitre.org/matrices/mobile/android/">MITRE ATT&amp;CK Android Matrix</a> before operational use.</p></body></html>'''
    audit("report_html_exported", sample_id)
    return HTMLResponse(doc, headers={"Content-Disposition": f'attachment; filename="TTPConsole-{sample_id}.html"'})


app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")
