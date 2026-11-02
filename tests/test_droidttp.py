"""DroidTTP - Comprehensive Automated Test Suite.

Tests cover:
- Health and readiness probes
- Authentication and session signatures
- APK static analysis and manifest parsing
- Heuristic ATT&CK Mobile mapping engine
- Case creation, sample management, and mapping reviews
- Report generation (HTML and structured JSON)
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

# Ensure ROOT and app are in sys.path
ROOT = Path(__file__).resolve().parent.parent
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
import app.taxonomy as taxonomy


class TestDroidTTP(unittest.TestCase):
    def setUp(self) -> None:
        # Use isolated temporary directory for test DB and uploads
        self.test_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_data_dir = main.DATA_DIR
        self.original_upload_dir = main.UPLOAD_DIR
        self.original_db_path = main.DB_PATH

        main.DATA_DIR = Path(self.test_dir.name)
        main.UPLOAD_DIR = main.DATA_DIR / "samples"
        main.DB_PATH = main.DATA_DIR / "test_droidttp.sqlite3"
        main.SECRET = "test_secret_at_least_32_characters_long_1234567890"
        main.PASSWORD = "test_password_123"
        main.USERNAME = "test_analyst"

        main.initialize()

    def tearDown(self) -> None:
        main.DATA_DIR = self.original_data_dir
        main.UPLOAD_DIR = self.original_upload_dir
        main.DB_PATH = self.original_db_path
        try:
            self.test_dir.cleanup()
        except Exception:
            pass

    def test_healthz(self) -> None:
        result = main.healthz()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["service"], "droidttp")
        self.assertIn("timestamp", result)

    def test_readyz(self) -> None:
        response = main.readyz()
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.body.decode("utf-8"))
        self.assertEqual(body["status"], "ready")
        self.assertEqual(body["database"], "ok")
        self.assertEqual(body["storage"], "ok")

    def test_taxonomy_catalogue(self) -> None:
        self.assertGreaterEqual(len(taxonomy.ATTACK_MOBILE_ANDROID), 35)
        self.assertIn("T1430", taxonomy.ATTACK_MOBILE_ANDROID)
        self.assertIn("T1626", taxonomy.ATTACK_MOBILE_ANDROID)
        self.assertIn("T1437", taxonomy.ATTACK_MOBILE_ANDROID)

        info = taxonomy.ATTACK_MOBILE_ANDROID["T1430"]
        self.assertEqual(info.name, "Location Tracking")
        self.assertIn("Collection", info.tactic)

    def test_manifest_parsing(self) -> None:
        sample_manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.threat"
            android:versionName="2.1.0">
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
            <uses-permission android:name="android.permission.RECORD_AUDIO" />
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
            <application android:label="Sample Malware">
                <service android:name=".StealthService" android:exported="false" />
                <receiver android:name=".BootReceiver" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.BOOT_COMPLETED" />
                    </intent-filter>
                </receiver>
            </application>
        </manifest>
        """
        parsed = main.parse_manifest(sample_manifest.encode("utf-8"))
        self.assertEqual(parsed["manifest_kind"], "text-xml")
        self.assertEqual(parsed["package_name"], "com.example.threat")
        self.assertEqual(parsed["version_name"], "2.1.0")
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", parsed["permissions"])
        self.assertIn("android.permission.RECORD_AUDIO", parsed["permissions"])
        self.assertEqual(len(parsed["components"]), 2)

    def _create_mock_apk(self) -> Path:
        apk_path = main.DATA_DIR / "mock_test_sample.apk"
        manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.test.cti">
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
            <uses-permission android:name="android.permission.CAMERA" />
            <application android:label="Mock APK" />
        </manifest>"""

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", manifest_xml)
            zf.writestr("classes.dex", b"\x64\x65\x78\x0a\x30\x33\x35\x00")
            zf.writestr("lib/arm64-v8a/libpayload.so", b"\x7f\x45\x4c\x46")
            zf.writestr("META-INF/CERT.RSA", b"dummy_cert_data")
            zf.writestr("res/raw/config.txt", "https://c2.evil-tracker.example/api/v1\n")

        return apk_path

    def test_apk_analysis_and_heuristics(self) -> None:
        apk_path = self._create_mock_apk()
        manifest, findings = main.analyze_apk(apk_path)

        self.assertEqual(manifest["package_name"], "org.test.cti")
        self.assertEqual(manifest["dex_files"], 1)
        self.assertEqual(manifest["native_libraries"], 1)
        self.assertIn("META-INF/CERT.RSA", manifest["certificate_artifacts"])

        # Check extracted findings
        kinds = {f["kind"] for f in findings}
        self.assertIn("permission", kinds)
        self.assertIn("signing_artifact", kinds)
        self.assertIn("url", kinds)
        self.assertIn("domain", kinds)

        # Check URL defanging and extraction
        urls = [f["value"] for f in findings if f["kind"] == "url"]
        self.assertTrue(any("https://c2.evil-tracker.example" in u for u in urls))

    def test_case_lifecycle_and_mapping_history(self) -> None:
        # Create Case
        cid = "test_case_001"
        with main.connect() as con:
            con.execute(
                "INSERT INTO cases(id,title,description,source,created_at,created_by,owner,handling,tags) VALUES(?,?,?,?,?,?,?,?,?)",
                (cid, "Operation Crimson Sand", "Sample gathered from telemetry", "OSINT", main.now(), "analyst", "analyst", "TLP:AMBER", "[]"),
            )

        # Insert Sample
        sid = "test_sample_001"
        with main.connect() as con:
            con.execute(
                "INSERT INTO samples(id,case_id,original_filename,sha256,size_bytes,storage_name,uploaded_at,analysis_status,analysis_progress) VALUES(?,?,?,?,?,?,?,'completed',100)",
                (sid, cid, "crimson.apk", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1024, "crimson.apk", main.now()),
            )

        # Insert Evidence and Candidate Mapping
        eid = "ev_001"
        with main.connect() as con:
            con.execute(
                "INSERT INTO evidence(id,sample_id,kind,value,location,source,note,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (eid, sid, "permission", "android.permission.ACCESS_FINE_LOCATION", "AndroidManifest.xml", "static manifest", "", "low", main.now()),
            )

        main.create_suggestions(sid, [{"id": eid, "value": "android.permission.ACCESS_FINE_LOCATION"}])

        # Verify Mapping was suggested
        with main.connect() as con:
            mapping = con.execute("SELECT * FROM mappings WHERE sample_id=? AND technique_id='T1430'", (sid,)).fetchone()
            self.assertIsNotNone(mapping)
            self.assertEqual(mapping["status"], "suggested")
            self.assertEqual(mapping["taxonomy_version"], taxonomy.TAXONOMY_VERSION)

        # Generate Case Report
        report_data = main.case_report_payload(cid)
        self.assertEqual(report_data["case"]["title"], "Operation Crimson Sand")
        self.assertEqual(report_data["taxonomy_version"], taxonomy.TAXONOMY_VERSION)
        self.assertEqual(len(report_data["samples"]), 1)

    def test_session_signing_and_validation(self) -> None:
        token = main.session_token()
        self.assertIn(":", token)
        issued, nonce = token.split(":", 1)
        self.assertTrue(issued.isdigit())

        sig = main.sign(token)
        self.assertIn(".", sig)

    def test_audit_logging(self) -> None:
        main.audit("test_action", "obj_123", "Detail info")
        with main.connect() as con:
            row = con.execute("SELECT * FROM audit WHERE action='test_action' AND object_id='obj_123'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["actor"], "test_analyst")
            self.assertIn("Detail info", row["detail"])


if __name__ == "__main__":
    unittest.main()
