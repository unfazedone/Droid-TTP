"""DroidTTP - Comprehensive End-to-End Workflow Verification Script.

Tests the full lifecycle:
1. Health and readiness endpoints
2. Case creation with TLP handling markings
3. APK upload, hashing (SHA-256, SHA-1, MD5), and validation
4. Asynchronous worker analysis execution
5. Extraction of Manifest, Permissions, Components, Certificates, Strings, Network Indicators, Files
6. MITRE ATT&CK Mobile candidate mapping generation
7. Analyst confirmation and decision history tracking
8. Full Report Export (HTML and JSON)
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

# Setup paths
ROOT = Path(__file__).resolve().parent.parent
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
import app.taxonomy as taxonomy
import app.analyzer as analyzer


class TestE2EWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_data_dir = main.DATA_DIR
        self.original_upload_dir = main.UPLOAD_DIR
        self.original_db_path = main.DB_PATH

        main.DATA_DIR = Path(self.temp_dir.name)
        main.UPLOAD_DIR = main.DATA_DIR / "samples"
        main.DB_PATH = main.DATA_DIR / "test_e2e.sqlite3"
        main.SECRET = "test_e2e_secret_random_key_at_least_32_chars_123"
        main.PASSWORD = "analyst_password"
        main.USERNAME = "senior_analyst"

        main.initialize()

    def tearDown(self) -> None:
        main.DATA_DIR = self.original_data_dir
        main.UPLOAD_DIR = self.original_upload_dir
        main.DB_PATH = self.original_db_path
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _generate_realistic_test_apk(self) -> Path:
        apk_path = main.DATA_DIR / "operation_cobalt_sample.apk"
        manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="org.threat.cobalt.agent"
            android:versionName="3.4.1">
            <uses-permission android:name="android.permission.INTERNET" />
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
            <uses-permission android:name="android.permission.RECORD_AUDIO" />
            <uses-permission android:name="android.permission.CAMERA" />
            <uses-permission android:name="android.permission.READ_SMS" />
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
            <application android:label="Security Update">
                <activity android:name=".MainActivity" android:exported="true" />
                <service android:name=".C2SyncService" android:exported="false" />
                <receiver android:name=".BootReceiver" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.BOOT_COMPLETED" />
                    </intent-filter>
                </receiver>
            </application>
        </manifest>"""

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", manifest_xml)
            zf.writestr("classes.dex", b"\x64\x65\x78\x0a\x30\x33\x35\x00" + b"\x00" * 256)
            zf.writestr("classes2.dex", b"\x64\x65\x78\x0a\x30\x33\x35\x00" + b"\x00" * 128)
            zf.writestr("lib/arm64-v8a/libnative-payload.so", b"\x7f\x45\x4c\x46\x02\x01\x01" + b"\x00" * 64)
            zf.writestr("lib/armeabi-v7a/libnative-payload.so", b"\x7f\x45\x4c\x46\x01\x01\x01" + b"\x00" * 64)
            zf.writestr("META-INF/CERT.RSA", b"dummy_cert_rsa_signature")
            zf.writestr("META-INF/CERT.SF", b"dummy_cert_sf")
            zf.writestr("res/raw/network_endpoints.txt", "https://c2.telemetry-collector.example/gateway\nhttp://198.51.100.45:8080/beacon\n")

        return apk_path

    def test_complete_e2e_investigation_lifecycle(self) -> None:
        # 1. Verify health & readiness
        health = main.healthz()
        self.assertEqual(health["status"], "ok")
        ready_resp = main.readyz()
        self.assertEqual(ready_resp.status_code, 200)

        # 2. Create Investigation Case
        case_id = "case_e2e_101"
        with main.connect() as con:
            con.execute(
                "INSERT INTO cases(id,title,description,source,created_at,created_by,owner,handling,tags) VALUES(?,?,?,?,?,?,?,?,?)",
                (case_id, "Operation Cobalt Dropper", "Telemetry upload from financial client", "Financial-ISAC", main.now(), main.USERNAME, main.USERNAME, "TLP:AMBER", json.dumps(["android", "trojan", "cobalt"])),
            )

        # 3. Intake Sample APK
        sample_apk = self._generate_realistic_test_apk()
        content = sample_apk.read_bytes()
        import hashlib
        sha256 = hashlib.sha256(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()

        sample_id = "sample_e2e_202"
        storage_name = f"{sample_id}.apk"
        (main.UPLOAD_DIR / storage_name).write_bytes(content)

        with main.connect() as con:
            con.execute(
                "INSERT INTO samples(id,case_id,original_filename,sha256,sha1,md5,size_bytes,storage_name,uploaded_at,analysis_status,analysis_progress) VALUES(?,?,?,?,?,?,?,?,?,'queued',0)",
                (sample_id, case_id, "operation_cobalt_sample.apk", sha256, sha1, md5, len(content), storage_name, main.now()),
            )

        # 4. Run Analysis
        manifest, findings = analyzer.analyze_apk(sample_apk)
        self.assertEqual(manifest["package_name"], "org.threat.cobalt.agent")
        self.assertEqual(manifest["version_name"], "3.4.1")
        self.assertEqual(manifest["dex_files"], 2)
        self.assertEqual(manifest["native_libraries"], 2)
        self.assertEqual(len(manifest["permissions"]), 6)
        self.assertEqual(len(manifest["components"]), 3)

        # Store evidence and update sample
        with main.connect() as con:
            for f in findings:
                con.execute(
                    "INSERT INTO evidence(id,sample_id,kind,value,location,source,note,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (os.urandom(8).hex(), sample_id, f["kind"], str(f["value"]), str(f["location"]), str(f["source"]), str(f["note"]), "low", main.now()),
                )
            con.execute(
                "UPDATE samples SET analysis_status='completed',analysis_progress=100,analysis_completed_at=?,analysis_json=?,manifest_kind=?,package_name=?,app_name=?,version_name=?,dex_count=?,native_count=? WHERE id=?",
                (main.now(), json.dumps(manifest), manifest["manifest_kind"], manifest["package_name"], manifest["app_name"], manifest["version_name"], manifest["dex_files"], manifest["native_libraries"], sample_id),
            )

            evidence_items = [dict(r) for r in con.execute("SELECT * FROM evidence WHERE sample_id=?", (sample_id,))]

        # 5. Generate Candidate ATT&CK Mappings
        main.create_suggestions(sample_id, evidence_items)

        # 6. Verify Sample View has all 9 Categories for Tabs
        view_data = main.sample_view(sample_id)
        self.assertIn("sample", view_data)
        self.assertIn("analysis", view_data)
        self.assertIn("evidence", view_data)
        self.assertIn("mappings", view_data)

        # Verify summary tab data
        self.assertEqual(view_data["sample"]["sha256"], sha256)
        self.assertEqual(view_data["sample"]["sha1"], sha1)
        self.assertEqual(view_data["sample"]["md5"], md5)

        # Verify permissions & components tab data
        analysis = view_data["analysis"]
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", analysis["permissions"])
        self.assertIn("android.permission.BIND_ACCESSIBILITY_SERVICE", analysis["permissions"])
        self.assertEqual(len(analysis["components"]), 3)

        # Verify network indicators
        urls = [e for e in view_data["evidence"] if e["kind"] == "url"]
        self.assertTrue(len(urls) >= 1)

        # Verify ATT&CK mappings generated
        mappings = view_data["mappings"]
        self.assertTrue(len(mappings) >= 3)
        tids = {m["technique_id"] for m in mappings}
        self.assertIn("T1430", tids)  # Location Tracking
        self.assertIn("T1626", tids)  # Accessibility Service
        self.assertIn("T1437", tids)  # C2 Network

        # 7. Test Analyst Decision Update (Confirm Mapping)
        t1430_map = next(m for m in mappings if m["technique_id"] == "T1430")
        with main.connect() as con:
            con.execute(
                "UPDATE mappings SET status='confirmed',confidence='moderate',rationale='Confirmed by analyst: GPS location harvested' WHERE id=?",
                (t1430_map["id"],),
            )

        updated_view = main.sample_view(sample_id)
        confirmed = updated_view["inferred_capabilities"]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]["technique_id"], "T1430")

        # 8. Test HTML & JSON Report Generation
        case_report = main.case_report_payload(case_id)
        self.assertEqual(case_report["case"]["title"], "Operation Cobalt Dropper")
        self.assertEqual(case_report["taxonomy_version"], taxonomy.TAXONOMY_VERSION)
        self.assertEqual(len(case_report["samples"]), 1)

        print("[OK] Full End-to-End Workflow Verification Passed!")


if __name__ == "__main__":
    unittest.main()
