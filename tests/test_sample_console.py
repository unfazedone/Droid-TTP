from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.cookiejar import CookieJar
from pathlib import Path

import uvicorn

import app.main as main


class TestSampleConsole(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.originals = {
            "DATA_DIR": main.DATA_DIR,
            "UPLOAD_DIR": main.UPLOAD_DIR,
            "DB_PATH": main.DB_PATH,
            "USERNAME": main.USERNAME,
            "PASSWORD": main.PASSWORD,
            "SECRET": main.SECRET,
            "COOKIE_SECURE": main.COOKIE_SECURE,
        }
        main.DATA_DIR = Path(cls.temp_dir.name)
        main.UPLOAD_DIR = main.DATA_DIR / "samples"
        main.DB_PATH = main.DATA_DIR / "droidttp.sqlite3"
        main.USERNAME = "sample_analyst"
        main.PASSWORD = "sample_console_test_password"
        main.SECRET = "sample_console_test_secret_which_is_at_least_32_chars"
        main.COOKIE_SECURE = False

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=cls.port, log_level="error"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{cls.base_url}/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("The sample console test server did not start.")

        cls.cookie_jar = CookieJar()
        cls.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cls.cookie_jar))
        cls._request(
            "/api/login",
            json.dumps({"username": main.USERNAME, "password": main.PASSWORD}).encode(),
            "POST",
            {"Content-Type": "application/json"},
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        for name, value in cls.originals.items():
            setattr(main, name, value)
        cls.temp_dir.cleanup()

    @classmethod
    def _request(cls, path: str, data: bytes | None = None, method: str | None = None, headers: dict | None = None):
        request = urllib.request.Request(
            f"{cls.base_url}{path}",
            data=data,
            method=method,
            headers=headers or {},
        )
        return cls.opener.open(request, timeout=10)

    @staticmethod
    def _valid_apk() -> bytes:
        content = io.BytesIO()
        manifest = b"""<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="org.sample.console" android:versionName="1.2.3">
            <uses-permission android:name="android.permission.INTERNET" />
            <application android:label="Sample Console">
                <activity android:name=".MainActivity" android:exported="true" />
            </application>
        </manifest>"""
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest)
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("assets/hosts.txt", "https://example.test/api")
        return content.getvalue()

    @classmethod
    def _upload(cls, case_id: str, filename: str, contents: bytes):
        boundary = "sample-console-boundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="case_id"\r\n\r\n'
            f"{case_id}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/vnd.android.package-archive\r\n\r\n"
        ).encode() + contents + f"\r\n--{boundary}--\r\n".encode()
        return cls._request(
            "/api/samples",
            body,
            "POST",
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )

    def test_sample_intake_search_inspection_download_export_and_delete(self) -> None:
        cases = json.loads(self._request("/api/cases?state=active").read())
        self.assertEqual(cases["cases"], [])

        with self._request(
            "/api/cases",
            json.dumps({"title": "Sample console flow"}).encode(),
            "POST",
            {"Content-Type": "application/json"},
        ) as response:
            case_id = json.loads(response.read())["id"]

        apk_contents = self._valid_apk()
        with self._upload(case_id, "console_sample.apk", apk_contents) as response:
            sample_id = json.loads(response.read())["id"]

        stored_path = main.UPLOAD_DIR / f"{sample_id}.apk"
        self.assertTrue(stored_path.is_file())
        self.assertEqual(stored_path.read_bytes(), apk_contents)
        with self.assertRaises(urllib.error.HTTPError) as queued_delete:
            self._request(f"/api/samples/{sample_id}", method="DELETE")
        self.assertEqual(queued_delete.exception.code, 409)
        queued_delete.exception.close()
        self.assertTrue(stored_path.is_file())

        with self.assertRaises(urllib.error.HTTPError) as invalid_upload:
            self._upload(case_id, "not_an_apk.apk", b"not a zip archive")
        self.assertEqual(invalid_upload.exception.code, 400)
        self.assertIn("ZIP archive", invalid_upload.exception.read().decode())
        invalid_upload.exception.close()

        worker_env = os.environ.copy()
        worker_env.update({
            "DROIDTTP_PROCESS_ROLE": "worker",
            "DROIDTTP_DATA_DIR": str(main.DATA_DIR),
            "DROIDTTP_ANALYSIS_TIMEOUT_SECONDS": "90",
        })
        worker = subprocess.Popen(
            [sys.executable, "-m", "app.queue_worker"],
            cwd=Path(__file__).resolve().parent.parent,
            env=worker_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        worker_output = b""
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if worker.poll() is not None:
                    break
                with self._request(f"/api/samples/{sample_id}") as response:
                    inspected = json.loads(response.read())
                if inspected["sample"]["analysis_status"] not in ("queued", "running"):
                    break
                time.sleep(0.1)
        finally:
            if worker.poll() is None:
                worker.terminate()
            worker_output = worker.communicate(timeout=5)[0]

        self.assertEqual(
            inspected["sample"]["analysis_status"],
            "completed",
            f"Worker exit={worker.returncode}; output={worker_output.decode('utf-8', 'replace')}",
        )
        self.assertEqual(inspected["sample"]["package_name"], "org.sample.console")
        self.assertIn("android.permission.INTERNET", inspected["analysis"]["permissions"])
        permission = next(item for item in inspected["evidence"] if item["kind"] == "permission")
        with self._request(
            f"/api/evidence/{permission['id']}",
            json.dumps({"note": "Reviewed locally", "confidence": "moderate"}).encode(),
            "PATCH",
            {"Content-Type": "application/json"},
        ):
            pass
        with self._request(f"/api/samples/{sample_id}") as response:
            inspected = json.loads(response.read())
        saved_permission = next(item for item in inspected["evidence"] if item["id"] == permission["id"])
        self.assertEqual(saved_permission["note"], "Reviewed locally")
        self.assertEqual(saved_permission["confidence"], "moderate")

        with self._request("/api/samples?q=org.sample.console") as response:
            self.assertEqual(json.loads(response.read())["samples"][0]["id"], sample_id)
        with self._request(f"/api/samples/{sample_id}/file") as response:
            self.assertEqual(response.read(), apk_contents)
            self.assertIn("console_sample.apk", response.headers["Content-Disposition"])
        with self._request("/api/samples/export.csv") as response:
            inventory = response.read().decode()
        self.assertIn("console_sample.apk", inventory)
        self.assertIn("org.sample.console", inventory)
        with self._request(f"/api/samples/{sample_id}/report.json") as response:
            self.assertEqual(json.loads(response.read())["sample"]["id"], sample_id)
        with self._request(f"/api/samples/{sample_id}/report.html") as response:
            self.assertIn("console_sample.apk", response.read().decode())

        with self._request(f"/api/samples/{sample_id}", method="DELETE") as response:
            self.assertTrue(json.loads(response.read())["deleted"])
        self.assertFalse(stored_path.exists())
        with self.assertRaises(urllib.error.HTTPError) as missing_sample:
            self._request(f"/api/samples/{sample_id}")
        self.assertEqual(missing_sample.exception.code, 404)
        missing_sample.exception.close()

    def test_bundled_dataset_summary_profiles_and_export(self) -> None:
        with self._request("/api/dataset") as response:
            summary = json.loads(response.read())
        self.assertEqual(summary["available"], True)
        self.assertEqual(summary["record_count"], 15_736)
        self.assertEqual(summary["unique_package_count"], 15_475)
        self.assertEqual(
            {item["value"]: item["count"] for item in summary["label_counts"]},
            {"0": 7_803, "1": 7_933},
        )
        self.assertIn("not APK files", summary["analysis_scope"])
        self.assertIn("api_call_count", summary["feature_summary_by_label"]["0"])

        with self._request("/api/dataset/records?label=1&limit=5") as response:
            result = json.loads(response.read())
        self.assertEqual(result["total"], 7_933)
        self.assertEqual(len(result["records"]), 5)
        self.assertTrue(all(record["label"] == "1" for record in result["records"]))
        self.assertNotIn("subject_EMAILADDRESS", result["records"][0]["features"])

        package_name = result["records"][0]["package_name"]
        with self._request(f"/api/dataset/records?q={package_name}&label=1&limit=100") as response:
            filtered = json.loads(response.read())
        self.assertEqual(filtered["total"], 1)

        with self._request(f"/api/dataset/records.csv?q={package_name}&label=1") as response:
            exported = response.read().decode("utf-8")
        self.assertIn(package_name, exported)
        self.assertIn("row_id,package_name,sha256,label", exported)


if __name__ == "__main__":
    unittest.main()
