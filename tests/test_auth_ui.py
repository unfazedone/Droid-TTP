import json
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.cookiejar import CookieJar
from pathlib import Path
import uvicorn
from app.main import app, COOKIE_NAME

ROOT = Path(__file__).resolve().parent.parent

class TestAuthAndUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 8998
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.config = uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="error")
        cls.server = uvicorn.Server(cls.config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        # Wait for server to start
        for _ in range(30):
            try:
                with urllib.request.urlopen(f"{cls.base_url}/healthz", timeout=1) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True

    def test_01_static_css_rules(self):
        css_path = ROOT / "app" / "static" / "styles.css"
        content = css_path.read_text(encoding="utf-8")
        
        # Verify [hidden] enforcement with display: none !important
        self.assertIn("[hidden]", content)
        self.assertIn("#loginView[hidden]", content)
        self.assertIn("#appView[hidden]", content)
        self.assertIn("display: none !important;", content)
        
        # Verify body state classes
        self.assertIn("body.unauthenticated", content)
        self.assertIn("overflow: hidden !important;", content)
        self.assertIn("body.authenticated", content)
        self.assertIn("overflow-y: auto", content)
        
        # Verify login-shell fixed positioning and no page-level scroll
        self.assertIn(".login-shell", content)
        self.assertIn("position: fixed;", content)
        self.assertIn("inset: 0;", content)
        self.assertIn("overflow: hidden;", content)
        
        # Verify login-card viewport fit and internal scroll on short screens
        self.assertIn(".login-card", content)
        self.assertIn("max-height: calc(100vh - 40px);", content)
        self.assertIn("overflow-y: auto;", content)
        self.assertIn("overscroll-behavior: contain;", content)
        
        # Verify short viewport media queries
        self.assertIn("@media (max-height:", content)

    def test_02_static_html_structure(self):
        html_path = ROOT / "app" / "static" / "index.html"
        content = html_path.read_text(encoding="utf-8")
        
        # Verify initial body class is unauthenticated
        self.assertIn('<body class="unauthenticated">', content)
        # Verify loginView has hidden by default
        self.assertIn('id="loginView" class="login-shell" hidden', content)
        # Verify appView has hidden by default
        self.assertIn('id="appView" class="app-layout" hidden', content)
        # Verify credentials form inputs
        self.assertIn('id="loginUsername"', content)
        self.assertIn('id="loginPassword"', content)
        self.assertIn('id="loginError"', content)
        self.assertIn('id="logoutBtn"', content)
        self.assertIn('id="overviewDatasetMetrics"', content)
        self.assertIn('id="overviewDatasetLabels"', content)
        self.assertIn('id="overviewDatasetGlance"', content)
        self.assertIn('id="overviewDemoNotice"', content)
        self.assertIn("How do I start an investigation?", content)
        self.assertIn("How do I add an APK?", content)
        self.assertIn("Where can I see sample results?", content)
        self.assertIn("How do I export my work?", content)

    def test_03_static_js_screen_control(self):
        js_path = ROOT / "app" / "static" / "app.js"
        content = js_path.read_text(encoding="utf-8")
        self.assertIn("async function loadOverviewDataset()", content)
        self.assertIn("api('/api/dataset')", content)
        self.assertIn("overview-dataset-glance-value", content)
        self.assertIn("counts: { cases: 2, samples: 3, review: 2, queued: 1 }", content)
        self.assertIn("data.counts.samples === 0", content)
        self.assertIn("data.latest_samples.length === 0", content)
        self.assertIn("overviewDemo.samples.map", content)
        self.assertIn("overviewDemo.reviews.map", content)
        
        # Verify showLogin resets scroll, switches displays, and toggles body classes
        self.assertIn("function showLogin()", content)
        self.assertIn("loginView.hidden = false;", content)
        self.assertIn("loginView.style.display = 'flex';", content)
        self.assertIn("appView.hidden = true;", content)
        self.assertIn("appView.style.display = 'none';", content)
        self.assertIn("document.body.classList.add('unauthenticated');", content)
        self.assertIn("document.body.classList.remove('authenticated');", content)
        self.assertIn("window.scrollTo(0, 0);", content)
        
        # Verify showApp resets scroll, switches displays, and toggles body classes
        self.assertIn("function showApp()", content)
        self.assertIn("loginView.hidden = true;", content)
        self.assertIn("loginView.style.display = 'none';", content)
        self.assertIn("appView.hidden = false;", content)
        self.assertIn("appView.style.display = 'flex';", content)
        self.assertIn("document.body.classList.remove('unauthenticated');", content)
        self.assertIn("document.body.classList.add('authenticated');", content)
        
        # Verify session expiry 401 handling resets session and redirects to login
        self.assertIn("if (response.status === 401)", content)
        self.assertIn("state.session = null;", content)
        self.assertIn("showLogin();", content)

    def test_04_unauthenticated_session_check(self):
        # Client without cookie checks /api/session
        req = urllib.request.Request(f"{self.base_url}/api/session")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            self.assertEqual(data["authenticated"], False)
            self.assertIsNone(data["username"])
            self.assertIsNone(data["role"])

    def test_05_login_and_valid_session_refresh(self):
        cookie_jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        
        # Attempt login with correct credentials
        payload = json.dumps({"username": "justayush", "password": "ayush123"}).encode()
        login_req = urllib.request.Request(
            f"{self.base_url}/api/login",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with opener.open(login_req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertTrue(data.get("ok"))
            self.assertEqual(data.get("username"), "justayush")
            
        # Verify session cookie was saved in cookie jar
        cookies = {c.name: c.value for c in cookie_jar}
        self.assertIn(COOKIE_NAME, cookies)
        
        # Simulate browser refresh by querying /api/session with the session cookie
        refresh_req = urllib.request.Request(f"{self.base_url}/api/session")
        with opener.open(refresh_req) as resp:
            self.assertEqual(resp.status, 200)
            session_data = json.loads(resp.read().decode())
            self.assertEqual(session_data["authenticated"], True)
            self.assertEqual(session_data["username"], "justayush")
            self.assertEqual(session_data["role"], "analyst")

    def test_06_sign_out_flow(self):
        cookie_jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        
        # Log in first
        payload = json.dumps({"username": "justayush", "password": "ayush123"}).encode()
        login_req = urllib.request.Request(
            f"{self.base_url}/api/login",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        opener.open(login_req)
        
        # Call logout endpoint
        logout_req = urllib.request.Request(f"{self.base_url}/api/logout", method="POST")
        with opener.open(logout_req) as resp:
            self.assertEqual(resp.status, 200)
            
        # Check session after logout
        check_req = urllib.request.Request(f"{self.base_url}/api/session")
        with opener.open(check_req) as resp:
            session_data = json.loads(resp.read().decode())
            self.assertEqual(session_data["authenticated"], False)
            self.assertIsNone(session_data["username"])

    def test_07_invalid_and_expired_session(self):
        # Tampered or invalid session cookie
        req = urllib.request.Request(
            f"{self.base_url}/api/session",
            headers={"Cookie": f"{COOKIE_NAME}=invalid_payload.bad_signature"}
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            self.assertEqual(data["authenticated"], False)
            self.assertIsNone(data["username"])
            
        # Protected route with invalid cookie returns 401
        protected_req = urllib.request.Request(
            f"{self.base_url}/api/cases",
            headers={"Cookie": f"{COOKIE_NAME}=invalid_payload.bad_signature"}
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(protected_req)
        self.assertEqual(ctx.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
