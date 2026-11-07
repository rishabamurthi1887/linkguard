"""HTTP-level auth, ownership, and CORS tests using the real FastAPI ASGI stack."""
import hashlib
import json
import sqlite3
import unittest
import uuid
from contextlib import closing
from unittest.mock import patch
from pathlib import Path

import app.main as linkguard
from tests.asgi_http_client import ASGIHttpClient


ALLOWED_ORIGIN = "http://127.0.0.1:8000"
BLOCKED_ORIGIN = "https://not-allowed.invalid"


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.old_db = linkguard.DB_PATH
        self.old_urlhaus = linkguard.URLHAUS_AUTH_KEY
        self.old_webrisk = linkguard.WEBRISK_API_KEY
        self.db_path = Path(__file__).parent / f".http-test-{uuid.uuid4().hex}.db"
        linkguard.DB_PATH = self.db_path
        linkguard.URLHAUS_AUTH_KEY = ""
        linkguard.WEBRISK_API_KEY = ""
        linkguard.rate_windows.clear()
        linkguard.provider_cache.clear()
        self.client = ASGIHttpClient(linkguard.app, ALLOWED_ORIGIN)

    def tearDown(self):
        linkguard.DB_PATH = self.old_db
        linkguard.URLHAUS_AUTH_KEY = self.old_urlhaus
        linkguard.WEBRISK_API_KEY = self.old_webrisk
        linkguard.rate_windows.clear()
        linkguard.provider_cache.clear()
        if self.db_path.exists():
            self.db_path.unlink()

    def register(self, client, username):
        response = client.post("/api/v1/auth/register", json_body={"username": username, "password": "test-passphrase-123"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn(linkguard.SESSION_COOKIE, client.cookies)
        return response.json()

    def csrf(self, client):
        response = client.get("/api/v1/auth/me")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["csrf_token"]

    def test_register_login_invalid_auth_cookie_and_logout_over_http(self):
        created = self.register(self.client, "http-auth-one")
        cookie_header = next(value for key, value in self.client.cookies.items() if key == linkguard.SESSION_COOKIE)
        self.assertTrue(cookie_header)
        with closing(sqlite3.connect(self.db_path)) as conn:
            stored = conn.execute("SELECT session_hash FROM sessions").fetchone()[0]
        self.assertEqual(stored, hashlib.sha256(cookie_header.encode("ascii")).hexdigest())

        token_header = next(value for key, value in self.client.cookies.items() if key == linkguard.SESSION_COOKIE)
        cookie_response = self.client.post("/api/v1/auth/login", json_body={"username": "HTTP-AUTH-ONE", "password": "test-passphrase-123"})
        self.assertEqual(cookie_response.status_code, 200)
        # Login replaces the browser session token instead of retaining a pre-login token.
        self.assertNotEqual(self.client.cookies[linkguard.SESSION_COOKIE], token_header)
        self.assertEqual(cookie_response.json()["user"]["id"], created["user"]["id"])
        self.assertIn("httponly", cookie_response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", cookie_response.headers["set-cookie"].lower())
        self.assertNotIn("secure", cookie_response.headers["set-cookie"].lower())  # local HTTP mode

        wrong_password = self.client.post("/api/v1/auth/login", json_body={"username": "http-auth-one", "password": "wrong-passphrase"})
        unknown_user = self.client.post("/api/v1/auth/login", json_body={"username": "not-registered", "password": "wrong-passphrase"})
        self.assertEqual((wrong_password.status_code, unknown_user.status_code), (401, 401))
        self.assertEqual(wrong_password.json()["detail"], unknown_user.json()["detail"])
        missing_user = ASGIHttpClient(linkguard.app, ALLOWED_ORIGIN).get("/api/v1/auth/me")
        self.assertEqual(missing_user.status_code, 401)

        csrf = self.csrf(self.client)
        no_csrf = self.client.post("/api/v1/auth/logout")
        self.assertEqual(no_csrf.status_code, 403)
        logged_out = self.client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        self.assertEqual(logged_out.status_code, 200)
        self.assertNotIn(linkguard.SESSION_COOKIE, self.client.cookies)
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 401)

    def test_session_expiration_is_enforced_over_http(self):
        self.register(self.client, "http-expire")
        token = self.client.cookies[linkguard.SESSION_COOKIE]
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("UPDATE sessions SET expires_at=? WHERE session_hash=?", ("2000-01-01T00:00:00+00:00", token_hash))
            conn.commit()
        response = self.client.get("/api/v1/auth/me")
        self.assertEqual(response.status_code, 401)
        with closing(sqlite3.connect(self.db_path)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM sessions WHERE session_hash=?", (token_hash,)).fetchone()[0], 0)

    def test_secure_cookie_flag_is_set_on_http_session_when_enabled(self):
        secure_client=ASGIHttpClient(linkguard.app, ALLOWED_ORIGIN)
        with patch.object(linkguard,"SESSION_COOKIE_SECURE",True):
            response=secure_client.post("/api/v1/auth/register",json_body={"username":"http-secure-cookie","password":"test-passphrase-123"})
        self.assertEqual(response.status_code,200)
        cookie=response.headers["set-cookie"].lower()
        self.assertIn("httponly",cookie)
        self.assertIn("secure",cookie)
        self.assertIn("samesite=strict",cookie)

    def test_csrf_and_account_isolation_through_private_http_endpoints(self):
        alice = ASGIHttpClient(linkguard.app, ALLOWED_ORIGIN)
        bob = ASGIHttpClient(linkguard.app, ALLOWED_ORIGIN)
        alice_account = self.register(alice, "http-alice")
        bob_account = self.register(bob, "http-bob")
        alice_csrf = self.csrf(alice)
        bob_csrf = self.csrf(bob)

        blocked_scan = alice.post("/api/v1/scan/url", json_body={"url": "https://alice.example"})
        self.assertEqual(blocked_scan.status_code, 403)
        scan = alice.post("/api/v1/scan/url", json_body={"url": "https://alice.example"}, headers={"X-CSRF-Token": alice_csrf})
        self.assertEqual(scan.status_code, 200, scan.content)
        report = scan.json()
        self.assertEqual(report["verdict"], "Scan incomplete")
        self.assertIn("not a probability", report["risk_score_label"].lower())
        self.assertEqual(report["confidence"], "Not calibrated")

        alice_history = alice.get("/api/v1/history")
        bob_history = bob.get("/api/v1/history")
        self.assertEqual([item["id"] for item in alice_history.json()["items"]], [report["id"]])
        self.assertEqual(bob_history.json()["items"], [])
        self.assertEqual(alice.get(f"/api/v1/reports/{report['id']}").status_code, 200)
        self.assertEqual(bob.get(f"/api/v1/reports/{report['id']}").status_code, 404)
        cross_delete = bob.delete(f"/api/v1/history/{report['id']}", headers={"X-CSRF-Token": bob_csrf})
        self.assertEqual(cross_delete.status_code, 404)
        self.assertEqual(alice.get(f"/api/v1/reports/{report['id']}").status_code, 200)

        deleted = alice.delete("/api/v1/auth/account", headers={"X-CSRF-Token": alice_csrf})
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(alice.get("/api/v1/auth/me").status_code, 401)
        self.assertEqual(bob.get("/api/v1/auth/me").json()["user"]["id"], bob_account["user"]["id"])
        self.assertNotEqual(alice_account["user"]["id"], bob_account["user"]["id"])

    def test_allowed_and_disallowed_cors_preflight_and_credentials(self):
        self.register(self.client, "cors-test")
        allowed = ASGIHttpClient(linkguard.app, ALLOWED_ORIGIN)
        allowed_preflight = allowed.request("OPTIONS", "/api/v1/history", headers={"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "DELETE", "Access-Control-Request-Headers": "X-CSRF-Token"})
        self.assertEqual(allowed_preflight.status_code, 200)
        self.assertEqual(allowed_preflight.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN)
        self.assertEqual(allowed_preflight.headers.get("access-control-allow-credentials"), "true")
        self.assertIn("DELETE", allowed_preflight.headers.get("access-control-allow-methods", ""))
        self.assertIn("x-csrf-token", allowed_preflight.headers.get("access-control-allow-headers", "").lower())

        disallowed = ASGIHttpClient(linkguard.app, BLOCKED_ORIGIN)
        denied_preflight = disallowed.request("OPTIONS", "/api/v1/history", headers={"Origin": BLOCKED_ORIGIN, "Access-Control-Request-Method": "DELETE", "Access-Control-Request-Headers": "X-CSRF-Token"})
        self.assertEqual(denied_preflight.status_code, 400)
        self.assertNotIn("access-control-allow-origin", denied_preflight.headers)

        credentialed = self.client.get("/api/v1/auth/me")
        self.assertEqual(credentialed.status_code, 200)
        self.assertEqual(credentialed.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN)
        self.assertEqual(credentialed.headers.get("access-control-allow-credentials"), "true")
        denied_actual = ASGIHttpClient(linkguard.app, BLOCKED_ORIGIN).get("/api/v1/config")
        self.assertNotIn("access-control-allow-origin", denied_actual.headers)


if __name__ == "__main__":
    unittest.main()
