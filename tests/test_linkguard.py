import io
import json
import sqlite3
import unittest
import uuid
import zipfile
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.error import HTTPError
from urllib.request import Request as HttpRequest
from unittest.mock import patch

from fastapi import HTTPException, Response
from pydantic import ValidationError
from starlette.requests import Request

import app.main as linkguard


class LinkGuardTests(unittest.TestCase):
    def setUp(self):
        self.old_db = linkguard.DB_PATH
        self.old_key = linkguard.URLHAUS_AUTH_KEY
        self.old_webrisk_key = linkguard.WEBRISK_API_KEY
        self.old_secure_cookie = linkguard.SESSION_COOKIE_SECURE
        self.test_db = Path(__file__).parent / f".test-{uuid.uuid4().hex}.db"
        linkguard.DB_PATH = self.test_db
        linkguard.URLHAUS_AUTH_KEY = ""
        linkguard.WEBRISK_API_KEY = ""
        linkguard.provider_cache.clear()
        linkguard.rate_windows.clear()

    def tearDown(self):
        linkguard.DB_PATH = self.old_db
        linkguard.URLHAUS_AUTH_KEY = self.old_key
        linkguard.WEBRISK_API_KEY = self.old_webrisk_key
        linkguard.SESSION_COOKIE_SECURE = self.old_secure_cookie
        linkguard.provider_cache.clear()
        linkguard.rate_windows.clear()
        if self.test_db.exists():
            self.test_db.unlink()

    def test_malformed_host_rejected(self):
        with self.assertRaises(HTTPException) as error:
            linkguard.url_report("not a valid url")
        self.assertEqual(error.exception.status_code, 422)

    def test_private_ip_is_flagged_without_fetch(self):
        report = linkguard.url_report("http://192.168.1.1/login")
        codes = {item["code"] for item in report["evidence"]}
        self.assertIn("nonpublic_ip", codes)
        self.assertFalse(report["external_data_shared"])

    def test_mixed_script_domain_is_flagged_as_a_clue(self):
        report=linkguard.url_report("https://раypal.example/")
        codes={item["code"] for item in report["evidence"]}
        self.assertIn("mixed_script_domain",codes)
        self.assertIn("homograph_pattern",codes)
        self.assertIn("punycode",codes)

    def test_url_normalization_is_local_and_does_not_retain_path_or_query(self):
        with patch.object(linkguard,"urlopen") as network:
            report=linkguard.url_report("HTTPS://PayPal.Example.:443/private/path?access_token=synthetic#fragment")
        self.assertEqual(report["url_normalization"],{"scheme":"https","hostname":"paypal.example","port":None,"idn_encoded":False,"trailing_dot_removed":True})
        self.assertNotIn("private/path",json.dumps(report))
        self.assertNotIn("synthetic",json.dumps(report))
        network.assert_not_called()

    def test_scheme_and_hostname_normalization_rejects_non_web_schemes(self):
        with self.assertRaises(HTTPException) as denied:
            linkguard.url_report("javascript:alert(1)")
        self.assertEqual(denied.exception.status_code,422)
        idn=linkguard.url_report("https://пример.рф/")
        self.assertTrue(idn["url_normalization"]["idn_encoded"])
        self.assertTrue(any(item["code"]=="punycode" for item in idn["evidence"]))
        with self.assertRaises(HTTPException):
            linkguard.url_report("https://example..")

    def test_missing_reputation_never_looks_like_a_clean_verdict(self):
        report = linkguard.url_report("https://ordinary-example.test/")
        self.assertEqual(report["verdict"], "Scan incomplete")
        self.assertEqual(report["scan_status"], "incomplete")
        self.assertIn("not a probability", report["risk_score_label"])

    def test_suspicious_message_explains_rule_based_indicator(self):
        report = linkguard.scan_message(linkguard.MessageRequest(message="Urgent, share your OTP now"), {"id":None})
        self.assertEqual(report["verdict"], "Suspicious")
        self.assertEqual(report["verdict_basis"], "evidence_found")
        self.assertIn("not a probability", report["risk_score_label"])

    def test_message_patterns_include_english_tamil_tanglish_and_hindi_examples(self):
        examples=[("Please share your OTP now","en"),("OTP பகிரவும்","ta"),("OTP share pannunga","tanglish"),("ओटीपी साझा करें","hi")]
        for message,language in examples:
            with self.subTest(language=language):
                report=linkguard.scan_message(linkguard.MessageRequest(message=message),{"id":None})
                otp=next(item for item in report["evidence"] if item["code"]=="otp")
                self.assertIn(language,otp["language_hints"])

    def test_taxonomy_marks_unimplemented_categories_honestly(self):
        taxonomy = linkguard.scam_categories()
        self.assertEqual(taxonomy["version"], "1.0.0")
        unknown = next(item for item in taxonomy["categories"] if item["id"] == "unknown_emerging")
        self.assertEqual(unknown["detection_status"], "not_implemented")

    def request_with_headers(self, headers=()):
        return Request({"type":"http","asgi":{"version":"3.0"},"http_version":"1.1","method":"POST","scheme":"http","path":"/api/v1/test","raw_path":b"/api/v1/test","query_string":b"","headers":list(headers),"client":("testclient",1234),"server":("testserver",80)})

    def register_test_user(self, username):
        response = Response()
        result = linkguard.register(linkguard.CredentialsRequest(username=username,password="test-password-long-123"),self.request_with_headers(),response)
        cookie = SimpleCookie(); cookie.load(response.headers["set-cookie"])
        token = cookie[linkguard.SESSION_COOKIE].value
        return result, token

    def test_password_hash_and_session_cookie_security(self):
        password = "a-long-test-password-123"
        encoded = linkguard.hash_password(password)
        self.assertNotIn(password, encoded)
        self.assertTrue(linkguard.verify_password(password, encoded))
        self.assertFalse(linkguard.verify_password("wrong-password", encoded))
        result, token = self.register_test_user("secure.user")
        self.assertEqual(len(token), 43)
        with linkguard.db_connection() as conn:
            self.assertNotIn(token, {row["session_hash"] for row in conn.execute("SELECT session_hash FROM sessions")})
        request = self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={token}".encode()),(b"x-csrf-token",result["csrf_token"].encode())])
        user = linkguard.authenticated_user(request)
        self.assertEqual(user["username"],"secure.user")
        self.assertEqual(linkguard.authenticated_write(request,user)["id"],user["id"])
        with self.assertRaises(HTTPException) as csrf_error:
            linkguard.authenticated_write(self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={token}".encode())]),user)
        self.assertEqual(csrf_error.exception.status_code,403)

    def test_registration_login_rotate_session_and_logout_invalidate_it(self):
        registration, first_token = self.register_test_user("rotate-session")
        login_response = Response()
        preexisting_cookie=self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={first_token}".encode())])
        login_result = linkguard.login(linkguard.CredentialsRequest(username="ROTATE-SESSION",password="test-password-long-123"),preexisting_cookie,login_response)
        login_cookie=SimpleCookie(); login_cookie.load(login_response.headers["set-cookie"])
        second_token=login_cookie[linkguard.SESSION_COOKIE].value
        self.assertNotEqual(first_token,second_token)
        self.assertEqual(login_result["user"]["id"],registration["user"]["id"])
        user=linkguard.authenticated_user(self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={second_token}".encode())]))
        logout_request=self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={second_token}".encode()),(b"x-csrf-token",login_result["csrf_token"].encode())])
        logout_response=Response()
        self.assertTrue(linkguard.logout(logout_request,logout_response,user)["logged_out"])
        with self.assertRaises(HTTPException) as expired:
            linkguard.authenticated_user(self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={second_token}".encode())]))
        self.assertEqual(expired.exception.status_code,401)

    def test_login_rejects_unknown_user_and_wrong_password_with_same_message(self):
        self.register_test_user("generic-login")
        errors=[]
        for username,password in (("generic-login","wrong-password-123"),("no-such-user","wrong-password-123")):
            with self.assertRaises(HTTPException) as denied:
                linkguard.login(linkguard.CredentialsRequest(username=username,password=password),self.request_with_headers(),Response())
            self.assertEqual(denied.exception.status_code,401)
            errors.append(denied.exception.detail)
        self.assertEqual(errors[0],errors[1])

    def test_private_routes_require_authenticated_dependencies(self):
        private_paths={"/api/v1/auth/me","/api/v1/auth/logout","/api/v1/auth/account","/api/v1/scan/url","/api/v1/scan/bulk","/api/v1/scan/message","/api/v1/scan/qr","/api/v1/scan/file","/api/v1/history","/api/v1/reports/{report_id}","/api/v1/history/{scan_id}"}
        routes={route.path:route for route in linkguard.app.routes if getattr(route,"path",None) in private_paths}
        self.assertEqual(set(routes),private_paths)
        def contains_auth(dependency):
            if dependency.call in (linkguard.authenticated_user,linkguard.authenticated_write): return True
            return any(contains_auth(child) for child in dependency.dependencies)
        for path,route in routes.items():
            with self.subTest(path=path): self.assertTrue(any(contains_auth(dep) for dep in route.dependant.dependencies))

    def test_session_expiry_and_secure_cookie_attribute(self):
        with patch.object(linkguard,"SESSION_COOKIE_SECURE",True):
            response=Response()
            result=linkguard.register(linkguard.CredentialsRequest(username="secure-cookie",password="test-password-long-123"),self.request_with_headers(),response)
        cookie=response.headers["set-cookie"].lower()
        parsed_cookie=SimpleCookie(); parsed_cookie.load(response.headers["set-cookie"])
        token=parsed_cookie[linkguard.SESSION_COOKIE].value
        self.assertIn("httponly",cookie)
        self.assertIn("secure",cookie)
        self.assertIn("samesite=strict",cookie)
        with linkguard.db_connection() as conn:
            conn.execute("UPDATE sessions SET expires_at=? WHERE session_hash=?",("2000-01-01T00:00:00+00:00",linkguard.session_token_hash(token)))
        with self.assertRaises(HTTPException) as expired:
            linkguard.authenticated_user(self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={token}".encode())]))
        self.assertEqual(expired.exception.status_code,401)

    def test_auth_origin_validation(self):
        request=self.request_with_headers([(b"origin",b"https://attacker.example")])
        with self.assertRaises(HTTPException) as denied:
            linkguard.register(linkguard.CredentialsRequest(username="origin-test",password="test-password-long-123"),request,Response())
        self.assertEqual(denied.exception.status_code,403)

    def test_registration_and_login_input_validation(self):
        invalid_inputs=({"username":"ab","password":"test-password-long-123"},{"username":"has space","password":"test-password-long-123"},{"username":"valid-name","password":"short"},{"username":"valid-name","password":"x"*129})
        for payload in invalid_inputs:
            with self.subTest(payload={"username":payload["username"]}):
                with self.assertRaises(ValidationError): linkguard.CredentialsRequest(**payload)

    def test_auth_rate_limit_blocks_ninth_attempt_from_same_client(self):
        outcomes=[linkguard.rate_limited("synthetic-client",True,now=100.0+index) for index in range(9)]
        self.assertEqual(outcomes,[False]*8+[True])
        self.assertFalse(linkguard.rate_limited("synthetic-client",True,now=161.1))

    def test_cross_user_reports_history_and_delete_are_isolated(self):
        first,_ = self.register_test_user("user-one")
        second,_ = self.register_test_user("user-two")
        report = linkguard.url_report("https://example.test/a",user_id=first["user"]["id"])
        self.assertEqual(linkguard.history(50,{"id":second["user"]["id"]})["items"],[])
        with self.assertRaises(HTTPException) as read_error:
            linkguard.get_report(report["id"],{"id":second["user"]["id"]})
        self.assertEqual(read_error.exception.status_code,404)
        with self.assertRaises(HTTPException) as delete_error:
            linkguard.delete_scan(report["id"],{"id":second["user"]["id"]})
        self.assertEqual(delete_error.exception.status_code,404)

    def test_account_deletion_removes_sessions_and_reports(self):
        registration,token = self.register_test_user("delete-me")
        other,_ = self.register_test_user("keep-me")
        user_id = registration["user"]["id"]
        other_report=linkguard.url_report("https://other-user.test/",user_id=other["user"]["id"])
        report = linkguard.url_report("https://example.test/a",user_id=user_id)
        request = self.request_with_headers([(b"cookie",f"{linkguard.SESSION_COOKIE}={token}".encode())])
        result = linkguard.delete_account(request,Response(),{"id":user_id})
        self.assertTrue(result["account_deleted"])
        with linkguard.db_connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM scans WHERE user_id=?",(user_id,)).fetchone()[0],0)
            self.assertEqual(conn.execute("SELECT count(*) FROM sessions WHERE user_id=?",(user_id,)).fetchone()[0],0)
            self.assertEqual(conn.execute("SELECT count(*) FROM users WHERE id=?",(user_id,)).fetchone()[0],0)
            self.assertEqual(conn.execute("SELECT count(*) FROM scans WHERE user_id=? AND id=?",(other["user"]["id"],other_report["id"])).fetchone()[0],1)

    def test_scan_history_retention_is_per_account(self):
        first,_=self.register_test_user("retention-a")
        second,_=self.register_test_user("retention-b")
        with linkguard.db_connection() as conn:
            for index in range(500):
                conn.execute("INSERT INTO scans(id,kind,subject,verdict,created_at,report,user_id) VALUES(?,?,?,?,?,?,?)",(f"legacy-a-{index}","url","a.test","Scan incomplete",f"2020-01-01T00:{index // 60:02}:{index % 60:02}+00:00","{}",first["user"]["id"]))
            conn.execute("INSERT INTO scans(id,kind,subject,verdict,created_at,report,user_id) VALUES(?,?,?,?,?,?,?)",("keep-b","url","b.test","Scan incomplete","2019-01-01T00:00:00+00:00","{}",second["user"]["id"]))
        linkguard.save("url","new-a.test",{"verdict":"Unable to verify","evidence":[],"checks_unavailable":[],"checks_completed":[]},first["user"]["id"])
        with linkguard.db_connection() as conn:
            count_a=conn.execute("SELECT count(*) FROM scans WHERE user_id=?",(first["user"]["id"],)).fetchone()[0]
            count_b=conn.execute("SELECT count(*) FROM scans WHERE user_id=?",(second["user"]["id"],)).fetchone()[0]
        self.assertEqual(count_a,500)
        self.assertEqual(count_b,1)

    def test_legacy_scan_migration_keeps_unowned_records_private(self):
        legacy_id=str(uuid.uuid4())
        conn=sqlite3.connect(self.test_db)
        conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, verdict TEXT NOT NULL, created_at TEXT NOT NULL, report TEXT NOT NULL)")
        conn.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",(legacy_id,"url","example.test","Scan incomplete","2026-01-01T00:00:00+00:00","{}"))
        conn.commit(); conn.close()
        with linkguard.db_connection() as migrated:
            versions={row[0] for row in migrated.execute("SELECT version FROM schema_migrations")}
            row=migrated.execute("SELECT user_id FROM scans WHERE id=?",(legacy_id,)).fetchone()
        self.assertEqual(versions,{1,2})
        self.assertIsNone(row["user_id"])
        with self.assertRaises(HTTPException) as error:
            linkguard.get_report(legacy_id,{"id":"any-account"})
        self.assertEqual(error.exception.status_code,404)

    def test_provider_requires_key_and_explicit_consent(self):
        report = linkguard.url_report("https://example.com/path", consent_external=True)
        self.assertEqual(report["provider_checks"][0]["status"], "not_configured")
        linkguard.URLHAUS_AUTH_KEY = "test-only-key"
        report = linkguard.url_report("https://example.com/path", consent_external=False)
        self.assertEqual(report["provider_checks"][0]["status"], "consent_required")
        self.assertFalse(report["external_data_shared"])

    def test_sensitive_url_never_sent_to_provider(self):
        linkguard.URLHAUS_AUTH_KEY = "test-only-key"
        with patch.object(linkguard, "_urlhaus_lookup") as lookup:
            report = linkguard.url_report("https://example.com/path?access_token=private", consent_external=True)
        lookup.assert_not_called()
        self.assertEqual(report["provider_checks"][0]["status"], "skipped_sensitive_url")

    def test_webrisk_requires_consent_and_preserves_provider_status(self):
        linkguard.WEBRISK_API_KEY="test-only-key"
        no_consent=linkguard.url_report("https://example.com/path",consent_external=False)
        self.assertEqual(next(item for item in no_consent["provider_checks"] if item["provider"]=="Google Web Risk")["status"],"consent_required")
        result={"status":"match","checked_at":"2026-11-07T00:00:00+00:00","threat_types":["SOCIAL_ENGINEERING"],"expire_time":"2026-11-07T00:10:00+00:00"}
        with patch.object(linkguard,"_webrisk_lookup",return_value=result):
            report=linkguard.url_report("https://example.com/path",consent_external=True)
        check=next(item for item in report["provider_checks"] if item["provider"]=="Google Web Risk")
        self.assertEqual(check["status"],"match")
        self.assertIn("webrisk_match",{item["code"] for item in report["evidence"]})

    def test_webrisk_error_is_not_reported_as_a_no_match(self):
        linkguard.WEBRISK_API_KEY="test-only-key"
        with patch.object(linkguard,"_webrisk_lookup",return_value={"status":"error","reason":"offline"}):
            report=linkguard.url_report("https://example.com/path",consent_external=True)
        check=next(item for item in report["provider_checks"] if item["provider"]=="Google Web Risk")
        self.assertEqual(check["status"],"error")
        self.assertIn("Google Web Risk reputation",report["checks_unavailable"])

    def test_provider_http_match_no_match_invalid_key_and_malformed_responses(self):
        request=HttpRequest("https://provider.example/lookup")
        class FakeResponse:
            status=200
            def __init__(self,body): self.body=body
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def read(self,_limit): return self.body
        with patch.object(linkguard,"urlopen",return_value=FakeResponse(b'{"query_status":"no_results"}')):
            parsed,error=linkguard._request_json(request)
        self.assertEqual(parsed["query_status"],"no_results"); self.assertIsNone(error)
        with patch.object(linkguard,"urlopen",side_effect=HTTPError(request.full_url,401,"invalid key",{},None)),patch.object(linkguard.time,"sleep") as sleeper:
            parsed,error=linkguard._request_json(request)
        self.assertIsNone(parsed); self.assertIsNotNone(error); sleeper.assert_not_called()
        with patch.object(linkguard,"urlopen",return_value=FakeResponse(b'{not-json')):
            parsed,error=linkguard._request_json(request)
        self.assertIsNone(parsed); self.assertIn("unreadable",error)
        linkguard.URLHAUS_AUTH_KEY="test-only-key"
        with patch.object(linkguard,"_request_json",return_value=({"query_status":"ok"},None)):
            result=linkguard._urlhaus_lookup("https://malformed.example")
        self.assertEqual(result["status"],"error")
        linkguard.WEBRISK_API_KEY="test-only-key"
        linkguard.provider_cache.clear()
        with patch.object(linkguard,"_request_json",return_value=({"threat":{"threatTypes":"MALWARE"}},None)):
            result=linkguard._webrisk_lookup("https://malformed.example")
        self.assertEqual(result["status"],"error")

    def test_provider_retry_timeout_and_cache(self):
        request=HttpRequest("https://provider.example/lookup")
        class FakeResponse:
            status=200
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def read(self,_limit): return b'{"query_status":"no_results"}'
        with patch.object(linkguard,"urlopen",side_effect=[TimeoutError("timeout"),FakeResponse()]) as network,patch.object(linkguard.time,"sleep"):
            result,error=linkguard._request_json(request)
        self.assertEqual(result["query_status"],"no_results"); self.assertIsNone(error); self.assertEqual(network.call_count,2)
        linkguard.URLHAUS_AUTH_KEY="test-only-key"
        payload=({"query_status":"no_results"},None)
        with patch.object(linkguard,"_request_json",return_value=payload) as lookup:
            first=linkguard._urlhaus_lookup("https://cached.example")
            second=linkguard._urlhaus_lookup("https://cached.example")
        self.assertFalse(first["cache_hit"]); self.assertTrue(second["cache_hit"]); self.assertEqual(lookup.call_count,1)

    def test_provider_rate_limit_and_unavailable_fail_closed(self):
        request=HttpRequest("https://provider.example/lookup")
        class FakeResponse:
            status=200
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def read(self,_limit): return b'{"query_status":"no_results"}'
        with patch.object(linkguard,"urlopen",side_effect=[HTTPError(request.full_url,429,"rate limited",{},None),FakeResponse()]) as network,patch.object(linkguard.time,"sleep"):
            result,error=linkguard._request_json(request)
        self.assertEqual(result["query_status"],"no_results"); self.assertIsNone(error); self.assertEqual(network.call_count,2)
        with patch.object(linkguard,"urlopen",side_effect=HTTPError(request.full_url,503,"unavailable",{},None)) as network,patch.object(linkguard.time,"sleep"):
            result,error=linkguard._request_json(request)
        self.assertIsNone(result); self.assertIsNotNone(error); self.assertEqual(network.call_count,2)
        linkguard.URLHAUS_AUTH_KEY="test-only-key"
        linkguard.provider_cache.clear()
        with patch.object(linkguard,"_request_json",return_value=(None,"Provider did not respond.")):
            failed=linkguard._urlhaus_lookup("https://unavailable.example")
        self.assertEqual(failed["status"],"error")
        self.assertNotIn("https://unavailable.example",json.dumps(failed))
        with patch.object(linkguard,"_request_json",return_value=(None,"bad")) as lookup:
            linkguard._urlhaus_lookup("https://unavailable.example")
        self.assertEqual(lookup.call_count,1,"provider errors are not cached")

    def test_webrisk_valid_no_match_and_match_response_shapes(self):
        linkguard.WEBRISK_API_KEY="test-only-key"
        with patch.object(linkguard,"_request_json",return_value=({},None)):
            self.assertEqual(linkguard._webrisk_lookup("https://clean.example")["status"],"no_match")
        linkguard.provider_cache.clear()
        with patch.object(linkguard,"_request_json",return_value=({"threat":{"threatTypes":["MALWARE"],"expireTime":"2026-11-08T00:00:00Z"}},None)):
            self.assertEqual(linkguard._webrisk_lookup("https://match.example")["status"],"match")

    def test_urlhaus_match_is_evidence_and_timeline(self):
        linkguard.URLHAUS_AUTH_KEY = "test-only-key"
        result = {"status":"match","checked_at":"2026-11-07T00:00:00+00:00","url_status":"online","threat":"malware_download","reference":"https://urlhaus.abuse.ch/url/1/"}
        with patch.object(linkguard, "_urlhaus_lookup", return_value=result):
            report = linkguard.url_report("https://example.com/path", consent_external=True)
        self.assertEqual(report["verdict"], "High risk")
        self.assertTrue(report["external_data_shared"])
        self.assertTrue(any(item["code"] == "urlhaus_match" for item in report["evidence"]))
        self.assertTrue(report["timeline"])
        self.assertIn("confirmed_threat_match", {item["status"] for item in report["check_statuses"]})

    def test_message_history_redacts_extracted_indicators(self):
        report = linkguard.scan_message(linkguard.MessageRequest(message="Urgent, share OTP at https://example.com and call 12345678901"), {"id":None})
        self.assertTrue(report["extracted_urls"])
        self.assertTrue(report["investigation_graph"]["edges"])
        with linkguard.db_connection() as conn:
            stored = json.loads(conn.execute("SELECT report FROM scans WHERE id=?",(report["id"],)).fetchone()["report"])
        self.assertNotIn("extracted_urls", stored)
        self.assertNotIn("extracted_phone_numbers", stored)
        self.assertNotIn("https://example.com", json.dumps(stored))

    def test_zip_metadata_inspected_without_extraction(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"synthetic")
            archive.writestr("classes.dex", b"synthetic")
            archive.writestr("../escape.txt", b"never extracted")
        class FakeUpload:
            filename = "sample.apk"
            content_type = "application/vnd.android.package-archive"

            async def read(self, size):
                return data.getvalue()

        upload = FakeUpload()
        task = linkguard.scan_file(upload, {"id":None})
        with self.assertRaises(StopIteration) as result:
            task.send(None)
        report = result.exception.value
        self.assertIn("Android package", report["file_type"])
        self.assertTrue(any(item["code"] == "archive_paths" for item in report["evidence"]))
        self.assertIn("without extraction", " ".join(report["checks_completed"]))

    def test_emergency_guidance_has_official_contacts(self):
        data = linkguard.emergency_guides()
        self.assertIn("https://www.cybercrime.gov.in/", data["official_links"]["national_portal"])
        self.assertTrue(any("1930" in " ".join(guide["steps"]) for guide in data["guides"]))

    def test_dataset_splits_are_disjoint_and_evaluator_metrics_are_consistent(self):
        split_root=Path(__file__).parent/"data"
        ids=set(); texts=set()
        for split in ("train","validation","test"):
            for path in (split_root/split).glob("*.jsonl"):
                for line in path.read_text(encoding="utf-8").splitlines():
                    row=json.loads(line)
                    self.assertNotIn(row["id"],ids); ids.add(row["id"])
                    normalized=" ".join(row["text"].casefold().split())
                    self.assertNotIn(normalized,texts); texts.add(normalized)
                    self.assertIn(row["label"],{"scam_like","legitimate_like"})
                    self.assertEqual(row["source"],"synthetic_product_authored")
        from scripts.evaluate_message_rules import score
        metrics=score([{"id":"a","language":"en","category":"x","label":"scam_like","text":"Share your OTP"},{"id":"b","language":"en","category":"x","label":"legitimate_like","text":"Monthly statement available"}])
        self.assertEqual((metrics["tp"],metrics["fp"],metrics["fn"],metrics["tn"]),(1,0,0,1))
        self.assertEqual(metrics["precision"],1.0); self.assertEqual(metrics["recall"],1.0)
        self.assertEqual(metrics["false_positive_rate"],0.0); self.assertEqual(metrics["false_negative_rate"],0.0)


if __name__ == "__main__":
    unittest.main()
