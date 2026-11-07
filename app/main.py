"""LinkGuard API: privacy-aware heuristic checks with no arbitrary URL fetching."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
import uuid
import zipfile
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as HttpRequest, urlopen
from urllib.parse import parse_qsl, unquote, urlsplit

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("LINKGUARD_DB", ROOT / "linkguard.db"))
MAX_FILE_BYTES = int(os.getenv("LINKGUARD_MAX_FILE_BYTES", 10 * 1024 * 1024))
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
WEBRISK_API_KEY = os.getenv("WEBRISK_API_KEY", "").strip()
URLHAUS_TIMEOUT_SECONDS = 4
RATE_LIMIT_PER_MINUTE = int(os.getenv("LINKGUARD_RATE_LIMIT_PER_MINUTE", "30"))
SESSION_COOKIE_SECURE = os.getenv("LINKGUARD_COOKIE_SECURE", "false").lower() == "true"
SESSION_TTL_SECONDS = int(os.getenv("LINKGUARD_SESSION_TTL_SECONDS", str(24 * 60 * 60)))
SESSION_COOKIE = "linkguard_session"
PASSWORD_SCRYPT_N = 2**14
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("LINKGUARD_CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if origin.strip()]
rate_windows: dict[str, deque[float]] = defaultdict(deque)
rate_lock = threading.Lock()
provider_cache: dict[str, tuple[float, dict]] = {}
provider_health: dict[str, dict] = {}
provider_health_lock = threading.Lock()
app = FastAPI(title="LinkGuard", version="2.2.0", description="Evidence-led scam checks. Submitted URLs are never fetched.")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"], expose_headers=["X-Request-ID"])

def rate_limited(remote: str, is_auth: bool, now: float | None = None) -> bool:
    now = time.monotonic() if now is None else now
    key = remote + ("|auth" if is_auth else "|scan")
    limit = 8 if is_auth else RATE_LIMIT_PER_MINUTE
    with rate_lock:
        window = rate_windows[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
    return False

@app.middleware("http")
async def safety_headers_and_local_rate_limit(request: Request, call_next):
    request_id = uuid.uuid4().hex
    if request.url.path.startswith(("/api/v1/scan/", "/api/v1/auth/login", "/api/v1/auth/register")):
        remote = request.client.host if request.client else "unknown"
        is_auth = request.url.path.startswith("/api/v1/auth/")
        if rate_limited(remote, is_auth):
            from fastapi.responses import JSONResponse
            response = JSONResponse(status_code=429, content={"detail":"Too many requests. Wait a minute and try again.","request_id":request_id})
            response.headers["Retry-After"] = "60"
            return _secure_headers(response, request_id)
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_FILE_BYTES + 1024 * 1024:
        from fastapi.responses import JSONResponse
        return _secure_headers(JSONResponse(status_code=413, content={"detail":"Request body is larger than the allowed limit.","request_id":request_id}), request_id)
    try:
        response = await call_next(request)
    except Exception:
        from fastapi.responses import JSONResponse
        response = JSONResponse(status_code=500, content={"detail":"The request could not be completed.","request_id":request_id})
    return _secure_headers(response, request_id)

def _secure_headers(response, request_id: str):
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: blob:; font-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    return response

SCAMS = [
    {"id":"upi_collect","name":"Unexpected UPI collect request","warning":"A collect request asks you to approve sending money. Receiving money does not require entering your UPI PIN.","action":"Decline unexpected requests. Never enter your UPI PIN to receive money.","updated":"2026-11-06","source":"LinkGuard safety guidance; verify against official NPCI guidance before publication."},
    {"id":"otp","name":"OTP or account takeover","warning":"A caller or message asks for an OTP, PIN, password, or screen-sharing access.","action":"Do not share OTPs or PINs, even with someone claiming to be support." ,"updated":"2026-11-06","source":"LinkGuard safety guidance."},
    {"id":"kyc","name":"Urgent KYC or account block threat","warning":"A message threatens immediate account suspension and pushes you to use its link or call its number.","action":"Open the official app independently or call the number on your bank card." ,"updated":"2026-11-06","source":"LinkGuard safety guidance."},
    {"id":"job_fee","name":"Job offer with an advance fee","warning":"A recruiter asks for a registration, training, equipment, or interview fee before a real hiring process.","action":"Verify the employer through its official careers page; do not pay to secure an offer." ,"updated":"2026-11-06","source":"LinkGuard safety guidance."},
    {"id":"apk","name":"Unknown APK installation","warning":"A message asks you to install an APK to receive a refund, delivery, job, or support.","action":"Do not install apps sent as message attachments. Use the official app store." ,"updated":"2026-11-06","source":"LinkGuard safety guidance."},
]

def load_taxonomy() -> dict:
    try:
        return json.loads((ROOT / "app" / "scam_taxonomy.v1.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version":"1.0.0","categories":SCAMS,"warning":"Versioned taxonomy data could not be loaded."}

class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    consent_external: bool = False

class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20000)

class BulkRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=25)

class CredentialsRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, verdict TEXT NOT NULL, created_at TEXT NOT NULL, report TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    apply_migrations(conn)
    return conn

def apply_migrations(conn: sqlite3.Connection) -> None:
    applied={row["version"] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    if 1 not in applied:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS sessions (session_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)")
        conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)",(utcnow(),))
    if 2 not in applied:
        columns={row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "user_id" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE CASCADE")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (2, ?)",(utcnow(),))

@contextmanager
def db_connection():
    connection = db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=PASSWORD_SCRYPT_N, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return f"scrypt${PASSWORD_SCRYPT_N}$8$1${salt.hex()}${digest.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "scrypt":
            return False
        calculated = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(digest_hex)), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(calculated.hex(), digest_hex)
    except (ValueError, TypeError):
        return False

def session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()

def set_session(response: Response, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = datetime.fromtimestamp(now.timestamp() + SESSION_TTL_SECONDS, timezone.utc).isoformat(timespec="seconds")
    with db_connection() as conn:
        conn.execute("INSERT INTO sessions(session_hash, csrf_token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)", (session_token_hash(token), csrf_token, user_id, now.isoformat(timespec="seconds"), expires))
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True, secure=SESSION_COOKIE_SECURE, samesite="strict", path="/")
    return csrf_token

def require_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") not in {item.rstrip("/") for item in ALLOWED_ORIGINS}:
        raise HTTPException(403, "This request origin is not allowed.")

def authenticated_user(request: Request) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Sign in to use LinkGuard.")
    with db_connection() as conn:
        row = conn.execute("SELECT users.id, users.username, sessions.csrf_token, sessions.expires_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.session_hash=?", (session_token_hash(token),)).fetchone()
        if row and row["expires_at"] <= utcnow():
            conn.execute("DELETE FROM sessions WHERE session_hash=?", (session_token_hash(token),))
            row = None
    if not row:
        raise HTTPException(401, "Your session has expired. Sign in again.")
    return {"id":row["id"],"username":row["username"],"csrf_token":row["csrf_token"]}

def authenticated_write(request: Request, user: dict = Depends(authenticated_user)) -> dict:
    supplied = request.headers.get("x-csrf-token", "")
    if not supplied or not hmac.compare_digest(supplied, user["csrf_token"]):
        raise HTTPException(403, "Refresh your session security token and try again.")
    return user

def _cached_provider_lookup(provider: str, url: str, lookup) -> dict:
    cache_key = hashlib.sha256((provider + "\0" + url).encode("utf-8")).hexdigest()
    cached = provider_cache.get(cache_key)
    if cached and time.monotonic() - cached[0] < 300:
        result = {**cached[1], "cache_hit": True}
    else:
        result = lookup()
        result.setdefault("checked_at", utcnow())
        result["cache_hit"] = False
        if result.get("status") in {"match", "no_match"}:
            provider_cache[cache_key] = (time.monotonic(), result.copy())
        if len(provider_cache) > 512:
            for key, (created, _) in list(provider_cache.items()):
                if time.monotonic() - created > 300:
                    provider_cache.pop(key, None)
    with provider_health_lock:
        provider_health[provider] = {"status":result.get("status", "error"),"last_checked":result.get("checked_at"),"cache_hit":result.get("cache_hit",False)}
    return result

def _request_json(request: HttpRequest) -> tuple[dict | None, str | None]:
    last_error = "Provider did not respond."
    for attempt in range(2):
        try:
            with urlopen(request, timeout=URLHAUS_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    return None, "Provider returned an unavailable response."
                body = response.read(128 * 1024 + 1)
            if len(body) > 128 * 1024:
                return None, "Provider response exceeded the size limit."
            value = json.loads(body.decode("utf-8"))
            if not isinstance(value, dict):
                return None, "Provider returned an unreadable response."
            return value, None
        except HTTPError as exc:
            last_error = "Provider did not respond."
            if exc.code not in (429, 500, 502, 503, 504) or attempt:
                break
        except (TimeoutError, URLError, OSError):
            last_error = "Provider did not respond."
            if attempt:
                break
        except (ValueError, UnicodeError, json.JSONDecodeError):
            return None, "Provider returned an unreadable response."
        time.sleep(0.15 * (attempt + 1))
    return None, last_error

def _urlhaus_lookup(url: str) -> dict:
    def lookup() -> dict:
        payload = urlencode({"url": url}).encode("ascii")
        request = HttpRequest("https://urlhaus-api.abuse.ch/v1/url/", data=payload, headers={"Auth-Key":URLHAUS_AUTH_KEY,"Content-Type":"application/x-www-form-urlencoded","User-Agent":"LinkGuard/2.2 URL reputation lookup"}, method="POST")
        data, error = _request_json(request)
        if error:
            return {"status":"error","reason":error}
        query_status = data.get("query_status")
        if query_status == "no_results":
            return {"status":"no_match"}
        if query_status == "ok":
            if not isinstance(data.get("url_status"), str) or not data["url_status"].strip() or not isinstance(data.get("threat"), str) or not data["threat"].strip():
                return {"status":"error","reason":"URLhaus returned an unreadable response."}
            return {"status":"match","url_status":data.get("url_status","unknown"),"threat":data.get("threat"),"date_added":data.get("date_added"),"reference":data.get("urlhaus_reference")}
        return {"status":"error","reason":"URLhaus could not complete this lookup."}
    return _cached_provider_lookup("URLhaus",url,lookup)

def _webrisk_lookup(url: str) -> dict:
    def lookup() -> dict:
        query = urlencode({"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],"uri":url,"key":WEBRISK_API_KEY}, doseq=True)
        request = HttpRequest("https://webrisk.googleapis.com/v1/uris:search?" + query, headers={"User-Agent":"LinkGuard/2.2 URL reputation lookup","Accept":"application/json"}, method="GET")
        data, error = _request_json(request)
        if error:
            return {"status":"error","reason":error}
        if "threat" not in data or data.get("threat") is None:
            return {"status":"no_match"}
        threat = data.get("threat")
        if not isinstance(threat, dict):
            return {"status":"error","reason":"Provider returned an unreadable response."}
        if not threat:
            return {"status":"no_match"}
        types = threat.get("threatTypes")
        allowed_types = {"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"}
        if not isinstance(types, list) or not types or any(not isinstance(item, str) or item not in allowed_types for item in types):
            return {"status":"error","reason":"Provider returned an unreadable response."}
        if types:
            return {"status":"match","threat_types":types,"expire_time":threat.get("expireTime")}
        return {"status":"error","reason":"Provider returned an unreadable response."}
    return _cached_provider_lookup("Google Web Risk",url,lookup)

def _add_urlhaus_check(report: dict, candidate: str, parts, host: str, consent_external: bool) -> None:
    if not URLHAUS_AUTH_KEY:
        report["provider_checks"].append({"provider":"URLhaus","status":"not_configured","checked_at":None})
        return
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if not ip.is_global:
            report["provider_checks"].append({"provider":"URLhaus","status":"skipped_nonpublic_address","checked_at":None})
            return
    except ValueError:
        pass
    sensitive_keys = {"token","access_token","auth","authorization","key","api_key","session","code","state","password","secret","signature","sig","otp"}
    query_keys = {key.lower() for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
    if parts.username or parts.password or query_keys.intersection(sensitive_keys):
        report["provider_checks"].append({"provider":"URLhaus","status":"skipped_sensitive_url","checked_at":None})
        return
    if not consent_external:
        report["provider_checks"].append({"provider":"URLhaus","status":"consent_required","checked_at":None})
        return
    lookup_url = parts._replace(fragment="").geturl()
    result = _urlhaus_lookup(lookup_url)
    status = result.get("status")
    check = {"provider":"URLhaus","status":status,"checked_at":result.get("checked_at"),"cache_hit":result.get("cache_hit",False)}
    if status == "match":
        check.update({"url_status":result.get("url_status"),"threat":result.get("threat"),"date_added":result.get("date_added"),"reference":result.get("reference")})
        online = result.get("url_status") == "online"
        report["evidence"].append({"code":"urlhaus_match","title":"URL listed by URLhaus","detail":"URLhaus lists this address as a malware-distribution URL." + (" Its latest status is online." if online else " The listing is not currently confirmed online."),"severity":"high" if online else "medium","source":"URLhaus Community API"})
        report["risk_score"] = max(report["risk_score"], 82 if online else 42)
        report["verdict"] = "High risk" if online else "Suspicious"
        report["summary"] = "URLhaus returned a malware-distribution listing. Check the source and current status before acting."
    elif status == "no_match":
        report["summary"] += " URLhaus returned no matching entry; this does not establish that the address is safe."
    else:
        check["reason"] = result.get("reason")
        report["checks_unavailable"].append("URLhaus reputation")
    report["provider_checks"].append(check)
    if status in ("match", "no_match") and "Threat-intelligence reputation" in report["checks_unavailable"]:
        report["checks_unavailable"].remove("Threat-intelligence reputation")
        report["checks_completed"].append("URLhaus malware URL reputation")
    report["external_data_shared"] = report["external_data_shared"] or (not check["cache_hit"] and status in ("match", "no_match", "error"))

def _add_webrisk_check(report: dict, candidate: str, parts, host: str, consent_external: bool) -> None:
    if not WEBRISK_API_KEY:
        report["provider_checks"].append({"provider":"Google Web Risk","status":"not_configured","checked_at":None})
        return
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        if not literal.is_global:
            report["provider_checks"].append({"provider":"Google Web Risk","status":"skipped_nonpublic_address","checked_at":None})
            return
    except ValueError:
        pass
    sensitive_keys = {"token","access_token","auth","authorization","key","api_key","session","code","state","password","secret","signature","sig","otp"}
    query_keys = {key.lower() for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
    if parts.username or parts.password or query_keys.intersection(sensitive_keys):
        report["provider_checks"].append({"provider":"Google Web Risk","status":"skipped_sensitive_url","checked_at":None})
        return
    if not consent_external:
        report["provider_checks"].append({"provider":"Google Web Risk","status":"consent_required","checked_at":None})
        return
    lookup_url = parts._replace(fragment="").geturl()
    result = _webrisk_lookup(lookup_url)
    status = result.get("status")
    check = {"provider":"Google Web Risk","status":status,"checked_at":result.get("checked_at"),"cache_hit":result.get("cache_hit",False)}
    if status == "match":
        types = result.get("threat_types",[])
        check.update({"threat_types":types,"expire_time":result.get("expire_time")})
        report["evidence"].append({"code":"webrisk_match","title":"Google Web Risk threat-list match","detail":"Google Web Risk returned a match for: " + ", ".join(types) + ". This is a provider warning, not a guarantee about the page's current behavior.","severity":"high","source":"Google Web Risk"})
        report["risk_score"] = max(report["risk_score"],78)
        report["verdict"] = "High risk"
        report["summary"] = "Google Web Risk returned a threat-list match. Review the source and timestamp before acting."
    elif status == "error":
        check["reason"] = result.get("reason")
        report["checks_unavailable"].append("Google Web Risk reputation")
    report["provider_checks"].append(check)
    if status in ("match", "no_match"):
        if "Threat-intelligence reputation" in report["checks_unavailable"]:
            report["checks_unavailable"].remove("Threat-intelligence reputation")
        report["checks_completed"].append("Google Web Risk URL reputation")
    report["external_data_shared"] = report["external_data_shared"] or (not check["cache_hit"] and status in ("match", "no_match", "error"))

def save(kind: str, subject: str, report: dict, user_id: str | None) -> dict:
    scan_id = str(uuid.uuid4())
    report.update({"id": scan_id, "created_at": utcnow()})
    evidence = report.get("evidence", [])
    unavailable = report.get("checks_unavailable", [])
    if report.get("verdict") == "Unable to verify":
        report["verdict"] = "Scan incomplete" if unavailable else "No known threat detected"
    report["scan_status"] = "incomplete" if unavailable else "completed"
    report["verdict_basis"] = (
        "evidence_found" if evidence else
        "checks_unavailable" if unavailable else
        "no_known_match"
    )
    report["risk_score_label"] = "Uncalibrated internal rule indicator; not a probability of fraud."
    report["confidence"] = "Not calibrated"
    evidence_sources = {item.get("source") for item in evidence}
    check_statuses = []
    for check in report.get("checks_completed", []):
        matched = any(source and source.casefold() in check.casefold() for source in evidence_sources)
        check_statuses.append({"check":check,"status":"suspicious_evidence_found" if matched else "completed"})
    for check in unavailable:
        check_statuses.append({"check":check,"status":"unavailable"})
    for provider in report.get("provider_checks", []):
        status = provider.get("status", "unknown")
        if status in {"match", "no_match"}:
            check_status = "confirmed_threat_match" if status == "match" else "completed"
        elif status == "error":
            check_status = "failed"
        else:
            check_status = "unavailable"
        check_statuses.append({"check":provider.get("provider", "Threat intelligence"),"status":check_status,"source_status":status,"checked_at":provider.get("checked_at")})
    report["check_statuses"] = check_statuses
    timeline = []
    for check in report.get("checks_completed", []):
        matched = any(source and source.casefold() in check.casefold() for source in evidence_sources)
        timeline.append({"time":report["created_at"],"step":check,"status":"suspicious_evidence_found" if matched else "completed"})
    for check in report.get("checks_unavailable", []):
        timeline.append({"time":report["created_at"],"step":check,"status":"unavailable"})
    for provider in report.get("provider_checks", []):
        timeline.append({"time":provider.get("checked_at") or report["created_at"],"step":provider["provider"],"status":provider["status"]})
    report["timeline"] = timeline
    persisted = report.copy()
    if kind == "message":
        # Keep report history useful without retaining extracted contact details or links.
        persisted.pop("extracted_urls", None)
        persisted.pop("extracted_phone_numbers", None)
    if kind == "file":
        persisted["submitted"] = "Uploaded file"
    with db_connection() as conn:
        conn.execute("INSERT INTO scans(id, kind, subject, verdict, created_at, report, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (scan_id, kind, subject[:500], report["verdict"], report["created_at"], json.dumps(persisted), user_id))
        conn.execute("DELETE FROM scans WHERE user_id IS ? AND id IN (SELECT id FROM scans WHERE user_id IS ? ORDER BY created_at DESC LIMIT -1 OFFSET 500)", (user_id, user_id))
    return report

def url_report(value: str, consent_external: bool = False, user_id: str | None = None) -> dict:
    raw = value.strip()
    if not raw or len(raw) > 4096:
        raise HTTPException(422, "Enter a URL up to 4,096 characters.")
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        _ = parts.port
    except ValueError:
        raise HTTPException(422, "This URL is malformed. Check the address and try again.")
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise HTTPException(422, "Only web addresses using HTTP or HTTPS can be checked.")
    root_dot_removed = host.endswith(".")
    unicode_host = unicodedata.normalize("NFC", host[:-1] if root_dot_removed else host)
    try:
        ascii_host = unicode_host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise HTTPException(422, "This domain name could not be read safely.")
    if any(ch.isspace() or ord(ch) < 32 for ch in host):
        raise HTTPException(422, "This address contains spaces or control characters in its host name.")
    try:
        ipaddress.ip_address(ascii_host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        domain = ascii_host
        labels = domain.split(".")
        if len(domain) > 253 or not domain or any(
            not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise HTTPException(422, "This does not look like a valid web domain. Check the spelling and try again.")
    evidence: list[dict] = []
    def flag(code: str, title: str, detail: str, severity: str = "medium"):
        evidence.append({"code":code,"title":title,"detail":detail,"severity":severity,"source":"Local URL inspection"})
    confusable_letters = {"а":"a", "е":"e", "о":"o", "р":"p", "с":"c", "х":"x", "у":"y", "і":"i", "ј":"j", "ӏ":"l", "α":"a", "ο":"o", "ρ":"p", "ι":"i", "χ":"x"}
    for label in unicode_host.split("."):
        scripts={script for char in label if char.isalpha() for script in ("Latin" if "LATIN" in unicodedata.name(char,"") else "Cyrillic" if "CYRILLIC" in unicodedata.name(char,"") else "Greek" if "GREEK" in unicodedata.name(char,"") else "Other",)}
        if len(scripts.intersection({"Latin","Cyrillic","Greek"})) > 1:
            flag("mixed_script_domain","Mixed-script domain label","This domain label mixes Latin, Cyrillic, or Greek letters that can look similar. Confirm its spelling carefully.","medium")
            if any(char in confusable_letters for char in label) and "Latin" in scripts:
                flag("homograph_pattern","Possible lookalike domain spelling","This label combines Latin letters with Unicode characters commonly used to imitate Latin letters. This heuristic can flag legitimate names and is not proof of impersonation.","medium")
            break
    try:
        ip = ipaddress.ip_address(ascii_host.strip("[]"))
        flag("ip_host", "Address uses an IP number", "The web address points directly to an IP address instead of a recognisable domain.", "high")
        if not ip.is_global:
            flag("nonpublic_ip", "Non-public network address", "This address resolves to a reserved or non-public IP literal. LinkGuard did not connect to it.", "high")
    except ValueError:
        pass
    if parts.username or parts.password:
        flag("userinfo", "Login-like text before the domain", "The address includes user information before its host, a pattern sometimes used to disguise the destination.", "high")
    if "xn--" in ascii_host:
        flag("punycode", "Internationalised domain encoding", "The domain uses Punycode. This can be legitimate, but inspect the spelling carefully.", "medium")
    if root_dot_removed:
        flag("root_dot_normalized", "Trailing domain dot normalized", "The hostname ended with a DNS root dot; LinkGuard removed it for local comparison. This is usually valid URL syntax.", "low")
    if len(ascii_host.split(".")) > 4:
        flag("deep_subdomain", "Many subdomain levels", "The address has several subdomain levels. Confirm the actual registrable domain before trusting it.", "low")
    shorteners = {"bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rebrand.ly","shorturl.at"}
    if ascii_host in shorteners:
        flag("shortener", "Shortened link", "The final destination is hidden. LinkGuard does not follow redirects, so the destination remains unknown.", "medium")
    suspicious_terms = {"login":"Sign-in language in the address", "verify":"Verification language in the address", "secure":"Security language in the address", "update":"Account update language in the address", "wallet":"Wallet/payment language in the address", "claim":"Claim or reward language in the address"}
    lower = unquote(candidate).lower()
    matches = [label for word,label in suspicious_terms.items() if word in lower]
    if matches:
        flag("sensitive_terms", "Sensitive-action wording", "Address contains: " + ", ".join(matches) + ". This is only a clue, not proof of fraud.", "low")
    if not parts.scheme.lower() == "https":
        flag("no_https", "Connection is not HTTPS", "The address uses HTTP, so the connection is not protected by HTTPS.", "medium")
    params = [k.lower() for k,_ in parse_qsl(parts.query, keep_blank_values=True)]
    if any(k in {"redirect","url","next","return","continue","target"} for k in params):
        flag("redirect_param", "Redirect-style parameter", "A query parameter may send visitors to another address. LinkGuard did not follow it.", "low")
    default_port = 80 if parts.scheme.lower() == "http" else 443
    normalized_port = parts.port if parts.port != default_port else None
    normalized_url_details = {"scheme":parts.scheme.lower(),"hostname":ascii_host,"port":normalized_port,"idn_encoded":("xn--" in ascii_host),"trailing_dot_removed":root_dot_removed}
    score = min(100, sum({"low":12,"medium":24,"high":38}[e["severity"]] for e in evidence))
    verdict = "Suspicious" if score >= 12 else "Unable to verify"
    confidence = "Low" if not evidence else "Moderate"
    # Do not retain raw query strings; history stores a redacted subject only.
    safe_host = ascii_host
    report = {"kind":"url","verdict":verdict,"risk_score":score,"confidence":confidence,"summary":"Local checks found indicators that deserve review." if evidence else "Local checks found no listed warning signs. No reputation service was queried, so this address is not confirmed safe.","submitted":safe_host,"url_normalization":normalized_url_details,"evidence":evidence,"checks_completed":["URL syntax, scheme, and normalization","Domain encoding and structure","Common URL warning patterns"],"checks_unavailable":["Threat-intelligence reputation","Redirect destination","DNS and TLS reputation"],"recommended_actions":["Do not enter passwords, one-time codes, or payment details on an unexpected page.","Open the organisation’s official app or type its known website address yourself."],"provider_checks":[],"external_data_shared":False,"limitations":["LinkGuard did not open or fetch this URL.","Redirect and DNS checks are not enabled.","Homograph checks are limited Unicode heuristics and may miss attacks or flag legitimate domains.","No warning signs found does not mean a link is safe."]}
    _add_urlhaus_check(report, candidate, parts, ascii_host, consent_external)
    _add_webrisk_check(report, candidate, parts, ascii_host, consent_external)
    return save("url", safe_host, report, user_id)

@app.get("/api/v1/health")
def health():
    providers = {}
    for name, configured in (("URLhaus",bool(URLHAUS_AUTH_KEY)),("Google Web Risk",bool(WEBRISK_API_KEY))):
        with provider_health_lock:
            state = dict(provider_health.get(name,{}))
        providers[name] = {"configured":configured,"status":state.get("status","unknown" if configured else "not_configured"),"last_checked":state.get("last_checked")}
    return {"status":"ok","version":"2.2.0","external_providers":providers,"url_fetching":False,"authentication_required":True}

@app.get("/api/v1/config")
def public_config():
    disclosure = "The full URL (including path and query, without fragment) is sent only after you opt in. Avoid private or sensitive links."
    return {"authentication_required":True,"providers":{"urlhaus":{"configured":bool(URLHAUS_AUTH_KEY),"name":"URLhaus","data_shared":disclosure,"consent_required":True},"webrisk":{"configured":bool(WEBRISK_API_KEY),"name":"Google Web Risk","data_shared":disclosure,"consent_required":True}},"limits":{"max_file_bytes":MAX_FILE_BYTES,"max_bulk_urls":25}}

@app.post("/api/v1/auth/register")
def register(req: CredentialsRequest, request: Request, response: Response):
    require_origin(request)
    username = req.username.strip().lower()
    user_id = str(uuid.uuid4())
    try:
        with db_connection() as conn:
            conn.execute("INSERT INTO users(id, username, password_hash, created_at) VALUES (?, ?, ?, ?)", (user_id, username, hash_password(req.password), utcnow()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That username is already in use.")
    csrf_token = set_session(response, user_id)
    return {"user":{"id":user_id,"username":username},"csrf_token":csrf_token}

@app.post("/api/v1/auth/login")
def login(req: CredentialsRequest, request: Request, response: Response):
    require_origin(request)
    username = req.username.strip().lower()
    with db_connection() as conn:
        row = conn.execute("SELECT id, username, password_hash FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    if not row:
        hashlib.scrypt(req.password.encode("utf-8"), salt=b"linkguard-dummy!!", n=PASSWORD_SCRYPT_N, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
        raise HTTPException(401, "Username or password is incorrect.")
    if not verify_password(req.password, row["password_hash"]):
        raise HTTPException(401, "Username or password is incorrect.")
    csrf_token = set_session(response, row["id"])
    return {"user":{"id":row["id"],"username":row["username"]},"csrf_token":csrf_token}

@app.get("/api/v1/auth/me")
def auth_me(user: dict = Depends(authenticated_user)):
    return {"user":{"id":user["id"],"username":user["username"]},"csrf_token":user["csrf_token"]}

@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response, user: dict = Depends(authenticated_write)):
    token = request.cookies.get(SESSION_COOKIE, "")
    with db_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE session_hash=? AND user_id=?", (session_token_hash(token), user["id"]))
    response.delete_cookie(SESSION_COOKIE, path="/", secure=SESSION_COOKIE_SECURE, httponly=True, samesite="strict")
    return {"logged_out":True}

@app.delete("/api/v1/auth/account")
def delete_account(request: Request, response: Response, user: dict = Depends(authenticated_write)):
    with db_connection() as conn:
        conn.execute("DELETE FROM scans WHERE user_id=?", (user["id"],))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        conn.execute("DELETE FROM users WHERE id=?", (user["id"],))
    response.delete_cookie(SESSION_COOKIE, path="/", secure=SESSION_COOKIE_SECURE, httponly=True, samesite="strict")
    return {"account_deleted":True,"reports_deleted":True}

@app.get("/api/v1/scam-categories")
def scam_categories(): return load_taxonomy()

@app.get("/api/v1/emergency-guides")
def emergency_guides():
    return {"reviewed_on":"2026-11-07","official_links":{"national_portal":"https://www.cybercrime.gov.in/","npci_upi_safety":"https://www.npci.org.in/what-we-do/upi/faqs"},"guides":[
        {"id":"money_sent","title":"I sent money or approved a payment","urgency":"Act promptly","steps":["Contact your bank or payment app through its official app or independently verified number and report the transaction.","For online financial cyber fraud in India, call the national helpline 1930 and report through the official National Cyber Crime Reporting Portal.","Keep the transaction reference/UTR, time, amount, bank or payment-app name, and relevant screenshots ready.","Do not pay anyone who promises guaranteed recovery of the money."],"sources":["https://www.cybercrime.gov.in/","https://cybercrime.gov.in/webform/Crime_AuthoLogin.aspx"]},
        {"id":"otp_shared","title":"I shared an OTP, password, or UPI PIN","urgency":"Secure the account now","steps":["Contact the bank or service using its official app or a number you independently verify. Ask how to secure or temporarily restrict the affected account.","From a device you trust, change the affected password and sign out sessions if the official service provides that option.","If money moved, call 1930 promptly and report at the official cybercrime portal.","Never share another OTP or UPI PIN with a caller or support agent."],"sources":["https://www.cybercrime.gov.in/","https://www.npci.org.in/what-we-do/upi/faqs"]},
        {"id":"suspicious_app","title":"I installed an app from a message","urgency":"Protect banking access","steps":["Do not open the app again or enter banking credentials into it.","If you suspect remote control, stop using that device for banking and contact your bank from another trusted device.","Ask the device maker or a trusted security professional how to remove it safely. Do not install another cleanup app from a message or advertisement.","If credentials or money may be affected, contact your bank and use the official cybercrime reporting options."],"sources":["https://www.cybercrime.gov.in/","https://www.npci.org.in/fraud-awareness"]},
        {"id":"clicked_link","title":"I opened a suspicious link","urgency":"Check what you entered","steps":["Close the page. Do not download files, approve a payment, or enter more information.","If you entered a password, change it using the official service on a trusted device and contact the service if account access changed.","If you shared payment credentials or money moved, contact your bank immediately and call 1930 for online financial cyber fraud.","Save the message and transaction details if available; do not forward a suspicious link to others."],"sources":["https://www.cybercrime.gov.in/"]},
        {"id":"remote_access","title":"I enabled screen sharing or remote access","urgency":"Stop the access","steps":["End the remote session or call and close the remote-access app if you can do so safely.","Contact your bank from a different trusted device if banking apps or payment details were visible.","Change exposed credentials from a trusted device and ask the official service or device maker for account/device recovery steps.","Report any financial loss through your bank and the official cybercrime channels."],"sources":["https://www.cybercrime.gov.in/","https://www.npci.org.in/fraud-awareness"]},
        {"id":"personal_data","title":"I shared personal or identity information","urgency":"Limit further exposure","steps":["Contact the organisation whose account or document was exposed using its official support channel.","Change affected passwords and secure accounts from a trusted device; do not share new verification codes.","Keep a record of what was shared, when, and with whom. Report suspected cybercrime through the official portal.","If money is involved, contact your bank and call 1930 promptly."],"sources":["https://www.cybercrime.gov.in/"]}
    ]}

@app.post("/api/v1/scan/url")
def scan_url(req: UrlRequest, user: dict = Depends(authenticated_write)): return url_report(req.url, req.consent_external, user["id"])

@app.post("/api/v1/scan/bulk")
def scan_bulk(req: BulkRequest, user: dict = Depends(authenticated_write)):
    results=[]
    for item in req.urls:
        try: results.append({"input":item[:300],"report":url_report(item, user_id=user["id"]),"error":None})
        except HTTPException as exc: results.append({"input":item[:300],"report":None,"error":str(exc.detail)})
    return {"results":results,"count":len(results),"limit":25}

def message_graph(evidence: list[dict], links: list[str], phones: list[str]) -> dict:
    nodes=[{"id":"message","type":"submitted_content","label":"Submitted message"}]
    edges=[]
    for i,item in enumerate(evidence):
        node_id="pattern-"+str(i+1)
        nodes.append({"id":node_id,"type":"observed_pattern","label":item["title"]})
        edges.append({"from":"message","to":node_id,"label":"contains matching phrase"})
    for i,value in enumerate(links[:10]):
        node_id="url-"+hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        nodes.append({"id":node_id,"type":"url_indicator","label":f"URL indicator {i+1}"})
        edges.append({"from":"message","to":node_id,"label":"contains URL text"})
    for i,value in enumerate(phones[:10]):
        node_id="phone-"+hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        nodes.append({"id":node_id,"type":"phone_indicator","label":f"Phone indicator {i+1}"})
        edges.append({"from":"message","to":node_id,"label":"contains phone-like text"})
    return {"nodes":nodes,"edges":edges,"note":"Edges describe only co-occurrence in the submitted text. They do not verify identity, ownership, or a relationship between indicators."}

def analyze_message_text(message: str) -> dict:
    msg=message.strip(); lower=msg.lower(); evidence=[]
    rules=[
      ("otp",{"en":["otp","one time password","verification code","share the code"],"ta":["otp பகிரவும்","otp-ஐ பகிரவும்","ஒரு முறை கடவுச்சொல்"],"tanglish":["otp share pannunga","otp sollunga","code share pannunga"],"hi":["ओटीपी साझा करें","ओटीपी बताएं","सत्यापन कोड साझा"]},"OTP or verification-code wording","Never share a one-time code."),
      ("upi",{"en":["upi pin","collect request","approve payment","receive money"],"ta":["upi pin","பணம் பெற","பணம் அனுப்ப ஒப்புதல்"],"tanglish":["upi pin sollunga","collect request approve","money receive panna pin"],"hi":["यूपीआई पिन","पैसे प्राप्त करने के लिए पिन","पेमेंट अनुरोध स्वीकार"]},"UPI or payment wording","Decline unexpected collect requests; a UPI PIN authorises a payment."),
      ("urgency",{"en":["immediately","within 24 hours","account blocked","will be disconnected","urgent"],"ta":["உடனே","கணக்கு முடக்கப்படும்","இன்றே சரிபார்க்கவும்"],"tanglish":["ippo seyyunga","account block aagum","udane pannunga"],"hi":["तुरंत","खाता बंद हो जाएगा","अभी सत्यापित करें"]},"Urgency or threat wording","Pause and contact the organisation through independently verified details."),
      ("kyc",{"en":["kyc update","kyc expired","complete kyc"],"ta":["kyc புதுப்பிக்க","கேஒய்சி புதுப்பிப்பு"],"tanglish":["kyc update pannunga","kyc expire aagiduchu"],"hi":["केवाईसी अपडेट","केवाईसी समाप्त","केवाईसी पूरा करें"]},"KYC wording","Open your bank’s official app independently."),
      ("fee",{"en":["registration fee","pay a fee","processing fee","training fee"],"ta":["பதிவு கட்டணம்","முன்பணம் செலுத்த"],"tanglish":["registration fee pay","advance fee kudunga"],"hi":["पंजीकरण शुल्क","प्रोसेसिंग फीस","पहले शुल्क जमा"]},"Advance-payment wording","Verify the offer before paying any fee."),
      ("apk",{"en":["install apk","download apk","application file"],"ta":["apk நிறுவ","பயன்பாட்டை நிறுவ"],"tanglish":["apk install pannunga","app download pannunga"],"hi":["एपीके इंस्टॉल","ऐप डाउनलोड करें"]},"App-installation wording","Do not install an APK sent by an unknown sender."),
      ("job",{"en":["work from home","guaranteed income","job offer","daily income"],"ta":["வீட்டிலிருந்து வேலை","உறுதியான வருமானம்"],"tanglish":["work from home job","daily income guarantee"],"hi":["घर से काम","गारंटीड आय","नौकरी का प्रस्ताव"]},"Job or income wording","Verify the employer on its official careers site.")]
    cautionary_context={
      "otp":["never share your otp","do not share your otp","don't share your otp","never share an otp","otp பகிர வேண்டாம்","otp-ஐ பகிர வேண்டாம்","otp share panna koodathu","otp share pannatheenga","ओटीपी साझा न करें","ओटीपी न बताएं"],
      "upi":["never enter your upi pin to receive money","do not share your upi pin","upi pin யாரிடமும் கூற வேண்டாம்","upi pin share pannatheenga","यूपीआई पिन साझा न करें","पैसे पाने के लिए पिन न डालें"]
    }
    for code,terms_by_language,title,action in rules:
        if any(safe_phrase in lower for safe_phrase in cautionary_context.get(code,[])):
            continue
        found=[(language,term) for language,terms in terms_by_language.items() for term in terms if term in lower]
        if found:
            languages=sorted({language for language,_ in found})
            phrases=list(dict.fromkeys(term for _,term in found))
            evidence.append({"code":code,"title":title,"detail":"Matched wording: “"+"”, “".join(phrases)+"”. This wording is a clue, not proof of a scam.","matched_terms":phrases,"language_hints":languages,"severity":"high" if code in ("otp","upi","apk") else "medium","source":"Local phrase matching"})
    links=re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\]\[()]+",msg)
    phones=re.findall(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)",msg)
    score=min(100, sum(30 if x["severity"]=="high" else 18 for x in evidence))
    verdict="Suspicious" if evidence else "Unable to verify"
    report={"kind":"message","verdict":verdict,"risk_score":score,"confidence":"Moderate" if evidence else "Low","summary":f"Found {len(evidence)} warning pattern(s) in the text." if evidence else "No configured warning phrases matched. This message has not been verified as safe.","submitted":"Message text (not stored)","evidence":evidence,"extracted_urls":links,"extracted_phone_numbers":phones,"investigation_graph":message_graph(evidence,links,phones),"scam_context":{"possible_categories":[item["title"] for item in evidence],"demanded_action_cues":[item["code"] for item in evidence],"missing_information":["Sender identity has not been verified.","The organisation or account owner cannot be confirmed from message text alone."]},"checks_completed":["Local scam phrase patterns","URL and phone-number extraction","Observed-only evidence relationship graph"],"checks_unavailable":["Sender identity verification","External reputation checks"],"recommended_actions":["Do not share passwords, one-time codes, or payment PINs.","Verify requests using contact details from the official app or website."],"provider_checks":[],"external_data_shared":False,"limitations":["Rules can miss new scams and may flag legitimate wording.","Sender identity and extracted links were not externally verified."]}
    return report

@app.post("/api/v1/scan/message")
def scan_message(req: MessageRequest, user: dict = Depends(authenticated_write)):
    # Deliberately do not persist raw message contents.
    return save("message", "Message text (redacted)", analyze_message_text(req.message), user["id"])

@app.post("/api/v1/scan/qr")
def scan_qr(req: UrlRequest, user: dict = Depends(authenticated_write)):
    value=req.url.strip()
    if value.lower().startswith("upi://"):
        parts=urlsplit(value); params=dict(parse_qsl(parts.query)); payee=params.get("pa","(not specified)"); name=params.get("pn","(not specified)")
        return save("qr", "UPI payment QR (redacted)", {"kind":"qr","verdict":"Unable to verify","risk_score":0,"confidence":"Low","summary":"This QR contains a UPI payment request. Review recipient and amount in your payment app before approving.","submitted":"UPI payment payload (sensitive fields hidden)","payment_preview":{"payee":payee,"name":name,"amount":params.get("am","not specified"),"currency":params.get("cu","INR")},"evidence":[],"checks_completed":["UPI payload structure"],"checks_unavailable":["Payee identity verification","Payment destination reputation"],"recommended_actions":["Only approve if you initiated the payment and recognise the payee and amount.","Never enter your UPI PIN to receive money."],"external_data_shared":False,"limitations":["LinkGuard cannot confirm that a UPI ID belongs to the named person."]}, user["id"])
    return url_report(value, req.consent_external)

@app.post("/api/v1/scan/file")
async def scan_file(file: UploadFile=File(...), user: dict = Depends(authenticated_write)):
    content=await file.read(MAX_FILE_BYTES+1)
    if len(content)>MAX_FILE_BYTES: raise HTTPException(413, f"File exceeds the {MAX_FILE_BYTES//1024//1024} MB limit.")
    if not content: raise HTTPException(422,"The file is empty.")
    digest=hashlib.sha256(content).hexdigest(); name=(file.filename or "upload").replace("\\","/").rsplit("/",1)[-1]; ext=Path(name).suffix.lower()
    evidence=[]; detected="Unknown / not identified"; details={}; checks=["SHA-256 fingerprint","File signature inspection"]
    if content.startswith(b"%PDF-"):
        detected="PDF document"
    elif content.startswith(b"MZ"):
        detected="Windows executable-like file (MZ header)"
    elif content.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        detected="Image"
    else:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                infos=archive.infolist()
                names=[info.filename.replace("\\","/") for info in infos]
                total_uncompressed=sum(info.file_size for info in infos)
                max_ratio=max((info.file_size/max(info.compress_size,1) for info in infos), default=0)
                details={"archive_entry_count":len(infos),"reported_uncompressed_bytes":total_uncompressed,"contains_android_manifest":"AndroidManifest.xml" in names,"contains_dex":any(n.endswith(".dex") for n in names),"contains_office_macro":any(n.lower().endswith("vbaproject.bin") for n in names)}
                if len(infos)>5000:
                    evidence.append({"code":"archive_entry_count","title":"Archive contains many entries","detail":"The archive lists more than 5,000 entries; this can make safe inspection difficult.","severity":"medium","source":"Local ZIP metadata inspection"})
                if total_uncompressed>200*1024*1024 or max_ratio>200:
                    evidence.append({"code":"archive_expansion","title":"Archive has an unusually large expansion ratio","detail":"The archive metadata reports very large uncompressed content or a compression ratio above 200:1. No files were extracted.","severity":"high","source":"Local ZIP metadata inspection"})
                if any(n.startswith("/") or re.match(r"^[a-zA-Z]:",n) or ".." in n.split("/") for n in names):
                    evidence.append({"code":"archive_paths","title":"Archive includes an unsafe-looking path","detail":"At least one archive entry contains an absolute or parent-directory path. LinkGuard did not extract it.","severity":"high","source":"Local ZIP metadata inspection"})
                checks.append("ZIP central-directory metadata (without extraction)")
                if "AndroidManifest.xml" in names:
                    detected="Android package archive (manifest present; not fully parsed)" if ext==".apk" else "ZIP archive with Android manifest"
                    checks.append("APK container indicators")
                elif "[Content_Types].xml" in names and any(n.startswith("word/") for n in names): detected="Word document archive"
                elif "[Content_Types].xml" in names and any(n.startswith("xl/") for n in names): detected="Excel workbook archive"
                elif "[Content_Types].xml" in names and any(n.startswith("ppt/") for n in names): detected="PowerPoint presentation archive"
                else: detected="ZIP archive"
        except (zipfile.BadZipFile, OSError, ValueError):
            if ext in {".zip",".apk",".docx",".xlsx",".pptx"}:
                evidence.append({"code":"archive_unreadable","title":"Archive structure could not be read","detail":"The filename suggests a ZIP-based format, but its structure could not be inspected.","severity":"medium","source":"Local ZIP metadata inspection"})
    expected={".pdf":"PDF document",".exe":"Windows executable-like file (MZ header)",".zip":"ZIP archive",".apk":"Android package archive (manifest present; not fully parsed)",".docx":"Word document archive",".xlsx":"Excel workbook archive",".pptx":"PowerPoint presentation archive"}
    if ext in expected and detected!=expected[ext]:
        evidence.append({"code":"extension_mismatch","title":"File extension and detected format differ","detail":f"The name ends in {ext}, but the inspected signature indicates {detected}.","severity":"high","source":"Local signature/metadata inspection"})
    mime=file.content_type or "application/octet-stream"
    if detected=="PDF document" and mime not in ("application/pdf","application/octet-stream"):
        evidence.append({"code":"mime_mismatch","title":"Declared MIME type differs from file signature","detail":"The uploaded content starts with a PDF signature, but the browser declared a different media type.","severity":"medium","source":"Local content-type comparison"})
    risk=min(100,sum({"low":12,"medium":24,"high":38}[item["severity"]] for item in evidence))
    report={"kind":"file","verdict":"Suspicious" if evidence else "Unable to verify","risk_score":risk,"confidence":"Low" if not evidence else "Moderate","summary":"Static checks found file-format indicators that deserve review. No malware scan was run." if evidence else "File fingerprint and basic format checks completed. No malware scan was run.","submitted":name,"sha256":digest,"size_bytes":len(content),"declared_mime_type":mime,"file_type":detected,"metadata":details,"evidence":evidence,"checks_completed":checks,"checks_unavailable":["Malware engine scan","Known-bad hash reputation","Full PDF/Office content inspection","APK signing and permission analysis"],"recommended_actions":["Do not open unexpected files or install apps from message attachments.","A hash not found in a database would not prove a file is safe."],"external_data_shared":False,"limitations":["File bytes were processed in memory and not saved.","Archives were inspected from metadata only; no files were extracted.","The file was not executed or scanned by an antivirus engine."]}
    return save("file","Uploaded file",report,user["id"])

@app.get("/api/v1/history")
def history(limit: int=Query(default=50, ge=1, le=100), user: dict = Depends(authenticated_user)):
    with db_connection() as conn: rows=conn.execute("SELECT id,kind,subject,verdict,created_at,report FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ?",(user["id"],limit)).fetchall()
    return {"items":[dict(r)|{"report":json.loads(r["report"])} for r in rows]}

@app.get("/api/v1/reports/{report_id}")
def get_report(report_id: str, user: dict = Depends(authenticated_user)):
    with db_connection() as conn: row=conn.execute("SELECT report FROM scans WHERE id=? AND user_id=?",(report_id,user["id"])).fetchone()
    if not row: raise HTTPException(404,"Report not found.")
    return json.loads(row["report"])

@app.delete("/api/v1/history/{scan_id}")
def delete_scan(scan_id: str, user: dict = Depends(authenticated_write)):
    with db_connection() as conn: cur=conn.execute("DELETE FROM scans WHERE id=? AND user_id=?",(scan_id,user["id"]))
    if not cur.rowcount: raise HTTPException(404,"Scan not found.")
    return {"deleted":True}

@app.delete("/api/v1/history")
def clear_history(user: dict = Depends(authenticated_write)):
    with db_connection() as conn: conn.execute("DELETE FROM scans WHERE user_id=?",(user["id"],))
    return {"deleted":True}

app.mount("/assets",StaticFiles(directory=ROOT/"web"),name="assets")
@app.get("/",include_in_schema=False)
def home(): return FileResponse(ROOT/"web"/"index.html")
