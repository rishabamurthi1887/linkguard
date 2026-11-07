"""Tiny in-process ASGI HTTP client for integration tests (no sockets or third-party client)."""
from __future__ import annotations

import asyncio
import json
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


class HttpResponse:
    def __init__(self, status: int, headers: list[tuple[bytes, bytes]], body: bytes):
        self.status_code = status
        self.headers = {}
        self.raw_headers = [(key.decode("latin-1").lower(), value.decode("latin-1")) for key, value in headers]
        for key, value in self.raw_headers:
            self.headers[key] = value
        self.content = body

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class ASGIHttpClient:
    def __init__(self, app, origin: str | None = None):
        self.app = app
        self.origin = origin
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, *, json_body=None, headers: dict[str, str] | None = None) -> HttpResponse:
        return asyncio.run(self._request(method, path, json_body=json_body, headers=headers or {}))

    async def _request(self, method: str, path: str, *, json_body=None, headers: dict[str, str]) -> HttpResponse:
        parsed = urlsplit(path)
        body = b"" if json_body is None else json.dumps(json_body).encode("utf-8")
        outgoing = {key.lower(): value for key, value in headers.items()}
        if json_body is not None:
            outgoing.setdefault("content-type", "application/json")
        if self.origin:
            outgoing.setdefault("origin", self.origin)
        if self.cookies:
            outgoing.setdefault("cookie", "; ".join(f"{name}={value}" for name, value in self.cookies.items()))
        outgoing.setdefault("host", "testserver")
        outgoing.setdefault("content-length", str(len(body)))
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": method.upper(), "scheme": "http",
            "path": parsed.path or "/", "raw_path": (parsed.path or "/").encode("ascii"),
            "query_string": parsed.query.encode("ascii"), "root_path": "",
            "headers": [(key.encode("latin-1"), value.encode("latin-1")) for key, value in outgoing.items()],
            "client": ("127.0.0.1", 49152), "server": ("testserver", 80), "state": {},
        }
        received = False
        messages = []

        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": body, "more_body": False}
            # Starlette's BaseHTTPMiddleware may poll receive while preparing its response.
            # Keep the synthetic request channel open until the ASGI app returns.
            await asyncio.sleep(0.001)
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        await asyncio.wait_for(self.app(scope, receive, send), timeout=10)
        start = next(message for message in messages if message["type"] == "http.response.start")
        response_body = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        response = HttpResponse(start["status"], start.get("headers", []), response_body)
        for key, value in response.raw_headers:
            if key == "set-cookie":
                jar = SimpleCookie()
                jar.load(value)
                for name, morsel in jar.items():
                    if morsel["max-age"] == "0" or morsel.value == "":
                        self.cookies.pop(name, None)
                    else:
                        self.cookies[name] = morsel.value
        return response

    def get(self, path: str, *, headers=None):
        return self.request("GET", path, headers=headers)

    def post(self, path: str, *, json_body=None, headers=None):
        return self.request("POST", path, json_body=json_body, headers=headers)

    def delete(self, path: str, *, headers=None):
        return self.request("DELETE", path, headers=headers)
