"""Tests for the bounded, scheme-guarded probe client.

Every probe here hits a local http.server on 127.0.0.1, never a remote host.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from huntkit.verify.client import Probe, probe


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server callback name
        if self.path == "/hello":
            body = b"hi"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/big":
            body = b"A" * (1024 * 1024)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: object) -> None:  # silence the test server
        pass


class _Server:
    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def url(self, path: str) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}{path}"


@pytest.fixture
def http_server():
    server = _Server()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_probe_returns_status_body_and_content_type(http_server):
    p = probe(http_server.url("/hello"))
    assert p.status == 200
    assert p.body == "hi"
    assert p.content_type.startswith("text/plain")


def test_probe_caps_the_body_read(http_server):
    p = probe(http_server.url("/big"), max_bytes=16)
    assert p.size <= 16
    assert len(p.body) <= 16


def test_probe_non_http_scheme_is_refused():
    p = probe("file:///etc/passwd")
    assert p.status == 0


def test_probe_transport_error_yields_status_zero():
    p = probe("http://127.0.0.1:1/")
    assert p.status == 0


def test_probe_dataclass_is_frozen():
    import dataclasses

    p = Probe("http://h/", 200, "hi", "text/plain", 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.status = 500  # type: ignore[misc]
