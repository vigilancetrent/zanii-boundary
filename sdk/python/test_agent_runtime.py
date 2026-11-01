import http.server
import json
import os
import pathlib
import ssl
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from agent_runtime import RuntimeClient

ROOT = pathlib.Path(__file__).resolve().parents[2]
PKI = ROOT / "artifacts"


class ClientTests(unittest.TestCase):
    def _client(self, origin, timeout):
        (ROOT / ".test-data").mkdir(exist_ok=True)
        handle, name = tempfile.mkstemp(dir=ROOT / ".test-data", suffix=".jwt")
        os.close(handle)
        token = pathlib.Path(name)
        token.write_text("test.token.value", encoding="ascii")
        os.chmod(token, 0o600)
        self.addCleanup(lambda: token.unlink(missing_ok=True))
        return RuntimeClient(origin=origin, ca_file=PKI / "test-pki-ca.pem", cert_file=PKI / "test-pki-agent-cert.pem",
            key_file=PKI / "test-pki-agent-key.pem", token_file=token, timeout=timeout)

    def test_dns_wait_is_bounded_and_abandoned_os_lookups_have_a_global_capacity(self):
        release = threading.Event()
        original = socket.getaddrinfo

        def slow_lookup(*args, **kwargs):
            release.wait(2)
            return original("127.0.0.1", 443, type=socket.SOCK_STREAM)

        client = self._client("https://gateway", 0.05)
        try:
            with patch("socket.getaddrinfo", slow_lookup):
                for _ in range(2):
                    start = time.monotonic()
                    with self.assertRaisesRegex(TimeoutError, "DNS_LOOKUP_DEADLINE"):
                        client.request("/v1/coverage")
                    self.assertLess(time.monotonic() - start, 0.2)
                with self.assertRaisesRegex(TimeoutError, "DNS_RESOLUTION_CAPACITY"):
                    client.request("/v1/coverage")
        finally:
            release.set()

    def test_slow_response_headers_cannot_extend_the_total_budget_by_dripping_bytes(self):
        class SlowHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}":
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    return

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(PKI / "test-pki-gateway-cert.pem", PKI / "test-pki-gateway-key.pem")
        context.load_verify_locations(PKI / "test-pki-ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = self._client("https://127.0.0.1:" + str(server.server_port), 0.12)
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                client.request("/v1/coverage")
            self.assertLess(time.monotonic() - start, 0.3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_real_mtls_bounds_identity_redirect_and_no_mutation_retry(self):
        effects = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.assert_identity()
                effects.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = b'{"state":"unknown"}'
                self.send_response(202)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://foreign.invalid")
                self.end_headers()

            def assert_identity(self):
                assert self.headers["Authorization"] == "Bearer test.token.value"
                assert self.connection.getpeercert()

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(PKI / "test-pki-gateway-cert.pem", PKI / "test-pki-gateway-key.pem")
        context.load_verify_locations(PKI / "test-pki-ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            handle, name = tempfile.mkstemp(dir=ROOT / ".test-data", suffix=".jwt")
            os.close(handle)
            token = pathlib.Path(name)
            try:
                token.write_text("test.token.value", encoding="ascii")
                os.chmod(token, 0o600)
                client = RuntimeClient(origin="https://127.0.0.1:" + str(server.server_port),
                    ca_file=PKI / "test-pki-ca.pem", cert_file=PKI / "test-pki-agent-cert.pem",
                    key_file=PKI / "test-pki-agent-key.pem", token_file=token)
                self.assertEqual(client.execute("task", {"id": "one"})["status"], 202)
                self.assertEqual(len(effects), 1)
                with self.assertRaisesRegex(ValueError, "TRANSPORT_REDIRECT_DENIED"):
                    client.request("/redirect")
                with self.assertRaisesRegex(ValueError, "INVALID_CLIENT_PATH"):
                    client.request("//foreign.invalid/path")
                token.write_text("bad\r\nheader", encoding="ascii")
                with self.assertRaisesRegex(ValueError, "CLIENT_TOKEN_REQUIRED"):
                    client.execute("task", {})
                self.assertEqual(len(effects), 1)
            finally:
                token.unlink(missing_ok=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
