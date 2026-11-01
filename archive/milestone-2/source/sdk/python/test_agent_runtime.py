import http.server
import json
import os
import pathlib
import ssl
import tempfile
import threading
import unittest

from agent_runtime import RuntimeClient

ROOT = pathlib.Path(__file__).resolve().parents[2]
PKI = ROOT / "artifacts"


class ClientTests(unittest.TestCase):
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
