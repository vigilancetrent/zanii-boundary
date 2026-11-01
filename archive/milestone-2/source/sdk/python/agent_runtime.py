"""Bounded stdlib HTTPS/mTLS client. Mutations are never automatically retried."""
import http.client
import json
import os
import re
import socket
import ssl
import stat
import time
import urllib.parse


def _file(path, secret=False, limit=65536):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > limit:
        raise ValueError("UNSAFE_IDENTITY_FILE")
    if secret and os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("UNSAFE_IDENTITY_PERMISSIONS")
    with open(path, "rb") as source:
        return source.read(limit + 1)


class _UnixHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, socket_path, **kwargs):
        super().__init__(host, **kwargs)
        self.socket_path = socket_path

    def connect(self):
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            raw.connect(self.socket_path)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class RuntimeClient:
    def __init__(self, *, origin, ca_file, cert_file, key_file, token_file,
                 socket_path=None, timeout=10, max_bytes=65536):
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("INVALID_TRUSTED_ORIGIN")
        if not 0 < timeout <= 120 or not 0 < max_bytes <= 1048576:
            raise ValueError("INVALID_CLIENT_LIMIT")
        _file(ca_file)
        _file(cert_file)
        _file(key_file, secret=True)
        _file(token_file, secret=True, limit=16384)
        self.context = ssl.create_default_context(cafile=ca_file)
        self.context.load_cert_chain(cert_file, key_file)
        self.origin = parsed
        self.token_file = token_file
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_bytes = max_bytes

    def request(self, path, body=None, method=None):
        if not isinstance(path, str) or not re.fullmatch(r"/(?:[A-Za-z0-9._:@/-])*", path) or path.startswith("//"):
            raise ValueError("INVALID_CLIENT_PATH")
        method = method or ("GET" if body is None else "POST")
        if method not in ("GET", "POST"):
            raise ValueError("INVALID_CLIENT_METHOD")
        token = _file(self.token_file, secret=True, limit=16384).decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,16384}", token):
            raise ValueError("CLIENT_TOKEN_REQUIRED")
        payload = None if body is None else json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if payload and len(payload) > self.max_bytes:
            raise ValueError("REQUEST_TOO_LARGE")
        if self.socket_path:
            connection = _UnixHTTPSConnection(self.origin.hostname, self.socket_path, context=self.context, timeout=self.timeout)
        else:
            connection = http.client.HTTPSConnection(self.origin.hostname, self.origin.port, context=self.context, timeout=self.timeout)
        try:
            deadline = time.monotonic() + self.timeout
            connection.request(method, path, payload, {"Authorization": "Bearer " + token, "Accept": "application/json", "Content-Type": "application/json"})
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise ValueError("TRANSPORT_REDIRECT_DENIED")
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError("TRANSPORT_ENCODING_DENIED")
            chunks = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TRANSPORT_DEADLINE")
                if connection.sock:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(16384, self.max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > self.max_bytes:
                    raise ValueError("RESPONSE_TOO_LARGE")
                chunks.append(chunk)
            data = b"".join(chunks)
            return {"status": response.status, "body": json.loads(data.decode("utf-8")) if data else None}
        finally:
            connection.close()

    def execute(self, task_id, action):
        return self.request("/v1/actions", {"taskId": task_id, "action": action})

    def operation(self, operation_id):
        if not re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", operation_id):
            raise ValueError("INVALID_OPERATION_ID")
        return self.request("/v1/operations/" + operation_id)
