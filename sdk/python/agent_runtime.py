"""Bounded stdlib HTTPS/mTLS client. Mutations are never automatically retried."""
import http.client
import io
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import stat
import threading
import time
import urllib.parse


def _file(path, secret=False, limit=65536):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > limit:
        raise ValueError("UNSAFE_IDENTITY_FILE")
    if secret and os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("UNSAFE_IDENTITY_PERMISSIONS")
    with open(path, "rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError("UNSAFE_IDENTITY_FILE")
    return value


_DNS_SLOTS = threading.BoundedSemaphore(2)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TRANSPORT_DEADLINE")
    return remaining


def _addresses(host, port, deadline):
    try:
        address = ipaddress.ip_address(host)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (host, port))]
    except ValueError:
        pass
    # OS getaddrinfo cannot be canceled. At most two daemon lookups may outlive callers.
    if not _DNS_SLOTS.acquire(blocking=False):
        raise TimeoutError("DNS_RESOLUTION_CAPACITY")
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except OSError:
            result.put((False, None))
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=resolve, daemon=True).start()
    try:
        success, addresses = result.get(timeout=_remaining(deadline))
    except queue.Empty:
        raise TimeoutError("DNS_LOOKUP_DEADLINE") from None
    if not success or not addresses:
        raise OSError("DNS_LOOKUP_FAILED")
    return addresses


class _DeadlineReader(io.RawIOBase):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def readable(self):
        return True

    def readinto(self, target):
        self.owner.raw.settimeout(_remaining(self.owner.deadline))
        return self.owner.raw.recv_into(target)

    def close(self):
        if not self.closed:
            self.owner.readers -= 1
            if self.owner.closing and not self.owner.readers:
                self.owner.raw.close()
        super().close()


class _DeadlineSocket:
    def __init__(self, raw, deadline):
        self.raw = raw
        self.deadline = deadline
        self.readers = 0
        self.closing = False

    def sendall(self, value):
        self.raw.settimeout(_remaining(self.deadline))
        return self.raw.sendall(value)

    def settimeout(self, timeout):
        self.raw.settimeout(min(timeout, _remaining(self.deadline)))

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError("UNSUPPORTED_RESPONSE_STREAM")
        self.readers += 1
        return io.BufferedReader(_DeadlineReader(self))

    def close(self):
        self.closing = True
        if not self.readers:
            self.raw.close()


class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, deadline, **kwargs):
        super().__init__(host, **kwargs)
        self.deadline = deadline

    def connect(self):
        for family, kind, protocol, _, address in _addresses(self.host, self.port, self.deadline):
            raw = socket.socket(family, kind, protocol)
            try:
                raw.settimeout(_remaining(self.deadline))
                raw.connect(address)
                raw.settimeout(_remaining(self.deadline))
                secured = self._context.wrap_socket(raw, server_hostname=self.host)
                self.sock = _DeadlineSocket(secured, self.deadline)
                self.sock.settimeout(_remaining(self.deadline))
                return
            except ssl.SSLCertVerificationError:
                raw.close()
                raise
            except OSError:
                raw.close()
                _remaining(self.deadline)
        raise OSError("TRANSPORT_CONNECT_FAILED")


class _UnixHTTPSConnection(_DeadlineHTTPSConnection):
    def __init__(self, host, socket_path, **kwargs):
        super().__init__(host, **kwargs)
        self.socket_path = socket_path

    def connect(self):
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            raw.settimeout(_remaining(self.deadline))
            raw.connect(self.socket_path)
            raw.settimeout(_remaining(self.deadline))
            self.sock = _DeadlineSocket(self._context.wrap_socket(raw, server_hostname=self.host), self.deadline)
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
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
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
        deadline = time.monotonic() + self.timeout
        if self.socket_path:
            connection = _UnixHTTPSConnection(self.origin.hostname, self.socket_path, context=self.context, timeout=self.timeout, deadline=deadline)
        else:
            connection = _DeadlineHTTPSConnection(self.origin.hostname, port=self.origin.port, context=self.context, timeout=self.timeout, deadline=deadline)
        response = None
        try:
            connection.request(method, path, payload, {"Authorization": "Bearer " + token, "Accept": "application/json", "Content-Type": "application/json"})
            connection.sock.settimeout(_remaining(deadline))
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
            if response:
                response.close()
            connection.close()

    def execute(self, task_id, action):
        return self.request("/v1/actions", {"taskId": task_id, "action": action})

    def operation(self, operation_id):
        if not re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", operation_id):
            raise ValueError("INVALID_OPERATION_ID")
        return self.request("/v1/operations/" + operation_id)
