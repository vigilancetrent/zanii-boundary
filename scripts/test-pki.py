"""Create local-test certificates and keys; never use this CA for production trust."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def public_jwks(key, kid: str) -> bytes:
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(public).decode().rstrip("="),
           "kid": kid, "alg": "EdDSA", "use": "sig"}
    return json.dumps({"keys": [jwk]}, sort_keys=True).encode()


def create_test_pki(output: Path, flat: bool = False, add_broker_trust: bool = False) -> dict:
    root = Path(__file__).resolve().parent.parent
    output = output.resolve()
    if not output.is_relative_to(root / "artifacts"):
        raise ValueError("Test PKI must stay inside this project's artifacts directory")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    filename = lambda name: "test-pki-" + name.replace("/", "-") if flat else name
    inventory = output / filename("inventory.json")
    if inventory.exists():
        data = json.loads(inventory.read_text(encoding="utf-8"))
        for name, digest in data["files"].items():
            path = (output / name).resolve()
            if not path.is_relative_to(output) or not path.is_file():
                raise ValueError("Existing test PKI is incomplete")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("Existing test PKI changed; choose a new artifact directory")
        cert = x509.load_pem_x509_certificate((output / filename("ca.pem")).read_bytes())
        if datetime.now(timezone.utc) >= cert.not_valid_after_utc:
            raise ValueError("Test PKI expired; choose a new artifact directory")
        broker_name = filename("broker-public.jwks.json")
        if add_broker_trust and broker_name not in data["files"]:
            signing_key = serialization.load_pem_private_key((output / filename("gateway-signing-key.pem")).read_bytes(), None)
            content = public_jwks(signing_key, "local-test-broker")
            with os.fdopen(os.open(output / broker_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "wb") as file:
                file.write(content)
            data["files"][broker_name] = hashlib.sha256(content).hexdigest()
            temporary = inventory.with_suffix(".upgrade.tmp")
            with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
                file.write(json.dumps(data, indent=2).encode())
            os.replace(temporary, inventory)
        return {"directory": str(output.relative_to(root)), "reused": True,
                "files": len(data["files"]), "purpose": "local-test-only"}
    if not flat and any(output.iterdir()):
        raise ValueError("Refusing to overwrite an incomplete PKI directory")

    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=2)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Agent Runtime LOCAL TEST CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(expiry)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                         key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    digests = {}

    def write(name: str, content: bytes, private: bool = False) -> None:
        name = filename(name)
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644), "wb") as file:
            file.write(content)
        digests[name] = hashlib.sha256(content).hexdigest()

    def private_bytes(key) -> bytes:
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

    write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    write("ca-key.pem", private_bytes(ca_key), True)
    for role in ["gateway", "resource", "agent", "observer", "operator", "broker"]:
        key = ec.generate_private_key(ec.SECP256R1())
        names = [x509.DNSName(role), x509.UniformResourceIdentifier(f"spiffe://agent-runtime.test/workload/{role}")]
        usages = [ExtendedKeyUsageOID.CLIENT_AUTH]
        if role in {"gateway", "resource"}:
            names += [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            usages += [ExtendedKeyUsageOID.SERVER_AUTH]
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(expiry)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.ExtendedKeyUsage(usages), critical=True)
                .sign(ca_key, hashes.SHA256()))
        write(f"{role}-cert.pem", cert.public_bytes(serialization.Encoding.PEM))
        write(f"{role}-key.pem", private_bytes(key), True)
        if role == "agent":
            write("agent-identity/agent-cert.pem", cert.public_bytes(serialization.Encoding.PEM))
            write("agent-identity/agent-key.pem", private_bytes(key), True)
            write("agent-identity/ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    for role in ["gateway", "resource"]:
        signing_key = ed25519.Ed25519PrivateKey.generate()
        write(f"{role}-signing-key.pem", private_bytes(signing_key), True)
        write(f"{role}-signing-public.pem", signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        if role == "gateway":
            write("broker-public.jwks.json", public_jwks(signing_key, "local-test-broker"))
        write(f"{role}-data.key", os.urandom(32).hex().encode("ascii") + b"\n", True)
        write(f"{role}-audit.key", os.urandom(32).hex().encode("ascii") + b"\n", True)
    issuer_key = ed25519.Ed25519PrivateKey.generate()
    write("issuer-key.pem", private_bytes(issuer_key), True)
    write("issuer-public.jwks.json", public_jwks(issuer_key, "local-test-issuer"))
    write("inventory.json", json.dumps({"purpose": "local-test-only", "expiresAt": expiry.isoformat(),
          "files": digests, "unixPermissionsEnforced": os.name != "nt",
          "warning": "Windows file ACL isolation is not established by os.chmod/open mode."}, indent=2).encode())
    return {"directory": str(output.relative_to(root)), "reused": False, "files": len(digests) - 1,
            "purpose": "local-test-only", "unixPermissionsEnforced": os.name != "nt"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent.parent / "artifacts/test-pki")
    parser.add_argument("--flat", action="store_true", help="Explicit prefixed-file mode for a restricted existing artifact directory")
    parser.add_argument("--add-broker-trust", action="store_true", help="Extend a verified existing inventory with public JWKS derived from its unchanged gateway key")
    args = parser.parse_args()
    try:
        print(json.dumps(create_test_pki(args.output, flat=args.flat, add_broker_trust=args.add_broker_trust)))
    except Exception:
        parser.exit(1, "Test PKI generation failed; existing files were not overwritten.\n")
