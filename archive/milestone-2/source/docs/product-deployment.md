# Deployment implementation and acceptance status

Implementation: `deploy/Dockerfile`, `deploy/compose.yaml`, `deploy/profile.json`, `src/product/deployment.mjs`, `scripts/doctor.mjs`, `scripts/containment-check.mjs` and `scripts/test-pki.py`. See the [deployment runbook](../deploy/README.md).

## Locally verified

- Static template validation rejects weakened networking, user/capability/security settings, writable agent mounts, extra secret grants, wrong role mounts and unpinned image references.
- Receipt verification requires an externally trusted signature, exact profile/image binding, Linux engine claims, all ten positive/negative acceptance checks, and bounded freshness. Static results cannot become live receipts.
- Pure fixture tests of the live Docker response parser reject additional unconfined security options, host IPC/user namespace, devices, published ports and mismatched actual image IDs. These are parser tests, not Docker acceptance.
- Python `cryptography` generated distinct local test CA/leaf keys and EdDSA issuer/signing keys. Certificate signatures, service DNS/IP names and separate role fingerprints are checked using Node's X509 implementation.

## Test PKI commands and paths

On an unrestricted workspace:

```powershell
python scripts/test-pki.py
```

This environment denies Python mkdir/list access to new nested artifact directories. Its explicit alternative uses the already writable artifact root, with a `test-pki-` filename prefix:

```powershell
python scripts/test-pki.py --flat --output artifacts
node --test --test-isolation=none test/product-deployment.test.mjs
```

Actual generated files include `artifacts/test-pki-ca.pem`, `test-pki-gateway-cert.pem`, `test-pki-gateway-key.pem` and equivalent `resource`, `agent`, `operator`, `observer` and `broker` names. The EdDSA issuer key is `test-pki-issuer-key.pem`, with public `test-pki-issuer-public.jwks.json`. Per-service data/audit keys and signing keys are prefixed similarly. The inventory verifies re-use without silently replacing trust; expired/changed/incomplete inventories fail.

The resource's separate broker trust file is `test-pki-broker-public.jwks.json`,
derived from the existing gateway signing key with `kid:local-test-broker`.
New inventories include it automatically. Upgrade an existing verified local
inventory with `python scripts/test-pki.py --flat --output artifacts --add-broker-trust`.
This explicit upgrade adds only derived public trust and its inventory entry;
private keys and existing certificate trust are preserved.

Private test files are generated artifacts, excluded from the Docker build context and source control. They must not enter public paper/evidence bundles or be presented as production secrets. No key material is printed. These are two-day self-signed test identities. Windows ACL isolation is explicitly unverified; Unix file modes are not a Windows confidentiality guarantee.

## Blocked external acceptance

Docker and Podman are unavailable, WSL enumeration returns access denied, and Node child launch returns `EPERM`. No image digest was obtained or fabricated. Therefore image provenance, actual process/container isolation, host-file permissions, DNS/metadata/egress denial, child inheritance and Linux TLS-over-UDS behavior are **not deployment verified** here. Run the live suite on a supported configured host. Missing prerequisites yield nonzero blocked status; they are not skipped-as-pass tests.

The template is an internal-provider deployment. External SaaS/model/ledger routes require an additional reviewed egress profile. The first production receipt also requires a narrowly scoped diagnostic bootstrap in the product service; see the runbook. Host administrators, daemon compromise and changes after measurement remain explicit trust assumptions.
