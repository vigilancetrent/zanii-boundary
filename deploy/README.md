# Linux containment deployment

This profile is implemented as a Docker Compose template and fail-closed acceptance tooling. It has **not** been executed in the current Windows command sandbox: Docker/Podman are absent, WSL enumeration is denied, and child-process launch returns `EPERM`. A successful static check is not host isolation, deployment acceptance or permission to connect company data.

`compose.yaml` deliberately uses JSON syntax, which is valid YAML. `profile.json` and the actual Compose template are checked together by `validateDeployment`; unsafe extra services, agent networks, privilege options, writable agent mounts, broad secret grants and changed resource mounts are rejected.

## Components and identities

| Service | Linux identity | Connectivity | Writable state |
| --- | --- | --- | --- |
| Gateway/broker | UID 10001, GID 2000 | Private backend; HTTPS over Unix socket from agent | Its socket directory and its own data directory |
| Resource | UID 10002, GID 2000 | Private backend, independently authenticated mTLS operations | Its own data directory |
| Agent | UID 10003, GID 2000 | `network_mode: none`; authenticated HTTPS over the mounted Unix socket only | Bounded `/tmp` tmpfs |

The agent receives only `/run/runtime` and `/run/identity`, both read-only binds. The identity directory must contain exactly `agent.jwt`, `agent-cert.pem`, `agent-key.pem` and `ca.pem`. These are the agent's narrow workload identity, not upstream provider credentials. Its certificate fingerprint must bind to the JWT where sender binding is required. Mounting the whole PKI/config/secrets directory would violate the profile.

All services run non-root, read-only, with all capabilities dropped, no new privileges and bounded CPU/memory/PIDs. Docker's default seccomp remains active; `seccomp:unconfined` and `apparmor:unconfined` fail live validation. No Docker/runtime socket, host PID/IPC namespace, device, published port or agent network attachment is allowed. The backend network is internal. This first profile consequently supports internal providers; external SaaS/model/ledger egress requires a separately reviewed and tested profile, not silently adding another gateway network.

## Provisioning requirements

1. Use a compatible Linux engine with rootless Docker or user namespaces. Host administrators and the Docker daemon are trusted components; this is not protection against a malicious host administrator.
2. Build the product using a verified digest-pinned **base** image in `NODE_IMAGE`, then obtain a verified digest for the **built product** in `RUNTIME_IMAGE`. Do not substitute a base Node image as the runnable product or fabricate a digest. `Dockerfile` installs the locked dependencies with lifecycle scripts disabled.
3. Provision configuration, private keys and database encryption/audit keys outside the agent. Examples of file names are in `.env.example` and Compose's service-specific secret mapping. Configure `scripts/start.mjs --config /run/config/gateway.json` and the equivalent resource config with the supported product schema.
4. Provision the dedicated socket directory with mapped owner UID 10001 and group 2000, mode `0750`, and create the HTTPS Unix socket as `0660`. Map user IDs correctly for rootless/user-namespace operation. The agent must not be able to unlink or replace the socket.
5. Provision separate state directories for gateway and resource. Their secrets must be readable only by the corresponding mapped service identity. **Compose ignores `uid`, `gid` and `mode` for file-backed secrets**; service grants and actual host-file ownership/permissions must be verified. Merely writing `mode:0400` would not establish confidentiality.
6. Supply your issuer/JWKS trust, CA, per-role certificates, narrowly scoped agent JWT, and separately trusted evaluator public key. No global assistant/provider key is imported. Production config must bind both expected profile digest and expected product image reference.

The gateway and resource config paths reference Compose secret targets such as `/run/secrets/gateway_tls_key`, `/run/secrets/gateway_tls_cert`, `/run/secrets/gateway_data_key`, `/run/secrets/gateway_audit_key` and `/run/secrets/gateway_signing_key`; resource names are analogous. The public CA/JWKS files are `/run/trust/ca.pem` and `/run/trust/issuer.jwks.json`. The test PKI below is not production provisioning.

## Check and accept a deployment

```powershell
node scripts/doctor.mjs --static
node scripts/doctor.mjs
```

The static command validates only the template and reports `liveVerified:false`, `imageVerified:false`. The default doctor exits nonzero until mandatory live prerequisites are available. It never starts, pulls or deploys containers. Use the configured, already running stack for live acceptance.

Prepare an operator-owned **read** probe JSON containing `path`, `body`, `selector` and `sha256`. For the initial receipt, the only permitted diagnostic probe is `/v1/diagnostic/read`, exactly `{}` as its body, `['canary']` as its selector, and the SHA-256 digest of the literal `agent-runtime-public-containment-canary-v1`. Its sender-bound agent identity must explicitly carry `containment:probe`. This authenticated fixed public value traverses the actual gateway/backend TLS path while company execution remains blocked. A post-receipt read may instead use exactly `/v1/actions`, `{taskId,action}` with `action.kind:'read'`, selector `['result','content']` and its known content digest. Other routes and mutations are rejected. No raw response, JWT or private key is printed.

```powershell
node scripts/containment-check.mjs --probe-file path/to/read-probe.json
node scripts/containment-check.mjs --probe-file path/to/read-probe.json --signing-key path/to/evaluator-private.pem --out path/to/new-containment-receipt.json
```

A receipt is written only if **all** live checks pass. The destination uses exclusive creation; existing receipts are not overwritten. Verification uses `verifyDeploymentReceipt` with the separately pinned evaluator key, expected template digest, expected product image and bounded age. An embedded or colocated key is not independent trust.

Live checks inspect actual image IDs, rootless/user-namespace engine settings, all container controls, mounts and backend topology. They require a successful authenticated read, denied direct external/metadata/backend access, DNS isolation, unreadable upstream secret/runtime files, a non-writable socket directory containing only the socket, a narrow identity directory, and child-process inheritance checks. Results are bounded observations on a trusted host, not proof that all possible escape paths have been discovered.

Receipts include the template digest plus a digest of observed runtime image/user/network/mount configuration. The latter records resolved mounts without disclosing their host paths. Verification still depends on the evaluator and host, and changes after measurement require invalidation/revalidation. A signed measurement is not a TEE or continuous hardware attestation.

### Initial acceptance bootstrap

Both trusted backend roles receive read-only `containment_receipt` and `containment_trust` secrets. The resource trusts the separately provisioned broker JWKS at `/run/trust/broker.jwks.json`; the gateway trusts workload issuance at `/run/trust/issuer.jwks.json`. Do not replace these independent trust domains with a shared issuer key. The agent's stdin remains open for its JSONL operations runner; it still has no network or trusted secret mounts.

No fabricated live receipt may unlock the first test. Only the separately authorized fixed public diagnostic above bypasses containment readiness. Normal company actions stay disabled until actual acceptance succeeds. A static receipt, generic testing switch or unverified JSON cannot substitute for it.

## Sources

- [Docker none network driver](https://docs.docker.com/engine/network/drivers/none/)
- [Compose service controls and file-backed secret limitations](https://docs.docker.com/reference/compose-file/services/)
- [Internal Compose networks](https://docs.docker.com/reference/compose-file/networks/)
- [Rootless Docker](https://docs.docker.com/engine/security/rootless/) and [user namespaces](https://docs.docker.com/engine/security/userns-remap/)
- [Default seccomp](https://docs.docker.com/engine/security/seccomp/)
- [Digest-pinned images](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions)
