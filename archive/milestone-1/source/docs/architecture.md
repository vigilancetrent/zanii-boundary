# Local experiment architecture

This project is a local research fixture for evaluating agent authorization under credential and configuration drift. It uses synthetic documents and loopback HTTP only. It is not a production agent runtime or a reproduction of a published system.

```text
Trusted controller and evaluator
  | fresh credentials, signed coverage, lifecycle management
  +--> resource process (documents, provider authorization, independent observations)
  +--> broker process (task, identity, replay/quota and coverage checks)

Untrusted client --> broker --> resource
Untrusted client ------------> resource (negative or deliberately weakened test)

Independent observer credential --> resource observations --> signed experiment evidence
```

The resource independently accepts its configured broker identity. The controller holds separate control and observation credentials; the agent receives neither. The evaluator's private signing key never belongs in a public artifact. An offline verifier requires a separately pinned public key.

The initial modes are `broker-static`, `lease-only` and `coverage-bound`. They share the same task and data fixture. They are experimental architectural comparisons, not benchmarks of external packages. Coverage is bounded empirical evidence for declared checks, not proof of exhaustive route discovery or complete mediation.

The trusted computing base contains the controller/evaluator, broker and resource implementations, their configuration and this host. The agent request, document text and self-asserted authority are untrusted. A separate same-user Windows process is not an OS sandbox. Host credential theft, cloud IAM propagation and real egress containment remain unverified.

All state is process-local and bounded for one run. Restarting creates a new experiment; it does not recover production state. No database, external model provider or ledger is used. Standard-library Ed25519 envelopes sign exact serialized bytes with a purpose domain separator; this format is not JCS, a Zanii receipt, a Merkle proof or an on-chain anchor.

Reference patterns were inspected in the Register HTTP fixture and projection signer, Passport digest helper, and Vault provider HTTP client and verifier tests. No sibling package is imported at runtime.

## Executable transports

`startHarness` supports explicit `process` and `in-process` transports. Process mode starts resource and broker through a validated IPC configuration, with no secrets in arguments, an allowlisted environment, bounded startup/output and Windows-hidden child processes. It never silently falls back. In this environment Node child creation returns `EPERM`, so process-mode acceptance remains blocked. Local integration tests explicitly select in-process transport and still exercise two actual HTTP listeners and independent authentication/authorization code paths. Passing those tests does not establish process or OS isolation.

The trusted evaluator performs an authorized read, a known-legacy direct-access denial and a wrong-identity denial before signing coverage. Provider observations retain the successful admission read with an `admission-` prefix. Workload metrics must exclude those probes without discarding them from the trace.

Resource configuration changes increment a monotonic version. Coverage-bound dispatch checks current state, then the provider checks the pinned version again immediately before an effect. Task/lease expiry limits the provider deadline as well as gateway admission. Response delay after a committed effect deliberately demonstrates an uncertain outcome; it is not treated as prevention and is never automatically replayed. Revocation applies to new admission, not an unconditional cancellation guarantee for in-flight calls.
