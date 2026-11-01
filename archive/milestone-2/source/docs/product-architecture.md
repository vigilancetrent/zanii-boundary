# Product architecture

The product adds persistent authority and execution state to the original experiment without converting its loopback fixtures into a production transport. The operator provisions task grants, public issuer keys, TLS material and secret-file paths; the agent receives only a short-lived gateway identity.

```text
Agent -> authenticated gateway -> task/flow/approval checks
                                  -> atomic SQLite reservation
                                  -> credential broker -> independently authorizing resource
Operator/learner -> role-separated management       -> observed outcome / durable audit
```

SQLite is a single-host, bounded-dataset initial deployment. Tenant and namespace predicates are attached in every storage method. Parameterized SQL and synchronous `BEGIN IMMEDIATE` protect operation uniqueness, aggregate task quotas and one-use approvals; no external call occurs inside a transaction. Reserved/dispatched operations left by a crash are marked unknown for reconciliation, never automatically executed again. Scaling beyond this host requires a separately accepted shared-store adapter.

The default database page ceiling is 128 MiB, enforced through SQLite's page limit before writes; encrypted records are limited to 64 KiB and object namespaces to 50,000 records per tenant. WAL/temporary/backup space is separate and requires deployment volume quotas. Audit verification streams rows rather than loading the entire chain. SQLite's built-in API and exact runtime version are recorded in tests; those tests do not establish API stability across Node releases. File backups are capped before serialization, and a capacity-failure regression verifies reservation/audit rollback.

Private object and operation JSON is AES-256-GCM encrypted with external 32-byte key material and tenant/namespace/identifier-bound associated data. This is field encryption, not whole-volume encryption. Audit records have a hash/HMAC chain and independently retainable checkpoints; a service-controlled SQLite file is not WORM storage. Production additionally needs encrypted volumes, externally protected checkpoints and managed key rotation.

Gateway/resource listeners use configured TLS/mTLS or a narrowly authenticated Unix-domain socket. JWTs pin issuer, audience, permitted algorithms, lifetime and optional certificate thumbprints. Credentials never come from assistant-provider environment variables. Production configuration requires an external deployment receipt and real containment acceptance; a static Compose file or local HTTP result cannot supply it.

Backup is a SQLite-consistent snapshot to a newly created destination, accompanied by a digest manifest. Restore requires a new destination and separately supplied encryption/audit keys. Backup files contain encrypted private records but require protected storage for metadata. The local restore test does not establish regional disaster recovery or HA.
