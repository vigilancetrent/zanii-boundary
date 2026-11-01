# Product threat model

The agent, documents, tool output, remembered content and learning feedback are untrusted. Trusted components are the configured issuer, operator, approval authority, gateway/executor, credential broker, resource authorizer, storage keys and independent deployment/evidence verifier. Host administrators and kernel compromise are outside the initial trust model and must not be hidden by process-isolation terminology.

| Threat | Boundary/control | Required evidence |
| --- | --- | --- |
| Spoofed identity or sender | JOSE issuer/audience/algorithm/lifetime checks; optional required mTLS thumbprint binding | Bad issuer/audience/expiry/algorithm/thumbprint tests |
| Cross-tenant access | Tenant predicate in every store query and provider object authorization | Foreign-tenant CRUD/reservation tests |
| Duplicate or concurrent effect | Durable unique operation identity, exact digest, atomic quota/approval reservation | Duplicate/reopen/parallel tests; provider reconciliation |
| Credential bypass | No upstream secret in agent; independently broker-only provider access | Live container/network/resource tests; currently external |
| Storage tampering/disclosure | AES-GCM associated data; hash/HMAC audit and externally held checkpoint | Reopen, ciphertext/AAD, chain and rollback tests |
| Poisoned learning/memory | Separate writer roles, quarantine, signed promotion and fixed policy digest | Held-out tests, untrusted feedback cannot promote |
| Ambiguous remote completion | Persist dispatch before contact; unknown state on crash/timeout; never replay blindly | Restart/recovery and provider-observation tests |
| Unsafe startup/deployment | Strict configuration, no production plaintext defaults, required deployment receipt | Missing-secret/configuration and live doctor failures |

Fields are bounded before encryption. Logs and public evidence must not contain keys, cookies, raw tokens, decrypted business content or training feedback. Encrypted private data has an explicit retention timestamp and purge job; legal holds and externally archived audit checkpoints require separate operator policy. Retention deletes payload records rather than rewriting the audit chain.

An attacker who can change the database and all trusted external checkpoints can rewrite local evidence. An attacker who gains broker credentials or changes resource-side permissions can bypass gateway-only controls. Availability, live containment, provider interoperation and independent scientific reproduction remain deployment/research acceptance gates.
