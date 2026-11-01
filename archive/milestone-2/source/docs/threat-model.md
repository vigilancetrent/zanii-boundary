# Threat model for the local experiment

Assets are the synthetic document boundaries, allowed recipients, operation budget, credentials, signing key and accuracy of the benchmark's observations. The controller, evaluator and resource observation channel are trusted. An adversarial client may bypass its helper, issue raw HTTP requests, replay identifiers, change fields and request resources outside its task.

| Class | Abuse | Control to verify |
| --- | --- | --- |
| Spoofing | Guess or copy an identity; claim another tenant | Fresh opaque credentials, timing-safe credential comparison, authenticated server-side identity |
| Tampering | Add unknown action fields, alter signed coverage, substitute a verification key | Strict bounded schemas, exact signed bytes, caller-supplied pinned public key |
| Repudiation | Claim a rejected request proves no resource effect | Independent provider observations correlated to action IDs |
| Disclosure | Read another tenant or an unapproved document; send to a different recipient | Task checks plus independent resource authorization; secrets excluded from artifacts |
| Denial of service | Oversized JSON, slow requests, unbounded request IDs, concurrent quota exhaustion | Body/response/time limits, bounded state, synchronous admission before awaits |
| Privilege escalation | Use a direct route, stale coverage or a delayed job after revocation | Resource-side identity controls, current task/coverage checks and dispatch revalidation |

An enabled direct route combined with weakened resource authority can permit unauthorized effects. Coverage invalidation at the broker cannot stop such direct calls; the benchmark must report them. Signatures authenticate evaluator statements, not the completeness or truth of every test. A compromised host, broker, evaluator or administrator is outside this experiment's adversary model.

Loopback binding is a test restriction, not encrypted transport or local-user isolation. Same-user subprocesses cannot defend secrets against hostile native processes. There is no production secret store, durable audit service, HA deployment, user login, learned detector or customer identity integration in this milestone.

Avoid arbitrary outbound destinations, redirects, shell evaluation, mutation retries after unknown outcomes and successful-looking responses on dependency failure. Synthetic fixtures must never become a reason to weaken validation at the actual HTTP boundaries.
