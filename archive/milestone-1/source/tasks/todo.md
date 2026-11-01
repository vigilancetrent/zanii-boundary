# Agent runtime milestone tracker

Source of truth: [Build plan](../BUILD-PLAN.md). Authorization: “plan and start building”; “create a separate project.”

- [x] Phase 0: investigate stack, local APIs, references, lessons and readiness requirements.
- [x] Phase 1: package, architecture/threat model, validated contracts, signatures and policy tests (15 passing tests; independent verification, quality and anti-pattern reviews complete).
- [x] Phase 2: broker/resource services, explicit process launcher and real HTTP boundary tests (31 passing tests; process acceptance remains environment-blocked).
- [x] Phase 3: reproducible baseline/scenario benchmark, independent outcome evidence and offline verifier (43 passing tests, 24 cases, verified signed artifacts, 400/400 observed load reads).
- [x] Phase 4: independent reviews, full checks, local load measurements and 47-row readiness report (10 PASS / 13 N/A / 24 GAP; local milestone complete, production clearance withheld).

## Review

Phase 1: `npm test` passed 15/15, all five JavaScript files passed syntax checks, and offline dependency audit found zero dependencies/vulnerabilities. Six local documentation links resolve. `test:isolated` and a direct child launch both failed with `spawn EPERM`; no tests were executed in that isolated runner. Phase 2 will use an explicit real-HTTP in-process transport here and retain a process transport with acceptance blocked. HTTP timeout is response-only unless dispatch has not started; uncertain business effects must not be replayed.

No production, novelty or LLM-defense claim is authorized by passing a synthetic local benchmark.

Phase 2: 31/31 tests pass, including resource observations, per-object and tenant checks, stale configuration, replay/quota races, uncertain outcomes, late task/lease expiry and authenticated readiness. Independent quality/anti-pattern reviews found and verified fixes for late execution after expiry and incomplete observation validation. Source `checkJs`, syntax and basic lint passed. Process mode fails explicitly with `PROCESS_TRANSPORT_UNAVAILABLE` under the observed `EPERM` restriction and never falls back silently. Revocation prevents new admissions; it does not retract already-sent actions. A metadata-only tool change is stale dispatch, not by itself a forbidden business effect.

Phase 3: parent and independent verification passed all 43 tests. Canonical run `cd8c6563-91ae-45b6-af3b-ffc6deb20867` covers 24 mode/scenario pairs. Its source digest is `e25385e5f8108076eb560fb47ac0a9a42d133d1b9c65204f219f6a718e4eb819`; the offline verifier and an independently recomputed implementation digest match it. All modes completed 2/2 healthy tasks and recorded one deliberately induced forbidden direct read. Coverage-bound mode had zero stale broker effects, versus two in each other mode. An independent Python recount matched these totals. Load completed 400/400 reads with 400 observed effects and no errors/denials; maximum observed short-run throughput was 443.99 successful requests/second, with no breaking point established. Basic lint, non-strict JavaScript type checking, 18-module syntax checks and offline zero-dependency audit passed. Reviews corrected non-exhaustive status metrics and wrong-actor healthy-completion counting. Artifact authenticity and internal consistency do not prove evaluator honesty or universal coverage.

Phase 4: the [runbook](../docs/runbook.md), [research status](../docs/research-status.md) and [readiness report](../docs/readiness-report.md) are complete. Independent documentation quality and anti-pattern reviews found no blockers. All 47 readiness rows appear once: 10 PASS, 13 N/A and 24 GAP. Secretlint checked 39 project files/public artifacts with zero errors or warnings; its JSON severity counts were explicitly checked. All 15 local documentation references then checked resolved, and the recorded source digest still matches. Later edits only update documentation. Privacy remains GAP because clean synthetic examples do not establish a general retention/minimization/deletion guarantee.

The first local research milestone is complete. Production containment, separate-process acceptance, customer/Zanii integrations, learned defenses, sustained capacity and publication remain future work; no sign-off or approval for those claims is implied.
