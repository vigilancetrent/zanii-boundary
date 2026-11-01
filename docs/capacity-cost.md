# Capacity and quote-driven costs

Zanii Boundary calculates exact estimates from dated quotes and declared usage. No provider, billed-host plan or actual prices have been supplied. The checked-in configuration therefore returns `BLOCKED`, `totalMinor: null` and an unavailable billing observation. A missing price is never a free service.

Run the unpriced configuration:

```sh
node scripts/cost-report.mjs --config config/cost.example.json
```

It exits 2. After supplying the required real inputs, an estimate can be saved privately with `--out artifacts/private/cost/report.json`. The command does not provision infrastructure, fetch arbitrary pricing URLs, send notifications, create a billing observation or publish an artifact.

## Actual capacity inputs

The [capacity measurement contract](capacity-measurement.md) records scheduled/issued/dropped requests, observed resource effects, endpoint latency and scoped local resource observations. A cost report may reference a bounded 32 MiB capacity JSON file. Its source digest must match the current implementation. The adapter independently recounts bounded unique per-arrival/status identities and uses the actual capacity effect reconciler before accepting aggregate counts. Successful responses above issued counts, mismatched effects/statuses, invalid authority/drain or missing events are rejected. It preserves the distinction between request counts, actual resource effects and application JSON body bytes; this consistency check is not provider authentication.

Application JSON bytes exclude HTTP, TLS and provider traffic, so they are not billed egress. A database size observation is not a byte-second integral or a storage-month quantity. Local resource effects are not automatically S3 requests. Missing actual ledger billing units remain unknown. The adapter never invents these quantities or extrapolates a local fixture into monthly production spend.

The distributed profile currently permits 18 continuously running containers at configured maxima and four additional manual rotator/migrator containers. The complete shared PostgreSQL connection budget is 101 of 128, including reserved/admin allowances. `deploymentCostInventory()` derives the actual per-role CPU/memory envelopes from the checked-in profile and Compose configuration. Monitoring host capacity is separate.

Container counts are not billed VM counts. A provider's host size, placement, redundancy, reserved capacity, monitoring deployment and maintenance duration must be supplied before estimating their cost. The report deliberately leaves `billedHostCount` null.

## Quote metadata

The config references a protected `quotesFile` containing an array of flat SKU quotes. Linux quote files must have private owner permissions, and links are rejected. No real prices are included in the repository.

| Field | Meaning |
|---|---|
| `id`, `component` | Unique quote ID and one of compute, database, object-storage, object-requests, kms, ledger, network-egress, monitoring |
| `provider`, `sku`, `region` | Exact provider/SKU/region; usage must reference matching SKU and region |
| `currency`, `minorDigits` | Explicit currency label and minor-unit decimal exponent; every price must match the report |
| `unit` | Exact normalized billing-unit label, such as instance-second, byte-second, request or egress-byte; no implicit conversion |
| `priceMinor`, `perUnits` | Integer decimal strings giving minor currency units per integer quantity of billing units |
| `billingIncrement` | Positive integer quantity increment; billed quantity rounds upward to this increment |
| `quotedAt`, `validFrom`, `expiresAt` | Epoch milliseconds; a fresh quote must cover the complete cost period and remain valid now |
| `synthetic` | Required boolean; synthetic prices are denied by the normal report command |
| `evidence` | Kind, reference, document/content SHA-256 and observation timestamp |

Evidence kind is `provider-published-rate`, `provider-quote` or `operator-quote`. Published rates require an HTTPS reference without embedded credentials. Private commercial quotes use an operator-controlled reference and document hash. Metadata records provenance; it does not independently authenticate a provider or authorize accepting a changed quote. Preserve the original document separately and confirm its hash and contractual scope.

Flat quotes support explicit billing increments. Tiered rates, discount commitments, taxes, currency exchange, minimum commitments and other contractual terms are not inferred. Unsupported extra schema fields are rejected. Model additional applicable costs explicitly in the supported estimate scope or retain the total as unknown; the tool does not claim a complete invoice.

Fractional request prices can be represented exactly as minor units per million requests. Avoid converting monetary inputs to JavaScript numbers. Currency values, quantities, products and sums use `BigInt` and serialize as decimal strings.

## Usage and rounding

The protected deployment configuration can reference a `usageFile` with version 1, source digest, period start/end, observation timestamp and up to 128 unique lines. Each line contains ID, component, SKU, region, unit, quote ID, integer quantity or null, and basis `measured` or `planning-assumption`.

Measured lines require an evidence digest, completed measurement period and a current observation. Planning lines require a written assumption. All required components need explicit matching quantities and valid quotes. Duplicate IDs, unsupported numeric formats or schemas are rejected. Missing, stale, foreign or mismatched evidence yields an unknown line and unavailable total. The known subtotal is not a complete estimate when any line is unknown.

For each line:

```text
billedQuantity = ceil(quantity / billingIncrement) * billingIncrement
costMinor = ceil(billedQuantity * priceMinor / perUnits)
totalMinor = sum(costMinor for every complete line)
```

Rounding occurs per SKU line, upwards to a currency minor unit; it is never silently deferred to the total. For a deliberately synthetic arithmetic example, 7 minor units per 3 units with quantity 4 and increment 1 costs `ceil(28/3) = 10` minor units. This is a math example, not a provider rate. The tests label every price fixture synthetic. Enabling synthetic math in an internal test produces `ILLUSTRATIVE`, never a normal estimated report.

An optional per-million-successful-request figure uses exact integer division with upward rounding. It inherits the supplied period and assumptions. It is an estimate allocation, not a measured provider charge or production unit economics claim.

## Independent billing and budget signals

`budgetFile` is an optional independent observation consumed through the existing `evaluateBudget()` function. It contains integer `spentMinor` and `limitMinor`, explicit currency, period, freshness, source kind and source digest. At 80% it warns and at 100% it exceeds the limit, using integer comparisons.

A forecast never becomes `spentMinor`. This tool does not write the monitoring budget input. Missing, invalid, stale or different-currency billing evidence stays unavailable. Configure a genuine provider invoice, usage API observation or separately verified operator cost report through `monitoring.budgetFile`; the monitoring pipeline exposes availability as well as the ratio. See the [monitoring runbook](monitoring-runbook.md#budget).

Controlled receiver tests exercise synthetic threshold/delivery contracts locally over mTLS. They do not establish actual provider billing, deployed Prometheus evaluation, on-call routing or delivery to a person. No human notification is sent by this report command.

## Validation and remaining acceptance

`test/product-cost-report.test.mjs` covers large integer arithmetic, rounding, synthetic-price rejection, missing/stale/scope/currency failures, required components, independent budget boundaries, deployment envelopes, capacity limitations and the actual no-quote CLI configuration. Static example configuration contains no prices and no made-up billing observation.

Production cost acceptance remains open until the operator supplies genuine dated quotes, actual host placement and billable usage, validates the relevant contractual terms and verifies the deployed budget path. Capacity acceptance remains limited to the scope of the actual measurement artifact. Neither cost estimates nor passing local arithmetic tests clear deployment readiness.

