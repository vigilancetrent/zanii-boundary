import { resolve, dirname, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes, createHash, createPublicKey, X509Certificate } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { ROOT_CONTEXT } from '@opentelemetry/api';
import { TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace';
import { AppError } from '../protocol.mjs';
import { createHttpsTransport } from '../adapters/transport.mjs';
import { readOperationsFile } from './operations-config.mjs';
import { assertNarrowMonitorToken } from './probes.mjs';
import { validateMonitoringBundle, MONITORING_COMPONENTS, MONITORING_IMAGE_ROLES, IMAGE_PATTERN, readMonitoringYaml } from './monitoring.mjs';
import { verifyMonitoringReceipt } from './monitoring-receiver.mjs';
import { runSecurityTool } from './security-delivery.mjs';

const file = z.string().min(1).max(4096); const hex = z.string().regex(/^[a-f0-9]{64}$/); const image = z.string().max(512).regex(IMAGE_PATTERN);
const endpoint = z.object({ origin: z.string().url(), servername: z.string().min(1).max(253), caFile: file, certFile: file, keyFile: file, tokenFile: file.optional(), allowPrivateNetworks: z.boolean().default(false) }).strict();
const schema = z.object({ version: z.literal(1), root: file.optional(), configurationDirectory: file, composeFile: file.optional(), monitoringNetwork: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/),
  containers: z.object(Object.fromEntries(MONITORING_COMPONENTS.map((role) => [role, hex]))).strict(), runtimeContainers: z.array(hex).min(2).max(128),
  images: z.object(Object.fromEntries([...new Set(Object.values(MONITORING_IMAGE_ROLES))].map((role) => [role, image]))).strict(),
  deployment: z.object({ mode: z.literal('deployment'), profileDigest: hex, runtimeImage: image, collectorImage: image }).strict(),
  endpoints: z.object({ prometheus: endpoint, alertmanager: endpoint, grafana: endpoint, loki: endpoint, tempo: endpoint, receiver: endpoint }).strict(),
  receiptPublicKeyFile: file,
  timeoutMs: z.number().int().min(10000).max(120000).default(60000),
}).strict();
const fail = (code) => { throw new AppError(503, code); };
const trustedRuntimeRoles = new Set(['gateway', 'resource', 'worker-gateway', 'worker-resource', 'archive-gateway', 'archive-resource', 'backup-gateway', 'backup-resource']);

/** Select a fresh observable test request without changing the runtime's configured sampling ratio. */
export function selectMonitoringTraceId(ratio = 0.1) {
  if (typeof ratio !== 'number' || !Number.isFinite(ratio) || ratio <= 0 || ratio > 1) fail('MONITORING_TRACE_SAMPLING_UNAVAILABLE');
  const sampler = new TraceIdRatioBasedSampler(ratio);
  for (let attempt = 0; attempt < 4096; attempt++) { const id = randomBytes(16).toString('hex'); if (sampler.shouldSample(ROOT_CONTEXT, id).decision === 2) return id; }
  fail('MONITORING_TRACE_SAMPLING_UNAVAILABLE');
}

/** No tool runner injection: deployment success requires actual engine inspection and native binaries. */
export async function runMonitoringAcceptance(raw, { baseDirectory = process.cwd(), execute = false } = {}) {
  const parsed = schema.safeParse(raw); if (!parsed.success) throw new AppError(400, 'INVALID_MONITORING_ACCEPTANCE_CONFIGURATION'); const config = parsed.data;
  const root = resolve(baseDirectory, config.root ?? '.'); const staticCheck = await validateMonitoringBundle({ root });
  if (!execute) return { status: 'BLOCKED', code: 'EXPLICIT_MONITORING_ACCEPTANCE_EXECUTION_REQUIRED', deploymentAccepted: false, staticCheck };
  if (process.platform !== 'linux') return { status: 'BLOCKED', code: 'LINUX_MONITORING_HOST_REQUIRED', deploymentAccepted: false, staticCheck };
  const startedAt = Date.now(); const deadline = startedAt + config.timeoutMs; const remaining = () => { const ms = deadline - Date.now(); if (ms <= 0) fail('MONITORING_ACCEPTANCE_DEADLINE'); return ms; };
  const tool = async (args) => { const result = await runSecurityTool('docker', args, { cwd: root, timeoutMs: Math.min(15000, remaining()), maxBytes: 2097152 }); if (result.code !== 0) fail('MONITORING_NATIVE_CHECK_FAILED'); return result.stdout.toString('utf8'); };
  const read = (path, secret = false) => readOperationsFile(path, { baseDirectory, secret });
  if (config.images.runtime !== config.deployment.runtimeImage || config.images['otel-collector-contrib'] !== config.deployment.collectorImage) fail('MONITORING_DEPLOYMENT_IMAGE_MISMATCH');
  const { readDistributedDeploymentFiles } = await import('./distributed-deployment.mjs');
  const distributed = await readDistributedDeploymentFiles(pathToFileURL(resolve(root, 'deploy/distributed') + sep), { configurationDirectory: resolve(baseDirectory, config.configurationDirectory), ...(config.composeFile ? { composeFile: resolve(baseDirectory, config.composeFile) } : {}) });
  if (distributed.profileDigest !== config.deployment.profileDigest) fail('MONITORING_PROFILE_DIGEST_MISMATCH');
  const engine = JSON.parse(await tool(['info', '--format', '{{json .}}']));
  if (engine.OSType !== 'linux' || !engine.SecurityOptions?.some((item) => item.includes('userns')) || engine.SecurityOptions.some((item) => item.includes('rootless'))) fail('ROOTFUL_USERNS_ENGINE_REQUIRED');
  const ids = Object.values(config.containers); if (new Set([...ids, ...config.runtimeContainers]).size !== ids.length + config.runtimeContainers.length) fail('DUPLICATE_MONITORING_CONTAINER');
  const inspected = JSON.parse(await tool(['inspect', ...ids, ...config.runtimeContainers])); const byId = new Map(inspected.map((container) => [container.Id, container]));
  const compose = await readMonitoringYaml(resolve(root, 'monitoring/compose.yaml'));
  const inspectedImages = [];
  for (const [role, id] of Object.entries(config.containers)) {
    const container = byId.get(id); const expectedImage = config.images[MONITORING_IMAGE_ROLES[role]];
    if (!container?.State?.Running || container.Config?.Image !== expectedImage || container.Config?.Labels?.['com.docker.compose.service'] !== role
        || !container.HostConfig?.ReadonlyRootfs || container.HostConfig?.Privileged || container.HostConfig?.NetworkMode === 'host'
        || container.HostConfig?.UsernsMode === 'host' || !container.HostConfig?.CapDrop?.includes('ALL') || container.HostConfig?.CapAdd?.length
        || !container.HostConfig?.SecurityOpt?.includes('no-new-privileges:true') || !/^\d+:3000$/.test(container.Config?.User ?? '')) fail('MONITORING_LIVE_CONTAINER_POLICY_INVALID');
    if (Object.keys(container.NetworkSettings?.Networks ?? {}).length !== 1 || !container.NetworkSettings.Networks[config.monitoringNetwork]) fail('MONITORING_LIVE_NETWORK_INVALID');
    const declared = compose.services[role].volumes ?? [];
    if ((container.Mounts ?? []).length !== declared.length) fail('MONITORING_UNDECLARED_MOUNT');
    for (const mount of container.Mounts ?? []) {
      const expected = declared.find((volume) => volume.target === mount.Destination);
      if (!expected || mount.Type !== 'bind' || Boolean(mount.RW) === Boolean(expected.read_only) || /docker\.sock|^\/proc|^\/sys/.test(mount.Source)
          || mount.Destination.startsWith('/var/log/runtime/') && (role !== 'otel-collector' || mount.RW)) fail('MONITORING_LIVE_MOUNT_INVALID');
      if (expected.source.startsWith('${RUNTIME_MONITORING_DIR:?}/')) {
        const name = expected.source.slice('${RUNTIME_MONITORING_DIR:?}/'.length);
        const bytes = await readOperationsFile(mount.Source, { maxBytes: 1048576 }); const committed = await readOperationsFile(resolve(root, 'monitoring', name), { maxBytes: 1048576 });
        if (bytes !== committed) fail('MONITORING_RUNNING_CONFIG_MISMATCH');
      }
    }
    const pinned = JSON.parse(await tool(['image', 'inspect', expectedImage]));
    if (pinned.length !== 1 || pinned[0].Id !== container.Image || !pinned[0].RepoDigests?.includes(expectedImage)) fail('MONITORING_IMAGE_INSPECTION_MISMATCH');
    inspectedImages.push({ role, imageId: container.Image, pinnedImage: expectedImage });
  }
  const prom = byId.get(config.containers.prometheus);
  const mounted = (container, path) => {
    const mount = container.Mounts.find((mount) => path === mount.Destination || path.startsWith(mount.Destination + '/'));
    if (!mount || mount.RW) fail('MONITORING_PRIVATE_MOUNT_MISSING'); return resolve(mount.Source, path.slice(mount.Destination.length).replace(/^\//, ''));
  };
  const promConfig = await readMonitoringYaml(resolve(root, 'monitoring/prometheus.yaml'));
  for (const role of ['gateway', 'resource']) {
    const scrape = promConfig.scrape_configs.find((job) => job.job_name === `runtime-${role}`);
    const cert = new X509Certificate(await readOperationsFile(mounted(prom, scrape.tls_config.cert_file)));
    const token = (await readOperationsFile(mounted(prom, scrape.authorization.credentials_file), { secret: true })).trim();
    assertNarrowMonitorToken(token, { audience: distributed.configs[role].auth.audience, fingerprint: createHash('sha256').update(cert.raw).digest('base64url') });
  }
  for (const id of config.runtimeContainers) if (!byId.get(id)?.State?.Running || !trustedRuntimeRoles.has(byId.get(id).Config?.Labels?.['com.docker.compose.service'])) fail('MONITORING_UNTRUSTED_NETWORK_MEMBER');
  for (const [name, port] of Object.entries({ prometheus: 9090, alertmanager: 9093, grafana: 3000, loki: 3100, tempo: 3200, receiver: 9444 })) {
    const service = name === 'receiver' ? 'monitoring-receiver' : name; const origin = new URL(config.endpoints[name].origin); const container = byId.get(config.containers[service]);
    const bindings = container.HostConfig?.PortBindings?.[`${port}/tcp`];
    if (origin.protocol !== 'https:' || origin.hostname !== '127.0.0.1' || config.endpoints[name].servername !== service || bindings?.length !== 1 || bindings[0].HostIp !== '127.0.0.1' || bindings[0].HostPort !== origin.port) fail('MONITORING_ENDPOINT_CONTAINER_MISMATCH');
  }
  const networks = JSON.parse(await tool(['network', 'inspect', config.monitoringNetwork])); const network = networks[0];
  if (networks.length !== 1 || !network.Internal || network.Driver !== 'bridge' || JSON.stringify(Object.keys(network.Containers ?? {}).sort()) !== JSON.stringify([...ids, ...config.runtimeContainers].sort())) fail('MONITORING_NETWORK_MEMBERSHIP_MISMATCH');
  const native = [ ['prometheus', '/bin/promtool', 'check', 'config', '/etc/prometheus/prometheus.yaml'],
    ['alertmanager', '/bin/amtool', 'check-config', '/etc/alertmanager/alertmanager.yaml'],
    ['otel-collector', '/otelcol-contrib', 'validate', '--config=/etc/otelcol/config.yaml'],
    ['loki', '/usr/bin/loki', '-config.file=/etc/loki/config.yaml', '-verify-config=true'],
    ['tempo', '/tempo', '--config.file=/etc/tempo/config.yaml', '--config.verify'] ];
  for (const [role, ...args] of native) await tool(['exec', config.containers[role], ...args]);
  const paths = { prometheus: ['/api/v1/targets', '/api/v1/rules', '/api/v1/query'], alertmanager: ['/api/v2/status', '/api/v2/alerts'],
    grafana: ['/api/health', '/api/dashboards/uid/runtime-operations', '/api/datasources/uid/runtime-prometheus', '/api/datasources/uid/loki', '/api/datasources/uid/tempo'],
    loki: ['/ready', '/loki/api/v1/query_range'], tempo: ['/ready', '/api/traces'], receiver: ['/v1/receipts/query'] };
  const clients = {};
  for (const [name, value] of Object.entries(config.endpoints)) {
    const tls = { ca: await read(value.caFile), cert: await read(value.certFile), key: await read(value.keyFile, true), servername: value.servername };
    const client = createHttpsTransport({ origin: value.origin, tls, allowPrivateNetworks: value.allowPrivateNetworks, timeoutMs: Math.min(5000, config.timeoutMs), maxBytes: 1048576, allowedMethods: name === 'receiver' ? ['POST'] : name === 'alertmanager' ? ['GET', 'POST'] : ['GET'], allowedPaths: paths[name] });
    const headers = value.tokenFile ? { authorization: `Bearer ${(await read(value.tokenFile, true)).trim()}` } : {};
    clients[name] = { async json(path, options = {}) { remaining(); const response = await client.request(path, { headers: { ...headers, accept: 'application/json' }, ...options }); if (response.status !== 200) fail('MONITORING_ENDPOINT_UNHEALTHY'); return response.body; },
      async ready() { const response = await client.fetch(`${client.origin}/ready`, { headers }); if (response.status !== 200) fail('MONITORING_STORAGE_UNREADY'); } };
  }
  const targets = await clients.prometheus.json('/api/v1/targets');
  const active = targets.data?.activeTargets;
  for (const job of ['runtime-gateway', 'runtime-resource', 'runtime-probes', 'monitoring-receiver', 'otel-collector', 'loki', 'tempo']) if (!active?.some((target) => target.labels?.job === job) || active.some((target) => target.labels?.job === job && target.health !== 'up')) fail('MONITORING_PROMETHEUS_TARGET_UNREADY');
  const ruleResponse = await clients.prometheus.json('/api/v1/rules'); const expectedRules = (await readMonitoringYaml(resolve(root, 'monitoring/alerts.yaml'))).groups.flatMap((group) => group.rules.map((rule) => rule.alert));
  const actualRules = ruleResponse.data?.groups?.flatMap((group) => group.rules) ?? [];
  if (expectedRules.some((name) => !actualRules.some((rule) => rule.name === name && rule.health === 'ok'))) fail('MONITORING_PROMETHEUS_RULES_INVALID');
  const sample = await clients.prometheus.json('/api/v1/query?query=' + encodeURIComponent('runtime_probe_success'));
  if (sample.status !== 'success' || sample.data?.result?.length < 6 || sample.data.result.some((row) => Number(row.value?.[1]) !== 1 || Number(row.value[0]) * 1000 < startedAt - 60000)) fail('MONITORING_PROBE_SAMPLES_MISSING');
  const dashboard = await clients.grafana.json('/api/dashboards/uid/runtime-operations');
  if (dashboard.dashboard?.uid !== 'runtime-operations' || dashboard.dashboard.panels?.length !== staticCheck.panels || dashboard.meta?.provisioned !== true) fail('MONITORING_DASHBOARD_NOT_PROVISIONED');
  for (const uid of ['runtime-prometheus', 'loki', 'tempo']) {
    if ((await clients.grafana.json(`/api/datasources/uid/${uid}/health`)).status !== 'OK') fail('MONITORING_GRAFANA_DATASOURCE_UNHEALTHY');
    const source = await clients.grafana.json(`/api/datasources/uid/${uid}`);
    if (!source.jsonData?.tlsAuth || !source.jsonData?.tlsAuthWithCACert || source.jsonData.tlsSkipVerify || !source.secureJsonFields?.tlsClientKey) fail('MONITORING_GRAFANA_TLS_INVALID');
  }
  await clients.loki.ready(); await clients.tempo.ready();
  const am = await clients.alertmanager.json('/api/v2/status');
  const amConfig = parseAlertmanager(am.config?.original);
  if (!amConfig) fail('MONITORING_ALERTMANAGER_ROUTE_UNVERIFIED');
  const nonce = randomBytes(32).toString('hex'); const startsAt = new Date().toISOString(); const endsAt = new Date(Date.now() + 60000).toISOString();
  await clients.alertmanager.json('/api/v2/alerts', { method: 'POST', body: [{ labels: { alertname: 'RuntimeMonitoringAcceptance', severity: 'info' }, annotations: { acceptance_nonce: nonce, summary: 'Controlled monitoring acceptance receipt only.' }, startsAt, endsAt, generatorURL: 'https://runtime.invalid/controlled-acceptance' }] });
  const publicKey = createPublicKey(await read(config.receiptPublicKeyFile));
  const receipt = async (kind, id, extra = {}) => {
    const response = await clients.receiver.json('/v1/receipts/query', { method: 'POST', body: { kind, ...(id ? { id } : {}), after: startedAt, limit: 1, ...extra } });
    return response.receipts?.length ? verifyMonitoringReceipt(response.receipts[0], publicKey, { kind, id, expectedDeployment: config.deployment, after: startedAt }) : null;
  };
  const observations = [];
  for (const role of ['gateway', 'resource']) {
    if (!distributed.configs[role].telemetry?.collector) fail('MONITORING_RUNTIME_COLLECTOR_UNCONFIGURED');
    const traceId = selectMonitoringTraceId(distributed.configs[role].telemetry.samplingRatio ?? 0.1);
    const probe = async (mode, traceparent = undefined) => JSON.parse(await tool(['exec', config.containers['probe-exporter'], 'node', 'scripts/probe-target.mjs', '--config', '/run/config/probe-server.json', '--target', role, '--mode', mode, ...(traceparent ? ['--traceparent', traceparent] : [])]));
    const result = await probe('ready', `00-${traceId}-${randomBytes(8).toString('hex')}-01`);
    if (!result.requestId || result.role !== role || result.containment?.imageRef !== config.deployment.runtimeImage || result.containment?.profileDigest !== config.deployment.profileDigest) fail('MONITORING_PROBE_DEPLOYMENT_IDENTITY_MISSING'); observations.push({ role, traceId, requestIds: [result.requestId] });
    // Success logging is sampled; bounded additional fixed-route probes require actual observed output.
    for (let index = 0; index < 19; index++) { const outcome = await probe('live'); if (outcome.requestId) observations[observations.length - 1].requestIds.push(outcome.requestId); }
  }
  let alert; let job; const traces = new Map(); const logs = new Map();
  while (remaining() > 500) {
    alert ??= await receipt('alert', nonce); job ??= await receipt('trace', undefined, { span: 'maintenance.job' });
    for (const item of observations) {
      if (!traces.has(item.role)) { const observed = await receipt('trace', item.traceId); const spans = observed?.summary?.spans ?? []; const parents = new Set(spans.filter((span) => span.role === item.role && span.name === 'http.server').map((span) => span.id)); if (spans.some((span) => span.role === item.role && span.name === 'db.operation' && parents.has(span.parentId))) traces.set(item.role, observed); }
      if (!logs.has(item.role)) for (const id of item.requestIds) { const observed = await receipt('log', id); if (observed?.summary?.entries?.some((entry) => entry.role === item.role)) { logs.set(item.role, observed); break; } }
    }
    if (alert && job && traces.size === 2 && logs.size === 2) break;
    await sleep(Math.min(1000, remaining()));
  }
  if (!alert || !job || traces.size !== 2 || logs.size !== 2 || !alert.summary.names?.includes('RuntimeMonitoringAcceptance')) fail('MONITORING_DEPLOYED_RECEIPTS_MISSING');
  for (const item of observations) {
    const trace = await clients.tempo.json(`/api/traces/${item.traceId}`); if (!trace.batches?.length && !trace.resourceSpans?.length) fail('MONITORING_TEMPO_TRACE_MISSING');
    const ids = item.requestIds; const query = `{service_name="runtime-${item.role}"} | json | requestId=~"${ids.join('|')}"`;
    const log = await clients.loki.json('/loki/api/v1/query_range?' + new URLSearchParams({ query, start: String(startedAt * 1000000), limit: '20' }));
    if (log.status !== 'success' || !log.data?.result?.some((row) => row.values?.some((value) => ids.some((id) => value[1]?.includes(id))))) fail('MONITORING_LOKI_LOG_MISSING');
  }
  return { status: 'DEPLOYMENT_ACCEPTED', deploymentAccepted: true, startedAt, completedAt: Date.now(), deployment: config.deployment, inspectedImages,
    nativeConfigurationsValidated: native.map(([role]) => role), alertReceiptDigest: createHash('sha256').update(JSON.stringify(alert)).digest('hex'), traceRoles: [...traces.keys()], logRoles: [...logs.keys()], maintenanceTraceObserved: true, humanAcknowledgement: false };
}

function parseAlertmanager(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 65536) return false;
  // Importing the parser once avoids treating a boolean summary as evidence of actual receiver routing.
  const doc = parseYaml(text); if (doc.errors.length) return false; const value = doc.toJS({ maxAliasCount: 0 }); const receiver = value.receivers?.[0];
  return value.receivers?.length === 1 && value.route?.receiver === 'controlled-receiver' && receiver?.name === 'controlled-receiver'
    && Object.keys(receiver).every((key) => ['name', 'webhook_configs'].includes(key)) && receiver.webhook_configs?.length === 1
    && receiver.webhook_configs[0].url === 'https://monitoring-receiver:9444/v1/alerts/alertmanager'
    && receiver.webhook_configs[0].http_config?.follow_redirects === false && !receiver.webhook_configs[0].http_config?.tls_config?.insecure_skip_verify;
}
import { parseDocument as parseYaml } from 'yaml';

export async function loadMonitoringAcceptance(path, options = {}) { let value; try { value = JSON.parse(await readOperationsFile(path)); } catch { throw new AppError(400, 'MONITORING_ACCEPTANCE_CONFIGURATION_UNAVAILABLE'); } return runMonitoringAcceptance(value, { ...options, baseDirectory: dirname(resolve(path)) }); }
