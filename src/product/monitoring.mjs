import { readFile, lstat, mkdir, open } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { parseDocument } from 'yaml';
import { createHash, X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { AppError } from '../protocol.mjs';
import { readOperationsFile } from './operations-config.mjs';

export const MONITORING_COMPONENTS = Object.freeze(['prometheus', 'alertmanager', 'grafana', 'otel-collector', 'loki', 'tempo', 'monitoring-receiver', 'probe-exporter']);
export const MONITORING_IMAGE_ROLES = Object.freeze({ prometheus: 'prometheus', alertmanager: 'alertmanager', grafana: 'grafana', 'otel-collector': 'otel-collector-contrib', loki: 'loki', tempo: 'tempo', 'monitoring-receiver': 'runtime', 'probe-exporter': 'runtime' });
export const IMAGE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/+-]*@sha256:[a-f0-9]{64}$/;
const fail = (code) => { throw new AppError(400, code); };
export async function readMonitoringYaml(path) {
  const stat = await lstat(path); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1048576) fail('UNSAFE_MONITORING_CONFIGURATION');
  const doc = parseDocument(await readFile(path, 'utf8'), { uniqueKeys: true });
  if (doc.errors.length) fail('INVALID_MONITORING_YAML');
  try { return doc.toJS({ maxAliasCount: 0 }); } catch { fail('MONITORING_YAML_ALIAS_DENIED'); }
}

/** Static policy checks are deliberately separate from native binary and deployed endpoint acceptance. */
export async function validateMonitoringBundle({ root = process.cwd() } = {}) {
  const load = (name) => readMonitoringYaml(resolve(root, 'monitoring', name));
  const [compose, prometheus, alerts, alertmanager, collector, dashboard, datasources, loki, tempo] = await Promise.all([
    'compose.yaml', 'prometheus.yaml', 'alerts.yaml', 'alertmanager.yaml', 'otel-collector.yaml', 'dashboard.json', 'grafana/datasources.template.json', 'loki.yaml', 'tempo.yaml',
  ].map(load));
  if (JSON.stringify(Object.keys(compose.services).sort()) !== JSON.stringify([...MONITORING_COMPONENTS].sort()) || !compose.networks?.monitoring?.external) fail('MONITORING_SERVICE_BOUNDARY_INVALID');
  const imageVariables = { prometheus: 'PROMETHEUS_IMAGE', alertmanager: 'ALERTMANAGER_IMAGE', grafana: 'GRAFANA_IMAGE', 'otel-collector': 'OTEL_COLLECTOR_IMAGE', loki: 'LOKI_IMAGE', tempo: 'TEMPO_IMAGE', 'monitoring-receiver': 'RUNTIME_IMAGE', 'probe-exporter': 'RUNTIME_IMAGE' };
  for (const [name, service] of Object.entries(compose.services)) {
    if (!service.read_only || !service.cap_drop?.includes('ALL') || !service.security_opt?.includes('no-new-privileges:true')
        || service.privileged || service.pid || service.ipc || service.network_mode || service.userns_mode || service.devices || service.cap_add
        || !/^\d+:3000$/.test(service.user) || !service.pids_limit || !service.mem_limit || !service.cpus
        || JSON.stringify(service.networks) !== '["monitoring"]' || !service.image.startsWith('${' + imageVariables[name] + ':?')) fail('MONITORING_CONTAINER_POLICY_INVALID');
    for (const volume of service.volumes ?? []) {
      if (typeof volume !== 'object' || volume.type !== 'bind' || /docker\.sock|\/proc|\/sys|\/var\/run|encryption-key|audit-key|issuer|gateway-keyring|resource-keyring/.test(volume.source)
          || !volume.read_only && !/^\/var\/(?:lib|log)\//.test(volume.target) && !['/prometheus', '/alertmanager'].includes(volume.target)) fail('MONITORING_MOUNT_POLICY_INVALID');
      if (volume.target.startsWith('/var/log/runtime/') && (name !== 'otel-collector' || !volume.read_only)) fail('MONITORING_LOG_MOUNT_INVALID');
    }
    for (const port of service.ports ?? []) if (port.host_ip !== '127.0.0.1' || port.protocol !== 'tcp') fail('MONITORING_PUBLIC_LISTENER_DENIED');
  }
  for (const job of prometheus.scrape_configs ?? []) {
    if (job.scheme !== 'https' || job.tls_config?.insecure_skip_verify || job.tls_config?.min_version !== 'TLS13'
        || !job.tls_config?.ca_file || !job.tls_config?.cert_file || !job.tls_config?.key_file || !job.sample_limit || job.label_limit > 16) fail('MONITORING_SCRAPE_POLICY_INVALID');
    if (job.job_name.startsWith('runtime-') && !job.authorization?.credentials_file) fail('MONITORING_NARROW_TOKEN_REQUIRED');
  }
  if (alertmanager.receivers?.length !== 1 || alertmanager.receivers[0].name !== 'controlled-receiver' || alertmanager.route?.receiver !== 'controlled-receiver') fail('MONITORING_HUMAN_DELIVERY_DENIED');
  const receiver = alertmanager.receivers[0];
  if (Object.keys(receiver).some((key) => !['name', 'webhook_configs'].includes(key)) || receiver.webhook_configs?.length !== 1) fail('MONITORING_HUMAN_DELIVERY_DENIED');
  const webhook = receiver.webhook_configs[0];
  if (webhook.url !== 'https://monitoring-receiver:9444/v1/alerts/alertmanager' || !webhook.send_resolved || webhook.http_config?.follow_redirects !== false
      || !webhook.http_config?.authorization?.credentials_file || !webhook.http_config?.tls_config?.cert_file) fail('MONITORING_ALERT_ROUTE_INVALID');
  const publicText = JSON.stringify({ collector, prometheus, alertmanager });
  if (/insecure_skip_verify":true|skip_verify":true|Bearer [A-Za-z0-9]/.test(publicText) || !collector.processors?.['transform/redact'] || !collector.extensions?.file_storage) fail('MONITORING_COLLECTOR_POLICY_INVALID');
  if (collector.receivers?.otlp?.protocols?.http?.tls?.client_ca_file === undefined || collector.exporters?.['otlp_http/receipt']?.encoding !== 'json') fail('MONITORING_RECEIPT_PIPELINE_INVALID');
  for (const pipeline of Object.values(collector.service?.pipelines ?? {})) if (!pipeline.processors?.includes('transform/redact')) fail('MONITORING_REDACTION_REQUIRED');
  const actual = await readFile(resolve(root, 'src/product/observability.mjs'), 'utf8');
  const signals = actual.slice(actual.indexOf('const SIGNALS'), actual.indexOf('export function routeTemplate'));
  const known = new Set([...actual.matchAll(/(?:counter|gauge)\('(runtime_[a-z_]+)/g)].map((match) => match[1]));
  for (const match of signals.matchAll(/(?:\{|,)\s*([a-z_]+):\s*'/g)) known.add(`runtime_${match[1]}`);
  for (const family of ['runtime_http_request_duration_seconds', 'runtime_store_duration_seconds']) for (const suffix of ['bucket', 'sum', 'count']) known.add(`${family}_${suffix}`);
  for (const name of ['runtime_probe_success', 'runtime_probe_duration_seconds', 'runtime_probe_instances']) known.add(name);
  const names = new Set(); const runbook = (await readFile(resolve(root, 'docs/monitoring-runbook.md'), 'utf8')).replaceAll('\r\n', '\n');
  const expressions = [];
  for (const group of alerts.groups ?? []) for (const rule of group.rules ?? []) {
    if (!/^[A-Z][A-Za-z0-9]{0,63}$/.test(rule.alert) || names.has(rule.alert) || !['warning', 'critical'].includes(rule.labels?.severity)) fail('INVALID_MONITORING_ALERT'); names.add(rule.alert);
    const link = rule.annotations?.runbook_url; if (!/^\.\.\/docs\/monitoring-runbook\.md#[a-z-]+$/.test(link ?? '') || !runbook.includes(`## ${link.split('#')[1]}\n`)) fail('MONITORING_RUNBOOK_MISSING'); expressions.push(rule.expr);
  }
  if (!names.size || dashboard.uid !== 'runtime-operations' || dashboard.panels?.length < 10) fail('MONITORING_DASHBOARD_MISSING');
  for (const panel of dashboard.panels) { if (panel.datasource?.uid !== 'runtime-prometheus') fail('MONITORING_DATASOURCE_MISMATCH'); for (const target of panel.targets ?? []) expressions.push(target.expr); }
  for (const expr of expressions) for (const match of expr.matchAll(/\bruntime_[a-z_]+\b/g)) if (!known.has(match[0])) fail('MONITORING_UNKNOWN_METRIC');
  if (!datasources.datasources?.some((source) => source.uid === 'runtime-prometheus') || datasources.datasources.some((source) => !source.jsonData?.tlsAuth || !source.jsonData?.tlsAuthWithCACert || source.jsonData?.tlsSkipVerify)) fail('MONITORING_DATASOURCE_TLS_REQUIRED');
  if (!loki.limits_config?.retention_period || !tempo.compactor?.compaction?.block_retention) fail('MONITORING_RETENTION_REQUIRED');
  return { status: 'STATIC_VALIDATED', deploymentAccepted: false, services: MONITORING_COMPONENTS.length, alerts: names.size, panels: dashboard.panels.length,
    missingLivePrerequisites: ['verified image manifest', 'rootful userns-remapped Linux Docker host', 'native component configuration checks', 'deployed dashboard/datasource checks', 'fresh signed deployed alert/trace/log receipts'] };
}

/** Grafana datasource TLS fields require PEM content. Only a private operator file receives the rendered keys. */
export async function provisionGrafanaDatasources({ root = process.cwd(), caFile, certFile, keyFile, output }) {
  const [ca, cert, key] = await Promise.all([readOperationsFile(caFile), readOperationsFile(certFile), readOperationsFile(keyFile, { secret: true })]);
  const certificate = new X509Certificate(cert); if (!createPublicKey(createPrivateKey(key)).equals(certificate.publicKey)) fail('GRAFANA_IDENTITY_MISMATCH');
  new X509Certificate(ca);
  const value = await readMonitoringYaml(resolve(root, 'monitoring/grafana/datasources.template.json'));
  for (const source of value.datasources) source.secureJsonData = { tlsCACert: ca, tlsClientCert: cert, tlsClientKey: key };
  const path = resolve(output); await mkdir(dirname(path), { recursive: true, mode: 0o700 }); const stat = await lstat(dirname(path));
  if (stat.isSymbolicLink() || !stat.isDirectory() || process.platform !== 'win32' && (stat.mode & 0o077)) fail('UNSAFE_MONITORING_PRIVATE_DIRECTORY');
  const bytes = JSON.stringify(value, null, 2) + '\n'; const handle = await open(path, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  return { provisioned: true, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: Buffer.byteLength(bytes), containsPrivateIdentity: true };
}
