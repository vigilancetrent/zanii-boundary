import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { validateMonitoringBundle, provisionGrafanaDatasources, readMonitoringYaml } from '../src/product/monitoring.mjs';
import { runMonitoringCommand } from '../scripts/monitoring-acceptance.mjs';
import { runMonitoringAcceptance } from '../src/product/monitoring-acceptance.mjs';

async function directory(t) { await mkdir('.test-data', { recursive: true }); const path = await mkdtemp(resolve('.test-data', 'monitor-bundle-')); t.after(() => rm(path, { recursive: true, force: true })); return path; }
test('monitoring bundle checks real metric names, runbooks, read-only mounts and never equates templates with deployment acceptance', async (t) => {
  const result = await validateMonitoringBundle(); assert.equal(result.status, 'STATIC_VALIDATED'); assert.equal(result.deploymentAccepted, false); assert.equal(result.alerts, 29); assert.equal(result.panels, 24);
  assert.equal((await runMonitoringCommand(['--static'])).deploymentAccepted, false); await assert.rejects(runMonitoringCommand(['--execute']), { code: 'MONITORING_CONFIG_REQUIRED' });
  const path = await directory(t); await cp('monitoring', join(path, 'monitoring'), { recursive: true }); await mkdir(join(path, 'src/product'), { recursive: true }); await mkdir(join(path, 'docs'));
  await cp('src/product/observability.mjs', join(path, 'src/product/observability.mjs')); await cp('docs/monitoring-runbook.md', join(path, 'docs/monitoring-runbook.md'));
  const compose = await readMonitoringYaml(join(path, 'monitoring/compose.yaml')); compose.services.grafana.volumes.push({ type: 'bind', source: '/var/run/docker.sock', target: '/run/docker.sock', read_only: true }); await writeFile(join(path, 'monitoring/compose.yaml'), JSON.stringify(compose));
  await assert.rejects(validateMonitoringBundle({ root: path }), { code: 'MONITORING_MOUNT_POLICY_INVALID' }); await cp('monitoring/compose.yaml', join(path, 'monitoring/compose.yaml'));
  const alerts = await readMonitoringYaml(join(path, 'monitoring/alerts.yaml')); alerts.groups[0].rules[0].expr = 'runtime_nonexistent_signal > 0'; await writeFile(join(path, 'monitoring/alerts.yaml'), JSON.stringify(alerts));
  await assert.rejects(validateMonitoringBundle({ root: path }), { code: 'MONITORING_UNKNOWN_METRIC' });
  await writeFile(join(path, 'alias.yaml'), 'a: &alias { key: value }\nb: *alias\n'); await assert.rejects(readMonitoringYaml(join(path, 'alias.yaml')), { code: 'MONITORING_YAML_ALIAS_DENIED' });
  await writeFile(join(path, 'duplicate.yaml'), 'key: a\nkey: b\n'); await assert.rejects(readMonitoringYaml(join(path, 'duplicate.yaml')), { code: 'INVALID_MONITORING_YAML' });
});
test('Grafana native datasource provisioning puts matching TLS identity only in a new private operator file', async (t) => {
  const path = await directory(t); const output = join(path, 'private', 'datasources.yaml');
  const options = { caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-observer-cert.pem'), keyFile: resolve('artifacts/test-pki-observer-key.pem'), output };
  const result = await provisionGrafanaDatasources(options); assert.equal(result.provisioned, true); assert.equal(result.containsPrivateIdentity, true); assert.equal(JSON.stringify(result).includes('PRIVATE KEY'), false);
  const value = JSON.parse(await readFile(output, 'utf8')); assert.equal(value.datasources[0].uid, 'runtime-prometheus'); assert.ok(value.datasources[0].secureJsonData.tlsClientKey.includes('PRIVATE KEY'));
  if (process.platform !== 'win32') assert.equal((await stat(output)).mode & 0o077, 0);
  await assert.rejects(provisionGrafanaDatasources(options), { code: 'EEXIST' });
  await assert.rejects(provisionGrafanaDatasources({ ...options, output: join(path, 'wrong.yaml'), keyFile: resolve('artifacts/test-pki-agent-key.pem') }), { code: 'GRAFANA_IDENTITY_MISMATCH' });
});
test('a syntactically complete acceptance input remains blocked without explicit execution and a genuine Linux deployment', async () => {
  const config = JSON.parse(await readFile('monitoring/acceptance.json.example', 'utf8')); config.root = process.cwd(); config.monitoringNetwork = 'monitoring';
  const image = (n) => `fixture/${n}@sha256:${'a'.repeat(64)}`; for (const name of Object.keys(config.images)) config.images[name] = image(name);
  for (const [index, name] of Object.keys(config.containers).entries()) config.containers[name] = String(index + 1).padStart(64, '0'); config.runtimeContainers = ['b'.repeat(64), 'c'.repeat(64)];
  config.deployment = { mode: 'deployment', profileDigest: 'd'.repeat(64), runtimeImage: config.images.runtime, collectorImage: config.images['otel-collector-contrib'] };
  assert.equal((await runMonitoringAcceptance(config)).deploymentAccepted, false);
  if (process.platform !== 'linux') assert.equal((await runMonitoringAcceptance(config, { execute: true })).code, 'LINUX_MONITORING_HOST_REQUIRED');
});
