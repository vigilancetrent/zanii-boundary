import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
import { AppError } from '../src/protocol.mjs';
import { createHttpsTransport } from '../src/adapters/transport.mjs';

/** Controlled local dependency loss; records denial latency, not production availability. */
export async function measureDependencyFailure() {
  const pem = (name) => readFile(new URL(`../artifacts/test-pki-${name}.pem`, import.meta.url), 'utf8');
  const ca = await pem('ca'); let forwarded = 0; let healthy = false;
  const server = createServer({ ca, cert: await pem('gateway-cert'), key: await pem('gateway-key'), requestCert: true, rejectUnauthorized: true }, (req, res) => {
    forwarded += 1;
    setTimeout(() => { res.writeHead(healthy ? 200 : 503, { 'content-type': 'application/json' }); res.end('{}'); }, healthy ? 0 : 40);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
  try {
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('INVALID_LISTENER');
    const transport = createHttpsTransport({ origin: `https://127.0.0.1:${address.port}`, allowPrivateNetworks: true,
      tls: { ca, cert: await pem('agent-cert'), key: await pem('agent-key') }, dependencyName: 'resource', timeoutMs: 1000,
      resilience: { failureThreshold: 2, cooldownMs: 100 } });
    const initial = [];
    for (let index = 0; index < 2; index++) { const start = performance.now(); assert.equal((await transport.request('/status')).status, 503); initial.push(performance.now() - start); }
    const burst = async () => {
      const before = forwarded; const start = performance.now(); const durations = [];
      const outcomes = await Promise.all(Array.from({ length: 20 }, async () => {
        const at = performance.now();
        try { return (await transport.request('/status')).status; }
        catch (error) { assert.ok(error instanceof AppError); assert.equal(error.code, 'CIRCUIT_OPEN'); return 503; }
        finally { durations.push(performance.now() - at); }
      }));
      durations.sort((a, b) => a - b);
      return { requests: outcomes.length, forwarded: forwarded - before, successful: outcomes.filter((status) => status === 200).length,
        rejected: outcomes.filter((status) => status === 503).length, elapsedMs: performance.now() - start, p95Ms: durations[18] };
    };
    const open = await burst(); assert.equal(open.forwarded, 0); assert.equal(open.rejected, 20);
    healthy = true; await new Promise((resolve) => setTimeout(resolve, 110));
    const halfOpen = await burst(); assert.equal(halfOpen.forwarded, 1); assert.equal(halfOpen.successful, 1); assert.equal(halfOpen.rejected, 19);
    assert.equal(transport.dependencyStatus().state, 'closed');
    return { version: 1, measuredAt: new Date().toISOString(), environment: { node: process.version, platform: process.platform, transport: 'loopback-real-mtls' },
      failureThreshold: 2, cooldownMs: 100, initialFailureLatencyMs: initial, open, halfOpen,
      claim: 'Controlled fail-closed dependency outage and single-probe recovery; no business mutation was sent or retried.',
      limitations: ['One process and synthetic dependency, not deployed availability, optional-service acceptance or HA.'] };
  } finally { await new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2); if (args.length !== 2 || args[0] !== '--out') throw new Error('INVALID_ARGUMENTS');
    const result = await measureDependencyFailure(); await writeFile(args[1], `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch { process.stderr.write('RELIABILITY_CHECK_FAILED\n'); process.exitCode = 1; }
}
