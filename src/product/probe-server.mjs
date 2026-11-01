import { createServer } from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { createHash, timingSafeEqual } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { sendJson, sendError } from '../http.mjs';
import { createConfiguredProbe, probeSchema } from './probes.mjs';
import { readOperationsFile } from './operations-config.mjs';
import { assertNetworkDestination } from '../adapters/transport.mjs';
import { requestContext } from './context.mjs';

const file = z.string().min(1).max(4096);
const schema = z.object({ version: z.literal(1), listen: z.object({ host: z.enum(['127.0.0.1', '0.0.0.0']), port: z.number().int().min(0).max(65535) }).strict(),
  tls: z.object({ caFile: file, certFile: file, keyFile: file }).strict(), authorizationFile: file, peers: z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(4),
  timeoutMs: z.number().int().min(100).max(15000).default(5000),
  targets: z.array(z.object({ name: z.enum(['gateway', 'resource']), maxReplicas: z.number().int().min(1).max(32), probe: probeSchema }).strict()).min(1).max(2) }).strict();

export function parseProbeServerConfig(raw) {
  const parsed = schema.safeParse(raw); if (!parsed.success) throw new AppError(400, 'INVALID_PROBE_SERVER_CONFIGURATION'); const config = parsed.data;
  if (new Set(config.targets.map((item) => item.name)).size !== config.targets.length) throw new AppError(400, 'DUPLICATE_PROBE_TARGET'); return config;
}

/** Enumerates each fixed service DNS name; request parameters cannot select a destination.
 * @param {any} raw @param {any} options */
export async function startProbeServer(raw, { baseDirectory = process.cwd() } = {}) {
  const config = parseProbeServerConfig(raw);
  const read = (path, secret = false) => readOperationsFile(path, { baseDirectory, secret });
  const tls = { ca: await read(config.tls.caFile), cert: await read(config.tls.certFile), key: await read(config.tls.keyFile, true) };
  for (const target of config.targets) await createConfiguredProbe(target.probe, { baseDirectory });
  let active = false; let closing = false;
  async function metrics() {
    const lines = ['# TYPE runtime_probe_success gauge', '# TYPE runtime_probe_duration_seconds gauge', '# TYPE runtime_probe_instances gauge'];
    for (const target of config.targets) {
      let addresses;
      try {
        const origin = new URL(target.probe.origin); const host = origin.hostname.replace(/^\[|\]$/g, ''); let timer;
        try { addresses = isIP(host) ? [{ address: host }] : await Promise.race([lookup(host, { all: true }), new Promise((_, reject) => { timer = setTimeout(() => reject(new AppError(503, 'PROBE_DNS_TIMEOUT')), Math.min(1000, config.timeoutMs)); })]); }
        finally { clearTimeout(timer); }
        addresses = [...new Set(addresses.map((item) => item.address))];
        if (!addresses.length || addresses.length > target.maxReplicas) throw new AppError(503, 'PROBE_REPLICA_BOUND_EXCEEDED');
        for (const address of addresses) assertNetworkDestination(address, { allowPrivateNetworks: target.probe.allowPrivateNetworks });
        const probes = await Promise.all(addresses.map((address) => createConfiguredProbe({ ...target.probe, origin: `https://${address.includes(':') ? `[${address}]` : address}:${origin.port || '443'}`,
          servername: target.probe.servername ?? (isIP(host) ? undefined : host) }, { baseDirectory })));
        lines.push(`runtime_probe_instances{target="${target.name}"} ${probes.length}`);
        for (const mode of ['live', 'startup', 'ready']) {
          const started = performance.now(); const outcomes = [];
          for (let offset = 0; offset < probes.length; offset += 8) outcomes.push(...await Promise.all(probes.slice(offset, offset + 8).map((probe) => probe.run(mode).then(() => true, () => false))));
          lines.push(`runtime_probe_success{target="${target.name}",mode="${mode}"} ${outcomes.every(Boolean) ? 1 : 0}`,
            `runtime_probe_duration_seconds{target="${target.name}",mode="${mode}"} ${(performance.now() - started) / 1000}`);
        }
      } catch {
        lines.push(`runtime_probe_instances{target="${target.name}"} 0`);
        for (const mode of ['live', 'startup', 'ready']) lines.push(`runtime_probe_success{target="${target.name}",mode="${mode}"} 0`);
      }
    }
    return `${lines.join('\n')}\n`;
  }
  const server = createServer({ ...tls, minVersion: 'TLSv1.3', requestCert: true, rejectUnauthorized: true, maxHeaderSize: 16384 }, (req, res) => {
    Promise.resolve().then(async () => {
      const socket = /** @type {import('node:tls').TLSSocket} */ (req.socket); const peer = socket.getPeerCertificate();
      const fingerprint = peer.raw && createHash('sha256').update(peer.raw).digest('hex'); const token = (await read(config.authorizationFile, true)).trim(); const expected = `Bearer ${token}`; const actual = req.headers.authorization;
      if (!socket.authorized || !config.peers.includes(fingerprint) || typeof actual !== 'string' || token.length < 32 || actual.length !== expected.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) throw new AppError(403, 'PROBE_EXPORTER_AUTHENTICATION_REQUIRED');
      if (req.method === 'GET' && req.url === '/health/live') return sendJson(res, 200, { live: !closing });
      if (req.method !== 'GET' || req.url !== '/metrics') throw new AppError(404, 'ROUTE_NOT_FOUND');
      if (active || closing) throw new AppError(503, 'PROBE_EXPORTER_BUSY'); active = true;
      try { const text = await requestContext.run({ deadlineAt: Date.now() + config.timeoutMs }, metrics); res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4', 'cache-control': 'no-store' }); res.end(text); }
      finally { active = false; }
    }).catch((error) => sendError(res, error));
  });
  server.maxConnections = 8; server.maxHeadersCount = 16; server.requestTimeout = config.timeoutMs + 1000; server.headersTimeout = config.timeoutMs + 1000; server.timeout = config.timeoutMs + 1000; server.on('timeout', (socket) => socket.destroy());
  await new Promise((done, reject) => { server.once('error', reject); server.listen(config.listen.port, config.listen.host, () => { server.off('error', reject); done(); }); });
  return { origin: `https://${config.listen.host}:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`, async close() { if (closing) return; closing = true; await new Promise((done) => { const timer = setTimeout(() => { server.closeAllConnections(); done(); }, config.timeoutMs + 1000); timer.unref(); server.close(() => { clearTimeout(timer); done(); }); server.closeIdleConnections(); }); } };
}
export async function loadProbeServer(path) { let raw; try { raw = JSON.parse(await readOperationsFile(path)); } catch { throw new AppError(400, 'PROBE_SERVER_CONFIGURATION_UNAVAILABLE'); } return startProbeServer(raw, { baseDirectory: dirname(resolve(path)) }); }
