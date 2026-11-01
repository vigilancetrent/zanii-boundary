import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError, exactObject, sha256, signEnvelope } from '../src/protocol.mjs';
import { CONTAINMENT_CHECKS, deploymentDoctor, dockerCommand, readDeploymentFiles, validateImageReference } from '../src/product/deployment.mjs';
import { validateProductAction } from '../src/product/policy.mjs';

// Executed inside the restricted agent. Keys never leave their files or enter stdout/argv.
const PROBE = String.raw`
import fs from 'node:fs'; import net from 'node:net'; import dns from 'node:dns/promises';
import https from 'node:https'; import crypto from 'node:crypto'; import {spawnSync} from 'node:child_process';
let raw=''; for await(const c of process.stdin){raw+=c;if(Buffer.byteLength(raw)>65536)throw Error('INPUT_LIMIT');}
const input=JSON.parse(raw); const secretPaths=['/run/secrets/resource_tls_key','/run/secrets/resource_data_key','/run/secrets/gateway_data_key','/run/secrets/gateway_signing_key','/proc/1/root/run/secrets/gateway_data_key'];
const unreadable=(path)=>{try{fs.readFileSync(path);return false;}catch(e){return ['ENOENT','EACCES','EPERM'].includes(e.code);}};
const connect=(host,port)=>new Promise(resolve=>{const s=net.connect({host,port});let done=false;const end=(denied,code)=>{if(!done){done=true;s.destroy();resolve({denied,code});}};s.setTimeout(2000,()=>end(true,'ETIMEDOUT'));s.once('connect',()=>end(false,'CONNECTED'));s.once('error',e=>end(['ENETUNREACH','EHOSTUNREACH','EACCES','EPERM','ETIMEDOUT'].includes(e.code),e.code));});
let result;
if(input.kind==='network')result=await connect(input.host,input.port);
else if(input.kind==='dns'){let timer;try{await Promise.race([dns.lookup('example.com'),new Promise((_,r)=>{timer=setTimeout(()=>r(Object.assign(Error(),{code:'ETIMEDOUT'})),3000);})]);result={denied:false,code:'RESOLVED'};}catch(e){result={denied:['EAI_AGAIN','EACCES','EPERM','ETIMEDOUT'].includes(e.code),code:e.code};}finally{clearTimeout(timer);}}
else if(input.kind==='secrets')result={denied:secretPaths.every(unreadable),code:'FILE_CHECK'};
else if(input.kind==='runtime')result={denied:['/var/run/docker.sock','/run/containerd/containerd.sock','/etc/shadow'].every(unreadable),code:'FILE_CHECK'};
else if(input.kind==='directory'){let noWrite=false;try{fs.accessSync('/run/runtime',fs.constants.W_OK);}catch(e){noWrite=['EROFS','EACCES','EPERM'].includes(e.code);}const names=fs.readdirSync('/run/runtime').sort();const ids=fs.readdirSync('/run/identity').sort();result={denied:noWrite&&JSON.stringify(names)===JSON.stringify(['gateway.sock'])&&JSON.stringify(ids)===JSON.stringify(['agent-cert.pem','agent-key.pem','agent.jwt','ca.pem']),code:'DIRECTORY_CHECK'};}
else if(input.kind==='child'){const script="const fs=require('node:fs');const names=Object.keys(process.env).filter(k=>/SECRET|PASSWORD|PRIVATE|API_KEY|ACCESS_KEY/.test(k));const paths="+JSON.stringify(secretPaths)+";let clean=!names.length;for(const p of paths){try{fs.readFileSync(p);clean=false;}catch(e){if(!['ENOENT','EACCES','EPERM'].includes(e.code))clean=false;}}process.stdout.write(JSON.stringify({clean}));";const r=spawnSync(process.execPath,['-e',script],{encoding:'utf8',timeout:3000,maxBuffer:4096,shell:false});result={denied:!r.error&&r.status===0&&JSON.parse(r.stdout).clean===true,code:r.error?'CHILD_UNVERIFIED':'CHILD_CHECK'};}
else if(input.kind==='authorized'){const p=input.probe;const token=fs.readFileSync('/run/identity/agent.jwt','utf8').trim();const body=JSON.stringify(p.body);result=await new Promise(resolve=>{let settled=false;const finish=(value)=>{if(!settled){settled=true;resolve(value);}};const r=https.request({socketPath:'/run/runtime/gateway.sock',servername:'gateway',path:p.path,method:'POST',ca:fs.readFileSync('/run/identity/ca.pem'),cert:fs.readFileSync('/run/identity/agent-cert.pem'),key:fs.readFileSync('/run/identity/agent-key.pem'),rejectUnauthorized:true,headers:{authorization:'Bearer '+token,'content-type':'application/json','content-length':Buffer.byteLength(body)}},s=>{let raw='';s.on('data',c=>{raw+=c;if(Buffer.byteLength(raw)>65536){r.destroy();finish({passed:false,code:'RESPONSE_LIMIT'});}});s.on('end',()=>{try{let v=JSON.parse(raw);for(const key of p.selector){if(!v||typeof v!=='object'||!Object.hasOwn(v,key))throw Error();v=v[key];}const hash=crypto.createHash('sha256').update(typeof v==='string'?v:JSON.stringify(v)).digest('hex');finish({passed:s.statusCode===200&&hash===p.sha256,code:'AUTHORIZED_ACTION'});}catch{finish({passed:false,code:'INVALID_RESPONSE'});}});});r.setTimeout(5000,()=>{r.destroy();finish({passed:false,code:'TIMEOUT'});});r.on('error',()=>finish({passed:false,code:'REQUEST_FAILED'}));r.end(body);});}
else throw Error('UNKNOWN_PROBE');
process.stdout.write(JSON.stringify(result));
`;

export function validateAuthorizedProbe(probe) {
  exactObject(probe, ['path', 'body', 'selector', 'sha256']);
  if (probe.path === '/v1/diagnostic/read') {
    exactObject(probe.body, []);
    if (!Array.isArray(probe.selector) || probe.selector.length !== 1 || probe.selector[0] !== 'canary'
        || probe.sha256 !== sha256('agent-runtime-public-containment-canary-v1')) throw new AppError(400, 'INVALID_AUTHORIZED_PROBE');
    return structuredClone(probe);
  }
  if (!probe.body || typeof probe.body !== 'object' || Array.isArray(probe.body)) throw new AppError(400, 'INVALID_AUTHORIZED_PROBE');
  exactObject(probe.body, ['taskId', 'action']);
  const action = validateProductAction(probe.body.action);
  if (probe.path !== '/v1/actions' || typeof probe.body.taskId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(probe.body.taskId)
      || action.kind !== 'read'
      || !Array.isArray(probe.selector) || probe.selector.length !== 2 || probe.selector[0] !== 'result' || probe.selector[1] !== 'content'
      || !/^[a-f0-9]{64}$/.test(probe.sha256) || Buffer.byteLength(JSON.stringify(probe.body)) > 16_384) {
    throw new AppError(400, 'INVALID_AUTHORIZED_PROBE');
  }
  return structuredClone(probe);
}

const safeOptions = (h) => Array.isArray(h.SecurityOpt) && h.SecurityOpt.length === 1 && ['no-new-privileges', 'no-new-privileges:true'].includes(h.SecurityOpt[0])
  && !['host', 'container'].some((value) => String(h.PidMode ?? '').startsWith(value))
  && !['host', 'container'].some((value) => String(h.IpcMode ?? '').startsWith(value))
  && h.UTSMode !== 'host' && h.UsernsMode !== 'host' && !(h.Devices ?? []).length
  && !(h.DeviceRequests ?? []).length && !Object.keys(h.PortBindings ?? {}).length;

export function validateAgentInspection(agent, expectedImage, expectedImageId) {
  const h = agent.HostConfig; const c = agent.Config;
  const paths = (agent.Mounts ?? []).filter((mount) => mount.Type !== 'tmpfs');
  const allowed = new Set(['/run/runtime', '/run/identity']);
  const envNames = ['PATH', 'NODE_VERSION', 'YARN_VERSION', 'NODE_ENV', 'HOME', 'LANG', 'TZ', 'TERM'];
  const forbiddenEnv = (c?.Env ?? []).some((entry) => typeof entry !== 'string' || !envNames.includes(entry.split('=', 1)[0]));
  return h?.NetworkMode === 'none' && h.Privileged === false && h.ReadonlyRootfs === true
    && !(h.CapAdd ?? []).length && (h.CapDrop ?? []).includes('ALL')
    && safeOptions(h) && c?.User === '10003:2000' && c.OpenStdin === true && c.Image === expectedImage && agent.Image === expectedImageId && h.PidsLimit > 0 && h.PidsLimit <= 64
    && h.Memory > 0 && h.Memory <= 268_435_456 && h.NanoCpus > 0 && h.NanoCpus <= 500_000_000
    && paths.length === 2 && paths.every((mount) => allowed.has(mount.Destination) && mount.RW === false && mount.Source !== '/')
    && !forbiddenEnv;
}

export function validateBackendInspection(container, service, expectedImageId) {
  const h = container.HostConfig; const c = container.Config;
  const mounts = new Map(service.volumes.map((mount) => [mount.target, mount.read_only === true]));
  for (const name of service.secrets) mounts.set(`/run/secrets/${name}`, true);
  const actual = (container.Mounts ?? []).filter((mount) => mount.Type !== 'tmpfs');
  return h?.Privileged === false && h.ReadonlyRootfs === true && !(h.CapAdd ?? []).length
    && (h.CapDrop ?? []).includes('ALL') && safeOptions(h)
    && c?.User === service.user && container.Image === expectedImageId && !['host', 'none'].includes(h.NetworkMode)
    && h.PidsLimit > 0 && h.PidsLimit <= service.pids_limit
    && h.Memory > 0 && h.Memory <= 536_870_912 && h.NanoCpus > 0 && h.NanoCpus <= 1_000_000_000
    && actual.length === mounts.size && actual.every((mount) => mounts.has(mount.Destination)
      && mount.RW === !mounts.get(mount.Destination) && mount.Source !== '/');
}

/** Runs read-only diagnostics on an already deployed stack; it never creates or starts containers.
 * @param {{imageRef?:string,probe?:any,composeFile?:string}} options
 */
export async function runContainmentChecks({ imageRef = process.env.RUNTIME_IMAGE, probe, composeFile } = {}) {
  validateImageReference(imageRef); const actionProbe = validateAuthorizedProbe(probe);
  const deployment = await readDeploymentFiles();
  const doctor = await deploymentDoctor({ imageRef });
  if (doctor.status !== 'live-unverified') return doctor;
  const file = composeFile ?? fileURLToPath(new URL('../deploy/compose.yaml', import.meta.url));
  const compose = ['compose', '--file', file]; const startedAt = Date.now();
  const blocked = (reason) => ({ status: 'blocked', reason, liveVerified: false, profileDigest: deployment.profileDigest });
  const command = (args, input, timeoutMs = 10_000) => dockerCommand(args, { imageRef, input, timeoutMs });
  /** @type {Record<string,any>} */
  const ids = {};
  for (const service of ['agent', 'gateway', 'resource']) {
    const found = command([...compose, 'ps', '-q', service]);
    if (!found.ok || !/^[a-f0-9]{12,64}$/.test(found.stdout.trim())) return blocked('RUNNING_STACK_REQUIRED');
    const inspected = command(['inspect', found.stdout.trim()]);
    if (!inspected.ok) return blocked('INSPECTION_FAILED');
    try { ids[service] = JSON.parse(inspected.stdout)[0]; } catch { return blocked('INVALID_INSPECTION'); }
  }
  const image = command(['image', 'inspect', imageRef]);
  let imageId;
  try {
    const data = JSON.parse(image.ok ? image.stdout : 'null')?.[0];
    if (!data || !data.RepoDigests?.includes(imageRef) || !/^sha256:[a-f0-9]{64}$/.test(data.Id)) return blocked('IMAGE_DIGEST_UNVERIFIED');
    imageId = data.Id;
  } catch { return blocked('IMAGE_DIGEST_UNVERIFIED'); }
  const info = command(['info', '--format', '{{json .}}']); let engine;
  try {
    const data = JSON.parse(info.ok ? info.stdout : 'null');
    if (data?.OSType !== 'linux' || !(data.SecurityOptions ?? []).some((v) => /rootless|userns/.test(v))) return blocked('ROOTLESS_OR_USER_NAMESPACE_REQUIRED');
    engine = { serverVersion: data.ServerVersion, kernel: data.KernelVersion, osType: data.OSType };
  } catch { return blocked('INVALID_ENGINE_RESPONSE'); }
  const checks = Object.fromEntries(CONTAINMENT_CHECKS.map((name) => [name, false]));
  const backendNames = Object.keys(ids.resource.NetworkSettings?.Networks ?? {});
  const gatewayNames = Object.keys(ids.gateway.NetworkSettings?.Networks ?? {});
  let backendIsPrivate = false;
  if (backendNames.length === 1 && equalNames(backendNames, gatewayNames)) {
    const network = command(['network', 'inspect', backendNames[0]]);
    try { backendIsPrivate = network.ok && JSON.parse(network.stdout)[0]?.Internal === true; } catch { backendIsPrivate = false; }
  }
  checks['container-controls'] = validateAgentInspection(ids.agent, imageRef, imageId) && ids.gateway.Config?.Image === imageRef
    && ids.resource.Config?.Image === imageRef && validateBackendInspection(ids.gateway, deployment.compose.services.gateway, imageId)
    && validateBackendInspection(ids.resource, deployment.compose.services.resource, imageId) && backendIsPrivate;
  const diagnostics = {};
  const probeAgent = (input, positive = false) => {
    const result = command([...compose, 'exec', '-T', 'agent', 'node', '--input-type=module', '-e', PROBE], JSON.stringify(input), 15_000);
    if (!result.ok) return { passed: false, code: result.reason };
    try {
      const value = JSON.parse(result.stdout);
      return { passed: positive ? value.passed === true : value.denied === true, code: typeof value.code === 'string' ? value.code : 'INVALID_PROBE' };
    } catch { return { passed: false, code: 'INVALID_PROBE' }; }
  };
  const resourceIps = Object.values(ids.resource.NetworkSettings?.Networks ?? {}).map((network) => network.IPAddress).filter(Boolean);
  /** @type {[string, any][]} */
  const probes = [
    ['authenticated-action', { kind: 'authorized', probe: actionProbe }],
    ['external-network', { kind: 'network', host: '1.1.1.1', port: 443 }],
    ['cloud-metadata', { kind: 'network', host: '169.254.169.254', port: 80 }],
    ['dns', { kind: 'dns' }], ['secret-files', { kind: 'secrets' }], ['runtime-socket', { kind: 'runtime' }],
    ['socket-directory', { kind: 'directory' }], ['child-inheritance', { kind: 'child' }],
  ];
  for (const [name, input] of probes) {
    const result = probeAgent(input, name === 'authenticated-action'); checks[name] = result.passed; diagnostics[name] = result.code;
  }
  const portResponse = command([...compose, 'exec', '-T', 'resource', 'node', '-e', "const f=require('node:fs');process.stdout.write(String(JSON.parse(f.readFileSync('/run/config/resource.json','utf8')).listen.port));"]);
  const port = portResponse.ok && /^\d{1,5}$/.test(portResponse.stdout) ? Number(portResponse.stdout) : 0;
  checks['backend-network'] = port > 0 && port <= 65535 && resourceIps.length > 0 && resourceIps.every((host) => probeAgent({ kind: 'network', host, port }).passed);
  if (CONTAINMENT_CHECKS.some((name) => !checks[name])) return { status: 'failed', liveVerified: false, checks, diagnostics, profileDigest: deployment.profileDigest };
  const completedAt = Date.now();
  const runtimeDigest = sha256(JSON.stringify(['agent', 'gateway', 'resource'].map((role) => ({ role, imageId: ids[role].Image,
    user: ids[role].Config.User, networkMode: ids[role].HostConfig.NetworkMode,
    networkNames: Object.keys(ids[role].NetworkSettings?.Networks ?? {}).sort(),
    mounts: (ids[role].Mounts ?? []).map((mount) => ({ type: mount.Type, source: mount.Source, target: mount.Destination, writable: mount.RW })) }))));
  return { status: 'live-verified', liveVerified: true, diagnostics, receipt: { version: 1, profileDigest: deployment.profileDigest, runtimeDigest,
    imageRef, imageId, startedAt, completedAt, expiresAt: completedAt + deployment.profile.receiptLifetimeMs, engine, checks } };
}

function equalNames(left, right) { return left.length === right.length && left.every((name) => right.includes(name)); }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    const args = process.argv.slice(2);
    /** @type {Record<string,string>} */
    const options = {};
    for (let i = 0; i < args.length; i += 2) {
      if (!['--probe-file', '--signing-key', '--out'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new AppError(400, 'INVALID_ARGUMENTS');
      options[args[i]] = args[i + 1];
    }
    if (!options['--probe-file'] || Boolean(options['--signing-key']) !== Boolean(options['--out'])) throw new AppError(400, 'INVALID_ARGUMENTS');
    const raw = await readFile(options['--probe-file']);
    if (raw.length > 16_384) throw new AppError(400, 'PROBE_TOO_LARGE');
    const result = await runContainmentChecks({ probe: JSON.parse(raw.toString('utf8')) });
    if (result.liveVerified && options['--signing-key']) {
      const key = await readFile(options['--signing-key']);
      if (key.length > 4_096) throw new AppError(400, 'KEY_TOO_LARGE');
      await writeFile(options['--out'], `${JSON.stringify(signEnvelope(result.receipt, key, 'containment'))}\n`, { flag: 'wx', mode: 0o600 });
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.liveVerified) process.exitCode = 2;
  })().catch((error) => { process.stderr.write(`${JSON.stringify({ status: 'blocked', code: error instanceof AppError ? error.code : 'CONTAINMENT_CHECK_FAILED' })}\n`); process.exitCode = 2; });
}
