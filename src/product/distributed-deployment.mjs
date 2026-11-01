import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { createPublicKey } from 'node:crypto';
import { z } from 'zod';
import canonicalize from 'canonicalize';
import { AppError,sha256,verifyEnvelope } from '../protocol.mjs';
import { validateImageReference } from './deployment.mjs';
import { parseProductConfig } from './config.mjs';
import { parseOperationsConfig } from './operations-config.mjs';
import { parseRelayConfig } from './relay.mjs';

export const DISTRIBUTED_KIND='linux-distributed-v2';
export const DISTRIBUTED_CHECKS=Object.freeze(['agent-no-network','agent-secret-isolation','socket-ownership','relay-client-identity','relay-no-retry','container-controls','role-secret-ownership','provider-egress','shared-postgres','cross-replica-authority','pool-capacity','maintenance-roles']);
const IMAGE='${RUNTIME_IMAGE:?Set a verified digest-pinned product image}';
const bad=(code='UNSAFE_DISTRIBUTED_DEPLOYMENT')=>{throw new AppError(400,code);};
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const budget=z.object({minimum:z.number().int().min(1).max(16),maximum:z.number().int().min(1).max(32),maxConnections:z.number().int().min(1).max(100)}).strict();
const roles=z.object({gateway:budget,resource:budget,worker:budget,archive:budget,backup:budget,rotator:budget,migrator:budget}).strict();
const profileSchema=z.object({version:z.literal(2),kind:z.literal(DISTRIBUTED_KIND),receiptLifetimeMs:z.number().int().min(1000).max(900000),roles,
  database:z.object({maxConnections:z.number().int().min(10).max(100000),serverReserved:z.number().int().min(1).max(1000),adminReserve:z.number().int().min(1).max(1000)}).strict(),
  providers:z.array(z.object({name:z.enum(['postgres','objects','kms']),host:z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/),port:z.number().int().min(1).max(65535),addresses:z.array(z.string().refine(value=>isIP(value)===4)).min(1).max(32)}).strict()).length(3),
  providerSubnet:z.string().refine(value=>{const [address,prefix,...extra]=value.split('/');return !extra.length&&isIP(address)===4&&/^\d{1,2}$/.test(prefix??'')&&Number(prefix)>=16&&Number(prefix)<=28;}),logQuotaBytes:z.number().int().min(10485760).max(10737418240),socketPath:z.literal('/run/runtime/gateway.sock')}).strict();
const roleNames=()=>['gateway','resource',...['worker','archive','backup','rotator','migrator'].flatMap(role=>[`${role}-gateway`,`${role}-resource`])];
export const DISTRIBUTED_SERVICES=Object.freeze(['agent','relay',...roleNames()]);
export const serviceRealm=(name)=>name==='gateway'||name==='resource'?name:name.split('-')[1];
export const serviceRole=(name)=>name==='gateway'||name==='resource'?'app':name.split('-')[0];
export const serviceUid=(name)=>name==='gateway'?10001:name==='resource'?10002:name==='agent'?10003:name==='relay'?10004:10000+({worker:10,archive:20,backup:30,rotator:40,migrator:50}[serviceRole(name)])+(serviceRealm(name)==='gateway'?1:2);
const secretName=(service,field)=>`${service.replaceAll('-','_')}_${field}`;
const secretPath=(service,field)=>`/run/secrets/${secretName(service,field)}`;
const secretFields=(name)=>{
  const role=serviceRole(name);const app=role==='app';return [...(app?['tls_key','tls_cert','data_key','audit_key','keyring','signing_key','containment_receipt']:['postgres_credentials']),
    ...(app?['postgres_credentials']:role==='worker'||role==='rotator'?['data_key','audit_key','keyring']:[]),
    ...(['resource','worker-resource'].includes(name)?['objects_credentials','objects_index_key','objects_data_key']:[]),
    ...(role==='archive'?['objects_credentials','objects_index_key','objects_data_key','archive_signing_key']:[]),
    ...(!['rotator','migrator'].includes(role)?['otel_cert','otel_key']:[]),
    ...(role==='backup'?['objects_credentials','objects_index_key','objects_data_key','backup_signing_key','spool_key']:[])];
};
export function distributedPoolBudget(profile){const p=profileSchema.parse(profile);let connections=0;const contributions={};for(const [name,role]of Object.entries(p.roles)){if(role.minimum>role.maximum||['gateway','resource'].includes(name)&&role.minimum<2)bad('INVALID_REPLICA_BUDGET');const realms=['gateway','resource'].includes(name)?1:2;contributions[name]=role.maximum*role.maxConnections*realms;connections+=contributions[name];}const total=connections+p.database.adminReserve+p.database.serverReserved;if(total>p.database.maxConnections)bad('DATABASE_POOL_CAPACITY_EXCEEDED');return {connections,adminReserve:p.database.adminReserve,serverReserved:p.database.serverReserved,total,capacity:p.database.maxConnections,contributions};}

/** Strict separate profile. Same-host replicas are shared-authority redundancy, never multi-AZ evidence. */
export function renderDistributedCompose(raw){
  const profile=profileSchema.parse(raw);distributedPoolBudget(profile);const services={};const secrets={};
  const mount=(source,target,readOnly=true)=>({type:'bind',source,target,read_only:readOnly});
  const common=(name)=>({image:IMAGE,user:`${serviceUid(name)}:2000`,entrypoint:['node'],read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],pids_limit:name==='agent'?64:128,mem_limit:name==='agent'?'256m':serviceRole(name)==='backup'?'2g':'512m',cpus:name==='agent'?0.5:1,tmpfs:[`/tmp:rw,noexec,nosuid,size=16m,mode=1770,uid=${serviceUid(name)},gid=2000`],environment:{NODE_ENV:'production'},stop_grace_period:name==='agent'?'10s':'30s'});
  services.agent={...common('agent'),network_mode:'none',stdin_open:true,command:['scripts/agent-runner.mjs','--socket',profile.socketPath,'--token-file','/run/identity/agent.jwt','--cert-file','/run/identity/agent-cert.pem','--key-file','/run/identity/agent-key.pem','--ca-file','/run/identity/ca.pem'],volumes:[mount('${RUNTIME_SOCKET_DIR:?}','/run/runtime'),mount('${RUNTIME_AGENT_IDENTITY_DIR:?}','/run/identity')]};
  services.relay={...common('relay'),command:['scripts/relay.mjs','--config','/run/config/relay.json'],networks:['ingress'],volumes:[mount('${RUNTIME_CONFIG_DIR:?}/relay.json','/run/config/relay.json'),mount('${RUNTIME_SOCKET_DIR:?}','/run/runtime',false)]};
  for(const name of roleNames()){
    const role=serviceRole(name);const realm=serviceRealm(name);const app=role==='app';const manual=['rotator','migrator'].includes(role);const limits=profile.roles[app?name:role];const fields=secretFields(name);
    for(const field of fields)secrets[secretName(name,field)]={file:`\${RUNTIME_SECRETS_DIR:?}/${name}/${field}`};
    const volumes=[mount(`\${RUNTIME_CONFIG_DIR:?}/${name}.json`,`/run/config/${name}.json`),mount('${RUNTIME_TRUST_DIR:?}','/run/trust'),mount(`\${RUNTIME_STATE_DIR:?}/${name}/logs`,'/var/log/runtime',false)];
    if(role==='backup')volumes.push(mount(`\${RUNTIME_STATE_DIR:?}/${name}/spool`,'/var/lib/runtime-backup',false));
    const command=app?['scripts/start.mjs','--config',`/run/config/${name}.json`]:role==='rotator'?['scripts/key-rotation.mjs','drain-status','--config',`/run/config/${name}.json`]:role==='migrator'?['scripts/migrate.mjs',`/run/config/${name}.json`,'up']:['scripts/worker.mjs',`/run/config/${name}.json`];
    services[name]={...common(name),command,networks:[...(name==='gateway'?['ingress']:[]),'runtime','providers','monitoring'],volumes,secrets:fields.map(field=>secretName(name,field)),deploy:{replicas:limits.minimum},...(manual?{profiles:['maintenance']}:{})};
    if(realm!=='gateway'&&realm!=='resource')bad();
  }
  return {name:'agent-runtime-distributed',services,networks:{ingress:{internal:true},runtime:{internal:true},providers:{external:true,name:'${RUNTIME_PROVIDER_NETWORK:?}'},monitoring:{external:true,name:'${RUNTIME_MONITORING_NETWORK:?}'}},secrets};
}

export function createDistributedConfigTemplates(profile){
  const configs={relay:{version:1,socketPath:profile.socketPath,target:{host:'gateway',port:8443},connectTimeoutMs:1000,idleTimeoutMs:15000,lifetimeMs:30000,maxConnections:256,maxBytes:4194304}};
  const object=(name,lock)=>({endpoint:'https://objects.company.invalid',region:'eu-central-1',credentialsFile:secretPath(name,'objects_credentials'),caFile:'/run/trust/provider-ca.pem',allowPrivateNetworks:true,timeoutMs:10000,bucket:lock?`runtime-${serviceRole(name)}-${serviceRealm(name)}`:'runtime-documents',prefix:lock?serviceRealm(name):'documents',indexKeyFile:secretPath(name,'objects_index_key'),encryptionKeyFile:secretPath(name,'objects_data_key'),encryptionKeyId:`${serviceRole(name)}-objects-v1`,serverEncryption:'aws:kms',sseKmsKeyId:'REPLACE_WITH_VERIFIED_KMS_KEY_ARN',requireLock:lock,maxBytes:1048576});
  for(const name of roleNames()){
    const role=serviceRole(name);const realm=serviceRealm(name);const app=role==='app';const limits=profile.roles[app?name:role];
    const storage={backend:'postgres',...(app||['worker','rotator'].includes(role)?{encryptionKeyFile:secretPath(name,'data_key'),auditKeyFile:secretPath(name,'audit_key'),keyringFile:secretPath(name,'keyring')}:{ }),retentionMs:86400000,postgres:{credentialsFile:secretPath(name,'postgres_credentials'),caFile:'/run/trust/postgres-ca.pem',...(app?{role:'app'}:{}),maxConnections:limits.maxConnections,acquireTimeoutMs:1000,queryTimeoutMs:2000,statementTimeoutMs:1500,lockTimeoutMs:500}};
    if(app){configs[name]={version:1,role:name,profile:'production',listen:{host:'0.0.0.0',port:name==='gateway'?8443:8444},tls:{certFile:secretPath(name,'tls_cert'),keyFile:secretPath(name,'tls_key'),caFile:'/run/trust/ca.pem',requireClientCertificate:true},auth:{issuer:name==='gateway'?'https://issuer.company.invalid':'https://company-runtime-broker',audience:name==='gateway'?'company-agent-runtime':'company-document-resource',jwksFile:`/run/trust/${name==='gateway'?'issuer':'broker'}.jwks.json`,algorithms:['EdDSA'],requireSenderBinding:true,maxLifetimeSeconds:900},storage,signing:{privateKeyFile:secretPath(name,'signing_key')},limits:{bodyBytes:65536,requestTimeoutMs:10000,rateWindowMs:60000,rateRequests:300,maxConcurrency:32},deployment:{kind:DISTRIBUTED_KIND,receiptFile:secretPath(name,'containment_receipt'),trustKeyFile:'/run/trust/distributed-evaluator.pem',maxAgeMs:900000,profileDigest:'REPLACE_WITH_MEASURED_PROFILE_DIGEST',imageRef:'REPLACE_WITH_VERIFIED_PRODUCT_IMAGE'},integrations:name==='gateway'?{resource:{origin:'https://resource:8444',caFile:'/run/trust/ca.pem',certFile:secretPath(name,'tls_cert'),keyFile:secretPath(name,'tls_key'),issuer:'https://company-runtime-broker',audience:'company-document-resource',signingKeyFile:secretPath(name,'signing_key'),kid:'REPLACE_WITH_BROKER_KEY_ID',allowPrivateNetworks:true,required:true}}:{documents:{toolVersion:'documents-v1',maxContentBytes:32768,internalRecipients:[]}},protocols:{},operations:{policy:{required:true,worker:{required:true},archive:{required:true},backup:{required:true}},services:{privacy:{},...(name==='resource'?{objects:object(name,false)}:{})}}};}
    if(role==='backup'){storage.postgres.queryTimeoutMs=30000;storage.postgres.statementTimeoutMs=15000;}
    if(!app){configs[name]={version:1,role,realm,storage,worker:{pollIntervalMs:1000,leaseMs:role==='backup'?300000:30000,timeoutMs:role==='backup'?240000:20000,batchSize:10},services:role==='worker'?{privacy:{},...(realm==='resource'?{objects:object(name,false)}:{})}:role==='archive'?{archive:{objectStorage:object(name,true),signingKeyFile:secretPath(name,'archive_signing_key'),publicKeyFile:`/run/trust/${name}-public.pem`,retentionMs:31536000000}}:role==='backup'?{backup:{objectStorage:object(name,true),signingKeyFile:secretPath(name,'backup_signing_key'),publicKeyFile:`/run/trust/${name}-public.pem`,spoolDirectory:'/var/lib/runtime-backup',spoolKeyFile:secretPath(name,'spool_key'),retentionMs:31536000000,maxSnapshotBytes:67108864}}:{}};}
  }
  for(const name of roleNames())if(!['rotator','migrator'].includes(serviceRole(name))){configs[name].logging={directory:'/var/log/runtime',maxBytes:8388608,files:3,maxQueueBytes:65536,required:true};configs[name].telemetry={serviceName:`runtime-${name}`,samplingRatio:0.1,maxQueueSize:512,maxExportBatchSize:64,exportTimeoutMs:3000,scheduledDelayMs:1000,collector:{url:'https://otel-collector:4318/v1/traces',caFile:'/run/trust/monitoring-ca.pem',certFile:secretPath(name,'otel_cert'),keyFile:secretPath(name,'otel_key'),allowPrivateNetworks:true}};}
  return configs;
}

export function validateDistributedDeployment(raw,compose,configs){
  let profile;try{profile=profileSchema.parse(raw);}catch{bad();}if(new Set(profile.providers.map(provider=>provider.name)).size!==3)bad('EXPLICIT_PROVIDER_TARGETS_REQUIRED');const poolBudget=distributedPoolBudget(profile);if(!same(compose,renderDistributedCompose(profile)))bad();
  if(!configs||!same(Object.keys(configs).sort(),['relay',...roleNames()].sort()))bad('DISTRIBUTED_CONFIGS_REQUIRED');parseRelayConfig(configs.relay);if(configs.relay.target.host!=='gateway'||configs.relay.target.port!==8443)bad('FIXED_GATEWAY_TARGET_REQUIRED');
  for(const name of roleNames()){
    const config=configs[name];const role=serviceRole(name);const app=role==='app';const realm=serviceRealm(name);const limits=profile.roles[app?name:role];const check=structuredClone(config);
    if(app){if(check.deployment?.kind!==DISTRIBUTED_KIND||check.profile!=='production'||check.role!==name||check.listen?.socketPath||check.listen?.host!=='0.0.0.0'||check.listen?.port!==(name==='gateway'?8443:8444))bad('DISTRIBUTED_TCP_REQUIRED');if(check.deployment.profileDigest==='REPLACE_WITH_MEASURED_PROFILE_DIGEST')check.deployment.profileDigest='0'.repeat(64);if(check.deployment.imageRef==='REPLACE_WITH_VERIFIED_PRODUCT_IMAGE')check.deployment.imageRef=`example.invalid/runtime@sha256:${'0'.repeat(64)}`;parseProductConfig(check);}
    else{if(config.role!==role||config.realm!==realm)bad('DISTRIBUTED_REALM_MISMATCH');parseOperationsConfig(config);}
    if(config.logging&&config.logging.maxBytes*config.logging.files*limits.maximum>profile.logQuotaBytes)bad('LOG_VOLUME_BUDGET_EXCEEDED');
    if(app&&config.storage.postgres.role!=='app')bad('APPLICATION_DATABASE_ROLE_REQUIRED');
    if(config.storage.backend!=='postgres'||config.storage.path||config.storage.postgres.maxConnections!==limits.maxConnections)bad('SHARED_AUTHORITY_REQUIRED');
    if(name==='gateway'&&config.integrations?.resource?.origin!=='https://resource:8444')bad('FIXED_RESOURCE_TARGET_REQUIRED');
    if(role==='backup'){const snapshot=config.services.backup.maxSnapshotBytes;const memory=Number.parseInt(compose.services[name].mem_limit,10)*1073741824;if(memory<snapshot*12+335544320||config.storage.postgres.acquireTimeoutMs+config.storage.postgres.queryTimeoutMs>config.worker.timeoutMs)bad('BACKUP_CAPACITY_BUDGET_REQUIRED');}
    const objects=config.operations?.services?.objects??config.services?.objects??config.services?.archive?.objectStorage??config.services?.backup?.objectStorage;
    if(objects){const target=profile.providers.find(provider=>provider.name==='objects');const url=new URL(objects.endpoint);if(url.protocol!=='https:'||url.hostname!==target.host||Number(url.port||443)!==target.port)bad('EXPLICIT_PROVIDER_TARGETS_REQUIRED');}
    const allowed=new Set(secretFields(name).map(field=>secretPath(name,field)));const walk=(value)=>{if(typeof value==='string'&&value.startsWith('/run/secrets/')&&!allowed.has(value))bad('CROSS_ROLE_SECRET_MOUNT');if(Array.isArray(value))for(const child of value)walk(child);else if(value&&typeof value==='object')for(const child of Object.values(value))walk(child);};walk(config);
  }
  const normalized=structuredClone(configs);for(const name of ['gateway','resource'])delete normalized[name].deployment.profileDigest;
  const profileDigest=sha256(canonicalize({profile,compose,configs:normalized}));return {status:'static-verified',liveVerified:false,imageVerified:false,profileDigest,poolBudget};
}

/** @param {URL|string} [root] @param {any} [options] */
export async function readDistributedDeploymentFiles(root=new URL('../../deploy/distributed/',import.meta.url),{configurationDirectory=undefined,composeFile=undefined}={}){
  if(typeof root==='string')root=root.startsWith('file:')?new URL(root):pathToFileURL(resolve(root)+'/');if(root.protocol!=='file:')bad('LOCAL_PROFILE_REQUIRED');
  const paths=[new URL('profile.json',root),composeFile??new URL('compose.yaml',root),...['relay',...roleNames()].map(name=>configurationDirectory?resolve(configurationDirectory,name+'.json'):new URL(`config/${name}.json.example`,root))];const [profile,compose,...values]=await Promise.all(paths.map(async(path)=>JSON.parse(await readFile(path,'utf8'))));const configs=Object.fromEntries(['relay',...roleNames()].map((name,index)=>[name,values[index]]));return {profile,compose,configs,...validateDistributedDeployment(profile,compose,configs)};
}

export function verifyDistributedDeploymentReceipt(envelope,pinnedPublicKey,{profileDigest=undefined,imageRef=undefined,now=Date.now(),maxAgeMs=900000}={}){
  try{if(!Number.isSafeInteger(now)||!Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||maxAgeMs>900000)bad();const receipt=verifyEnvelope(envelope,pinnedPublicKey?.type==='public'?pinnedPublicKey:createPublicKey(pinnedPublicKey),'containment-distributed');const parsed=z.object({version:z.literal(2),profileKind:z.literal(DISTRIBUTED_KIND),profileDigest:z.string().regex(/^[a-f0-9]{64}$/),runtimeDigest:z.string().regex(/^[a-f0-9]{64}$/),imageRef:z.string(),imageId:z.string().regex(/^sha256:[a-f0-9]{64}$/),startedAt:z.number().int().positive(),completedAt:z.number().int().positive(),expiresAt:z.number().int().positive(),engine:z.object({osType:z.literal('linux'),serverVersion:z.string().min(1).max(256),kernel:z.string().min(1).max(256)}).strict(),checks:z.record(z.string(),z.boolean()),observations:z.object({replicas:z.object({gateway:z.number().int().min(2).max(32),resource:z.number().int().min(2).max(32)}).strict(),databaseAuthorityDigest:z.string().regex(/^[a-f0-9]{64}$/),egressPolicyDigest:z.string().regex(/^[a-f0-9]{64}$/),poolCapacity:z.number().int().positive(),poolBudget:z.number().int().positive(),relayAttempts:z.literal(1),forwardedIdentityTrusted:z.literal(false),failureDomainClaim:z.literal('same-host-replicas-only')}).strict()}).strict().parse(receipt);
    validateImageReference(imageRef);validateImageReference(parsed.imageRef);if(parsed.profileDigest!==profileDigest||parsed.imageRef!==imageRef||!same(Object.keys(parsed.checks).sort(),[...DISTRIBUTED_CHECKS].sort())||DISTRIBUTED_CHECKS.some(name=>parsed.checks[name]!==true)||parsed.observations.poolBudget>parsed.observations.poolCapacity||parsed.startedAt>parsed.completedAt||parsed.completedAt>now||parsed.expiresAt<=now||parsed.expiresAt-parsed.completedAt>900000||now-parsed.completedAt>Math.min(maxAgeMs,900000))bad();return Object.freeze(parsed);
  }catch{throw new AppError(403,'INVALID_DISTRIBUTED_DEPLOYMENT_RECEIPT');}
}
