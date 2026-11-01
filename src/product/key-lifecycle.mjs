import { AppError, identifier, positiveInteger } from '../protocol.mjs';
import { createPublicKey, verify, createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { z } from 'zod';
import { hashCanonical } from './policy.mjs';
import { readOperationsFile } from './operations-config.mjs';
import { createHttpsTransport } from '../adapters/transport.mjs';
import { verifyArchiveManifest, verifySignedValue } from './audit-archive.mjs';

/** Retirement is allowed only while a realm-wide epoch is frozen and all leases have drained. */
export function createKeyLifecycle({store,verifyRetainedRecord,now=Date.now,signal=undefined,deadlineAt=Infinity}){
  const check=()=>{if(signal?.aborted)throw new AppError(503,'KEY_MAINTENANCE_SHUTDOWN');if(now()>=deadlineAt)throw new AppError(504,'KEY_MAINTENANCE_TIMEOUT');};
  const frozen=async()=>{check();const epoch=await store.keyEpoch();if(!epoch.frozen)throw new AppError(409,'KEY_WRITERS_NOT_FROZEN');if(await store.activeLeaseCount({now:now()}))throw new AppError(409,'KEY_WRITERS_NOT_DRAINED');return epoch;};
  return Object.freeze({
    async freeze(){const epoch=await store.keyEpoch();return epoch.frozen?epoch:store.freezeWrites({expectedVersion:epoch.version});},
    async drained(){const epoch=await store.keyEpoch();return {epoch,activeLeases:await store.activeLeaseCount({now:now()}),drained:epoch.frozen&&!(await store.activeLeaseCount({now:now()}))};},
    async rotate({activeKeyId,limit=100,onActivated=async(_epoch)=>{void _epoch;}}){identifier(activeKeyId);positiveInteger(limit,1000);let epoch=await frozen();epoch=await store.activateKeyEpoch({expectedVersion:epoch.version,activeKeyId});await onActivated(epoch);let examined=0;let rotated=0;
      if(store.backend==='postgres'){let after='';do{check();const page=await store.listTenants({limit:100,after});for(const tenantId of [...(!after?['system']:[]),...page.items]){let cursor='';do{check();const batch=await store.rekeyRecords({tenantId,limit,after:cursor});examined+=batch.examined;rotated+=batch.rotated;cursor=batch.next;}while(cursor);}after=page.next;}while(after);}
      else {let after='';do{check();const batch=await store.rekeyRecords({limit,after});examined+=batch.examined;rotated+=batch.rotated;after=batch.next;}while(after);}
      return {epoch,examined,rotated,auditCiphertextPreserved:true,frozen:true};
    },
    async retirementProof(keyId){identifier(keyId);const epoch=await frozen();if(keyId===epoch.activeKeyId)throw new AppError(409,'KEY_STILL_REFERENCED');if(typeof verifyRetainedRecord!=='function')throw new AppError(409,'RETAINED_KEY_VERIFIER_REQUIRED');
      let references=0;let after='';do{check();const page=await store.retainedKeyRecords({after,limit:100});for(const record of page.items){const verified=await verifyRetainedRecord(record);if(!verified||verified.verified!==true||!Array.isArray(verified.keyIds))throw new AppError(409,'KEY_INVENTORY_INCOMPLETE');if(verified.keyIds.includes(keyId)||keyId!=='legacy'&&verified.keyIds.some(id=>['legacy','legacy-v1'].includes(id)))references++;}after=page.next;}while(after);
      await store.assertKeyRetirable(keyId,{backupReferences:references});const current=await frozen();if(current.version!==epoch.version)throw new AppError(409,'WRITE_EPOCH_CONFLICT');return {keyDomain:'application-realm-dek',realm:store.realm??'local',keyId,epoch:epoch.version,references:0,frozen:true};
    },
    async retire(keyId,removeKey){
      identifier(keyId);if(typeof removeKey!=='function')throw new AppError(400,'KEY_REMOVAL_CALLBACK_REQUIRED');
      if(!store.beginKeyRetirement||!store.finishKeyRetirement)throw new AppError(503,'KEY_RETIREMENT_SEAL_REQUIRED');
      let epoch=await frozen();let referenceProofHash;let proof;
      if(epoch.retirement){if(epoch.retirement.keyId!==keyId||epoch.retirement.state!=='sealed')throw new AppError(409,'KEY_RETIREMENT_ALREADY_SEALED');referenceProofHash=epoch.retirement.proofHash;proof={realm:store.realm??'local',keyId,epoch:epoch.version,references:0,frozen:true};}
      else{proof=await this.retirementProof(keyId);referenceProofHash=hashCanonical(proof);const seal=await store.beginKeyRetirement({expectedVersion:proof.epoch,keyId,referenceProofHash});epoch={...epoch,version:seal.version};}
      // Unknown provider outcomes keep the durable seal. A trusted adapter must retry the same idempotency key.
      const receipt=await removeKey({...proof,epoch:epoch.version,referenceProofHash,idempotencyKey:referenceProofHash});
      if(receipt?.retired!==true||receipt.keyId!==keyId||receipt.referenceProofHash!==referenceProofHash||!(/^[a-f0-9]{64}$/.test(receipt.providerReceiptDigest??'')))throw new AppError(503,'KEY_DELETION_UNCONFIRMED');
      await store.finishKeyRetirement({expectedVersion:epoch.version,keyId,referenceProofHash});return {retired:true,keyId,referenceProofHash,providerReceiptDigest:receipt.providerReceiptDigest,frozen:true};
    },
    async unfreeze(){const epoch=await frozen();return store.unfreezeWrites({expectedVersion:epoch.version});},
  });
}

/** Public verification keys only. Pending/unknown uploads cannot establish a complete retirement inventory. */
export function createRetainedKeyVerifier({archivePublicKey,backupPublicKey,realm}){
  return async({kind,tenantId,record})=>{
    let manifest;
    if(kind==='archive'&&archivePublicKey)manifest=verifyArchiveManifest(record,{publicKey:archivePublicKey,tenantId});
    else if(kind==='archive-intent'&&record?.status==='complete'&&archivePublicKey){manifest=verifyArchiveManifest(record.signedManifest,{publicKey:archivePublicKey,tenantId,checkpoint:record.checkpoint});if(manifest.id!==record.id||canonicalize(manifest.base)!==canonicalize(record.expectedBase)||canonicalize(manifest.keyIds)!==canonicalize(record.keyIds)||manifest.createdAt!==record.createdAt||manifest.retainUntil!==record.retainUntil)throw new AppError(409,'KEY_INVENTORY_INCOMPLETE');}
    else if(kind==='backup'&&record?.status==='complete'&&backupPublicKey){manifest=verifySignedValue(record.signedManifest,backupPublicKey);if(manifest.purpose!=='agent-runtime-postgres-backup'||manifest.tenantId!==tenantId||manifest.realm!==realm||manifest.id!==record.id)throw new AppError(409,'KEY_INVENTORY_INCOMPLETE');}
    else throw new AppError(409,'KEY_INVENTORY_INCOMPLETE');
    if(!Array.isArray(manifest.keyIds)||manifest.keyIds.some(id=>typeof id!=='string'||id.length>2048))throw new AppError(409,'KEY_INVENTORY_INCOMPLETE');
    return {verified:true,keyIds:manifest.keyIds};
  };
}

/** Hash only authoritative deletion state; raw subject identities never leave this process.
 * @param {any} options */
export async function privacyInventoryDigest({store,realm,deadlineAt=Date.now()+20000}){
  const hash=createHash('sha256');hash.update(canonicalize({version:1,purpose:'agent-runtime-privacy-inventory',realm}));
  let after='';let pages=0;const visit=async(tenant)=>{let cursor='';do{if(Date.now()>=deadlineAt||++pages>10000)throw new AppError(503,'PRIVACY_INVENTORY_INCOMPLETE');const page=await store.list(tenant,'privacy',{limit:100,after:cursor});for(const row of page.items)if(row.value.type==='tombstone'||row.value.type==='request'&&row.value.kind==='delete'||['cleanup-intent','cleanup-receipt','hold-seal'].includes(row.value.type)){const text=canonicalize({tenantId:tenant,id:row.id,value:row.value});hash.update(`${Buffer.byteLength(text)}:`);hash.update(text);}cursor=page.next;}while(cursor);};
  await visit('system');do{if(Date.now()>=deadlineAt)throw new AppError(503,'PRIVACY_INVENTORY_INCOMPLETE');const page=await store.listTenants({limit:100,after});for(const tenant of page.items)if(tenant!=='system')await visit(tenant);after=page.next;}while(after);
  return hash.digest('hex');
}

/** The configured authority attests fencing; a caller-supplied boolean is never accepted.
 * @param {any} raw @param {any} options
 */
export async function createConfiguredSourceFenceVerifier(raw,{baseDirectory=process.cwd(),now=Date.now}={}){
  const schema=z.object({origin:z.string().url(),path:z.literal('/v1/runtime/fencing/status'),caFile:z.string().min(1),certFile:z.string().min(1),keyFile:z.string().min(1),trustKeyFile:z.string().min(1),allowPrivateNetworks:z.boolean().default(false),maxAgeMs:z.number().int().min(100).max(300000).default(60000),timeoutMs:z.number().int().min(100).max(30000).default(5000)}).strict();
  const parsed=schema.safeParse(raw);if(!parsed.success)throw new AppError(400,'INVALID_FENCE_VERIFIER_CONFIGURATION');const config=parsed.data;
  const pinned=createPublicKey(await readOperationsFile(config.trustKeyFile,{baseDirectory}));if(pinned.asymmetricKeyType!=='ed25519')throw new AppError(400,'INVALID_FENCE_TRUST_KEY');
  const transport=createHttpsTransport({origin:config.origin,tls:{ca:await readOperationsFile(config.caFile,{baseDirectory}),cert:await readOperationsFile(config.certFile,{baseDirectory}),key:await readOperationsFile(config.keyFile,{baseDirectory,secret:true})},allowPrivateNetworks:config.allowPrivateNetworks,timeoutMs:config.timeoutMs,maxBytes:4096,allowedPaths:[config.path],allowedMethods:['POST'],dependencyName:'recovery'});
  return async({realm,restoreSha256,epoch,targetPrivacyDigest})=>{
    if(!['gateway','resource'].includes(realm)||!(/^[a-f0-9]{64}$/.test(restoreSha256))||!(/^[a-f0-9]{64}$/.test(targetPrivacyDigest))||!Number.isSafeInteger(epoch))throw new AppError(400,'INVALID_FENCE_REQUEST');
    const response=await transport.request(config.path,{method:'POST',body:{version:1,realm,restoreSha256,epoch,targetPrivacyDigest}});
    const envelope=z.object({manifest:z.object({version:z.literal(1),purpose:z.literal('agent-runtime-source-fence'),realm:z.enum(['gateway','resource']),restoreSha256:z.string().regex(/^[a-f0-9]{64}$/),epoch:z.number().int().positive(),sourceWritersFenced:z.literal(true),providerCredentialsRevoked:z.literal(true),privacyReconciled:z.literal(true),targetPrivacyDigest:z.string().regex(/^[a-f0-9]{64}$/),observedAt:z.number().int().positive(),expiresAt:z.number().int().positive()}).strict(),signature:z.string().regex(/^[A-Za-z0-9_-]{86}$/)}).strict().safeParse(response.body);
    if(response.status!==200||!envelope.success)throw new AppError(503,'SOURCE_FENCE_UNVERIFIED');const {manifest,signature}=envelope.data;const time=now();
    if(manifest.realm!==realm||manifest.restoreSha256!==restoreSha256||manifest.epoch!==epoch||manifest.targetPrivacyDigest!==targetPrivacyDigest||manifest.observedAt>time||time-manifest.observedAt>config.maxAgeMs||manifest.expiresAt<=time||manifest.expiresAt-manifest.observedAt>config.maxAgeMs||!verify(null,Buffer.from(canonicalize(manifest)),pinned,Buffer.from(signature,'base64url')))throw new AppError(503,'SOURCE_FENCE_UNVERIFIED');
    return {verified:true,evidenceDigest:hashCanonical(envelope.data),observedAt:manifest.observedAt};
  };
}
