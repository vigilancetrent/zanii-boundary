import { randomUUID } from 'node:crypto';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { assertProductIdentity } from './policy.mjs';
import { storeHash, storeJson } from './storage-crypto.mjs';

const CATEGORIES=Object.freeze(['documents','deliveries','memory','learning-examples','learning-candidates','learning-active','learning-promotions','a2a','protocol-sessions','resource-operations','privacy']);
const MODELS=new Set(['learning-candidates','learning-active','learning-promotions']);
export const privacySubjectId=(subject)=>`subject-${storeHash(storeJson(subject))}`;
export const privacyRequestKey=(id)=>`request-${storeHash(identifier(id))}`;
const holdKey=(id)=>`hold-${storeHash(identifier(id))}`;
const subjectOf=(subject)=>{exactObject(subject,['kind','id']);if(!['actor','document'].includes(subject.kind))throw new AppError(400,'INVALID_PRIVACY_SUBJECT');identifier(subject.id);return {kind:subject.kind,id:subject.id};};
const matches=(value,subject)=>subject.kind==='actor'?[value.actorId,value.ownerId,value.createdBy,value.authorizedBy,value.approvedBy,value.identity?.actorId].includes(subject.id):[value.id,value.documentId,value.sourceId,value.action?.documentId,value.result?.documentId].includes(subject.id)||(value.sourceDocumentIds??[]).includes(subject.id)||(value.documentIds??[]).includes(subject.id);

/** Tombstone first; physical cleanup is bounded and may be resumed after a crash.
 * @param {any} options */
export function createPrivacyService({store,jobs,policy={},authorize=async(identity)=>assertProductIdentity(identity,['operator']),now=Date.now,realm=store.realm??'local',readReference}){
  exactObject(policy,[],['retentionMs','exportLifetimeMs']);if(policy.exportLifetimeMs!==undefined)positiveInteger(policy.exportLifetimeMs,86400000);
  const ttl=policy.retentionMs??{};for(const [category,duration]of Object.entries(ttl)){if(!CATEGORIES.includes(category))throw new AppError(400,'INVALID_RETENTION_CATEGORY');positiveInteger(duration,315360000000);}
  const auth=async(identity,action)=>{assertProductIdentity(identity,['operator']);await authorize(identity,action);return identity.tenantId;};
  const holds=async(tenant)=>{const result=[];let after='';let pages=0;do{if(++pages>1000)throw new AppError(503,'PRIVACY_HOLD_CAPACITY');const page=await store.list(tenant,'privacy',{limit:100,after});result.push(...page.items.map(row=>row.value).filter(value=>value.type==='hold'&&!value.releasedAt));if(result.length>1000)throw new AppError(503,'PRIVACY_HOLD_CAPACITY');after=page.next;}while(after);return result;};
  const rejectPurgingIntent=async(tenant,subject)=>{let after='';let pages=0;do{if(++pages>100)throw new AppError(503,'PRIVACY_INTENT_CAPACITY');const page=await store.list(tenant,'object-intents',{limit:100,after});if(page.items.some(row=>row.value.state==='purging'&&(subject.kind==='document'?row.value.documentId===subject.id:row.value.actorId===subject.id)))throw new AppError(409,'PRIVACY_DELETION_IN_PROGRESS');after=page.next;}while(after);};
  const sealKey=(subject)=>`hold-seal-${storeHash(storeJson(subject))}`;
  const sealSubjects=async(tenant,requestId,value)=>{
    const subjects=[...new Set([value.actorId,value.ownerId,value.createdBy,value.authorizedBy,value.approvedBy,value.identity?.actorId].filter(Boolean))].map(id=>({kind:'actor',id}));
    for(const id of new Set([value.documentId,value.sourceId,value.action?.documentId,value.result?.documentId,...(value.sourceDocumentIds??[]),...(value.documentIds??[])].filter(Boolean)))subjects.push({kind:'document',id});
    for(const subject of subjects){subjectOf(subject);const key=sealKey(subject);const previous=await store.get(tenant,'privacy',key);const active=[];for(const id of previous?.requestIds??[]){const request=await store.get(tenant,'privacy',privacyRequestKey(id));if(request&&request.state!=='done')active.push(id);}if(!active.includes(requestId))active.push(requestId);if(active.length>1000)throw new AppError(503,'PRIVACY_SEAL_CAPACITY');await store.put(tenant,'privacy',key,{type:'hold-seal',subject,requestIds:active.sort(),at:now()});}
  };
  const rejectSubjectSeal=async(tenant,subject)=>{const seal=await store.get(tenant,'privacy',sealKey(subject));for(const id of seal?.requestIds??[]){const request=await store.get(tenant,'privacy',privacyRequestKey(id));if(request&&request.state!=='done')throw new AppError(409,'PRIVACY_DELETION_IN_PROGRESS');}};
  const isHeld=async(tenant,subject)=> (await holds(tenant)).some(hold=>hold.subject.kind===subject.kind&&hold.subject.id===subject.id);
  const service={
    async request(identity,{kind,subject,id=randomUUID()}){
      if(!['export','delete'].includes(kind))throw new AppError(400,'INVALID_PRIVACY_REQUEST');const tenant=await auth(identity,`privacy.${kind}`);subject=subjectOf(subject);identifier(id);
      return store.transaction(async()=>{const prior=await store.get(tenant,'privacy',privacyRequestKey(id));if(prior){if(prior.kind!==kind||storeJson(prior.subject)!==storeJson(subject))throw new AppError(409,'PRIVACY_REQUEST_CONFLICT');return prior;}
        const request={version:1,id,type:'request',kind,subject,state:'pending',scope:'single-realm',realm,pendingCleanup:0,createdAt:now(),cursor:{category:0,after:''},removed:0};
        if(kind==='delete'){const existing=await store.get(tenant,'privacy',privacySubjectId(subject));if(existing&&existing.requestId!==id)throw new AppError(409,'PRIVACY_SUBJECT_ALREADY_REQUESTED');await store.put(tenant,'privacy',privacySubjectId(subject),{type:'tombstone',subject,requestId:id,at:now()});await store.put(tenant,'metadata','privacy-learning-block',{requestId:id,at:now()});}
        await store.put(tenant,'privacy',privacyRequestKey(id),request);await jobs.enqueue(identity,{kind:`privacy-${kind}`,payload:{requestId:id},idempotencyKey:id});await store.appendAudit({tenantId:tenant,actorId:identity.actorId,event:`privacy.${kind}.requested`,target:id});return request;
      },{tenantId:tenant});
    },
    async status(identity,id){const tenant=await auth(identity,'privacy.status');identifier(id);const value=await store.get(tenant,'privacy',privacyRequestKey(id));if(!value||value.type!=='request')throw new AppError(404,'PRIVACY_REQUEST_NOT_FOUND');return value;},
    async exportPage(identity,id,{limit=10,after=''}={}){
      const tenant=await auth(identity,'privacy.export');identifier(id);positiveInteger(limit,10);if(after)identifier(after);
      const check=async(request,items)=>{await service.assertAccessible(tenant,request.subject);for(const item of items)for(const entry of item.rows){for(const actor of new Set([entry.value.actorId,entry.value.createdBy,entry.value.authorizedBy,entry.value.ownerId].filter(Boolean)))await service.assertAccessible(tenant,{kind:'actor',id:actor});if(MODELS.has(entry.category)&&await store.get(tenant,'metadata','privacy-learning-block'))throw new AppError(503,'PRIVACY_MODEL_REBUILD_REQUIRED');for(const source of new Set([entry.category==='documents'?entry.value.id:null,entry.value.sourceId,entry.value.documentId,...(entry.value.sourceDocumentIds??[])].filter(Boolean)))await service.assertAccessible(tenant,{kind:'document',id:source});}};
      const snapshot=await store.transaction(async()=>{
        const request=await store.get(tenant,'privacy',privacyRequestKey(id));if(!request||request.kind!=='export')throw new AppError(404,'PRIVACY_REQUEST_NOT_FOUND');
        const page=await store.list(tenant,'privacy',{limit,after});const records=page.items.filter(row=>row.value.type==='export-chunk'&&row.value.requestId===id);
        await check(request,records.map(row=>row.value));return {request,records,next:page.next};
      },{tenantId:tenant});
      const items=structuredClone(snapshot.records.map(row=>row.value));
      for(const item of items)for(const entry of item.rows){const holder=entry.value.objectRef?entry.value:entry.value.result?.objectRef?entry.value.result:null;if(!holder)continue;if(typeof readReference!=='function')throw new AppError(503,'PRIVACY_OBJECT_SOURCE_UNAVAILABLE');const reference=holder.objectRef;const bytes=await readReference(reference,{tenantId:tenant,id:reference.id,purpose:'document'});if(!(bytes instanceof Uint8Array)||bytes.length>32768)throw new AppError(413,'PRIVACY_OBJECT_TOO_LARGE');holder.content=new TextDecoder('utf-8',{fatal:true}).decode(bytes);delete holder.objectRef;}
      return store.transaction(async()=>{
        const request=await store.get(tenant,'privacy',privacyRequestKey(id));if(!request||request.kind!=='export')throw new AppError(404,'PRIVACY_REQUEST_NOT_FOUND');
        for(const row of snapshot.records){const current=await store.get(tenant,'privacy',row.id);if(!current||storeJson(current)!==storeJson(row.value))throw new AppError(409,'PRIVACY_EXPORT_CHANGED');}
        await check(request,items);if(Buffer.byteLength(storeJson(items,1048576))>524288)throw new AppError(413,'PRIVACY_EXPORT_PAGE_TOO_LARGE');
        await store.appendAudit({tenantId:tenant,actorId:identity.actorId,event:'privacy.export.read',target:id,data:{count:items.length}});return {items,next:snapshot.next,state:request.state,scope:'single-realm',realm};
      },{tenantId:tenant});
    },
    async retentionStatus(tenant){identifier(tenant);return {held:(await holds(tenant)).length>0};},
    async assertUnheld(tenant,{actorIds=[],documentIds=[],models=false}={}){
      identifier(tenant);for(const values of [actorIds,documentIds]){if(!Array.isArray(values)||values.length>128)throw new AppError(400,'INVALID_HOLD_SUBJECTS');for(const id of values)identifier(id);}
      if(typeof models!=='boolean')throw new AppError(400,'INVALID_HOLD_SUBJECTS');
      if((await holds(tenant)).some(hold=>models||(hold.subject.kind==='actor'?actorIds.includes(hold.subject.id):documentIds.includes(hold.subject.id))))throw new AppError(409,'LEGAL_HOLD_ACTIVE');return true;
    },
    async resetLearning(identity){
      const tenant=await auth(identity,'privacy.learning.reset');
      return store.transaction(async()=>{
        if((await holds(tenant)).length)throw new AppError(409,'PRIVACY_MODEL_HOLD_ACTIVE');
        let after='';let pages=0;do{if(++pages>1000)throw new AppError(503,'PRIVACY_REQUEST_CAPACITY');const page=await store.list(tenant,'privacy',{limit:100,after});if(page.items.some(row=>row.value.type==='request'&&row.value.kind==='delete'&&row.value.state!=='done'))throw new AppError(409,'PRIVACY_CLEANUP_PENDING');after=page.next;}while(after);
        for(const namespace of MODELS)if((await store.list(tenant,namespace,{limit:1})).items.length)throw new AppError(409,'PRIVACY_MODEL_COPIES_REMAIN');
        const examples=await store.list(tenant,'learning-examples',{limit:100});if(examples.next)throw new AppError(503,'PRIVACY_MODEL_SOURCE_CAPACITY');
        for(const row of examples.items){await service.assertAccessible(tenant,{kind:'actor',id:row.value.actorId});if(row.value.sourceKind==='document')await service.assertAccessible(tenant,{kind:'document',id:row.value.sourceId});}
        await store.delete(tenant,'metadata','privacy-learning-block');await store.appendAudit({tenantId:tenant,actorId:identity.actorId,event:'privacy.learning.reset',target:'current'});return {cleared:true,retrainingRequired:true};
      },{tenantId:tenant});
    },
    async hold(identity,{subject,reason,id=randomUUID()}){const tenant=await auth(identity,'privacy.hold');subject=subjectOf(subject);identifier(id);if(typeof reason!=='string'||reason.length<1||reason.length>256)throw new AppError(400,'INVALID_HOLD_REASON');return store.transaction(async()=>{await rejectPurgingIntent(tenant,subject);await rejectSubjectSeal(tenant,subject);const tombstone=await store.get(tenant,'privacy',privacySubjectId(subject));const request=tombstone?await store.get(tenant,'privacy',privacyRequestKey(tombstone.requestId)):null;if(request&&['purging','cleanup-pending','done'].includes(request.state))throw new AppError(409,'PRIVACY_DELETION_IN_PROGRESS');const previous=await store.get(tenant,'privacy',holdKey(id));if(previous){if(previous.type!=='hold'||storeJson(previous.subject)!==storeJson(subject)||previous.reason!==reason)throw new AppError(409,'PRIVACY_HOLD_CONFLICT');return previous;}const hold={id,type:'hold',subject,reason,createdAt:now(),actorId:identity.actorId};await store.put(tenant,'privacy',holdKey(id),hold);await store.appendAudit({tenantId:tenant,actorId:identity.actorId,event:'privacy.hold.created',target:id});return hold;},{tenantId:tenant});},
    async releaseHold(identity,id){const tenant=await auth(identity,'privacy.hold.release');identifier(id);return store.transaction(async()=>{const hold=await store.get(tenant,'privacy',holdKey(id));if(!hold||hold.type!=='hold')throw new AppError(404,'PRIVACY_HOLD_NOT_FOUND');await store.put(tenant,'privacy',holdKey(id),{...hold,releasedAt:now(),releasedBy:identity.actorId});await store.appendAudit({tenantId:tenant,actorId:identity.actorId,event:'privacy.hold.released',target:id});return {released:true};},{tenantId:tenant});},
    async assertAccessible(tenant,subject){subject=subjectOf(subject);if(await store.get(tenant,'privacy',privacySubjectId(subject)))throw new AppError(410,'PRIVACY_SUBJECT_BLOCKED');return true;},
    async canDeleteReference(tenant,reference){identifier(tenant);const subject={kind:'document',id:identifier(reference.id)};return store.transaction(async()=>{if(await isHeld(tenant,subject))return false;const doc=await store.get(tenant,'documents',subject.id);if(doc?.objectRef&&storeJson(doc.objectRef)===storeJson(reference))return false;return true;},{tenantId:tenant});},
    async completeReference(tenant,requestId,reference){identifier(tenant);identifier(requestId);return store.transaction(async()=>{const marker=`cleanup-${storeHash(storeJson([requestId,reference]))}`;const intent=await store.get(tenant,'privacy',marker);if(intent?.completedAt)return {duplicate:true};const request=await store.get(tenant,'privacy',privacyRequestKey(requestId));if(!intent||!request||request.kind!=='delete'||!['purging','cleanup-pending'].includes(request.state)||request.pendingCleanup<1)throw new AppError(409,'PRIVACY_CLEANUP_CONFLICT');const pendingCleanup=request.pendingCleanup-1;await store.put(tenant,'privacy',marker,{...intent,type:'cleanup-receipt',completedAt:now()});await store.put(tenant,'privacy',privacyRequestKey(requestId),{...request,pendingCleanup,state:request.state==='cleanup-pending'&&pendingCleanup===0?'done':request.state,completedAt:request.state==='cleanup-pending'&&pendingCleanup===0?now():null});return {pendingCleanup};},{tenantId:tenant});},
    async process(job){
      const tenant=job.tenantId;identifier(tenant);exactObject(job.payload,['requestId']);identifier(job.payload.requestId);
      const outcome=await store.transaction(async()=>{const request=await store.get(tenant,'privacy',privacyRequestKey(job.payload.requestId));if(!request||request.type!=='request')throw new AppError(404,'PRIVACY_REQUEST_NOT_FOUND');if(['done','cleanup-pending'].includes(request.state))return {done:request.state==='done',pendingCleanup:request.pendingCleanup};
        const category=CATEGORIES[request.cursor.category];const activeHolds=await holds(tenant);if(await isHeld(tenant,request.subject)||request.kind==='delete'&&MODELS.has(category)&&activeHolds.length){await store.put(tenant,'privacy',privacyRequestKey(request.id),{...request,state:'held',updatedAt:now()});return {held:true};}
        if(!category){if(request.kind==='delete'){if(typeof store.pruneSubjectOperationResults!=='function')throw new AppError(503,'PRIVACY_RESULT_PRUNING_UNAVAILABLE');const result=await store.pruneSubjectOperationResults(tenant,request.subject,{limit:100,after:request.operationAfter??''});if(result.next){await store.put(tenant,'privacy',privacyRequestKey(request.id),{...request,operationAfter:result.next});return {more:true};}}await store.put(tenant,'privacy',privacyRequestKey(request.id),{...request,state:request.pendingCleanup?'cleanup-pending':'done',completedAt:request.pendingCleanup?null:now()});return {done:!request.pendingCleanup,pendingCleanup:request.pendingCleanup};}
        const page=await store.list(tenant,category,{limit:100,after:request.cursor.after});let changed=0;const external=[];const exported=[];
        const selected=(row)=>category==='privacy'?request.kind==='delete'&&row.value.type==='export-chunk'&&row.value.rows.some(entry=>MODELS.has(entry.category)||matches(entry.value,request.subject)):matches(row.value,request.subject)||request.kind==='delete'&&MODELS.has(category);
        if(request.kind==='delete'&&page.items.some(row=>selected(row)&&activeHolds.some(hold=>category==='privacy'?row.value.rows.some(entry=>MODELS.has(entry.category)||matches(entry.value,hold.subject)):matches(row.value,hold.subject)))){await store.put(tenant,'privacy',privacyRequestKey(request.id),{...request,state:'held',updatedAt:now()});return {held:true};}
        for(const row of page.items){if(!selected(row))continue;
          if(request.kind==='export'){exported.push({category,id:row.id,value:row.value});continue;}
          if(category==='privacy')for(const entry of row.value.rows)await sealSubjects(tenant,request.id,entry.value);else await sealSubjects(tenant,request.id,row.value);
          if(category==='documents')await store.put(tenant,'privacy',privacySubjectId({kind:'document',id:row.id}),{type:'tombstone',subject:{kind:'document',id:row.id},requestId:request.id,at:now()});
          const reference=row.value.objectRef??row.value.result?.objectRef;if(reference){const marker=`cleanup-${storeHash(storeJson([request.id,reference]))}`;if(!await store.get(tenant,'privacy',marker)){await store.put(tenant,'privacy',marker,{type:'cleanup-intent',requestId:request.id,at:now()});external.push(reference);}}
          if(category==='resource-operations')await store.put(tenant,category,row.id,{...row.value,result:null,resultExpiredAt:now()});else await store.delete(tenant,category,row.id);changed++;
        }
        const cursor=page.next?{category:request.cursor.category,after:page.next}:{category:request.cursor.category+1,after:''};
        for(const entry of exported)await store.put(tenant,'privacy',`export-${storeHash(storeJson([request.id,entry.category,entry.id]))}`,{type:'export-chunk',requestId:request.id,rows:[entry],createdAt:now()},{expiresAt:now()+(policy.exportLifetimeMs??86400000)});
        // The seal makes later hold creation fail before provider deletion starts.
        const next={...request,state:request.kind==='delete'?'purging':'pending',cursor,removed:request.removed+changed,pendingCleanup:(request.pendingCleanup??0)+external.length,updatedAt:now()};await store.put(tenant,'privacy',privacyRequestKey(request.id),next);
        for(const reference of external)await jobs.enqueue(tenant,{kind:'object-cleanup',payload:{reference,privacyRequestId:request.id},idempotencyKey:storeHash(storeJson([request.id,reference]))});
        return {more:true,requestId:request.id};
      },{tenantId:tenant});
      if(outcome.held||outcome.more)await jobs.enqueue(tenant,{kind:job.kind,payload:job.payload,idempotencyKey:`${job.id}-next`,runAt:now()+(outcome.held?60000:1)});
      return outcome;
    },
    async retain(tenant,{limit=100}={}){identifier(tenant);positiveInteger(limit,100);if((await holds(tenant)).length)return {held:true,removed:0};return store.transaction(async()=>{if((await holds(tenant)).length)return {held:true,removed:0};const cursor=await store.get(tenant,'metadata','privacy-retention-cursor')??{category:0,after:''};const category=CATEGORIES[cursor.category];const page=await store.list(tenant,category,{limit,after:cursor.after});let removed=0;const duration=ttl[category];if(duration)for(const row of page.items){const created=row.value.createdAt??row.value.at;if(Number.isSafeInteger(created)&&created+duration<=now()){if(category==='resource-operations')await store.put(tenant,category,row.id,{...row.value,result:null,resultExpiredAt:now()});else if(category!=='privacy'&&!row.value.objectRef){await store.delete(tenant,category,row.id);removed++;}}}await store.put(tenant,'metadata','privacy-retention-cursor',page.next?{category:cursor.category,after:page.next}:{category:(cursor.category+1)%CATEGORIES.length,after:''});return {examined:page.items.length,removed};},{tenantId:tenant});},
  };return Object.freeze(service);
}
