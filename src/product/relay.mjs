import net from 'node:net';
import { chmod,lstat,unlink } from 'node:fs/promises';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';

const codeOf=(error)=>error&&typeof error==='object'&&'code' in error?error.code:undefined;
const schema=z.object({version:z.literal(1),socketPath:z.literal('/run/runtime/gateway.sock'),target:z.object({host:z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/),port:z.number().int().min(1).max(65535)}).strict(),connectTimeoutMs:z.number().int().min(10).max(10000),idleTimeoutMs:z.number().int().min(100).max(60000),lifetimeMs:z.number().int().min(100).max(120000),maxConnections:z.number().int().min(1).max(1024),maxBytes:z.number().int().min(65536).max(16777216)}).strict();
export function parseRelayConfig(raw){const result=schema.safeParse(raw);if(!result.success)throw new AppError(400,'INVALID_RELAY_CONFIGURATION');return result.data;}

async function unboundSocket(path,timeoutMs){return new Promise((resolve)=>{const socket=net.createConnection({path});let done=false;const finish=(unbound)=>{if(done)return;done=true;socket.destroy();resolve(unbound);};socket.once('connect',()=>finish(false));socket.once('error',(error)=>finish(codeOf(error)==='ECONNREFUSED'));socket.setTimeout(timeoutMs,()=>finish(false));});}
/** Owner/inode checks apply to the single pinned leaf; an active or replaced endpoint is never removed. */
export async function recoverOwnedRelaySocket(path,{ownerUid,timeoutMs=500,stat=lstat,remove=unlink,probe=unboundSocket}){
  let before;try{before=await stat(path);}catch(error){if(codeOf(error)==='ENOENT')return false;throw error;}
  if(!before.isSocket()||before.isSymbolicLink()||before.uid!==ownerUid)throw new AppError(403,'UNSAFE_RELAY_SOCKET');
  if(!await probe(path,timeoutMs))throw new AppError(409,'RELAY_SOCKET_ALREADY_EXISTS');
  const current=await stat(path);if(!current.isSocket()||current.isSymbolicLink()||current.uid!==ownerUid||current.ino!==before.ino||current.dev!==before.dev)throw new AppError(409,'RELAY_SOCKET_CHANGED');
  await remove(path);return true;
}

/** Opaque bytes preserve end-to-end TLS client identity. There is exactly one outbound attempt. */
export function createFixedTargetRelay(raw){
  const config=parseRelayConfig(raw);const pairs=new Set();let closed=false;let accepted=0;let refused=0;let sentBytes=0;let receivedBytes=0;
  const server=net.createServer({pauseOnConnect:true,allowHalfOpen:false},(incoming)=>{
    if(closed||pairs.size>=config.maxConnections){refused++;incoming.destroy();return;}
    const pair={incoming,outgoing:null,finished:false,incomingClosed:false,outgoingClosed:false};pairs.add(pair);accepted++;let bytes=0;let connectTimer;let lifetimeTimer;
    const finish=()=>{if(pair.finished)return;pair.finished=true;clearTimeout(connectTimer);clearTimeout(lifetimeTimer);pairs.delete(pair);incoming.destroy();pair.outgoing?.destroy();};
    const close=(side)=>{pair[`${side}Closed`]=true;if(pair.incomingClosed&&pair.outgoingClosed)finish();else(side==='incoming'?pair.outgoing:incoming)?.end();};
    incoming.once('error',finish);incoming.once('close',()=>close('incoming'));incoming.setTimeout(config.idleTimeoutMs,finish);
    lifetimeTimer=setTimeout(finish,config.lifetimeMs);lifetimeTimer.unref?.();
    // No target, headers, TLS settings or routing decisions come from client bytes.
    const outgoing=net.createConnection({host:config.target.host,port:config.target.port,allowHalfOpen:false,autoSelectFamily:false});pair.outgoing=outgoing;
    outgoing.once('error',finish);outgoing.once('close',()=>close('outgoing'));outgoing.setTimeout(config.idleTimeoutMs,finish);
    connectTimer=setTimeout(finish,config.connectTimeoutMs);connectTimer.unref?.();
    const count=(chunk,direction)=>{bytes+=chunk.length;if(bytes>config.maxBytes){finish();return;}if(direction==='sent')sentBytes+=chunk.length;else receivedBytes+=chunk.length;};
    outgoing.once('connect',()=>{clearTimeout(connectTimer);if(pair.finished)return;incoming.on('data',(chunk)=>count(chunk,'sent'));outgoing.on('data',(chunk)=>count(chunk,'received'));incoming.pipe(outgoing);outgoing.pipe(incoming);incoming.resume();});
  });
  return Object.freeze({server,status:()=>({active:pairs.size,accepted,refused,sentBytes,receivedBytes,closed,retries:0}),async close({graceMs=1000}={}){closed=true;let timer;const done=new Promise((resolve)=>server.close(resolve));timer=setTimeout(()=>{for(const pair of pairs){pair.incoming.destroy();pair.outgoing?.destroy();}},Math.min(10000,Math.max(1,graceMs)));timer.unref?.();try{await done;}finally{clearTimeout(timer);}}});
}

/** Filesystem ownership is part of Linux acceptance, never inferred from a TCP fixture. */
export async function startFixedTargetRelay(raw){
  if(process.platform!=='linux')throw new AppError(503,'RELAY_REQUIRES_LINUX');const config=parseRelayConfig(raw);const directory='/run/runtime';const stat=await lstat(directory);
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||stat.gid!==process.getgid()||(stat.mode&0o777)!==0o750)throw new AppError(403,'UNSAFE_RELAY_DIRECTORY');
  await recoverOwnedRelaySocket(config.socketPath,{ownerUid:process.getuid(),timeoutMs:Math.min(500,config.connectTimeoutMs)});
  const relay=createFixedTargetRelay(config);try{await new Promise((resolve,reject)=>{relay.server.once('error',reject);relay.server.listen(config.socketPath,()=>{relay.server.off('error',reject);resolve();});});await chmod(config.socketPath,0o660);}catch(error){await relay.close().catch(()=>{});throw error;}
  const bound=await lstat(config.socketPath);
  return {...relay,async close(options){await relay.close(options);try{const socket=await lstat(config.socketPath);if(socket.isSocket()&&socket.uid===process.getuid()&&socket.ino===bound.ino&&socket.dev===bound.dev)await unlink(config.socketPath);}catch(error){if(codeOf(error)!=='ENOENT')throw error;}}};
}
