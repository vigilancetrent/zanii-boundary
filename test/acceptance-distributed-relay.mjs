import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { mkdir,mkdtemp,rm,lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createFixedTargetRelay,recoverOwnedRelaySocket } from '../src/product/relay.mjs';

test('Linux UDS byte relay carries bytes and recovers an owned SIGKILL socket while refusing an active endpoint',{timeout:10000},async(t)=>{
  if(process.platform!=='linux')throw new Error('DISTRIBUTED_SOCKET_ACCEPTANCE_REQUIRES_LINUX');
  await mkdir('.test-data',{recursive:true});const directory=await mkdtemp(resolve('.test-data','relay-linux-'));const socketPath=resolve(directory,'relay.sock');const stalePath=resolve(directory,'stale.sock');let child;let relay;let backend;
  t.after(async()=>{child?.kill();await relay?.close();if(backend)await new Promise(done=>backend.close(done));await rm(directory,{recursive:true,force:true});});
  backend=net.createServer(socket=>socket.pipe(socket));await new Promise(done=>backend.listen(0,'127.0.0.1',done));
  relay=createFixedTargetRelay({version:1,socketPath:'/run/runtime/gateway.sock',target:{host:'127.0.0.1',port:backend.address().port},connectTimeoutMs:1000,idleTimeoutMs:2000,lifetimeMs:5000,maxConnections:4,maxBytes:65536});await new Promise(done=>relay.server.listen(socketPath,done));
  assert.equal(await new Promise((done,reject)=>{const client=net.connect(socketPath,()=>client.write('opaque-mutation'));client.once('data',bytes=>{client.destroy();done(bytes.toString());});client.once('error',reject);}), 'opaque-mutation');
  await assert.rejects(recoverOwnedRelaySocket(socketPath,{ownerUid:process.getuid()}),{code:'RELAY_SOCKET_ALREADY_EXISTS'});
  child=spawn(process.execPath,['--input-type=module','-e',"import net from 'node:net';net.createServer().listen(process.argv[1],()=>process.stdout.write('READY\\n'));",stalePath],{stdio:['ignore','pipe','pipe'],shell:false});
  await new Promise((done,reject)=>{child.once('error',reject);child.stdout.once('data',done);child.once('exit',()=>reject(new Error('SOCKET_CHILD_EXITED')));});const exited=new Promise(done=>child.once('exit',done));child.kill('SIGKILL');await exited;assert.equal((await lstat(stalePath)).isSocket(),true);assert.equal(await recoverOwnedRelaySocket(stalePath,{ownerUid:process.getuid()}),true);await assert.rejects(lstat(stalePath),{code:'ENOENT'});
});
