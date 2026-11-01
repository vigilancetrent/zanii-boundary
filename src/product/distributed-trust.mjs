import { X509Certificate,createPublicKey } from 'node:crypto';
import { lstatSync,mkdtempSync,writeFileSync,unlinkSync,rmdirSync,readFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { AppError } from '../protocol.mjs';

export const DISTRIBUTED_TRUST_FILES=Object.freeze(['ca.pem','postgres-ca.pem','provider-ca.pem','monitoring-ca.pem','issuer.jwks.json','broker.jwks.json','distributed-evaluator.pem','archive-gateway-public.pem','archive-resource-public.pem','backup-gateway-public.pem','backup-resource-public.pem']);
const fail=()=>{throw new AppError(403,'INVALID_DISTRIBUTED_PUBLIC_TRUST');};
const same=(a,b)=>JSON.stringify([...a].sort())===JSON.stringify([...b].sort());
export function probeIpv4OnlyNetwork(){
  if(Object.values(networkInterfaces()).flat().some(value=>value.family==='IPv6'&&!value.internal))return false;
  try{return readFileSync('/proc/net/ipv6_route','utf8').split('\n').filter(Boolean).every(line=>line.trim().split(/\s+/).at(-1)==='lo');}
  catch(error){return error&&typeof error==='object'&&'code' in error&&error.code==='ENOENT';}
}
/** Fixed tiny write validates the declared tmpfs ownership from inside each non-root role. */
export function probeOwnedTemporaryDirectory(){
  const parent=lstatSync('/tmp');if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||parent.gid!==2000||(parent.mode&0o7777)!==0o1770)return false;
  const directory=mkdtempSync('/tmp/runtime-probe-');const path=directory+'/bounded';try{writeFileSync(path,'temporary-role-check',{flag:'wx',mode:0o600});const value=lstatSync(path);return value.isFile()&&!value.isSymbolicLink()&&value.uid===process.getuid()&&value.gid===2000&&(value.mode&0o777)===0o600;}
  finally{try{unlinkSync(path);}finally{rmdirSync(directory);}}
}
/** Shared trust is public-only by construction; unknown files never become shared credentials. */
export function validateDistributedTrustFiles(files){
  if(!files||typeof files!=='object'||Array.isArray(files)||!same(Object.keys(files),DISTRIBUTED_TRUST_FILES))fail();
  for(const [name,raw]of Object.entries(files)){
    if(typeof raw!=='string'||!raw.length||Buffer.byteLength(raw)>65536)fail();const text=raw.trim();
    try{
      if(name.endsWith('.jwks.json')){
        const value=JSON.parse(text);if(!value||text!==JSON.stringify(value)&&text!==JSON.stringify(value,null,2)||!same(Object.keys(value),['keys'])||!Array.isArray(value.keys)||value.keys.length<1||value.keys.length>16)fail();const ids=new Set();
        for(const jwk of value.keys){if(!jwk||typeof jwk!=='object'||Array.isArray(jwk)||Object.keys(jwk).some(key=>!['kty','crv','x','kid','alg','use','key_ops'].includes(key))||jwk.kty!=='OKP'||jwk.crv!=='Ed25519'||typeof jwk.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(jwk.x)||typeof jwk.kid!=='string'||!/^[A-Za-z0-9._-]{1,128}$/.test(jwk.kid)||ids.has(jwk.kid)||jwk.alg!==undefined&&jwk.alg!=='EdDSA'||jwk.use!==undefined&&jwk.use!=='sig'||jwk.key_ops!==undefined&&(!Array.isArray(jwk.key_ops)||!same(jwk.key_ops,['verify'])))fail();ids.add(jwk.kid);if(createPublicKey({key:jwk,format:'jwk'}).asymmetricKeyType!=='ed25519')fail();}
      }else if(['ca.pem','postgres-ca.pem','provider-ca.pem','monitoring-ca.pem'].includes(name)){
        const blocks=text.match(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/g);if(!blocks?.length||blocks.length>8||blocks.join('').replace(/\s/g,'')!==text.replace(/\s/g,''))fail();for(const block of blocks)if(!new X509Certificate(block).ca)fail();
      }else{
        if(!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----$/.test(text)||createPublicKey(text).asymmetricKeyType!=='ed25519')fail();
      }
    }catch{fail();}
  }
  return true;
}
