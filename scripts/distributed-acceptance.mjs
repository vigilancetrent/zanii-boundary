import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError,signEnvelope } from '../src/protocol.mjs';
import { readOperationsFile } from '../src/product/operations-config.mjs';
import { readDistributedDeploymentFiles } from '../src/product/distributed-deployment.mjs';
import { loadAcceptanceConfig,runDistributedAcceptance,providerRules } from '../src/product/distributed-acceptance.mjs';
export function acceptanceArguments(args){const values={};for(let index=0;index<args.length;index++){const name=args[index];if(['--static','--execute','--print-egress-rules'].includes(name)){if(values[name])throw new AppError(400,'INVALID_ACCEPTANCE_ARGUMENTS');values[name]=true;}else{if(!['--config','--signing-key','--out'].includes(name)||!args[index+1]||values[name])throw new AppError(400,'INVALID_ACCEPTANCE_ARGUMENTS');values[name]=args[++index];}}return values;}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{const args=acceptanceArguments(process.argv.slice(2));let result;
  if(args['--static']||args['--print-egress-rules']){const deployment=await readDistributedDeploymentFiles();result=args['--print-egress-rules']?providerRules(deployment.profile):{status:'STATIC_ONLY',liveVerified:false,imageVerified:false,profileDigest:deployment.profileDigest,poolBudget:deployment.poolBudget};}
  else{if(!args['--config'])throw new AppError(400,'ACCEPTANCE_CONFIG_REQUIRED');const config=await loadAcceptanceConfig(args['--config']);result=await runDistributedAcceptance(config,{execute:args['--execute']===true});if(Boolean(args['--signing-key'])!==Boolean(args['--out']))throw new AppError(400,'ACCEPTANCE_SIGNING_ARGUMENTS_REQUIRED');if(result.liveVerified&&args['--out']){const key=await readOperationsFile(args['--signing-key'],{secret:true,maxBytes:4096});await writeFile(args['--out'],JSON.stringify(signEnvelope(result.receipt,key,'containment-distributed'))+'\n',{flag:'wx',mode:0o600});}}
  process.stdout.write(JSON.stringify(result)+'\n');if(!args['--static']&&!args['--print-egress-rules']&&(!('liveVerified' in result)||result.liveVerified!==true))process.exitCode=2;
}catch(error){process.stderr.write(JSON.stringify({status:'BLOCKED',code:error instanceof AppError?error.code:'DISTRIBUTED_ACCEPTANCE_FAILED',liveVerified:false})+'\n');process.exitCode=2;}}
