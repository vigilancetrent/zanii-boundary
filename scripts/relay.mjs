import { readOperationsFile } from '../src/product/operations-config.mjs';
import { startFixedTargetRelay } from '../src/product/relay.mjs';
import { AppError } from '../src/protocol.mjs';
let relay;
try{const args=process.argv.slice(2);if(args.length!==2||args[0]!=='--config')throw new AppError(400,'RELAY_CONFIG_REQUIRED');relay=await startFixedTargetRelay(JSON.parse(await readOperationsFile(args[1])));let stopping=false;for(const signal of ['SIGINT','SIGTERM'])process.once(signal,async()=>{if(stopping)return;stopping=true;try{await relay.close();process.exitCode=0;}catch{process.exitCode=1;}});}
catch(error){process.stderr.write(JSON.stringify({status:'BLOCKED',code:error instanceof AppError?error.code:'RELAY_START_FAILED'})+'\n');process.exitCode=2;}
