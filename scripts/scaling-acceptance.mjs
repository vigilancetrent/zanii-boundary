import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { loadExercise,runScalingExercise } from '../src/product/deployment-exercises.mjs';
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{const args=process.argv.slice(2);if(args.length!==3||args[0]!=='--config'||!args[1]||args[2]!=='--execute')throw new AppError(400,'EXPLICIT_EXERCISE_CONFIG_REQUIRED');const input=await loadExercise(args[1],'scaling');const result=await runScalingExercise(input.config,{execute:true,baseDirectory:input.baseDirectory});process.stdout.write(JSON.stringify(result)+'\n');if(result.liveVerified!==true)process.exitCode=2;}
  catch(error){process.stderr.write(JSON.stringify({status:'BLOCKED',liveVerified:false,code:error instanceof AppError?error.code:'DEPLOYMENT_EXERCISE_FAILED'})+'\n');process.exitCode=2;}
}
