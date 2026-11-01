import { Pool } from 'pg';
import { AppError } from '../src/protocol.mjs';
import { loadOperationsConfig } from '../src/product/operations-config.mjs';
import { migratePostgres,migrateSqlite } from '../src/product/migrations.mjs';
let pool;let material;
try{const [path,direction,...flags]=process.argv.slice(2);if(!['up','down'].includes(direction)||flags.some(flag=>!['--allow-destructive','--decommission','--target=0','--target=1','--target=2','--target=3'].includes(flag)))throw new AppError(400,'MIGRATION_ARGUMENTS_REQUIRED');
  const loaded=await loadOperationsConfig(path);material=loaded.material;const config=loaded.config;const target=flags.find(flag=>flag.startsWith('--target='));const options={direction,allowDestructive:flags.includes('--allow-destructive'),allowDecommission:flags.includes('--decommission'),...(target?{targetVersion:Number(target.slice(9))}:{})};
  let result;if(config.storage.backend==='sqlite')result=await migrateSqlite({path:config.storage.path,...options});
  else{if(!material.postgres?.ca?.includes('BEGIN CERTIFICATE'))throw new AppError(400,'POSTGRES_TLS_REQUIRED');if(['PGOPTIONS','PGBINARY','PGREPLICATION'].some(name=>process.env[name]))throw new AppError(400,'AMBIENT_POSTGRES_CONFIGURATION');pool=new Pool({...material.postgres.connection,ssl:{ca:material.postgres.ca,rejectUnauthorized:true},max:1,connectionTimeoutMillis:1000,query_timeout:5000,statement_timeout:4000,lock_timeout:500,application_name:'agent-runtime-migrator'});result=await migratePostgres({pool,realm:config.realm,...options});}
  process.stdout.write(JSON.stringify(result)+'\n');
}catch(error){process.stderr.write(JSON.stringify({error:error instanceof AppError?error.code:'MIGRATION_FAILED'})+'\n');process.exitCode=1;}
finally{await pool?.end();material?.encryptionKey?.fill(0);material?.auditKey?.fill(0);}
