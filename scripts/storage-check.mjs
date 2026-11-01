import { loadOperationsConfig } from '../src/product/operations-config.mjs';
import { openPostgresStore } from '../src/product/postgres-store.mjs';
import { openAsyncSqliteStore } from '../src/product/async-store.mjs';
import { AppError } from '../src/protocol.mjs';
let store;let material;
try{const loaded=await loadOperationsConfig(process.argv[2]);material=loaded.material;const config=loaded.config;
  store=config.storage.backend==='postgres'?await openPostgresStore({...config.storage.postgres,...material.postgres,realm:config.realm,role:config.role,...material}):openAsyncSqliteStore({path:config.storage.path,...material,role:config.role});
  process.stdout.write(JSON.stringify({health:store.health?await store.health():{healthy:true,backend:'sqlite'},epoch:await store.keyEpoch(),restore:store.restoreStatus?await store.restoreStatus():null})+'\n');
}catch(error){process.stderr.write(JSON.stringify({error:error instanceof AppError?error.code:'STORAGE_CHECK_FAILED'})+'\n');process.exitCode=1;}
finally{await store?.close();material?.encryptionKey?.fill(0);material?.auditKey?.fill(0);}
