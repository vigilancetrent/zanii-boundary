import { readFile } from 'node:fs/promises';
import { effectiveDeadline,remainingBudget } from './context.mjs';
import { AppError,positiveInteger } from '../protocol.mjs';
import { storeHash } from './storage-crypto.mjs';
import { DatabaseSync } from 'node:sqlite';
import { lstatSync } from 'node:fs';

export const databaseRealm = (realm) => {
  if (!['gateway', 'resource'].includes(realm)) throw new AppError(400, 'INVALID_STORAGE_REALM'); return `runtime_${realm}`;
};

/** The migrator uses its own credential. Runtime roles cannot alter schema or audit history.
 * Transaction connection rule: https://node-postgres.com/features/transactions */
export async function migrationFiles() {
  return Promise.all(['001_authority', '002_maintenance'].map(async (name, index) => {
    const [up, down] = await Promise.all(['up', 'down'].map((direction) => readFile(new URL(`../../migrations/postgres/${name}.${direction}.sql`, import.meta.url), 'utf8')));
    return { version: index + 1, up, down, checksum: storeHash(`${up}\0${down}`) };
  }));
}
export async function migratePostgres({ pool, realm, direction = 'up', allowDestructive = false, allowDecommission = false, timeoutMs=30000, acquireTimeoutMs=1000, targetVersion = direction === 'up' ? 2 : 0 }) {
  const schema = databaseRealm(realm); const role = `${schema}_app`; const worker = `${schema}_worker`;
  if (!['up', 'down'].includes(direction) || direction === 'down' && !allowDestructive) throw new AppError(400, 'MIGRATION_ARGUMENTS_REQUIRED');
  if (!Number.isInteger(targetVersion) || targetVersion < 0 || targetVersion > 2 || direction==='up'&&targetVersion===0 || allowDecommission&&(direction!=='down'||targetVersion!==0)) throw new AppError(400, 'INVALID_MIGRATION_TARGET');
  const files = await migrationFiles(); const { up, down, checksum } = files[0];
  const client = await boundedMigrationClient(pool,{timeoutMs,acquireTimeoutMs});
  try {
    await client.query('BEGIN');await client.query("SET LOCAL statement_timeout='5000ms';SET LOCAL lock_timeout='500ms'"); await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`${schema}:migrations`]);
    const exists = (await client.query('SELECT to_regclass($1) AS name', [`${schema}.schema_version`])).rows[0].name;
    let currentVersion=0;
    if (exists) {
      const rows = (await client.query(`SELECT version,checksum FROM ${schema}.schema_version ORDER BY version`)).rows;
      if (!rows.length || rows.some((row, index) => row.version !== index + 1 || row.checksum !== files[index]?.checksum)) throw new AppError(409, 'MIGRATION_CHECKSUM_MISMATCH');currentVersion=rows.at(-1).version;
    }
    if(direction==='up'&&targetVersion<currentVersion||direction==='down'&&targetVersion>currentVersion)throw new AppError(400,'INVALID_MIGRATION_DIRECTION');
    if(direction==='down'&&targetVersion===currentVersion){await client.query('COMMIT');return {realm,direction,version:currentVersion,checksum:currentVersion?files[currentVersion-1].checksum:null,decommissioned:false};}
    if(direction==='down'&&targetVersion<currentVersion&&!allowDecommission){
      for(const table of currentVersion>=2?['objects','operations','audit','usage','leases','audit_bases','archive_segments','archive_intents','backup_catalogues','job_tombstones','archive_jobs','backup_jobs']:['objects','operations','audit','usage','leases'])if((await client.query(`SELECT 1 FROM ${schema}.${table} LIMIT 1`)).rows.length)throw new AppError(409,'MIGRATION_DOWN_REQUIRES_RESTORE');
      if(currentVersion>=2&&(await client.query(`SELECT 1 FROM ${schema}.key_epochs WHERE frozen OR quarantined OR retiring_id IS NOT NULL OR retirement_state IS NOT NULL OR active_id<>'legacy' OR version<>1`)).rows.length)throw new AppError(409,'MIGRATION_DOWN_REQUIRES_RESTORE');
    }
    if (direction === 'down') {
      if (exists) {
        if (targetVersion === 0) await client.query(down.replaceAll('__SCHEMA__', schema));
        else { for(const table of ['objects','operations','audit','usage','leases','audit_bases','archive_segments','archive_intents','backup_catalogues','job_tombstones','archive_jobs','backup_jobs'])if((await client.query(`SELECT 1 FROM ${schema}.${table} LIMIT 1`)).rows.length)throw new AppError(409,'MIGRATION_DOWN_REQUIRES_RESTORE');const rows = (await client.query(`SELECT version FROM ${schema}.schema_version ORDER BY version DESC`)).rows; for (const row of rows) if (row.version > targetVersion) { await client.query(files[row.version - 1].down.replaceAll('__SCHEMA__', schema)); await client.query(`DELETE FROM ${schema}.schema_version WHERE version=$1`, [row.version]); } }
      }
    } else if (!exists) {
      for (const name of [role, worker]) await client.query(`DO $$ BEGIN CREATE ROLE ${name} NOLOGIN NOSUPERUSER NOBYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$;`);
      await client.query(up.replaceAll('__SCHEMA__', schema));
      for (const table of ['objects', 'operations', 'usage', 'audit', 'leases']) {
        await client.query(`ALTER TABLE ${schema}.${table} ENABLE ROW LEVEL SECURITY; ALTER TABLE ${schema}.${table} FORCE ROW LEVEL SECURITY;
          CREATE POLICY tenant_isolation ON ${schema}.${table} USING (tenant=current_setting('runtime.tenant_id',true)) WITH CHECK (tenant=current_setting('runtime.tenant_id',true));`);
      }
      await client.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role},${worker};
        GRANT SELECT,INSERT,UPDATE,DELETE ON ${schema}.objects TO ${role},${worker};
        GRANT SELECT,INSERT,UPDATE ON ${schema}.operations,${schema}.usage,${schema}.leases TO ${role},${worker};
        GRANT SELECT,INSERT ON ${schema}.audit TO ${role},${worker};
        GRANT SELECT ON ${schema}.schema_version TO ${role},${worker};
        REVOKE ALL ON ${schema}.tenants FROM PUBLIC;
        CREATE FUNCTION ${schema}.register_tenant(value text) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS
          'INSERT INTO ${schema}.tenants(tenant) VALUES(value) ON CONFLICT DO NOTHING';
        REVOKE ALL ON FUNCTION ${schema}.register_tenant(text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION ${schema}.register_tenant(text) TO ${role},${worker};
        CREATE FUNCTION ${schema}.list_tenants(cursor text,maximum integer) RETURNS TABLE(tenant text) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS
          'SELECT tenant FROM ${schema}.tenants WHERE tenant>cursor AND tenant<>''system'' ORDER BY tenant LIMIT LEAST(GREATEST(maximum,1),1001)';
        REVOKE ALL ON FUNCTION ${schema}.list_tenants(text,integer) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION ${schema}.list_tenants(text,integer) TO ${worker};`);
      await client.query(`INSERT INTO ${schema}.schema_version VALUES(1,$1)`, [checksum]);
    }
    if (direction === 'up' && targetVersion >= 2) {
      const applied = (await client.query(`SELECT version FROM ${schema}.schema_version WHERE version=2`)).rows.length;
      if (!applied) {
        for (const suffix of ['archive', 'backup', 'rotator']) await client.query(`DO $$ BEGIN CREATE ROLE ${schema}_${suffix} NOLOGIN NOSUPERUSER NOBYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$;`);
        await client.query("SELECT set_config('runtime.tenant_id','system',true)");
        await client.query(files[1].up.replaceAll('__SCHEMA__', schema));
        for (const table of ['job_tombstones', 'job_index', 'audit_bases', 'backup_catalogues', 'archive_segments', 'archive_intents', 'archive_jobs', 'backup_jobs', 'maintenance_heartbeats']) await client.query(`ALTER TABLE ${schema}.${table} ENABLE ROW LEVEL SECURITY; ALTER TABLE ${schema}.${table} FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ON ${schema}.${table} USING (tenant=current_setting('runtime.tenant_id',true)) WITH CHECK (tenant=current_setting('runtime.tenant_id',true));`);
        await client.query(`GRANT USAGE ON SCHEMA ${schema} TO ${schema}_archive,${schema}_backup,${schema}_rotator;
          GRANT SELECT ON ALL TABLES IN SCHEMA ${schema} TO ${schema}_backup;
          REVOKE SELECT ON ${schema}.tenants FROM ${schema}_backup;
          GRANT SELECT ON ${schema}.key_epochs,${schema}.audit_bases TO ${role},${worker},${schema}_archive,${schema}_rotator;
          GRANT SELECT,INSERT ON ${schema}.job_tombstones TO ${role},${worker};
          GRANT SELECT,INSERT,UPDATE,DELETE ON ${schema}.job_index TO ${role},${worker};
          GRANT SELECT ON ${schema}.audit,${schema}.schema_version,${schema}.archive_intents TO ${schema}_archive;
          GRANT SELECT ON ${schema}.backup_catalogues,${schema}.archive_segments TO ${role},${worker},${schema}_rotator,${schema}_archive;
          GRANT SELECT,INSERT,UPDATE,DELETE ON ${schema}.archive_jobs TO ${schema}_archive;
          GRANT SELECT,INSERT,UPDATE,DELETE ON ${schema}.backup_jobs TO ${schema}_backup;
          GRANT SELECT ON ${schema}.maintenance_heartbeats TO ${role},${worker},${schema}_archive;
          GRANT EXECUTE ON FUNCTION ${schema}.write_backup_catalogue(text,text,text) TO ${schema}_backup;
          GRANT SELECT,INSERT,UPDATE,DELETE ON ${schema}.objects TO ${schema}_rotator;
          GRANT SELECT,UPDATE ON ${schema}.operations TO ${schema}_rotator;
          GRANT SELECT ON ${schema}.audit,${schema}.leases,${schema}.usage,${schema}.schema_version TO ${schema}_rotator;
          GRANT INSERT ON ${schema}.audit TO ${schema}_rotator;
          GRANT UPDATE ON ${schema}.key_epochs TO ${schema}_rotator;
          GRANT EXECUTE ON FUNCTION ${schema}.active_lease_count() TO ${schema}_rotator;
          GRANT EXECUTE ON FUNCTION ${schema}.retained_key_records(text,integer) TO ${schema}_rotator;
          GRANT EXECUTE ON FUNCTION ${schema}.initialize_epoch(text) TO ${role},${worker};
          GRANT EXECUTE ON FUNCTION ${schema}.maintenance_admission() TO ${schema}_archive,${schema}_backup;
          GRANT EXECUTE ON FUNCTION ${schema}.prepare_archive_intent(text,text,text) TO ${schema}_archive;
          GRANT EXECUTE ON FUNCTION ${schema}.archive_prefix(text,bigint,text,bigint,text,text,text) TO ${schema}_archive;
          GRANT EXECUTE ON FUNCTION ${schema}.register_tenant(text) TO ${schema}_rotator;
          GRANT EXECUTE ON FUNCTION ${schema}.list_tenants(text,integer) TO ${schema}_archive,${schema}_backup,${schema}_rotator;`);
        await client.query(`CREATE FUNCTION ${schema}.write_maintenance_heartbeat(value text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
          DECLARE purpose text; BEGIN purpose=CASE current_setting('role',true) WHEN '${schema}_archive' THEN 'archive' WHEN '${schema}_backup' THEN 'backup' WHEN '${schema}_worker' THEN 'worker' ELSE NULL END;
          IF purpose IS NULL THEN RAISE EXCEPTION 'ROLE_DENIED' USING ERRCODE='42501'; END IF;
          INSERT INTO ${schema}.maintenance_heartbeats VALUES('system',purpose,(value::jsonb)->>'ownerId',value) ON CONFLICT(tenant,kind,id) DO UPDATE SET record=excluded.record; END $body$;
          REVOKE ALL ON FUNCTION ${schema}.write_maintenance_heartbeat(text) FROM PUBLIC;
          GRANT EXECUTE ON FUNCTION ${schema}.write_maintenance_heartbeat(text) TO ${schema}_archive,${schema}_backup,${schema}_worker;`);
        await client.query(`INSERT INTO ${schema}.schema_version VALUES(2,$1)`, [files[1].checksum]);
      }
    }
    await client.query('COMMIT'); return { realm, direction, version: direction==='up'?Math.max(currentVersion,targetVersion):targetVersion, decommissioned:allowDecommission, checksum: files[Math.max(0, targetVersion - 1)].checksum };
  } catch (error) { try { await client.query('ROLLBACK'); } catch { /* Preserve migration failure. */ } throw error; }
  finally { client.release(); }
}

export async function migrateSqlite({path,direction='up',allowDestructive=false,targetVersion=direction==='up'?3:1}){
  if(!['up','down'].includes(direction)||direction==='down'&&!allowDestructive||![1,2,3].includes(targetVersion))throw new AppError(400,'MIGRATION_ARGUMENTS_REQUIRED');
  const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink())throw new AppError(400,'INVALID_STORAGE_PATH');
  const files=await Promise.all(['002_operational_indexes','003_maintenance'].map(async(name,index)=>{const [up,down]=await Promise.all(['up','down'].map(d=>readFile(new URL(`../../migrations/sqlite/${name}.${d}.sql`,import.meta.url),'utf8')));return {version:index+2,up,down,checksum:storeHash(`${up}\0${down}`)};}));
  const db=new DatabaseSync(path);db.function('runtime_rotator',()=>0);
  try{db.exec('PRAGMA busy_timeout=1000;BEGIN IMMEDIATE;CREATE TABLE IF NOT EXISTS runtime_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL) STRICT;');
    const applied=db.prepare('SELECT version,checksum FROM runtime_migrations ORDER BY version').all();const currentVersion=Math.max(1,...applied.map(row=>Number(row.version)));if(direction==='up'&&targetVersion<currentVersion||direction==='down'&&targetVersion>currentVersion)throw new AppError(400,'INVALID_MIGRATION_DIRECTION');for(const row of applied)if(files.find(file=>file.version===row.version)?.checksum!==row.checksum)throw new AppError(409,'MIGRATION_CHECKSUM_MISMATCH');
    if(direction==='up')for(const file of files){if(file.version<=targetVersion&&!applied.some(row=>row.version===file.version)){db.exec(file.up);db.prepare('INSERT INTO runtime_migrations VALUES(?,?)').run(file.version,file.checksum);}}
    else for(const file of [...files].reverse())if(file.version>targetVersion&&applied.some(row=>row.version===file.version)){
      if(file.version===3){if(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='key_epochs'").get()&&db.prepare("SELECT 1 FROM key_epochs WHERE frozen<>0 OR version<>1 OR active_id<>'legacy' OR retiring_id IS NOT NULL OR retirement_state IS NOT NULL").get())throw new AppError(409,'MIGRATION_DOWN_REQUIRES_RESTORE');for(const table of ['job_index','audit_bases','archive_segments','archive_intents','backup_catalogues','job_tombstones'])if(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table)&&db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get())throw new AppError(409,'MIGRATION_DOWN_REQUIRES_RESTORE');}
      db.exec(file.down);db.prepare('DELETE FROM runtime_migrations WHERE version=?').run(file.version);
    }
    db.exec('COMMIT');return {backend:'sqlite',direction,version:targetVersion,checksum:files[Math.max(0,targetVersion-2)].checksum};
  }catch(error){if(db.isTransaction)db.exec('ROLLBACK');throw error;}finally{db.close();}
}

async function boundedMigrationClient(pool,{timeoutMs,acquireTimeoutMs}){
  positiveInteger(timeoutMs,60000);positiveInteger(acquireTimeoutMs,10000);const deadline=effectiveDeadline({timeoutMs});const acquireDeadline=Math.min(deadline,Date.now()+acquireTimeoutMs);let abandoned=false;let timer;let raw;
  try{raw=await Promise.race([Promise.resolve().then(()=>pool.connect()).then(client=>{if(abandoned||Date.now()>=acquireDeadline){client.release(new Error('MIGRATION_ACQUIRE_TIMEOUT'));throw new AppError(503,'DATABASE_ACQUIRE_TIMEOUT');}return client;}),new Promise((_,reject)=>{timer=setTimeout(()=>{abandoned=true;reject(new AppError(503,'DATABASE_ACQUIRE_TIMEOUT'));},Math.max(1,acquireDeadline-Date.now()));})]);}finally{clearTimeout(timer);}
  let uncertain=false;return {async query(text,values=undefined){const remaining=text==='ROLLBACK'?500:Math.min(5000,remainingBudget(deadline));let queryTimer;try{return await Promise.race([raw.query(text,values),new Promise((_,reject)=>{queryTimer=setTimeout(()=>{uncertain=true;reject(new AppError(503,'DATABASE_TIMEOUT'));},remaining);})]);}finally{clearTimeout(queryTimer);}},release(){raw.release(uncertain?new Error('MIGRATION_CONNECTION_UNCERTAIN'):undefined);}};
}
