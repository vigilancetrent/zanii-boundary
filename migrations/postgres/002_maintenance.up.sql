CREATE TABLE __SCHEMA__.job_index(tenant text NOT NULL,id text NOT NULL,state text NOT NULL,kind text NOT NULL,due bigint NOT NULL,PRIMARY KEY(tenant,id));
CREATE INDEX job_index_due ON __SCHEMA__.job_index(tenant,due,id) WHERE state IN ('queued','retry','running');
CREATE TABLE __SCHEMA__.audit_bases(tenant text PRIMARY KEY,sequence bigint NOT NULL,hash text NOT NULL,reference text NOT NULL,manifest text NOT NULL);
CREATE TABLE __SCHEMA__.backup_catalogues(tenant text NOT NULL,id text NOT NULL,record text NOT NULL,PRIMARY KEY(tenant,id));
CREATE TABLE __SCHEMA__.archive_intents(tenant text NOT NULL,id text NOT NULL,record text NOT NULL,PRIMARY KEY(tenant,id));
CREATE TABLE __SCHEMA__.archive_segments(tenant text NOT NULL,sequence bigint NOT NULL,reference text NOT NULL,manifest text NOT NULL,PRIMARY KEY(tenant,sequence));
CREATE TABLE __SCHEMA__.key_epochs(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),version bigint NOT NULL,active_id text NOT NULL,frozen boolean NOT NULL,quarantined boolean NOT NULL DEFAULT false,restore_sha text,retiring_id text,retirement_proof text,retirement_state text);
INSERT INTO __SCHEMA__.key_epochs(singleton,version,active_id,frozen) VALUES(true,1,COALESCE((SELECT (encrypted::jsonb)->>'kid' FROM __SCHEMA__.objects WHERE tenant='system' AND namespace='metadata' AND id='key-check'),'legacy'),false);
CREATE FUNCTION __SCHEMA__.enforce_write_epoch() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE epoch record; kid text;
BEGIN
 SELECT * INTO epoch FROM __SCHEMA__.key_epochs WHERE singleton FOR SHARE;
 kid=COALESCE((NEW.encrypted::jsonb)->>'kid','legacy');
 IF kid<>epoch.active_id OR (epoch.frozen AND current_setting('role',true)<>'__SCHEMA___rotator') THEN RAISE EXCEPTION 'WRITE_EPOCH_REJECTED' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER objects_epoch BEFORE INSERT OR UPDATE ON __SCHEMA__.objects FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enforce_write_epoch();
CREATE TRIGGER operations_epoch BEFORE INSERT OR UPDATE ON __SCHEMA__.operations FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enforce_write_epoch();
CREATE TRIGGER audit_epoch BEFORE INSERT OR UPDATE ON __SCHEMA__.audit FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enforce_write_epoch();
CREATE FUNCTION __SCHEMA__.initialize_epoch(kid text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior_tenant text; epoch record;
BEGIN
 prior_tenant=current_setting('runtime.tenant_id',true);
 SELECT * INTO epoch FROM __SCHEMA__.key_epochs WHERE singleton FOR UPDATE;
 IF epoch.version<>1 OR epoch.frozen OR epoch.quarantined OR epoch.retiring_id IS NOT NULL OR epoch.retirement_state IS NOT NULL OR epoch.restore_sha IS NOT NULL OR EXISTS(SELECT 1 FROM __SCHEMA__.tenants WHERE tenant<>'system') THEN RETURN; END IF;
 PERFORM set_config('runtime.tenant_id','system',true);
 IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.objects WHERE tenant='system') AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.operations WHERE tenant='system') AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.audit WHERE tenant='system') THEN UPDATE __SCHEMA__.key_epochs SET active_id=kid WHERE singleton; END IF;
 PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true);
EXCEPTION WHEN OTHERS THEN PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true); RAISE;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.enforce_write_epoch() FROM PUBLIC;
REVOKE ALL ON FUNCTION __SCHEMA__.initialize_epoch(text) FROM PUBLIC;
CREATE FUNCTION __SCHEMA__.archive_prefix(t text,old_sequence bigint,old_hash text,end_sequence bigint,end_hash text,ref text,signed_manifest text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE base record; actual text; count_rows bigint;
BEGIN
 PERFORM 1 FROM __SCHEMA__.key_epochs WHERE singleton AND retiring_id IS NULL FOR SHARE; IF NOT FOUND THEN RAISE EXCEPTION 'KEY_RETIREMENT_SEALED'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('__SCHEMA__:'||t,0));
 SELECT * INTO base FROM __SCHEMA__.audit_bases WHERE tenant=t FOR UPDATE;
 IF COALESCE(base.sequence,0)<>old_sequence OR COALESCE(base.hash,repeat('0',64))<>old_hash OR end_sequence<=old_sequence THEN RAISE EXCEPTION 'ARCHIVE_PREFIX_CONFLICT'; END IF;
 SELECT hash INTO actual FROM __SCHEMA__.audit WHERE tenant=t AND sequence=end_sequence;
 SELECT count(*) INTO count_rows FROM __SCHEMA__.audit WHERE tenant=t AND sequence>old_sequence AND sequence<=end_sequence;
 IF actual IS DISTINCT FROM end_hash OR count_rows<>end_sequence-old_sequence THEN RAISE EXCEPTION 'ARCHIVE_PREFIX_INVALID'; END IF;
 INSERT INTO __SCHEMA__.audit_bases VALUES(t,end_sequence,end_hash,ref,signed_manifest) ON CONFLICT(tenant) DO UPDATE SET sequence=excluded.sequence,hash=excluded.hash,reference=excluded.reference,manifest=excluded.manifest;
 INSERT INTO __SCHEMA__.archive_segments VALUES(t,end_sequence,ref,signed_manifest);
 UPDATE __SCHEMA__.archive_intents SET record=jsonb_set(record::jsonb,'{status}','"complete"'::jsonb)::text WHERE tenant=t AND id=(signed_manifest::jsonb)->'manifest'->>'id';
 DELETE FROM __SCHEMA__.audit WHERE tenant=t AND sequence<=end_sequence;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.archive_prefix(text,bigint,text,bigint,text,text,text) FROM PUBLIC;
CREATE FUNCTION __SCHEMA__.write_backup_catalogue(t text,i text,value text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior text;
BEGIN
 PERFORM 1 FROM __SCHEMA__.key_epochs WHERE singleton AND retiring_id IS NULL FOR SHARE; IF NOT FOUND THEN RAISE EXCEPTION 'KEY_RETIREMENT_SEALED'; END IF;
 SELECT record INTO prior FROM __SCHEMA__.backup_catalogues WHERE tenant=t AND id=i FOR UPDATE;
 IF prior IS NOT NULL AND (prior::jsonb)->>'status'='complete' THEN
  IF prior<>value THEN RAISE EXCEPTION 'BACKUP_CATALOGUE_IMMUTABLE'; END IF; RETURN;
 END IF;
 IF (value::jsonb)->>'status' NOT IN ('pending','complete') THEN RAISE EXCEPTION 'BACKUP_CATALOGUE_INVALID'; END IF;
 INSERT INTO __SCHEMA__.backup_catalogues VALUES(t,i,value) ON CONFLICT(tenant,id) DO UPDATE SET record=excluded.record;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.write_backup_catalogue(text,text,text) FROM PUBLIC;

CREATE TABLE __SCHEMA__.archive_jobs(tenant text NOT NULL,id text NOT NULL,job text NOT NULL,state text NOT NULL,due bigint NOT NULL,owner text NOT NULL DEFAULT '',fence bigint NOT NULL DEFAULT 0,expires bigint NOT NULL DEFAULT 0,PRIMARY KEY(tenant,id));
CREATE INDEX archive_jobs_due ON __SCHEMA__.archive_jobs(tenant,due,id) WHERE state IN ('queued','retry','running');
CREATE TABLE __SCHEMA__.backup_jobs(LIKE __SCHEMA__.archive_jobs INCLUDING ALL);
CREATE TABLE __SCHEMA__.maintenance_heartbeats(tenant text NOT NULL,kind text NOT NULL,id text NOT NULL,record text NOT NULL,PRIMARY KEY(tenant,kind,id));
CREATE FUNCTION __SCHEMA__.retained_key_records(cursor_value text,maximum integer) RETURNS TABLE(cursor text,kind text,tenant_id text,record text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior_tenant text; tenant_value text; entry record; rank_value integer; taken integer=0; ceiling_value integer; cursor_parts jsonb; row_cursor text;
BEGIN
 prior_tenant=current_setting('runtime.tenant_id',true);ceiling_value=LEAST(GREATEST(maximum,1),101);
 cursor_parts=CASE WHEN cursor_value='' THEN '[-1,"",""]'::jsonb ELSE cursor_value::jsonb END;
 IF jsonb_typeof(cursor_parts)<>'array' OR jsonb_array_length(cursor_parts)<>3 THEN RAISE EXCEPTION 'INVALID_INVENTORY_CURSOR'; END IF;
 FOR rank_value IN 0..2 LOOP
  IF rank_value<(cursor_parts->>0)::integer THEN CONTINUE; END IF;
  FOR tenant_value IN SELECT t.tenant FROM __SCHEMA__.tenants t UNION SELECT 'system' ORDER BY 1 LOOP
   IF rank_value=(cursor_parts->>0)::integer AND tenant_value<cursor_parts->>1 THEN CONTINUE; END IF;
   PERFORM set_config('runtime.tenant_id',tenant_value,true);
   row_cursor=CASE WHEN rank_value=(cursor_parts->>0)::integer AND tenant_value=cursor_parts->>1 THEN cursor_parts->>2 ELSE '' END;
   IF rank_value=0 THEN
    FOR entry IN SELECT lpad(a.sequence::text,16,'0') AS record_id,a.manifest AS evidence FROM __SCHEMA__.archive_segments a WHERE a.tenant=tenant_value AND lpad(a.sequence::text,16,'0')>row_cursor ORDER BY a.sequence LIMIT ceiling_value-taken LOOP
     cursor=json_build_array(rank_value,tenant_value,entry.record_id)::text;kind='archive';tenant_id=tenant_value;record=entry.evidence;RETURN NEXT;taken=taken+1;
    END LOOP;
   ELSIF rank_value=1 THEN
    FOR entry IN SELECT b.id AS record_id,b.record AS evidence FROM __SCHEMA__.backup_catalogues b WHERE b.tenant=tenant_value AND b.id>row_cursor ORDER BY b.id LIMIT ceiling_value-taken LOOP
     cursor=json_build_array(rank_value,tenant_value,entry.record_id)::text;kind='backup';tenant_id=tenant_value;record=entry.evidence;RETURN NEXT;taken=taken+1;
    END LOOP;
   ELSE
    FOR entry IN SELECT i.id AS record_id,i.record AS evidence FROM __SCHEMA__.archive_intents i WHERE i.tenant=tenant_value AND i.id>row_cursor AND i.record::jsonb->>'status' IS DISTINCT FROM 'complete' ORDER BY i.id LIMIT ceiling_value-taken LOOP
     cursor=json_build_array(rank_value,tenant_value,entry.record_id)::text;kind='archive-intent';tenant_id=tenant_value;record=entry.evidence;RETURN NEXT;taken=taken+1;
    END LOOP;
   END IF;
   IF taken>=ceiling_value THEN PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true);RETURN; END IF;
  END LOOP;
 END LOOP;
 PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true);
EXCEPTION WHEN OTHERS THEN PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true);RAISE;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.retained_key_records(text,integer) FROM PUBLIC;
CREATE FUNCTION __SCHEMA__.active_lease_count() RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior_tenant text;tenant_value text;total bigint=0;current_total bigint;cutoff bigint;
BEGIN
 prior_tenant=current_setting('runtime.tenant_id',true);cutoff=(extract(epoch FROM clock_timestamp())*1000)::bigint;
 FOR tenant_value IN SELECT t.tenant FROM __SCHEMA__.tenants t UNION SELECT 'system' ORDER BY 1 LOOP
  PERFORM set_config('runtime.tenant_id',tenant_value,true);
  SELECT count(*) INTO current_total FROM (SELECT expires FROM __SCHEMA__.leases WHERE tenant=tenant_value UNION ALL SELECT expires FROM __SCHEMA__.archive_jobs WHERE tenant=tenant_value UNION ALL SELECT expires FROM __SCHEMA__.backup_jobs WHERE tenant=tenant_value) ownership WHERE expires>cutoff;
  total=total+current_total;
 END LOOP;
 PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true);RETURN total;
EXCEPTION WHEN OTHERS THEN PERFORM set_config('runtime.tenant_id',COALESCE(prior_tenant,''),true);RAISE;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.active_lease_count() FROM PUBLIC;
CREATE FUNCTION __SCHEMA__.enforce_lease_epoch() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE is_frozen boolean;
BEGIN
 IF TG_OP='INSERT' OR NEW.expires>OLD.expires THEN SELECT frozen INTO is_frozen FROM __SCHEMA__.key_epochs WHERE singleton FOR SHARE; IF is_frozen THEN RAISE EXCEPTION 'WRITE_EPOCH_REJECTED' USING ERRCODE='55000'; END IF; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.enforce_lease_epoch() FROM PUBLIC;
CREATE TRIGGER leases_epoch BEFORE INSERT OR UPDATE ON __SCHEMA__.leases FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enforce_lease_epoch();

CREATE FUNCTION __SCHEMA__.prepare_archive_intent(t text,i text,value text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior text;
BEGIN
 PERFORM 1 FROM __SCHEMA__.key_epochs WHERE singleton AND NOT frozen AND retiring_id IS NULL FOR SHARE; IF NOT FOUND THEN RAISE EXCEPTION 'MAINTENANCE_FROZEN'; END IF;
 INSERT INTO __SCHEMA__.archive_intents VALUES(t,i,value) ON CONFLICT(tenant,id) DO NOTHING;
 SELECT record INTO prior FROM __SCHEMA__.archive_intents WHERE tenant=t AND id=i; RETURN prior;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.prepare_archive_intent(text,text,text) FROM PUBLIC;

CREATE TABLE __SCHEMA__.job_tombstones(tenant text NOT NULL,id text NOT NULL,record text NOT NULL,mac text NOT NULL,PRIMARY KEY(tenant,id));
CREATE FUNCTION __SCHEMA__.remove_job_index() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN IF OLD.namespace='jobs' THEN DELETE FROM __SCHEMA__.job_index WHERE tenant=OLD.tenant AND id=OLD.id; END IF; RETURN OLD; END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.remove_job_index() FROM PUBLIC;
CREATE TRIGGER jobs_index_cleanup AFTER DELETE ON __SCHEMA__.objects FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.remove_job_index();

CREATE INDEX backup_catalogues_latest ON __SCHEMA__.backup_catalogues(tenant,((record::jsonb->>'createdAt')::bigint) DESC,((record::jsonb->>'lastVerifiedAt')::bigint) DESC,id DESC) WHERE record::jsonb->>'status'='complete';
CREATE INDEX backup_catalogues_pending ON __SCHEMA__.backup_catalogues(tenant) WHERE record::jsonb->>'status'='pending';

CREATE FUNCTION __SCHEMA__.maintenance_admission() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE blocked boolean; BEGIN SELECT frozen INTO blocked FROM __SCHEMA__.key_epochs WHERE singleton FOR SHARE; IF blocked THEN RAISE EXCEPTION 'WRITE_EPOCH_REJECTED' USING ERRCODE='55000'; END IF; END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.maintenance_admission() FROM PUBLIC;

CREATE FUNCTION __SCHEMA__.register_operational_tenant() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN INSERT INTO __SCHEMA__.tenants VALUES(NEW.tenant) ON CONFLICT DO NOTHING;RETURN NEW;END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.register_operational_tenant() FROM PUBLIC;
CREATE TRIGGER archive_job_tenant AFTER INSERT ON __SCHEMA__.archive_jobs FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.register_operational_tenant();
CREATE TRIGGER backup_job_tenant AFTER INSERT ON __SCHEMA__.backup_jobs FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.register_operational_tenant();
CREATE TRIGGER backup_catalogue_tenant AFTER INSERT ON __SCHEMA__.backup_catalogues FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.register_operational_tenant();
CREATE TRIGGER archive_intent_tenant AFTER INSERT ON __SCHEMA__.archive_intents FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.register_operational_tenant();

CREATE INDEX archive_jobs_completion ON __SCHEMA__.archive_jobs(tenant,((job::jsonb->>'payloadExpiresAt')::bigint),id) WHERE state='done' AND job::jsonb->>'compacted' IS DISTINCT FROM 'true';
CREATE INDEX backup_jobs_completion ON __SCHEMA__.backup_jobs(tenant,((job::jsonb->>'payloadExpiresAt')::bigint),id) WHERE state='done' AND job::jsonb->>'compacted' IS DISTINCT FROM 'true';
CREATE INDEX archive_jobs_state ON __SCHEMA__.archive_jobs(tenant,state);
CREATE INDEX backup_jobs_state ON __SCHEMA__.backup_jobs(tenant,state);
