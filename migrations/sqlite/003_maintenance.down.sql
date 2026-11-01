DROP TRIGGER IF EXISTS jobs_index_cleanup;
DROP TABLE IF EXISTS job_index;
DROP TABLE IF EXISTS job_tombstones;
DROP TABLE IF EXISTS audit_bases;
DROP TABLE IF EXISTS archive_segments;
DROP TABLE IF EXISTS archive_intents;
DROP TABLE IF EXISTS backup_catalogues;
DROP TABLE IF EXISTS maintenance_heartbeats;
DROP TABLE IF EXISTS tenants;
-- Epoch enforcement is preserved on downgrade. Removing a live epoch would reopen old writers.
