CREATE SCHEMA IF NOT EXISTS __SCHEMA__;
CREATE TABLE __SCHEMA__.objects (
 tenant text NOT NULL, namespace text NOT NULL, id text NOT NULL, encrypted text NOT NULL, expires bigint,
 PRIMARY KEY(tenant,namespace,id), CHECK(expires IS NULL OR expires>0));
CREATE INDEX objects_expiry ON __SCHEMA__.objects(expires);
CREATE TABLE __SCHEMA__.operations (
 tenant text NOT NULL,id text NOT NULL,task text NOT NULL,root text NOT NULL,digest text NOT NULL,
 state text NOT NULL CHECK(state IN ('reserved','dispatched','unknown','succeeded','failed')),
 encrypted text NOT NULL,created bigint NOT NULL,updated bigint NOT NULL,PRIMARY KEY(tenant,id));
CREATE INDEX operations_state ON __SCHEMA__.operations(tenant,state,updated);
CREATE INDEX operations_retention ON __SCHEMA__.operations(tenant,updated,id) WHERE state IN ('succeeded','failed');
CREATE TABLE __SCHEMA__.usage (
 tenant text NOT NULL,root text NOT NULL,consumed integer NOT NULL CHECK(consumed>=0),mac text NOT NULL,PRIMARY KEY(tenant,root));
CREATE TABLE __SCHEMA__.audit (
 tenant text NOT NULL,sequence bigint NOT NULL,previous text NOT NULL,hash text NOT NULL,mac text NOT NULL,
 encrypted text NOT NULL,at bigint NOT NULL,PRIMARY KEY(tenant,sequence));
CREATE TABLE __SCHEMA__.leases (
 tenant text NOT NULL,resource text NOT NULL,owner text NOT NULL,fence bigint NOT NULL,expires bigint NOT NULL,mac text NOT NULL,PRIMARY KEY(tenant,resource));
CREATE TABLE __SCHEMA__.tenants (tenant text PRIMARY KEY);
CREATE TABLE __SCHEMA__.schema_version (version integer PRIMARY KEY,checksum text NOT NULL);
-- The matching migrator grants DELETE only on objects for privacy. Operation,
-- usage and lease tombstones are retained; audit history is append-only.
