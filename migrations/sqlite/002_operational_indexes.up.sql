CREATE INDEX IF NOT EXISTS operations_retention ON operations(tenant,updated,id) WHERE state IN ('succeeded','failed');
CREATE INDEX IF NOT EXISTS objects_tenant_expiry ON objects(tenant,expires,id);
