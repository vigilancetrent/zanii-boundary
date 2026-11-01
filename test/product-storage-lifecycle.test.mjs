import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { openStore } from '../src/product/store.mjs';
import { migrateSqlite } from '../src/product/migrations.mjs';
import { createKeyring } from '../src/product/keyring.mjs';

test('validated keyring epochs and key bytes cannot change through the caller specification', () => {
  const active = randomBytes(32); const old = randomBytes(32);
  const spec = { activeKeyId: 'new', legacyKeyId: 'old', keys: { new: active, old } };
  const codec = createKeyring(spec);
  spec.activeKeyId = 'old'; spec.legacyKeyId = 'new'; spec.keys.new = old; active.fill(0);
  const encrypted = codec.encrypt('private', 'bound');
  assert.equal(codec.activeKeyId, 'new'); assert.equal(codec.legacyKeyId, 'old');
  assert.equal(JSON.parse(encrypted).kid, 'new'); assert.equal(codec.decrypt(encrypted, 'bound'), 'private');
  assert.throws(() => codec.assertRetirable('new', 0), { code: 'KEY_STILL_REFERENCED' });
  assert.equal(codec.assertRetirable('old', 0), true); codec.close();
});

test('key rotation reads legacy values, rekeys live payloads and preserves immutable audit ciphertext', async (t) => {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true }); const directory = mkdtempSync(join(base, 'keyring-')); const path = join(directory, 'store.db');
  const old = randomBytes(32); const current = randomBytes(32); const auditKey = randomBytes(32);
  let store = openStore({ path, encryptionKey: old, auditKey });
  t.after(() => { store.close(); assert.ok(resolve(directory).startsWith(base + sep)); rmSync(directory, { recursive: true, force: true }); });
  store.put('company', 'memory', 'note', { text: 'sensitive' }); store.appendAudit({ tenantId: 'company', actorId: 'operator', event: 'private.event', data: { text: 'historic' } });
  const original = store.exportAudit('company'); store.close();
  const keyring = { activeKeyId: 'new', legacyKeyId: 'old', keys: { old: old.toString('hex'), new: current.toString('hex') } };
  store = openStore({ path, encryptionKey: current, auditKey, keyring, role:'rotator' });let epoch=store.freezeWrites({expectedVersion:store.keyEpoch().version});epoch=store.activateKeyEpoch({expectedVersion:epoch.version,activeKeyId:'new'}); assert.equal(store.get('company', 'memory', 'note').text, 'sensitive');
  let after = ''; let rotated = 0;
  do { const page = store.rekeyRecords({ limit: 1, after }); rotated += page.rotated; after = page.next; } while (after);
  assert.equal(rotated, 2); assert.deepEqual(store.exportAudit('company'), original);
  assert.deepEqual(store.keyReferences(), { new: 2, old: 1 });
  assert.throws(() => store.assertKeyRetirable('old', { backupReferences: 0 }), { code: 'KEY_STILL_REFERENCED' });
  const codec = createKeyring(keyring); const encrypted = codec.encrypt('private', 'bound'); const tampered = JSON.parse(encrypted); tampered.kid = 'old';
  assert.throws(() => codec.decrypt(JSON.stringify(tampered), 'bound'), { code: 'STORE_INTEGRITY_ERROR' }); codec.close();
});

test('SQLite migrations up/down rehearse with checksums and actual hot query indexes', async (t) => {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true }); const directory = mkdtempSync(join(base, 'migrations-')); const path = join(directory, 'store.db'); const key = randomBytes(32);
  let store = openStore({ path, encryptionKey: key }); store.close();
  t.after(() => { store.close(); assert.ok(resolve(directory).startsWith(base + sep)); rmSync(directory, { recursive: true, force: true }); });
  const first = await migrateSqlite({ path }); assert.equal(first.version, 3); assert.equal((await migrateSqlite({ path })).checksum, first.checksum);
  assert.equal((await migrateSqlite({ path, direction: 'down', allowDestructive: true })).version, 1); await migrateSqlite({ path });
  store = openStore({ path, encryptionKey: key }); const plans = store.queryPlans('company');
  for (const plan of Object.values(plans.plans)) assert.ok(plan.some((row) => /INDEX/.test(row.detail)));
});
