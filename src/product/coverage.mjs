import { readFile } from 'node:fs/promises';
import { createPublicKey } from 'node:crypto';
import { AppError, signEnvelope } from '../protocol.mjs';
import { verifyDeploymentReceipt } from './deployment.mjs';
import { DISTRIBUTED_KIND,verifyDistributedDeploymentReceipt } from './distributed-deployment.mjs';
/** Reload on every dispatch: expired or replaced evidence cannot stay cached as authority. */
export function createCoverageService({ config, now = Date.now }) {
    return Object.freeze({
        async status() {
            if (config.profile === 'local-test')
                return { verified: false, permitted: true, status: 'local-test-unverified', expiresAt: now() + config.limits.requestTimeoutMs };
            try {
                const [raw, key] = await Promise.all([readFile(config.deployment.receiptFile, 'utf8'), readFile(config.deployment.trustKeyFile, 'utf8')]);
                const kind=config.deployment.kind??'linux-no-network-v1';const verifier=kind==='linux-no-network-v1'?verifyDeploymentReceipt:kind===DISTRIBUTED_KIND?verifyDistributedDeploymentReceipt:null;
                if(!verifier)throw new AppError(403,'INVALID_DEPLOYMENT_KIND');
                const receipt = verifier(JSON.parse(raw), createPublicKey(key), { ...config.deployment, now: now() });
                return { verified: true, permitted: true, status: 'verified', expiresAt: receipt.expiresAt, profileDigest: receipt.profileDigest, runtimeDigest: receipt.runtimeDigest, imageRef: receipt.imageRef };
            }
            catch {
                return { verified: false, permitted: false, status: 'blocked', reason: 'DEPLOYMENT_RECEIPT_REQUIRED' };
            }
        },
        async require() {
            const result = await this.status();
            if (!result.permitted)
                throw new AppError(503, 'DEPLOYMENT_RECEIPT_REQUIRED');
            return result;
        },
    });
}
export async function checkpointEvidence({ store, identity, signingKey, now = Date.now }) {
    const chain = (await store.verifyAudit(identity.tenantId));
    if (chain.ok === false)
        throw new AppError(503, 'AUDIT_CHAIN_INVALID');
    return signEnvelope({ version: 1, tenantId: identity.tenantId, issuedAt: now(), checkpoint: (await store.checkpoint(identity.tenantId)), verification: chain,
        statement: 'Historical encrypted-store checkpoint; signature does not establish OS containment or prevent rollback without an independently pinned checkpoint.' }, signingKey, 'product-audit-checkpoint');
}
