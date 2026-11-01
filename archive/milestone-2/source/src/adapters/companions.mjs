import { readFileSync, lstatSync, realpathSync, existsSync } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { credentialFileProvider } from './companion-common.mjs';
import { createRegisterClient } from './register.mjs';
import { createPassportClient } from './passport.mjs';
import { createVaultClient } from './vault.mjs';

const path = z.string().min(1).max(4096);
const common = { origin: z.url(), caFile: path.optional(), certificateFile: path.optional(), keyFile: path.optional(),
  allowPrivateNetworks: z.boolean().optional(), tenantId: z.uuid().optional(), required: z.boolean().default(false) };
const configuration = z.object({ agentRoot: path,
  register: z.object({ ...common, credentialFile: path.optional() }).strict().optional(),
  passport: z.object({ ...common, viewerCredentialFile: path.optional(), workloadCredentialFile: path.optional() }).strict().optional(),
  vault: z.object({ ...common, credentialFile: path.optional() }).strict().optional(),
}).strict();

/** Trusted startup-only configuration. Never expose file paths or credentials in tool arguments. */
export function createConfiguredCompanions(input) {
  const config = configuration.parse(input); const clients = {};
  const readTls = (file, sensitive = false) => {
    const full = resolve(file); const stat = lstatSync(full);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new AppError(400, 'INVALID_COMPANION_TLS_FILE');
    if (sensitive) {
      const root = resolve(config.agentRoot); const rel = relative(existsSync(root) ? realpathSync(root) : root, realpathSync(full));
      if (!rel || (!rel.startsWith('..') && !isAbsolute(rel)) || (process.platform !== 'win32' && (stat.mode & 0o077))) throw new AppError(403, 'UNSAFE_COMPANION_TLS_KEY');
    }
    return readFileSync(full);
  };
  const provider = (file) => file ? credentialFileProvider({ path: file, agentRoot: config.agentRoot }) : undefined;
  for (const service of ['register', 'passport', 'vault']) {
    const settings = config[service]; if (!settings) continue;
    if (Boolean(settings.certificateFile) !== Boolean(settings.keyFile)) throw new AppError(400, 'COMPANION_TLS_IDENTITY_INCOMPLETE');
    const options = { origin: settings.origin, tenantId: settings.tenantId, allowPrivateNetworks: settings.allowPrivateNetworks,
      tls: { ...(settings.caFile ? { ca: readTls(settings.caFile) } : {}),
        ...(settings.certificateFile ? { cert: readTls(settings.certificateFile), key: readTls(settings.keyFile, true) } : {}) } };
    clients[service] = service === 'passport'
      ? createPassportClient({ ...options, viewerCredentials: provider(settings.viewerCredentialFile), workloadCredentials: provider(settings.workloadCredentialFile) })
      : service === 'register' ? createRegisterClient({ ...options, credentials: provider(settings.credentialFile) })
        : createVaultClient({ ...options, credentials: provider(settings.credentialFile) });
  }
  return Object.freeze({ ...clients,
    status() {
      const services = Object.entries(clients).map(([service, client]) => ({ ...client.capabilities(), required: config[service].required }));
      return { ready: services.every((service) => !service.required || service.liveValidated), services };
    },
  });
}
