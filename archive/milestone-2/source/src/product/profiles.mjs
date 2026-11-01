import { AppError } from '../protocol.mjs';

export const LABELS = Object.freeze(['public', 'internal', 'confidential', 'restricted']);

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

/** Reviewed starting policies, not regulatory certification or physical safety envelopes. */
export const PROFILES = freeze({
  general: { version: 1, purposes: ['support', 'research', 'operations'], actions: ['read', 'share'],
    maxSensitivity: 'confidential', maxActions: 1_000, taskLifetimeMs: 3_600_000,
    approvalFor: ['share'], approvalLifetimeMs: 120_000, externalShareLabels: ['public'], physicalCommands: false },
  finance: { version: 1, purposes: ['finance-review'], actions: ['read', 'share'],
    maxSensitivity: 'restricted', maxActions: 100, taskLifetimeMs: 900_000,
    approvalFor: ['share'], approvalLifetimeMs: 120_000, externalShareLabels: [], physicalCommands: false },
  healthcare: { version: 1, purposes: ['health-admin'], actions: ['read', 'share'],
    maxSensitivity: 'restricted', maxActions: 100, taskLifetimeMs: 900_000,
    approvalFor: ['share'], approvalLifetimeMs: 60_000, externalShareLabels: [], physicalCommands: false },
  industrial: { version: 1, purposes: ['maintenance-advice'], actions: ['read', 'share'],
    maxSensitivity: 'confidential', maxActions: 100, taskLifetimeMs: 600_000,
    approvalFor: ['share'], approvalLifetimeMs: 60_000, externalShareLabels: [], physicalCommands: false },
});

export function getProfile(name) {
  if (!Object.hasOwn(PROFILES, name)) throw new AppError(400, 'UNKNOWN_PROFILE');
  return PROFILES[name];
}

export function sensitivity(value) {
  if (!LABELS.includes(value)) throw new AppError(400, 'INVALID_SENSITIVITY');
  return value;
}

export function highestSensitivity(...values) {
  return LABELS[Math.max(...values.map((value) => LABELS.indexOf(sensitivity(value))))];
}
