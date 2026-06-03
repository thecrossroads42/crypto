// =============================================================================
// Client-side encryption — keyring / tier manager (PROTOTYPE)
//
// The single authority over a user's CEK and which §11 tier wraps it. Holds the
// unlocked CEK in memory for the session.
//
// The wrapped-CEK *record* lives SERVER-SIDE (backend/encryption, via keyringApi)
// so clearing browser storage doesn't lose the key, the passphrase tier works
// across devices, and the managed tier is operator-recoverable. The one thing
// that must NOT go to the server is the device tier's KEK — the *device key* —
// which stays in local storage (that's what keeps the operator out for that
// tier). Managed is wrapped by a server-held key, so its record carries the raw
// CEK over the wire (the tier's intended operator-can-read property).
//
// Both backends are injectable (__setRecordBackend / __setStorageBackend) so the
// Node harness (keyring.mjs) runs the real logic in-memory. envelope.js is pure.
// =============================================================================

import {
  generateCEK, generateRawKey, exportCEKRaw, importCEKRaw, _internal,
  wrapCEK_passphrase, unwrapCEK_passphrase,
  wrapCEK_device, unwrapCEK_device,
} from './envelope.js';

const { b64 } = _internal;

// Honest, scope-bounded labeling copy (§8). `guarantee: 'hard'` = operator
// cannot read; `'soft'` = operator can read.
export const TIER_INFO = {
  passphrase: {
    label: 'Passphrase',
    guarantee: 'hard',
    summary: 'Encrypted with a key only your passphrase unlocks. We never receive the passphrase, so we cannot read your stored record, and it works on any device you sign in from. If you forget the passphrase it is permanently unrecoverable.',
  },
  device: {
    label: 'This device',
    guarantee: 'hard',
    summary: 'Encrypted with a key kept on this device — no passphrase to type. We cannot read your stored record. It is tied to this device: sign in elsewhere, or clear this browser, and the record becomes unreadable.',
  },
  managed: {
    label: 'Managed (recoverable)',
    guarantee: 'soft',
    summary: 'Encrypted at rest, but we hold the key, so we can read your records if compelled — and can restore access if you lose yours. Protects against a data leak that does not also take the key, not against us being fully compromised.',
  },
};

// --- injectable backends -----------------------------------------------------
// Record backend (server): { get(userId) -> record|null, put(userId, record) }.
let recordBackend = null;
export function __setRecordBackend(b) { recordBackend = b; }
async function records() {
  if (!recordBackend) recordBackend = await import('./keyringApi.js');
  return recordBackend;
}
const getRecord = async (userId) => (await records()).get(userId);
const putRecord = async (userId, record) => (await records()).put(userId, record);

// Local storage backend (device key only — must never reach the server).
let storageBackend = null;
export function __setStorageBackend(b) { storageBackend = b; }
async function storage() {
  if (!storageBackend) storageBackend = (await import('../storage')).storage;
  return storageBackend;
}
const deviceKeyKey = (userId) => `crossroads_enc_devicekey:${userId}`;
async function loadDeviceKey(userId) {
  const raw = await (await storage()).getItem(deviceKeyKey(userId));
  return raw ? b64.decode(raw) : null;
}
async function saveDeviceKey(userId, rawBytes) {
  await (await storage()).setItem(deviceKeyKey(userId), b64.encode(rawBytes));
}

// In-memory unlocked CEKs (cleared on lock / logout).
const unlocked = new Map();

// Build the server record for a CEK under a tier (mints + stores the device key
// locally for the device tier; emits the raw CEK for managed).
async function buildRecord(userId, cek, tier, opts = {}) {
  if (tier === 'device') {
    const dk = generateRawKey();
    await saveDeviceKey(userId, dk);
    return { tier: 'device', env: await wrapCEK_device(cek, dk) };
  }
  if (tier === 'passphrase') {
    if (!opts.passphrase) throw new Error('PASSPHRASE_REQUIRED');
    return { tier: 'passphrase', env: await wrapCEK_passphrase(cek, opts.passphrase) };
  }
  if (tier === 'managed') {
    return { tier: 'managed', cek: b64.encode(await exportCEKRaw(cek)) };
  }
  throw new Error(`UNKNOWN_TIER:${tier}`);
}

async function cekFromRecord(userId, rec, opts = {}) {
  if (rec.tier === 'device') {
    const dk = await loadDeviceKey(userId);
    if (!dk) throw new Error('NO_DEVICE_KEY'); // device-tier record, but not this device
    return unwrapCEK_device(rec.env, dk);
  }
  if (rec.tier === 'passphrase') {
    if (!opts.passphrase) throw new Error('PASSPHRASE_REQUIRED');
    return unwrapCEK_passphrase(rec.env, opts.passphrase);
  }
  if (rec.tier === 'managed') {
    return importCEKRaw(b64.decode(rec.cek)); // server already unwrapped
  }
  throw new Error(`UNKNOWN_TIER:${rec.tier}`);
}

// --- public API --------------------------------------------------------------
export async function getTier(userId) { return (await getRecord(userId))?.tier ?? null; }
export function getTierInfo(tier) { return TIER_INFO[tier] ?? null; }
export async function isProvisioned(userId) { return (await getRecord(userId)) != null; }
export function getUnlockedCEK(userId) { return unlocked.get(userId) ?? null; }
export function lock(userId) { unlocked.delete(userId); }
export function lockAll() { unlocked.clear(); }

export async function provision(userId, tier, opts = {}) {
  const cek = await generateCEK();
  await putRecord(userId, await buildRecord(userId, cek, tier, opts));
  unlocked.set(userId, cek);
  return cek;
}

export async function unlock(userId, opts = {}) {
  const rec = await getRecord(userId);
  if (!rec) throw new Error('NOT_PROVISIONED');
  const cek = await cekFromRecord(userId, rec, opts);
  unlocked.set(userId, cek);
  return cek;
}

// Default no-signing path: device tier, auto-provisioned then auto-unlocked.
export async function ensureDevice(userId) {
  if (unlocked.has(userId)) return unlocked.get(userId);
  const rec = await getRecord(userId);
  if (!rec) return provision(userId, 'device');
  return unlock(userId);
}

// Move tiers by RE-WRAPPING the in-memory CEK (no re-encryption of records).
export async function changeTier(userId, newTier, opts = {}) {
  const cek = unlocked.get(userId);
  if (!cek) throw new Error('LOCKED');
  await putRecord(userId, await buildRecord(userId, cek, newTier, opts));
  return cek;
}

// Forgotten-passphrase escape: discard the old record + device key and provision
// a fresh device-tier CEK. The old record stays unreadable (unrecoverable, by
// design — the proof the passphrase guarantee was real). Caller warns first.
export async function reset(userId) {
  lock(userId);
  await (await storage()).removeItem(deviceKeyKey(userId));
  return provision(userId, 'device'); // overwrites the server record
}
