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
// The backends are injectable (__setRecordBackend / __setStorageBackend /
// __setSessionBackend) so the Node harness (keyring.mjs) runs the real logic
// in-memory. envelope.js is pure.
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
    summary: 'Encrypted with a key kept on this device — no passphrase to type. We cannot read your stored record. It is tied to this device: Clear this browser / app memory, and the record becomes unreadable.',
  },
  managed: {
    label: 'Managed',
    guarantee: 'soft',
    summary: 'Encrypted at rest, but we hold the key, so we can read your records if compelled — but you can never lock yourself out, since there is no passphrase or device key for you to lose. Protects against a data leak.',
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

// Session backend (the *unlocked* CEK, cached so a web refresh doesn't force the
// passphrase tier to re-unlock — and re-run Argon2 — on every load). Web:
// sessionStorage (survives refresh, cleared on tab/browser close, never on disk),
// plus an optional requestFromPeers() that fetches the CEK from another open
// same-origin tab (so a fresh tab needn't re-prompt); native/Node: in-memory
// only. Distinct from the device-key (localStorage) backend. Injectable for the
// harness (which omits requestFromPeers).
let sessionBackend = null;
export function __setSessionBackend(b) { sessionBackend = b; }
async function sessionStore() {
  if (!sessionBackend) sessionBackend = (await import('../sessionStore')).sessionStore;
  return sessionBackend;
}
const cekKey = (userId) => `crossroads_enc_cek:${userId}`;
async function cacheUnlockedCEK(userId, cek) {
  try { await (await sessionStore()).setItem(cekKey(userId), b64.encode(await exportCEKRaw(cek))); }
  catch { /* session cache is best-effort — never block an unlock on it */ }
}
async function clearUnlockedCEK(userId) {
  try { await (await sessionStore()).removeItem(cekKey(userId)); } catch { /* ignore */ }
}
async function clearAllUnlockedCEKs() {
  try { await (await sessionStore()).clear(); } catch { /* ignore */ }
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
export function lock(userId) { unlocked.delete(userId); clearUnlockedCEK(userId); }
export function lockAll() { unlocked.clear(); clearAllUnlockedCEKs(); }

// Re-hydrate the unlocked CEK so the passphrase tier doesn't re-prompt: from this
// tab's session cache (after a web refresh wiped memory), or — failing that —
// from an already-open same-origin tab over the session backend's peer channel
// (a fresh tab has its own empty sessionStorage). A peer answer is cached locally
// so later refreshes in this tab are fast. No-op if it's already in memory or
// nothing is available anywhere. Returns the CEK, or null.
export async function restoreSession(userId) {
  const live = unlocked.get(userId);
  if (live) return live;
  const store = await sessionStore();
  const key = cekKey(userId);
  let raw;
  try { raw = await store.getItem(key); } catch { return null; }
  if (!raw && store.requestFromPeers) {
    try { raw = await store.requestFromPeers(key); } catch { raw = null; }
    if (raw) { try { await store.setItem(key, raw); } catch { /* best-effort local cache */ } }
  }
  if (!raw) return null;
  const cek = await importCEKRaw(b64.decode(raw));
  unlocked.set(userId, cek);
  return cek;
}

export async function provision(userId, tier, opts = {}) {
  const cek = await generateCEK();
  await putRecord(userId, await buildRecord(userId, cek, tier, opts));
  unlocked.set(userId, cek);
  await cacheUnlockedCEK(userId, cek);
  return cek;
}

export async function unlock(userId, opts = {}) {
  const rec = await getRecord(userId);
  if (!rec) throw new Error('NOT_PROVISIONED');
  const cek = await cekFromRecord(userId, rec, opts);
  unlocked.set(userId, cek);
  await cacheUnlockedCEK(userId, cek);
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
