// =============================================================================
// Client-side encryption — envelope core (PROTOTYPE)
//
// Implements §11 of todo/client-side-encryption.md: every record is encrypted
// at rest under a per-user *content key* (CEK); what differs per account is only
// how that CEK is *wrapped*. One engine, three tiers, an upgrade path between
// them by re-wrapping the CEK (no re-encryption of the records).
//
//   record plaintext  --AES-GCM(CEK)-->  { iv, ct }      (the at-rest blob)
//   CEK               --wrap(KEK)----->  wrappedCEK       (the only per-tier part)
//
// Tiers (§11):
//   - passphrase : KEK = KDF(passphrase, salt).  Operator cannot read.   (§1/§2 hard guarantee)
//   - device     : KEK = a random key held only on the device.            Operator cannot read.
//   - managed    : KEK = a key the operator/KMS holds.                    Operator CAN read.  (§12 weaker tier)
//
// Runs unchanged in the browser and in Node 20+ (both expose globalThis.crypto
// with SubtleCrypto), so the same module backs the live app and demo.mjs.
//
// KDF is Argon2id (memory-hard, @noble/hashes — pure JS, runs in browser + RN +
// Node). The wrapped record stores the exact params so a record always reproduces
// its own KEK. Legacy PBKDF2 records (early prototype) are still read, by the
// `kdf.name` branch in deriveKEKFromPassphrase, so switching the default didn't
// strand any existing passphrase account.
//
// REMAINING PROTOTYPE CAVEAT:
//   * The device tier uses a random local key as a stand-in for the production
//     WebAuthn-PRF / non-extractable platform key. Same envelope either way.
// =============================================================================

import { argon2id } from '@noble/hashes/argon2';

// Optional-chained so this module is import-safe on platforms without Web Crypto
// (e.g. RN/Hermes). `subtle` is only ever *used* inside functions, which only
// run when ENCRYPTED_VISITS is on (web). Touching it at import must not throw.
const subtle = globalThis.crypto?.subtle;
const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// --- base64 <-> bytes (browser + Node, no Buffer dependency) -----------------
const b64 = {
  encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    // btoa exists in browsers and in Node 16+ globals.
    return btoa(s);
  },
  decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

const utf8 = {
  encode: (str) => new TextEncoder().encode(str),
  decode: (bytes) => new TextDecoder().decode(bytes),
};

// Argon2id parameters (memory-hard). m is KiB → 64 MiB here; t = passes;
// p = lanes. Stored in the wrapped record so a record reproduces its own KEK;
// tune for the device class without breaking existing records. Derivation runs
// once per provision/unlock, not per turn.
const KDF = { name: 'argon2id', t: 3, m: 65536, p: 1 };

// =============================================================================
// CEK — the per-user content key (§3, §11). One per account; never changes.
// Extractable so it can be wrapped under each tier's KEK; the raw bytes only
// ever exist in memory during wrap/unwrap, never persisted unwrapped.
// =============================================================================

export async function generateCEK() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportCEKRaw(cek) {
  return new Uint8Array(await subtle.exportKey('raw', cek));
}

export async function importCEKRaw(rawBytes) {
  return subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

// =============================================================================
// Per-record content encryption (§3). Unique IV per call — never reused under a
// key. The output { iv, ct } is exactly what the server stores; it is opaque
// without the CEK.
// =============================================================================

export async function encryptRecord(cek, plainObject) {
  const iv = randomBytes(12);
  const plaintext = utf8.encode(JSON.stringify(plainObject));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, cek, plaintext));
  return { v: 1, alg: 'AES-GCM', iv: b64.encode(iv), ct: b64.encode(ct) };
}

export async function decryptRecord(cek, env) {
  const iv = b64.decode(env.iv);
  const ct = b64.decode(env.ct);
  const plaintext = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, cek, ct));
  return JSON.parse(utf8.decode(plaintext));
}

// =============================================================================
// KEK derivation / import. A KEK only ever wraps the CEK — it never touches
// record content directly.
// =============================================================================

// Passphrase tier: KEK = KDF(passphrase, salt). The passphrase and KEK never
// leave the client; the server stores only `salt` (not secret), the KDF params,
// and the wrapped CEK. `kdf` (from the stored record) selects the algorithm so a
// record reproduces its own KEK — including legacy PBKDF2 records.
async function deriveKEKFromPassphrase(passphrase, salt, kdf = KDF) {
  if (kdf.name === 'PBKDF2') {
    // Legacy early-prototype records — still readable.
    const baseKey = await subtle.importKey('raw', utf8.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: kdf.hash, salt, iterations: kdf.iterations },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }
  // Argon2id (default). @noble returns 32 raw bytes → AES-256 key. Awaited so a
  // platform may swap in an async native Argon2 (RN/libsodium — noble freezes
  // Hermes); `await` is a no-op on noble's synchronous return.
  const raw = await argon2id(utf8.encode(passphrase), salt, { t: kdf.t, m: kdf.m, p: kdf.p, dkLen: 32 });
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Device / managed tiers: KEK is a raw 256-bit key (held on the device, or by the
// operator/KMS). Imported as a non-extractable AES-GCM key used only to wrap.
async function importRawKEK(rawBytes) {
  return subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// A fresh random 256-bit key — used for the device tier (stand-in for WebAuthn-PRF)
// and to simulate the operator/KMS key in the managed tier.
export function generateRawKey() {
  return randomBytes(32);
}

// =============================================================================
// Wrap / unwrap the CEK under a KEK. wrappedCEK is AES-GCM(KEK, rawCEK).
// =============================================================================

async function wrapCEKWithKEK(cek, kek) {
  const iv = randomBytes(12);
  const rawCEK = await exportCEKRaw(cek);
  const wrapped = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, kek, rawCEK));
  return { iv: b64.encode(iv), wrapped: b64.encode(wrapped) };
}

async function unwrapCEKWithKEK(blob, kek) {
  const iv = b64.decode(blob.iv);
  const wrapped = b64.decode(blob.wrapped);
  const rawCEK = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, kek, wrapped));
  return importCEKRaw(rawCEK);
}

// --- Tier: passphrase --------------------------------------------------------
export async function wrapCEK_passphrase(cek, passphrase) {
  const salt = randomBytes(16);
  const kek = await deriveKEKFromPassphrase(passphrase, salt);
  const { iv, wrapped } = await wrapCEKWithKEK(cek, kek);
  return { tier: 'passphrase', kdf: { ...KDF }, salt: b64.encode(salt), iv, wrapped };
}

export async function unwrapCEK_passphrase(blob, passphrase) {
  const kek = await deriveKEKFromPassphrase(passphrase, b64.decode(blob.salt), blob.kdf || KDF);
  return unwrapCEKWithKEK(blob, kek);
}

// --- Tier: device (random local key; WebAuthn-PRF is the production upgrade) --
export async function wrapCEK_device(cek, deviceKeyRaw) {
  const kek = await importRawKEK(deviceKeyRaw);
  const { iv, wrapped } = await wrapCEKWithKEK(cek, kek);
  return { tier: 'device', iv, wrapped };
}

export async function unwrapCEK_device(blob, deviceKeyRaw) {
  return unwrapCEKWithKEK(blob, await importRawKEK(deviceKeyRaw));
}

// --- Tier: managed (operator/KMS-held key) -----------------------------------
export async function wrapCEK_managed(cek, managedKeyRaw) {
  const kek = await importRawKEK(managedKeyRaw);
  const { iv, wrapped } = await wrapCEKWithKEK(cek, kek);
  return { tier: 'managed', iv, wrapped };
}

export async function unwrapCEK_managed(blob, managedKeyRaw) {
  return unwrapCEKWithKEK(blob, await importRawKEK(managedKeyRaw));
}

export const _internal = { b64, utf8, KDF };
