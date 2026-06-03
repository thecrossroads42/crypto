// =============================================================================
// Client-side encryption — keyring/tier verification (PROTOTYPE)
//
//   node frontend/src/services/crypto/keyring.mjs
//
// Exercises the REAL keyring against an injected in-memory store: provision /
// lock / unlock per tier, the passphrase gate, the device no-signing path, the
// managed auto-unlock, the re-wrap upgrade (same CEK, no re-encryption), and the
// honest per-tier labeling (§8).
// =============================================================================

import { encryptRecord, decryptRecord } from './envelope.js';
import * as keyring from './keyring.js';

// In-memory local storage backend (device key only).
const mem = new Map();
keyring.__setStorageBackend({
  async getItem(k) { return mem.has(k) ? mem.get(k) : null; },
  async setItem(k, v) { mem.set(k, v); },
  async removeItem(k) { mem.delete(k); },
});
// In-memory record backend (stands in for the server-side keyring store; passes
// records through verbatim, incl. managed's raw cek — the real server wraps it).
const recs = new Map();
keyring.__setRecordBackend({
  async get(uid) { return recs.has(uid) ? recs.get(uid) : null; },
  async put(uid, record) { recs.set(uid, record); },
});

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  \x1b[32m✓\x1b[0m ' + m); } else { fail++; console.log('  \x1b[31m✗ ' + m + '\x1b[0m'); } };
async function throws(fn, code, m) {
  try { await fn(); ok(false, m + ' (did not throw)'); }
  catch (e) { ok(e.message.startsWith(code) || e.name === code, m + ' → ' + (e.name === code ? e.name : e.message)); }
}
// Prove a CEK works by round-tripping a record through it.
async function cekReads(cek, env) { try { return (await decryptRecord(cek, env)).t === 'secret'; } catch { return false; } }

console.log('\x1b[1m═══ keyring / tier manager ═══\x1b[0m');

// --- device tier (no-signing default) ---------------------------------------
console.log('\n1. Device tier — auto-provision, lock, auto-unlock');
const dCek = await keyring.ensureDevice('user_dev');
const dEnv = await encryptRecord(dCek, { t: 'secret' });
ok(await keyring.getTier('user_dev') === 'device', 'provisioned as device');
keyring.lock('user_dev');
ok(keyring.getUnlockedCEK('user_dev') === null, 'lock clears in-memory CEK');
const dCek2 = await keyring.ensureDevice('user_dev'); // auto-unlock, no secret
ok(await cekReads(dCek2, dEnv), 'device auto-unlock recovers the SAME CEK (no passphrase)');

// --- passphrase tier (hard guarantee + gate) --------------------------------
console.log('\n2. Passphrase tier — gate on the passphrase');
const pCek = await keyring.provision('user_pp', 'passphrase', { passphrase: 'right pass' });
const pEnv = await encryptRecord(pCek, { t: 'secret' });
keyring.lock('user_pp');
await throws(() => keyring.unlock('user_pp'), 'PASSPHRASE_REQUIRED', 'unlock without passphrase refused');
await throws(() => keyring.unlock('user_pp', { passphrase: 'wrong' }), 'OperationError', 'unlock with wrong passphrase fails');
const pCek2 = await keyring.unlock('user_pp', { passphrase: 'right pass' });
ok(await cekReads(pCek2, pEnv), 'unlock with correct passphrase recovers the CEK');

// --- managed tier (operator-held key; auto-unlock, recoverable) -------------
console.log('\n3. Managed tier — recoverable, no user secret');
const mCek = await keyring.provision('user_mg', 'managed');
const mEnv = await encryptRecord(mCek, { t: 'secret' });
keyring.lock('user_mg');
const mCek2 = await keyring.unlock('user_mg'); // no secret needed
ok(await cekReads(mCek2, mEnv), 'managed unlock needs no user secret (recoverable tier)');

// --- re-wrap upgrade (§11): managed → passphrase, same CEK, no re-encryption -
console.log('\n4. Upgrade managed → passphrase by re-wrapping');
const upEnv = await encryptRecord(keyring.getUnlockedCEK('user_mg'), { t: 'secret' });
await keyring.changeTier('user_mg', 'passphrase', { passphrase: 'new secret' });
ok(await keyring.getTier('user_mg') === 'passphrase', 'tier is now passphrase');
ok(await cekReads(keyring.getUnlockedCEK('user_mg'), upEnv), 'pre-upgrade ciphertext still decrypts (same CEK — no re-encryption)');
keyring.lock('user_mg');
await throws(() => keyring.unlock('user_mg'), 'PASSPHRASE_REQUIRED', 'after upgrade, unlock now demands the passphrase');
ok(await cekReads(await keyring.unlock('user_mg', { passphrase: 'new secret' }), upEnv), 'unlocks with the new passphrase');

// --- honest labeling (§8) ----------------------------------------------------
console.log('\n5. Per-account labeling guarantees (§8)');
ok(keyring.getTierInfo('passphrase').guarantee === 'hard', 'passphrase = hard guarantee');
ok(keyring.getTierInfo('device').guarantee === 'hard', 'device = hard guarantee');
ok(keyring.getTierInfo('managed').guarantee === 'soft', 'managed = soft guarantee (operator can read)');
ok(/cannot read/.test(keyring.getTierInfo('passphrase').summary), 'passphrase copy states operator cannot read');
ok(/we hold the key/.test(keyring.getTierInfo('managed').summary), 'managed copy states operator holds the key');

// --- reset (forgotten passphrase) — fresh key, old data abandoned -----------
console.log('\n6. Reset (forgotten passphrase) — fresh key, old record abandoned');
const rCek = await keyring.provision('user_rs', 'passphrase', { passphrase: 'the old one' });
const rEnv = await encryptRecord(rCek, { t: 'secret' });
keyring.lock('user_rs');
const freshCek = await keyring.reset('user_rs');
ok(await keyring.getTier('user_rs') === 'device', 'reset drops to the device (no-signing) tier');
ok(!(await cekReads(freshCek, rEnv)), 'pre-reset ciphertext is unreadable under the fresh CEK (unrecoverable, by design)');

console.log(`\n\x1b[1m═══ ${fail === 0 ? '\x1b[32mall ' + pass + ' checks passed' : '\x1b[31m' + fail + ' FAILED'}\x1b[0m\x1b[1m ═══\x1b[0m`);
process.exit(fail === 0 ? 0 : 1);
