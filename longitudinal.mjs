// =============================================================================
// Client-side encryption — longitudinal consent-gate verification
//
//   node frontend/src/services/crypto/longitudinal.mjs
//
// Locks the consent gate at the client-side pure-logic level — the same claims
// backend/discussion/carry-path.test.js makes server-side: a declined read never
// resurfaces, only accepted reads carry, resolved forks leave the greeting set.
// Plus the store-encryption round-trip (the array encrypts opaque and restores).
// =============================================================================

import {
  reconcileHeldForks, updateHeldFork, openForks,
  reconcilePendingJudgments, decideJudgment, confirmedJudgments,
} from './longitudinalLogic.js';
import { generateCEK, encryptRecord, decryptRecord } from './envelope.js';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  \x1b[32m✓\x1b[0m ' + m); } else { fail++; console.log('  \x1b[31m✗ ' + m + '\x1b[0m'); } };

console.log('\x1b[1m═══ longitudinal consent gate (client-side) ═══\x1b[0m');

// --- judgments: the consent gate --------------------------------------------
console.log('\n1. Judgments — rejected never resurfaces, only accepted carries');
let J = [];
J = reconcilePendingJudgments(J, 1, [{ text: 'You avoid conflict', basis: '...' }, { text: 'You over-plan', basis: '...' }]);
ok(J.length === 2 && J.every(j => j.status === 'pending'), 'two reads land as pending');
ok(confirmedJudgments(J).length === 0, 'pending reads do NOT carry');

// User rejects the first, accepts the second.
J = decideJudgment(J, J[0].id, 'rejected').store;
J = decideJudgment(J, J[1].id, 'accepted').store;
ok(confirmedJudgments(J).length === 1 && confirmedJudgments(J)[0].text === 'You over-plan', 'only the accepted read carries');

// A later visit re-proposes BOTH (stateless summary). The gate must not resurface them.
const before = J.length;
J = reconcilePendingJudgments(J, 2, [{ text: 'You avoid conflict' }, { text: 'You over-plan' }]);
ok(J.length === before, 'a re-proposed rejected/accepted read is NOT re-added (dedup vs ALL statuses)');
ok(!confirmedJudgments(J).some(j => j.text === 'You avoid conflict'), 'the rejected read never enters the carry set');

// A genuinely new read still lands.
J = reconcilePendingJudgments(J, 2, [{ text: 'You seek others approval' }]);
ok(J.some(j => j.text === 'You seek others approval' && j.status === 'pending'), 'a new read still lands as pending');

// --- held forks: open-only carry, resolved may recur ------------------------
console.log('\n2. Held forks — greeting revisits OPEN only; resolved may recur');
let F = [];
F = reconcileHeldForks(F, 1, [{ fork: 'Stay vs leave', valueQuestion: 'security vs growth' }]);
ok(openForks(F).length === 1, 'fork lands open');
const dup = reconcileHeldForks(F, 2, [{ fork: 'Stay vs leave', valueQuestion: 'security vs growth' }]);
ok(dup.length === 1, 'duplicate of an OPEN fork is not re-added');

// User resolves it → leaves the greeting set.
F = updateHeldFork(F, F[0].id, { status: 'resolved', resolution: 'left' }).store;
ok(openForks(F).length === 0, 'resolved fork drops out of the greeting open set');
// The same tension genuinely recurs later → allowed to re-open.
F = reconcileHeldForks(F, 3, [{ fork: 'Stay vs leave', valueQuestion: 'security vs growth' }]);
ok(openForks(F).length === 1, 'a resolved fork may re-open when it recurs');
ok(F.length === 2, 'reconcile is append-only (old resolved entry retained)');

// reconcile never mutates an existing entry's user-owned status.
const resolvedStill = F.find(f => f.status === 'resolved');
ok(!!resolvedStill, 'reconcile never flipped the resolved entry back to open');

// --- store encryption round-trip --------------------------------------------
console.log('\n3. Encrypted store round-trip');
const cek = await generateCEK();
const env = await encryptRecord(cek, J);
const blob = JSON.stringify(env);
ok(!blob.includes('over-plan') && !blob.includes('approval'), 'encrypted judgments store is opaque at rest');
const restored = await decryptRecord(cek, env);
ok(JSON.stringify(restored) === JSON.stringify(J), 'store decrypts back exactly');
ok(confirmedJudgments(restored).length === confirmedJudgments(J).length, 'consent gate intact after round-trip');

console.log(`\n\x1b[1m═══ ${fail === 0 ? '\x1b[32mall ' + pass + ' checks passed' : '\x1b[31m' + fail + ' FAILED'}\x1b[0m\x1b[1m ═══\x1b[0m`);
process.exit(fail === 0 ? 0 : 1);
