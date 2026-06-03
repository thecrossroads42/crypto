// =============================================================================
// Client-side encryption — runnable demo (PROTOTYPE)
//
//   node frontend/src/services/crypto/demo.mjs
//
// Walks the §11 envelope end to end on a real-shaped visit: encrypt content
// under a per-user CEK, wrap that CEK under each of the three tiers, show what
// the operator actually has on disk, prove who can and cannot read it, and
// demonstrate the re-wrap upgrade path. No app, no network, no dependencies.
// =============================================================================

import {
  generateCEK, encryptRecord, decryptRecord, generateRawKey,
  wrapCEK_passphrase, unwrapCEK_passphrase,
  wrapCEK_device, unwrapCEK_device,
  wrapCEK_managed, unwrapCEK_managed,
} from './envelope.js';

const line = (s = '') => console.log(s);
const h = (s) => { line(); line('\x1b[1m' + s + '\x1b[0m'); };
const ok = (s) => line('  \x1b[32m✓\x1b[0m ' + s);
const no = (s) => line('  \x1b[31m✗\x1b[0m ' + s);
const dim = (s) => '\x1b[2m' + s + '\x1b[0m';

// A visit shaped like the real ones (frontend persists this via PUT /visits/:id).
// Operational metadata (id/dates/draft/cost) stays cleartext — the §6 envelope.
// Everything under `content` is what must become opaque at rest.
const visit = {
  id: 7,
  startDate: 1733200000000,
  endDate: 1733201800000,
  draft: false,
  cost: { total: { usd: 0.04 } },
  content: {
    name: 'Whether to leave the job',
    icon: '🪧',
    messages: [
      { role: 'user', text: 'I have a stable job but I feel like it is quietly costing me my twenties.' },
      { role: 'keeper', text: 'Two voices want to take this up — the Steward and the Lever…' },
    ],
    summary: {
      headline: 'Security versus the cost of staying',
      keyTopics: ['career', 'risk', 'identity'],
      openThreads: ['What would you regret not having tried at 40?'],
    },
    plan: '- Name the worst realistic outcome of leaving\n- Give it a deadline, not an open question',
  },
};

function showServerView(stored) {
  line(dim('  what the operator has on disk:'));
  line(dim('    enc.content = ' + JSON.stringify(stored.enc.content).slice(0, 72) + '…'));
  line(dim('    wrappedCEK  = ' + JSON.stringify(stored.wrappedCEK).slice(0, 72) + '…'));
  // Prove no plaintext leaked into the at-rest blob.
  const blob = JSON.stringify(stored);
  const leaked = ['twenties', 'Steward', 'Security versus', 'regret'].filter((w) => blob.includes(w));
  if (leaked.length === 0) ok('at-rest blob contains no plaintext content');
  else no('LEAK: plaintext found in blob: ' + leaked.join(', '));
}

async function tryRead(label, openFn) {
  try {
    const cek = await openFn();
    const content = await decryptRecord(cek, atRest.enc.content);
    return { read: true, headline: content.summary.headline };
  } catch {
    return { read: false };
  }
}

let atRest; // the stored blob, reused across reader attempts

line('\x1b[1m═══ Client-side encryption — envelope demo ═══\x1b[0m');
line(dim('visit #7 plaintext headline: "' + visit.content.summary.headline + '"'));

// --- Encrypt once under a per-user CEK --------------------------------------
h('1. Encrypt the visit content under a per-user CEK (§3)');
const cek = await generateCEK();
const encContent = await encryptRecord(cek, visit.content);
ok('content encrypted (AES-GCM, unique IV) — CEK never leaves the client');

// =============================================================================
// TIER 1 — passphrase (the §1/§2 hard guarantee)
// =============================================================================
h('2. Tier: PASSPHRASE — operator must not be able to read');
const passphrase = 'correct horse battery staple';
const wrappedPass = await wrapCEK_passphrase(cek, passphrase);
atRest = { id: visit.id, startDate: visit.startDate, draft: visit.draft, cost: visit.cost,
           enc: { content: encContent }, wrappedCEK: wrappedPass };
showServerView(atRest);

const operatorNoPass = await tryRead('operator', async () => {
  // The operator has the full disk but not the passphrase. Best they can do is guess.
  return unwrapCEK_passphrase(atRest.wrappedCEK, 'password123');
});
operatorNoPass.read ? no('operator READ it (should not happen)') : ok('operator cannot read (no passphrase → unwrap fails)');

const userPass = await tryRead('user', () => unwrapCEK_passphrase(atRest.wrappedCEK, passphrase));
userPass.read ? ok('user unlocks with passphrase → "' + userPass.headline + '"') : no('user could not read (bug)');

// =============================================================================
// TIER 2 — device key (no-signing default; operator still cannot read)
// =============================================================================
h('3. Tier: DEVICE — no passphrase typed; operator still cannot read');
const deviceKey = generateRawKey(); // lives only on the device (localStorage / PRF in prod)
const wrappedDev = await wrapCEK_device(cek, deviceKey);
atRest = { ...atRest, wrappedCEK: wrappedDev };
showServerView(atRest);

const operatorNoDevice = await tryRead('operator', () => unwrapCEK_device(atRest.wrappedCEK, generateRawKey()));
operatorNoDevice.read ? no('operator READ it (should not happen)') : ok('operator cannot read (device key never sent to server)');

const userDevice = await tryRead('user', () => unwrapCEK_device(atRest.wrappedCEK, deviceKey));
userDevice.read ? ok('device unlocks silently → "' + userDevice.headline + '" (no passphrase)') : no('device could not read (bug)');

// =============================================================================
// TIER 3 — managed / KMS (zero friction; operator CAN read — §12 weaker tier)
// =============================================================================
h('4. Tier: MANAGED — operator holds the key, so operator CAN read (weaker tier)');
const kmsKey = generateRawKey(); // stands in for a server-held KMS/HSM key (§12)
const wrappedMgd = await wrapCEK_managed(cek, kmsKey);
atRest = { ...atRest, wrappedCEK: wrappedMgd };
showServerView(atRest);

const operatorManaged = await tryRead('operator', () => unwrapCEK_managed(atRest.wrappedCEK, kmsKey));
operatorManaged.read
  ? ok('operator CAN read → "' + operatorManaged.headline + '"  ' + dim('(expected: this is the recoverable tier)'))
  : no('operator could not read (bug — managed tier should be operator-readable)');
line(dim('  §12: this only resists a leak where the KMS key is NOT also taken.'));
line(dim('       Co-locating kmsKey with the disk (e.g. CREDENTIALS_KEY in env) defeats it.'));

// =============================================================================
// Re-wrap upgrade path (§11): change tier WITHOUT re-encrypting the records.
// =============================================================================
h('5. Upgrade managed → passphrase by RE-WRAPPING the CEK (no re-encryption)');
const contentBefore = JSON.stringify(atRest.enc.content);
// Operator-readable today (managed). User upgrades to the hard guarantee:
const cekRecovered = await unwrapCEK_managed(atRest.wrappedCEK, kmsKey);
const upgraded = await wrapCEK_passphrase(cekRecovered, 'a brand new passphrase only I know');
atRest = { ...atRest, wrappedCEK: upgraded };
const contentAfter = JSON.stringify(atRest.enc.content);

contentBefore === contentAfter ? ok('record ciphertext untouched (only the wrapped CEK changed)') : no('records were rewritten (should not be)');
const operatorAfter = await tryRead('operator', () => unwrapCEK_managed(atRest.wrappedCEK, kmsKey));
operatorAfter.read ? no('operator still readable after upgrade (bug)') : ok('operator can no longer read — upgraded to the hard guarantee');

line();
line('\x1b[1m═══ done ═══\x1b[0m');
