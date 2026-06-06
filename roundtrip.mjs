// =============================================================================
// Client-side encryption — Layer 2 round-trip verification
//
//   node frontend/src/services/crypto/roundtrip.mjs
//
// Drives the REAL pure transform (envelope.js + visitEnvelope.js) through a
// simulated client<->server cycle and asserts the Layer 2 contract:
//   * content stored on the server is opaque (no plaintext leaks)
//   * the server retains no cleartext content keys
//   * partial updates merge correctly client-side (the moved field-merge)
//   * GET round-trips to the exact original content
//   * the list card decrypts for display
//
// The RN-coupled wrapper (visitCrypto.js / session.js) is exercised only when
// the app runs with ENCRYPTED_VISITS=true; here we inject the CEK + a plain Map
// cache and mirror the ~4 lines of server merge/strip so the test runs in Node.
// =============================================================================

import { generateCEK } from './envelope.js';
import { splitContent, encryptUpdate, decryptFullVisit, decryptCard, CONTENT_FIELDS } from './visitEnvelope.js';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  \x1b[32m✓\x1b[0m ' + m); } else { fail++; console.log('  \x1b[31m✗ ' + m + '\x1b[0m'); } };
const eq = (a, b, m) => ok(JSON.stringify(a) === JSON.stringify(b), m);

const cek = await generateCEK();

// --- client side: merge cache (mirrors session.mergeContent) ----------------
const cache = new Map();
function mergeContent(id, partial) {
  const merged = { ...(cache.get(id) || {}), ...partial };
  cache.set(id, merged);
  return merged;
}
async function clientEncryptUpdate(id, updates) {
  const { content, meta } = splitContent(updates);
  return encryptUpdate(cek, meta, mergeContent(id, content));
}

// --- server side: store + merge/strip (mirrors handleUpdateVisit) -----------
const disk = new Map();
function serverPut(id, wire) {
  const existing = disk.get(id) || { id, draft: true, cost: { total: { usd: 0 } } };
  const { cost, ...body } = wire; // cost is server-authoritative
  const updated = { ...existing, ...body, id };
  if (updated.encrypted) {
    for (const f of ['messages', 'name', 'icon', 'summary', 'plan']) delete updated[f];
  }
  disk.set(id, updated);
}
function serverGet(id) { return disk.get(id); }
function serverListEntry(id) {
  const v = disk.get(id);
  return v.encrypted
    ? { id: v.id, startDate: v.startDate, endDate: v.endDate, encrypted: true, enc: { card: v.enc?.card } }
    : { id: v.id, name: v.name, icon: v.icon, summary: v.summary };
}

console.log('\x1b[1m═══ Layer 2 round-trip (encrypt-before-PUT) ═══\x1b[0m');

const ID = 42;
disk.set(ID, { id: ID, startDate: 111, draft: true, cost: { total: { usd: 0 } } });

// 1. First save: just messages (the chat turn).
console.log('\n1. First save — messages only');
serverPut(ID, await clientEncryptUpdate(ID, {
  draft: false,
  messages: [
    { role: 'user', text: 'I feel my stable job is costing me my twenties.' },
    { role: 'keeper', text: 'The Steward and the Lever both want this…' },
  ],
}));
const after1 = serverGet(ID);
ok(after1.encrypted === true, 'visit marked encrypted on disk');
ok(after1.draft === false, 'cleartext meta (draft) passed through');
ok(!('messages' in after1), 'no cleartext `messages` key on disk');
ok(after1.cost.total.usd === 0, 'server-authoritative cost preserved (not clobbered)');

// 2. Second save: partial — adds end/summary/name/icon/plan (visit conclusion).
console.log('\n2. Second save — partial fields merge client-side');
serverPut(ID, await clientEncryptUpdate(ID, {
  endDate: 222,
  name: 'Whether to leave the job',
  icon: '🪧',
  summary: { headline: 'Security versus the cost of staying', keyTopics: ['career', 'risk'], outcome: 'leaning toward a deadline' },
  plan: '- Name the worst realistic outcome\n- Give it a deadline',
}));
const after2 = serverGet(ID);
ok(after2.endDate === 222, 'cleartext meta (endDate) passed through');
for (const f of CONTENT_FIELDS) ok(!(f in after2), `no cleartext \`${f}\` key on disk`);

// 3. Opaqueness: no plaintext anywhere in the stored blob.
console.log('\n3. At-rest opaqueness');
const blob = JSON.stringify(after2);
const leaked = ['twenties', 'Steward', 'Security versus', 'deadline', 'career'].filter(w => blob.includes(w));
ok(leaked.length === 0, 'stored blob contains no plaintext content' + (leaked.length ? ' (LEAKED: ' + leaked + ')' : ''));

// 4. GET round-trip: decrypt back to the exact merged content.
console.log('\n4. GET round-trip (decrypt)');
const { visit } = await decryptFullVisit(cek, serverGet(ID));
eq(visit.messages?.length, 2, 'messages restored');
eq(visit.name, 'Whether to leave the job', 'name restored');
eq(visit.summary.headline, 'Security versus the cost of staying', 'summary restored');
eq(visit.plan?.startsWith('- Name'), true, 'plan restored');
ok(visit.endDate === 222 && visit.draft === false, 'meta + content both present after decrypt');

// 5. List card decrypts for display.
console.log('\n5. List row card');
const row = await decryptCard(cek, serverListEntry(ID));
eq(row.name, 'Whether to leave the job', 'card name decrypts');
eq(row.icon, '🪧', 'card icon decrypts');
eq(row.summary.headline, 'Security versus the cost of staying', 'card headline decrypts');

// 6. Wrong key cannot read (sanity: a different CEK can't recover the content).
//    Decryption degrades gracefully (no throw) — the record is marked
//    undecryptable and the plaintext is not exposed.
console.log('\n6. Wrong key cannot read');
const otherCek = await generateCEK();
const wrong = await decryptFullVisit(otherCek, serverGet(ID));
ok(wrong.undecryptable === true, 'a different CEK is rejected (record marked undecryptable, no throw)');
ok(!wrong.visit.messages?.length && wrong.visit.name === 'Unreadable visit', 'no plaintext leaks; shows an unreadable placeholder');

// 7. Layer 3b contract: a decrypted visit, shaped as buildClientContext does,
//    exposes the fields the server's formatSummaryEntries reads for the
//    mega-batch prior-context block.
console.log('\n7. Layer 3b — client-supplied prior summary shape');
const dv = (await decryptFullVisit(cek, serverGet(ID))).visit;
const shaped = { id: dv.id, startDate: dv.startDate, endDate: dv.endDate, ...dv.summary };
ok(shaped.id === ID && typeof shaped.startDate !== 'undefined', 'shaped entry carries id + startDate (server reads these)');
ok(typeof shaped.headline === 'string', 'shaped entry carries summary.headline (the Focus line)');
ok(Array.isArray(shaped.keyTopics), 'shaped entry carries summary.keyTopics (the Topics line)');
ok(!('enc' in shaped) && !('messages' in shaped), 'shaped entry leaks no ciphertext / raw messages');

console.log(`\n\x1b[1m═══ ${fail === 0 ? '\x1b[32mall ' + pass + ' checks passed' : '\x1b[31m' + fail + ' FAILED'}\x1b[0m\x1b[1m ═══\x1b[0m`);
process.exit(fail === 0 ? 0 : 1);
