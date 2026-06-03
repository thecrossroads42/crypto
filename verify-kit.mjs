// =============================================================================
// Audit-kit drift guard
//
//   node verify-kit.mjs            # check files against KIT-MANIFEST.txt (exit 1 on drift)
//   node verify-kit.mjs --write    # (re)generate KIT-MANIFEST.txt
//
// KIT-MANIFEST.txt is the SHA-256 of every file in the published audit kit. It
// is the bridge between this repo and the public mirror: CI here runs `--check`
// so the committed manifest always reflects the real files, and anyone with the
// mirror can run the same check (or a bare `sha256sum`) to confirm the mirror
// is byte-for-byte these files. See README.md for the trust model and its limit.
// =============================================================================

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { createHash } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const DIR = dirname(fileURLToPath(import.meta.url));
const MANIFEST = 'KIT-MANIFEST.txt';

// The published kit. Excludes this script and the manifest itself.
const KIT = [
  'LICENSE',
  'README.md',
  'envelope.js',
  'visitEnvelope.js',
  'longitudinalLogic.js',
  'keyring.js',
  'demo.mjs',
  'roundtrip.mjs',
  'keyring.mjs',
  'longitudinal.mjs',
].sort();

function sha256(relPath) {
  return createHash('sha256').update(readFileSync(join(DIR, relPath))).digest('hex');
}

function currentManifest() {
  return KIT.map((f) => `${sha256(f)}  ${f}`).join('\n') + '\n';
}

const write = process.argv.includes('--write');

if (write) {
  writeFileSync(join(DIR, MANIFEST), currentManifest());
  console.log(`wrote ${MANIFEST} (${KIT.length} files)`);
  process.exit(0);
}

// --check (default)
const manifestPath = join(DIR, MANIFEST);
if (!existsSync(manifestPath)) {
  console.error(`✗ ${MANIFEST} missing — run: node verify-kit.mjs --write`);
  process.exit(1);
}
const expected = readFileSync(manifestPath, 'utf-8').trim();
const actual = currentManifest().trim();

if (expected === actual) {
  console.log(`✓ audit kit matches ${MANIFEST} (${KIT.length} files)`);
  process.exit(0);
}

// Report the specific drift.
const exp = new Map(expected.split('\n').map((l) => { const [h, f] = l.split(/\s+/); return [f, h]; }));
const act = new Map(actual.split('\n').map((l) => { const [h, f] = l.split(/\s+/); return [f, h]; }));
console.error(`✗ audit kit drifted from ${MANIFEST}:`);
for (const f of KIT) {
  if (!exp.has(f)) console.error(`   + ${f} (not in manifest)`);
  else if (exp.get(f) !== act.get(f)) console.error(`   ~ ${f} (changed)`);
}
for (const f of exp.keys()) if (!act.has(f)) console.error(`   - ${f} (in manifest, file gone)`);
console.error('   run: node verify-kit.mjs --write  (after intended changes)');
process.exit(1);
