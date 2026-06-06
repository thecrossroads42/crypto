// =============================================================================
// Client-side encryption — pure visit transform (Layer 2)
//
// The content-split / encrypt / decrypt logic, with NO React-Native or session
// coupling: every function takes an explicit CEK. visitCrypto.js is the thin
// wrapper that resolves the userId + session CEK and calls these. Keeping this
// pure means it runs in Node for the round-trip test (roundtrip.mjs) and is the
// actual code under test, not a re-implementation.
// =============================================================================

import { encryptRecord, decryptRecord } from './envelope.js';

// Fields that are CONTENT (encrypted). Everything else is cleartext operational
// metadata (§6) and passes through.
export const CONTENT_FIELDS = ['messages', 'name', 'icon', 'summary', 'plan'];

export function splitContent(obj) {
  const content = {};
  const meta = {};
  for (const [k, v] of Object.entries(obj)) {
    if (CONTENT_FIELDS.includes(k)) content[k] = v;
    else meta[k] = v;
  }
  return { content, meta };
}

// The lightweight digest the History/Landing list needs (§6: minimize what the
// list reads). Decrypted per row instead of the full content.
export function cardOf(content) {
  return {
    name: content.name ?? null,
    icon: content.icon ?? null,
    headline: content.summary?.headline ?? null,
    keyTopics: content.summary?.keyTopics ?? null,
    outcome: content.summary?.outcome ?? null,
  };
}

// Build the encrypted wire body from cleartext meta + the FULL merged content.
export async function encryptUpdate(cek, meta, fullContent) {
  return {
    ...meta,
    encrypted: true,
    enc: {
      card: await encryptRecord(cek, cardOf(fullContent)),
      content: await encryptRecord(cek, fullContent),
    },
  };
}

// Decrypt a full visit back into plaintext fields. Returns { meta, content } so
// the caller can seed its cache with the content. Pass-through marker if not
// encrypted.
export async function decryptFullVisit(cek, wireVisit) {
  if (!wireVisit?.encrypted || !wireVisit.enc?.content) {
    return { passthrough: true, visit: wireVisit };
  }
  const { enc, encrypted, ...meta } = wireVisit;
  try {
    const content = await decryptRecord(cek, wireVisit.enc.content);
    return { passthrough: false, content, visit: { ...meta, ...content } };
  } catch (err) {
    // Wrong/rotated key or corrupt ciphertext — degrade instead of throwing, so
    // one undecryptable record can't break the screen (or, in a list, the
    // readable records alongside it). The cleartext metadata still renders.
    console.warn(`Visit ${meta.id}: content could not be decrypted (${err?.name || 'error'}) — key mismatch?`);
    return { passthrough: false, undecryptable: true, content: {}, visit: { ...meta, undecryptable: true, name: 'Unreadable visit', messages: [] } };
  }
}

// Decrypt a list row's card into display fields. Pass-through if not encrypted.
export async function decryptCard(cek, entry) {
  if (!entry?.encrypted || !entry.enc?.card) return entry;
  const { enc, encrypted, ...meta } = entry;
  try {
    const card = await decryptRecord(cek, entry.enc.card);
    return {
      ...meta,
      name: card.name,
      icon: card.icon,
      summary: meta.summary || (card.headline
        ? { headline: card.headline, keyTopics: card.keyTopics, outcome: card.outcome }
        : null),
    };
  } catch (err) {
    console.warn(`Visit ${meta.id}: card could not be decrypted (${err?.name || 'error'}) — key mismatch?`);
    return { ...meta, name: 'Unreadable visit', icon: '🔒', summary: null, undecryptable: true };
  }
}
