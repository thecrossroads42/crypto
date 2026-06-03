// =============================================================================
// Client-side encryption — longitudinal logic, ported pure (PROTOTYPE)
//
// When the longitudinal stores (heldForks / judgments) are client-encrypted,
// the server can't read them, so the reconcile + consent-gate logic that lives
// in backend/longitudinal/db.js must run CLIENT-SIDE. This is that logic, ported
// as pure array→array functions (no fs, no per-user paths) so it is identical in
// behavior and Node-verifiable (longitudinal.mjs).
//
// The load-bearing invariants preserved verbatim from the server:
//   * Held forks: append-only; status (resolve/retire) is user-only and never
//     touched by reconcile; dedup against OPEN forks only (a resolved fork may
//     legitimately re-open).
//   * Judgments (consent gate): dedup against ALL statuses incl. `rejected`, so
//     a declined read is never silently re-surfaced; only `accepted` judgments
//     are ever eligible to carry into a prompt.
// =============================================================================

const uuid = () => globalThis.crypto.randomUUID();
const nowMs = () => Date.now();

function normalize(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

// --- held forks --------------------------------------------------------------
export function reconcileHeldForks(store, fromVisitId, newForks) {
  if (!Array.isArray(newForks) || newForks.length === 0) return store;
  const next = [...store];
  const openKeys = new Set(
    next.filter(f => f.status === 'open').map(f => `${normalize(f.fork)}|${normalize(f.valueQuestion)}`)
  );
  const now = nowMs();
  for (const f of newForks) {
    if (!f || !f.fork) continue;
    const key = `${normalize(f.fork)}|${normalize(f.valueQuestion)}`;
    if (openKeys.has(key)) continue;
    openKeys.add(key);
    next.push({
      id: `hf_${uuid()}`,
      fork: f.fork, sideA: f.sideA || '', sideB: f.sideB || '', valueQuestion: f.valueQuestion || '',
      fromVisitId, createdAt: now, status: 'open', resolution: null, updatedAt: now,
    });
  }
  return next;
}

const HELD_FORK_STATUSES = new Set(['open', 'resolved', 'retired']);

export function updateHeldFork(store, id, updates) {
  const next = store.map(f => ({ ...f }));
  const entry = next.find(f => f.id === id);
  if (!entry) return { store, entry: null };
  if (updates.status !== undefined) {
    if (!HELD_FORK_STATUSES.has(updates.status)) throw new Error(`Invalid status: ${updates.status}`);
    entry.status = updates.status;
  }
  if (updates.resolution !== undefined) entry.resolution = updates.resolution;
  entry.updatedAt = nowMs();
  return { store: next, entry };
}

// Open forks, for the returning greeting (the only forks it should revisit).
export function openForks(store) {
  return store.filter(f => f.status === 'open');
}

// --- judgments (consent gate) ------------------------------------------------
export function reconcilePendingJudgments(store, fromVisitId, newJudgments) {
  if (!Array.isArray(newJudgments) || newJudgments.length === 0) return store;
  const next = [...store];
  const seen = new Set(next.map(j => normalize(j.text))); // ALL statuses, incl. rejected
  const now = nowMs();
  for (const j of newJudgments) {
    if (!j || !j.text) continue;
    const key = normalize(j.text);
    if (seen.has(key)) continue;
    seen.add(key);
    next.push({ id: `jd_${uuid()}`, text: j.text, basis: j.basis || '', fromVisitId, status: 'pending', createdAt: now, decidedAt: null });
  }
  return next;
}

const JUDGMENT_DECISIONS = new Set(['accepted', 'rejected']);

export function decideJudgment(store, id, status) {
  if (!JUDGMENT_DECISIONS.has(status)) throw new Error(`Invalid decision: ${status}`);
  const next = store.map(j => ({ ...j }));
  const entry = next.find(j => j.id === id);
  if (!entry) return { store, entry: null };
  entry.status = status;
  entry.decidedAt = nowMs();
  return { store: next, entry };
}

// The ONLY judgments eligible to carry into a prompt (the consent gate).
export function confirmedJudgments(store) {
  return store.filter(j => j.status === 'accepted');
}
