# The Crossroads — client-side encryption (audit kit)

This is the privacy-critical encryption code from
[The Crossroads](https://thecrossroads.to), published so you can **check our
claims instead of trusting them**. It is the real code that runs in the
browser — the part that decides whether your stored record is readable by
anyone but you — separated from the rest of the app (which stays closed; it
holds no secret that affects your privacy).

The security here does not depend on this code being secret (Kerckhoffs's
principle): publishing it costs us nothing and lets you verify it. Licensed
MIT (see `LICENSE`).

> **One honest limit, stated up front.** Opening this code lets you audit the
> *design*, and lets you spot-check your *own* session (below). It does **not**
> cryptographically guarantee that the JavaScript your browser ran on a given
> day is byte-for-byte this code — a web app serves its code each load, so a
> compromised or coerced server could serve different code to a targeted user,
> and this repo would not catch that. That is the standard limit of in-browser
> crypto. The path to closing it (subresource integrity, reproducible builds, a
> pinning browser extension, a native client) is on our roadmap; until then,
> treat web delivery as a *soft* boundary, the same way we label the in-visit
> moment as soft.

## Run the proofs yourself

No build step, no dependencies beyond Node 20+ and `@noble/hashes`:

```
node demo.mjs          # the §11 envelope + all three tiers + the re-wrap upgrade
node roundtrip.mjs     # encrypt-before-PUT round-trip (content opaque at rest, etc.)
node keyring.mjs       # tier manager: provision / unlock / upgrade / labeling
node longitudinal.mjs  # the consent gate (a declined read never resurfaces)
```

Each harness verifies its claims and prints a pass/fail count.

## Claims → code

| Claim | Where it lives |
|---|---|
| Stored content is opaque at rest (AES-256-GCM, unique IV per record) | `encryptRecord` / `decryptRecord` in `envelope.js` |
| A passphrase account is unreadable to the operator | `wrapCEK_passphrase` / `unwrapCEK_passphrase` + `deriveKEKFromPassphrase` (`envelope.js`); the server stores only `{ kdf, salt, iv, wrapped }` — never the passphrase or key |
| The passphrase key is Argon2id (memory-hard), not a fast hash | `deriveKEKFromPassphrase` (`envelope.js`), params recorded per record |
| A device account is unreadable to the operator | `wrapCEK_device` / `unwrapCEK_device` (`envelope.js`); the device key never leaves local storage |
| The managed tier is operator-*readable* by design (the honest soft tier) | `TIER_INFO.managed` (`keyring.js`); its key is held server-side |
| Switching tiers re-wraps the key without re-encrypting your data | `changeTier` (`keyring.js`) — see `keyring.mjs` step 4 |
| Consent gate: a rejected read never resurfaces; only accepted reads carry | `reconcilePendingJudgments` (dedup vs **all** statuses) + `confirmedJudgments` (accepted only) in `longitudinalLogic.js` |
| A forgotten passphrase is unrecoverable (the proof the guarantee is real) | `reset` (`keyring.js`) — see `keyring.mjs` step 6 |

## What the server actually sees

Every stored content object is an envelope `{ v, alg:"AES-GCM", iv, ct }` — `ct`
is ciphertext. The shapes at rest:

- **Visit:** cleartext operational metadata (`id`, dates, `draft`, `cost`) plus
  `encrypted:true` and `enc: { card, content }` — both opaque envelopes.
- **Held forks / judgments, profile, action plan, notes:** stored as
  `{ encrypted:true, enc }`.
- **Key record (server-side):** `{ tier, env }`. For **passphrase**, `env` is
  `{ kdf, salt, iv, wrapped }` — the operator cannot derive the key without your
  passphrase. For **device**, `env` is `{ iv, wrapped }` and the unwrapping key
  is only in your browser. For **managed**, the key is held server-side and the
  operator *can* unwrap (that tier's stated trade).

What the server never receives: your passphrase, the device key, or the
unwrapped content key, for the passphrase and device tiers.

## Verify your own session (no code required)

Open your browser's dev tools → Network, start and end a visit, and inspect the
`PUT /api/visits/:id` body: you should see `enc: { content: { iv, ct } }`
ciphertext and **no** plaintext of what you wrote. Then check that your
passphrase never appears in any request.

## What's here, and what isn't

**Here:** the pure, security-determining code — `envelope.js`,
`visitEnvelope.js`, `longitudinalLogic.js`, `keyring.js` — and the runnable
harnesses.

**Not here (and not where your privacy lives):** the glue that wires this core
to auth, HTTP, and local storage; the server; and the app's content (the voices
and prompts). None of that holds a secret that affects whether your stored
record is readable.

`KIT-MANIFEST.txt` lists the SHA-256 of each file in this kit; `verify-kit.mjs`
regenerates and checks it, so this published copy can be shown to match the code
that builds the app.
