# PlainReal Verifier

A single HTML file that checks the cryptographic signature on a signed decision record, entirely in your browser.

**Live:** https://verify.plainreal.com

No account. No API call. No PlainReal service is contacted at any point. Save the
page to your disk, disconnect from the network, and open it again. It works the
same. That is the only honest way to check the claim.

---

## What a green result proves

The signature matches the record's contents exactly. Every byte is what was
signed. **The record has not changed since it was sealed.**

## What a green result does not prove

- **Not that the decision was correct.** A verified record of a bad decision is
  a verified record of a bad decision. Integrity is not merit.
- **Not that the record is complete.** A signature covers what is present. It
  cannot show you what a producer chose never to record.
- **Not WORM custody.** The S3 bucket, object version and retention date are
  not fields of a record. Only the *declared* `retention_class` is
  signed. Confirming that an object is genuinely under an Object Lock requires
  the storage account, not this page.
- **Not the time it was made.** A signature covers content, not time. That is
  the RFC 3161 timestamp's job, and the samples here carry no timestamp token.
- **Not who changed it**, when it fails. A broken signature proves the bytes
  are not what was sealed. It says nothing about who broke them.

Records are **tamper-evident**, not tamper-proof. Nothing stops
anyone editing a record; what they cannot do is edit it and still produce a
signature that verifies.

**If PlainReal ceases to exist, your records remain verifiable.** The method is
published, the format is documented, and checking a signature needs nothing
from us: a public key, a canonicalization rule and a hash function, all of them
public standards. Evidence that only its producer can check is not evidence.

---

## The four outcomes

The page keeps these strictly separate, because collapsing them is how a
verification tool starts lying:

| Outcome | Meaning |
|---|---|
| **Signature valid** | Everything was computed and it checks out. |
| **Does not verify** | Parsed fine; the signature does not match the contents. This is the tampering result. |
| **Not a record** | Unreadable, or not record-shaped. **This is not an accusation.** Dropping a random JSON file in must not read as "tampered". |
| **Could not verify** | Something failed inside the page. No verdict was reached. "We could not check" is not "it is bad". |
| **Different signing key** | Signed by a key this page does not hold. **Not a failed signature**; see below. |

---

## The key

This page carries **one** public key: the demo key that signed the samples in
this repository.

```
SHA3-256 fingerprint (this is the value in each sample's signing_key_id):

  69a0bbac56da5fae1b82f570328dc9c71437c9d685f0280d1d31b65c1ae3d5b1
```

It is **not** a universal PlainReal key. A customer's records are signed by the
key their own deployment holds, so this page cannot check them, and says so
plainly rather than showing a failure.

### Checking the key yourself

The fingerprint is `SHA3-256` of the raw 32-byte Ed25519 public key
(specification §4.5). The page computes it at runtime rather than hard-coding
it, so it cannot drift from the key it actually carries. Recompute it:

```bash
openssl pkey -pubin -in public/samples/demo_pubkey.pem -outform DER \
  | tail -c 32 | openssl dgst -sha3-256
```

Expected output:

```
SHA3-256(stdin)= 69a0bbac56da5fae1b82f570328dc9c71437c9d685f0280d1d31b65c1ae3d5b1
```

If you get `a7ffc6f8bf1ed766…` instead, that is the SHA3-256 of an *empty*
input: `openssl` could not find the key file and the pipeline hashed nothing.
Check the path rather than concluding the key is wrong.

The same fingerprint is published in more than one place, and they should all
agree:

1. this README
2. the `signing_key_id` field inside every sample
3. `_plainreal-key.plainreal.com` (DNS TXT record)

**Be clear about what that is worth.** All three channels are controlled by
PlainReal. This is multi-channel publication with third-party-observable history
(git history, DNS history services), **not** independent key custody. A key
transparency log is the real answer to that problem and this is not one.

---

## Evidence tier: declared, not confirmed

Every record carries an `evidence_tier` field. TIER-A means signed
**and** WORM-committed **and** RFC 3161 timestamped.

`evidence_tier` is a **declared** field. The signature covers it, so it cannot
have been altered after sealing. But a declaration is not a confirmation, and
only one of those three pillars is checkable from an artifact on its own.

The page therefore shows the declared tier, and separately shows which pillars
it actually verified. For the samples here that is one of three: the signature.
WORM custody needs the storage account. The RFC 3161 pillar needs a `.tsr`
token, which these samples do not have.

A page that printed a green "TIER-A" badge would be claiming two things it
never checked.

---

## Verify the independence claim yourself

Do not take "nothing leaves this page" on trust. Three ways to check, in
increasing order of paranoia:

1. **Open devtools → Network, then use the page.** It makes no requests.
2. **Save the page (Cmd/Ctrl-S), turn off your wifi, open the saved file.**
   Identical behaviour, including the fonts.
3. **Read the Content-Security-Policy** in the `<head>` and in `_headers`:
   ```
   default-src 'none'; connect-src 'none'; form-action 'none'; ...
   ```
   The policy allows `'unsafe-inline'` for scripts and styles, which a scanner
   will flag. It is unavoidable in a single self-contained file, and the
   mitigation is that there is nothing for it to be exploited *by*: no remote
   script source, no `eval`, no `innerHTML` anywhere in the file, and every
   value the page renders is written with `textContent`.

   `connect-src 'none'` means the *browser* forbids this page from opening any
   network connection. That is enforcement, not a promise in marketing copy.
   The policy is duplicated in a `<meta>` tag because `_headers` does not apply
   to a file opened from disk, and working offline is the point.

**4. Run the test suite.** Every assertion behind this page is published at
   [tests.html](https://verify.plainreal.com/tests.html) and runs in your own
   browser: RFC 8785 canonicalization vectors, SHA3-256 and SHA-512
   known-answer tests, 76 Ed25519 cases including signature malleability and
   non-canonical key encodings, the curve algebra (`[L]B = O`, associativity,
   encode/decode round-trips), and a cross-check against your own platform's
   WebCrypto where it supports Ed25519.

There is no analytics and no logging. One consequence worth stating: **we do
not know how many people use this page.**

---

## For your own records

This page carries only the demo key, so it cannot check records signed by your
own deployment.

A standalone CLI, `plainreal-verify`, exists and does more than this page: it
also validates TIER-A field requirements and local invariants, and verifies an
RFC 3161 timestamp token against a trusted TSA root. It takes any public key,
has no PlainReal runtime dependencies, and makes no network calls.

**It is not published yet.** When it is, it will be linked here. Until then,
this page is a demonstration of the verification method, not a production
audit tool.

---

## What is in this repository

```
public/index.html            the whole page: crypto, UI, sample, fonts inlined
public/_headers              CSP and cache policy (Cloudflare)
public/tests.html            the full test suite, runnable in a browser
public/.well-known/security.txt   RFC 9116 security contact
public/samples/              sealed sample record and the demo public key
wrangler.toml                deploy config; only public/ is served
LICENSE                      Apache-2.0
NOTICE                       copyright, scope boundary, font attribution
OFL.txt                      SIL Open Font License 1.1, for the typefaces
```

Only `public/` is served. `README.md`, `LICENSE`, `NOTICE` and `OFL.txt` are
in the repository but are deliberately not reachable at the site's URL.

`public/index.html` is generated from sources in the private repository and committed
here in full. It is **not minified**, because the page's argument is "read the
source that is running" and minified source is not readable source.

### The cryptography

All implemented in this file, all running in your browser:

| | |
|---|---|
| Canonicalization | RFC 8785 (JCS) |
| Hash | SHA3-256, NIST FIPS 202, *not* legacy Keccak-256 |
| Signature | Ed25519, RFC 8032 |
| `record_hash` | `SHA3-256(JCS(record with signing_attestation removed))` |

Two implementation notes a reviewer may care about:

- **The record is never parsed with `JSON.parse`.** It fails open on duplicate
  keys (silently keeping the last) and on integers beyond ±(2^53−1) (silently
  rounding). Both are rejected here, in lock-step with the Go producer.
**On vendored cryptography.** The usual objection to a hand-written
implementation is side channels, weak randomness and key handling. None of
those apply here, and the reason is structural: **this code verifies, so it
holds no secret.** There is no private key, no nonce, no randomness, and no
secret-dependent branch or timing. An attacker who learns everything this code
does learns only what is already public. That is a different risk profile from
a signer, and it is why a verifier is a reasonable thing to vendor.

It has **not** had a third-party cryptographic audit. What it has: agreement
with Go's `crypto/ed25519` across 76 adversarial cases, agreement with Chrome's
and Firefox's WebCrypto on the same cases, NIST known-answer tests for both
hashes, and algebraic checks on the curve itself (`[L]B = O`, associativity,
encode/decode round-trips). Run them yourself at
[tests.html](https://verify.plainreal.com/tests.html).

- **Ed25519 is vendored, not WebCrypto.** WebCrypto support is uneven, and
  during testing Safari 18.6's implementation was found to reject *valid*
  signatures over empty messages, where Go, Chrome and Firefox all accept them.
  A vendored implementation behaves identically in every browser. It is gated
  against Go's `crypto/ed25519` over 76 cases, including signature malleability
  (`S ≥ L`) and non-canonical key encodings.

---

## Checking a copy you were given

If someone sends you this page as a file, you should not simply trust it. A
verifier is exactly the thing worth tampering with.

Each release publishes the SHA-256 of `public/index.html` in its signed git tag
and here:

```
v1.0.0   sha256(public/index.html)
         d65481f49926b268c533a19923f44319a455df477616077ab2b8d9bad9dd8662
```

Check a copy against it:

```bash
shasum -a 256 the-file-you-were-given.html
```

If it does not match a published release, do not trust it. Get it from
https://verify.plainreal.com or from this repository.

**Hash only a copy you downloaded directly.** Use `curl`, `wget`, or right-click →
Save Link As on `public/index.html`. A copy produced by this page's own save
button, or by the browser's Save Page As, is re-serialised from the live DOM and
will **not** match the published hash. That is expected and is not a sign of
tampering: such a copy is functionally identical and verifies records exactly the
same way. It simply is not the published bytes, so the published hash says
nothing about it. If you need to check a hash, get the file directly.

The release tags are signed. `git tag -v v1.0.0` verifies the signature, and
the commits are signed too.

---

## Scope: this repository verifies one artifact's signature, and nothing else

This is a deliberate boundary, not an unfinished state. This repository does
not contain, and will not be extended to contain:

- a sealer, or any code that produces a signed record
- authorization-token issuance, or `input_hash` pre-commitment binding
- WORM commitment, Object Lock sequencing, or retention derivation
- RFC 3161 timestamp acquisition
- causality-chain traversal, renewal/re-anchoring checks, or divergence
  adjudication
- any private key, or any code that signs

The last two lines matter as much as the first. **Contributors: please do not
add capability here without asking first**, even verification capability, and
even if it looks like an obvious improvement. Open an issue instead.

See `NOTICE` for the reasoning.

---

## Licence

Apache License 2.0. See `LICENSE`.

Apache-2.0 was chosen over MIT for its explicit, **bounded** patent grant.
Section 3 grants a patent licence limited to claims necessarily infringed by a
contributor's contribution, alone or in combination with this Work. And this
Work verifies a signature: it does not seal, bind, commit, or issue.

It also carries defensive termination: a party who initiates patent litigation
alleging this Work infringes loses the **patent** licence granted here. The
copyright licence is unaffected.

### Embedded typefaces

`index.html` embeds the Latin subsets of Fraunces, DM Sans and JetBrains Mono
as `data:` URIs, verbatim and unmodified, so the page renders identically with
no network access. All three are SIL Open Font License 1.1. See `OFL.txt`.

---

## Reporting a problem

If this page reports a **valid** signature on a record that should not verify,
that is a serious bug and we want to hear about it immediately. The same goes
for a record that verifies with the standalone CLI but fails here.

Open an issue, or write to security@plainreal.com.
