# Security policy

## Reporting

Email **security@plainreal.com**. The same contact is published, with the
canonical URL and an expiry, at
[`/.well-known/security.txt`](https://verify.plainreal.com/.well-known/security.txt)
per RFC 9116.

Please report privately first. There is no bug bounty and no reward programme;
saying so up front is fairer than letting you find out after the work.

Say what you tried and what happened. A saved copy of the page, the record you
pasted, and the browser and version are usually enough to reproduce it.

## What this repository is

One HTML file that checks an Ed25519 signature over a canonicalized JSON record,
plus its published test suite. It has no server, no build step at run time, no
dependencies, and no network access. `connect-src 'none'` is enforced by the
browser rather than promised in the copy.

That shape rules out most of what a report would usually cover, and rules a few
things sharply in.

## In scope

- A record that verifies when it should not, or fails when it should not.
- Any way the page transmits, stores, caches or logs what a reader pastes.
- Any way to make it execute attacker-controlled script, including through a
  crafted record, or through a page saved and reopened from disk.
- A defect in the vendored cryptography: canonicalization, SHA3-256, SHA-512,
  Ed25519, or the curve arithmetic under them.
- A published `index.html` whose SHA-256 does not match the signed release tag.
- Anything in the page that overstates what a valid signature proves.

## Out of scope

- The absence of a third-party audit. This is stated in the README; it is a known
  limitation, not a finding.
- `script-src 'unsafe-inline'` in the Content-Security-Policy. It is unavoidable
  in a single self-contained file. There is no remote script source, no `eval`,
  no `new Function`, and no `innerHTML` anywhere in the page, so there is no
  injection sink for it to widen. A report needs a working injection, not the
  directive on its own.
- The demo public key embedded in the page. It signs the bundled sample only.
  The matching private key is not in this repository and is not published.
- A saved copy whose SHA-256 differs from the release. A copy produced by the
  page's own save button, or by the browser's Save Page As, is re-serialised from
  the live DOM. That is expected and is documented in the README. Fetch the file
  directly before comparing hashes.
- Missing security headers on a copy opened from `file://`. `_headers` cannot
  apply there, which is why the policy is duplicated in a `<meta>` tag.

## What you can expect

A human reply, from one person, not a queue. If the report is valid, a fix and a
new signed release; if it is not, the reasoning rather than a form letter. If
something is a real limitation rather than a defect, it gets written into the
README where readers will see it.

## Verifying a release yourself

Each release publishes `sha256(public/index.html)` in its **signed git tag**, and
repeats it in the README. Trust the tag: a hash published only in the repository
it describes is circular, because whoever can edit one can edit the other.

```bash
git tag -v v1.0.0                       # signature, and the hash in the message
shasum -a 256 public/index.html         # compare
```
