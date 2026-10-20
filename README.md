# PlainReal Verifier

Two independent ways to check that a signed decision record has not been altered:
a single HTML file that runs in your browser, and a standalone command-line tool.

**Live:** https://verify.plainreal.com
**CLI:** [`cmd/plainreal-verify`](cmd/plainreal-verify)

Neither needs an account, an API call, or any PlainReal service. Save the page to
your disk, disconnect from the network, and open it again; it works the same.
That is the only honest way to check the claim.

They exist as a pair on purpose. A release gate refuses to publish if they ever
disagree about whether a record is sound, so a reader holding one can cross-check
it against the other without asking us anything.

That gate reaches only as far as the overlap. The CLI checks more of a record
than the page does (the table below says exactly how much more), so agreement
covers the part they share and nothing beyond it. The part it covers best is
the cryptography: the browser's Ed25519 is gated against Go's standard library
across 76 adversarial cases, and neither of those was copied from the other.

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
- **Not that its timestamp is true.** The decision time is in the record, in
  `created_at`, and it is signed like every other field, so nobody altered it
  after sealing. That is a different thing from it being correct: the producer
  writes that value itself, and can write anything there and sign it perfectly.
  No field in a record is a clock the producer does not control.

  Seal time is not in the record at all. Nothing carries it, because a record
  cannot contain the time of its own signing. An RFC 3161 token is the only
  thing that supplies it, from an authority that is not us, and the samples
  here carry no token.
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

## The five outcomes

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
key their own deployment holds, so this one cannot check them. Paste your own
under **Use your own key** and the page checks against that instead; a record
signed by some third key then reports as a different key rather than as a
failure.

### Checking the key yourself

The fingerprint is `SHA3-256` of the raw 32-byte Ed25519 public key, with no
prefix and no encoding step, rendered as 64 lowercase hex characters. The page computes it at runtime rather than hard-coding
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

**Be clear about what that is worth.** Both channels are controlled by
PlainReal, and both live in this repository. This is publication with
third-party-observable history (git history), **not** independent key custody. A
key transparency log is the real answer to that problem and this is not one.

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
   default-src 'none'; script-src 'unsafe-inline';
   style-src 'unsafe-inline'; img-src data:; font-src data:;
   connect-src 'none'; form-action 'none'; base-uri 'none';
   frame-ancestors 'none'
   ```
   The policy allows `'unsafe-inline'` for scripts and styles, which a scanner
   will flag. It is unavoidable in a single self-contained file, and the
   mitigation is that there is nothing for it to be exploited *by*: no remote
   script source, no `eval`, no `new Function`, no `document.write`, no
   `insertAdjacentHTML`, and **nothing is ever assigned to `innerHTML`**. Every
   value the page renders is written with `textContent`.

   Grep and hold us to it, with the counts stated per file so the grep either
   agrees or catches us. `innerHTML` appears once in `index.html` and once in
   `tests.html`, each time inside a comment saying not to use it. `outerHTML`
   appears once, in `index.html`, and it is **read**, never assigned, to
   serialize the page for the download button. Reading a property is not an
   injection sink.

   This paragraph has been wrong twice. It first claimed no `innerHTML`
   anywhere in the file, which a ten-second grep falsified. It then said
   `innerHTML` "appears twice" without naming a file, and a reader grepping
   `index.html` finds one. A claim that cannot survive being checked is worse
   than a narrower one that can, and the narrow version is a count per file.

   `connect-src 'none'` means the *browser* forbids this page from opening any
   network connection. That is enforcement, not a promise in marketing copy.
   The policy is repeated in a `<meta>` tag because `_headers` cannot apply to a
   file opened from disk, and working offline is the point. The `<meta>` copy
   omits `frame-ancestors`, which the CSP specification defines as
   header-only: a browser ignores it in a `<meta>` tag, so carrying it there
   would look like protection that was never in force. Framing is blocked for
   the served page, by the header, where the directive works.

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

Both tools take your own public key, so neither is limited to the samples here.

In the browser, open **Use your own key** under the record box and paste the
public key that signed it, either as PEM or as 64 hex characters. The key stays
in the tab. It is not stored, not put in the URL, and not sent anywhere, which
you can confirm the same way as everything else here: the network panel stays
empty. A key it cannot read is refused rather than quietly ignored, because
falling back to our demo key would report a verdict about a key you never gave.

Never paste a private key, into this page or any other. Verification needs only
the public half.

## The standalone CLI

`plainreal-verify` is in this repository, under `cmd/plainreal-verify`. It needs no
PlainReal service, no account and no key of ours, and it makes no network
calls.

```bash
# one record
plainreal-verify --record decision.json --key your-key.pem

# several, each checked independently
plainreal-verify --key your-key.pem *.json

# with an RFC 3161 timestamp, anchored to a TSA you trust
plainreal-verify --record decision.json --key your-key.pem \
                 --tsr decision.tsr --tsa-root your-tsa-root.pem
```

Exit codes, which are the contract a script should read:

| code | meaning |
|---|---|
| `0` | every record given verified |
| `1` | every record was checked, and at least one did not verify |
| `2` | something could not be checked at all, or the command was refused |

`2` takes precedence over `1` deliberately. "I could not check one of these" is
what you most need to know, because nothing can be concluded about that file.

`--json` emits an object for a single record and an array for several, each
naming its file.

Flags must come before bare paths. Parsing stops at the first path, so
`--key k.pem *.json --json` would silently drop the `--json`; the tool refuses
that invocation and says so rather than running with a flag it ignored.

`--key-hex` takes the same key as 64 hex characters instead of a PEM file, for
a pipeline that already holds the raw key. `--help` lists every flag, including
`--verbose` and `--color`.

### What it looks like

Every block below is the tool's real output, injected from the same files its
tests assert against. If the tool's output changes and these are not
regenerated, the test suite fails.

They are shown without colour, because the tests capture them with
`--color never` and a Markdown block cannot carry it. In a terminal the verdict
line is coloured: green for VERIFIED, red for FAILED, cyan for DIFFERENT
SIGNING KEY, amber for COULD NOT VERIFY, and plain for NOT A CONFORMANT RECORD.
The page uses the same five, with blue where the terminal uses cyan.
`[x]` is green and `[!]` is red.

**Colour is never the only signal.** Every verdict is a word, and every check
carries an ASCII marker, so a reader piping to a file, reading through a screen
reader, or working in a terminal without colour loses nothing. Colour switches
off by itself when output is not a terminal, so redirecting to a file never
embeds escape codes in something you attach to a report. `NO_COLOR` is honoured
and `--color always|never|auto` overrides both.

A record that verifies:

```
$ plainreal-verify --record testdata/timestamped_record.json --key testdata/timestamped_record.pub.pem
PlainReal Record Verification
plainreal-verify 1.1.1  ·  record schema 1.0.0
─────────────────────────────────────────────────────

THE RECORD
Record ID:       a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
Evidence Tier:   TIER-A
Principal:       agent:credit-scoring-v2
Action Type:     credit_decision
Created:         2026-04-20T14:30:00.000000000Z
Model:           openai / gpt-4-turbo-2024-04-09
Record Hash:     28847586860d4195c0ca9e00dfcee6aa0d4ebe442a09f83e8a9b4014757026a2
Signing Key ID:  dd0148d7d15aad9de768519ff0e1abcc0abb27e905d276b934a44cb936ccb00b

WHAT WAS CHECKED
  [x] JSON Parse
  [x] Record Version
  [x] TIER-A Validation + Local Invariants
  [x] Record Hash Computed
  [x] Signature

VERIFIED

This artifact has NOT been modified since it was signed.
The signature was produced by the key you supplied on the command line.

CAVEAT: no RFC 3161 timestamp was supplied (--tsr),
so the independent time-proof pillar of TIER-A was not verified.
Supply the .tsr to confirm it.

WHAT WAS NOT CHECKED
This reads one record, on its own. Each item below needs something
this file does not contain, and none of it was fetched or consulted:
  · the agent's input was what was authorized
    the record holds only a hash of the input, not the input. Checking it
    needs the agent_input.json this record came with. [I1]
  · the parent records exist and are unaltered
    this record names its parents by hash. Confirming a parent is really
    there, and really the one named, means fetching it. [I6 chain]
  · every alternative considered was recorded
    a candidate that was never written down leaves no trace here. Confirming
    the set is complete needs the issuing service's own authorization trail.
    [I7b]
  · the parent's retention outlives this record's
    comparing the two retention horizons needs the parent record. [I8b]
  · parent and child belong to the same tenant
    the parent's tenant is in the parent, not here. [I11]
  · no attempt was left out
    an attempt the producer never recorded is invisible to any check of this
    file. Detecting omission needs a witness outside the record. This is a
    stated limit, not a gap to be closed. [I13]
  · a required human approval actually happened
    this record can declare that an approval was required. The approval
    comes AFTER the decision, and records only ever point backwards, so the
    proof is in the later record, not this one. [I14b]

  Also runs in a browser: https://verify.plainreal.com
  Source of both:         https://github.com/plainreal/verify
  A release gate requires the two to agree wherever both check.
  This tool checks more of a record than the page does.
  Nothing was contacted to produce this result.

$ echo $?
0
```

The same record with one byte changed:

```
$ plainreal-verify --record testdata/bad/tampered.json --key testdata/timestamped_record.pub.pem
PlainReal Record Verification
plainreal-verify 1.1.1  ·  record schema 1.0.0
─────────────────────────────────────────────────────

THE RECORD
Record ID:       a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
Evidence Tier:   TIER-A
Principal:       agent:credit-scoring-v2
Action Type:     wire_transfer
Created:         2026-04-20T14:30:00.000000000Z
Model:           openai / gpt-4-turbo-2024-04-09
Record Hash:     c52e6a1f3e1e197e2b155225f01fdc62da2bbbba28f04f0ae1693870a54236f7
Signing Key ID:  dd0148d7d15aad9de768519ff0e1abcc0abb27e905d276b934a44cb936ccb00b

WHAT WAS CHECKED
  [x] JSON Parse
  [x] Record Version
  [x] TIER-A Validation + Local Invariants
  [x] Record Hash Computed
  [!] Signature: signature does not match record content

FAILED
Reason: signature verification failed; record may have been tampered with

This artifact could not be verified with the key you supplied.
Any of these would produce that result:
  1. The record was modified after it was signed.
  2. The signature is not a signature over these bytes.

This tool cannot tell you which, and does not guess.

  Also runs in a browser: https://verify.plainreal.com
  Source of both:         https://github.com/plainreal/verify
  A release gate requires the two to agree wherever both check.
  This tool checks more of a record than the page does.
  Nothing was contacted to produce this result.

$ echo $?
1
```

A real record checked with the wrong key. Note that this is **not** a failure,
and the tool says so rather than implying tampering:

```
$ plainreal-verify --record testdata/timestamped_record.json --key-hex 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
PlainReal Record Verification
plainreal-verify 1.1.1  ·  record schema 1.0.0
─────────────────────────────────────────────────────

THE RECORD
Record ID:       a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
Evidence Tier:   TIER-A
Principal:       agent:credit-scoring-v2
Action Type:     credit_decision
Created:         2026-04-20T14:30:00.000000000Z
Model:           openai / gpt-4-turbo-2024-04-09
Record Hash:     28847586860d4195c0ca9e00dfcee6aa0d4ebe442a09f83e8a9b4014757026a2
Signing Key ID:  dd0148d7d15aad9de768519ff0e1abcc0abb27e905d276b934a44cb936ccb00b

WHAT WAS CHECKED
  [x] JSON Parse
  [x] Record Version
  [x] TIER-A Validation + Local Invariants
  [x] Record Hash Computed
  [!] Signature: record declares signing_key_id dd0148d7d15aad9d…, the supplied key is e8a825047e13f637…

DIFFERENT SIGNING KEY
Reason: signed by a different key: this is not the public key that signed this record, which is NOT the same as the record having been altered

This record was signed by a key other than the one you supplied.
That is NOT a failed signature and NOT evidence of tampering.
The record names the key that signed it; supply that key to check it.

  Also runs in a browser: https://verify.plainreal.com
  Source of both:         https://github.com/plainreal/verify
  A release gate requires the two to agree wherever both check.
  This tool checks more of a record than the page does.
  Nothing was contacted to produce this result.

$ echo $?
1
```

Several records at once, each judged on its own:

```
$ plainreal-verify --key testdata/timestamped_record.pub.pem testdata/timestamped_record.json testdata/bad/tampered.json
PlainReal Record Verification
plainreal-verify 1.1.1  ·  record schema 1.0.0
=====================================================

  [x] testdata/timestamped_record.json
      signature valid
  [!] testdata/bad/tampered.json
      signature verification failed; record may have been tampered with

Checked 2 records INDEPENDENTLY, one at a time: 1 verified, 1 did not.

This says nothing about how these records relate to one another. Each was
checked on its own. Verifying every record in a workflow proves every record,
not the workflow: what ties them together is the references between them, and
those were never followed.

NOT CHECKED, for every record above. Each needs something no single
record contains, and none of it was fetched:
  - the agent's input was what was authorized
    the record holds only a hash of the input, not the input. Checking it
    needs the agent_input.json this record came with. [I1]
  - the parent records exist and are unaltered
    this record names its parents by hash. Confirming a parent is really
    there, and really the one named, means fetching it. [I6 chain]
  - every alternative considered was recorded
    a candidate that was never written down leaves no trace here. Confirming
    the set is complete needs the issuing service's own authorization trail.
    [I7b]
  - the parent's retention outlives this record's
    comparing the two retention horizons needs the parent record. [I8b]
  - parent and child belong to the same tenant
    the parent's tenant is in the parent, not here. [I11]
  - no attempt was left out
    an attempt the producer never recorded is invisible to any check of this
    file. Detecting omission needs a witness outside the record. This is a
    stated limit, not a gap to be closed. [I13]
  - a required human approval actually happened
    this record can declare that an approval was required. The approval
    comes AFTER the decision, and records only ever point backwards, so the
    proof is in the later record, not this one. [I14b]

$ echo $?
1
```

### What each one checks

**Level 0** is the name for everything decidable from one record, offline:
recompute its hash from its own bytes, check the signature, check that the
document conforms, and check the invariants that need no second file. Measuring
both tools against that, rather than against each other, is the honest way to
say where they stand:

| | web | CLI |
|---|:---:|:---:|
| `record_hash` recomputed from the artifact's own bytes | yes | yes |
| Ed25519 signature against the key you supply | yes | yes |
| The 33-field set, frozen, no additions or omissions | yes | yes |
| Rejects duplicate JSON keys and unsafe integers | yes | yes |
| Field values: enums, UUIDs, hex formats, UTC-strict times | no | yes |
| Local invariants decidable from one record | **0 of 12** | **12 of 12** |
| RFC 3161 timestamp against a root you supply | no | yes |
| Several records in one run, each judged on its own | no | yes |
| Follows a reference to a parent record | no | no |
| Confirms the WORM lock | no | no |
| Proves an omitted attempt was omitted | no | no |

**The web verifier is not a Level-0 implementation.** It checks that the bytes
are what was signed and that the document has the right shape. It does not read
the contents for contradictions, so a record that is properly signed and
internally inconsistent, one that says it chose from alternatives while listing
none, gets a green result there and a refusal from the CLI. Closing that is the
v1.2.0 goal; until then this table is the honest statement of where they differ,
and the CLI is the one to reach for when the verdict has to be complete.

The last three rows are "no" in both columns, and always will be. Those are the
boundary, not a backlog.

### Building it, and checking the binary

The quickest route, if you have Go:

```bash
go install github.com/plainreal/verify/cmd/plainreal-verify@v1.1.1
```

That builds from source the Go module proxy fetched by tag, so there is no
download to trust. The binary reports its own version, taken from the module
version Go records in it.

Otherwise, six binaries are attached to the GitHub release: macOS and Linux on
both Intel and ARM, and Windows on both. **Their SHA-256 hashes are in the
signed tag message**, not only on the release page: release assets can be
replaced by anyone with write access to this repository, and a signed tag
cannot be quietly re-signed. Check the hash, do not trust the download.

`SHA256SUMS` ships beside them, so one command checks everything you
downloaded:

```bash
shasum -a 256 -c SHA256SUMS
```

`SHA256SUMS` is in the same repository as the binaries it describes, so it is
only as trustworthy as whoever can write there. The signed tag is the check
that does not have that problem:

```bash
git tag -v v1.1.1        # the signature, and the binary hashes
shasum -a 256 plainreal-verify-*         # compare against the tag message
```

The first line of that output is the one that matters. It should begin `Good`
and name the signing address:

```
Good "git" signature for swapan@plainreal.com with ED25519 key SHA256:pdoW3TQ…
```

These tags are signed with an **SSH** key, so the first run on a fresh machine
says `No principal matched` rather than verifying. That means you have not told
git which key to trust yet, not that the tag is bad. Fetch the key and say so:

```bash
curl -s https://api.github.com/users/swapanshridhar/ssh_signing_keys \
  | grep -o 'ssh-ed25519 [A-Za-z0-9+/=]*' > /tmp/plainreal.pub

printf 'swapan@plainreal.com %s\n' "$(cat /tmp/plainreal.pub)" \
  >> ~/.ssh/allowed_signers

git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
git tag -v v1.1.1
```

That key is published by GitHub, on an account separate from this repository,
which is the point: a key published only here would be no check at all.
GitHub also shows the tag as **Verified** on the releases page, and the steps
above are for anyone who would rather confirm it without taking GitHub's word.

`BAD signature`, or a `Good` line naming any other address, means stop and do
not use the download.

Better still, build it yourself. The build is **reproducible**: the same source
and the same Go toolchain produce a byte-identical binary from any directory, so
our published hash becomes something you can confirm for yourself.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-buildid= -X main.Version=1.1.1" \
  -o plainreal-verify-1.1.1-linux-amd64 ./cmd/plainreal-verify
shasum -a 256 plainreal-verify-1.1.1-linux-amd64
```

Set `GOOS` and `GOARCH` to the target you want: `darwin/arm64`,
`darwin/amd64`, `linux/amd64`, `linux/arm64`, `windows/amd64` or
`windows/arm64`. Those three flags are not decoration. `-trimpath` removes the
build directory, `-buildid=` removes the one field Go otherwise varies between
identical builds, and `CGO_ENABLED=0` removes the host toolchain. Together they
are why your bytes can equal ours.

That has a limit worth naming. The page ships as **readable** bytes, so you can
inspect the thing you are hashing. A binary cannot be read. Its guarantee is
either "this key signed that hash" or "I rebuilt it and got the same bytes", and
only the second is independent of us. The reproducible build is what makes the
second one available to anyone with Go installed.

### Running its tests

```bash
go test ./... -cover
```

Everything needed is in this repository: the RFC 8785 conformance vectors, the
SHA3-256 and Ed25519 known-answer tests, signature malleability and
non-canonical key cases, the single-artifact invariants, and a committed RFC
3161 token with its mock authority root so the timestamp path runs with no
network and no TSA account.

That command prints two figures, and those are the ones to check us on:

```
ok  github.com/plainreal/verify/cmd/plainreal-verify   coverage: 91.9% of statements
ok  github.com/plainreal/verify/verifycore   coverage: 80.4% of statements
```

Merged across both, 86.5%, which you can reproduce with
`go test ./... -coverprofile=cov.out -coverpkg=./... && go tool cover -func=cov.out`.
We print the commands so you can run them yourself, and the figure comes with
two caveats.

Coverage counts lines executed, and says nothing about whether they are
correct. A hundred percent would only mean every line ran. The assertions above
are the stronger claim: the conformance vectors and known-answer tests ship
with the code and run offline.

What is uncovered tells you more than the number does, so here it is. The remainder is
`main()`, which is an `os.Exit` wrapper, and two validators exercised in part
rather than in full. Nothing cryptographic is uncovered, and nothing exported
is untested. If you find that not to be true, that is a bug report we want.

## What neither of them checks

Both tools judge **each record on its own**. The CLI accepts many files in one
run, and that is many independent verdicts rather than one verdict about the
set. Nothing about a record's neighbours enters into its result.

Records reference the records they came from. Following one of those references
means fetching the parent and confirming it is the record that was actually
cited. That is a **different check**, and neither tool performs it.

Verifying ten records proves ten records, one at a time. It does not prove the
workflow that produced them. What ties a workflow together is the references
between its records, and nothing here follows one.

We are not planning to close that gap here; it belongs on the other side of the
boundary this repository draws. The CLI prints what it left unchecked on every
run, including a clean pass, so the limit travels with the result instead of
living only in this file.

---

## What is in this repository

```
public/index.html            the whole page: crypto, UI, sample, fonts inlined
public/_headers              CSP and cache policy (Cloudflare)
public/tests.html            the full test suite, runnable in a browser
public/og-image.png          social card; the page never loads it
public/.well-known/security.txt   RFC 9116 security contact
public/samples/              sealed sample record and the demo public key

cmd/plainreal-verify/                  the standalone CLI, and its tests and fixtures
verifycore/                  the verification package both halves of the CLI use
go.mod, go.sum               a standalone Go module: go build ./... works here
wrangler.toml                deploy config; only public/ is served
LICENSE                      Apache-2.0
NOTICE                       copyright, scope boundary, font attribution
SECURITY.md                  what is in scope to report, and what is not
README.md                    this file
OFL.txt                      SIL Open Font License 1.1, for the typefaces
```

**Only `public/` is served.** The Go source, the licences and this README are in
the repository and are deliberately not reachable at the site's URL, so nothing
under `cmd/` or `verifycore/` can be fetched from verify.plainreal.com.

`verifycore` is a verification-only package. It has no sealer and no signing
code, and that is enforced rather than intended: `Record` is defined there, Go
requires a type's methods to live in the package that defines it, so the sealing
function cannot be attached from outside. Two tests in `verifycore` fail the
build if a signing import or a producer-shaped name appears.

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
- **Ed25519 is vendored, not WebCrypto.** WebCrypto support is uneven, and
  during testing Safari 18.6's implementation was found to reject *valid*
  signatures over empty messages, where Go, Chrome and Firefox all accept them.
  A vendored implementation behaves identically in every browser. It is gated
  against Go's `crypto/ed25519` over 76 cases, including signature malleability
  (`S ≥ L`) and non-canonical key encodings.

### On vendored cryptography

The usual objection to a hand-written implementation is side channels, weak
randomness and key handling. None of those apply here, for a structural reason:
**this code verifies, so it holds no secret.** There is no private key, no
nonce, no randomness, and no secret-dependent branch or timing. An attacker who
learns everything this code does learns only what is already public. A verifier
carries a different risk profile from a signer, which is why vendoring one is a
reasonable thing to do.

It has **not** had a third-party cryptographic audit. What it has: agreement
with Go's `crypto/ed25519` across 76 adversarial cases, agreement with Chrome's
and Firefox's WebCrypto on the same cases, NIST known-answer tests for both
hashes, and algebraic checks on the curve itself (`[L]B = O`, associativity,
encode/decode round-trips). Run them yourself at
[tests.html](https://verify.plainreal.com/tests.html).

---

## Checking a copy you were given

If someone sends you this page as a file, do not take it on trust. A
verifier is exactly the thing worth tampering with.

Each release publishes the SHA-256 of `public/index.html` in its signed git tag
and here:

```
v1.1.1   sha256(public/index.html)
         f3dd80526c0c31b08b50a94b91156af1c2002f349b4270c1e727f5dc8188b690
```

Check a copy against it:

```bash
shasum -a 256 the-file-you-were-given.html
```

The output is the hash then the filename, and the hash is what you compare
against the block above:

```
f3dd80526c0c31b08b50a94b91156af1c2002f349b4270c1e727f5dc8188b690  the-file-you-were-given.html
```

If the two strings are not identical, character for character, do not trust it. Get it from
https://verify.plainreal.com or from this repository.

**Hash only a copy you downloaded directly.** This fetches the published bytes:

```bash
curl -L https://verify.plainreal.com/ -o verify.html
shasum -a 256 verify.html
```

`-L` matters. The site serves the page at `/` and redirects `/index.html` to
it, so `curl` without `-L` writes an **empty file** and you get
`e3b0c442…`, which is the SHA-256 of nothing. That looks like a failed check
and is not one. `wget` follows the redirect on its own and needs no flag.

A copy produced by this page's own save button, or by the browser's Save Page
As, is re-serialised from the live DOM and will **not** match the published
hash. That is expected and is not a sign of tampering: such a copy is
functionally identical and verifies records exactly the same way. It is simply
not the published bytes, so the published hash says nothing about it.

The release tags are signed. `git tag -v v1.1.1` verifies the signature, and
the commits are signed too.

---

## Scope: this repository verifies one artifact, held on its own

This is a deliberate boundary, not an unfinished state.

The heading used to read "one artifact's signature, and nothing else". That
stopped being true when the page began checking the frozen field set, and
stopped further when the CLI arrived checking field values, the single-artifact
invariants and RFC 3161 tokens. None of those needs a second record, which is
the line that actually matters.

This repository does not contain, and will not be extended to contain:

- a sealer, or any code that produces a signed record
- authorization-token issuance, or `input_hash` pre-commitment binding
- WORM commitment, Object Lock sequencing, or retention derivation
- RFC 3161 timestamp acquisition
- causality-chain traversal, renewal/re-anchoring checks, or divergence
  adjudication
- any private key, or any code that signs

Stated as a test rather than a principle: **if a change would make either tool
open a file it was not given, follow a reference to another record, or ask a
service anything, it does not belong here.**

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
that is a serious bug and we want to hear about it immediately.

The same goes for **any** disagreement between this page and the standalone
CLI, in either direction. A record that passes there and fails here, or passes
here and fails there. Both directions matter, and asking for only one of them
was itself the bug: v1.0.1 fixed a case where this page reported an artifact as
intact that the CLI refused, which is exactly the direction the earlier wording
here did not invite anyone to report.

Open an issue, or write to security@plainreal.com.
