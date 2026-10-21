# cmd/plainreal-verify/testdata

`unsealed_record.json` is a structurally valid TIER-A record with an empty
`signing_attestation`. The CLI's tests seal it with an ephemeral Ed25519 key
they generate themselves.

It is committed rather than built by calling the producer, because these tests
ship with the CLI to a repository that deliberately has no producer in it. A
test that needs a sealer to construct its input cannot travel with a verifier,
and a verifier published without its tests is not a verifier anyone can check.

Regenerate from the private repository with `core.NewTestRecord()` if the schema
changes. The cross-language contract lives in `testdata/jcs_vectors.json` at the
repository root, not here.

## Timestamp fixtures

`timestamped_record.json` with its `.tsr`, public key and `mock_tsa_root.pem`
let a stranger exercise the RFC 3161 path with no network, no TSA account and
no access to this repository's test helpers:

```
plainreal-verify \
  --record   testdata/timestamped_record.json \
  --key      testdata/timestamped_record.pub.pem \
  --tsr      testdata/timestamped_record.tsr \
  --tsa-root testdata/mock_tsa_root.pem
```

**The token is signed by a MOCK authority generated for these tests**, not by a
real TSA. It proves the verification path works; it proves nothing about time.
`mock_tsa_root.pem` is that authority's self-signed certificate, and passing it
to `--tsa-root` is what makes the issuer check pass.

Without `--tsa-root` the same command still reports a valid timestamp, and says
the issuer was not verified. That is the honest distinction: a self-signed
token passes the MessageImprint and GenTime checks, so anchoring is what makes
the time proof forgery-resistant.

These are deliberately NOT in the browser page's samples. The page states that
its sample carries no timestamp token, and shipping a mock-authority token
there would let a reader infer a time proof that does not exist.

Regenerate with:

```
PLAINREAL_WRITE_TSR_FIXTURES=1 go test ./cmd/plainreal-verify/ -run TestGenerateTSRFixtures
```
