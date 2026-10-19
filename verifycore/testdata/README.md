# verifycore/testdata

`jcs_vectors.json` is the RFC 8785 canonicalization contract: the same input,
the same canonical bytes, the same SHA3-256 digest, in every language that
implements it. Go is the reference; the Python SDK and the in-browser verifier
are held to these exact values.

**This is a copy.** The canonical file is `testdata/jcs_vectors.json` at the
root of the private repository, where the Python and JavaScript suites also read
it. The copy exists so that this package's tests pass when it is published on
its own: the vectors are what proves the canonicalization correct, and shipping
the code without them would leave a stranger with three failing tests and no way
to check the thing that matters most.

`scripts/published-tree-check.sh` fails if the two files differ, so the copy
cannot drift from the contract it copies.
