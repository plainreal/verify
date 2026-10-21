# cmd/plainreal-verify/testdata/bad

Records that must NOT verify, each derived from `../timestamped_record.json` by
one deliberate change. They are committed so the failure paths are exercised by
the golden-output tests and so anyone can reproduce a refusal without building
the bad input themselves.

The signature is checked before the fields, so HOW a defect got there decides
what is reported. A field edited after signing is reported as altered:
`tampered.json` shows that. Four files are instead **signed with the defect
already in them**, by the key in `signed_defects.pub.pem`, which is what a
producer that emitted it would hand you: their signatures are valid, and they
are refused for their content. Check them with that key, not the timestamped
record's. Regenerate the four and the key with
`PLAINREAL_WRITE_BAD_FIXTURES=1 go test ./cmd/plainreal-verify/ -run TestGenerateSignedDefectFixtures`.

| file | what is wrong | expected |
|---|---|---|
| `tampered.json` | `action_type` edited after signing | exit 1, signature mismatch |
| `missing_field.json` | signed with one of the 33 fields removed | exit 1, not conformant |
| `unknown_version.json` | signed with a `record_version` this binary does not know | **exit 2**, no verdict reached |
| `extra_field.json` | signed with a field outside the frozen 33 | exit 1, not conformant |
| `unsafe_integer.json` | an integer past ±(2^53−1) | exit 1, cannot be canonicalized |
| `duplicate_key.json` | a repeated top-level key | exit 1, RFC 8785 forbids it |
| `malleable_signature.json` | signature with S ≥ L | exit 1, non-canonical S |
| `wrong_type.json` | signed with `params.seed` a JSON number, not a string | exit 1, names the field and its index |
| `not_json.txt` | not JSON at all | **exit 2**, never a record |

The two exit-2 rows are worth reading twice, because they are exit 2 for
different reasons.

A file that is not JSON was never checked, so there is nothing to accuse: it is
an input problem, not a verdict. Reporting a shopping list as FAILED would make
the real tamper result look like theatre, and this tool did exactly that until a
golden test covering the failure paths existed.

A record declaring a schema version this binary does not know WAS read, and its
signature may well be valid. What the tool cannot do is check it against a field
list that may not describe it. So it reaches no verdict, rather than calling a
record from a newer producer a failure. Until v1.1.0 it exited 1 here, the code
for "checked and did not verify", while printing that no verdict was reached.

`wrong_type.json` is here because of what its error used to say. A JSON value
of the wrong type in any typed field was reported in Go's words, "cannot
unmarshal number into Go struct field LLMCallParams...", naming a type that
means nothing outside this repository and omitting which of several model calls
was wrong. It now reads `execution_context.llm_calls[1].params.seed must be a
string, got a number`.
