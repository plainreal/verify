# cmd/verify/testdata/bad

Records that must NOT verify, each derived from `../timestamped_record.json` by
one deliberate change. They are committed so the failure paths are exercised by
the golden-output tests and so anyone can reproduce a refusal without building
the bad input themselves.

| file | what is wrong | expected |
|---|---|---|
| `tampered.json` | `action_type` edited after signing | exit 1, signature mismatch |
| `missing_field.json` | one of the 33 fields removed | exit 1, not conformant |
| `unknown_version.json` | `record_version` this binary does not know | exit 1 |
| `extra_field.json` | a field outside the frozen 33 | exit 1, not conformant |
| `unsafe_integer.json` | an integer past ±(2^53−1) | exit 1, cannot be canonicalized |
| `duplicate_key.json` | a repeated top-level key | exit 1, RFC 8785 forbids it |
| `malleable_signature.json` | signature with S ≥ L | exit 1, non-canonical S |
| `not_json.txt` | not JSON at all | **exit 2**, never a record |

That last row is the one worth reading twice. A file that is not a record was
never checked, so there is nothing to accuse: it is an input problem, not a
verdict. Reporting a shopping list as FAILED would make the real tamper result
look like theatre, and this tool did exactly that until a golden test covering
the failure paths existed.
