// Verification tests that came across when the checking half moved out of core.
//
// They were left behind in the first pass because they still compiled there
// through core's aliases, and nothing was checking that the PUBLISHED package
// carried its own proof. verifycore alone measured 9.7 percent covered while
// reading 82.7 percent, because core's tests were doing the work. A package
// published as "check this yourself" that ships without the assertions proving
// it correct is the wrong artifact.
package verifycore

import (
	"bytes"
	"encoding/json"
	"testing"
)

var benchInput = mustJSON(map[string]any{
	"applicant_id":   "A-2847193",
	"score":          720,
	"annual_income":  145000,
	"requested_loan": 250000.50,
	"employment":     map[string]any{"status": "employed", "years": 6.5, "employer": "Acme Corp"},
	"flags":          []any{"verified_income", "clean_credit", "existing_customer"},
	"prompt":         "Evaluate this credit application against policy v2 and return APPROVE or DECLINE with rationale.",
})

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func BenchmarkCanonicalizeJSON_Realistic(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := CanonicalizeJSON(benchInput); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashJSON_Realistic(b *testing.B) {
	// JCS canonicalize + SHA3-256 — the full input_hash computation done once at
	// /authorize and again at /seal.
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := HashJSON(benchInput); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashSHA3256_1KB(b *testing.B) {
	data := benchInput
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = HashSHA3256(data)
	}
}

func BenchmarkCanonicalizeJSON_DecodeOnlyBaseline(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dec := json.NewDecoder(bytes.NewReader(benchInput))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}
