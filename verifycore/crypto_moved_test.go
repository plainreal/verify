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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

func TestHashSHA3256_NISTVectors(t *testing.T) {
	// Official NIST FIPS 202 test vectors.
	cases := []struct {
		input, want string
	}{
		{"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
		{"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
	}
	for _, c := range cases {
		got := HashSHA3256([]byte(c.input))
		if got != c.want {
			t.Errorf("SHA3-256(%q) = %s, want %s", c.input, got, c.want)
		}
	}
}

func TestHashSHA3256_OutputFormat(t *testing.T) {
	hexRE := regexp.MustCompile(`^[0-9a-f]{64}$`)
	inputs := [][]byte{
		[]byte(""),
		[]byte("a"),
		bytes.Repeat([]byte("x"), 10*1024),
	}
	for _, in := range inputs {
		got := HashSHA3256(in)
		if len(got) != 64 {
			t.Errorf("hash length = %d, want 64 (input len %d)", len(got), len(in))
		}
		if strings.HasPrefix(got, "0x") {
			t.Errorf("hash has 0x prefix: %s", got)
		}
		if !hexRE.MatchString(got) {
			t.Errorf("hash not lowercase hex: %s", got)
		}
	}
}

func TestSHA3256IsNotKeccak256(t *testing.T) {
	// Guard: SHA3-256 and Keccak-256 differ by padding byte (0x06 vs 0x01).
	// If someone accidentally swaps to LegacyKeccak256, this test catches it.
	sha3Hash := HashSHA3256([]byte("abc"))

	k := sha3.NewLegacyKeccak256()
	k.Write([]byte("abc"))
	keccak := hex.EncodeToString(k.Sum(nil))

	if sha3Hash == keccak {
		t.Fatalf("SHA3-256 and Keccak-256 produced identical output; one of them is wrong")
	}
	// Known Keccak-256("abc").
	const expectedKeccak = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
	if keccak != expectedKeccak {
		t.Fatalf("Keccak baseline mismatch: got %s want %s", keccak, expectedKeccak)
	}
	const expectedSHA3 = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
	if sha3Hash != expectedSHA3 {
		t.Fatalf("SHA3-256 baseline mismatch: got %s want %s", sha3Hash, expectedSHA3)
	}
}

// === JCS Vectors ===

type jcsVector struct {
	ID                 string          `json:"id"`
	Description        string          `json:"description"`
	Input              json.RawMessage `json:"input"`
	ExpectedJCS        string          `json:"expected_jcs"`
	ExpectedSHA3256Hex string          `json:"expected_sha3_256_hex"`
}

type jcsVectorFile struct {
	Version string      `json:"version"`
	Note    string      `json:"note"`
	Vectors []jcsVector `json:"vectors"`
}

func loadVectors(t *testing.T) []jcsVector {
	t.Helper()
	path := filepath.Join("testdata", "jcs_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file jcsVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return file.Vectors
}

func TestCanonicalizeJSON_AllVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			got, err := CanonicalizeJSON(v.Input)
			if err != nil {
				t.Fatalf("CanonicalizeJSON error: %v", err)
			}
			want := []byte(v.ExpectedJCS)
			if !bytes.Equal(got, want) {
				t.Errorf("%s: canonical mismatch\n  input:    %s\n  got:      %s\n  expected: %s",
					v.ID, string(v.Input), string(got), string(want))
			}
		})
	}
}

func TestHashJSON_AllVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			if strings.HasPrefix(v.ExpectedSHA3256Hex, "COMPUTE") || strings.HasPrefix(v.ExpectedSHA3256Hex, "PENDING") {
				t.Skipf("%s: expected hash not yet computed", v.ID)
			}
			got, err := HashJSON(v.Input)
			if err != nil {
				t.Fatalf("HashJSON error: %v", err)
			}
			if got != v.ExpectedSHA3256Hex {
				t.Errorf("%s: hash mismatch\n  got:      %s\n  expected: %s", v.ID, got, v.ExpectedSHA3256Hex)
			}
		})
	}
}

func TestCanonicalizeJSON_Idempotent(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			once, err := CanonicalizeJSON(v.Input)
			if err != nil {
				t.Fatalf("first pass: %v", err)
			}
			twice, err := CanonicalizeJSON(once)
			if err != nil {
				t.Fatalf("second pass: %v", err)
			}
			if !bytes.Equal(once, twice) {
				t.Errorf("%s: not idempotent\n  once:  %s\n  twice: %s", v.ID, once, twice)
			}
		})
	}
}

func TestCanonicalizeJSON_InvalidJSON(t *testing.T) {
	bad := [][]byte{
		[]byte("not json at all"),
		[]byte("{truncated"),
		[]byte(""),
		[]byte(`{"a": 1,}`),
		[]byte(`{"a": 1} extra`),
	}
	for _, b := range bad {
		if _, err := CanonicalizeJSON(b); err == nil {
			t.Errorf("expected error for %q, got none", string(b))
		}
	}
}

func TestCanonicalizeJSON_DuplicateKeys(t *testing.T) {
	// Duplicate keys are REJECTED (RFC 8785; matches the Python SDK). Go's
	// json.Decoder would otherwise silently keep the last value, making the
	// committed hash depend on an undocumented last-wins rule and diverge from
	// the Python reference.
	rejected := []string{
		`{"a":1,"a":2}`,                      // top-level
		`{"a":1,"b":{"c":1,"c":2}}`,          // nested object
		`{"a":1,"b":[{"x":1,"x":2}]}`,        // inside an array
		`{"dup":true,"other":1,"dup":false}`, // non-adjacent
	}
	for _, in := range rejected {
		if _, err := CanonicalizeJSON([]byte(in)); err == nil {
			t.Errorf("expected duplicate-key rejection for %s, got none", in)
		}
	}
	// Distinct keys with a repeated key name at different nesting levels are OK.
	ok := `{"a":{"k":1},"b":{"k":2}}`
	if _, err := CanonicalizeJSON([]byte(ok)); err != nil {
		t.Errorf("same key name at different levels must be allowed: %v", err)
	}
}

func TestCanonicalizeJSON_LargeInput(t *testing.T) {
	obj := make(map[string]interface{}, 200)
	for i := 0; i < 200; i++ {
		obj[fmt.Sprintf("key_%04d", i)] = map[string]interface{}{
			"n":     i,
			"flag":  i%2 == 0,
			"label": strings.Repeat("x", 500),
			"tags":  []interface{}{"a", "b", "c", i},
		}
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 100*1024 {
		t.Fatalf("test input too small: %d bytes", len(raw))
	}
	start := time.Now()
	out, err := CanonicalizeJSON(raw)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("canonicalize took %v, want <100ms", elapsed)
	}
	// Output must itself be valid JSON.
	var sink interface{}
	if err := json.Unmarshal(out, &sink); err != nil {
		t.Errorf("canonical output is not valid JSON: %v", err)
	}
}

func TestCanonicalizeJSON_NegativeZero(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`{"value":-0.0}`, `{"value":0}`},
		{`{"value":-0}`, `{"value":0}`},
		{`{"value":0.0}`, `{"value":0}`},
	}
	for _, c := range cases {
		got, err := CanonicalizeJSON([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("%s: got %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalizeJSON_RejectsUnsafeIntegers(t *testing.T) {
	// The exact boundary is accepted and canonicalizes to its literal.
	for _, ok := range []struct{ in, want string }{
		{`{"n":9007199254740991}`, `{"n":9007199254740991}`},   // 2^53 - 1
		{`{"n":-9007199254740991}`, `{"n":-9007199254740991}`}, // -(2^53 - 1)
		{`{"n":0}`, `{"n":0}`},
		{`{"n":9007199254740991.0}`, `{"n":9007199254740991}`}, // float form still routes through the double path
	} {
		got, err := CanonicalizeJSON([]byte(ok.in))
		if err != nil {
			t.Errorf("%s: unexpected error %v", ok.in, err)
			continue
		}
		if string(got) != ok.want {
			t.Errorf("%s: got %s, want %s", ok.in, got, ok.want)
		}
	}

	// One past the boundary (and far beyond) must be rejected, not rounded —
	// in ANY spelling. The exponent/decimal forms are the bypass the first C1
	// fix missed: they skip a literal-based check but not a value-based one.
	for _, bad := range []string{
		`{"n":9007199254740992}`,     // 2^53, bare
		`{"n":-9007199254740992}`,    // -2^53, bare
		`{"n":12345678901234567890}`, // 20-digit id, bare
		`{"n":9999999999999999}`,     // 16-digit int just over the safe range
		`{"n":9007199254740993E0}`,   // trailing-exponent spelling (bypass)
		`{"n":9.007199254740993e15}`, // scientific spelling of ...993 (bypass)
		`{"n":1e19}`,                 // exponent integer > 2^53 (bypass)
		`{"n":6.022e23}`,             // integer-valued scientific (bypass)
		`{"n":-1e20}`,                // negative exponent integer
	} {
		if _, err := CanonicalizeJSON([]byte(bad)); err == nil {
			t.Errorf("expected rejection for unsafe integer-valued number %s, got none", bad)
		}
	}

	// Non-integer values remain accepted regardless of magnitude of the
	// fractional part — only integer-VALUED numbers beyond the range are barred.
	for _, ok := range []string{`{"n":0.1}`, `{"n":2.5}`, `{"n":1.5e-10}`, `{"n":1e-7}`} {
		if _, err := CanonicalizeJSON([]byte(ok)); err != nil {
			t.Errorf("%s: unexpected rejection %v", ok, err)
		}
	}
}

func TestCanonicalizeJSON_FloatFormatting(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`{"v":1.0}`, `{"v":1}`},
		{`{"v":0.5}`, `{"v":0.5}`},
		{`{"v":0.125}`, `{"v":0.125}`},
		{`{"v":0.001}`, `{"v":0.001}`},
		{`{"v":0.00001}`, `{"v":0.00001}`},
		{`{"v":1e-6}`, `{"v":0.000001}`},
		{`{"v":1e-7}`, `{"v":1e-7}`},
		{`{"v":-3.14}`, `{"v":-3.14}`},
		{`{"v":1000000.0}`, `{"v":1000000}`},
		{`{"v":100.5}`, `{"v":100.5}`},
		{`{"v":42}`, `{"v":42}`},
	}
	for _, c := range cases {
		got, err := CanonicalizeJSON([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("%s: got %s, want %s", c.in, got, c.want)
		}
	}

	// Integer-VALUED numbers beyond the safe range are rejected in every
	// spelling, including scientific notation (1e20, 1e21). This is the
	// value-based rule that keeps Go and Python identical and closes the
	// exponent bypass; large integers must be sent as JSON strings. Non-integer
	// scientific values (covered above, e.g. 1e-7) are unaffected.
	for _, bad := range []string{`{"v":1e20}`, `{"v":1e21}`, `{"v":1e30}`} {
		if _, err := CanonicalizeJSON([]byte(bad)); err == nil {
			t.Errorf("expected rejection for integer-valued scientific number %s", bad)
		}
	}
}

func TestHashJSON_InvalidJSON(t *testing.T) {
	if _, err := HashJSON([]byte("{not valid")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestHashJSON_DeterministicAcrossKeyOrders(t *testing.T) {
	a, err := HashJSON([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashJSON([]byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("hashes differ for logically identical JSON: %s vs %s", a, b)
	}
}

// === Causality Chain Tests ===
//
// ComputeCausalityHash and its tests are DELETED. §3.5 re-binds causality to
// SHA3-256(JCS(provenance)); the binding, the normative build order, and I3 are
// tested in record_test.go / invariants_test.go against the provenance
// envelope. The old linear "prev_hash + step_index" model could not express a
// node with two parents, which is the entire point of the 33-field schema.

// Helper: print the computed SHA3-256 of vector 15's expected_jcs so the
// vector file can be populated. Runs only when PLAINREAL_PRINT_VECTOR_HASHES=1.
func TestVerifyWithPublicKey_InvalidInputs(t *testing.T) {
	validPub := strings.Repeat("a", 64)
	validHash := strings.Repeat("b", 64)
	validSig := strings.Repeat("c", 128)
	cases := []struct {
		name, pub, hash, sig string
	}{
		{"empty_pub", "", validHash, validSig},
		{"short_pub", strings.Repeat("a", 32), validHash, validSig},
		{"nonhex_pub", strings.Repeat("z", 64), validHash, validSig},
		{"empty_hash", validPub, "", validSig},
		{"short_hash", validPub, strings.Repeat("b", 32), validSig},
		{"nonhex_hash", validPub, strings.Repeat("z", 64), validSig},
		{"empty_sig", validPub, validHash, ""},
		{"short_sig", validPub, validHash, strings.Repeat("c", 64)},
		{"nonhex_sig", validPub, validHash, strings.Repeat("z", 128)},
	}
	for _, c := range cases {
		_, err := VerifyWithPublicKey(c.pub, c.hash, c.sig)
		if err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

// TestVerifyWithPublicKey_ZeroDependencies parses core/crypto.go and asserts
// that the body of VerifyWithPublicKey references no PlainReal-specific
// identifiers. The function must depend only on crypto/ed25519, encoding/hex,
// and fmt — if an PlainReal helper ever sneaks into its body, this fails.
func flipFirstHexNibble(hexStr string) string {
	if hexStr == "" {
		return hexStr
	}
	b := []byte(hexStr)
	// Flip '0' <-> '1'. If it's anything else, map through the hex alphabet so
	// the result is still a valid hex char of different value.
	switch b[0] {
	case '0':
		b[0] = '1'
	case '1':
		b[0] = '0'
	default:
		if b[0] >= 'a' && b[0] <= 'f' {
			b[0] = 'a' + (b[0]-'a'+1)%6
		} else if b[0] >= '0' && b[0] <= '9' {
			b[0] = '0' + (b[0]-'0'+1)%10
		}
	}
	return string(b)
}

func flipLastHexNibble(hexStr string) string {
	if hexStr == "" {
		return hexStr
	}
	b := []byte(hexStr)
	i := len(b) - 1
	switch b[i] {
	case '0':
		b[i] = '1'
	case '1':
		b[i] = '0'
	default:
		if b[i] >= 'a' && b[i] <= 'f' {
			b[i] = 'a' + (b[i]-'a'+1)%6
		} else if b[i] >= '0' && b[i] <= '9' {
			b[i] = '0' + (b[i]-'0'+1)%10
		}
	}
	return string(b)
}

func TestVerifyWithPublicKey_ZeroDependencies(t *testing.T) {
	src, err := os.ReadFile("crypto.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "crypto.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "VerifyWithPublicKey" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("VerifyWithPublicKey not found in crypto.go")
	}
	forbidden := map[string]bool{
		"SigningService":             true,
		"SoftwareSigningService":     true,
		"HashSHA3256":                true,
		"HashJSON":                   true,
		"CanonicalizeJSON":           true,
		"canonicalizeValue":          true,
		"canonicalizeNumber":         true,
		"writeCanonicalString":       true,
		"ecmaNumberToString":         true,
		"compareUTF16":               true,
		"compareUTF16Units":          true,
		"decodeSHA3Hash":             true,
		"decodeEd25519Signature":     true,
		"readPrivateKeyPEM":          true,
		"readPublicKeyPEM":           true,
		"writePrivateKeyPEM":         true,
		"writePublicKeyPEM":          true,
		"checkPrivateKeyPermissions": true,
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if forbidden[id.Name] {
				t.Errorf("VerifyWithPublicKey references forbidden PlainReal identifier %q at %v",
					id.Name, fset.Position(id.Pos()))
			}
		}
		return true
	})
}
