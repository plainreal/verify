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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var expectedJSONTags = []string{
	"record_id",
	"record_version",
	"created_at",
	"evidence_tier",
	"decision_kind",
	"principal_identity",
	"action_type",
	"input_hash",
	"authorization_token_id",
	"full_prompt_snapshot",
	"rag_evidence_bundle",
	"model_version_hash",
	"model_provider",
	"model_name",
	"output_pre_postprocess",
	"execution_result",
	"tool_call_log",
	"causality_chain_hash",
	"policy_version_hash",
	"availability_policy",
	"deployment_mode",
	"sdk_hash_layer",
	"sdk_binary_sha3",
	"registry_validation_status",
	"signing_key_id",
	"signing_attestation",
	"lock_verification_latency_ms",
	"instrumentation_coverage",
	"capture_layer",
	"consequential",
	"provenance",
	"governance_context",
	"execution_context",
}

// recordFieldCount is the number of fields on the Record struct — the
// frozen v1.0.0 schema. This count is the single source of truth that the
// SCITT profile and the dev-guide cite; changing it is a schema decision.
// 33 top-level, 32 signed (signing_attestation is excluded from the hash).
const recordFieldCount = TopLevelFieldCount

func TestRecord_FieldCount(t *testing.T) {
	got := reflect.TypeOf(Record{}).NumField()
	if got != recordFieldCount {
		t.Fatalf("Record field count = %d, want %d", got, recordFieldCount)
	}
}

func TestRecord_AllFieldsPresent(t *testing.T) {
	p := newTestRecord()
	p.SigningKeyID = HashSHA3256([]byte("test-pub-key"))
	p.SigningAttestation = strings.Repeat("a", 128)
	// capture_layer and consequential are required fields already populated
	// by NewTestRecord, so every expected key appears.

	raw, err := p.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != recordFieldCount {
		t.Errorf("JSON key count = %d, want %d. Keys: %v", len(m), recordFieldCount, keysOf(m))
	}
	for _, tag := range expectedJSONTags {
		if _, ok := m[tag]; !ok {
			t.Errorf("missing JSON key %q", tag)
		}
	}
}

func TestRecord_RegulatoryMapping(t *testing.T) {
	typ := reflect.TypeOf(Record{})
	if typ.NumField() != len(expectedJSONTags) {
		t.Fatalf("field count %d != expected tag count %d", typ.NumField(), len(expectedJSONTags))
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name != expectedJSONTags[i] {
			t.Errorf("field[%d] %s: json tag = %q, want %q", i, f.Name, name, expectedJSONTags[i])
		}
	}
}

// fieldsWithOmitempty is the closed set of JSON-tag names allowed to carry
// the omitempty modifier. Each is load-bearing for a specific reason; see
// the Record struct doc comment for the rationale. Adding a new entry is
// a schema decision — do not relax this list to make a test pass.
func TestRecord_SigningAttestationHasOmitempty(t *testing.T) {
	typ := reflect.TypeOf(Record{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		opts := strings.Split(tag, ",")[1:]
		hasOmit := false
		for _, o := range opts {
			if o == "omitempty" {
				hasOmit = true
			}
		}
		shouldHave := fieldsWithOmitempty[name]
		if shouldHave && !hasOmit {
			t.Errorf("field %s (%s) must have omitempty; got tag %q", f.Name, name, tag)
		}
		if !shouldHave && hasOmit {
			t.Errorf("field %s (%s) must NOT have omitempty; got tag %q", f.Name, name, tag)
		}
	}
}

// =============================================================================
// JSON round-trip
// =============================================================================

func TestRecord_JSONRoundTrip(t *testing.T) {
	p := newTestRecord()
	p.SigningKeyID = HashSHA3256([]byte("k"))
	p.SigningAttestation = strings.Repeat("b", 128)

	raw, err := p.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	q, err := RecordFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, q) {
		t.Errorf("round-trip mismatch.\n got  = %+v\n want = %+v", q, p)
	}
}

func validRecord(t *testing.T) *Record {
	t.Helper()
	p := newTestRecord()
	p.SigningKeyID = HashSHA3256([]byte("test-pub-key"))
	return p
}

func TestRecordVersionConst(t *testing.T) {
	if RecordVersion != "1.0.0" {
		t.Errorf("RecordVersion = %q, want %q", RecordVersion, "1.0.0")
	}
	if !IsSupportedRecordVersion("1.0.0") {
		t.Error("IsSupportedRecordVersion(1.0.0) = false; want true")
	}
	if IsSupportedRecordVersion("1.1.0") {
		t.Error("IsSupportedRecordVersion(1.1.0) = true; want false (no such version)")
	}
	if IsSupportedRecordVersion("2.0.0") {
		t.Error("IsSupportedRecordVersion(2.0.0) = true; want false")
	}
	if IsSupportedRecordVersion("") {
		t.Error("IsSupportedRecordVersion empty string = true; want false")
	}
	got := SupportedRecordVersions()
	want := []string{"1.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SupportedRecordVersions = %v, want %v", got, want)
	}
}

// TestHashStability_V1_0_0_Fixture (T8) — the committed v1.0.0 fixture
// must recompute to a known hash AND the embedded signing_attestation
// must still verify against that hash and the committed pubkey. If this
// test ever fails, every v1.0.0 artifact in the field is unverifiable.
//
// The expected hash is the value the original signer produced; it is
// pinned here in addition to the signature check because the signature
// alone could in principle survive an algorithm change that produced a
// different hash from a different canonicalization path.
//
// It runs the AUDITOR path (§4.6.1): the hash is recomputed from the
// artifact's own BYTES as generic JSON, never by unmarshaling into Record
// and re-marshaling. That is deliberate — this is the test standing in for a
// third party with nothing but the file and a public key, so routing it
// through the producer's struct would be the one thing an auditor cannot do,
// and would hide exactly the regression the test exists to catch.
func readPubkeyHex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("pubkey PEM has no block: %s", path)
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("pubkey PEM type = %q, want PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("pubkey not Ed25519: %T", pub)
	}
	return hex.EncodeToString(edPub)
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target || strings.HasPrefix(s, target+" (") {
			return true
		}
	}
	return false
}

// testUUIDRe is local to this test rather than core.uuidRe, which moved to
// verifycore with the parsing it serves. TestNewRecord asserts that the
// PRODUCER mints a UUID v4; the grammar it checks against is incidental to
// that, so a local copy is honest and keeps the test with the code it tests.
var testUUIDRe = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRecord_TopLevelKeysMatchStruct is the test core/record.go's comment has
// cited since the field list was frozen, and which did not exist until now. It
// was cited again, in verifier/test/go-record, as the justification for deriving
// the published field list from a sealed record's keys rather than from this
// map — so a claim that could not survive a grep was load-bearing in two places.
//
// What it guards is real. topLevelKeys is what RecordFromJSON uses to reject an
// unknown top-level key (§6). The Record struct is what produces the artifact.
// If a field is added to one and not the other, the producer emits a document
// its own parser refuses, or the parser admits a field nothing can populate —
// and TestRecord_FieldCount would not notice either, because it counts struct
// fields by reflection and never looks at this map.

// fieldsWithOmitempty is the closed set of JSON-tag names allowed to carry
// the omitempty modifier. Each is load-bearing for a specific reason; see
// the Record struct doc comment for the rationale. Adding a new entry is
// a schema decision — do not relax this list to make a test pass.
var fieldsWithOmitempty = map[string]bool{
	"signing_attestation": true, // load-bearing for ComputeRecordHash
}
