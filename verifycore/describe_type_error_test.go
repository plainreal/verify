package verifycore

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// describeTypeError decides what a reader is told when a field has the wrong
// JSON type. Before it existed they were told "cannot unmarshal number into Go
// struct field LLMCallParams...", a Go type name with no array index. These
// cases pin the shapes that matter, including the rare ones no record in the
// corpus happens to produce.

func TestDescribeTypeError_NamesFieldIndexAndJSONKinds(t *testing.T) {
	data := []byte(`{"a":{"calls":[{"seq":1},{"seq":"two"},{"seq":3}]}}`)
	te := &json.UnmarshalTypeError{Value: "string", Type: reflect.TypeOf(0), Field: "a.calls.seq"}
	got := describeTypeError(data, te)
	want := "a.calls[1].seq must be a whole number, got a string"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestDescribeTypeError_EveryWrongElementIsNamed(t *testing.T) {
	data := []byte(`{"calls":[{"seq":"x"},{"seq":2},{"seq":"y"}]}`)
	te := &json.UnmarshalTypeError{Value: "string", Type: reflect.TypeOf(0), Field: "calls.seq"}
	got := describeTypeError(data, te)
	if !strings.Contains(got, "calls[0].seq") || !strings.Contains(got, "calls[2].seq") {
		t.Fatalf("both wrong elements must be named, got %q", got)
	}
	if strings.Contains(got, "calls[1]") {
		t.Fatalf("the correct element must not be named, got %q", got)
	}
}

func TestDescribeTypeError_NeverNamesAGoType(t *testing.T) {
	type Inner struct{ Seed string }
	data := []byte(`{"p":{"seed":42}}`)
	te := &json.UnmarshalTypeError{Value: "number", Type: reflect.TypeOf(""), Field: "p.seed",
		Struct: "Inner"}
	got := describeTypeError(data, te)
	for _, goWord := range []string{"Inner", "Go struct", "unmarshal", "int", "float64"} {
		if strings.Contains(got, goWord) {
			t.Errorf("message leaks %q: %q", goWord, got)
		}
	}
	_ = Inner{}
}

func TestDescribeTypeError_EmptyFieldDescribesTheRecord(t *testing.T) {
	te := &json.UnmarshalTypeError{Value: "array", Type: reflect.TypeOf(Record{}), Field: ""}
	got := describeTypeError([]byte(`[]`), te)
	if got != "the record must be an object, got an array" {
		t.Fatalf("got %q", got)
	}
}

func TestDescribeTypeError_FallsBackToTheUnindexedPath(t *testing.T) {
	// If the walk finds nothing, say what encoding/json said, in JSON terms,
	// rather than nothing at all.
	te := &json.UnmarshalTypeError{Value: "string", Type: reflect.TypeOf(0), Field: "missing.path"}
	got := describeTypeError([]byte(`{"other":1}`), te)
	if got != "missing.path must be a whole number, got a string" {
		t.Fatalf("got %q", got)
	}
}

func TestDescribeTypeError_UnparseableBytesStillDescribeTheField(t *testing.T) {
	te := &json.UnmarshalTypeError{Value: "bool", Type: reflect.TypeOf(""), Field: "x"}
	got := describeTypeError([]byte(`{not json`), te)
	if got != "x must be a string, got true or false" {
		t.Fatalf("got %q", got)
	}
}

func TestJSONKindOf_SpeaksJSONForEveryKind(t *testing.T) {
	var s *string
	cases := []struct {
		t    reflect.Type
		want string
	}{
		{reflect.TypeOf(""), "a string"},
		{reflect.TypeOf(true), "true or false"},
		{reflect.TypeOf(int64(0)), "a whole number"},
		{reflect.TypeOf(uint8(0)), "a whole number"},
		{reflect.TypeOf(1.5), "a number"},
		{reflect.TypeOf([]string{}), "an array"},
		{reflect.TypeOf([2]int{}), "an array"},
		{reflect.TypeOf(Record{}), "an object"},
		{reflect.TypeOf(map[string]int{}), "an object"},
		{reflect.TypeOf(s), "a string"}, // pointers resolve to their element
		{reflect.TypeOf(func() {}), "a value of a different type"},
		{nil, "a value of a different type"},
	}
	for _, c := range cases {
		if got := jsonKindOf(c.t); got != c.want {
			t.Errorf("jsonKindOf(%v) = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestGenericKind_MatchesEncodingJSONVocabulary(t *testing.T) {
	// genericKind must use the same words encoding/json puts in
	// UnmarshalTypeError.Value, or the walk never matches anything.
	for in, want := range map[string]string{
		`"s"`: "string", `1`: "number", `true`: "bool",
		`[]`: "array", `{}`: "object", `null`: "null",
	} {
		var v interface{}
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			t.Fatal(err)
		}
		if got := genericKind(v); got != want {
			t.Errorf("genericKind(%s) = %q, want %q", in, got, want)
		}
	}
	if genericKind(struct{}{}) != "unknown" {
		t.Error("an unexpected Go value should report unknown, not guess")
	}
}

func TestArticled(t *testing.T) {
	for in, want := range map[string]string{
		"array": "an array", "object": "an object", "number": "a number",
		"string": "a string", "bool": "true or false", "null": "null",
	} {
		if got := articled(in); got != want {
			t.Errorf("articled(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRecordFromJSON_NullWhereTheSchemaForbidsIt: encoding/json decodes null
// into a non-pointer field as its zero value, silently, so until v1.2.0 a
// record with consequential: null validated as false. The browser page refused
// it, and the two verifiers gave different verdicts on the same signed record.
func TestRecordFromJSON_NullWhereTheSchemaForbidsIt(t *testing.T) {
	corpus := loadInvariantCorpus(t)
	try := func(path string, value interface{}) error {
		doc := deepCopyJSON(t, corpus.Base)
		if err := applyMutation(doc, path, value, false); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(doc)
		_, err := RecordFromJSON(raw)
		return err
	}
	for _, c := range []struct{ path, want string }{
		{"consequential", "consequential must be true or false, got null"},
		{"instrumentation_coverage", "instrumentation_coverage must be a number, got null"},
		{"rag_evidence_bundle.0.score", "rag_evidence_bundle[0].score must be a number, got null"},
		{"execution_context.llm_calls.1.seq", "execution_context.llm_calls[1].seq must be a whole number, got null"},
		{"governance_context", "governance_context must be an object, got null"},
	} {
		err := try(c.path, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s := null: got %v, want an error containing %q", c.path, err, c.want)
		}
	}
	// §4.10's nullables, a null array (I5 reports that), and an envelope key
	// this verifier does not know (§6) are all left alone.
	for _, path := range []string{
		"execution_context.llm_calls.1.params.temperature",
		"execution_context.retrievals.0.params.top_k",
		"tool_call_log",
		"provenance.from_a_newer_producer",
	} {
		if err := try(path, nil); err != nil {
			t.Errorf("%s := null must decode, got %v", path, err)
		}
	}
}

// TestRecordFromJSON_KeysAreCaseSensitive: encoding/json matches keys
// case-insensitively, with Unicode folding, so "OVERSIGHT_MODE" was read AS
// oversight_mode, and with both spellings present the last one in the
// document won. The browser page reads the exact key. Found by the v1.2.0
// security review.
func TestRecordFromJSON_KeysAreCaseSensitive(t *testing.T) {
	corpus := loadInvariantCorpus(t)
	mutate := func(fn func(doc map[string]interface{})) error {
		doc := deepCopyJSON(t, corpus.Base)
		fn(doc)
		raw, _ := json.Marshal(doc)
		_, err := RecordFromJSON(raw)
		return err
	}
	gov := func(doc map[string]interface{}) map[string]interface{} {
		return doc["governance_context"].(map[string]interface{})
	}
	for name, fn := range map[string]func(map[string]interface{}){
		"renamed": func(d map[string]interface{}) {
			g := gov(d)
			g["OVERSIGHT_MODE"] = g["oversight_mode"]
			delete(g, "oversight_mode")
		},
		"beside the exact key": func(d map[string]interface{}) { gov(d)["Oversight_Mode"] = "PRE_AUTHORIZED" },
	} {
		err := mutate(fn)
		if err == nil || !strings.Contains(err.Error(), "only in letter case") {
			t.Errorf("%s: want a case-sensitivity error, got %v", name, err)
		}
	}
	// top_k folds with the Kelvin sign (U+212A) under strings.EqualFold.
	err := mutate(func(d map[string]interface{}) {
		r := d["execution_context"].(map[string]interface{})["retrievals"].([]interface{})[0].(map[string]interface{})
		params := r["params"].(map[string]interface{})
		params["top_K"] = 3
	})
	if err == nil || !strings.Contains(err.Error(), `"top_k" only in letter case`) {
		t.Errorf("Kelvin-sign spelling of top_k: want a case-sensitivity error, got %v", err)
	}
	// A genuinely new envelope key is still tolerated (§6).
	if err := mutate(func(d map[string]interface{}) { gov(d)["added_in_1_1"] = "x" }); err != nil {
		t.Errorf("an unknown envelope key must be tolerated, got %v", err)
	}
}
