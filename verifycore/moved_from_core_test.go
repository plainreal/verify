// Tests that came with the code when the verification half moved out of core.
//
// They exercise unexported internals -- the canonicalization number formatter,
// the UTF-16 key comparator, the frozen top-level key map, the edge sort key --
// so they can only live in the package that now defines them. Moving the code
// and leaving its tests behind would have quietly dropped the coverage.
package verifycore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalizeJSON_RejectsSpecialFloats(t *testing.T) {
	// Standard JSON parsers reject NaN and Infinity at parse time — verify
	// CanonicalizeJSON surfaces an error rather than silently accepting them.
	// Also attempt construction via json.Number to reach the hash path directly.
	for _, bad := range []string{`{"x":NaN}`, `{"x":Infinity}`, `{"x":-Infinity}`} {
		if _, err := CanonicalizeJSON([]byte(bad)); err == nil {
			t.Errorf("expected error for %s, got none", bad)
		}
	}
	// Direct: if someone fed a NaN through json.Number at a lower level.
	if _, err := canonicalizeNumber(json.Number("NaN")); err == nil {
		t.Error("expected error for json.Number(NaN)")
	}
	if _, err := canonicalizeNumber(json.Number("Infinity")); err == nil {
		t.Error("expected error for json.Number(Infinity)")
	}
	// Overflow: 1e400 parses to +Inf with an error — must also be rejected.
	if _, err := canonicalizeNumber(json.Number("1e400")); err == nil {
		t.Error("expected error for overflowing number")
	}
}

// TestCanonicalizeJSON_RejectsUnsafeIntegers pins the fix for the cross-language
// divergence where Go rounded integers > 2^53 through float64 while the Python
// SDK preserved them exactly — producing different hashes for the same input.
// Both implementations now REJECT integers outside the IEEE-754 safe range.
// TestCompareUTF16_Ordering exercises the comparator directly, including the
// length branches.
//
// Those branches were previously reached only incidentally, by whatever key
// sets the other tests happened to sort. Go randomises map iteration, so
// whether a shorter-key comparison came up at all varied run to run, and
// verifycore's reported coverage flickered between 80.1% and 80.3%. The README
// publishes that figure and tells the reader to check it, so a number that
// moves on its own is a claim that looks false to anyone who runs it twice.
//
// The ordering itself matters beyond the figure: RFC 8785 key order is what
// makes two canonicalizations of the same object identical, so a prefix
// comparison getting the wrong sign would change a record_hash.
func TestCompareUTF16_Ordering(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
	}{
		{"identical", "alpha", "alpha", 0},
		{"both empty", "", "", 0},
		{"empty sorts before anything", "", "a", -1},
		{"anything sorts after empty", "a", "", 1},
		{"a is a prefix of b", "rec", "record", -1},
		{"b is a prefix of a", "record", "rec", 1},
		{"differs early, a lower", "abc", "abd", -1},
		{"differs early, b lower", "abd", "abc", 1},
		{"length is only consulted after content", "b", "aa", 1},
		{"non-BMP sorts by surrogate pair, not code point", "\U0001D11E", "\uFFFD", -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := compareUTF16(c.a, c.b)
			if sign(got) != c.want {
				t.Errorf("compareUTF16(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
			}
			// Antisymmetry: swapping the arguments must flip the sign. A
			// comparator that fails this can make sort.Slice produce a
			// different order for the same input set.
			if rev := compareUTF16(c.b, c.a); sign(rev) != -c.want {
				t.Errorf("compareUTF16(%q, %q) = %d, not the negation of %d",
					c.b, c.a, rev, got)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestCanonicalizeJSON_UTF16KeySort(t *testing.T) {
	// U+FFFD ("\uFFFD") is a single UTF-16 code unit FFFD.
	// U+1D11E (𝄞, Musical Symbol G Clef) is the surrogate pair D834 DD1E.
	// UTF-16 code unit ordering: D834 < FFFD, so 𝄞 sorts BEFORE U+FFFD.
	// Unicode code point ordering would put U+FFFD first — opposite.
	in := []byte("{\"\uFFFD\":\"replacement\",\"\U0001D11E\":\"g-clef\"}")
	got, err := CanonicalizeJSON(in)
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}
	want := []byte("{\"\U0001D11E\":\"g-clef\",\"\uFFFD\":\"replacement\"}")
	if !bytes.Equal(got, want) {
		t.Errorf("UTF-16 key sort wrong\n  got:  %s\n  want: %s", got, want)
	}
	// Direct comparator check too.
	if compareUTF16("\U0001D11E", "\uFFFD") >= 0 {
		t.Error("compareUTF16: expected 𝄞 < U+FFFD under UTF-16 ordering")
	}
}

func TestRecord_TopLevelKeysMatchStruct(t *testing.T) {
	structTags := map[string]struct{}{}
	rt := reflect.TypeOf(Record{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			t.Fatalf("field %s has no json tag; the wire name is the contract", rt.Field(i).Name)
		}
		name := strings.Split(tag, ",")[0]
		structTags[name] = struct{}{}
	}

	for name := range structTags {
		if _, ok := topLevelKeys[name]; !ok {
			t.Errorf("struct field %q is missing from topLevelKeys — RecordFromJSON would reject an artifact this package produces", name)
		}
	}
	for name := range topLevelKeys {
		if _, ok := structTags[name]; !ok {
			t.Errorf("topLevelKeys has %q with no struct field — the parser admits a key nothing populates", name)
		}
	}
	if len(topLevelKeys) != TopLevelFieldCount {
		t.Errorf("topLevelKeys has %d entries, TopLevelFieldCount says %d", len(topLevelKeys), TopLevelFieldCount)
	}
}

// withUpstream returns the standard fixture re-bound with the given edges.
// Re-binds causality (§3.5) since provenance changed.
