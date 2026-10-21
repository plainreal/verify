package verifycore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The cross-language invariant conformance corpus.
//
// testdata/invariant_vectors.json is derived from docs/RECORD_SCHEMA.md, not
// from this package. That direction matters: a corpus read off one
// implementation can only ever prove that the other one copied it, and the
// README tells readers that two independent implementations agree.
//
// The browser verifier will be checked against the same file in v1.2.0. Until
// both sides pass it, "they agree" is a claim about the corpus and nothing
// more, which is exactly what it should be.
//
// This file exists because of what happened to the Python SDK: from 2026-07-16
// to 2026-10-19 it could not seal at all while both test suites passed, each
// side testing against its own idea of the other. A shared contract is the
// only thing that catches that.

type invariantCase struct {
	ID         string `json:"id"`
	Invariant  string `json:"invariant"`
	Spec       string `json:"spec"`
	Why        string `json:"why"`
	Expect     string `json:"expect"`
	ExpectPath string `json:"expect_path"`
	// KnownDivergence marks a case whose expected verdict is the spec's answer
	// and which an implementation does not yet reach the right way. It is a
	// skip with a stated reason, never a silent one, and the release preflight
	// refuses to ship a corpus that still carries any.
	KnownDivergence string `json:"known_divergence"`
	Mutations       []struct {
		Path   string          `json:"path"`
		Set    json.RawMessage `json:"set"`
		Delete bool            `json:"delete"`
	} `json:"mutations"`
}

type invariantCorpus struct {
	Version          string                 `json:"version"`
	RelationshipEnum []string               `json:"relationship_enum"`
	Base             map[string]interface{} `json:"base"`
	Cases            []invariantCase        `json:"cases"`
}

func loadInvariantCorpus(t *testing.T) *invariantCorpus {
	t.Helper()
	// Repo root, then the published tree's copy. verifycore ships standalone,
	// so the vectors must sit beside it there (see scripts/published-tree-check).
	for _, p := range []string{
		filepath.Join("..", "testdata", "invariant_vectors.json"),
		filepath.Join("testdata", "invariant_vectors.json"),
	} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var c invariantCorpus
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return &c
	}
	t.Fatal("invariant_vectors.json not found")
	return nil
}

// applyMutation walks a dotted path and sets or deletes the leaf. A segment
// that parses as an integer indexes an array. Deliberately simple: this is a
// cross-language contract, and anything clever here is a second thing that has
// to be implemented identically in JavaScript.
func applyMutation(doc map[string]interface{}, path string, value interface{}, del bool) error {
	segs := strings.Split(path, ".")
	var cur interface{} = doc
	for i, s := range segs {
		last := i == len(segs)-1
		switch node := cur.(type) {
		case map[string]interface{}:
			if last {
				if del {
					delete(node, s)
				} else {
					node[s] = value
				}
				return nil
			}
			next, ok := node[s]
			if !ok {
				return fmt.Errorf("no key %q at %q", s, strings.Join(segs[:i+1], "."))
			}
			cur = next
		case []interface{}:
			idx, err := strconv.Atoi(s)
			if err != nil {
				return fmt.Errorf("segment %q is not an array index", s)
			}
			if idx < 0 || idx >= len(node) {
				return fmt.Errorf("index %d out of range at %q", idx, path)
			}
			if last {
				if del {
					return fmt.Errorf("delete from an array is not supported (%q)", path)
				}
				node[idx] = value
				return nil
			}
			cur = node[idx]
		default:
			return fmt.Errorf("cannot descend into %T at %q", cur, s)
		}
	}
	return nil
}

func deepCopyJSON(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// normalisePath turns the corpus's display form into something comparable with
// an issue string: "execution_context.llm_calls[0].output_hash" and
// "execution_context.llm_calls.0.output_hash" both reduce to the same stem.
func normalisePath(p string) string {
	p = strings.ReplaceAll(p, "[", ".")
	p = strings.ReplaceAll(p, "]", "")
	return p
}

func TestInvariantVectors(t *testing.T) {
	corpus := loadInvariantCorpus(t)
	if len(corpus.Cases) == 0 {
		t.Fatal("corpus has no cases")
	}

	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.KnownDivergence != "" {
				t.Skipf("KNOWN DIVERGENCE, blocks release: %s", c.KnownDivergence)
			}
			doc := deepCopyJSON(t, corpus.Base)
			for _, mu := range c.Mutations {
				var val interface{}
				if !mu.Delete {
					if err := json.Unmarshal(mu.Set, &val); err != nil {
						t.Fatalf("case %s: bad `set` value: %v", c.ID, err)
					}
				}
				if err := applyMutation(doc, mu.Path, val, mu.Delete); err != nil {
					t.Fatalf("case %s: %v", c.ID, err)
				}
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}

			_, issues, vErr := ValidateArtifactBytes(raw)
			rejected := vErr != nil || len(issues) > 0

			switch c.Expect {
			case "accept":
				if rejected {
					t.Errorf("expected ACCEPT, got rejection.\n  spec: %s\n  why: %s\n  err: %v\n  issues: %v",
						c.Spec, c.Why, vErr, issues)
				}
			case "reject":
				if !rejected {
					t.Errorf("expected REJECT, got acceptance.\n  spec: %s\n  why: %s",
						c.Spec, c.Why)
					return
				}
				// Rejecting for an unrelated reason is not conformance. The
				// corpus names the field a conforming validator must point at.
				if c.ExpectPath == "" {
					return
				}
				want := normalisePath(c.ExpectPath)
				joined := normalisePath(strings.Join(issues, " | "))
				if vErr != nil {
					joined += " | " + normalisePath(vErr.Error())
				}
				if !strings.Contains(joined, want) {
					t.Errorf("rejected, but not for %q.\n  spec: %s\n  why: %s\n  err: %v\n  issues: %v",
						c.ExpectPath, c.Spec, c.Why, vErr, issues)
				}
			default:
				t.Fatalf("case %s: unknown expect %q", c.ID, c.Expect)
			}
		})
	}
}

// TestInvariantVectors_EnumMatchesSpec keeps the corpus's copy of the §3.2.1
// enum honest. The corpus lists the ten values so the JavaScript side can read
// them from the contract rather than retyping them.
func TestInvariantVectors_EnumMatchesSpec(t *testing.T) {
	corpus := loadInvariantCorpus(t)
	if len(corpus.RelationshipEnum) != 10 {
		t.Fatalf("§3.2.1 is a closed enum of ten; corpus lists %d",
			len(corpus.RelationshipEnum))
	}
	for _, rel := range corpus.RelationshipEnum {
		doc := deepCopyJSON(t, corpus.Base)
		e := map[string]interface{}{
			"record_id":                "11111111-2222-4333-8444-555555555555",
			"record_hash":              strings.Repeat("b", 64),
			"relationship":             rel,
			"consumed_output_selector": "/execution_result",
			"consumed_output_hash":     strings.Repeat("a", 64),
			"parent_signing_key_id":    strings.Repeat("c", 64),
		}
		switch rel {
		case "APPROVES", "REVISES", "RETRACTS", "TRIGGERED_BY", "EXECUTES":
			// §3.2.1: control edges carry "" and the 64-zero hash.
			e["consumed_output_selector"] = ""
			e["consumed_output_hash"] = strings.Repeat("0", 64)
		case "SELECTED_FROM":
			// I7 needs a companion; covered by its own case.
			continue
		}
		if err := applyMutation(doc, "provenance.upstream",
			[]interface{}{e}, false); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(doc)
		_, issues, vErr := ValidateArtifactBytes(raw)
		for _, is := range issues {
			if strings.Contains(is, "relationship") {
				t.Errorf("%s is one of the ten but was rejected on relationship: %s", rel, is)
			}
		}
		_ = vErr
	}
}
