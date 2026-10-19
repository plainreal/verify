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
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func hex64(pair string) string { return strings.Repeat(pair, 32) }

const (
	parentA = "11111111-1111-4111-8111-111111111111"
	parentB = "22222222-2222-4222-8222-222222222222"
)

// humanPrincipal is a well-formed §4.7 human principal: "human:" + a
// 64-lowercase-hex salted ref. The ref value is arbitrary here — I12 checks its
// SHAPE, which is all that is locally decidable. Constructing a real
// HMAC-SHA3-256(tenant_salt, subject_identifier) needs the tenant salt and is
// producer-side (M2).
var humanPrincipal = "human:" + hex64("7a")

// dataEdge builds a NON-control edge whose consumed_output_hash really is
// SHA3-256(JCS(value)) — so I1 holds by construction and a test that breaks it
// is breaking something real.
func dataEdge(parentID, parentHashPair string, rel Relationship, sel string, value string) UpstreamEdge {
	canonical, err := CanonicalizeJSON([]byte(value))
	if err != nil {
		panic("dataEdge: bad value: " + err.Error())
	}
	return UpstreamEdge{
		RecordID:               parentID,
		RecordHash:             hex64(parentHashPair),
		Relationship:           rel,
		ConsumedOutputSelector: sel,
		ConsumedOutputHash:     HashSHA3256(canonical),
		ParentSigningKeyID:     hex64("cd"),
	}
}

// controlEdge builds a control edge: empty selector + sentinel hash (§3.2.1).
func controlEdge(parentID, parentHashPair string, rel Relationship) UpstreamEdge {
	return UpstreamEdge{
		RecordID:               parentID,
		RecordHash:             hex64(parentHashPair),
		Relationship:           rel,
		ConsumedOutputSelector: "",
		ConsumedOutputHash:     ZeroHash64,
		ParentSigningKeyID:     hex64("cd"),
	}
}

// sortEdges puts edges into §4.3's total order, so a test fixture is sorted by
// construction and only the test that MEANS to break sortedness does.
func withUpstream(t *testing.T, edges ...UpstreamEdge) *Record {
	t.Helper()
	p := newTestRecord()
	p.Provenance.Upstream = sortEdges(edges)
	bindCausalityForTest(p)
	return p
}

// mustBeClean fails unless the record validates. Guards the NEGATIVE tests:
// if a fixture were already dirty, an "invariant fires" assertion could pass
// for the wrong reason and prove nothing.
func TestCausalityHashFromBytes_ToleratesUnknownEnvelopeKey(t *testing.T) {
	p := newTestRecord()
	raw, err := p.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]interface{}
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	prov := tree["provenance"].(map[string]interface{})
	prov["future_capability_ref"] = "wf:some-new-thing"

	// A newer producer's causality_chain_hash covers the key it wrote.
	provBytes, err := json.Marshal(prov)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalizeJSON(provBytes)
	if err != nil {
		t.Fatal(err)
	}
	want := HashSHA3256(canonical)
	tree["causality_chain_hash"] = want
	evolved, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}

	got, err := CausalityHashFromBytes(evolved)
	if err != nil {
		t.Fatalf("CausalityHashFromBytes: %v", err)
	}
	if got != want {
		t.Errorf("I3 over artifact bytes = %s, want %s", got, want)
	}

	// The struct path disagrees — which is why verifiers must not use it.
	viaStruct, err := RecordFromJSON(evolved)
	if err != nil {
		t.Fatal(err)
	}
	structHash, err := causalityFromStructForTest(&viaStruct.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	if structHash == want {
		t.Fatal("struct-marshaled provenance matched the artifact's own bytes; the I3 trap is not pinned")
	}
}

// TestParseStrictness_TopLevelStrict_EnvelopeLenient pins §6's split. The two
// halves are one rule: unknown TOP-LEVEL key = someone inventing a field
// outside the frozen 33 (reject); unknown ENVELOPE key = sanctioned additive
// evolution (tolerate).
func TestI2_RelationshipEnum(t *testing.T) {
	p := withUpstream(t, dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`))
	mustBeClean(t, p)

	p.Provenance.Upstream[0].Relationship = Relationship("CONSUMED_MAYBE")
	bindCausalityForTest(p)
	mustFire(t, p, "provenance.upstream[0].relationship")
}

func TestI2_AllTenValuesAccepted(t *testing.T) {
	all := []Relationship{
		DerivedFrom, Aggregates, Validates, SelectedFrom, ConsideredAlternative,
		Approves, Revises, Retracts, TriggeredBy, Executes,
	}
	if len(all) != 10 {
		t.Fatalf("the enum is frozen at 10 values (§3.2.1); got %d", len(all))
	}
	for _, r := range all {
		if !IsValidRelationship(r) {
			t.Errorf("%s rejected by IsValidRelationship", r)
		}
	}
	// The control/data split must classify every value — an unclassified value
	// would silently take the data path and demand an upstream_outputs entry.
	control := 0
	for _, r := range all {
		if IsControlEdge(r) {
			control++
		}
	}
	if control != 5 {
		t.Errorf("control edges = %d, want 5 (APPROVES, REVISES, RETRACTS, TRIGGERED_BY, EXECUTES)", control)
	}
}

// =============================================================================
// I5 — defined sentinels, never emptiness
// =============================================================================

func TestI5_SentinelsNotEmptiness(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*Record)
		field  string
	}{
		{"rag bundle null", func(p *Record) { p.RAGEvidenceBundle = nil }, "rag_evidence_bundle"},
		{"tool log null", func(p *Record) { p.ToolCallLog = nil }, "tool_call_log"},
		{"upstream null", func(p *Record) { p.Provenance.Upstream = nil }, "provenance.upstream"},
		{"llm_calls null", func(p *Record) { p.ExecutionContext.LLMCalls = nil }, "execution_context.llm_calls"},
		{"retrievals null", func(p *Record) { p.ExecutionContext.Retrievals = nil }, "execution_context.retrievals"},
		{"guardrails null", func(p *Record) { p.ExecutionContext.Guardrails = nil }, "execution_context.guardrails"},
		{"data_subject_refs null", func(p *Record) { p.GovernanceContext.DataSubjectRefs = nil }, "governance_context.data_subject_refs"},
		{"correlation_ids null", func(p *Record) { p.GovernanceContext.CorrelationIDs = nil }, "governance_context.correlation_ids"},
		{"workflow_id empty not \"adhoc\"", func(p *Record) { p.Provenance.WorkflowID = "" }, "provenance.workflow_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestRecord()
			mustBeClean(t, p)
			tc.break_(p)
			// Re-bind so the mutation is judged on its own terms rather than
			// tripping I3 first.
			bindCausalityForTest(p)
			mustFire(t, p, tc.field)
		})
	}
}

// TestI5_AdHocSentinelsArePackageDeal — "adhoc" means no declared DAG, which
// means no definition to hash and no vertex to name. A record claiming a
// declared workflow_id while carrying the ad-hoc definition sentinel would make
// workflow_definition_hash unresolvable against the WORM archive in year six.
func TestI5_AdHocSentinelsArePackageDeal(t *testing.T) {
	t.Run("adhoc requires the zero definition hash", func(t *testing.T) {
		p := newTestRecord()
		p.Provenance.WorkflowDefinitionHash = hex64("ab")
		bindCausalityForTest(p)
		mustFire(t, p, "provenance.workflow_definition_hash")
	})
	t.Run("adhoc requires node_id to echo record_id", func(t *testing.T) {
		p := newTestRecord()
		p.Provenance.WorkflowNodeID = "some-other-node"
		bindCausalityForTest(p)
		mustFire(t, p, "provenance.workflow_node_id")
	})
	t.Run("a declared workflow requires a real definition hash", func(t *testing.T) {
		p := newTestRecord()
		p.Provenance.WorkflowID = "wf-loan-2agent"
		p.Provenance.WorkflowNodeID = "adjudicator"
		// ...but leaves the ad-hoc sentinel in place.
		bindCausalityForTest(p)
		mustFire(t, p, "provenance.workflow_definition_hash")
	})
}

// =============================================================================
// I6 — self-edge (acyclicity itself is by construction)
// =============================================================================

// TestI6_SelfEdgeRejected documents the ONE degenerate case construction does
// not preclude. Acyclicity at large needs no check and gets none: an edge
// commits its parent's record_hash, which exists only AFTER that parent is
// sealed, so a cycle would require committing a hash that did not yet exist.
// It is unrepresentable, not merely invalid — there is no graph walk here, in
// M1 or ever. But nothing stops a producer fabricating an edge to ITSELF with
// a syntactically valid hash, so that case is checked.
func TestI6_SelfEdgeRejected(t *testing.T) {
	p := newTestRecord()
	e := dataEdge(p.RecordID, "aa", DerivedFrom, "/execution_result", `"APPROVED"`)
	p.Provenance.Upstream = []UpstreamEdge{e}
	bindCausalityForTest(p)
	mustFire(t, p, "provenance.upstream[0].record_id")
}

// =============================================================================
// I7(a) — SELECTED_FROM requires >=1 CONSIDERED_ALTERNATIVE
// =============================================================================

// TestI7_SelectedFromRequiresAlternative pins the draft-4 tightening. Zero
// alternatives alongside a claimed selection is a cherry-picking lie that reads
// as diligence: it asserts a choice while withholding what it was chosen over,
// and nothing local could distinguish it from an honest single-candidate run.
func TestI7_SelectedFromRequiresAlternative(t *testing.T) {
	t.Run("SELECTED_FROM alone is rejected", func(t *testing.T) {
		p := withUpstream(t, dataEdge(parentA, "aa", SelectedFrom, "/execution_result", `"APPROVED"`))
		mustFire(t, p, "provenance.upstream")
	})

	t.Run("SELECTED_FROM with an alternative is accepted", func(t *testing.T) {
		p := withUpstream(t,
			dataEdge(parentA, "aa", SelectedFrom, "/execution_result", `"APPROVED"`),
			dataEdge(parentB, "bb", ConsideredAlternative, "/execution_result", `"DENIED"`),
		)
		mustBeClean(t, p)
	})

	t.Run("an honest single-candidate consumption is DERIVED_FROM", func(t *testing.T) {
		p := withUpstream(t, dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`))
		mustBeClean(t, p)
	})
}

// =============================================================================
// I8(a) — the production floor, ordinal
// =============================================================================

func TestI8_OrdinalComparator(t *testing.T) {
	order := []RetentionClass{DevEphemeral, Short1Y, Standard7Y, Extended10Y, Permanent}
	for i, lo := range order {
		for j, hi := range order {
			want := j >= i
			if got := RetentionHorizonAtLeast(hi, lo); got != want {
				t.Errorf("RetentionHorizonAtLeast(%s, %s) = %v, want %v", hi, lo, got, want)
			}
		}
	}

	// A SHORT_1Y child under a DEV_EPHEMERAL parent must be forbidden: the
	// parent expires first, guaranteeing a dangling edge and an unverifiable
	// chain. This falls out of the ordinal rather than needing its own clause.
	if RetentionHorizonAtLeast(DevEphemeral, Short1Y) {
		t.Error("a DEV_EPHEMERAL parent must not satisfy a SHORT_1Y child's horizon")
	}

	// An unknown class has no position in the order. Guessing one would be the
	// silent bypass the fail-closed rule exists to prevent.
	if RetentionHorizonAtLeast(RetentionClass("FOREVER_PLUS"), Short1Y) {
		t.Error("an unknown retention class must not satisfy any horizon")
	}
}

// =============================================================================
// I9 — decisive-call binding
// =============================================================================

func TestI9_AmbiguousDecisiveSeq(t *testing.T) {
	p := newTestRecord()
	// Two entries claiming the same seq. (Contiguity fires too; the point is
	// that decisive_seq must not silently pick one.)
	p.ExecutionContext.LLMCalls[0].Seq = 2
	mustFire(t, p, "execution_context.decisive_seq")
}

// TestI9_DecisiveCallMustBeOK (§3.4.1) — you cannot designate a failed attempt
// as the decision. The fixture's seq=1 is a TIMEOUT with no output; naming it
// would bind field 14 to a sentinel and claim a verdict came from a call that
// never returned one.
func TestI9_DecisiveCallMustBeOK(t *testing.T) {
	p := newTestRecord()
	mustBeClean(t, p)
	if p.ExecutionContext.LLMCalls[0].Status != AttemptStatusTimeout {
		t.Fatal("fixture no longer carries a failed attempt; this test is vacuous")
	}
	p.ExecutionContext.DecisiveSeq = 1 // the TIMEOUT attempt
	mustFire(t, p, "execution_context.decisive_seq")
}

// =============================================================================
// I10 — edge uniqueness / §4.3 sort order
// =============================================================================

func TestI10_DuplicateEdgeRejected(t *testing.T) {
	e := dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`)
	p := withUpstream(t, e, e)
	mustFire(t, p, "provenance.upstream[1]")
}

// TestI10_SameParentDifferentRelationshipIsLegal — §3.6 explicitly permits a
// node that both DERIVED_FROM and VALIDATES the same parent field. The
// uniqueness key is the TRIPLE, not the pair; a check on (hash, selector) alone
// would reject a conformant artifact.
func TestI10_SameParentDifferentRelationshipIsLegal(t *testing.T) {
	p := withUpstream(t,
		dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`),
		dataEdge(parentA, "aa", Validates, "/execution_result", `"APPROVED"`),
	)
	mustBeClean(t, p)
}

func TestSortOrder_UnsortedUpstreamRejected(t *testing.T) {
	a := dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`)
	b := dataEdge(parentB, "bb", DerivedFrom, "/execution_result", `"DENIED"`)
	p := newTestRecord()
	// Deliberately reversed: "bb" sorts after "aa".
	p.Provenance.Upstream = []UpstreamEdge{b, a}
	bindCausalityForTest(p)
	mustFire(t, p, "provenance.upstream")

	// And the sorted arrangement is clean — proving the test above failed for
	// the ordering, not for some unrelated defect in the edges.
	p2 := withUpstream(t, b, a)
	mustBeClean(t, p2)
}

// =============================================================================
// §4.1 — selector grammar; §3.2.1 — control/data split
// =============================================================================

func TestSelectorGrammar(t *testing.T) {
	cases := []struct {
		sel string
		ok  bool
	}{
		{"/execution_result", true},
		{"/output_pre_postprocess", true},
		{"", true},                    // control-only sentinel
		{"/a~1b", true},               // "/" escaped as ~1
		{"/a~0b", true},               // "~" escaped as ~0
		{"execution_result", false},   // missing leading /
		{"/", false},                  // empty segment
		{"/a/b", false},               // multi-segment: reserved in v1
		{"#/execution_result", false}, // URI form: non-URI required
		{"/a~", false},                // dangling escape
		{"/a~2b", false},              // invalid escape
	}
	for _, tc := range cases {
		if got := IsValidSelector(tc.sel); got != tc.ok {
			t.Errorf("IsValidSelector(%q) = %v, want %v", tc.sel, got, tc.ok)
		}
	}
}

func TestControlDataSplit(t *testing.T) {
	t.Run("control edge with a selector is rejected", func(t *testing.T) {
		e := controlEdge(parentA, "aa", Approves)
		e.ConsumedOutputSelector = "/execution_result"
		p := withUpstream(t, e)
		mustFire(t, p, "provenance.upstream[0].consumed_output_selector")
	})
	t.Run("control edge with a real hash is rejected", func(t *testing.T) {
		e := controlEdge(parentA, "aa", Approves)
		e.ConsumedOutputHash = hex64("ab")
		p := withUpstream(t, e)
		mustFire(t, p, "provenance.upstream[0].consumed_output_hash")
	})
	t.Run("data edge with an empty selector is rejected", func(t *testing.T) {
		e := dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`)
		e.ConsumedOutputSelector = ""
		p := withUpstream(t, e)
		mustFire(t, p, "provenance.upstream[0].consumed_output_selector")
	})
	t.Run("data edge carrying the absent-value sentinel is rejected", func(t *testing.T) {
		e := dataEdge(parentA, "aa", DerivedFrom, "/execution_result", `"APPROVED"`)
		e.ConsumedOutputHash = ZeroHash64
		p := withUpstream(t, e)
		mustFire(t, p, "provenance.upstream[0].consumed_output_hash")
	})
	t.Run("a well-formed control edge is accepted", func(t *testing.T) {
		p := withUpstream(t, controlEdge(parentA, "aa", Approves))
		mustBeClean(t, p)
	})
}

// =============================================================================
// I12 — kind conformance
// =============================================================================

func nonModelFixture(t *testing.T, kind DecisionKind) *Record {
	t.Helper()
	p := newTestRecord()
	p.DecisionKind = kind
	p.PrincipalIdentity = humanPrincipal
	if kind == ToolExecution {
		p.PrincipalIdentity = "tool:payments-api"
	}
	p.ModelVersionHash = ZeroHash64
	p.ModelProvider = NoneSentinel
	p.ModelName = NoneSentinel
	p.ExecutionContext.LLMCalls = []LLMCall{}
	p.ExecutionContext.DecisiveSeq = 0
	// A non-model node did no retrieval in this fixture, so the RAG bundle
	// must be empty too — its entries link to retrievals[].
	p.RAGEvidenceBundle = []RAGEvidenceEntry{}
	p.ExecutionContext.Retrievals = []Retrieval{}
	bindCausalityForTest(p)
	return p
}

func TestI12_NonModelKindsRequireSentinels(t *testing.T) {
	for _, kind := range []DecisionKind{HumanDecision, ToolExecution} {
		t.Run(string(kind), func(t *testing.T) {
			base := nonModelFixture(t, kind)
			mustBeClean(t, base)

			cases := []struct {
				name   string
				break_ func(*Record)
				field  string
			}{
				{"real model_version_hash", func(p *Record) { p.ModelVersionHash = hex64("ab") }, "model_version_hash"},
				{"real model_provider", func(p *Record) { p.ModelProvider = "openai" }, "model_provider"},
				{"real model_name", func(p *Record) { p.ModelName = "gpt-4o" }, "model_name"},
				{"non-empty llm_calls", func(p *Record) {
					p.ExecutionContext.LLMCalls = newTestRecord().ExecutionContext.LLMCalls
				}, "execution_context.llm_calls"},
				{"non-zero decisive_seq", func(p *Record) { p.ExecutionContext.DecisiveSeq = 1 }, "execution_context.decisive_seq"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					p := nonModelFixture(t, kind)
					tc.break_(p)
					mustFire(t, p, tc.field)
				})
			}
		})
	}
}

func TestI12_ModelKindRejectsSentinels(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*Record)
		field  string
	}{
		{"sentinel model_version_hash", func(p *Record) { p.ModelVersionHash = ZeroHash64 }, "model_version_hash"},
		{"NONE provider", func(p *Record) { p.ModelProvider = NoneSentinel }, "model_provider"},
		{"NONE name", func(p *Record) { p.ModelName = NoneSentinel }, "model_name"},
		{"empty llm_calls", func(p *Record) { p.ExecutionContext.LLMCalls = []LLMCall{} }, "execution_context.llm_calls"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestRecord()
			tc.break_(p)
			mustFire(t, p, tc.field)
		})
	}
}

// =============================================================================
// I13 — attempt completeness (the locally decidable slice)
// =============================================================================

// TestI13_AttemptSentinels pins BOTH directions of §3.4.1's status rule.
//
// The converse matters as much as the forward rule: "status OK, output_hash
// 0…0" is a contradiction the artifact makes about itself, and it is the shape
// a producer lands on by copying a failure branch. A forward-only check would
// let it validate.
func TestI13_AttemptSentinels(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*Record)
		field  string
	}{
		{"invalid llm status", func(p *Record) {
			p.ExecutionContext.LLMCalls[1].Status = "SUCCESS"
		}, "execution_context.llm_calls[1].status"},
		{"failed attempt carrying a real output_hash", func(p *Record) {
			p.ExecutionContext.LLMCalls[0].OutputHash = hex64("ab")
		}, "execution_context.llm_calls[0].output_hash"},
		{"failed attempt carrying a real finish_reason", func(p *Record) {
			p.ExecutionContext.LLMCalls[0].FinishReason = "stop"
		}, "execution_context.llm_calls[0].finish_reason"},
		// These two use an AUXILIARY (non-decisive) OK call on purpose.
		// Mutating the decisive call would also trip I9's prompt/output
		// binding, so the test would still pass with I13's converse deleted —
		// it would be measuring I9 while claiming to measure I13. On an
		// auxiliary call, I13 is the SOLE detector, which is the whole point:
		// §3.4 explicitly contemplates post-verdict calls (output guardrails,
		// rewriters) that carry a higher seq and are covered by nothing else.
		{"auxiliary OK attempt carrying the no-output sentinel", func(p *Record) {
			aux := auxOKCall(3)
			aux.OutputHash = ZeroHash64
			p.ExecutionContext.LLMCalls = append(p.ExecutionContext.LLMCalls, aux)
		}, "execution_context.llm_calls[2].output_hash"},
		{"auxiliary OK attempt carrying the NONE finish_reason", func(p *Record) {
			aux := auxOKCall(3)
			aux.FinishReason = FinishReasonNone
			p.ExecutionContext.LLMCalls = append(p.ExecutionContext.LLMCalls, aux)
		}, "execution_context.llm_calls[2].finish_reason"},
		{"invalid tool status", func(p *Record) {
			p.ToolCallLog[0].Status = "success"
		}, "tool_call_log[0].status"},
		{"failed tool call with a real output_hash", func(p *Record) {
			p.ToolCallLog[0].Status = AttemptStatusError
		}, "tool_call_log[0].output_hash"},
		{"invalid retrieval status", func(p *Record) {
			p.ExecutionContext.Retrievals[0].Status = "done"
		}, "execution_context.retrievals[0].status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestRecord()
			mustBeClean(t, p)
			tc.break_(p)
			mustFire(t, p, tc.field)
		})
	}
}

// auxOKCall builds a well-formed OK model call at the given seq — an
// AUXILIARY call, i.e. one that runs after the verdict (§3.4: output
// guardrails, rewriters). It is not the decisive call and I9 does not look at
// it, so it is the honest place to test I13's rules in isolation.
func auxOKCall(seq int) LLMCall {
	return LLMCall{
		Seq:           seq,
		ModelProvider: "openai",
		ModelName:     "gpt-4-turbo-2024-04-09",
		Params: LLMCallParams{
			Temperature: ptr(0.0), TopP: nil, Seed: nil,
			MaxTokens: ptr(int64(256)), ResponseSchemaHash: ZeroHash64,
		},
		Status:       AttemptStatusOK,
		PromptHash:   HashSHA3256([]byte("rewrite the rationale for the customer")),
		OutputHash:   HashSHA3256([]byte("Your application was approved.")),
		FinishReason: "stop",
		StartedAt:    "2026-04-20T14:30:02.000Z",
		EndedAt:      "2026-04-20T14:30:02.400Z",
	}
}

// TestI13_AuxiliaryCallDoesNotBecomeDecisive — §3.4: a call that runs AFTER
// the verdict does not become "decisive" by carrying a higher seq. This is why
// decisive_seq exists at all instead of "the last call wins".
func TestI13_AuxiliaryCallDoesNotBecomeDecisive(t *testing.T) {
	p := newTestRecord()
	p.ExecutionContext.LLMCalls = append(p.ExecutionContext.LLMCalls, auxOKCall(3))
	// decisive_seq still names seq 2; the artifact stays valid.
	mustBeClean(t, p)
	if p.ExecutionContext.DecisiveSeq != 2 {
		t.Fatal("fixture's decisive_seq moved; this test no longer proves position does not decide")
	}
}

// TestI13_SeqContiguity — a gap is how a removed attempt shows, when the
// producer forgets to renumber. Weak (renumbering defeats it) but free, and
// §5's stated limit is explicit that omission itself is not locally detectable.
func TestI13_SeqContiguity(t *testing.T) {
	t.Run("llm_calls gap", func(t *testing.T) {
		p := newTestRecord()
		p.ExecutionContext.LLMCalls[1].Seq = 3 // 1, 3 — attempt 2 vanished
		p.ExecutionContext.DecisiveSeq = 3
		mustFire(t, p, "execution_context.llm_calls[1].seq")
	})
	t.Run("tool_call_log gap", func(t *testing.T) {
		p := newTestRecord()
		p.ToolCallLog[1].Seq = 5
		mustFire(t, p, "tool_call_log[1].seq")
	})
	t.Run("retrievals not 1-based", func(t *testing.T) {
		p := newTestRecord()
		p.ExecutionContext.Retrievals[0].Seq = 0
		p.RAGEvidenceBundle[0].RetrievalSeq = 0
		mustFire(t, p, "execution_context.retrievals[0].seq")
	})
}

// TestI13_RAGEntryRequiresOKRetrieval — a document cannot come from a
// retrieval that failed. Locally decidable contradiction; same rule and reason
// as I9's "the decisive call must be OK".
func TestI13_RAGEntryRequiresOKRetrieval(t *testing.T) {
	p := newTestRecord()
	mustBeClean(t, p)
	p.ExecutionContext.Retrievals[0].Status = AttemptStatusError
	mustFire(t, p, "rag_evidence_bundle[0].retrieval_seq")
}

// TestRAGRetrievalSeqMustResolve — a dangling link is not a link (§3.1.1).
func TestRAGRetrievalSeqMustResolve(t *testing.T) {
	p := newTestRecord()
	p.RAGEvidenceBundle[0].RetrievalSeq = 42
	mustFire(t, p, "rag_evidence_bundle[0].retrieval_seq")
}

// =============================================================================
// §4.10 — params typing (the cross-language determinism traps)
// =============================================================================

// TestParamsTyping_SeedIsDecimalString pins the seed trap. A 64-bit seed
// exceeds JCS's ±(2^53-1) safe window, so a NUMERIC seed would be rejected at
// canonicalization or silently rounded to a DIFFERENT value in a different
// language — and the record_hash contract rests on Go and Python agreeing
// byte-for-byte.
func TestParamsNullability_KeysAlwaysPresent(t *testing.T) {
	p := newTestRecord()
	raw, err := json.Marshal(p.ExecutionContext.LLMCalls[1].Params)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"temperature", "top_p", "seed", "max_tokens", "response_schema_hash"} {
		if _, present := m[k]; !present {
			t.Errorf("llm_calls[].params key %q absent; §4.11 fixes the key set", k)
		}
	}
	if len(m) != 5 {
		t.Errorf("params key count = %d, want 5 (§4.11 freezes the set with the envelope version)", len(m))
	}
	if v, ok := m["top_p"]; !ok || v != nil {
		t.Errorf("top_p = %v; an unset param must serialize as null, not vanish", v)
	}

	rp, err := json.Marshal(p.ExecutionContext.Retrievals[0].Params)
	if err != nil {
		t.Fatal(err)
	}
	var rm map[string]interface{}
	if err := json.Unmarshal(rp, &rm); err != nil {
		t.Fatal(err)
	}
	if len(rm) != 4 {
		t.Errorf("retrievals[].params key count = %d, want 4 (§4.11)", len(rm))
	}
}

// =============================================================================
// I14 — oversight-mode conformance (local slice)
// =============================================================================

// TestI14_PreAuthorizedRequiresAuthorizingEdge pins the ONE locally decidable
// slice of I14 (§3.3.1).
//
// PRE_AUTHORIZED is checkable precisely because its authorization is in the
// PAST — a pre-existing artifact is exactly what a backward edge can commit to.
// A PRE_AUTHORIZED node with no TRIGGERED_BY edge references no authorization
// at all, which the artifact states about itself.
func sortEdges(edges []UpstreamEdge) []UpstreamEdge {
	out := append([]UpstreamEdge(nil), edges...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RecordHash != out[j].RecordHash {
			return out[i].RecordHash < out[j].RecordHash
		}
		if out[i].ConsumedOutputSelector != out[j].ConsumedOutputSelector {
			return out[i].ConsumedOutputSelector < out[j].ConsumedOutputSelector
		}
		return string(out[i].Relationship) < string(out[j].Relationship)
	})
	return out
}

// mustFire asserts that some issue names the given field path.
func mustFire(t *testing.T, p *Record, field string) {
	t.Helper()
	issues := p.ValidateFields(mustCausalityForTest(p))
	if !containsString(issues, field) {
		t.Fatalf("expected an issue naming %q; got %v", field, issues)
	}
}

// TestParamsNullability_KeysAlwaysPresent — §4.10/§4.11: the key SET is fixed,
// and a key the provider did not set is JSON null. null means "not set by this
// call", which is a FACT worth signing — not an optional field. omitempty here
// would erase the difference between "temperature 0" and "temperature unset".
