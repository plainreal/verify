// A valid TIER-A record for tests, built without a key.
//
// Derived from core.NewTestRecord. It exists here because this package's tests
// need a record to mutate and validate, and building one needs no signing.
// That is the point: if constructing a fixture required the sealer, the
// verification tests could not live beside the verification code, and the
// published package would ship without them.
//
// Test-only, so none of this is compiled into the CLI.
package verifycore

import (
	"encoding/json"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func bindCausalityForTest(p *Record) {
	provBytes, err := json.Marshal(&p.Provenance)
	if err != nil {
		panic("verifycore: bindCausalityForTest: marshal: " + err.Error())
	}
	canonical, err := CanonicalizeJSON(provBytes)
	if err != nil {
		panic("verifycore: bindCausalityForTest: canonicalize: " + err.Error())
	}
	p.CausalityChainHash = HashSHA3256(canonical)
}

// causalityFromStructForTest is I3's digest computed from a typed Provenance.
//
// The PRODUCER path (core.ComputeCausalityChainHash) is deliberately absent
// from this package. Tests that construct provenance in Go rather than reading
// bytes need the same digest to assert against, so they compute it here.
func causalityFromStructForTest(pr *Provenance) (string, error) {
	b, err := json.Marshal(pr)
	if err != nil {
		return "", err
	}
	canonical, err := CanonicalizeJSON(b)
	if err != nil {
		return "", err
	}
	return HashSHA3256(canonical), nil
}

// mustBeClean fails unless the record validates. Guards the NEGATIVE tests:
// if a fixture were already dirty, an "invariant fires" assertion could pass
// for the wrong reason and prove nothing.
func mustBeClean(t *testing.T, p *Record) {
	t.Helper()
	if issues := p.ValidateFields(mustCausalityForTest(p)); len(issues) != 0 {
		t.Fatalf("fixture is not clean before mutation: %v", issues)
	}
}

// mustCausalityForTest returns the I3 digest and error a validation call needs,
// computed the way this package can: from the struct, without a producer.
func mustCausalityForTest(p *Record) (string, error) {
	return causalityFromStructForTest(&p.Provenance)
}

func newTestRecord() *Record {
	const (
		id     = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
		prompt = "You are a credit scoring agent. Evaluate the following application..."
		output = "Based on the application data, the credit score is 720; recommendation is APPROVE."

		provider = "openai"
		model    = "gpt-4-turbo-2024-04-09"
	)

	p := &Record{
		RecordID:             id,
		RecordVersion:        RecordVersion,
		CreatedAt:            "2026-04-20T14:30:00.000000000Z",
		EvidenceTier:         TierA,
		DecisionKind:         ModelDecision,
		PrincipalIdentity:    "agent:credit-scoring-v2",
		ActionType:           "credit_decision",
		InputHash:            HashSHA3256([]byte("test-input-data")),
		AuthorizationTokenID: "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
		FullPromptSnapshot:   prompt,
		RAGEvidenceBundle: []RAGEvidenceEntry{{
			Source:       "policy://credit/v2",
			Content:      "Credit score threshold is 650",
			Score:        0.873,
			Cached:       false,
			DocID:        "credit-policy-2024",
			DocVersion:   "v2",
			RetrievalSeq: 1, // resolves to ExecutionContext.Retrievals[0].Seq
		}},
		// §3.1 field 11 — the model IDENTITY tuple, JCS-canonical (keys sorted),
		// not a hash of weights.
		ModelVersionHash: HashSHA3256([]byte(
			`{"model_name":"` + model + `","provider":"` + provider + `","served_version":"` + model + `"}`)),
		ModelProvider:        provider,
		ModelName:            model,
		OutputPrePostprocess: output,
		ExecutionResult:      "APPROVED",
		ToolCallLog: []ToolCallEntry{
			{
				Tool: "credit_api", ToolVersion: "2.3.0", Seq: 1,
				StartedAt: "2026-04-20T14:30:01.123Z", EndedAt: "2026-04-20T14:30:01.298Z",
				Status:     AttemptStatusOK,
				InputHash:  HashSHA3256([]byte(`{"applicant_id":"A-4471"}`)),
				OutputHash: HashSHA3256([]byte(`{"score":720}`)),
			},
			{
				Tool: "risk_model", ToolVersion: "1.0.4", Seq: 2,
				StartedAt: "2026-04-20T14:30:01.456Z", EndedAt: "2026-04-20T14:30:01.702Z",
				Status:     AttemptStatusOK,
				InputHash:  HashSHA3256([]byte(`{"score":720}`)),
				OutputHash: HashSHA3256([]byte(`{"risk":"LOW"}`)),
			},
		},
		// CausalityChainHash is bound below, from provenance (§3.5).
		PolicyVersionHash:        HashSHA3256([]byte("plainreal-policy-v1")),
		AvailabilityPolicy:       BlockOnServiceUnavailable,
		DeploymentMode:           SaaSManaged,
		SDKHashLayer:             ServiceEndpoint,
		SDKBinarySHA3:            HashSHA3256([]byte("plainreal-sdk-python-0.1.0")),
		RegistryValidationStatus: RegistryValidated,
		// §4.5 grammar: 64 lowercase hex, no prefix. Seal overwrites.
		SigningKeyID:              strings.Repeat("ab", 32),
		LockVerificationLatencyMs: 47,
		InstrumentationCoverage:   1.0,
		CaptureLayer:              BusinessLayerCapture,
		Consequential:             true,

		// --- Field 30: an ad-hoc ROOT (§4.4 ad-hoc defaults; upstream []) ---
		Provenance: Provenance{
			SchemaVersion:          EnvelopeSchemaVersion,
			WorkflowID:             AdhocWorkflowID,
			WorkflowRunID:          "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
			WorkflowNodeID:         id, // ad-hoc: echoes record_id
			WorkflowDefinitionHash: ZeroHash64,
			Upstream:               []UpstreamEdge{},
		},

		// --- Field 31 ---
		GovernanceContext: GovernanceContext{
			SchemaVersion:    EnvelopeSchemaVersion,
			OversightMode:    SolelyAutomated,
			AccountableParty: "org:acme-lending",
			DataSubjectRefs:  []string{},
			TenantID:         "tenant:acme",
			RetentionClass:   Standard7Y,
			Environment:      EnvProd,
			CorrelationIDs:   []string{"case:CRM-88213"},
		},

		// --- Field 32 ---
		ExecutionContext: ExecutionContext{
			SchemaVersion: EnvelopeSchemaVersion,
			AgentVersion:  "credit-adjudicator@1.4.2",
			DecisiveSeq:   2, // the OK attempt; §3.4.1 forbids naming a failed one
			// Two attempts: the first TIMED OUT, the second succeeded and is
			// the decisive one (§3.4.1). The fixture carries a real retry on
			// purpose — a happy-path-only fixture would let the I13 sentinel
			// rules rot untested, and the retry is the case the schema change
			// exists for.
			LLMCalls: []LLMCall{
				{
					Seq:           1,
					ModelProvider: provider,
					ModelName:     model,
					Params: LLMCallParams{
						Temperature:        ptr(0.0),
						TopP:               nil,
						Seed:               nil,
						MaxTokens:          ptr(int64(1024)),
						ResponseSchemaHash: ZeroHash64,
					},
					Status: AttemptStatusTimeout,
					// The prompt is REAL even on a failed attempt — it is
					// exactly what an examiner wants to see.
					PromptHash: HashSHA3256([]byte(prompt)),
					// No output to hash, no provider finish_reason (§4.4).
					OutputHash:   ZeroHash64,
					FinishReason: FinishReasonNone,
					StartedAt:    "2026-04-20T14:30:00.100Z",
					EndedAt:      "2026-04-20T14:30:00.700Z",
				},
				{
					Seq:           2,
					ModelProvider: provider,
					ModelName:     model,
					Params: LLMCallParams{
						Temperature: ptr(0.0),
						TopP:        nil, // not set by this call — a fact, hence null
						Seed:        nil,
						MaxTokens:   ptr(int64(1024)),
						// No structured-output schema on this call.
						ResponseSchemaHash: ZeroHash64,
					},
					Status: AttemptStatusOK,
					// I9: the decisive call's hashes bind fields 9 and 14 (§4.2
					// — SHA3-256 over the UTF-8 bytes of the stored string).
					PromptHash:   HashSHA3256([]byte(prompt)),
					OutputHash:   HashSHA3256([]byte(output)),
					FinishReason: "stop",
					StartedAt:    "2026-04-20T14:30:00.800Z",
					EndedAt:      "2026-04-20T14:30:01.900Z",
				},
			},
			Retrievals: []Retrieval{{
				Seq:            1,
				QueryHash:      HashSHA3256([]byte("credit score threshold policy")),
				IndexID:        "lending_policy_v1",
				IndexVersion:   "v1",
				EmbeddingModel: "lexical-overlap@1",
				Status:         AttemptStatusOK,
				Params: RetrievalParams{
					TopK:        ptr(int64(6)),
					MinScore:    ptr(0.15),
					FiltersHash: ZeroHash64,
					Reranker:    "none",
				},
			}},
			Guardrails: []Guardrail{{
				Name: "pii-scrubber", Version: "2.1",
				Stage: GuardrailStageInput, Verdict: GuardrailPass,
			}},
		},
	}

	// §3.5 build order: provenance is complete, so bind causality. Seal would
	// do this itself; doing it here keeps the fixture ValidateTierA-clean
	// without a Seal.
	// Bind causality inline rather than via core.BindCausality. This package
	// deliberately has no producer path, and I3 is one canonicalization and one
	// hash, both of which live here because a verifier has to recompute exactly
	// this to check the binding.
	provBytes, mErr := json.Marshal(&p.Provenance)
	if mErr != nil {
		panic("verifycore: newTestRecord: marshal provenance: " + mErr.Error())
	}
	canonical, cErr := CanonicalizeJSON(provBytes)
	if cErr != nil {
		panic("verifycore: newTestRecord: canonicalize provenance: " + cErr.Error())
	}
	p.CausalityChainHash = HashSHA3256(canonical)
	return p
}
