// The record schema (spec section 3): types, enums and their validators.
//
// agent_input (AgentInput, UpstreamOutput, ParseAgentInput) is deliberately NOT
// here. It is the substrate's input to I1, which needs a bundle a Level-0
// verifier does not hold, so it stays in core alongside ValidateI1.
package verifycore

// =============================================================================

const (
	// ZeroHash64 is the defined sentinel for an absent hash: 64 lowercase
	// zeros. Used by workflow_definition_hash (ad-hoc runs), a control edge's
	// consumed_output_hash, response_schema_hash / filters_hash (N/A), and
	// model_version_hash on non-model kinds.
	ZeroHash64 = "0000000000000000000000000000000000000000000000000000000000000000"

	// NoneSentinel is the defined sentinel for model_provider / model_name on
	// non-MODEL decision kinds (§4.4). Not "", not null — "NONE" is an
	// assertion that the field does not apply, which is a fact worth signing.
	NoneSentinel = "NONE"

	// AdhocWorkflowID is workflow_id's value for a run with no declared DAG
	// (§4.4). Such a run also carries workflow_definition_hash = ZeroHash64 and
	// workflow_node_id = its own record_id.
	AdhocWorkflowID = "adhoc"
)

// =============================================================================
// decision_kind (§3.0) — the node-type discriminator, field 33.
// =============================================================================

// DecisionKind governs how the model-facet fields (9, 11–14) and I9 are
// populated. The first adversarial gate proved a single undifferentiated shape
// was unsatisfiable for non-model decision nodes: a human approval has no
// model_name, and a sentinel-free schema forced producers to either lie or omit.
// This discriminator closes that hole.
type DecisionKind string

const (
	// ModelDecision — an AI agent's decision arising from >=1 model call.
	// principal_identity is prefixed "agent:". I9 applies.
	ModelDecision DecisionKind = "MODEL_DECISION"

	// HumanDecision — a human approval / override / sign-off.
	// principal_identity is prefixed "human:" and is PSEUDONYMOUS (§3.1 field
	// 5): a salted ref, never a raw identity.
	HumanDecision DecisionKind = "HUMAN_DECISION"

	// ToolExecution — a side-effecting action actually carried out (moved
	// money, sent a message, wrote a record). Its own node, never inline in a
	// tool_call_log (§9). principal_identity is prefixed "agent:" or "tool:".
	ToolExecution DecisionKind = "TOOL_EXECUTION"
)

// IsValidDecisionKind reports whether k is one of the three closed values.
func IsValidDecisionKind(k DecisionKind) bool {
	return k == ModelDecision || k == HumanDecision || k == ToolExecution
}

// IsModelKind reports whether the kind carries model facets (fields 11–14
// populated, llm_calls non-empty, I9 applied). Only MODEL_DECISION does.
func IsModelKind(k DecisionKind) bool { return k == ModelDecision }

// principalPrefixes returns the permitted principal_identity prefixes for a
// kind (§3.0 table). I12 enforces these.
func principalPrefixes(k DecisionKind) []string {
	switch k {
	case ModelDecision:
		return []string{"agent:"}
	case HumanDecision:
		return []string{"human:"}
	case ToolExecution:
		return []string{"agent:", "tool:"}
	default:
		return nil
	}
}

// =============================================================================
// relationship (§3.2.1) — closed enum of 10, direction convention FIXED.
// =============================================================================

// Relationship is the edge type. EVERY edge reads:
//
//	"THIS node <relationship> the PARENT."
//
// The direction convention is fixed and load-bearing — reversing it silently
// inverts the meaning of every chain in the system.
type Relationship string

const (
	// --- Data edges: this node consumed something from the parent. Each has a
	// non-empty consumed_output_selector and a real consumed_output_hash, and
	// each has a corresponding upstream_outputs entry in agent_input (§3.6).
	DerivedFrom           Relationship = "DERIVED_FROM"           // consumed the parent's output
	Aggregates            Relationship = "AGGREGATES"             // combined this parent with siblings (all used)
	Validates             Relationship = "VALIDATES"              // checked / scored the parent
	SelectedFrom          Relationship = "SELECTED_FROM"          // chose this parent as the winner (from >=2 candidates)
	ConsideredAlternative Relationship = "CONSIDERED_ALTERNATIVE" // evaluated this parent and did NOT choose it

	// --- Control edges: causal, but no data consumed. Each carries
	// consumed_output_selector "" + consumed_output_hash ZeroHash64, and has NO
	// upstream_outputs entry (§3.6) — there is nothing to bind.
	Approves    Relationship = "APPROVES"     // (human/authority) approves the parent decision
	Revises     Relationship = "REVISES"      // supersedes the parent with a correction
	Retracts    Relationship = "RETRACTS"     // withdraws the parent's decision
	TriggeredBy Relationship = "TRIGGERED_BY" // was caused by the parent (sub-workflow root)
	Executes    Relationship = "EXECUTES"     // (TOOL_EXECUTION) carried out what the parent authorized
)

// IsValidRelationship reports whether r is in the 10-value enum (I2).
func IsValidRelationship(r Relationship) bool {
	switch r {
	case DerivedFrom, Aggregates, Validates, SelectedFrom, ConsideredAlternative,
		Approves, Revises, Retracts, TriggeredBy, Executes:
		return true
	}
	return false
}

// IsControlEdge reports whether r is a control (no-data) relationship.
//
// This predicate decides three things at once, so it is written as an explicit
// allowlist rather than "not a data edge": whether the edge must carry the
// empty selector + sentinel hash (§3.2.1), whether it participates in I1's
// upstream_outputs correspondence (§3.6), and whether the substrate recomputes
// a consumed value for it. A new enum value therefore fails closed — it is
// neither a valid relationship (I2 rejects it) nor silently treated as control.
func IsControlEdge(r Relationship) bool {
	switch r {
	case Approves, Revises, Retracts, TriggeredBy, Executes:
		return true
	}
	return false
}

// =============================================================================
// retention_class (§4.8) — the SOURCE of the applied lock, ordered enum.
// =============================================================================

// RetentionClass declares the artifact's retention horizon AND is the input the
// substrate derives the S3 Object Lock period from (§4.8). The direction is
// normative: the class is not a label describing a duration chosen elsewhere.
//
// This inversion is what makes a mislabeled artifact structurally impossible
// rather than merely detectable — a producer cannot apply a duration its
// declared class did not specify, because the class IS the input. The equality
// check thereby degrades from a lie detector to a bug detector, which is what an
// invariant should be.
type RetentionClass string

const (
	// DevEphemeral — dev / CI / demo. Operator-configured duration, MUST be
	// < 24h (bounded at WORMService construction). NOT retention-bearing
	// evidence. It exists so the dev path can declare what was ACTUALLY
	// applied: without it, a sub-day lock had no honest label and the producer
	// had to misstate its retention. An environment-gated exemption was
	// rejected instead — a check the subject can opt out of is not a check.
	DevEphemeral RetentionClass = "DEV_EPHEMERAL"

	Short1Y     RetentionClass = "SHORT_1Y"     // 365 days
	Standard7Y  RetentionClass = "STANDARD_7Y"  // 2555 days — regulatory default
	Extended10Y RetentionClass = "EXTENDED_10Y" // 3653 days
	// Permanent — Object Lock requires a finite RetainUntilDate; 36525 days
	// (100y) is its representation of "permanent".
	Permanent RetentionClass = "PERMANENT"
)

// Lock periods in days, derived from the class (§4.8 table). DevEphemeral has
// no entry — its duration is the operator's bounded (<24h) knob.
const (
	Short1YDays     = 365
	Standard7YDays  = 2555
	Extended10YDays = 3653
	PermanentDays   = 36525
)

// retentionOrdinals is the total order of §4.8:
//
//	DEV_EPHEMERAL < SHORT_1Y < STANDARD_7Y < EXTENDED_10Y < PERMANENT
var retentionOrdinals = map[RetentionClass]int{
	DevEphemeral: 0,
	Short1Y:      1,
	Standard7Y:   2,
	Extended10Y:  3,
	Permanent:    4,
}

// IsValidRetentionClass reports whether rc is in the closed enum.
func IsValidRetentionClass(rc RetentionClass) bool {
	_, ok := retentionOrdinals[rc]
	return ok
}

// RetentionOrdinal returns the class's position in §4.8's total order, and
// false if rc is not a member. I8's horizon comparison rides on this ordinal
// rather than on durations, so a future class slots in by position.
func RetentionOrdinal(rc RetentionClass) (int, bool) {
	o, ok := retentionOrdinals[rc]
	return o, ok
}

// RetentionHorizonAtLeast reports whether class a's horizon is >= class b's.
//
// This is I8's comparator. Its cross-artifact use (parent horizon >= every
// child's) lands in M3, when parents exist to compare against; M1 uses it for
// the local PROD floor. Returns false if either class is not a member — an
// unknown class has no position in the order, and guessing one would be the
// silent bypass the fail-closed rule exists to prevent.
func RetentionHorizonAtLeast(a, b RetentionClass) bool {
	oa, oka := RetentionOrdinal(a)
	ob, okb := RetentionOrdinal(b)
	if !oka || !okb {
		return false
	}
	return oa >= ob
}

// =============================================================================
// governance_context enums (§3.3)
// =============================================================================

// OversightMode records the human-oversight posture in force (§3.3).
type OversightMode string

const (
	SolelyAutomated OversightMode = "SOLELY_AUTOMATED"
	HumanInTheLoop  OversightMode = "HUMAN_IN_THE_LOOP"
	HumanOnTheLoop  OversightMode = "HUMAN_ON_THE_LOOP"
	PreAuthorized   OversightMode = "PRE_AUTHORIZED"
)

// IsValidOversightMode reports whether m is in the closed enum.
func IsValidOversightMode(m OversightMode) bool {
	return m == SolelyAutomated || m == HumanInTheLoop || m == HumanOnTheLoop || m == PreAuthorized
}

// Environment is the execution environment (§3.3). Distinct from
// deployment_mode (field 20), which is the PlainReal hosting model.
type Environment string

const (
	EnvProd    Environment = "PROD"
	EnvStaging Environment = "STAGING"
	EnvTest    Environment = "TEST"
)

// IsValidEnvironment reports whether e is in the closed enum.
func IsValidEnvironment(e Environment) bool {
	return e == EnvProd || e == EnvStaging || e == EnvTest
}

// =============================================================================
// tool_call_log / guardrail enums (§3.1.2, §3.4)
// =============================================================================

// Attempt status (§3.4.1). Shared by tool_call_log[], llm_calls[], and
// retrievals[] — one enum, because they are the same fact: an attempt either
// produced an output or it did not.
//
// Every attempt is an entry, failures INCLUDED. Omitting a failed attempt is
// how "call the model five times and keep the flattering answer" would hide —
// the same cherry-picking hole I7 closes for racing candidates. decisive_seq
// (I9) then names which attempt was kept, so an examiner sees every attempt AND
// the choice.
const (
	AttemptStatusOK      = "OK"
	AttemptStatusError   = "ERROR"
	AttemptStatusTimeout = "TIMEOUT"

	// FinishReasonNone is finish_reason's sentinel on a non-OK llm_calls
	// attempt (§4.4): the provider never returned one, and "" would be
	// indistinguishable from a producer that forgot.
	FinishReasonNone = "NONE"
)

// IsValidAttemptStatus reports whether s is one of OK / ERROR / TIMEOUT.
func IsValidAttemptStatus(s string) bool {
	return s == AttemptStatusOK || s == AttemptStatusError || s == AttemptStatusTimeout
}

// execution_context.guardrails[] stages and verdicts (§3.4).
const (
	GuardrailStageInput  = "input"
	GuardrailStageOutput = "output"

	GuardrailPass     = "PASS"
	GuardrailModified = "MODIFIED"
	// GuardrailBlocked — RECORDED like any other verdict; it does NOT suppress
	// the record (§3.4.0). The decision was authorized (token matched) and it
	// executed (the model ran); a policy control intervened at the end. The
	// artifact is sealed with the verdict signed and execution_result recording
	// that no output was delivered.
	//
	// The rule: the fact always survives somewhere; what varies is whether it
	// earns a SIGNED ARTIFACT, and that turns on whether an AUTHORIZED DECISION
	// existed — not on whether the outcome was delivered. Contrast the
	// input-hash mismatch, which produces no artifact because no authorization
	// ever covered what occurred (the ledger still records it).
	//
	// An earlier draft had BLOCKED suppress the record. That was wrong twice
	// over: it made MODIFIED and BLOCKED arbitrarily different when both are
	// authorized executed decisions filtered at the end, and it opened an
	// evidence-deletion channel — no artifact means no evidence one was owed,
	// contradicting I13.
	GuardrailBlocked = "BLOCKED"
)

func isValidGuardrailStage(s string) bool {
	return s == GuardrailStageInput || s == GuardrailStageOutput
}

func isValidGuardrailVerdict(v string) bool {
	return v == GuardrailPass || v == GuardrailModified || v == GuardrailBlocked
}

// =============================================================================
// Field 30 — provenance (§3.2)
// =============================================================================

// UpstreamEdge is one BACKWARD edge to a parent (§3.2).
//
// Backward-only is a design invariant, not a convenience: a node commits its
// parents' hashes, and a parent's hash exists only once that parent is sealed.
// That is also why acyclicity needs no check — a cycle would require committing
// a hash that did not yet exist, which is unrepresentable (I6).
type UpstreamEdge struct {
	RecordID     string       `json:"record_id"`
	RecordHash   string       `json:"record_hash"`
	Relationship Relationship `json:"relationship"`

	// ConsumedOutputSelector is an RFC 6901 JSON Pointer (§4.1): non-URI,
	// single segment, addressing a TOP-LEVEL field of the parent record.
	// "" is reserved for control-only edges and means "no value consumed" —
	// never "whole document".
	ConsumedOutputSelector string `json:"consumed_output_selector"`

	// ConsumedOutputHash is SHA3-256 over the consumed value per §4.2, or
	// ZeroHash64 for a control edge. I1 binds this to agent_input.
	ConsumedOutputHash string `json:"consumed_output_hash"`

	// ParentSigningKeyID is the parent's Ed25519 public-key fingerprint,
	// same grammar as signing_key_id (§4.5). Level-1 verifies the parent's
	// signature through it.
	ParentSigningKeyID string `json:"parent_signing_key_id"`
}

// Provenance is field 30 — the workflow/causality envelope (§3.2).
// Versioned, always present, LENIENTLY parsed (§6).
type Provenance struct {
	SchemaVersion string `json:"schema_version"`

	// WorkflowID is the TEMPLATE id — an index concern, not integrity.
	// AdhocWorkflowID for a run with no declared DAG.
	WorkflowID string `json:"workflow_id"`

	// WorkflowRunID is the EXECUTION INSTANCE, SDK-minted (UUIDv4) at run
	// start. The substrate never mints one: the run instance is a fact the
	// server did not observe, and inventing it would be fabrication.
	WorkflowRunID string `json:"workflow_run_id"`

	// WorkflowNodeID is the vertex of the declared DAG this node IS.
	// Ad-hoc runs echo their own record_id.
	WorkflowNodeID string `json:"workflow_node_id"`

	// WorkflowDefinitionHash is SHA3-256(JCS(declared DAG)), or ZeroHash64 when
	// ad-hoc. The definition BODY is WORM-archived content-addressed (§8) so
	// this hash still resolves in year six.
	WorkflowDefinitionHash string `json:"workflow_definition_hash"`

	// Upstream holds the backward edges; [] for a root. TOTAL sort order per
	// §4.3, duplicate triples forbidden (I10). Both are enforced invariants —
	// a verifier rejects an unsorted array rather than sorting it, because
	// canonical order is part of what was signed.
	Upstream []UpstreamEdge `json:"upstream"`
}

// =============================================================================
// Field 31 — governance_context (§3.3)
// =============================================================================

// GovernanceContext is field 31 — the legal/organizational envelope (§3.3).
// Versioned, always present, leniently parsed.
//
// PII discipline (§2.5 / I4): every field here is an opaque identifier or a
// salted ref. Raw subject data lives only in the core capture fields
// (full_prompt_snapshot, rag_evidence_bundle[].content, output_pre_postprocess)
// — that is the evidence, not a leak.
type GovernanceContext struct {
	SchemaVersion string `json:"schema_version"`

	OversightMode OversightMode `json:"oversight_mode"`

	// AccountableParty is the LEGAL entity (controller / deployer).
	AccountableParty string `json:"accountable_party"`

	// DataSubjectRefs are salted refs (§4.7): HMAC-SHA3-256(tenant_salt,
	// subject_identifier), 64-hex. The salt lives in the tenant's KMS, NEVER in
	// the artifact — a deterministic unsalted hash of a national ID is a
	// dictionary attack waiting to happen. [] = no subject.
	DataSubjectRefs []string `json:"data_subject_refs"`

	// TenantID is the isolation anchor. I11 enforces cross-tenant edges at
	// seal.
	TenantID string `json:"tenant_id"`

	// RetentionClass — see RetentionClass. SOURCE of the applied Object Lock
	// period (§4.8), not a description of it.
	RetentionClass RetentionClass `json:"retention_class"`

	Environment Environment `json:"environment"`

	// CorrelationIDs are opaque tokens (§4.9), operator-asserted PII-free.
	// May be [].
	CorrelationIDs []string `json:"correlation_ids"`

	// Reserved names for additive evolution (§3.3): "legal_basis",
	// "jurisdiction". Reserved NAMES on paper are the only reservation
	// mechanism — there are deliberately no padding fields (§2.4).
}

// =============================================================================
// Field 32 — execution_context (§3.4)
// =============================================================================

// LLMCallParams is the FIXED key set of llm_calls[].params (§4.11). The set is
// frozen with the envelope schema_version.
//
// Nullability is semantic, not decorative (§4.10): a key the provider did not
// set is JSON null, and "not set by this call" is a FACT worth signing — not an
// optional field. Hence pointers with no omitempty: nil marshals to null and
// the key is always present.
type LLMCallParams struct {
	// Temperature / TopP are JSON numbers canonicalized by JCS's ECMAScript
	// number rule (core.CanonicalizeJSON / the Python _canonicalize_float).
	Temperature *float64 `json:"temperature"`
	TopP        *float64 `json:"top_p"`

	// Seed is a DECIMAL STRING or null (§4.10) — deliberately not a number.
	// A 64-bit seed exceeds JCS's ±(2^53-1) safe-integer window, so a numeric
	// seed would either be rejected at canonicalization or silently rounded to
	// a different value in a different language. Both outcomes break the
	// cross-language determinism the whole hash contract rests on.
	Seed *string `json:"seed"`

	// MaxTokens is an integer inside the JCS-safe range.
	MaxTokens *int64 `json:"max_tokens"`

	// ResponseSchemaHash is 64-hex, ZeroHash64 when N/A. A sentinel rather
	// than null: the key is a hash slot, and "no schema" is expressible.
	ResponseSchemaHash string `json:"response_schema_hash"`
}

// LLMCall is one model call ATTEMPT (§3.4) — one entry per attempt, in order,
// INCLUDING failed and retried attempts (§3.4.1, I13).
//
// A failed attempt is evidence, not noise: it is the thing you retried, and the
// record of the retry is what stops "call it until it flatters" from hiding.
type LLMCall struct {
	// Seq is 1-based, strictly increasing, contiguous.
	Seq int `json:"seq"`

	ModelProvider string        `json:"model_provider"`
	ModelName     string        `json:"model_name"` // served id
	Params        LLMCallParams `json:"params"`

	// Status is OK | ERROR | TIMEOUT (§3.4.1). A non-OK attempt has no output,
	// so it carries the sentinels below.
	Status string `json:"status"`

	// PromptHash per §4.2 (SHA3-256 over the UTF-8 bytes of the stored
	// canonical string). Always real — a failed attempt still HAD a prompt,
	// and that prompt is exactly what an examiner wants to see.
	PromptHash string `json:"prompt_hash"`
	// OutputHash per §4.2; ZeroHash64 when Status != OK — there is no output
	// to hash (§4.4). The same rule tool_call_log already used.
	OutputHash string `json:"output_hash"`

	// FinishReason is the provider's value, verbatim; FinishReasonNone when
	// Status != OK, because the provider never returned one.
	FinishReason string `json:"finish_reason"`

	StartedAt string `json:"started_at"` // Z-strict
	EndedAt   string `json:"ended_at"`   // Z-strict
}

// RetrievalParams is the FIXED key set of retrievals[].params (§4.11).
type RetrievalParams struct {
	TopK     *int64   `json:"top_k"`
	MinScore *float64 `json:"min_score"`
	// FiltersHash is 64-hex, ZeroHash64 when no filters applied.
	FiltersHash string `json:"filters_hash"`
	// Reranker is the reranker identity; "none" when none ran (§3.4).
	Reranker string `json:"reranker"`
}

// Retrieval is one retrieval ATTEMPT (§3.4), failures included (§3.4.1, I13).
// Hash-only per I4: the raw query never appears, only query_hash.
type Retrieval struct {
	Seq int `json:"seq"`
	// QueryHash — the raw retrieval query is deliberately excluded (§11); the
	// query can carry subject data and the hash is sufficient to bind it.
	// Always real: a failed retrieval still had a query.
	QueryHash      string `json:"query_hash"`
	IndexID        string `json:"index_id"`
	IndexVersion   string `json:"index_version"`
	EmbeddingModel string `json:"embedding_model"`

	// Status is OK | ERROR | TIMEOUT (§3.4.1). A retrieval has no output_hash
	// field to sentinel — its result lands in rag_evidence_bundle — so the
	// binding runs the other way: a rag_evidence_bundle entry may only link to
	// an OK retrieval (§3.1.1). Documents cannot come from a retrieval that
	// failed.
	Status string `json:"status"`

	Params RetrievalParams `json:"params"`
}

// Guardrail is one guardrail evaluation (§3.4).
type Guardrail struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Stage   string `json:"stage"`   // input | output
	Verdict string `json:"verdict"` // PASS | MODIFIED | BLOCKED
}

// ExecutionContext is field 32 — how the decision was actually executed (§3.4).
// Versioned, always present, leniently parsed.
type ExecutionContext struct {
	SchemaVersion string `json:"schema_version"`

	// AgentVersion is the AGENT's own code / prompt-template version. Three
	// distinct things are attested by three distinct mechanisms and must not be
	// conflated: ABSA attests the SDK binary (field 22), the model fields
	// attest the model (11–14), and this attests the agent.
	AgentVersion string `json:"agent_version"`

	// DecisiveSeq names which llm_calls[].seq produced the verdict (I9); 0 for
	// non-MODEL kinds.
	//
	// It exists because "the decisive call" cannot be inferred from position:
	// auxiliary calls that run AFTER the verdict (output guardrails,
	// rewriters) legitimately carry a higher seq and would otherwise be
	// mistaken for it. The pointer must resolve to EXACTLY ONE existing seq —
	// dangling or ambiguous is a validation FAILURE, not a lookup miss.
	DecisiveSeq int `json:"decisive_seq"`

	LLMCalls   []LLMCall   `json:"llm_calls"`
	Retrievals []Retrieval `json:"retrievals"`
	Guardrails []Guardrail `json:"guardrails"`
}

// =============================================================================
// Enriched nested records (§3.1.1, §3.1.2)
// =============================================================================

// RAGEvidenceEntry is one retrieved document (§3.1.1).
//
// content_hash is deliberately absent — it is derivable from content, and §2.7
// forbids storing a fact derivable from a sibling sealed in the same artifact.
type RAGEvidenceEntry struct {
	Source  string  `json:"source"`
	Content string  `json:"content"` // verbatim retrieved text — this IS the evidence
	Score   float64 `json:"score"`
	Cached  bool    `json:"cached"`

	DocID      string `json:"doc_id"`
	DocVersion string `json:"doc_version"`
	// RetrievalSeq links to execution_context.retrievals[].seq.
	RetrievalSeq int `json:"retrieval_seq"`
}

// ToolCallEntry is one READ-ONLY tool invocation (§3.1.2).
//
// Side-effecting tools are NEVER here — they are their own TOOL_EXECUTION nodes
// (§9). Read-only tools never leave tool_call_log; side-effecting tools never
// enter it. Args and results appear as hashes only (I4).
type ToolCallEntry struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	// Seq is 1-based, strictly increasing, contiguous.
	Seq       int    `json:"seq"`
	StartedAt string `json:"started_at"` // Z-strict
	EndedAt   string `json:"ended_at"`   // Z-strict
	Status    string `json:"status"`     // OK | ERROR | TIMEOUT

	// InputHash = SHA3-256(JCS(args)).
	InputHash string `json:"input_hash"`
	// OutputHash = SHA3-256(JCS(result)); ZeroHash64 for ERROR/TIMEOUT with no
	// result.
	OutputHash string `json:"output_hash"`
}

// =============================================================================
// Canonical agent_input (§3.6) — the preimage of field 7, input_hash.
// =============================================================================

// UpstreamOutput is one entry of agent_input.upstream_outputs (§3.6).
//
// Correspondence with upstream[] is BY KEY (record_id,
// consumed_output_selector) and is ONE ENTRY PER DISTINCT KEY — not one per
// edge. Two non-control edges may share a parent+selector while differing only
// in relationship (a node that both DERIVED_FROM and VALIDATES the same parent
// field); they consume the SAME value and share the single entry.
