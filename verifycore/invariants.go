// The invariants decidable from ONE artifact (spec section 5).
//
// ValidateI1 and HashAgentInput are NOT here: I1 needs agent_input, which is a
// bundle input a Level-0 verifier does not hold. They stay in core.
package verifycore

import (
	"fmt"
	"regexp"
	"strings"
)

// seedRe matches §4.10's seed grammar: a DECIMAL STRING, or null (nil pointer).
// Deliberately not a JSON number — a 64-bit seed exceeds JCS's ±(2^53-1) safe
// window, so a numeric seed would be rejected at canonicalization or silently
// rounded to a DIFFERENT value in a different language. Either outcome breaks
// the cross-language determinism every hash in the system rests on.
var seedRe = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// =============================================================================
// ValidateArtifactBytes is the VERIFIER path: validate a received artifact from
// its own bytes.
//
// Identical to ValidateTierA except for one thing that matters: I3's expected
// digest is computed from the artifact's OWN provenance sub-tree as generic
// JSON (§4.6.1), not by re-marshaling the typed struct.
//
// Without this split, a verifier would reject a forward-compatible artifact.
// An unknown envelope key is covered by the producer's causality_chain_hash,
// but re-marshaling Provenance silently DROPS that key and yields a different
// digest — so I3 would fail on an artifact whose record_hash verifies
// perfectly. That is §6's additive-evolution promise broken one level down,
// and it would present as "this evidence is invalid" rather than "this verifier
// is older than this artifact".
//
// Returns the parsed record (for interpretation, which the struct is fine
// for), the validation issues, and a parse error if the bytes are not a
// well-formed record.
func ValidateArtifactBytes(raw []byte) (*Record, []string, error) {
	p, err := RecordFromJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	// A document JCS cannot canonicalize has no record_hash, so it is not a
	// conformant record whatever its fields say. encoding/json reads
	// 9007199254740993 into a float64 field without complaint (rounded); the
	// browser page's reader refuses it, and so does this.
	if _, err := CanonicalizeJSON(raw); err != nil {
		return nil, nil, err
	}
	want, cErr := CausalityHashFromBytes(raw)
	return p, p.ValidateFields(want, cErr), nil
}

// ValidateFields is the shared check set, exported so core's producer-side
// ValidateTierA can reuse it without this package gaining a struct-path
// causality hash.
//
// Original name: validateTierA. wantCausality is I3's expected digest
// and causalityErr reports a failure to compute it; the two callers differ ONLY
// in how that digest was obtained (struct vs. artifact bytes), which is exactly
// the §4.6.1 boundary.
func (p *Record) ValidateFields(wantCausality string, causalityErr error) []string {
	var issues []string

	// --- Identity ---
	if p.RecordID == "" || !uuidRe.MatchString(p.RecordID) {
		issues = append(issues, "record_id")
	}
	// Only the frozen schema version verifies. An additive revision would
	// widen the supported set in IsSupportedRecordVersion, not here.
	if !IsSupportedRecordVersion(p.RecordVersion) {
		issues = append(issues, "record_version")
	}
	if p.CreatedAt == "" || !isISO8601UTC(p.CreatedAt) {
		issues = append(issues, "created_at")
	}
	if p.EvidenceTier != TierA {
		issues = append(issues, "evidence_tier")
	}
	if !IsValidDecisionKind(p.DecisionKind) {
		issues = append(issues, "decision_kind")
	}

	// --- Actor and action ---
	if p.PrincipalIdentity == "" {
		issues = append(issues, "principal_identity")
	}
	if p.ActionType == "" {
		issues = append(issues, "action_type")
	}

	// --- Pre-execution binding ---
	if !lowerHex64Re.MatchString(p.InputHash) {
		issues = append(issues, "input_hash")
	}
	if p.AuthorizationTokenID == "" || !uuidRe.MatchString(p.AuthorizationTokenID) {
		issues = append(issues, "authorization_token_id")
	}

	// --- Capture ---
	if p.FullPromptSnapshot == "" {
		issues = append(issues, "full_prompt_snapshot")
	}
	if p.RAGEvidenceBundle == nil {
		issues = append(issues, "rag_evidence_bundle ([I5] the sentinel is [], never null)")
	}
	if !lowerHex64Re.MatchString(p.ModelVersionHash) {
		issues = append(issues, "model_version_hash")
	}
	if p.ModelProvider == "" {
		issues = append(issues, "model_provider")
	}
	if p.ModelName == "" {
		issues = append(issues, "model_name")
	}
	if p.OutputPrePostprocess == "" {
		issues = append(issues, "output_pre_postprocess")
	}
	if p.ExecutionResult == "" {
		issues = append(issues, "execution_result")
	}
	if p.ToolCallLog == nil {
		issues = append(issues, "tool_call_log ([I5] the sentinel is [], never null)")
	}

	// --- I3: causality binding (§3.5). Required and non-empty for EVERY
	// artifact, roots included — the provenance envelope is never empty. The
	// empty-allowed path of the 29-field schema is deleted, not deprecated.
	//
	// wantCausality comes from the caller: the struct on the producer path, the
	// artifact's own bytes on the verifier path (§4.6.1). See
	// ValidateArtifactBytes for why the distinction is load-bearing.
	if p.CausalityChainHash == "" {
		issues = append(issues, "causality_chain_hash ([I3] required, non-empty; derive via Seal)")
	} else if !lowerHex64Re.MatchString(p.CausalityChainHash) {
		issues = append(issues, "causality_chain_hash ([I3] must be 64 lowercase hex)")
	} else if causalityErr != nil {
		issues = append(issues, fmt.Sprintf("causality_chain_hash ([I3] cannot canonicalize provenance: %v)", causalityErr))
	} else if wantCausality != p.CausalityChainHash {
		issues = append(issues, "causality_chain_hash ([I3] != SHA3-256(JCS(provenance)); the record was hashed before the causality binding, or provenance changed after it)")
	}

	if !lowerHex64Re.MatchString(p.PolicyVersionHash) {
		issues = append(issues, "policy_version_hash")
	}
	if !isValidAvailabilityPolicy(p.AvailabilityPolicy) {
		issues = append(issues, "availability_policy")
	}
	if !isValidDeploymentMode(p.DeploymentMode) {
		issues = append(issues, "deployment_mode")
	}
	if !isValidSDKHashLayer(p.SDKHashLayer) {
		issues = append(issues, "sdk_hash_layer")
	}
	if !lowerHex64Re.MatchString(p.SDKBinarySHA3) {
		issues = append(issues, "sdk_binary_sha3")
	}
	if !isValidRegistryStatus(p.RegistryValidationStatus) {
		issues = append(issues, "registry_validation_status")
	}
	// §4.5 — signing_key_id and parent_signing_key_id share ONE grammar:
	// 64 lowercase hex = SHA3-256(raw 32-byte Ed25519 public key), no prefix.
	if !lowerHex64Re.MatchString(p.SigningKeyID) {
		issues = append(issues, "signing_key_id (64 lowercase hex, no prefix)")
	}
	if p.LockVerificationLatencyMs < 0 {
		issues = append(issues, "lock_verification_latency_ms")
	}
	if p.InstrumentationCoverage < 0.0 || p.InstrumentationCoverage > 1.0 {
		issues = append(issues, "instrumentation_coverage")
	}
	// capture_layer is required and must be one of the two enum values.
	// consequential is a plain bool — every value is structurally valid — so
	// it carries no validation clause here.
	if p.CaptureLayer != BusinessLayerCapture && p.CaptureLayer != LLMLayerCapture {
		issues = append(issues, "capture_layer")
	}

	issues = append(issues, p.validateRAGBundle()...)
	issues = append(issues, p.validateToolCallLog()...)
	issues = append(issues, p.validateProvenance()...)
	issues = append(issues, p.validateGovernanceContext()...)
	issues = append(issues, p.validateExecutionContext()...)
	issues = append(issues, p.validateKindConformance()...)

	return issues
}

// =============================================================================
// Nested records
// =============================================================================

func (p *Record) validateRAGBundle() []string {
	var issues []string
	// Index the retrievals by seq WITH their status, so a retrieval_seq link
	// can be resolved rather than merely range-checked, and so the OK rule
	// below is decidable.
	bySeq := make(map[int]*Retrieval, len(p.ExecutionContext.Retrievals))
	for i := range p.ExecutionContext.Retrievals {
		r := &p.ExecutionContext.Retrievals[i]
		bySeq[r.Seq] = r
	}

	for i, e := range p.RAGEvidenceBundle {
		at := fmt.Sprintf("rag_evidence_bundle[%d]", i)
		if e.Source == "" {
			issues = append(issues, at+".source")
		}
		if e.DocID == "" {
			issues = append(issues, at+".doc_id")
		}
		if e.DocVersion == "" {
			issues = append(issues, at+".doc_version")
		}
		// §3.1.1: retrieval_seq LINKS to execution_context.retrievals[].seq.
		// A dangling link is not a link — same rule as decisive_seq (§3.4):
		// a pointer that does not resolve is a validation failure, not a
		// lookup miss.
		r, ok := bySeq[e.RetrievalSeq]
		if !ok {
			issues = append(issues, fmt.Sprintf(
				"%s.retrieval_seq (%d does not resolve to any execution_context.retrievals[].seq)", at, e.RetrievalSeq))
			continue
		}
		// §3.1.1 / I13 — a document cannot come from a retrieval that failed.
		// Locally decidable contradiction; same rule and same reasoning as
		// I9's "the decisive call must be OK".
		if r.Status != AttemptStatusOK {
			issues = append(issues, fmt.Sprintf(
				"%s.retrieval_seq ([I13] links to retrievals[seq=%d] with status %s; a document cannot come from a retrieval that failed)",
				at, e.RetrievalSeq, r.Status))
		}
	}
	return issues
}

func (p *Record) validateToolCallLog() []string {
	var issues []string
	for i, t := range p.ToolCallLog {
		at := fmt.Sprintf("tool_call_log[%d]", i)
		if t.Tool == "" {
			issues = append(issues, at+".tool")
		}
		if t.ToolVersion == "" {
			issues = append(issues, at+".tool_version")
		}
		if !isISO8601UTC(t.StartedAt) {
			issues = append(issues, at+".started_at (Z-strict)")
		}
		if !isISO8601UTC(t.EndedAt) {
			issues = append(issues, at+".ended_at (Z-strict)")
		}
		if !lowerHex64Re.MatchString(t.InputHash) {
			issues = append(issues, at+".input_hash")
		}
		if !lowerHex64Re.MatchString(t.OutputHash) {
			issues = append(issues, at+".output_hash")
		}
		// I13 — status + the output_hash sentinel rule, both directions.
		issues = append(issues, validateAttemptOutcome(at, t.Status, t.OutputHash, "", false)...)
	}
	// §3.1.2: seq is 1-based, strictly increasing, contiguous.
	issues = append(issues, validateSeqRun("tool_call_log", toolSeqs(p.ToolCallLog))...)
	return issues
}

func toolSeqs(ts []ToolCallEntry) []int {
	out := make([]int, len(ts))
	for i, t := range ts {
		out[i] = t.Seq
	}
	return out
}

// validateAttemptOutcome enforces I13's status/sentinel rule for one attempt,
// in BOTH directions (§3.4.1, §4.4).
//
// Forward: a non-OK attempt produced no output, so output_hash is the 64-zero
// sentinel and finish_reason is "NONE".
//
// Converse: an OK attempt must NOT carry those sentinels. The spec's prose
// implied this but did not state it, so it is stated here and in §4.4: "status
// OK, output_hash 0…0" is a contradiction the artifact makes about itself — it
// claims a call succeeded while recording that there was nothing to hash. Only
// checking the forward direction would let exactly that validate, which is the
// shape a producer lands on by copying a failure branch.
//
// hasFinishReason distinguishes llm_calls (which carries finish_reason) from
// tool_call_log (which does not).
func validateAttemptOutcome(at, status, outputHash, finishReason string, hasFinishReason bool) []string {
	var issues []string
	if !IsValidAttemptStatus(status) {
		issues = append(issues, fmt.Sprintf("%s.status ([I13] %q; want OK, ERROR, or TIMEOUT)", at, status))
		// Without a valid status the sentinel rule is undecidable — do not
		// guess a direction.
		return issues
	}

	if status == AttemptStatusOK {
		if outputHash == ZeroHash64 {
			issues = append(issues, fmt.Sprintf(
				"%s.output_hash ([I13] status OK carries the no-output sentinel; an attempt cannot both succeed and have no output to hash)", at))
		}
		if hasFinishReason && finishReason == FinishReasonNone {
			issues = append(issues, fmt.Sprintf(
				"%s.finish_reason ([I13] status OK carries the %q sentinel; a completed call returns a provider finish_reason)", at, FinishReasonNone))
		}
		return issues
	}

	// status is ERROR or TIMEOUT.
	if outputHash != ZeroHash64 {
		issues = append(issues, fmt.Sprintf(
			"%s.output_hash ([I13] status %s must carry the 64-zero sentinel; a failed attempt has no output to hash)", at, status))
	}
	if hasFinishReason && finishReason != FinishReasonNone {
		issues = append(issues, fmt.Sprintf(
			"%s.finish_reason ([I13] status %s must carry %q; the provider never returned a finish_reason)", at, status, FinishReasonNone))
	}
	return issues
}

// validateSeqRun enforces "1-based, strictly increasing, contiguous" — i.e.
// seqs[i] == i+1. Contiguity is what makes a MISSING entry detectable: a gap
// would let a producer silently drop a call from the record while every
// remaining entry still validated.
func validateSeqRun(at string, seqs []int) []string {
	var issues []string
	for i, s := range seqs {
		if s != i+1 {
			issues = append(issues, fmt.Sprintf(
				"%s[%d].seq (%d; must be 1-based, strictly increasing, contiguous; want %d)", at, i, s, i+1))
		}
	}
	return issues
}

// =============================================================================
// Field 30 — provenance (§3.2)
// =============================================================================

func (p *Record) validateProvenance() []string {
	var issues []string
	pr := &p.Provenance

	if !IsAcceptedEnvelopeVersion(pr.SchemaVersion) {
		issues = append(issues, fmt.Sprintf("provenance.schema_version (%q; want 1.x.y, the major this verifier implements)", pr.SchemaVersion))
	}
	if pr.WorkflowID == "" {
		issues = append(issues, "provenance.workflow_id (sentinel is \"adhoc\", never empty)")
	}
	// §3.2: SDK-minted UUIDv4 at run start. The substrate never mints one.
	if !uuidRe.MatchString(pr.WorkflowRunID) {
		issues = append(issues, "provenance.workflow_run_id (UUIDv4, SDK-minted at run start)")
	}
	if pr.WorkflowNodeID == "" {
		issues = append(issues, "provenance.workflow_node_id")
	}
	if !lowerHex64Re.MatchString(pr.WorkflowDefinitionHash) {
		issues = append(issues, "provenance.workflow_definition_hash")
	}
	if pr.Upstream == nil {
		issues = append(issues, "provenance.upstream (sentinel is [], never null)")
	}

	// Ad-hoc consistency (§4.4). "adhoc" is a package deal: no declared DAG
	// means no definition to hash and no vertex to name, so the node echoes its
	// own id. A run that declares a DAG must carry its definition hash, or
	// workflow_definition_hash could not resolve against the WORM-archived
	// body in year six (§8).
	if pr.WorkflowID == AdhocWorkflowID {
		if pr.WorkflowDefinitionHash != ZeroHash64 {
			issues = append(issues, "provenance.workflow_definition_hash (must be the 64-zero sentinel when workflow_id is \"adhoc\")")
		}
		if pr.WorkflowNodeID != p.RecordID {
			issues = append(issues, "provenance.workflow_node_id (must echo record_id when workflow_id is \"adhoc\")")
		}
	} else if pr.WorkflowDefinitionHash == ZeroHash64 {
		issues = append(issues, "provenance.workflow_definition_hash (a declared workflow_id requires a real SHA3-256(JCS(DAG)); the 64-zero sentinel is for ad-hoc runs only)")
	}

	issues = append(issues, p.validateUpstreamEdges()...)
	return issues
}

func (p *Record) validateUpstreamEdges() []string {
	var issues []string
	edges := p.Provenance.Upstream

	seen := make(map[string]int, len(edges)) // I10
	selectedFrom, consideredAlt := 0, 0

	for i, e := range edges {
		at := fmt.Sprintf("provenance.upstream[%d]", i)

		if !uuidRe.MatchString(e.RecordID) {
			issues = append(issues, at+".record_id")
		}
		if !lowerHex64Re.MatchString(e.RecordHash) {
			issues = append(issues, at+".record_hash")
		}
		// §4.5 — parent_signing_key_id shares signing_key_id's grammar exactly.
		if !lowerHex64Re.MatchString(e.ParentSigningKeyID) {
			issues = append(issues, at+".parent_signing_key_id (64 lowercase hex, no prefix)")
		}

		// I2 — closed enum of 10.
		if !IsValidRelationship(e.Relationship) {
			issues = append(issues, fmt.Sprintf("%s.relationship ([I2] %q is not one of the 10 values)", at, e.Relationship))
			// Without a valid relationship the control/data split below is
			// undecidable, so stop analyzing this edge rather than guess.
			continue
		}

		// I6 (local) — a self-edge. Acyclicity at large is guaranteed by
		// construction (an edge commits a hash that exists only after the
		// parent seals), but nothing stops a producer fabricating an edge to
		// ITSELF with a syntactically valid hash. That degenerate case is the
		// only one construction does not preclude, so it is the only one
		// checked.
		if e.RecordID == p.RecordID {
			issues = append(issues, fmt.Sprintf("%s.record_id ([I6] self-edge; a node cannot be its own parent)", at))
		}

		if !IsValidSelector(e.ConsumedOutputSelector) {
			issues = append(issues, fmt.Sprintf(
				"%s.consumed_output_selector (non-URI RFC 6901 pointer, single segment addressing a top-level parent field, e.g. \"/execution_result\"; deeper paths are reserved in v1)", at))
		}
		if !lowerHex64Re.MatchString(e.ConsumedOutputHash) {
			issues = append(issues, at+".consumed_output_hash")
		}

		// §3.2.1 control/data split. Control edges are causal but consume
		// nothing: empty selector + sentinel hash + no upstream_outputs entry.
		if IsControlEdge(e.Relationship) {
			if e.ConsumedOutputSelector != "" {
				issues = append(issues, fmt.Sprintf(
					"%s.consumed_output_selector (control edge %s consumes no value; selector must be \"\")", at, e.Relationship))
			}
			if e.ConsumedOutputHash != ZeroHash64 {
				issues = append(issues, fmt.Sprintf(
					"%s.consumed_output_hash (control edge %s must carry the 64-zero sentinel)", at, e.Relationship))
			}
		} else {
			if e.ConsumedOutputSelector == "" {
				issues = append(issues, fmt.Sprintf(
					"%s.consumed_output_selector (data edge %s must name what it consumed; \"\" is reserved for control edges)", at, e.Relationship))
			}
			// The sentinel means "no value consumed" (§4.4). A data edge
			// consumes a value by definition, so the sentinel here is a
			// contradiction the artifact states about itself. I1 would also
			// catch it at the substrate, but it is locally decidable.
			if e.ConsumedOutputHash == ZeroHash64 {
				issues = append(issues, fmt.Sprintf(
					"%s.consumed_output_hash (data edge %s carries the absent-value sentinel; a data edge consumes a value)", at, e.Relationship))
			}
		}

		switch e.Relationship {
		case SelectedFrom:
			selectedFrom++
		case ConsideredAlternative:
			consideredAlt++
		}

		// I10 — no two edges share (record_hash, selector, relationship).
		// This triple is also §4.3's sort key; uniqueness is what makes that
		// order TOTAL rather than merely defined.
		k := edgeSortKey(e)
		if prev, dup := seen[k]; dup {
			issues = append(issues, fmt.Sprintf(
				"%s ([I10] duplicate edge; same (record_hash, selector, relationship) as upstream[%d])", at, prev))
		} else {
			seen[k] = i
		}
	}

	// I7(a) — SELECTED_FROM implies a choice, and a choice implies
	// alternatives (§3.2.1). Zero alternatives alongside a claimed selection is
	// a cherry-picking lie that reads as diligence: it asserts a choice while
	// withholding what it was chosen over, and no local check could distinguish
	// it from an honest single-candidate run. An honest single-candidate
	// consumption is DERIVED_FROM.
	//
	// M3 adds (b): alternatives must cover every SEALED candidate, audited
	// against the ledger's authorization trail.
	if selectedFrom > 0 && consideredAlt == 0 {
		issues = append(issues, "provenance.upstream ([I7] a SELECTED_FROM edge requires >=1 CONSIDERED_ALTERNATIVE edge; a selection from a single candidate is a DERIVED_FROM consumption, not a selection)")
	}

	// §4.3 — total sort order, an ENFORCED invariant. A verifier rejects an
	// unsorted array rather than sorting it: canonical order is part of what
	// was signed, so re-sorting would silently "fix" an artifact whose bytes
	// are not what the producer claimed.
	for i := 1; i < len(edges); i++ {
		if compareEdges(edges[i-1], edges[i]) > 0 {
			issues = append(issues, fmt.Sprintf(
				"provenance.upstream (not sorted: [%d] must sort before [%d]; order is ascending by (record_hash, consumed_output_selector, relationship))", i-1, i))
			break
		}
	}

	return issues
}

// compareEdges is §4.3's order: ascending by record_hash, then
// consumed_output_selector, then relationship, each compared as bytes (which
// for UTF-8 is code-point order).
//
// It compares the components in turn. An earlier version compared the three
// joined with 0x1F, which agrees with the tuple order only while no selector
// contains a byte below 0x1F: for selectors "/a" and "/a\x01" under one
// record_hash, the joined form put "/a\x01" first and refused a record that
// was sorted.
func compareEdges(a, b UpstreamEdge) int {
	if c := strings.Compare(a.RecordHash, b.RecordHash); c != 0 {
		return c
	}
	if c := strings.Compare(a.ConsumedOutputSelector, b.ConsumedOutputSelector); c != 0 {
		return c
	}
	return strings.Compare(string(a.Relationship), string(b.Relationship))
}

// edgeSortKey is I10's identity for an edge: (record_hash,
// consumed_output_selector, relationship) as one map key.
//
// The components are joined with 0x1F so that a selector's trailing bytes
// cannot borrow from the next component and make two distinct edges collide.
// relationship is a closed enum with no 0x1F in it, so the last separator is
// unambiguous. It is a key for equality only; order is compareEdges.
func edgeSortKey(e UpstreamEdge) string {
	const sep = "\x1f"
	return e.RecordHash + sep + e.ConsumedOutputSelector + sep + string(e.Relationship)
}

// =============================================================================
// Field 31 — governance_context (§3.3)
// =============================================================================

func (p *Record) validateGovernanceContext() []string {
	var issues []string
	g := &p.GovernanceContext

	if !IsAcceptedEnvelopeVersion(g.SchemaVersion) {
		issues = append(issues, fmt.Sprintf("governance_context.schema_version (%q; want 1.x.y, the major this verifier implements)", g.SchemaVersion))
	}
	if !IsValidOversightMode(g.OversightMode) {
		issues = append(issues, "governance_context.oversight_mode")
	}
	if g.AccountableParty == "" {
		issues = append(issues, "governance_context.accountable_party (the LEGAL entity)")
	}
	if g.TenantID == "" {
		issues = append(issues, "governance_context.tenant_id")
	}
	if !IsValidRetentionClass(g.RetentionClass) {
		issues = append(issues, "governance_context.retention_class (DEV_EPHEMERAL, SHORT_1Y, STANDARD_7Y, EXTENDED_10Y, or PERMANENT)")
	}
	if !IsValidEnvironment(g.Environment) {
		issues = append(issues, "governance_context.environment (PROD, STAGING, or TEST)")
	}

	if g.DataSubjectRefs == nil {
		issues = append(issues, "governance_context.data_subject_refs (sentinel is [], never null)")
	}
	for i, ref := range g.DataSubjectRefs {
		// §4.7 — HMAC-SHA3-256(tenant_salt, subject_identifier), 64-hex. The
		// salt lives in the tenant's KMS and NEVER in the artifact: an unsalted
		// deterministic hash of a national ID is a dictionary attack waiting to
		// happen.
		if !lowerHex64Re.MatchString(ref) {
			issues = append(issues, fmt.Sprintf("governance_context.data_subject_refs[%d] (64-hex salted ref)", i))
		}
	}

	if g.CorrelationIDs == nil {
		issues = append(issues, "governance_context.correlation_ids (sentinel is [], never null)")
	}
	for i, c := range g.CorrelationIDs {
		if !correlationIDRe.MatchString(c) {
			issues = append(issues, fmt.Sprintf("governance_context.correlation_ids[%d] (^[A-Za-z0-9:_.-]{1,128}$, no PII)", i))
		}
	}

	// I14 (local slice) — oversight-mode conformance (§3.3.1).
	//
	// PRE_AUTHORIZED is the ONLY mode with a local check, and precisely because
	// its authorization is in the PAST: a pre-existing artifact is exactly what
	// a backward edge can commit to. A PRE_AUTHORIZED node carrying no
	// TRIGGERED_BY edge references no authorization at all — locally decidable,
	// so enforced at seal.
	//
	// The other three modes have NO local check and never will. On the AI's own
	// record the approval is a FUTURE event, and edges are backward-only (a
	// node cannot commit a hash that does not yet exist), so the declaration is
	// structurally unverifiable from the artifact alone. This is the one
	// self-declaration that could not be fixed by inversion the way
	// retention_class was — it is verified FORWARD through the index (§8) in M3
	// ("you declared HUMAN_IN_THE_LOOP; show me the APPROVES edge pointing at
	// this node") or not at all.
	if g.OversightMode == PreAuthorized {
		hasAuthorizingEdge := false
		for _, e := range p.Provenance.Upstream {
			if e.Relationship == TriggeredBy {
				hasAuthorizingEdge = true
				break
			}
		}
		if !hasAuthorizingEdge {
			issues = append(issues, "governance_context.oversight_mode ([I14] PRE_AUTHORIZED requires >=1 TRIGGERED_BY upstream edge referencing the authorizing artifact (the schema); "+
				"the authorization pre-exists, so a backward edge can and must reference it. A PRE_AUTHORIZED node with none references no authorization at all)")
		}
	}

	// I8(a) — the production floor, expressed ORDINALLY (>= SHORT_1Y) rather
	// than as "!= DEV_EPHEMERAL", so a future sub-floor class cannot smuggle
	// itself in the way an inequality against a single value would permit.
	if g.Environment == EnvProd && IsValidRetentionClass(g.RetentionClass) {
		if !RetentionHorizonAtLeast(g.RetentionClass, Short1Y) {
			issues = append(issues, fmt.Sprintf(
				"governance_context.retention_class ([I8] %s is below the production floor; environment=PROD requires >= SHORT_1Y)", g.RetentionClass))
		}
	}

	return issues
}

// =============================================================================
// Field 32 — execution_context (§3.4)
// =============================================================================

func (p *Record) validateExecutionContext() []string {
	var issues []string
	x := &p.ExecutionContext

	if !IsAcceptedEnvelopeVersion(x.SchemaVersion) {
		issues = append(issues, fmt.Sprintf("execution_context.schema_version (%q; want 1.x.y, the major this verifier implements)", x.SchemaVersion))
	}
	// The agent's own code / prompt-template version. ABSA attests the SDK
	// binary, the model fields attest the model, this attests the agent —
	// three distinct things, three distinct mechanisms.
	if x.AgentVersion == "" {
		issues = append(issues, "execution_context.agent_version")
	}
	if x.LLMCalls == nil {
		issues = append(issues, "execution_context.llm_calls (sentinel is [], never null)")
	}
	if x.Retrievals == nil {
		issues = append(issues, "execution_context.retrievals (sentinel is [], never null)")
	}
	if x.Guardrails == nil {
		issues = append(issues, "execution_context.guardrails (sentinel is [], never null)")
	}

	for i, c := range x.LLMCalls {
		at := fmt.Sprintf("execution_context.llm_calls[%d]", i)
		if c.ModelProvider == "" {
			issues = append(issues, at+".model_provider")
		}
		if c.ModelName == "" {
			issues = append(issues, at+".model_name")
		}
		if !lowerHex64Re.MatchString(c.PromptHash) {
			issues = append(issues, at+".prompt_hash")
		}
		if !lowerHex64Re.MatchString(c.OutputHash) {
			issues = append(issues, at+".output_hash")
		}
		if c.FinishReason == "" {
			issues = append(issues, at+".finish_reason (provider value verbatim, or \"NONE\" on a non-OK attempt)")
		}
		// I13 — every attempt is an entry, failures included, and a failure
		// carries the defined sentinels.
		issues = append(issues, validateAttemptOutcome(at, c.Status, c.OutputHash, c.FinishReason, true)...)
		if !isISO8601UTC(c.StartedAt) {
			issues = append(issues, at+".started_at (Z-strict)")
		}
		if !isISO8601UTC(c.EndedAt) {
			issues = append(issues, at+".ended_at (Z-strict)")
		}
		issues = append(issues, validateLLMParams(at+".params", c.Params)...)
	}
	issues = append(issues, validateSeqRun("execution_context.llm_calls", llmSeqs(x.LLMCalls))...)

	for i, r := range x.Retrievals {
		at := fmt.Sprintf("execution_context.retrievals[%d]", i)
		// I4 — the raw query never appears, only its hash (§11).
		if !lowerHex64Re.MatchString(r.QueryHash) {
			issues = append(issues, at+".query_hash")
		}
		if r.IndexID == "" {
			issues = append(issues, at+".index_id")
		}
		if r.IndexVersion == "" {
			issues = append(issues, at+".index_version")
		}
		if r.EmbeddingModel == "" {
			issues = append(issues, at+".embedding_model")
		}
		// I13 — a retrieval carries no output_hash of its own (its result
		// lands in rag_evidence_bundle), so only the status enum is checked
		// here; the OK binding runs from the RAG side (§3.1.1).
		if !IsValidAttemptStatus(r.Status) {
			issues = append(issues, fmt.Sprintf("%s.status ([I13] %q; want OK, ERROR, or TIMEOUT)", at, r.Status))
		}
		if !lowerHex64Re.MatchString(r.Params.FiltersHash) {
			issues = append(issues, at+".params.filters_hash")
		}
		if r.Params.Reranker == "" {
			issues = append(issues, at+".params.reranker (\"none\" when none ran)")
		}
		if r.Params.TopK != nil && *r.Params.TopK < 0 {
			issues = append(issues, at+".params.top_k")
		}
	}
	issues = append(issues, validateSeqRun("execution_context.retrievals", retrievalSeqs(x.Retrievals))...)

	for i, g := range x.Guardrails {
		at := fmt.Sprintf("execution_context.guardrails[%d]", i)
		if g.Name == "" {
			issues = append(issues, at+".name")
		}
		if g.Version == "" {
			issues = append(issues, at+".version")
		}
		if !isValidGuardrailStage(g.Stage) {
			issues = append(issues, at+".stage (want input or output)")
		}
		if !isValidGuardrailVerdict(g.Verdict) {
			issues = append(issues, at+".verdict (want PASS, MODIFIED, or BLOCKED)")
		}
	}

	return issues
}

func llmSeqs(cs []LLMCall) []int {
	out := make([]int, len(cs))
	for i, c := range cs {
		out[i] = c.Seq
	}
	return out
}

func retrievalSeqs(rs []Retrieval) []int {
	out := make([]int, len(rs))
	for i, r := range rs {
		out[i] = r.Seq
	}
	return out
}

// validateLLMParams enforces §4.10's typing. The key SET is fixed by the struct
// (§4.11); what varies is whether each key carries a value or null, and null
// means "not set by this call" — a fact, not an optional field.
func validateLLMParams(at string, pm LLMCallParams) []string {
	var issues []string

	// §4.10 — seed is a DECIMAL STRING or null. See seedRe for why not a
	// number.
	if pm.Seed != nil && !seedRe.MatchString(*pm.Seed) {
		issues = append(issues, fmt.Sprintf(
			"%s.seed (decimal string or null, got %q; a numeric seed would exceed JCS's ±(2^53-1) window and round differently across languages)", at, *pm.Seed))
	}
	// max_tokens must sit inside the JCS-safe integer range, or it cannot be
	// canonicalized identically in Go and Python.
	if pm.MaxTokens != nil {
		if *pm.MaxTokens < 0 || *pm.MaxTokens > MaxSafeInteger {
			issues = append(issues, fmt.Sprintf(
				"%s.max_tokens (integer within ±(2^53-1), got %d)", at, *pm.MaxTokens))
		}
	}
	// response_schema_hash is a hash slot with a sentinel, never null.
	if !lowerHex64Re.MatchString(pm.ResponseSchemaHash) {
		issues = append(issues, fmt.Sprintf(
			"%s.response_schema_hash (64-hex, or the 64-zero sentinel when N/A)", at))
	}
	return issues
}

// =============================================================================
// I12 — kind conformance, and I9 — decisive-call binding
// =============================================================================

func (p *Record) validateKindConformance() []string {
	var issues []string
	if !IsValidDecisionKind(p.DecisionKind) {
		return issues // decision_kind already reported; nothing to conform to
	}

	// §3.0 — principal_identity is typed to the kind.
	prefixes := principalPrefixes(p.DecisionKind)
	matched := false
	for _, pre := range prefixes {
		if strings.HasPrefix(p.PrincipalIdentity, pre) {
			matched = true
			break
		}
	}
	if !matched {
		issues = append(issues, fmt.Sprintf(
			"principal_identity ([I12] %s requires prefix %s)", p.DecisionKind, strings.Join(prefixes, " or ")))
	} else if p.DecisionKind == HumanDecision {
		// §4.7 / §3.0.1 — a human principal is "human:" + a 64-lowercase-hex
		// salted ref, not merely the prefix.
		//
		// A prefix-only check accepts "human:jane@acme.com" — the raw identity
		// the pseudonym exists to keep OUT of the artifact, sitting in a signed,
		// WORM-committed, undeletable field. The format is locally decidable, so
		// it is enforced here; CONSTRUCTING the ref needs the tenant salt and is
		// producer-side (M2).
		//
		// This checks SHAPE only. It cannot confirm the value is really an HMAC
		// under the tenant's salt, and it proves nothing about who the human
		// was — see §3.0.1: the substrate signs, the human does not.
		ref := strings.TrimPrefix(p.PrincipalIdentity, "human:")
		if !lowerHex64Re.MatchString(ref) {
			issues = append(issues, fmt.Sprintf(
				"principal_identity ([I12] HUMAN_DECISION requires human:<64-hex salted ref> = "+
					"HMAC-SHA3-256(tenant_salt, subject_identifier); got %q. A raw identity must never "+
					"enter a signed, undeletable field)", p.PrincipalIdentity))
		}
	}

	if !IsModelKind(p.DecisionKind) {
		// §4.4 non-model sentinels. Each is an ASSERTION that the facet does
		// not apply — which is a fact, and facts get signed. Emptiness would
		// be indistinguishable from a producer that forgot.
		if p.ModelVersionHash != ZeroHash64 {
			issues = append(issues, fmt.Sprintf(
				"model_version_hash ([I12] %s requires the 64-zero sentinel)", p.DecisionKind))
		}
		if p.ModelProvider != NoneSentinel {
			issues = append(issues, fmt.Sprintf(
				"model_provider ([I12] %s requires %q)", p.DecisionKind, NoneSentinel))
		}
		if p.ModelName != NoneSentinel {
			issues = append(issues, fmt.Sprintf(
				"model_name ([I12] %s requires %q)", p.DecisionKind, NoneSentinel))
		}
		if len(p.ExecutionContext.LLMCalls) != 0 {
			issues = append(issues, fmt.Sprintf(
				"execution_context.llm_calls ([I12] %s requires [])", p.DecisionKind))
		}
		if p.ExecutionContext.DecisiveSeq != 0 {
			issues = append(issues, fmt.Sprintf(
				"execution_context.decisive_seq ([I12] %s requires 0)", p.DecisionKind))
		}
		return issues // I9 is not applied to non-MODEL kinds.
	}

	// --- MODEL_DECISION ---
	if p.ModelVersionHash == ZeroHash64 {
		issues = append(issues, "model_version_hash ([I12] MODEL_DECISION requires the real identity-tuple hash, not the absent sentinel)")
	}
	if p.ModelProvider == NoneSentinel {
		issues = append(issues, "model_provider ([I12] MODEL_DECISION requires the decisive call's provider, not the NONE sentinel)")
	}
	if p.ModelName == NoneSentinel {
		issues = append(issues, "model_name ([I12] MODEL_DECISION requires the decisive call's served id, not the NONE sentinel)")
	}
	if len(p.ExecutionContext.LLMCalls) == 0 {
		issues = append(issues, "execution_context.llm_calls ([I12] MODEL_DECISION arises from >=1 model call)")
		return issues // I9 has nothing to resolve against
	}

	issues = append(issues, p.validateDecisiveCall()...)
	return issues
}

// validateDecisiveCall implements I9 (§3.4), MODEL kind only.
//
// decisive_seq MUST resolve to EXACTLY ONE existing llm_calls[].seq. A dangling
// or ambiguous pointer is a validation FAILURE, not a lookup miss — the whole
// point of the field is that "the decisive call" cannot be inferred from
// position: auxiliary calls that run AFTER the verdict (output guardrails,
// rewriters) legitimately carry a higher seq and would otherwise be mistaken
// for it.
func (p *Record) validateDecisiveCall() []string {
	var issues []string
	x := &p.ExecutionContext

	var decisive *LLMCall
	matches := 0
	for i := range x.LLMCalls {
		if x.LLMCalls[i].Seq == x.DecisiveSeq {
			matches++
			decisive = &x.LLMCalls[i]
		}
	}
	if matches == 0 {
		issues = append(issues, fmt.Sprintf(
			"execution_context.decisive_seq ([I9] %d does not resolve to any llm_calls[].seq; a dangling pointer is a failure, not a lookup miss)", x.DecisiveSeq))
		return issues
	}
	if matches > 1 {
		issues = append(issues, fmt.Sprintf(
			"execution_context.decisive_seq ([I9] %d resolves to %d llm_calls entries; it must resolve to exactly one)", x.DecisiveSeq, matches))
		return issues
	}

	// §3.4.1 — a decisive call MUST have status OK. You cannot designate a
	// failed attempt as the decision: a timed-out call produced no output, so
	// the prompt/output bindings below would be binding field 14 to a sentinel,
	// and the artifact would claim a verdict came from a call that never
	// returned one.
	if decisive.Status != AttemptStatusOK {
		issues = append(issues, fmt.Sprintf(
			"execution_context.decisive_seq ([I9] names llm_calls[seq=%d] with status %s; a failed attempt cannot be the decision)",
			decisive.Seq, decisive.Status))
		return issues
	}

	// §4.2 — full_prompt_snapshot and output_pre_postprocess are stored as the
	// exact canonical string; their hashes are SHA3-256 over the UTF-8 BYTES of
	// the stored string (a multi-message prompt was already canonicalized into
	// JCS([{role,content},...]) BEFORE storage, so there is one stored string
	// hashed byte-for-byte).
	if want := HashSHA3256([]byte(p.FullPromptSnapshot)); decisive.PromptHash != want {
		issues = append(issues, fmt.Sprintf(
			"execution_context.llm_calls[seq=%d].prompt_hash ([I9] != SHA3-256(full_prompt_snapshot))", decisive.Seq))
	}
	if want := HashSHA3256([]byte(p.OutputPrePostprocess)); decisive.OutputHash != want {
		issues = append(issues, fmt.Sprintf(
			"execution_context.llm_calls[seq=%d].output_hash ([I9] != SHA3-256(output_pre_postprocess))", decisive.Seq))
	}
	if decisive.ModelProvider != p.ModelProvider {
		issues = append(issues, fmt.Sprintf(
			"execution_context.llm_calls[seq=%d].model_provider ([I9] != model_provider field 12)", decisive.Seq))
	}
	if decisive.ModelName != p.ModelName {
		issues = append(issues, fmt.Sprintf(
			"execution_context.llm_calls[seq=%d].model_name ([I9] != model_name field 13)", decisive.Seq))
	}
	return issues
}

// =============================================================================
// I1 — consumed content bound to input (§3.6)
// =============================================================================

// ValidateI1 checks that every non-control edge's consumed_output_hash is bound
// to the value the child actually received, as carried in the canonical
// agent_input (§3.6). Returns an empty slice when the binding holds.
//
// THE SUBSTRATE CALLS THIS. It is the enforcement authority: it recomputes the
// hashes independently from agent_input rather than trusting the SDK's
// assembly. That ordering matters — the check was written against the spec
// BEFORE its producer exists (M2), precisely so it cannot degenerate into a
// rubber stamp on whatever the SDK happens to emit.
//
// Because agent_input is the preimage of input_hash, which the Authorization
// Token committed to BEFORE execution, this is what makes in-transit tampering
// between agents detectable rather than merely discouraged: an attacker who
// alters a parent's value in flight must also alter agent_input, which breaks
// the pre-commitment the token already holds.
//
// Correspondence rules (§3.6), all enforced here:
//   - By KEY (record_id, consumed_output_selector), never by index.
//   - EXACTLY ONE entry per distinct key — not one per edge. Two non-control
//     edges may share a parent+selector while differing only in relationship
//     (a node that both DERIVED_FROM and VALIDATES the same parent field);
//     they consume the same value and share the single entry.
//   - Every non-control edge's consumed_output_hash == SHA3-256(JCS(value)) of
//     the entry bearing its key.
//   - No entry may exist without a matching non-control edge.
//   - Control-only edges have NO entry (nothing to bind).
//   - Entries sorted ascending by (record_id, consumed_output_selector).

// HashAgentInput returns SHA3-256(JCS(agent_input)) — the value of input_hash
// (field 7), computed from raw agent_input bytes.
//
// Takes BYTES, not the struct: field 7 commits to the caller's own preimage, and
// a Go round-trip through AgentInput could re-format a number or drop an
// unknown key, producing a hash for a document nobody sent.
