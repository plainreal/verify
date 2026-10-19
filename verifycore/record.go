// The Record itself: the 33-field model, the byte-faithful hash path, the
// signature check, and strict top-level parsing.
//
// Producer-side operations (NewRecord, BindCausality, ComputeRecordHash, Seal)
// are NOT here. They are functions in core, which is what makes it impossible
// for code importing only this package to produce a signature.
package verifycore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// EvidenceTier classifies the attestation level of a record.
type EvidenceTier string

const (
	TierA EvidenceTier = "TIER-A" // Full attestation. Primary evidence.
	TierB EvidenceTier = "TIER-B" // Partial attestation. Corroborating evidence.
	TierC EvidenceTier = "TIER-C" // Metadata only.
)

// AvailabilityPolicy defines service behavior when PlainReal is unavailable.
type AvailabilityPolicy string

const (
	FallbackToTierB           AvailabilityPolicy = "FALLBACK_TO_TIER_B"
	BlockOnServiceUnavailable AvailabilityPolicy = "BLOCK_ON_SERVICE_UNAVAILABLE"
	ConfigurableByActionType  AvailabilityPolicy = "CONFIGURABLE_BY_ACTION_TYPE"
)

// DeploymentMode identifies how the PlainReal service is deployed. Distinct from
// governance_context.environment, which is where the AGENT executed (§3.1).
type DeploymentMode string

const (
	SaaSManaged              DeploymentMode = "SAAS_MANAGED"
	CustomerHostedAttested   DeploymentMode = "CUSTOMER_HOSTED_ATTESTED"
	CustomerHostedUnattested DeploymentMode = "CUSTOMER_HOSTED_UNATTESTED"
)

// SDKHashLayer identifies where input hashing occurs.
type SDKHashLayer string

const (
	ServiceEndpoint SDKHashLayer = "SERVICE_ENDPOINT"
	SDKInternal     SDKHashLayer = "SDK_INTERNAL"
)

// RegistryValidationStatus identifies SDK registry validation state.
type RegistryValidationStatus string

const (
	RegistryValidated   RegistryValidationStatus = "VALIDATED"
	RegistryUnvalidated RegistryValidationStatus = "UNVALIDATED"
	RegistryBypassed    RegistryValidationStatus = "BYPASSED"
)

// RecordVersion is the top-level schema version. NewRecord stamps this into
// every record it creates. The schema is frozen at 1.0.0: 33 fields, all
// required, with signing_attestation the only field excluded from the record
// hash.
//
// The GOAL is that this never bumps again (§6). Four independent version lines
// exist: this one, plus a schema_version inside each of the three envelopes.
// Additive capability bumps an ENVELOPE version, not this.
const RecordVersion = "1.0.0"

// EnvelopeSchemaVersion is the current schema_version of provenance,
// governance_context, and execution_context (§6). Additive envelope changes bump
// this; the top-level list stays locked.
const EnvelopeSchemaVersion = "1.0.0"

// capture_layer permitted values. The Record.CaptureLayer field is a plain
// required string — the cross-language schema contract (the Python SDK and any
// future Node SDK send a JSON string, not a Go enum). These named constants
// carry the two permitted values for producers and for ValidateTierA.
const (
	// BusinessLayerCapture — input captured at the business / orchestration
	// boundary (decorator wrapping a business function).
	BusinessLayerCapture = "BUSINESS_LAYER"
	// LLMLayerCapture — input captured at the LLM call boundary
	// (auto-instrumented OpenAI / Anthropic patch).
	LLMLayerCapture = "LLM_LAYER"
)

// IsSupportedRecordVersion reports whether v is in the schema-version set
// this binary will verify. Used by ValidateTierA and the standalone verify
// CLI; do NOT hardcode the predicate at call sites. Today the set is the
// single frozen version {1.0.0}; an additive revision would widen it here.
func IsSupportedRecordVersion(v string) bool {
	return v == RecordVersion
}

// SupportedRecordVersions returns the verifiable schema versions in
// OLDEST-first (ascending) order. Stable contract — auditor-facing surfaces
// like the verify CLI's --version-info flag and the unsupported-version
// error message render this slice verbatim. Today it is the single frozen
// version; an additive revision would append the new version here. The slice
// is freshly allocated per call.
func SupportedRecordVersions() []string {
	return []string{RecordVersion}
}

// =============================================================================
// Record — 33 fields (schema v1.0.0).
// =============================================================================

// Record is the record — the core evidence artifact.
//
// v1.0.0: 33 top-level fields, all required. The signed record hash covers 32;
// signing_attestation is the sole field excluded from the hash.
//
// Exactly ONE field carries `omitempty`:
//
//   - signing_attestation — load-bearing for ComputeRecordHash, which
//     zeros it on a shallow copy and relies on omitempty to drop the key
//     entirely from the canonical JSON.
//
// ANY other field must NOT carry omitempty
// (TestRecord_SigningAttestationHasOmitempty enforces this).
type Record struct {
	// --- Identity ---
	RecordID      string `json:"record_id"`
	RecordVersion string `json:"record_version"`
	// CreatedAt is DECISION time — when the verdict or action occurred. It is
	// deliberately NOT seal time; RFC 3161 anchors that independently. Must end
	// in a literal "Z" (§4 / isISO8601UTC).
	CreatedAt    string       `json:"created_at"`
	EvidenceTier EvidenceTier `json:"evidence_tier"`

	// --- Node type (field 33) ---
	// DecisionKind governs how fields 9, 11–14 and I9 are populated (§3.0).
	DecisionKind DecisionKind `json:"decision_kind"`

	// --- Actor and Action ---
	// PrincipalIdentity is typed to DecisionKind (§3.0). Human principals are
	// PSEUDONYMOUS ("human:<salted-ref>"), never a raw identity.
	PrincipalIdentity string `json:"principal_identity"`
	ActionType        string `json:"action_type"`

	// --- Pre-execution binding ---
	// InputHash = SHA3-256(JCS(agent_input)) where agent_input has the canonical
	// shape of §3.6 ({business_input, upstream_outputs}). Pre-committed in the
	// Authorization Token BEFORE execution; the substrate re-derives and
	// compares at seal. This is the control that separates PlainReal from an
	// audit log.
	InputHash            string `json:"input_hash"`
	AuthorizationTokenID string `json:"authorization_token_id"`

	// --- Input capture ---
	// FullPromptSnapshot is per-kind (§3.1 field 9): MODEL -> the decisive
	// call's complete prompt canonically serialized per §4.2; HUMAN -> the exact
	// material presented to the reviewer; TOOL_EXECUTION -> the tool request.
	FullPromptSnapshot string             `json:"full_prompt_snapshot"`
	RAGEvidenceBundle  []RAGEvidenceEntry `json:"rag_evidence_bundle"`

	// --- Model identification (sentinel-bearing on non-MODEL kinds) ---
	// ModelVersionHash is the model IDENTITY tuple hash — SHA3-256(JCS({provider,
	// model_name, served_version})) — NOT a hash of weights. ZeroHash64 on
	// non-MODEL kinds.
	ModelVersionHash string `json:"model_version_hash"`
	ModelProvider    string `json:"model_provider"` // NoneSentinel on non-MODEL
	ModelName        string `json:"model_name"`     // NoneSentinel on non-MODEL

	// --- Output capture ---
	OutputPrePostprocess string          `json:"output_pre_postprocess"`
	ExecutionResult      string          `json:"execution_result"`
	ToolCallLog          []ToolCallEntry `json:"tool_call_log"`

	// --- Causality and policy ---
	// CausalityChainHash = SHA3-256(JCS(provenance)) (§3.5, I3). Required and
	// non-empty for EVERY artifact, roots included — the provenance envelope is
	// never empty. Seal derives this; do not set it by hand.
	CausalityChainHash string             `json:"causality_chain_hash"`
	PolicyVersionHash  string             `json:"policy_version_hash"`
	AvailabilityPolicy AvailabilityPolicy `json:"availability_policy"`

	// --- Deployment and SDK ---
	DeploymentMode           DeploymentMode           `json:"deployment_mode"`
	SDKHashLayer             SDKHashLayer             `json:"sdk_hash_layer"`
	SDKBinarySHA3            string                   `json:"sdk_binary_sha3"`
	RegistryValidationStatus RegistryValidationStatus `json:"registry_validation_status"`

	// --- Signing and verification ---
	// SigningKeyID is a 64-hex Ed25519 public-key fingerprint (§4.5) — the same
	// grammar as parent_signing_key_id. No prefix.
	SigningKeyID string `json:"signing_key_id"`
	// SigningAttestation MUST carry omitempty — it is excluded from the JSON
	// used for record_hash computation. Changing this tag breaks signing.
	SigningAttestation string `json:"signing_attestation,omitempty"`

	// --- WORM integrity ---
	// LockVerificationLatencyMs is the AT-SEAL SNAPSHOT (0 in the server path).
	// A field cannot causally contain the latency of its own write; the
	// authoritative measured value lives in the ledger + DynamoDB metadata.
	LockVerificationLatencyMs int64   `json:"lock_verification_latency_ms"`
	InstrumentationCoverage   float64 `json:"instrumentation_coverage"`

	// --- Capture classification ---
	// CaptureLayer records where the agent input was captured: BUSINESS_LAYER
	// (decorator wrapping a business function) or LLM_LAYER (auto-instrumented
	// model call). Required plain string — a cross-language schema contract,
	// always present, validated as one of the two enum values by ValidateTierA.
	CaptureLayer string `json:"capture_layer"`
	// Consequential signals whether the action is consequential for
	// evidence-tier policy. Required plain bool, always serialized (true or
	// false). The producer sets it explicitly at seal time; NewRecord
	// defaults it to true so an unset producer fails safe (treats the action
	// as consequential) rather than silently downgrading.
	Consequential bool `json:"consequential"`

	// --- Envelopes (fields 30–32) — versioned, leniently parsed (§6) ---
	Provenance        Provenance        `json:"provenance"`
	GovernanceContext GovernanceContext `json:"governance_context"`
	ExecutionContext  ExecutionContext  `json:"execution_context"`
}

// topLevelKeys is the frozen set of 33 top-level field names. RecordFromJSON
// rejects any key outside this set (§6: the top-level object is parsed
// STRICTLY, envelopes leniently).
//
// It is a literal list rather than reflection over the struct tags on purpose:
// this set is the FROZEN CONTRACT, so it must not silently follow a struct edit.
// TestRecord_TopLevelKeysMatchStruct proves the two agree, which turns any
// divergence into a failing test instead of a silent schema change.
var topLevelKeys = map[string]struct{}{
	"record_id": {}, "record_version": {}, "created_at": {}, "evidence_tier": {},
	"decision_kind": {}, "principal_identity": {}, "action_type": {},
	"input_hash": {}, "authorization_token_id": {},
	"full_prompt_snapshot": {}, "rag_evidence_bundle": {},
	"model_version_hash": {}, "model_provider": {}, "model_name": {},
	"output_pre_postprocess": {}, "execution_result": {}, "tool_call_log": {},
	"causality_chain_hash": {}, "policy_version_hash": {}, "availability_policy": {},
	"deployment_mode": {}, "sdk_hash_layer": {}, "sdk_binary_sha3": {},
	"registry_validation_status": {}, "signing_key_id": {}, "signing_attestation": {},
	"lock_verification_latency_ms": {}, "instrumentation_coverage": {},
	"capture_layer": {}, "consequential": {},
	"provenance": {}, "governance_context": {}, "execution_context": {},
}

// TopLevelFieldCount is the frozen top-level field count (33). The signed count
// is 32 — signing_attestation is excluded from the hash.
const TopLevelFieldCount = 33

// =============================================================================
// Constructor
// =============================================================================

// present as "signature invalid" — indistinguishable, to an auditor, from
// tampering.
//
// So: hash the bytes you were given; interpret only the keys you know. That
// combination is exactly what makes forward-compatible evolution safe.
func RecordHashFromBytes(raw []byte) (string, error) {
	obj, err := parseCanonicalObject(raw)
	if err != nil {
		return "", err
	}
	// Delete the KEY — not "set it to empty". The canonical JSON must have no
	// signing_attestation key at all, which is what omitempty achieves on the
	// producer side.
	delete(obj, "signing_attestation")

	var buf bytes.Buffer
	if err := canonicalizeValue(&buf, obj); err != nil {
		return "", fmt.Errorf("record: canonicalize artifact bytes: %w", err)
	}
	return HashSHA3256(buf.Bytes()), nil
}

// CausalityHashFromBytes recomputes SHA3-256(JCS(provenance)) from an
// artifact's OWN BYTES (§4.6.1), for a verifier checking I3.
//
// Same reasoning as RecordHashFromBytes, one level down: re-marshaling the
// typed Provenance struct would drop an unknown envelope key and fail I3 on an
// artifact whose record_hash verifies fine — the §6 promise broken in a
// subtler and more confusing place.
func CausalityHashFromBytes(raw []byte) (string, error) {
	obj, err := parseCanonicalObject(raw)
	if err != nil {
		return "", err
	}
	prov, ok := obj["provenance"]
	if !ok {
		return "", fmt.Errorf("record: artifact has no provenance key")
	}
	var buf bytes.Buffer
	if err := canonicalizeValue(&buf, prov); err != nil {
		return "", fmt.Errorf("record: canonicalize provenance bytes: %w", err)
	}
	return HashSHA3256(buf.Bytes()), nil
}

// parseCanonicalObject parses raw into a generic JSON object tree, applying the
// same ingestion rules CanonicalizeJSON applies: duplicate keys rejected
// anywhere in the document (RFC 8785 forbids them, and Go's last-wins default
// would make the committed hash depend on an undocumented rule), numbers kept as
// json.Number so no float round-trip alters them, and trailing data rejected.
func parseCanonicalObject(raw []byte) (map[string]interface{}, error) {
	dupDec := json.NewDecoder(bytes.NewReader(raw))
	dupDec.UseNumber()
	if err := rejectDuplicateKeys(dupDec); err != nil {
		return nil, fmt.Errorf("record: invalid JSON: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed interface{}
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("record: invalid JSON: %w", err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("record: invalid JSON: %w", err)
		}
		return nil, fmt.Errorf("record: invalid JSON: unexpected trailing token %v", tok)
	}

	obj, ok := parsed.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("record: artifact is not a JSON object")
	}
	return obj, nil
}

// Seal signs the record for TIER-A attestation, enforcing the NORMATIVE build
// order of §3.5 so it cannot be got wrong:
//
//  1. Write signer.KeyID() into SigningKeyID so the hash covers the key ID.
//  2. BindCausality — causality_chain_hash = SHA3-256(JCS(provenance)).
//     Done HERE, not left to the caller: it is a signed field derived from
//     another signed field, so computing the record hash first would sign a
//     stale value, and no test of the resulting artifact could tell.
//  3. ValidateTierA.
//  4. Compute record_hash.
//  5. Ed25519-sign record_hash into SigningAttestation.
//
// Returns the record_hash that was signed. If validation fails, no signing
// occurs and SigningAttestation is left untouched.

func VerifyRecordBytes(raw []byte, publicKeyHex string) (ok bool, recordHash string, err error) {
	obj, err := parseCanonicalObject(raw)
	if err != nil {
		return false, "", err
	}
	sigVal, present := obj["signing_attestation"]
	if !present {
		return false, "", fmt.Errorf("record: signing_attestation absent; artifact was not sealed")
	}
	sig, isStr := sigVal.(string)
	if !isStr || sig == "" {
		return false, "", fmt.Errorf("record: signing_attestation is not a non-empty string")
	}

	hash, err := RecordHashFromBytes(raw)
	if err != nil {
		return false, "", err
	}
	valid, err := VerifyWithPublicKey(publicKeyHex, hash, sig)
	if err != nil {
		return false, hash, err
	}
	return valid, hash, nil
}

// =============================================================================
// Shared validation helpers
// =============================================================================

var lowerHex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// correlationIDRe matches §4.9's opaque-token grammar.
var correlationIDRe = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,128}$`)

// isISO8601UTC requires strict UTC: the timestamp MUST end with a literal "Z"
// suffix. Non-UTC offsets like "+05:30" are rejected, even though they parse
// as valid RFC 3339. Forensic evidence cannot carry timezone ambiguity — all
// record timestamps are normalized to UTC at issuance.
func isISO8601UTC(s string) bool {
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return true
	}
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return true
	}
	return false
}

func isValidAvailabilityPolicy(a AvailabilityPolicy) bool {
	return a == FallbackToTierB || a == BlockOnServiceUnavailable || a == ConfigurableByActionType
}

func isValidDeploymentMode(d DeploymentMode) bool {
	return d == SaaSManaged || d == CustomerHostedAttested || d == CustomerHostedUnattested
}

func isValidSDKHashLayer(s SDKHashLayer) bool {
	return s == ServiceEndpoint || s == SDKInternal
}

func isValidRegistryStatus(r RegistryValidationStatus) bool {
	return r == RegistryValidated || r == RegistryUnvalidated || r == RegistryBypassed
}

// IsValidSelector reports whether s is a legal consumed_output_selector (§4.1):
// an RFC 6901 JSON Pointer, NON-URI, SINGLE SEGMENT, addressing a top-level
// field of the parent record. Escaping is only "~"->"~0" and "/"->"~1".
//
// "" is legal here and means "no value consumed" — reserved for CONTROL-ONLY
// edges (§4.1). It is explicitly NOT "whole document", which is RFC 6901's
// meaning for the empty pointer; the pairing with a control relationship is
// checked by the edge validator, not here.
//
// Deeper paths are RESERVED and rejected in v1: a multi-segment pointer would
// let two artifacts disagree about what "the parent's output" means while both
// validating.
func IsValidSelector(s string) bool {
	if s == "" {
		return true // control-only sentinel; pairing checked by the caller
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	seg := s[1:]
	if seg == "" {
		return false
	}
	if strings.Contains(seg, "/") {
		return false // multi-segment: reserved in v1
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] == '~' {
			if i+1 >= len(seg) || (seg[i+1] != '0' && seg[i+1] != '1') {
				return false // dangling or invalid escape
			}
			i++
		}
	}
	return true
}

// =============================================================================
// JSON serialization
// =============================================================================

// ToJSON returns the record as JSON bytes. signing_attestation is the only
// omitempty field: it is dropped when unsealed and present once sealed. A
// sealed record serializes to 33 keys; an unsealed record to 32.
func (p *Record) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// RecordFromJSON deserializes a record from JSON, enforcing §6's parse
// strictness split: the TOP-LEVEL object rejects unknown keys, while the
// ENVELOPES tolerate them.
//
// encoding/json's DisallowUnknownFields is deliberately NOT used — it applies
// RECURSIVELY, which would reject exactly the additive envelope keys §6 promises
// to tolerate, inverting the rule this function exists to implement. So the
// top-level key set is checked explicitly and the struct decode is left lenient.
//
// Performs no value validation; callers should run ValidateTierA or verify as
// appropriate. Note that an artifact carrying an unknown envelope key survives
// this round trip semantically but NOT byte-wise — which is precisely why hash
// recomputation must go through RecordHashFromBytes (§4.6.1), never through
// this struct.

func RecordFromJSON(data []byte) (*Record, error) {
	var probe map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&probe); err != nil {
		return nil, fmt.Errorf("record: unmarshal: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("record: unmarshal: trailing data after top-level value")
	}
	for k := range probe {
		if _, known := topLevelKeys[k]; !known {
			return nil, fmt.Errorf("record: unknown top-level key %q (the 33-field list is frozen; new capability goes inside a versioned envelope, never as a new top-level field)", k)
		}
	}

	var p Record
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("record: unmarshal: %w", err)
	}
	return &p, nil
}
