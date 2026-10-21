// Package main — Standalone record verification CLI.
//
// plainreal-verify is a single Go binary with zero dependencies on PlainReal
// runtime infrastructure. Given a sealed record JSON file and
// PlainReal's published public key (PEM or hex), it independently verifies:
//
//  1. The JSON parses as a valid Record (structurally).
//  2. The record meets TIER-A field requirements (for TIER-A artifacts).
//  3. The record_hash = SHA3-256(JCS(record sans signing_attestation)).
//  4. The Ed25519 signing_attestation is valid for that hash and public key.
//  5. (Optional) The RFC 3161 timestamp .tsr matches the record_hash.
//
// Exit codes:
//
//	0 — VERIFIED: artifact is authentic and unmodified.
//	1 — FAILED  : verification failed (possible tampering or wrong key).
//	2 — ERROR   : input problem (file missing, malformed, bad flags, etc.).
//
// This CLI makes NO network calls at runtime and requires NO PlainReal
// account, API key, service, or SDK. It is the single artifact an auditor
// runs on the CCO's workstation (or their own) to confirm a Decision
// Record has not been modified since PlainReal signed it.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/plainreal/verify/verifycore"
)

// =============================================================================
// Constants
// =============================================================================

// Version is this binary's RELEASE version, surfaced via --version.
//
// One number for the page and the CLI, because they ship under one signed tag:
// see docs/VERIFIER_RELEASE_PLAN.md. It is injected at build time from
// verifier/page/VERSION so there is a single source, and the release preflight
// fails if the binary, the page and the tag disagree.
//
// The default below is what an unstamped `go build` produces. It is deliberately
// not a plausible version number: a binary that says "dev" is obviously not a
// release, whereas one that says 1.1.0 because someone forgot -ldflags is a
// binary claiming to be something it is not.
var Version = "dev"

// init recovers the version for a `go install ...@vX.Y.Z` build.
//
// The release build passes -ldflags "-X main.Version=...", but `go install`
// cannot pass ldflags, so an installed binary reported "dev" in the header of
// every report it produced. The report naming its own build is the whole point
// of that line, and "dev" names nothing.
//
// Go records the module version in the binary for a versioned install. A local
// `go install ./...` has Main.Version "(devel)" and is left as "dev", which is
// honest: that build came from a working tree, not a tagged release.
func init() {
	Version = resolveVersion(Version, debug.ReadBuildInfo)
}

// resolveVersion picks the version string the report will carry.
//
// Split out of init so it can be tested: the init path runs once, before any
// test can arrange the inputs, and this is the logic that decides what every
// report claims about its own provenance.
func resolveVersion(current string, read func() (*debug.BuildInfo, bool)) string {
	if current != "dev" {
		return current // an explicit -ldflags value always wins
	}
	bi, ok := read()
	if !ok || bi == nil || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return current
	}
	return strings.TrimPrefix(bi.Main.Version, "v")
}

// Exit codes — stable public contract consumed by auditor scripts.
const (
	ExitVerified = 0 // Artifact authentic and unmodified.
	ExitFailed   = 1 // Verification failed (artifact problem).
	ExitError    = 2 // Input problem (not an artifact judgment).
)

// pemPublicKeyType is the only PEM block type accepted for the public key.
const pemPublicKeyType = "PUBLIC KEY"

// ed25519PublicKeyHexLen is the expected length of an Ed25519 public key
// encoded as lowercase hex (32 bytes * 2 chars).
const ed25519PublicKeyHexLen = 64

// =============================================================================
// Result types — stable JSON schema for --json output
// =============================================================================

// Outcome is the verdict vocabulary, deliberately identical to the five names
// the web verifier uses in src/record.js. Both tools reaching for the same word
// is what lets the agreement gate compare them at all; before this existed the
// CLI had two words (VERIFIED / FAILED) for the page's five, so "signed by a
// key you do not hold" arrived as a red FAILED on a record that was intact.
//
// The exit code is a SEPARATE, coarser contract and does not change here:
// scripts testing `exit == 1` keep working, because UNKNOWN_KEY still means
// "not verified with the key you supplied".
type Outcome string

const (
	OutcomeVerified          Outcome = "VERIFIED"
	OutcomeFailsVerification Outcome = "FAILS_VERIFICATION"
	OutcomeNotARecord        Outcome = "NOT_A_RECORD"
	OutcomeCouldNotVerify    Outcome = "COULD_NOT_VERIFY"
	OutcomeUnknownKey        Outcome = "UNKNOWN_KEY"
)

// VerificationResult captures the full outcome of a verification run.
// The struct is the JSON schema emitted by --json; consumers depend on
// field names and types. Adding a field is safe; renaming one is not.
type VerificationResult struct {
	// ToolVersion is the build that produced this verdict, and SchemaVersions
	// the record schemas it accepts. In the JSON contract for the same reason
	// they are in the human report: a stored verdict nobody can attribute to a
	// build is not reproducible.
	ToolVersion    string   `json:"tool_version"`
	SchemaVersions []string `json:"schema_versions"`

	Verified bool `json:"verified"`
	// Outcome is the five-value verdict. Additive to the JSON contract; the
	// existing `verified` boolean is unchanged and still means "VERIFIED".
	Outcome Outcome `json:"outcome"`
	// Path is the file this verdict is about.
	//
	// Added when batch landed, because without it a --json array is unusable: a
	// record that could not be read has no record_id, and several copies of the
	// same artifact share one, so a consumer could not map a verdict back to a
	// file. Additive, so the single-record object contract is unchanged.
	Path           string `json:"path,omitempty"`
	RecordID       string `json:"record_id"`
	RecordVersion  string `json:"record_version,omitempty"`
	EvidenceTier   string `json:"evidence_tier"`
	RecordHash     string `json:"record_hash,omitempty"`
	SignatureValid bool   `json:"signature_valid"`
	TimestampValid *bool  `json:"timestamp_valid,omitempty"`
	// TimestampIssuerVerified reports whether the TSA signing certificate was
	// anchored to a caller-supplied trusted root (--tsa-root). When false, the
	// timestamp's MessageImprint and GenTime were checked but the issuer's
	// identity was NOT established — a self-signed .tsr would pass, so the time
	// proof is not forgery-resistant. nil when no timestamp was checked.
	TimestampIssuerVerified *bool      `json:"timestamp_issuer_verified,omitempty"`
	TimestampGenTime        *time.Time `json:"timestamp_gen_time,omitempty"`
	FailureReason           string     `json:"failure_reason,omitempty"`
	Checks                  []Check    `json:"checks"`

	// Level is the verification level this run performed (§7.2). 0 = the
	// record alone, offline. Level 1 (chain-aware, from a bundle) lands in
	// M3 — this binary cannot walk a chain and does not pretend to.
	Level int `json:"level"`
	// InvariantsChecked names the invariants this run actually verified, and
	// InvariantsDeferred names the ones it did NOT, each with the reason.
	//
	// Both are emitted on every run, including a clean VERIFIED. A verifier
	// that prints "VERIFIED" without stating what it left unchecked invites the
	// reader to assume it checked everything — and an auditor relying on that
	// assumption would overstate the evidence in front of a court. §5 requires
	// coverage to be stated and never inferred; that rule binds this output as
	// much as it binds the spec.
	InvariantsChecked  []string            `json:"invariants_checked"`
	InvariantsDeferred []DeferredInvariant `json:"invariants_deferred"`
	// ValidationIssues lists every local-invariant violation verbatim, so a
	// failure is actionable from the JSON alone rather than only from the
	// human-readable Details string.
	ValidationIssues []string `json:"validation_issues,omitempty"`
	// Metadata surfaces the capture_layer and consequential classification
	// fields directly in the result so an auditor sees them without parsing
	// the record body. Both are required v1.0.0 fields, always present.
	Metadata ResultMetadata `json:"metadata"`

	// view is what the human report shows about the record, read once from
	// its bytes. Unexported, so not part of the JSON contract.
	view recordView
}

// DeferredInvariant names an invariant this verification level did NOT check,
// and why. Emitted so the gap is explicit in machine-readable output rather
// than something a reader has to know to ask about.
type DeferredInvariant struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// level0Invariants are the invariants checkable from a single artifact, which
// is exactly what ValidateArtifactBytes enforces (§5, §7.2).
var level0Invariants = []string{
	"I2 (relationship enum)",
	"I3 (causality_chain_hash == SHA3-256(JCS(provenance)))",
	"I4 (hash-only envelopes, structural)",
	"I5 (defined sentinels)",
	"I6 (self-edge; acyclicity is by construction)",
	"I7a (SELECTED_FROM requires >=1 CONSIDERED_ALTERNATIVE)",
	"I8a (PROD retention floor)",
	"I9 (decisive-call binding)",
	"I10 (edge uniqueness)",
	"I12 (kind conformance, incl. human:<64-hex> grammar)",
	"I13 (attempt status/sentinels, local slice)",
	"I14a (PRE_AUTHORIZED carries an authorizing edge)",
	"the schema selector grammar, the schema sort order",
}

// level0Deferred are the invariants a Level-0 run CANNOT check, with the reason
// stated in the artifact-consumer's terms. These are not bugs; they are the
// honest boundary of what one artifact can prove about itself.
var level0Deferred = []DeferredInvariant{
	{
		ID: "the agent's input was what was authorized",
		Reason: "the record holds only a hash of the input, not the input. " +
			"Checking it needs the agent_input.json this record came with. [I1]",
	},
	{
		ID: "the parent records exist and are unaltered",
		Reason: "this record names its parents by hash. Confirming a parent is " +
			"really there, and really the one named, means fetching it. [I6 chain]",
	},
	{
		ID: "every alternative considered was recorded",
		Reason: "a candidate that was never written down leaves no trace here. " +
			"Confirming the set is complete needs the issuing service's own " +
			"authorization trail. [I7b]",
	},
	{
		ID:     "the parent's retention outlives this record's",
		Reason: "comparing the two retention horizons needs the parent record. [I8b]",
	},
	{
		ID:     "parent and child belong to the same tenant",
		Reason: "the parent's tenant is in the parent, not here. [I11]",
	},
	{
		ID: "no attempt was left out",
		Reason: "an attempt the producer never recorded is invisible to any " +
			"check of this file. Detecting omission needs a witness outside " +
			"the record. This is a stated limit, not a gap to be closed. [I13]",
	},
	{
		ID: "a required human approval actually happened",
		Reason: "this record can declare that an approval was required. The " +
			"approval comes AFTER the decision, and records only ever point " +
			"backwards, so the proof is in the later record, not this one. [I14b]",
	},
}

// ResultMetadata is a convenience view of the capture-classification fields,
// copied verbatim from the record. Always present.
type ResultMetadata struct {
	CaptureLayer  string `json:"capture_layer"`
	Consequential bool   `json:"consequential"`
}

// Check is a single verification step's outcome. Every check the CLI runs
// produces exactly one entry, in the order checks were executed. Early
// termination on first failure is indicated by a Passed=false entry being
// the last item in the slice.
type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// =============================================================================
// Public key loading
// =============================================================================

// loadPublicKey returns the Ed25519 public key as a lowercase hex string,
// loaded either from a PEM file (keyPath) or directly as hex (keyHex).
// Exactly one of keyPath or keyHex must be non-empty.
func loadPublicKey(keyPath, keyHex string) (string, error) {
	if keyPath != "" && keyHex != "" {
		return "", errors.New("use either --key or --key-hex, not both")
	}
	if keyPath == "" && keyHex == "" {
		return "", errors.New("public key required: provide --key or --key-hex")
	}
	if keyHex != "" {
		return validatePublicKeyHex(keyHex)
	}
	return loadPublicKeyPEM(keyPath)
}

// loadPublicKeyPEM reads an Ed25519 public key from a PKIX-encoded PEM file
// and returns its raw 32 bytes as lowercase hex.
func loadPublicKeyPEM(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read public key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("invalid PEM format in %s: no PEM block found", path)
	}
	if block.Type != pemPublicKeyType {
		return "", fmt.Errorf("invalid PEM format in %s: expected %q block, got %q",
			path, pemPublicKeyType, block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse PKIX public key in %s: %w", path, err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("expected Ed25519 public key, got %T", pub)
	}
	if len(edPub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("ed25519 public key has wrong byte length: got %d, want %d",
			len(edPub), ed25519.PublicKeySize)
	}
	return hex.EncodeToString(edPub), nil
}

// loadTSARoots reads one or more PEM CERTIFICATE blocks from path and returns
// them as an x509.CertPool for anchoring the .tsr issuer (--tsa-root). Returns
// an error if the file has no valid certificate, so a typo'd root path fails
// loudly rather than silently leaving the timestamp issuer unverified.
func loadTSARoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read TSA root file %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("TSA root file %s contains no valid PEM certificate", path)
	}
	return pool, nil
}

// validatePublicKeyHex enforces format rules on a --key-hex value: exactly
// 64 characters, all lowercase hex digits. Returns the input unchanged on
// success so callers can use it directly.
func validatePublicKeyHex(s string) (string, error) {
	if len(s) != ed25519PublicKeyHexLen {
		return "", fmt.Errorf("public key hex must be exactly 64 characters (32 bytes), got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("public key hex is not valid hexadecimal: %w", err)
	}
	if strings.ToLower(s) != s {
		return "", fmt.Errorf("public key hex must be lowercase")
	}
	return s, nil
}

// =============================================================================
// Record loading
// =============================================================================

// loadRecord reads a record file. It is a READER, not a judge: the only thing
// it refuses is a file that is not JSON at all, which was never a record, so
// nothing was checked and there is nothing to accuse (exit 2). Everything else,
// a duplicate key, an unknown field, a wrong type, is a verdict about the
// artifact, and verifyRecord reaches it in the order the browser page does.
//
// It returns the RAW BYTES alongside. The bytes are the evidence; the struct is
// only an interpretation of them. Every hash this CLI recomputes must come
// from the bytes (§4.6.1) — see verifyRecord.
func loadRecord(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read record file %s: %w", path, err)
	}
	// The browser page draws exactly this line and says why: crying tamper on
	// garbage makes the real tamper result look like theatre, and it is the
	// first thing a sceptical reader tries.
	if !json.Valid(data) {
		return nil, fmt.Errorf("%s is not JSON, so it is not a record; nothing was checked", path)
	}
	return data, nil
}

// =============================================================================
// Verification — the critical path
// =============================================================================

// The order of the questions is the browser page's, and it is the same order
// in both tools so that both give the same verdict on the same bytes:
//
//  1. Is it a JSON object, read strictly (no duplicate keys, no unsafe
//     integers)? Does it name its version, id and key? Is it sealed?
//  2. Are the signature and key id well formed?
//  3. Does it declare the key you supplied?            -> DIFFERENT SIGNING KEY
//  4. Does the signature match the bytes?              -> FAILS VERIFICATION
//  5. Is it a schema version this binary knows?        -> COULD NOT VERIFY
//  6. Is it a conformant record: the 33 fields, their types, a known tier,
//     and for TIER-A every field rule and the local invariants?
//                                                      -> NOT A CONFORMANT RECORD
//  7. The RFC 3161 token, when one is supplied.
//
// The signature comes before conformance on purpose. A record edited after
// sealing is ALTERED, and saying so is the most serious true thing about it,
// even when the edit also broke a rule. Until v1.2.0 this binary checked the
// fields first and reported such a record as non-conformant, while the page
// reported it as altered; the two now agree, and a release gate holds them to
// the same verdict.

var (
	signatureHexRe = regexp.MustCompile(`^[0-9a-f]{128}$`)
	keyIDHexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// rawString returns the string value of a top-level key, and whether the key
// is present with a string value. Read from the generic object, never from the
// struct, because these questions are asked before the record is known to
// decode.
func rawString(obj map[string]json.RawMessage, key string) (string, bool) {
	v, ok := obj[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// verifyRecord runs every verification check against the artifact's RAW BYTES
// and the supplied public key, in the order above. It stops at the first
// failed check, because the later ones would describe a record that is not
// what it claims, but records every check it ran in result.Checks, in order.
// The returned result is always non-nil unless error is non-nil; error is for
// a document that is not a JSON object read strictly, and for
// impossible-to-report internal faults.
//
// It takes the raw bytes because §4.6.1 makes them, not a parsed struct, the
// thing that gets hashed. An auditor holds a file and a public key; this
// function is that auditor.
func verifyRecord(raw []byte, publicKeyHex, tsrPath string, tsaRoots *x509.CertPool) (*VerificationResult, error) {
	// Step 1. The strict read. RecordHashFromBytes rejects duplicate keys,
	// unsafe integers and a non-object, exactly as the page's reader does, and
	// the hash it returns is the one the signature is checked against below.
	//
	// The whole document is canonicalized first, signing_attestation
	// included. RecordHashFromBytes removes that key before canonicalizing, so
	// on its own it never saw an unsafe integer or an out-of-range number
	// written there, and the CLI called such a record FAILS VERIFICATION where
	// the page, whose reader refuses the number wherever it is, says it is not
	// a record.
	if _, err := verifycore.CanonicalizeJSON(raw); err != nil {
		return nil, rejectArtifact("%s", strings.TrimPrefix(err.Error(), "record: "))
	}
	hash, err := verifycore.RecordHashFromBytes(raw)
	if err != nil {
		return nil, rejectArtifact("%s", strings.TrimPrefix(err.Error(), "record: "))
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, rejectArtifact("%v", err)
	}

	view := viewOf(raw)
	result := &VerificationResult{
		view:               view,
		ToolVersion:        Version,
		SchemaVersions:     verifycore.SupportedRecordVersions(),
		RecordID:           view.RecordID,
		RecordVersion:      view.RecordVersion,
		EvidenceTier:       view.EvidenceTier,
		Checks:             []Check{},
		Level:              0, // record alone; Level 1 (chain) is not this binary
		InvariantsChecked:  level0Invariants,
		InvariantsDeferred: level0Deferred,
		Metadata: ResultMetadata{
			CaptureLayer:  view.CaptureLayer,
			Consequential: view.Consequential,
		},
	}
	result.Checks = append(result.Checks, Check{
		Name:    "JSON Parse",
		Passed:  true,
		Details: "read strictly: no duplicate keys, no integers beyond ±(2^53-1)",
	})

	var missing []string
	for _, k := range []string{"record_version", "record_id", "signing_key_id"} {
		if _, ok := obj[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, rejectArtifact("valid JSON, but missing %s, which every record carries, "+
			"so there is no record here to verify", strings.Join(missing, ", "))
	}

	// A record-shaped document with no signature was never sealed. That is a
	// different thing from a broken signature and must not read as one.
	if _, sealed := obj["signing_attestation"]; !sealed {
		result.Checks = append(result.Checks, Check{
			Name:    "Signature Present",
			Passed:  false,
			Details: "no signing_attestation",
		})
		result.Outcome = OutcomeNotARecord
		result.FailureReason = "record is not sealed (no signature)"
		return result, nil
	}

	// Step 2. A signature field holding something that is not a signature is a
	// statement about this record, so it does not verify. It used to be
	// COULD_NOT_VERIFY here, "no verdict", which undersold it.
	signature, _ := rawString(obj, "signing_attestation")
	if !signatureHexRe.MatchString(signature) {
		result.Checks = append(result.Checks, Check{
			Name:    "Signature",
			Passed:  false,
			Details: "signing_attestation is not a 128-character lowercase hex signature",
		})
		result.Outcome = OutcomeFailsVerification
		result.FailureReason = "signing_attestation is not a 128-character lowercase hex signature, " +
			"so there is nothing to check it against"
		return result, nil
	}
	keyID, _ := rawString(obj, "signing_key_id")
	if !keyIDHexRe.MatchString(keyID) {
		result.Checks = append(result.Checks, Check{
			Name:    "Signature",
			Passed:  false,
			Details: "signing_key_id is not a 64-character lowercase hex fingerprint",
		})
		result.Outcome = OutcomeFailsVerification
		result.FailureReason = "signing_key_id is not a 64-character lowercase hex fingerprint"
		return result, nil
	}

	// Step 3. Is it signed by the key we were handed? BEFORE the signature,
	// deliberately: checking against a key the record says is not its own
	// would report a failed signature for a record that is very likely fine.
	//
	// signing_key_id is SHA3-256 of the raw public key (§4.5) and it is a
	// signed field, so a record whose signature verifies under your key while
	// naming another key misstates its own signer. Until v1.2.0 this binary
	// checked the key id only after a signature failed, and so VERIFIED that
	// record; the page did not. Now neither does.
	pubBytes, decErr := hex.DecodeString(publicKeyHex)
	if decErr != nil {
		return nil, fmt.Errorf("decode public key: %w", decErr)
	}
	if want := verifycore.HashSHA3256(pubBytes); keyID != want {
		result.Checks = append(result.Checks, Check{
			Name:   "Signing Key",
			Passed: false,
			Details: fmt.Sprintf("record declares signing_key_id %s…, the supplied key is %s…",
				keyID[:16], want[:16]),
		})
		result.Outcome = OutcomeUnknownKey
		// "Names", not "was signed by": the declared id is all that was compared.
		// Usually the record was signed by the key it names; when its signature
		// verifies under yours instead, it misstates its own signer. Either
		// way the record does not name the key you supplied.
		// "different key" stays at the front: failure_reason is the machine
		// contract, and scripts match on it.
		result.FailureReason = "different key: the record names a signing key other than the one you supplied, " +
			"which is NOT the same as the record having been altered"
		return result, nil
	}
	result.Checks = append(result.Checks, Check{
		Name:    "Signing Key",
		Passed:  true,
		Details: "the record declares the key you supplied",
	})

	// Step 4. The signature, over record_hash recomputed FROM THE ARTIFACT'S
	// OWN BYTES as generic JSON (§4.6.1). Not a struct round trip: unmarshaling
	// and re-marshaling drops any key this binary does not know, which would
	// reject a valid artifact as "signature invalid", indistinguishable from
	// tampering, and make §6's additive-evolution promise false.
	result.RecordHash = hash
	result.Checks = append(result.Checks, Check{
		Name:    "Record Hash Computed",
		Passed:  true,
		Details: hash,
	})
	valid, err := verifycore.VerifyWithPublicKey(publicKeyHex, hash, signature)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:    "Signature",
			Passed:  false,
			Details: err.Error(),
		})
		result.Outcome = OutcomeCouldNotVerify
		result.FailureReason = "signature verification error: " + err.Error()
		return result, nil
	}
	result.SignatureValid = valid
	if !valid {
		result.Checks = append(result.Checks, Check{
			Name:    "Signature",
			Passed:  false,
			Details: "signature does not match record content",
		})
		result.Outcome = OutcomeFailsVerification
		result.FailureReason = "signature verification failed; record may have been tampered with"
		return result, nil
	}
	result.Checks = append(result.Checks, Check{
		Name:    "Signature",
		Passed:  true,
		Details: "Ed25519 signature valid",
	})

	// Step 5. A schema version this binary knows. COULD NOT VERIFY, not a
	// failure: the field set below is version-specific, and a newer record is
	// very likely fine.
	if !verifycore.IsSupportedRecordVersion(view.RecordVersion) {
		result.Checks = append(result.Checks, Check{
			Name:    "Record Version",
			Passed:  false,
			Details: unsupportedVersionMessage(view.RecordVersion),
		})
		result.Outcome = OutcomeCouldNotVerify
		result.FailureReason = unsupportedVersionMessage(view.RecordVersion)
		return result, nil
	}
	result.Checks = append(result.Checks, Check{
		Name:    "Record Version",
		Passed:  true,
		Details: view.RecordVersion,
	})

	// Step 6. Conformance. The signature is valid, so each refusal below says
	// so: the record was signed like this.
	notConformant := func(name, details, reason string, issues []string) (*VerificationResult, error) {
		result.Checks = append(result.Checks, Check{Name: name, Passed: false, Details: details})
		result.Outcome = OutcomeNotARecord
		result.FailureReason = reason + "; the signature is valid, so this is not a claim that anything was altered"
		result.ValidationIssues = issues
		return result, nil
	}

	// 6a. The 33 fields, frozen, and their JSON types.
	record, err := verifycore.RecordFromJSON(raw)
	if err != nil {
		msg := strings.TrimPrefix(err.Error(), "record: ")
		return notConformant("Record Structure", msg, msg, []string{msg})
	}
	result.Checks = append(result.Checks, Check{
		Name:    "Record Structure",
		Passed:  true,
		Details: "all 33 fields present, none added, every JSON type as the schema defines",
	})

	// 6b. A tier that exists. A fabricated "PRIMARY-EVIDENCE" must not borrow
	// TIER-A's credibility on the strength of a bare signature.
	if !isKnownTier(record.EvidenceTier) {
		return notConformant("Evidence Tier",
			fmt.Sprintf("unrecognized evidence_tier %q (must be one of %s, %s, %s)",
				record.EvidenceTier, verifycore.TierA, verifycore.TierB, verifycore.TierC),
			fmt.Sprintf("unrecognized evidence_tier %q", record.EvidenceTier),
			[]string{"evidence_tier"})
	}

	// 6c. TIER-A: every field rule and the local invariants. ValidateArtifactBytes,
	// not ValidateTierA: I3's expected digest must come from THIS artifact's
	// provenance as generic JSON (§4.6.1 / §6).
	if record.EvidenceTier == verifycore.TierA {
		_, issues, vErr := verifycore.ValidateArtifactBytes(raw)
		if vErr != nil {
			return nil, fmt.Errorf("validate artifact: %w", vErr)
		}
		if len(issues) > 0 {
			return notConformant("TIER-A Validation + Local Invariants",
				fmt.Sprintf("%d issue(s): %s", len(issues), strings.Join(issues, ", ")),
				"TIER-A validation failed", issues)
		}
		result.Checks = append(result.Checks, Check{
			Name:   "TIER-A Validation + Local Invariants",
			Passed: true,
			Details: fmt.Sprintf("schema %s: all required fields valid; local invariants hold (%s)",
				record.RecordVersion, strings.Join(level0Invariants, "; ")),
		})
	}

	// Check 7 — RFC 3161 timestamp (optional).
	if tsrPath != "" {
		tsValid, tsTime, issuerVerified, tsErr := verifyTimestamp(tsrPath, hash, tsaRoots)
		result.TimestampValid = &tsValid
		result.TimestampIssuerVerified = &issuerVerified
		if tsTime != nil {
			result.TimestampGenTime = tsTime
		}
		if tsErr != nil {
			result.Checks = append(result.Checks, Check{
				Name:    "RFC 3161 Timestamp",
				Passed:  false,
				Details: tsErr.Error(),
			})
			result.Outcome = OutcomeFailsVerification
			result.FailureReason = "timestamp verification failed: " + tsErr.Error()
			return result, nil
		}
		details := fmt.Sprintf("valid at %s", tsTime.Format(time.RFC3339))
		if issuerVerified {
			details += "; TSA certificate anchored to a trusted root"
		} else {
			details += "; TSA issuer NOT verified (no --tsa-root supplied)"
		}
		result.Checks = append(result.Checks, Check{
			Name:    "RFC 3161 Timestamp",
			Passed:  true,
			Details: details,
		})
	}

	result.Verified = true
	result.Outcome = OutcomeVerified
	return result, nil
}

// recordView is what the report shows about a record, read from its bytes.
//
// Not from the decoded struct: a record can now be refused AFTER its signature
// verified, for a field the struct cannot hold, and the report must still say
// which record it is about. A value of the wrong type shows as absent.
type recordView struct {
	RecordID, RecordVersion, EvidenceTier, Principal, ActionType, CreatedAt string
	ModelProvider, ModelName, SigningKeyID, CaptureLayer                    string
	Consequential                                                           bool
	Upstream                                                                int
}

func viewOf(raw []byte) recordView {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(raw, &obj)
	str := func(k string) string { s, _ := rawString(obj, k); return s }
	v := recordView{
		RecordID: str("record_id"), RecordVersion: str("record_version"),
		EvidenceTier: str("evidence_tier"), Principal: str("principal_identity"),
		ActionType: str("action_type"), CreatedAt: str("created_at"),
		ModelProvider: str("model_provider"), ModelName: str("model_name"),
		SigningKeyID: str("signing_key_id"), CaptureLayer: str("capture_layer"),
	}
	_ = json.Unmarshal(obj["consequential"], &v.Consequential)
	var prov struct {
		Upstream []json.RawMessage `json:"upstream"`
	}
	if json.Unmarshal(obj["provenance"], &prov) == nil {
		v.Upstream = len(prov.Upstream)
	}
	return v
}

// isKnownTier reports whether t is one of the three defined evidence tiers.
// An artifact carrying any other value is rejected rather than verified, so a
// downgraded or fabricated tier cannot skip the TIER-A field checks.
func isKnownTier(t verifycore.EvidenceTier) bool {
	return t == verifycore.TierA || t == verifycore.TierB || t == verifycore.TierC
}

// unsupportedVersionMessage is the exact stderr / FailureReason string used
// when the record carries a record_version this binary does not know.
// The format is stable — auditor tooling greps for "unsupported record
// version" — and lists the supported versions verbatim so operators see
// which verify binary they need.
func unsupportedVersionMessage(got string) string {
	return fmt.Sprintf(
		"unsupported record version: %s; supported: %s",
		got,
		strings.Join(verifycore.SupportedRecordVersions(), ", "),
	)
}

// supportedVersionsLine is the stable stdout payload for --version-info.
// Format: comma-space separated, newest first, one trailing newline.
// Stable contract — auditor scripts may pipe this into version compat
// checks.
func supportedVersionsLine() string {
	return strings.Join(verifycore.SupportedRecordVersions(), ", ") + "\n"
}

// =============================================================================
// RFC 3161 timestamp verification
// =============================================================================

// verifyTimestamp reads an RFC 3161 .tsr file and confirms that its
// MessageImprint matches expectedHashHex (the record_hash), that a GenTime is
// present, and — when roots is non-nil — that the TSA signing certificate
// chains to one of those trusted roots with the timestamping extended key
// usage. It returns (valid, genTime, issuerVerified, err).
//
// TRUST ANCHORING (finding C2): digitorus ParseResponse verifies the token
// signature only against the certificate EMBEDDED in the token — it passes a
// nil truststore to pkcs7, so it does NOT anchor that certificate to a trusted
// root. A self-signed .tsr therefore parses without error. This function closes
// that gap: when the caller supplies --tsa-root, the embedded TSA certificate
// is verified against those roots (issuerVerified=true) and a forged self-signed
// timestamp is rejected. When roots is nil, the MessageImprint and GenTime are
// still checked but issuerVerified is false — the caller is warned that the
// third-party time proof is not forgery-resistant without a trusted root.
func verifyTimestamp(tsrPath, expectedHashHex string, roots *x509.CertPool) (bool, *time.Time, bool, error) {
	data, err := os.ReadFile(tsrPath)
	if err != nil {
		return false, nil, false, fmt.Errorf("read timestamp file %s: %w", tsrPath, err)
	}
	if len(data) == 0 {
		return false, nil, false, fmt.Errorf("timestamp file %s is empty", tsrPath)
	}

	tsToken, err := timestamp.ParseResponse(data)
	if err != nil {
		return false, nil, false, fmt.Errorf("parse RFC 3161 response: %w", err)
	}

	expectedHash, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		return false, nil, false, fmt.Errorf("expected hash not valid hex: %w", err)
	}
	if !bytes.Equal(tsToken.HashedMessage, expectedHash) {
		return false, nil, false, fmt.Errorf(
			"MessageImprint mismatch: timestamp is for hash %x, record hash is %x",
			tsToken.HashedMessage, expectedHash)
	}

	if tsToken.Time.IsZero() {
		return false, nil, false, errors.New("timestamp has no GenTime")
	}
	gen := tsToken.Time.UTC()

	issuerVerified := false
	if roots != nil {
		if err := verifyTSACertChain(tsToken, roots); err != nil {
			return false, &gen, false, fmt.Errorf("TSA certificate not trusted: %w", err)
		}
		issuerVerified = true
	}

	return true, &gen, issuerVerified, nil
}

// verifyTSACertChain verifies that the ACTUAL signer of the timestamp token
// chains to one of the supplied trusted roots at the token's GenTime, and that
// that signer carries the timestamping extended key usage.
//
// It must NOT assume the signer is Certificates[0]: the CMS `certificates`
// field is an ASN.1 SET, so its order is unspecified — a real TSA may embed
// [intermediate, leaf] and a hostile .tsr may embed a genuine trusted cert as a
// decoy at index 0 while being signed by an untrusted cert referenced later.
// So we re-parse the token with pkcs7 and use VerifyWithChainAtTime, which
// binds the chain check to the certificate the SignerInfo issuer+serial
// actually references (the true signer) — closing both the false-reject of a
// legitimately-ordered multi-cert chain and the decoy-cert trust bypass.
func verifyTSACertChain(tsToken *timestamp.Timestamp, roots *x509.CertPool) error {
	if len(tsToken.RawToken) == 0 {
		return errors.New("timestamp token has no raw bytes for chain verification")
	}
	p7, err := pkcs7.Parse(tsToken.RawToken)
	if err != nil {
		return fmt.Errorf("parse timestamp token: %w", err)
	}
	// Binds the signature to the issuer+serial-referenced signer AND chains that
	// signer to the trusted roots at GenTime (defaults to ExtKeyUsageAny).
	if err := p7.VerifyWithChainAtTime(roots, tsToken.Time); err != nil {
		return err
	}
	// Enforce the timestamping EKU on the ACTUAL signer (RFC 3161 requires it).
	signer := p7.GetOnlySigner()
	if signer == nil {
		return errors.New("timestamp token does not have a single signer certificate")
	}
	for _, eku := range signer.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return nil
		}
	}
	return errors.New("TSA signer certificate lacks the timestamping extended key usage")
}

// =============================================================================
// Colour
// =============================================================================
//
// Colour is an ENHANCEMENT and never the only signal. The [x] and [!] markers
// carry the verdict on their own, so a reader piping to a file, running in a
// pipeline, or using a screen reader loses nothing. That is not politeness: a
// verification tool whose result is legible only in a colour terminal has a
// verdict some readers cannot receive.
//
// Off automatically when stdout is not a terminal, so redirecting to a file or
// piping to grep never embeds escape codes in something an auditor may attach
// to a report. NO_COLOR is honoured (no-color.org), and --color overrides both.

type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p palette) ok(s string) string   { return p.wrap("32", s) } // green
func (p palette) bad(s string) string  { return p.wrap("31", s) } // red
func (p palette) warn(s string) string { return p.wrap("33", s) } // amber

// info is the fifth verdict colour, for UNKNOWN_KEY. It exists because amber
// was doing double duty: "I could not check this" and "this is not my key" are
// different things to tell a reader, and the second is not a problem with the
// record at all. Cyan rather than a second shade of amber, so the two stay
// apart for a reader with limited colour discrimination.
func (p palette) info(s string) string   { return p.wrap("36", s) } // cyan
func (p palette) dim(s string) string    { return p.wrap("2", s) }
func (p palette) bold(s string) string   { return p.wrap("1", s) }
func (p palette) header(s string) string { return p.wrap("1;36", s) }

// newPalette decides whether to colour. mode is auto, always or never.
func newPalette(mode string, w io.Writer) palette {
	switch mode {
	case "always":
		return palette{on: true}
	case "never":
		return palette{on: false}
	}
	if os.Getenv("NO_COLOR") != "" {
		return palette{on: false}
	}
	f, ok := w.(*os.File)
	if !ok {
		return palette{on: false}
	}
	info, err := f.Stat()
	if err != nil {
		return palette{on: false}
	}
	return palette{on: info.Mode()&os.ModeCharDevice != 0}
}

// =============================================================================
// Output formatters
// =============================================================================

// printJSON writes the VerificationResult as indented JSON to w.
// Schema is the stable --json contract — consumers may depend on field
// names and nesting.
func printJSON(w io.Writer, r *VerificationResult) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result JSON: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

// printHuman writes the human-readable verification report. Plain ASCII
// markers ([x] / [!]) for cross-terminal and clipboard-copy compatibility.
func printHuman(w io.Writer, r *VerificationResult, p recordView, verbose bool, c palette) {
	// The tool and schema versions belong IN the report.
	//
	// This output is meant to be pasted into an audit file or attached to a
	// finding, and read by someone who was not at the keyboard. Without a
	// version they cannot tell which build produced it, cannot reproduce it,
	// and cannot tell whether a later release changed a verdict. We spent a
	// release making the version consistent across the page, the binary and
	// the tag, and then left it out of the one artifact a reader keeps.
	title := "PlainReal Record Verification"
	subtitle := "plainreal-verify " + Version +
		"  ·  record schema " + strings.Join(verifycore.SupportedRecordVersions(), ", ")
	fmt.Fprintln(w, c.bold(title))
	fmt.Fprintln(w, c.dim(subtitle))
	// The rule is measured, not typed. It was a fixed 40 characters, which was
	// right until the version line appeared underneath it at 46 and left the
	// rule stopping short of the text it underlines. A hard-coded width is also
	// wrong the first time a version string changes length.
	fmt.Fprintln(w, c.dim(rule(title, subtitle)))
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.header("THE RECORD"))

	// Record header — print what we know even on a failed verification
	// so the auditor can correlate the artifact under review.
	printField(w, "Record ID", orDash(p.RecordID))
	printField(w, "Evidence Tier", orDash(p.EvidenceTier))
	printField(w, "Principal", orDash(p.Principal))
	printField(w, "Action Type", orDash(p.ActionType))
	printField(w, "Created", orDash(p.CreatedAt))
	if p.ModelProvider != "" || p.ModelName != "" {
		printField(w, "Model", fmt.Sprintf("%s / %s", orDash(p.ModelProvider), orDash(p.ModelName)))
	}
	if r.RecordHash != "" {
		printField(w, "Record Hash", r.RecordHash)
	}
	if p.SigningKeyID != "" {
		printField(w, "Signing Key ID", p.SigningKeyID)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, c.header("WHAT WAS CHECKED"))
	// The loop variable is `ch`, not `c`: `c` is the palette, and a Check named
	// c shadowed it here silently. The code still compiled and the colouring
	// simply did not happen, which is the worst kind of shadowing bug.
	for _, ch := range r.Checks {
		marker := c.ok("[x]")
		if !ch.Passed {
			marker = c.bad("[!]")
		}
		if verbose || !ch.Passed {
			fmt.Fprintf(w, "  %s %s: %s\n", marker, ch.Name, c.dim(ch.Details))
		} else {
			fmt.Fprintf(w, "  %s %s\n", marker, ch.Name)
		}
	}

	fmt.Fprintln(w)
	if r.Verified {
		fmt.Fprintln(w, c.ok(c.bold("VERIFIED")))
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This artifact has NOT been modified since it was signed.")
		fmt.Fprintln(w, "The signature was produced by the key you supplied on the command line.")
		// Qualify the verdict so a valid signature is never mistaken for full
		// TIER-A primary evidence when the artifact is not TIER-A, or when the
		// RFC 3161 timestamp pillar was not verified (no .tsr supplied).
		if p.EvidenceTier != string(verifycore.TierA) {
			fmt.Fprintln(w)
			fmt.Fprintln(w, c.warn(fmt.Sprintf(
				"CAVEAT: evidence_tier is %s. This is NOT TIER-A primary evidence.", orDash(p.EvidenceTier))))
			fmt.Fprintln(w, c.warn("A valid signature here proves authorship."))
			fmt.Fprintln(w, c.warn("It does not prove WORM commitment, RFC 3161 timestamping,"))
			fmt.Fprintln(w, c.warn("or pre-execution input binding."))
		} else if r.TimestampValid == nil {
			fmt.Fprintln(w)
			fmt.Fprintln(w, c.warn("CAVEAT: no RFC 3161 timestamp was supplied (--tsr),"))
			fmt.Fprintln(w, c.warn("so the independent time-proof pillar of TIER-A was not verified."))
			fmt.Fprintln(w, c.warn("Supply the .tsr to confirm it."))
		} else if r.TimestampIssuerVerified != nil && !*r.TimestampIssuerVerified {
			fmt.Fprintln(w)
			fmt.Fprintln(w, c.warn("CAVEAT: the timestamp's issuer was NOT verified against a trusted root."))
			fmt.Fprintln(w, c.warn("The MessageImprint and the time were checked,"))
			fmt.Fprintln(w, c.warn("but a self-signed timestamp would pass those too."))
			fmt.Fprintln(w, c.warn("Supply --tsa-root to anchor the TSA."))
		}

		// SCOPE — always printed on a VERIFIED result, not only when something
		// is missing.
		//
		// "VERIFIED" answers "is this artifact intact and authentic?", not "is
		// every claim in it corroborated?". A reader who assumes the latter
		// would overstate the evidence, and the assumption is the natural one
		// to make from the word alone. So the boundary is stated every time,
		// unprompted — the same rule §5 applies to the spec: coverage is
		// stated, never inferred.
		fmt.Fprintln(w)
		fmt.Fprintln(w, c.header("WHAT WAS NOT CHECKED"))
		// No section numbers here. They point at a specification this
		// repository does not publish, so a reader who followed one would
		// find nothing -- precision that cannot be acted on reads as
		// precision all the same, which is worse than plain words. The
		// bracketed invariant ids stay on each line for anyone who does hold
		// the spec.
		fmt.Fprintln(w, c.dim("This reads one record, on its own. Each item below needs something"))
		fmt.Fprintln(w, c.dim("this file does not contain, and none of it was fetched or consulted:"))
		for _, d := range r.InvariantsDeferred {
			fmt.Fprintf(w, "  %s %s\n", c.dim("·"), c.dim(d.ID))
			for _, line := range wrapIndent(d.Reason, 72, 0) {
				fmt.Fprintf(w, "    %s\n", c.dim(line))
			}
		}
		printFooter(w, c)

		if p.Upstream > 0 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "NOTE: this record commits to %d upstream edge(s). Their parents were NOT\n",
				p.Upstream)
			fmt.Fprintln(w, "Their parents were not fetched or verified; that is a Level-1 check.")
			fmt.Fprintln(w, "A valid signature proves what this record CLAIMS about its parents,")
			fmt.Fprintln(w, "not that those claims are true.")
		}
		return
	}

	// Each non-VERIFIED outcome gets its own headline, colour and explanation.
	// Previously all four printed a red FAILED and then the three-possibility
	// list below, which was untrue for UNKNOWN_KEY: the fingerprints differ, so
	// the tool knows exactly which of the three it is and said it could not tell.
	switch r.Outcome {
	case OutcomeUnknownKey:
		fmt.Fprintln(w, c.info(c.bold("DIFFERENT SIGNING KEY")))
		if r.FailureReason != "" {
			fmt.Fprintf(w, "%s %s\n", c.dim("Reason:"), r.FailureReason)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This record names a signing key other than the one you supplied.")
		fmt.Fprintln(w, "That is NOT a failed signature and NOT evidence of tampering.")
		fmt.Fprintln(w, "Supply the key it names to check it.")

	case OutcomeCouldNotVerify:
		fmt.Fprintln(w, c.warn(c.bold("COULD NOT VERIFY")))
		if r.FailureReason != "" {
			fmt.Fprintf(w, "%s %s\n", c.dim("Reason:"), r.FailureReason)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "No verdict was reached. This says nothing about the record.")
		fmt.Fprintln(w, "\"We could not check it\" is not \"it is bad\".")

	case OutcomeNotARecord:
		fmt.Fprintln(w, c.bold("NOT A CONFORMANT RECORD"))
		if r.FailureReason != "" {
			fmt.Fprintf(w, "%s %s\n", c.dim("Reason:"), r.FailureReason)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This document is not shaped like a record this tool can check.")
		fmt.Fprintln(w, "That is a statement about its structure, not an accusation.")

	default:
		fmt.Fprintln(w, c.bad(c.bold("FAILED")))
		if r.FailureReason != "" {
			fmt.Fprintf(w, "%s %s\n", c.dim("Reason:"), r.FailureReason)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This artifact could not be verified with the key you supplied.")
		// "You used the wrong key" is not on this list because it cannot be the
		// reason: the record's signing_key_id was compared with the supplied
		// key before the signature, and reaching here means they matched.
		fmt.Fprintln(w, "Either of these would produce that result:")
		fmt.Fprintln(w, "  1. The record was modified after it was signed.")
		fmt.Fprintln(w, "  2. The signature is not a signature over these bytes.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This tool cannot tell you which, and does not guess.")
	}
	printFooter(w, c)
}

// wrapIndent breaks text at word boundaries to fit `width` columns, indenting
// every line after the first by `hang` spaces.
//
// The deferred-invariant reasons used to be terse code fragments that fit a
// line. Rewriting them into sentences a reader can act on made them long
// enough to wrap in any terminal, and a report that wraps wherever the window
// happens to end is harder to read than one that chooses its own breaks.
func wrapIndent(text string, width, hang int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	pad := strings.Repeat(" ", hang)
	var lines []string
	cur := words[0]
	limit := width
	for _, word := range words[1:] {
		if len(cur)+1+len(word) > limit {
			lines = append(lines, cur)
			cur = pad + word
			limit = width
			continue
		}
		cur += " " + word
	}
	return append(lines, cur)
}

// rule returns a horizontal line as wide as the widest line it underlines.
//
// Measured in runes rather than bytes: the separator in the subtitle is U+00B7,
// which is two bytes and one column, so len() would overshoot by one for every
// multi-byte character the header carries.
func rule(lines ...string) string {
	width := 0
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > width {
			width = n
		}
	}
	return strings.Repeat("─", width)
}

// printField is a two-column field printer used by the human output. The
// fixed-width label column aligns all rows regardless of label length.
func printField(w io.Writer, label, value string) {
	fmt.Fprintf(w, "%-16s %s\n", label+":", value)
}

// orDash returns "-" for empty strings. Non-empty fields render verbatim.
// Used by the header printer so an absent value reads as a dash rather
// than collapsing whitespace, which would be confusing on a failed load.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// =============================================================================
// CLI entry point
// =============================================================================

// flagSet holds parsed command-line flags. Extracted from a flag.FlagSet
// so tests can exercise run() without touching package-global state.
type flagSet struct {
	// recordPaths is every record named on the command line, in order: one per
	// --record, plus any bare paths after the flags.
	//
	// Bare paths are ACCEPTED rather than refused. Step 12 made them an error
	// because they were being silently discarded while the tool exited 0, and
	// refusing was the safe fix. Verifying them is the right one: a shell
	// expands `--record *.json` into one --record and several bare paths, so
	// accepting them makes the natural invocation do the natural thing. What
	// must never happen -- a file on the command line going unexamined while
	// the tool reports success -- is now impossible in either direction.
	recordPaths   []string
	keyPath       string
	keyHex        string
	timestampPath string
	tsaRootPath   string
	verbose       bool
	jsonOutput    bool
	colorMode     string
	showVersion   bool
	showVersInfo  bool
}

// parseFlags parses args (without argv[0]) using a fresh FlagSet so run()
// is safe to invoke repeatedly from tests.
func parseFlags(args []string, stderr io.Writer) (*flagSet, error) {
	fs := flag.NewFlagSet("plainreal-verify", flag.ContinueOnError)
	// Usage goes to STDERR for a genuine flag error, and to STDOUT for an
	// explicit --help. The single stderr destination meant `--help | less`
	// showed an empty screen and `--help` in a script looked like a failure,
	// which is a poor first minute for the one tool a stranger runs. run()
	// re-routes it below when the request was --help.
	fs.SetOutput(stderr)

	out := &flagSet{}
	fs.Var((*repeatedPath)(&out.recordPaths), "record",
		"Path to a sealed record JSON file. Repeat for several; bare paths after the flags are records too")
	fs.StringVar(&out.keyPath, "key", "", "Path to PlainReal public key PEM file")
	fs.StringVar(&out.keyHex, "key-hex", "", "PlainReal public key as 64-char hex (alternative to --key)")
	fs.StringVar(&out.timestampPath, "tsr", "", "Path to RFC 3161 timestamp token (.tsr file); optional")
	fs.StringVar(&out.tsaRootPath, "tsa-root", "", "Path to trusted TSA root certificate(s) (PEM). Anchors the .tsr issuer; without it the timestamp issuer is not verified")
	fs.BoolVar(&out.verbose, "verbose", false, "Print all verification steps in detail")
	fs.StringVar(&out.colorMode, "color", "auto", "Colour output: auto (only when stdout is a terminal), always, or never")
	fs.BoolVar(&out.jsonOutput, "json", false, "Output verification result as JSON")
	fs.BoolVar(&out.showVersion, "version", false, "Print this binary's release version and the schema versions it accepts")
	fs.BoolVar(&out.showVersInfo, "version-info", false, "Print the record schema versions this binary accepts, one line, and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "plainreal-verify %s\n\n", Version)
		fmt.Fprintln(stderr, "Standalone record verification CLI.")
		fmt.Fprintln(stderr, "Runs with ZERO PlainReal runtime dependencies.")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  plainreal-verify --record <path> --key <path>   [--tsr <path>] [--verbose] [--json]")
		fmt.Fprintln(stderr, "  plainreal-verify --record <path> --key-hex <hex> [--tsr <path>] [--verbose] [--json]")
		fmt.Fprintln(stderr, "  plainreal-verify --version")
		fmt.Fprintln(stderr, "  plainreal-verify --version-info")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Exit codes:")
		fmt.Fprintln(stderr, "  0  every record given verified")
		fmt.Fprintln(stderr, "  1  every record was checked, and at least one did not verify")
		fmt.Fprintln(stderr, "  2  something could not be checked at all, or the command was refused")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Outcomes (the same five the web verifier reports):")
		fmt.Fprintln(stderr, "  VERIFIED                 signature matches; the bytes are what was signed")
		fmt.Fprintln(stderr, "  FAILED                   parsed, and the signature does not match the contents")
		fmt.Fprintln(stderr, "  DIFFERENT SIGNING KEY    signed by a key other than the one supplied;")
		fmt.Fprintln(stderr, "                           NOT a failed signature and NOT evidence of tampering")
		fmt.Fprintln(stderr, "  NOT A CONFORMANT RECORD  unreadable, or not shaped like a record;")
		fmt.Fprintln(stderr, "                           a statement about structure, not an accusation")
		fmt.Fprintln(stderr, "  COULD NOT VERIFY         no verdict reached; says nothing about the record")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Bare paths are records. See recordPaths above for why they are accepted
	// rather than refused.
	//
	// But a bare path that LOOKS like a flag is refused, because Go's flag
	// package stops parsing at the first non-flag argument. That means
	// `--record a.json b.json --json` silently loses --json AND adds a record
	// path called "--json": the flag does nothing and the tool tries to read a
	// file that does not exist. Found by running it, not by a test.
	//
	// Silently reinterpreting a flag as a filename is the same failure this
	// whole stage exists to remove, so it is an error with the fix in it.
	for _, a := range fs.Args() {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(stderr, "ERROR: %q looks like a flag but appears after a file path.\n", a)
			fmt.Fprintln(stderr, "Flags must come before bare paths, because parsing stops at the first path:")
			fmt.Fprintln(stderr, "  plainreal-verify --key k.pem --json record1.json record2.json")
			fmt.Fprintln(stderr, "Nothing was checked.")
			return nil, errFlagAfterPath
		}
	}
	out.recordPaths = append(out.recordPaths, fs.Args()...)

	return out, nil
}

// errFlagAfterPath signals a flag written after a bare path, where the flag
// parser would have silently treated it as a filename.
var errFlagAfterPath = errors.New("flag after path")

// repeatedPath collects a flag that may be given more than once.
type repeatedPath []string

func (r *repeatedPath) String() string { return strings.Join(*r, ", ") }
func (r *repeatedPath) Set(v string) error {
	*r = append(*r, v)
	return nil
}

// run is the CLI entry point as a pure function of args/stdout/stderr.
// Returns the process exit code. main() wraps this with os.Exit. Tests
// call run() directly to assert on output and exit behavior.
func run(args []string, stdout, stderr io.Writer) int {
	// --help is a request that was satisfied, not an error, so it goes to
	// stdout and exits 0.
	//
	// Detected via flag.ErrHelp, NOT by scanning raw args for "-h". The first
	// version scanned, and a hostile review found that a record file named
	// exactly "-h" -- passed as the VALUE of --record -- printed help and
	// exited 0 having verified nothing. That is the same defect as the
	// positional-argument footgun above, reintroduced two steps later while
	// fixing something else. flag knows which token is a flag and which is a
	// value; a scan cannot.
	//
	// Usage is buffered so it can be routed by outcome: stdout for a help
	// request, stderr for a genuine misuse.
	var usage bytes.Buffer
	flags, err := parseFlags(args, &usage)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stdout, &usage)
			return ExitVerified
		}
		_, _ = io.Copy(stderr, &usage)
		return ExitError
	}

	if flags.showVersion {
		// Labelled, because --version and --version-info both used to print a
		// bare semver and nothing said which was which: this is the BINARY's
		// release version, that one is the RECORD SCHEMA it accepts.
		fmt.Fprintf(stdout, "plainreal-verify %s\n", Version)
		fmt.Fprintf(stdout, "record schema versions accepted: %s", supportedVersionsLine())
		return ExitVerified
	}

	if flags.showVersInfo {
		fmt.Fprint(stdout, supportedVersionsLine())
		return ExitVerified
	}

	if len(flags.recordPaths) == 0 {
		fmt.Fprintln(stderr, "ERROR: no record given. Use --record <path>, or list paths after the flags.")
		return ExitError
	}

	publicKeyHex, err := loadPublicKey(flags.keyPath, flags.keyHex)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: %v\n", err)
		return ExitError
	}

	// An RFC 3161 token commits to ONE record's hash, so there is no coherent
	// way to apply a single --tsr to several records. Reusing it would report a
	// MessageImprint mismatch on every record but the first, which reads as a
	// timestamp failure on records that are perfectly sound -- the same false
	// accusation as reporting a wrong key as tampering.
	//
	// Refused rather than silently applied. Per-record timestamps need one
	// invocation per record until there is a flag shape that pairs them.
	if flags.timestampPath != "" && len(flags.recordPaths) > 1 {
		fmt.Fprintf(stderr,
			"ERROR: --tsr names one timestamp token, but %d records were given.\n", len(flags.recordPaths))
		fmt.Fprintln(stderr, "An RFC 3161 token commits to a single record's hash, so one token cannot")
		fmt.Fprintln(stderr, "cover several records. Verify them one at a time, each with its own .tsr.")
		fmt.Fprintln(stderr, "Nothing was checked.")
		return ExitError
	}

	var tsaRoots *x509.CertPool
	if flags.tsaRootPath != "" {
		tsaRoots, err = loadTSARoots(flags.tsaRootPath)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %v\n", err)
			return ExitError
		}
	}

	// Verify EVERY record before deciding anything.
	//
	// No short circuit on the first failure. Stopping early would leave later
	// records unexamined while still exiting non-zero, which reads as "these
	// were all checked and one was bad" -- a stronger claim than was earned,
	// and the same shape as the defects this tool has already shipped twice.
	type outcome struct {
		path      string
		view      recordView
		result    *VerificationResult
		inputErr  error // could not read it at all; nothing was checked
		rejectErr error // read, and refused as non-conformant
	}
	outcomes := make([]outcome, 0, len(flags.recordPaths))

	for _, path := range flags.recordPaths {
		o := outcome{path: path}
		raw, err := loadRecord(path)
		if err != nil {
			// "I could not read your input" (exit 2) versus "this file is not a
			// conformant record" (exit 1). Both used to exit 2, so a record
			// tampered with by APPENDING a field reported as an input problem
			// and an auditor script testing `exit == 1` never saw it.
			if isArtifactRejection(err) {
				o.rejectErr = err
			} else {
				o.inputErr = err
			}
			outcomes = append(outcomes, o)
			continue
		}
		result, err := verifyRecord(raw, publicKeyHex, flags.timestampPath, tsaRoots)
		if err != nil {
			if isArtifactRejection(err) {
				o.rejectErr = err
			} else {
				o.inputErr = fmt.Errorf("verification internal error: %w", err)
			}
			outcomes = append(outcomes, o)
			continue
		}
		result.Path = path
		o.view = result.view
		o.result = result
		outcomes = append(outcomes, o)
	}

	// Exit code. 2 wins over 1 deliberately: "I could not check one of these"
	// is what you most need to know, because nothing at all can be concluded
	// about that file. 1 means every record was checked and at least one did
	// not verify. 0 means every record was checked and every one verified.
	anyInputErr, anyFailed := false, false
	for _, o := range outcomes {
		switch {
		case o.inputErr != nil:
			anyInputErr = true
		case o.rejectErr != nil:
			anyFailed = true
		case o.result.Outcome == OutcomeCouldNotVerify:
			// Exit 2, not 1. This outcome means no verdict was reached, and
			// ExitFailed is documented as "was checked and did not verify".
			// Returning 1 for a record whose schema version this binary cannot
			// speak to would report a failure it explicitly declined to find --
			// the printed text says "no verdict was reached" and the exit code
			// said the opposite. A newer record is most likely fine.
			anyInputErr = true
		case !o.result.Verified:
			anyFailed = true
		}
	}

	// Diagnostics that belong on stderr regardless of output format.
	for _, o := range outcomes {
		switch {
		case o.inputErr != nil:
			fmt.Fprintf(stderr, "ERROR: %v\n", o.inputErr)
		case o.rejectErr != nil:
			fmt.Fprintf(stderr, "%v\n", o.rejectErr)
		case o.result != nil && !o.result.Verified &&
			strings.HasPrefix(o.result.FailureReason, "unsupported record version"):
			// The auditor needs to fetch a matching binary; keep it greppable.
			fmt.Fprintln(stderr, o.result.FailureReason)
		}
	}

	single := len(outcomes) == 1

	if flags.jsonOutput {
		// A single record emits an OBJECT, as it always has: that is a published
		// contract and auditor scripts parse it. Several emit an ARRAY. The
		// shape tells a consumer which it got without a flag.
		if single {
			o := outcomes[0]
			if o.inputErr != nil {
				return ExitError
			}
			if o.rejectErr != nil {
				printRejection(stdout, o.path, o.rejectErr, true)
				return ExitFailed
			}
			if err := printJSON(stdout, o.result); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
				return ExitError
			}
		} else {
			arr := make([]*VerificationResult, 0, len(outcomes))
			for _, o := range outcomes {
				if o.result != nil {
					arr = append(arr, o.result)
					continue
				}
				// A refusal is a verdict and says so, as the single-record
				// object does. A file that could not be read has no outcome:
				// nothing was checked, so there is nothing to call it.
				reason, outcome := "", Outcome("")
				if o.inputErr != nil {
					reason = o.inputErr.Error()
				} else if o.rejectErr != nil {
					reason, outcome = o.rejectErr.Error(), OutcomeNotARecord
				}
				arr = append(arr, &VerificationResult{
					ToolVersion:        Version,
					SchemaVersions:     verifycore.SupportedRecordVersions(),
					Verified:           false,
					Outcome:            outcome,
					Path:               o.path,
					FailureReason:      reason,
					Checks:             []Check{{Name: "Record Load", Passed: false, Details: reason}},
					Level:              0,
					InvariantsChecked:  level0Invariants,
					InvariantsDeferred: level0Deferred,
				})
			}
			b, err := json.MarshalIndent(arr, "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
				return ExitError
			}
			fmt.Fprintf(stdout, "%s\n", b)
		}
	} else if single {
		o := outcomes[0]
		switch {
		case o.inputErr != nil:
			return ExitError
		case o.rejectErr != nil:
			printRejection(stdout, o.path, o.rejectErr, false)
		default:
			printHuman(stdout, o.result, o.view, flags.verbose, newPalette(flags.colorMode, stdout))
		}
	} else {
		batchTitle := "PlainReal Record Verification"
		batchSub := "plainreal-verify " + Version +
			"  ·  record schema " + strings.Join(verifycore.SupportedRecordVersions(), ", ")
		fmt.Fprintln(stdout, batchTitle)
		fmt.Fprintln(stdout, batchSub)
		fmt.Fprintln(stdout, strings.Repeat("=", utf8.RuneCountInString(batchSub)))
		fmt.Fprintln(stdout)
		nOK := 0
		for _, o := range outcomes {
			var mark, note string
			switch {
			case o.inputErr != nil:
				mark, note = "[!]", "could not be read: "+o.inputErr.Error()
			case o.rejectErr != nil:
				mark, note = "[!]", "not a conformant record: "+o.rejectErr.Error()
			case !o.result.Verified:
				mark, note = "[!]", o.result.FailureReason
			default:
				mark, note = "[x]", "signature valid"
				nOK++
			}
			fmt.Fprintf(stdout, "  %s %s\n      %s\n", mark, o.path, note)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Checked %d records INDEPENDENTLY, one at a time: %d verified, %d did not.\n",
			len(outcomes), nOK, len(outcomes)-nOK)
		fmt.Fprintln(stdout)

		// The boundary, stated every time and not only when something fails.
		//
		// N independent Level-0 verdicts are not a statement about a workflow.
		// Records reference the records they came from, and this tool never
		// follows one of those references -- that is a Level-1 check and it is
		// deliberately not here. A reader who took a green batch as "the
		// workflow is sound" would be overstating the evidence, and the phrasing
		// of a summary line is exactly where that misreading would start.
		fmt.Fprintln(stdout, "This says nothing about how these records relate to one another. Each was")
		fmt.Fprintln(stdout, "checked on its own. Verifying every record in a workflow proves every record,")
		fmt.Fprintln(stdout, "not the workflow: what ties them together is the references between them, and")
		fmt.Fprintln(stdout, "those were never followed.")

		if len(outcomes) > 0 && outcomes[0].result != nil {
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "NOT CHECKED, for every record above. Each needs something no single")
			fmt.Fprintln(stdout, "record contains, and none of it was fetched:")
			for _, d := range level0Deferred {
				fmt.Fprintf(stdout, "  - %s\n", d.ID)
				for _, line := range wrapIndent(d.Reason, 72, 0) {
					fmt.Fprintf(stdout, "    %s\n", line)
				}
			}
		}
	}

	switch {
	case anyInputErr:
		return ExitError
	case anyFailed:
		return ExitFailed
	}
	return ExitVerified
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// =============================================================================
// Artifact rejections vs. input errors
// =============================================================================

// errArtifactRejected marks an error as a verdict about the DOCUMENT rather
// than a problem reading input. Such errors exit FAILED (1), not ERROR (2): the
// file was read, understood well enough to judge, and found wanting.
//
// This started as substring matching over error messages, and a hostile review
// broke it in one line. The messages embed the record PATH, so a file named
// "does-not-exist unknown top-level key.json" made a plain missing-file error
// classify as an artifact verdict. User-controlled text was reaching a security
// decision through an error string.
//
// So the classification happens where the semantics are KNOWN -- at the call
// site that produced the error -- and travels as a sentinel. errors.Is cannot
// be fooled by a filename.
var errArtifactRejected = errors.New("artifact rejected")

// artifactRejection carries the sentinel WITHOUT putting it in the message.
//
// The first version wrapped with fmt.Errorf("%w: "+format, errArtifactRejected,
// ...), which made every rejection read "Reason: artifact rejected: parse record
// JSON in ...". The line already says FAILED; repeating it as a prefix is noise
// in front of the part the reader needs. A type gives errors.Is the sentinel and
// the reader the message.
type artifactRejection struct{ err error }

func (a artifactRejection) Error() string        { return a.err.Error() }
func (a artifactRejection) Unwrap() error        { return a.err }
func (a artifactRejection) Is(target error) bool { return target == errArtifactRejected }

// rejectArtifact marks err as a verdict about the document rather than a
// problem reading input.
func rejectArtifact(format string, args ...any) error {
	return artifactRejection{fmt.Errorf(format, args...)}
}

// isArtifactRejection reports whether err is a verdict about the artifact.
func isArtifactRejection(err error) bool { return errors.Is(err, errArtifactRejected) }

// printRejection emits a rejection in whichever format the caller asked for, so
// --json consumers get a parseable verdict instead of only a stderr line.
func printRejection(w io.Writer, path string, err error, asJSON bool) {
	if asJSON {
		_ = printJSON(w, &VerificationResult{
			ToolVersion:        Version,
			SchemaVersions:     verifycore.SupportedRecordVersions(),
			Verified:           false,
			Outcome:            OutcomeNotARecord,
			FailureReason:      err.Error(),
			Checks:             []Check{{Name: "Record Parse", Passed: false, Details: err.Error()}},
			Level:              0,
			InvariantsChecked:  level0Invariants,
			InvariantsDeferred: level0Deferred,
		})
		return
	}
	rejTitle := "PlainReal Record Verification"
	rejSub := "plainreal-verify " + Version +
		"  ·  record schema " + strings.Join(verifycore.SupportedRecordVersions(), ", ")
	fmt.Fprintln(w, rejTitle)
	fmt.Fprintln(w, rejSub)
	fmt.Fprintln(w, strings.Repeat("=", utf8.RuneCountInString(rejSub)))
	fmt.Fprintln(w)
	printField(w, "Record", path)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Result: NOT A CONFORMANT RECORD")
	fmt.Fprintf(w, "Reason: %s\n", err.Error())
	fmt.Fprintln(w)
	fmt.Fprintln(w, "This file is not a conformant record. That is a judgment about the")
	fmt.Fprintln(w, "document, not a problem reading it: it was read, and it does not")
	fmt.Fprintln(w, "conform to the schema this binary verifies.")
}

// printFooter names the second implementation.
//
// The page and this binary check the same thing two different ways, and a
// release gate requires them to agree. That is the whole reason both exist, and
// it is worth nothing to a reader who does not know the other one is there: an
// auditor holding one tool has a result, and an auditor who knows about both
// has a way to cross-check it without asking us anything.
//
// Printing a URL is not a network call. This binary contacts nothing, and the
// address is here so a reader can reach the page and the signed tag it is
// published under.
func printFooter(w io.Writer, c palette) {
	// URLs carry https:// and sit alone on their lines.
	//
	// The scheme is not decoration. Most terminals only hyperlink a URL that has
	// one, so without it a reader has to retype the address; and a bare hostname
	// is an instruction a careless reader can follow over http://, which is the
	// wrong advice from a tool whose entire subject is not trusting the channel.
	//
	// Alone on the line so the URL can be double-clicked or copied without
	// picking up the surrounding words.
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s\n", c.dim("Also runs in a browser:"), c.dim("https://verify.plainreal.com"))
	fmt.Fprintf(w, "  %s %s\n", c.dim("Source of both:        "), c.dim("https://github.com/plainreal/verify"))
	// One thought per line, and each short enough to need no break. The previous
	// version split a single sentence at its comma, which is a clause boundary
	// but not a reason: the sentence was simply too long. Shortening it was the
	// fix, not choosing a better place to snap it.
	// "This tool checks more of a record than the page does" was true until
	// v1.2.0, when the page gained the field rules and the invariants. What the
	// CLI still has that the page lacks is the timestamp token.
	fmt.Fprintln(w, c.dim("  A release gate tests that the two give the same verdict."))
	fmt.Fprintln(w, c.dim("  This tool also checks an RFC 3161 token; the page does not."))
	fmt.Fprintln(w, c.dim("  Nothing was contacted to produce this result."))
}
