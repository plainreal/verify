package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ts3161 "github.com/digitorus/timestamp"
	"github.com/plainreal/verify/verifycore"
)

// =============================================================================
// Fixture helpers
// =============================================================================

// sealedFixture is a freshly generated sealed record plus the keys that
// produced it, ready for on-disk write by individual tests.
type sealedFixture struct {
	record       *verifycore.Record
	recordJSON   []byte
	publicKeyPEM []byte
	publicKeyHex string
	privateKey   ed25519.PrivateKey
	signer       testSigner
	keyDir       string
}

// createSealedRecordFixture generates an Ed25519 key pair, produces a
// TIER-A test record, seals it, and returns all material needed to
// assert against verification behavior (PEM, hex, JSON, signer).
//
// Each call generates FRESH keys — tests that need isolation across runs
// do not share key material. Tests that need on-disk fixtures use the
// helpers below (writeFixture, tamperRecord, etc.).
func createSealedRecordFixture(t *testing.T) *sealedFixture {
	t.Helper()

	// An ephemeral key generated here, not a SoftwareSigningService from core.
	//
	// These tests ship with the CLI to a repository that deliberately contains
	// no producer, so a fixture that needed the sealer could not travel with
	// them, and a verifier published without its tests is not one anyone can
	// check. Signing thirty-two bytes with crypto/ed25519 is all a fixture
	// needs, and none of it reaches the binary: test files are not compiled
	// into it.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "unsealed_record.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	doc["signing_key_id"] = verifycore.HashSHA3256(pub)
	delete(doc, "signing_attestation")

	unsigned, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	hash, err := verifycore.RecordHashFromBytes(unsigned)
	if err != nil {
		t.Fatalf("record hash: %v", err)
	}
	hb, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	doc["signing_attestation"] = hex.EncodeToString(ed25519.Sign(priv, hb))

	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal sealed: %v", err)
	}
	p, err := verifycore.RecordFromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("parse sealed: %v", err)
	}

	keyDir := t.TempDir()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(keyDir, "plainreal_ed25519_pub.pem"), pubPEM, 0o600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	return &sealedFixture{
		record:       p,
		recordJSON:   jsonBytes,
		publicKeyPEM: pubPEM,
		publicKeyHex: hex.EncodeToString(pub),
		signer:       testSigner{priv: priv, pub: pub},
		keyDir:       keyDir,
	}
}

// testSigner stands in for core's SigningService in tests only. It exists so a
// fixture can re-sign after a deliberate mutation without importing a producer.
type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s testSigner) Sign(hash string) (string, error) {
	hb, err := hex.DecodeString(hash)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(s.priv, hb)), nil
}
func (s testSigner) PublicKeyHex() string { return hex.EncodeToString(s.pub) }

// recordHashOfStruct hashes a record the way a VERIFIER does: serialize, then
// hash the bytes (section 4.6.1). core.ComputeRecordHash is the producer's
// struct path and is deliberately not reachable from here.
func recordHashOfStruct(t *testing.T, p *verifycore.Record) (string, error) {
	t.Helper()
	raw, err := p.ToJSON()
	if err != nil {
		return "", err
	}
	return verifycore.RecordHashFromBytes(raw)
}

// writeFixtureFiles writes the fixture's record JSON and public key PEM
// to a fresh temp directory and returns the two paths.
func writeFixtureFiles(t *testing.T, f *sealedFixture) (recordPath, pubkeyPath string) {
	t.Helper()
	dir := t.TempDir()
	recordPath = filepath.Join(dir, "record.json")
	pubkeyPath = filepath.Join(dir, "pubkey.pem")
	if err := os.WriteFile(recordPath, f.recordJSON, 0o644); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := os.WriteFile(pubkeyPath, f.publicKeyPEM, 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return recordPath, pubkeyPath
}

// reSerializeTampered mutates the given record (via cb) WITHOUT re-signing
// and returns the JSON bytes. This models an adversary editing the record
// payload after signing.
func reSerializeTampered(t *testing.T, p *verifycore.Record, cb func(p *verifycore.Record)) []byte {
	t.Helper()
	cp := *p
	cb(&cp)
	data, err := cp.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON tampered: %v", err)
	}
	return data
}

// =============================================================================
// loadPublicKey — all accepted and rejected input shapes
// =============================================================================

func TestLoadPublicKey_PEMFile(t *testing.T) {
	f := createSealedRecordFixture(t)
	pubPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pubPath, f.publicKeyPEM, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := loadPublicKey(pubPath, "")
	if err != nil {
		t.Fatalf("loadPublicKey: %v", err)
	}
	if got != f.publicKeyHex {
		t.Fatalf("hex mismatch: got %s want %s", got, f.publicKeyHex)
	}
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(got))
	}
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("hex contains non-lowercase char: %q", got)
		}
	}
}

func TestLoadPublicKey_Hex(t *testing.T) {
	f := createSealedRecordFixture(t)
	got, err := loadPublicKey("", f.publicKeyHex)
	if err != nil {
		t.Fatalf("loadPublicKey: %v", err)
	}
	if got != f.publicKeyHex {
		t.Fatalf("hex round-trip mismatch: got %s want %s", got, f.publicKeyHex)
	}
}

func TestLoadPublicKey_BothProvided(t *testing.T) {
	f := createSealedRecordFixture(t)
	pubPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pubPath, f.publicKeyPEM, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadPublicKey(pubPath, f.publicKeyHex)
	if err == nil {
		t.Fatal("expected error when both flags provided")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("error should mention 'not both': %v", err)
	}
}

func TestLoadPublicKey_NeitherProvided(t *testing.T) {
	_, err := loadPublicKey("", "")
	if err == nil {
		t.Fatal("expected error when neither flag provided")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("error should mention 'required': %v", err)
	}
}

func TestLoadPublicKey_PEMFileNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent.pem")
	_, err := loadPublicKey(missing, "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error should mention path %s: %v", missing, err)
	}
}

func TestLoadPublicKey_PEMMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("this is not a PEM file"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadPublicKey(path, "")
	if err == nil {
		t.Fatal("expected error for malformed PEM")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("error should mention PEM: %v", err)
	}
}

func TestLoadPublicKey_WrongKeyType_RSA(t *testing.T) {
	// Generate an RSA key and write it as a PKIX PEM block — same block
	// type, wrong algorithm. This is a common mistake (ops uploads the
	// wrong key format).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA gen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "rsa.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err = loadPublicKey(path, "")
	if err == nil {
		t.Fatal("expected error for RSA key")
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("error should mention Ed25519: %v", err)
	}
}

func TestLoadPublicKey_WrongPEMBlockType(t *testing.T) {
	// A valid PEM block of the wrong type — e.g. a CERTIFICATE — should
	// fail with a type-specific error rather than crashing through to the
	// parser.
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x00, 0x01, 0x02}}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadPublicKey(path, "")
	if err == nil {
		t.Fatal("expected error for wrong block type")
	}
	if !strings.Contains(err.Error(), "PUBLIC KEY") {
		t.Fatalf("error should mention block type: %v", err)
	}
}

func TestLoadPublicKey_HexWrongLength(t *testing.T) {
	_, err := loadPublicKey("", "abc")
	if err == nil {
		t.Fatal("expected error for short hex")
	}
	if !strings.Contains(err.Error(), "64 characters") {
		t.Fatalf("error should mention 64 characters: %v", err)
	}
}

func TestLoadPublicKey_HexNotHex(t *testing.T) {
	// 64 chars, but with non-hex characters.
	bad := strings.Repeat("zz", 32)
	_, err := loadPublicKey("", bad)
	if err == nil {
		t.Fatal("expected error for non-hex")
	}
	if !strings.Contains(err.Error(), "hex") {
		t.Fatalf("error should mention hex: %v", err)
	}
}

func TestLoadPublicKey_HexUppercaseRejected(t *testing.T) {
	// 64 chars, valid hex, but uppercase. We enforce lowercase so forensic
	// evidence carries a canonical representation.
	upper := strings.Repeat("AA", 32)
	_, err := loadPublicKey("", upper)
	if err == nil {
		t.Fatal("expected error for uppercase hex")
	}
	if !strings.Contains(err.Error(), "lowercase") {
		t.Fatalf("error should mention lowercase: %v", err)
	}
}

// =============================================================================
// loadRecord — JSON parsing + file handling
// =============================================================================

func TestLoadRecord_Valid(t *testing.T) {
	f := createSealedRecordFixture(t)
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, f.recordJSON, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, p, err := loadRecord(path)
	if err != nil {
		t.Fatalf("loadRecord: %v", err)
	}
	if p.RecordID != f.record.RecordID {
		t.Fatalf("record_id mismatch: got %s want %s", p.RecordID, f.record.RecordID)
	}
	if p.EvidenceTier != verifycore.TierA {
		t.Fatalf("evidence_tier = %s, want TIER-A", p.EvidenceTier)
	}
	if len(p.SigningAttestation) != 128 {
		t.Fatalf("SigningAttestation len = %d, want 128", len(p.SigningAttestation))
	}
}

func TestLoadRecord_FileNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	_, _, err := loadRecord(missing)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error should mention path: %v", err)
	}
}

func TestLoadRecord_MalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := loadRecord(path)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	// The assertion used to require the word "parse". The message changed when
	// non-JSON stopped being reported as a verdict about an artifact, so the
	// test now checks the two properties that actually matter: the reader is
	// told nothing was checked, and it is NOT classified as an artifact
	// rejection, which is what keeps it at exit 2 rather than exit 1.
	if !strings.Contains(err.Error(), "not a record") {
		t.Errorf("error should say it is not a record: %v", err)
	}
	if isArtifactRejection(err) {
		t.Error("a non-JSON file must not be classified as an artifact verdict; nothing was checked")
	}
}

func TestLoadRecord_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := loadRecord(path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

// =============================================================================
// verifyRecord — valid artifact
// =============================================================================

func TestVerifyRecord_ValidRecord(t *testing.T) {
	f := createSealedRecordFixture(t)
	result, err := verifyStructAsArtifact(t, f.record, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified=true, got false. FailureReason=%q", result.FailureReason)
	}
	if !result.SignatureValid {
		t.Fatal("expected SignatureValid=true")
	}
	if result.RecordHash == "" {
		t.Fatal("expected non-empty RecordHash")
	}
	if len(result.RecordHash) != 64 {
		t.Fatalf("RecordHash len = %d, want 64", len(result.RecordHash))
	}
	if result.FailureReason != "" {
		t.Fatalf("expected empty FailureReason, got %q", result.FailureReason)
	}
	// All checks should have Passed=true.
	for _, c := range result.Checks {
		if !c.Passed {
			t.Errorf("check %q failed: %s", c.Name, c.Details)
		}
	}
	// Must have the core check names.
	requireCheck(t, result.Checks, "JSON Parse", true)
	requireCheck(t, result.Checks, "Record Version", true)
	requireCheck(t, result.Checks, "TIER-A Validation + Local Invariants", true)
	requireCheck(t, result.Checks, "Record Hash Computed", true)
	requireCheck(t, result.Checks, "Signature", true)
}

// =============================================================================
// verifyRecord — every failure mode produces a structured FAILED result
// =============================================================================

func TestVerifyRecord_TamperedField(t *testing.T) {
	f := createSealedRecordFixture(t)

	// Mutate a non-hash field — the signed hash covers action_type via JCS,
	// so ANY semantic change invalidates the signature.
	tampered := reSerializeTampered(t, f.record, func(p *verifycore.Record) {
		p.ActionType = "hiring_decision"
	})
	// Reparse so the record we pass to verify is the tampered one.
	p, err := verifycore.RecordFromJSON(tampered)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	result, err := verifyStructAsArtifact(t, p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false for tampered record")
	}
	if result.SignatureValid {
		t.Fatal("expected SignatureValid=false for tampered record")
	}
	if !strings.Contains(result.FailureReason, "signature") {
		t.Fatalf("FailureReason should mention signature, got %q", result.FailureReason)
	}
	// Last check must be the failed signature check.
	last := result.Checks[len(result.Checks)-1]
	if last.Name != "Signature" || last.Passed {
		t.Fatalf("expected last check to be failed Signature, got %+v", last)
	}
}

func TestVerifyRecord_TamperedInstrumentationCoverage(t *testing.T) {
	// Float coverage change — exercises that float JCS canonicalization is
	// fully covered by the signed hash (not just strings/enums).
	f := createSealedRecordFixture(t)
	tampered := reSerializeTampered(t, f.record, func(p *verifycore.Record) {
		p.InstrumentationCoverage = 0.5
	})
	p, err := verifycore.RecordFromJSON(tampered)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result, err := verifyStructAsArtifact(t, p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false")
	}
}

func TestVerifyRecord_WrongPublicKey(t *testing.T) {
	f := createSealedRecordFixture(t)

	// Generate an unrelated Ed25519 key pair and verify with its public key.
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongPub := hex.EncodeToString(pub2)
	if wrongPub == f.publicKeyHex {
		t.Fatal("generated the same pub key by coincidence (vanishingly unlikely)")
	}

	result, err := verifyStructAsArtifact(t, f.record, wrongPub, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false with wrong public key")
	}
	if result.SignatureValid {
		t.Fatal("expected SignatureValid=false with wrong public key")
	}
}

func TestVerifyRecord_EmptySigningAttestation(t *testing.T) {
	f := createSealedRecordFixture(t)
	p := *f.record
	p.SigningAttestation = ""
	result, err := verifyStructAsArtifact(t, &p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false")
	}
	if !strings.Contains(result.FailureReason, "not sealed") {
		t.Fatalf("FailureReason should mention 'not sealed', got %q", result.FailureReason)
	}
}

func TestVerifyRecord_UnsupportedVersion(t *testing.T) {
	f := createSealedRecordFixture(t)
	p := *f.record
	p.RecordVersion = "2.0.0"
	result, err := verifyStructAsArtifact(t, &p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false")
	}
	if !strings.Contains(result.FailureReason, "version") {
		t.Fatalf("FailureReason should mention version, got %q", result.FailureReason)
	}
}

func TestVerifyRecord_MissingTierAField(t *testing.T) {
	// Build a TIER-A record that fails ValidateTierA. Do this by zeroing
	// a required field on a sealed fixture — we do NOT reseal, so the
	// check failure fires before the signature check would have.
	f := createSealedRecordFixture(t)
	p := *f.record
	p.InputHash = "" // ValidateTierA rejects malformed input_hash
	result, err := verifyStructAsArtifact(t, &p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false")
	}
	if !strings.Contains(result.FailureReason, "TIER-A") {
		t.Fatalf("FailureReason should mention TIER-A, got %q", result.FailureReason)
	}
	// The failure must be detected at TIER-A Validation, before the
	// signature check — so no Signature check is emitted.
	for _, c := range result.Checks {
		if c.Name == "Signature" {
			t.Fatalf("signature check should not have run after TIER-A failure")
		}
	}
}

func TestVerifyRecord_MalformedSignatureHex(t *testing.T) {
	f := createSealedRecordFixture(t)
	p := *f.record
	p.SigningAttestation = "not valid hex at all of the wrong length too"
	result, err := verifyStructAsArtifact(t, &p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false")
	}
	// Must fail signature verification (not crash).
	last := result.Checks[len(result.Checks)-1]
	if last.Name != "Signature" || last.Passed {
		t.Fatalf("expected failed Signature check, got %+v", last)
	}
}

// =============================================================================
// evidence_tier floor
// =============================================================================

// TestVerifyRecord_UnrecognizedTierRejected proves the evidence-tier floor:
// a record carrying a fabricated tier ("PRIMARY-EVIDENCE") must NOT verify,
// even when the Ed25519 signature over that body is valid — otherwise a hollow
// artifact could skip all TIER-A field checks and borrow TIER-A's credibility.
func TestVerifyRecord_UnrecognizedTierRejected(t *testing.T) {
	f := createSealedRecordFixture(t)
	p := *f.record
	p.EvidenceTier = "PRIMARY-EVIDENCE" // not one of TIER-A/B/C
	// Re-sign the tampered body so the signature itself is valid — the point is
	// that a valid signature must not rescue an unrecognized tier.
	p.SigningAttestation = ""
	hash, err := recordHashOfStruct(t, &p)
	if err != nil {
		t.Fatalf("ComputeRecordHash: %v", err)
	}
	sig, err := f.signer.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	p.SigningAttestation = sig

	result, err := verifyStructAsArtifact(t, &p, f.publicKeyHex, "", nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("record with unrecognized evidence_tier must NOT verify")
	}
	if !strings.Contains(result.FailureReason, "evidence_tier") {
		t.Fatalf("expected an evidence_tier failure, got %q", result.FailureReason)
	}
}

// =============================================================================
// verifyTimestamp — the RFC 3161 checker
// =============================================================================

func TestVerifyTimestamp_Valid(t *testing.T) {
	// Produce a real .tsr file via mockTSA (same pattern as
	// storage/timestamp_test.go so we exercise the digitorus parse path
	// end-to-end).
	hashHex, tsrBytes := mintTimestamp(t)
	tsrPath := filepath.Join(t.TempDir(), "record.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("write tsr: %v", err)
	}

	valid, gen, issuerVerified, err := verifyTimestamp(tsrPath, hashHex, nil)
	if err != nil {
		t.Fatalf("verifyTimestamp: %v", err)
	}
	if !valid {
		t.Fatal("expected valid=true")
	}
	if issuerVerified {
		t.Fatal("without --tsa-root the issuer must NOT be reported as verified")
	}
	if gen == nil {
		t.Fatal("expected non-nil GenTime")
	}
	if gen.IsZero() {
		t.Fatal("GenTime must be non-zero")
	}
	if time.Since(*gen) > time.Minute {
		t.Fatalf("GenTime looks wrong: %v", gen)
	}
}

// TestVerifyTimestamp_TrustedRoot proves that anchoring to the genuine TSA root
// verifies the issuer (finding C2). The mock cert is self-signed, so it is its
// own trusted root.
func TestVerifyTimestamp_TrustedRoot(t *testing.T) {
	hashHex, tsrBytes, cert := mintTimestampWithCert(t)
	tsrPath := filepath.Join(t.TempDir(), "record.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("write tsr: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	valid, _, issuerVerified, err := verifyTimestamp(tsrPath, hashHex, roots)
	if err != nil {
		t.Fatalf("verifyTimestamp with trusted root: %v", err)
	}
	if !valid || !issuerVerified {
		t.Fatalf("expected valid+issuerVerified, got valid=%v issuerVerified=%v", valid, issuerVerified)
	}
}

// TestVerifyTimestamp_ForgedIssuerRejected is the core C2 regression: a .tsr
// signed by an untrusted (self-signed) TSA is REJECTED when the auditor anchors
// to a different, genuine root. Before the fix such a forged timestamp passed.
func TestVerifyTimestamp_ForgedIssuerRejected(t *testing.T) {
	// The forged .tsr is signed by TSA A (an attacker's self-signed cert).
	hashHex, tsrBytes, _ := mintTimestampWithCert(t)
	tsrPath := filepath.Join(t.TempDir(), "forged.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("write tsr: %v", err)
	}
	// The auditor trusts a DIFFERENT root (genuine TSA B).
	_, _, foreignCert := mintTimestampWithCert(t)
	roots := x509.NewCertPool()
	roots.AddCert(foreignCert)

	valid, _, issuerVerified, err := verifyTimestamp(tsrPath, hashHex, roots)
	if err == nil {
		t.Fatal("expected the forged (untrusted-issuer) timestamp to be REJECTED")
	}
	if valid || issuerVerified {
		t.Fatalf("forged timestamp must not verify: valid=%v issuerVerified=%v", valid, issuerVerified)
	}
}

func TestVerifyTimestamp_WrongHash(t *testing.T) {
	// Timestamp is for hash A; we verify against hash B. Must fail with an
	// error that identifies the MessageImprint mismatch so an auditor can
	// see the timestamp is for a different artifact.
	_, tsrBytes := mintTimestamp(t)
	tsrPath := filepath.Join(t.TempDir(), "record.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	otherHash := strings.Repeat("de", 32)
	valid, gen, _, err := verifyTimestamp(tsrPath, otherHash, nil)
	if err == nil {
		t.Fatal("expected error for wrong hash")
	}
	if valid {
		t.Fatal("expected valid=false")
	}
	if gen != nil {
		t.Fatalf("expected nil GenTime on mismatch, got %v", gen)
	}
	if !strings.Contains(err.Error(), "MessageImprint") {
		t.Fatalf("error should mention MessageImprint: %v", err)
	}
}

func TestVerifyTimestamp_MalformedTSR(t *testing.T) {
	tsrPath := filepath.Join(t.TempDir(), "garbage.tsr")
	if err := os.WriteFile(tsrPath, []byte{0x00, 0x01, 0x02, 0x03}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	valid, _, _, err := verifyTimestamp(tsrPath, strings.Repeat("ab", 32), nil)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if valid {
		t.Fatal("expected valid=false")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("error should mention parse: %v", err)
	}
}

func TestVerifyTimestamp_FileNotFound(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.tsr")
	_, _, _, err := verifyTimestamp(missing, strings.Repeat("ab", 32), nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error should mention path: %v", err)
	}
}

func TestVerifyTimestamp_EmptyTSR(t *testing.T) {
	tsrPath := filepath.Join(t.TempDir(), "empty.tsr")
	if err := os.WriteFile(tsrPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, _, err := verifyTimestamp(tsrPath, strings.Repeat("ab", 32), nil)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error should mention empty: %v", err)
	}
}

// =============================================================================
// verifyRecord — end-to-end with real RFC 3161 token
// =============================================================================

func TestVerifyRecord_WithValidTimestamp(t *testing.T) {
	f := createSealedRecordFixture(t)
	// Mint a timestamp for the record's actual hash so MessageImprint
	// matches — exercises the full 7-check path.
	hash, err := recordHashOfStruct(t, f.record)
	if err != nil {
		t.Fatalf("ComputeRecordHash: %v", err)
	}
	tsrBytes := mintTimestampFor(t, hash)
	tsrPath := filepath.Join(t.TempDir(), "record.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := verifyStructAsArtifact(t, f.record, f.publicKeyHex, tsrPath, nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if !result.Verified {
		t.Fatalf("expected Verified=true, got false. Reason=%q", result.FailureReason)
	}
	if result.TimestampValid == nil || !*result.TimestampValid {
		t.Fatal("expected TimestampValid=true")
	}
	if result.TimestampGenTime == nil {
		t.Fatal("expected TimestampGenTime to be set")
	}
	requireCheck(t, result.Checks, "RFC 3161 Timestamp", true)
}

func TestVerifyRecord_WithMismatchedTimestamp(t *testing.T) {
	f := createSealedRecordFixture(t)
	// Mint a timestamp for a DIFFERENT hash — must fail on MessageImprint.
	tsrBytes := mintTimestampFor(t, strings.Repeat("7f", 32))
	tsrPath := filepath.Join(t.TempDir(), "record.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := verifyStructAsArtifact(t, f.record, f.publicKeyHex, tsrPath, nil)
	if err != nil {
		t.Fatalf("verifyRecord: %v", err)
	}
	if result.Verified {
		t.Fatal("expected Verified=false")
	}
	if !strings.Contains(result.FailureReason, "timestamp") {
		t.Fatalf("FailureReason should mention timestamp, got %q", result.FailureReason)
	}
}

// =============================================================================
// run() integration — exit codes + stdout/stderr
// =============================================================================

func TestCLI_ValidArtifact_ExitCodeZero(t *testing.T) {
	f := createSealedRecordFixture(t)
	recordPath, pubkeyPath := writeFixtureFiles(t, f)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want %d. stderr=%q stdout=%q",
			code, ExitVerified, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("stdout should contain VERIFIED: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "FAILED") {
		t.Fatalf("stdout should not contain FAILED: %q", stdout.String())
	}
}

func TestCLI_TamperedArtifact_ExitCodeOne(t *testing.T) {
	f := createSealedRecordFixture(t)

	// Write a tampered record to disk — flip one char of the action_type.
	tampered := reSerializeTampered(t, f.record, func(p *verifycore.Record) {
		p.ActionType = "credit_decisionX"
	})
	dir := t.TempDir()
	recordPath := filepath.Join(dir, "record.json")
	if err := os.WriteFile(recordPath, tampered, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	pubkeyPath := filepath.Join(dir, "pubkey.pem")
	if err := os.WriteFile(pubkeyPath, f.publicKeyPEM, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath}, &stdout, &stderr)
	if code != ExitFailed {
		t.Fatalf("exit code = %d, want %d. stderr=%q stdout=%q",
			code, ExitFailed, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAILED") {
		t.Fatalf("stdout should contain FAILED: %q", stdout.String())
	}
}

func TestCLI_MissingRecord_ExitCodeTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit code = %d, want %d. stderr=%q", code, ExitError, stderr.String())
	}
	// The wording changed when --record became repeatable; what must survive is
	// that the message tells the reader how to supply a record.
	if !strings.Contains(stderr.String(), "--record") {
		t.Fatalf("stderr should tell the reader how to pass a record: %q", stderr.String())
	}
}

func TestCLI_MissingPublicKey_ExitCodeTwo(t *testing.T) {
	f := createSealedRecordFixture(t)
	recordPath, _ := writeFixtureFiles(t, f)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "public key") {
		t.Fatalf("stderr should mention 'public key': %q", stderr.String())
	}
}

func TestCLI_NonexistentRecordFile_ExitCodeTwo(t *testing.T) {
	f := createSealedRecordFixture(t)
	_, pubkeyPath := writeFixtureFiles(t, f)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", "/nonexistent.json", "--key", pubkeyPath}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "ERROR") {
		t.Fatalf("stderr should start with ERROR: %q", stderr.String())
	}
}

func TestCLI_BothKeyFlags_ExitCodeTwo(t *testing.T) {
	f := createSealedRecordFixture(t)
	recordPath, pubkeyPath := writeFixtureFiles(t, f)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--record", recordPath,
		"--key", pubkeyPath,
		"--key-hex", f.publicKeyHex,
	}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not both") {
		t.Fatalf("stderr should mention 'not both': %q", stderr.String())
	}
}

func TestCLI_JSONOutput(t *testing.T) {
	f := createSealedRecordFixture(t)
	recordPath, pubkeyPath := writeFixtureFiles(t, f)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath, "--json"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want %d. stderr=%q", code, ExitVerified, stderr.String())
	}
	// Human output must NOT appear in stdout when --json is set.
	if strings.Contains(stdout.String(), "VERIFIED\n") && strings.Contains(stdout.String(), "====") {
		t.Fatalf("stdout looks like human output, not JSON: %q", stdout.String())
	}
	// Parse the JSON and assert on fields we care about.
	var parsed map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw=%q", err, stdout.String())
	}
	if v, ok := parsed["verified"].(bool); !ok || !v {
		t.Fatalf("expected verified=true, got %v", parsed["verified"])
	}
	if id, _ := parsed["record_id"].(string); id != f.record.RecordID {
		t.Fatalf("record_id = %q, want %q", id, f.record.RecordID)
	}
	if tier, _ := parsed["evidence_tier"].(string); tier != "TIER-A" {
		t.Fatalf("evidence_tier = %q, want TIER-A", tier)
	}
	if v, ok := parsed["signature_valid"].(bool); !ok || !v {
		t.Fatalf("expected signature_valid=true, got %v", parsed["signature_valid"])
	}
	if ph, _ := parsed["record_hash"].(string); len(ph) != 64 {
		t.Fatalf("record_hash wrong length: %q", ph)
	}
	// Checks array present.
	if _, ok := parsed["checks"].([]interface{}); !ok {
		t.Fatalf("expected checks array: %v", parsed["checks"])
	}
}

func TestCLI_JSONOutput_Failed(t *testing.T) {
	f := createSealedRecordFixture(t)
	tampered := reSerializeTampered(t, f.record, func(p *verifycore.Record) {
		p.ActionType = "different"
	})
	dir := t.TempDir()
	recordPath := filepath.Join(dir, "p.json")
	pubkeyPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(recordPath, tampered, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(pubkeyPath, f.publicKeyPEM, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath, "--json"}, &stdout, &stderr)
	if code != ExitFailed {
		t.Fatalf("exit code = %d, want %d. stderr=%q", code, ExitFailed, stderr.String())
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if v, _ := parsed["verified"].(bool); v {
		t.Fatal("expected verified=false in JSON output")
	}
	if reason, _ := parsed["failure_reason"].(string); reason == "" {
		t.Fatal("expected non-empty failure_reason")
	}
}

func TestCLI_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), Version) {
		t.Fatalf("stdout should contain %s: %q", Version, stdout.String())
	}
}

func TestCLI_Verbose(t *testing.T) {
	f := createSealedRecordFixture(t)
	recordPath, pubkeyPath := writeFixtureFiles(t, f)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath, "--verbose"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want 0. stderr=%q", code, stderr.String())
	}
	// Verbose includes check details.
	if !strings.Contains(stdout.String(), "JSON parsed successfully") {
		t.Fatalf("verbose output should include details: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Ed25519 signature valid") {
		t.Fatalf("verbose output should include signature detail: %q", stdout.String())
	}
}

func TestCLI_KeyHexFlag(t *testing.T) {
	// --key-hex path, proving auditors with just hex can still verify.
	f := createSealedRecordFixture(t)
	dir := t.TempDir()
	recordPath := filepath.Join(dir, "record.json")
	if err := os.WriteFile(recordPath, f.recordJSON, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key-hex", f.publicKeyHex}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want 0. stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatal("stdout should contain VERIFIED")
	}
}

func TestCLI_UnknownFlag_ExitCodeTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--no-such-flag"}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit code = %d, want %d", code, ExitError)
	}
}

// =============================================================================
// Standalone claim — NO PlainReal infrastructure required
// =============================================================================

// TestStandaloneVerification_NoPlainRealRuntime is the FORENSIC test: the
// verification succeeds with only the record JSON and the public key
// PEM on disk. No server, no ledger, no S3, no auth service, no network.
//
// If this test ever grows a dependency on those, the CLI has broken the
// zero-infrastructure claim that makes the artifact forensically credible.
func TestStandaloneVerification_NoPlainRealRuntime(t *testing.T) {
	f := createSealedRecordFixture(t)
	recordPath, pubkeyPath := writeFixtureFiles(t, f)

	// The test intentionally uses only the file paths and public key PEM —
	// no in-memory record handed in, no signer, no storage reference.
	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("standalone verification failed: exit=%d stderr=%q stdout=%q",
			code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("standalone verification did not report VERIFIED: %q", stdout.String())
	}
	// The artifact identity must be preserved in the output so the auditor
	// knows which record was checked.
	if !strings.Contains(stdout.String(), f.record.RecordID) {
		t.Fatalf("record_id %q must appear in output, got %q",
			f.record.RecordID, stdout.String())
	}
}

// TestStandaloneVerification_CommittedFixture exercises the fixture checked
// in under testdata/ — proves the fixture files are a self-contained
// verification unit. `make demo-verify` reproduces this from the shell.
func TestStandaloneVerification_CommittedFixture(t *testing.T) {
	recordPath := filepath.Join("..", "..", "testdata", "fixture_record.json")
	pubkeyPath := filepath.Join("..", "..", "testdata", "fixture_pubkey.pem")
	if _, err := os.Stat(recordPath); err != nil {
		t.Skipf("committed fixture missing (run `go test -tags=fixturegen ...` to regenerate): %v", err)
	}
	if _, err := os.Stat(pubkeyPath); err != nil {
		t.Skipf("committed fixture missing: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("committed fixture did not verify: exit=%d stderr=%q stdout=%q",
			code, stderr.String(), stdout.String())
	}
}

// =============================================================================
// Schema v1.0.0 — CLI version handling
// =============================================================================

// TestVerify_V1_0_0_Fixture (T11) — full verify flow against the
// committed v1.0.0 fixture under the new (multi-version) CLI. Exit 0,
// stdout reports VERIFIED, and the Record Version check echoes 1.0.0.
func TestVerify_V1_0_0_Fixture(t *testing.T) {
	recordPath := filepath.Join("..", "..", "testdata", "fixture_record.json")
	pubkeyPath := filepath.Join("..", "..", "testdata", "fixture_pubkey.pem")
	if _, err := os.Stat(recordPath); err != nil {
		t.Skipf("v1.0.0 fixture missing: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recordPath, "--key", pubkeyPath, "--verbose"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want %d. stderr=%q stdout=%q",
			code, ExitVerified, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("stdout should contain VERIFIED: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Record Version: 1.0.0") {
		t.Fatalf("verbose output should report version 1.0.0: %q", stdout.String())
	}
}

// TestVerify_UnsupportedVersion (T13) — a record_version this binary
// does not know yields exit 1 and the EXACT stderr message format the
// auditor tooling greps for ("unsupported record version: <v>;
// supported: 1.0.0"). Forward-incompatible artifacts must surface
// clearly enough for an operator to download the matching verify binary.
func TestVerify_UnsupportedVersion(t *testing.T) {
	cases := []string{"2.0.0", "0.9.0"}
	for _, version := range cases {
		t.Run(version, func(t *testing.T) {
			f := createSealedRecordFixture(t)
			// Mutate the version on disk (without re-signing). The version
			// check fires before signature verification, so the failure
			// reason must be the version, not "signature does not match".
			tampered := reSerializeTampered(t, f.record, func(p *verifycore.Record) {
				p.RecordVersion = version
			})
			dir := t.TempDir()
			recordPath := filepath.Join(dir, "p.json")
			pubkeyPath := filepath.Join(dir, "k.pem")
			if err := os.WriteFile(recordPath, tampered, 0o644); err != nil {
				t.Fatalf("write record: %v", err)
			}
			if err := os.WriteFile(pubkeyPath, f.publicKeyPEM, 0o644); err != nil {
				t.Fatalf("write pubkey: %v", err)
			}

			var stdout, stderr bytes.Buffer
			code := run([]string{"--record", recordPath, "--key", pubkeyPath}, &stdout, &stderr)
			// ExitError, not ExitFailed. A schema version this binary cannot
			// speak to is COULD_NOT_VERIFY: no verdict was reached, and the
			// field list we would check against may not describe the record at
			// all. ExitFailed is documented as "was checked and did not
			// verify", so returning it here would report a failure the tool
			// explicitly declined to find, and would make a newer record --
			// most likely a perfectly good one -- look tampered to a script.
			// The web verifier has always called this COULD_NOT_VERIFY; this
			// is the CLI matching it.
			if code != ExitError {
				t.Fatalf("exit code = %d, want %d. stderr=%q stdout=%q",
					code, ExitError, stderr.String(), stdout.String())
			}
			// EXACT stderr line — the architect-pinned format used by
			// downstream log-grep pipelines.
			wantStderr := "unsupported record version: " + version + "; supported: 1.0.0\n"
			if stderr.String() != wantStderr {
				t.Fatalf("stderr mismatch:\n got  = %q\n want = %q", stderr.String(), wantStderr)
			}
			// The same message must appear in the structured output so
			// the auditor's checklist sees it without re-reading stderr.
			if !strings.Contains(stdout.String(), "unsupported record version") {
				t.Fatalf("stdout should also report the unsupported version: %q", stdout.String())
			}
		})
	}
}

// TestVerify_VersionInfoFlag (T14) — `--version-info` prints the
// auditor-facing supported-version list and exits 0 with no other side
// effects. The exact format is a stable contract for any tool that
// inspects which versions a given verify binary supports.
func TestVerify_VersionInfoFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version-info"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit code = %d, want %d. stderr=%q", code, ExitVerified, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for --version-info, got %q", stderr.String())
	}
	const want = "1.0.0\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

// TestVerify_Output_IncludesCaptureFields (T15) — the --json output must
// include the capture_layer and consequential values in the metadata block,
// copied verbatim from the (required, always-present) record fields.
func TestVerify_Output_IncludesCaptureFields(t *testing.T) {
	cases := []struct {
		name           string
		recordPath     string
		pubkeyPath     string
		wantCaptureLay string
		wantConsequent bool
	}{
		{
			name:           "v1_0_0",
			recordPath:     filepath.Join("..", "..", "testdata", "fixture_record.json"),
			pubkeyPath:     filepath.Join("..", "..", "testdata", "fixture_pubkey.pem"),
			wantCaptureLay: "BUSINESS_LAYER",
			wantConsequent: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.recordPath); err != nil {
				t.Skipf("fixture missing: %v", err)
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{
				"--record", tc.recordPath,
				"--key", tc.pubkeyPath,
				"--json",
			}, &stdout, &stderr)
			if code != ExitVerified {
				t.Fatalf("exit code = %d, want %d. stderr=%q", code, ExitVerified, stderr.String())
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
				t.Fatalf("invalid JSON output: %v\nraw=%q", err, stdout.String())
			}
			meta, ok := parsed["metadata"].(map[string]interface{})
			if !ok {
				t.Fatalf("metadata missing or wrong type: %v", parsed["metadata"])
			}
			gotCL, _ := meta["capture_layer"].(string)
			if gotCL != tc.wantCaptureLay {
				t.Errorf("metadata.capture_layer = %q, want %q", gotCL, tc.wantCaptureLay)
			}
			gotCons, ok := meta["consequential"].(bool)
			if !ok {
				t.Fatalf("metadata.consequential not a bool: %v", meta["consequential"])
			}
			if gotCons != tc.wantConsequent {
				t.Errorf("metadata.consequential = %v, want %v", gotCons, tc.wantConsequent)
			}
		})
	}
}

// =============================================================================
// Import discipline — zero PlainReal-runtime dependencies
// =============================================================================

// TestZeroPlainRealInfrastructureImports parses cmd/plainreal-verify/main.go on every
// run and fails if it imports any PlainReal package that pulls in runtime
// infrastructure (storage, auth, sdk, absa). The verifier depends on
// 'core' for pure types and pure crypto — anything else would break the
// zero-infrastructure forensic claim.
func TestZeroPlainRealInfrastructureImports(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	forbidden := []string{
		"github.com/plainreal/plainreal/storage",
		"github.com/plainreal/plainreal/auth",
		"github.com/plainreal/plainreal/sdk",
		"github.com/plainreal/plainreal/absa",
		"github.com/aws/aws-sdk-go-v2",
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbidden {
			if strings.HasPrefix(path, bad) {
				t.Errorf("forbidden import in main.go: %s — verifier must not depend on runtime infra", path)
			}
		}
	}
}

// TestVerifyFunctionUsesVerifycoreVerifyWithPublicKey asserts that our
// verification path delegates to verifycore.VerifyWithPublicKey rather than
// re-implementing Ed25519 verification locally. Divergence would be a subtle
// forensic risk; any future change to the auditor's zero-dependency path should
// propagate here automatically.
//
// The package moved from core to verifycore in the split that took the sealer
// out of the CLI's build. The assertion is the same one.
func TestVerifyFunctionUsesVerifycoreVerifyWithPublicKey(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "verifyRecord" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("verifyRecord not found")
	}
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "verifycore" && sel.Sel.Name == "VerifyWithPublicKey" {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatal("verifyRecord must delegate to verifycore.VerifyWithPublicKey")
	}
}

// =============================================================================
// Helpers
// =============================================================================

// requireCheck fails the test if no entry in checks matches name + passed.
func requireCheck(t *testing.T, checks []Check, name string, passed bool) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if c.Passed != passed {
				t.Fatalf("check %q: passed=%v, want %v. details=%q", name, c.Passed, passed, c.Details)
			}
			return
		}
	}
	t.Fatalf("check %q not found in %+v", name, checks)
}

// =============================================================================
// mockTSA — in-process Time Stamping Authority for RFC 3161 tests
// =============================================================================
//
// This is a minimized, local variant of storage/timestamp_test.go's mockTSA.
// Duplicated intentionally so cmd/plainreal-verify/ has no test-time dependency on
// the storage package — keeping the verifier's test harness as clean as
// the production binary.

var tsaOIDKeyPurposeTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

type mockTSA struct {
	server *httptest.Server
	cert   *x509.Certificate
	key    *rsa.PrivateKey
}

func newMockTSA(t *testing.T) *mockTSA {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PlainReal Verify Mock TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{tsaOIDKeyPurposeTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	m := &mockTSA{cert: cert, key: key}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockTSA) url() string { return m.server.URL }

func (m *mockTSA) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	req, err := ts3161.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tkn := &ts3161.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              time.Now().UTC(),
		Nonce:             req.Nonce,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      serial,
		Certificates:      []*x509.Certificate{m.cert},
		AddTSACertificate: true,
	}
	resp, err := tkn.CreateResponseWithOpts(m.cert, m.key, crypto.SHA256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(resp)
}

// mintTimestamp generates a fresh 32-byte hash and returns (hashHex, tsrBytes).
func mintTimestamp(t *testing.T) (string, []byte) {
	t.Helper()
	hashBytes := make([]byte, 32)
	if _, err := rand.Read(hashBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	hashHex := hex.EncodeToString(hashBytes)
	return hashHex, mintTimestampFor(t, hashHex)
}

// mintTimestampWithCert timestamps a random hash and also returns the mock
// TSA's signing certificate, so C2 tests can build a trusted-root pool (the
// mock cert is self-signed, so it is its own root) or a foreign pool.
func mintTimestampWithCert(t *testing.T) (string, []byte, *x509.Certificate) {
	t.Helper()
	hashBytes := make([]byte, 32)
	if _, err := rand.Read(hashBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	hashHex := hex.EncodeToString(hashBytes)
	m := newMockTSA(t)
	return hashHex, mintViaMock(t, m, hashHex), m.cert
}

// mintTimestampFor timestamps a specific hash and returns the raw .tsr bytes.
func mintTimestampFor(t *testing.T, hashHex string) []byte {
	t.Helper()
	m := newMockTSA(t)
	return mintViaMock(t, m, hashHex)
}

// mintViaMock issues a .tsr for hashHex against an already-constructed mock TSA.
func mintViaMock(t *testing.T, m *mockTSA, hashHex string) []byte {
	t.Helper()
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	req := &ts3161.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: hashBytes,
		Certificates:  true,
		Nonce:         big.NewInt(12345),
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}
	httpResp, err := http.Post(m.url(), "application/timestamp-query", bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("TSA HTTP %d: %s", httpResp.StatusCode, body)
	}
	return body
}

// newTestCA mints a self-signed CA (no timestamping EKU — it is a root, not a
// leaf signer).
func newTestCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

// newTSALeafSignedBy mints a timestamping leaf certificate signed by the given
// CA (so the leaf chains to the CA, not to itself).
func newTSALeafSignedBy(t *testing.T, cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{tsaOIDKeyPurposeTimeStamping},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert, key
}

// TestVerifyTimestamp_MultiCertChainAndSignerBinding is the regression guard for
// the round-3 finding that verifyTSACertChain assumed the signer was
// Certificates[0]. It mints a token from a real CA -> leaf chain (the token is
// signed by the LEAF and embeds both the leaf and the CA). Two properties:
//   - Anchoring to the CA root must ACCEPT. The old positional code would run
//     leaf.Verify() on whichever cert the ASN.1 SET happened to place at index
//     0 — if that was the CA, the timestamping-EKU requirement failed and a
//     GENUINE multi-cert timestamp was wrongly rejected. The signer-bound code
//     verifies correctly regardless of SET order.
//   - Anchoring to an UNRELATED root must REJECT — trust binds to the signer
//     chain, not to any embedded certificate.
func TestVerifyTimestamp_MultiCertChainAndSignerBinding(t *testing.T) {
	ca, caKey := newTestCA(t, "PlainReal Test Root CA")
	leaf, leafKey := newTSALeafSignedBy(t, "PlainReal TSA Leaf", ca, caKey)

	hashBytes := make([]byte, 32)
	if _, err := rand.Read(hashBytes); err != nil {
		t.Fatal(err)
	}
	hashHex := hex.EncodeToString(hashBytes)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tkn := &ts3161.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     hashBytes,
		Time:              time.Now().UTC(),
		Nonce:             big.NewInt(1),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      serial,
		Certificates:      []*x509.Certificate{ca}, // embed the CA alongside the signing leaf
		AddTSACertificate: true,
	}
	tsr, err := tkn.CreateResponseWithOpts(leaf, leafKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("create multi-cert response: %v", err)
	}
	tsrPath := filepath.Join(t.TempDir(), "chain.tsr")
	if err := os.WriteFile(tsrPath, tsr, 0o644); err != nil {
		t.Fatal(err)
	}

	// Anchor to the genuine CA root -> ACCEPT (no false reject on a real chain).
	caRoots := x509.NewCertPool()
	caRoots.AddCert(ca)
	valid, _, issuerVerified, err := verifyTimestamp(tsrPath, hashHex, caRoots)
	if err != nil || !valid || !issuerVerified {
		t.Fatalf("genuine CA-rooted multi-cert timestamp must verify: valid=%v issuer=%v err=%v", valid, issuerVerified, err)
	}

	// Anchor to an unrelated root -> REJECT (trust binds to the signer chain).
	other, _ := newTestCA(t, "Unrelated Root")
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other)
	valid2, _, issuerVerified2, err2 := verifyTimestamp(tsrPath, hashHex, otherRoots)
	if err2 == nil || valid2 || issuerVerified2 {
		t.Fatalf("an unrelated root must REJECT: valid=%v issuer=%v err=%v", valid2, issuerVerified2, err2)
	}
}

// TestVerifyTimestamp_NoEmbeddedCertWithRoot proves the signer-bound chain
// check rejects cleanly (no panic) when the token embeds no certificate but the
// auditor supplied --tsa-root: without the signer cert, trust cannot be
// established, so it must be reported as not-issuer-verified / rejected.
func TestVerifyTimestamp_NoEmbeddedCertWithRoot(t *testing.T) {
	ca, caKey := newTestCA(t, "Root CA")
	leaf, leafKey := newTSALeafSignedBy(t, "TSA Leaf", ca, caKey)
	hashBytes := make([]byte, 32)
	if _, err := rand.Read(hashBytes); err != nil {
		t.Fatal(err)
	}
	hashHex := hex.EncodeToString(hashBytes)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tkn := &ts3161.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     hashBytes,
		Time:              time.Now().UTC(),
		Nonce:             big.NewInt(1),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      serial,
		AddTSACertificate: false, // do NOT embed the signing cert
	}
	tsr, err := tkn.CreateResponseWithOpts(leaf, leafKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("create response: %v", err)
	}
	tsrPath := filepath.Join(t.TempDir(), "nocert.tsr")
	if err := os.WriteFile(tsrPath, tsr, 0o644); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	valid, _, issuerVerified, err := verifyTimestamp(tsrPath, hashHex, roots)
	if err == nil || valid || issuerVerified {
		t.Fatalf("a token with no embedded cert must fail issuer verification: valid=%v issuer=%v err=%v", valid, issuerVerified, err)
	}
}

// Ensure package imports that could otherwise appear unused under certain
// build tags remain referenced. (Defensive — keeps CI stable as mockTSA
// evolves.)
var _ = fmt.Sprintf

// verifyStructAsArtifact marshals p and runs the real byte-based verifier over
// the resulting bytes (§4.6.1).
//
// Tests that mutate a record are simulating a TAMPERED ARTIFACT, so
// serializing the mutation and verifying the bytes is the faithful translation:
// it is exactly what a tamperer would hand an auditor. Passing the struct
// straight to the verifier would test a path no auditor has — they hold a file,
// not a Go value.
func verifyStructAsArtifact(t *testing.T, p *verifycore.Record, pubHex, tsrPath string, roots *x509.CertPool) (*VerificationResult, error) {
	t.Helper()
	raw, err := p.ToJSON()
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return verifyRecord(raw, p, pubHex, tsrPath, roots)
}

// =============================================================================
// §4.6.1 / §6 — the auditor path over the artifact's own bytes
// =============================================================================

// TestVerify_ForwardCompatibleArtifact_StillVerifies is the CLI-level proof of
// §6's additive-evolution promise, and the reason verifyRecord takes bytes.
//
// A NEWER producer adds a key inside the versioned provenance envelope — which
// §6 explicitly permits — and signs the document it actually emits. THIS binary
// does not know that key. It must still verify the artifact: the unknown key is
// part of the document, so it is hashed and signed; interpretation ignores it.
//
// Before M1 this CLI unmarshaled into verifycore.Record and re-marshaled, which
// dropped the unknown key, computed a different hash, and reported the artifact
// as INVALID. To an auditor that is indistinguishable from tampering — the
// worst possible failure mode for evidence, because it accuses a valid record.
func TestVerify_ForwardCompatibleArtifact_StillVerifies(t *testing.T) {
	f := createSealedRecordFixture(t)

	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}

	// A future capability lands as a new named key inside the envelope (§2.4).
	prov := tree["provenance"].(map[string]interface{})
	prov["future_capability_ref"] = "wf:some-new-thing"

	// The newer producer re-derives I3 over the provenance it actually wrote...
	provBytes, err := json.Marshal(prov)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := verifycore.CanonicalizeJSON(provBytes)
	if err != nil {
		t.Fatal(err)
	}
	tree["causality_chain_hash"] = verifycore.HashSHA3256(canonical)

	// ...and signs the bytes it emits.
	delete(tree, "signing_attestation")
	unsigned, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := verifycore.RecordHashFromBytes(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := f.signer.Sign(hash)
	if err != nil {
		t.Fatal(err)
	}
	tree["signing_attestation"] = sig
	evolved, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "evolved_record.json")
	if err := os.WriteFile(path, evolved, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", path, "--key-hex", f.publicKeyHex, "--json"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("an artifact carrying an unknown ENVELOPE key was rejected (exit %d) — "+
			"§6 promises envelopes may grow additively, and §4.6.1 is what makes that true.\nstdout: %s\nstderr: %s",
			code, stdout.String(), stderr.String())
	}

	var result VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse --json: %v", err)
	}
	if !result.Verified || !result.SignatureValid {
		t.Fatalf("verified=%v signature_valid=%v, want both true", result.Verified, result.SignatureValid)
	}
	if result.RecordHash != hash {
		t.Errorf("record_hash = %s, want %s (the hash the producer signed)", result.RecordHash, hash)
	}
}

// TestVerify_UnknownTopLevelKeyIsRejected is §6's other half. An unknown key at
// the TOP level is not additive evolution — it is someone inventing a field
// outside the frozen 33-field list, and the list is frozen precisely so that
// cannot happen silently.
func TestVerify_UnknownTopLevelKeyIsRejected(t *testing.T) {
	f := createSealedRecordFixture(t)

	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}
	tree["invented_field"] = "nope"
	mutated, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "extra_key.json")
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", path, "--key-hex", f.publicKeyHex, "--json"}, &stdout, &stderr); code == ExitVerified {
		t.Fatal("a record with an unknown TOP-LEVEL key verified; the 33-field list is frozen (§6)")
	}
}

// =============================================================================
// Stage 3: verdict classification and CLI hygiene
// =============================================================================

// TestCLI_TrailingPositionalArgs_AreVerifiedNotIgnored is the original footgun,
// restated after Stage 4 changed what the right answer is.
//
// `--record a.json --key k.pem b.json c.json` once verified a.json, silently
// discarded b.json and c.json, and exited 0. That is what a shell produces from
// `--record *.json`. Step 12 made it an error, which was the safe fix. Batch
// makes the bare paths RECORDS, which is the right one.
//
// The invariant is the same in both designs and is what this test pins: no file
// named on the command line goes unexamined while the tool reports success.
// Here the two extra paths do not exist, so each must be reported by name.
func TestCLI_TrailingPositionalArgs_AreVerifiedNotIgnored(t *testing.T) {
	f := createSealedRecordFixture(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "a.json")
	if err := os.WriteFile(good, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	missingB := filepath.Join(dir, "b.json")
	missingC := filepath.Join(dir, "c.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", good, "--key-hex", f.publicKeyHex, missingB, missingC}, &stdout, &stderr)

	if code == ExitVerified {
		t.Fatal("VERIFIED with two unreadable files on the command line; " +
			"this is the --record *.json footgun and it must never exit 0")
	}
	for _, want := range []string{"b.json", "c.json"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not mention %q; every path on the command line must be accounted for.\ngot: %s",
				want, stderr.String())
		}
	}
}

// TestCLI_UnknownTopLevelKey_IsArtifactVerdict pins step 9. A record carrying a
// field outside the frozen 33 is a judgment about the artifact, so it exits
// FAILED. It used to exit ERROR, which meant a record tampered with by
// APPENDING a field reported as an input problem, and an auditor script testing
// `exit == 1` for tampering saw 2 and moved on.
func TestCLI_UnknownTopLevelKey_IsArtifactVerdict(t *testing.T) {
	f := createSealedRecordFixture(t)
	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}
	tree["invented_field"] = "nope"
	mutated, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "extra.json")
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", path, "--key-hex", f.publicKeyHex}, &stdout, &stderr); code != ExitFailed {
		t.Fatalf("exit = %d, want %d: a non-conformant document is an artifact verdict, not an input error", code, ExitFailed)
	}
}

// TestCLI_UnsafeInteger_IsArtifactVerdict pins step 10. An integer beyond
// ±(2^53-1) cannot be canonicalized losslessly, which is a fact about the FILE.
// It used to print "verification internal error", which reads as "the verifier
// is broken" rather than "this document cannot be hashed".
func TestCLI_UnsafeInteger_IsArtifactVerdict(t *testing.T) {
	f := createSealedRecordFixture(t)
	raw := strings.Replace(string(f.recordJSON),
		`"lock_verification_latency_ms":47`, `"lock_verification_latency_ms":9007199254740993`, 1)
	path := filepath.Join(t.TempDir(), "bigint.json")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", path, "--key-hex", f.publicKeyHex}, &stdout, &stderr)
	if code == ExitVerified {
		t.Fatal("an unhashable document verified")
	}
	if strings.Contains(stderr.String(), "internal error") {
		t.Errorf("still reported as an internal error; it is a property of the file.\ngot: %s", stderr.String())
	}
}

// TestCLI_WrongKey_IsNotReportedAsTampering pins step 11. A valid record checked
// against the wrong key used to produce failure_reason "may have been tampered
// with" -- accusing an intact record. The browser page has kept these apart
// since v1.0.0 because collapsing them is how a verification tool starts lying.
func TestCLI_WrongKey_IsNotReportedAsTampering(t *testing.T) {
	f := createSealedRecordFixture(t)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(path, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", path, "--key-hex", hex.EncodeToString(other), "--json"},
		&stdout, &stderr); code != ExitFailed {
		t.Fatalf("exit = %d, want %d", code, ExitFailed)
	}
	var res VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("parse --json: %v", err)
	}
	if strings.Contains(res.FailureReason, "tampered") {
		t.Errorf("wrong key reported as tampering: %q", res.FailureReason)
	}
	if !strings.Contains(res.FailureReason, "different key") {
		t.Errorf("failure_reason does not say it is a key mismatch: %q", res.FailureReason)
	}
}

// TestCLI_Help_GoesToStdoutAndExitsZero pins step 13. `--help | less` showed an
// empty screen and `--help` in a script looked like a failure.
func TestCLI_Help_GoesToStdoutAndExitsZero(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{flag}, &stdout, &stderr); code != ExitVerified {
			t.Errorf("%s exit = %d, want 0: asking for help is not an error", flag, code)
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("%s wrote no usage to stdout", flag)
		}
	}
}

// TestCLI_VersionOutputsAreLabelled pins step 15. --version and --version-info
// both printed a bare semver with nothing saying which was the binary and which
// was the record schema.
func TestCLI_VersionOutputsAreLabelled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != ExitVerified {
		t.Fatalf("exit = %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "plainreal-verify") {
		t.Error("--version does not name the binary")
	}
	if !strings.Contains(out, "record schema versions accepted") {
		t.Error("--version does not distinguish the binary version from the schema versions")
	}
}

// TestCLI_FilenameCannotForgeAVerdict is a regression test for a defect a
// hostile review of Stage 3 found in Stage 3's own fix.
//
// Artifact rejections were originally told apart from input errors by matching
// substrings against the error message. Those messages embed the record PATH,
// so a file named "does-not-exist unknown top-level key.json" made a plain
// missing-file error classify as a verdict about an artifact. User-controlled
// text was reaching a security decision through an error string.
func TestCLI_FilenameCannotForgeAVerdict(t *testing.T) {
	f := createSealedRecordFixture(t)
	dir := t.TempDir()
	for _, name := range []string{
		"does-not-exist unknown top-level key.json",
		"canonicalize.json",
		"duplicate key.json",
	} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--record", filepath.Join(dir, name), "--key-hex", f.publicKeyHex}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("%q: exit = %d, want %d. A missing file is an input error however it is named",
				name, code, ExitError)
		}
	}
}

// TestCLI_RecordNamedLikeAFlag_IsNotHelp is the second regression from that
// review, and it is the sharper one: it was the SAME defect step 12 fixed,
// reintroduced by step 13 two changes later.
//
// --help was first detected by scanning raw args for "-h". A record file named
// exactly "-h", passed as the VALUE of --record, printed usage and exited 0
// having verified nothing. flag knows which token is a flag and which is a
// value; a scan cannot, so detection is now flag.ErrHelp.
func TestCLI_RecordNamedLikeAFlag_IsNotHelp(t *testing.T) {
	f := createSealedRecordFixture(t)
	dir := t.TempDir()
	for _, name := range []string{"-h", "--help", "-help"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, f.recordJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		// Pass the bare name, as a shell would from that directory.
		cwd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"--record", name, "--key-hex", f.publicKeyHex}, &stdout, &stderr)
		_ = os.Chdir(cwd)

		if strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("--record %q printed usage; a record named like a flag must still be verified", name)
		}
		if code != ExitVerified {
			t.Errorf("--record %q: exit = %d, want %d (it is a valid record)", name, code, ExitVerified)
		}
	}
}

// =============================================================================
// Stage 4: batch. Tests written BEFORE the implementation.
// =============================================================================
//
// Batch is where "exit 0 without verifying" lives most naturally: a wrong
// aggregate exit code, a short circuit on the first record, or an empty input
// list all produce a green result over records nobody checked. That defect
// class has already appeared three times in this work, twice from fixes meant
// to remove it, so the properties come first and the code comes second.

// batchFixture writes n records to a temp dir, corrupting the ones named in
// bad, and returns their paths in order.
func batchFixture(t *testing.T, f *sealedFixture, n int, bad map[int]bool) []string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i := 0; i < n; i++ {
		raw := f.recordJSON
		if bad[i] {
			var tree map[string]interface{}
			if err := json.Unmarshal(raw, &tree); err != nil {
				t.Fatal(err)
			}
			tree["action_type"] = "tampered_after_sealing"
			m, err := json.Marshal(tree)
			if err != nil {
				t.Fatal(err)
			}
			raw = m
		}
		p := filepath.Join(dir, fmt.Sprintf("record_%02d.json", i))
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	return paths
}

func batchArgs(keyHex string, paths []string, extra ...string) []string {
	args := append([]string{"--key-hex", keyHex}, extra...)
	for _, p := range paths {
		args = append(args, "--record", p)
	}
	return args
}

// TestBatch_AllGood_ExitZero — the only case that may exit 0.
func TestBatch_AllGood_ExitZero(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 3, nil)
	var stdout, stderr bytes.Buffer
	if code := run(batchArgs(f.publicKeyHex, paths), &stdout, &stderr); code != ExitVerified {
		t.Fatalf("exit = %d, want 0.\n%s\n%s", code, stdout.String(), stderr.String())
	}
}

// TestBatch_OneBadAmongMany_ExitOne — the exit code means "did any of these
// fail". A single bad record among nine good ones must not be averaged away.
func TestBatch_OneBadAmongMany_ExitOne(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 9, map[int]bool{7: true})
	var stdout, stderr bytes.Buffer
	if code := run(batchArgs(f.publicKeyHex, paths), &stdout, &stderr); code != ExitFailed {
		t.Fatalf("exit = %d, want %d: one failure among nine must fail the batch", code, ExitFailed)
	}
}

// TestBatch_DoesNotShortCircuit — every record gets a verdict. Stopping at the
// first failure would leave later records unexamined while still exiting 1,
// which reads as "these were checked and one was bad".
func TestBatch_DoesNotShortCircuit(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 5, map[int]bool{0: true, 1: true})
	var stdout, stderr bytes.Buffer
	run(batchArgs(f.publicKeyHex, paths, "--json"), &stdout, &stderr)

	var results []VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("--json must emit an array for a batch: %v\n%s", err, stdout.String())
	}
	if len(results) != len(paths) {
		t.Fatalf("got %d verdicts for %d records; every record must be reported", len(results), len(paths))
	}
}

// TestBatch_NoRecords_IsAnError — the empty case. Verifying nothing and
// reporting success is the purest form of this defect.
func TestBatch_NoRecords_IsAnError(t *testing.T) {
	f := createSealedRecordFixture(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--key-hex", f.publicKeyHex}, &stdout, &stderr)
	if code == ExitVerified {
		t.Fatal("exited 0 having verified nothing")
	}
	if code != ExitError {
		t.Errorf("exit = %d, want %d", code, ExitError)
	}
}

// TestBatch_MissingFileFailsTheBatch — an unreadable record must not be skipped
// with the rest reported green.
func TestBatch_MissingFileFailsTheBatch(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 2, nil)
	paths = append(paths, filepath.Join(t.TempDir(), "absent.json"))
	var stdout, stderr bytes.Buffer
	if code := run(batchArgs(f.publicKeyHex, paths), &stdout, &stderr); code == ExitVerified {
		t.Fatal("exited 0 with an unreadable record in the batch")
	}
}

// TestBatch_OutputIsNeverAChainClaim enforces the publication boundary.
// N independent Level-0 verdicts are not a statement about a workflow, and
// CLAUDE.md forbids output that could be read as one.
func TestBatch_OutputIsNeverAChainClaim(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 3, nil)
	var stdout, stderr bytes.Buffer
	run(batchArgs(f.publicKeyHex, paths), &stdout, &stderr)

	out := strings.ToLower(stdout.String())
	for _, banned := range []string{"workflow verified", "chain intact", "chain verified", "all records verified together"} {
		if strings.Contains(out, banned) {
			t.Errorf("batch output contains %q; N independent verdicts are not a chain result", banned)
		}
	}
	if !strings.Contains(out, "one at a time") && !strings.Contains(out, "independently") {
		t.Error("batch output does not say the records were checked independently")
	}
}

// TestBatch_GlobShapeVerifiesEveryFile is the original footgun, restated as the
// property that actually matters.
//
// Step 12 made `--record *.json` refuse rather than silently ignore the extra
// paths. Refusing was the safe fix; verifying them is the right one. What must
// never happen is a file on the command line going unexamined while the tool
// reports success.
func TestBatch_GlobShapeVerifiesEveryFile(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 4, map[int]bool{3: true})

	// Exactly what a shell produces from `--record *.json`.
	args := []string{"--record", paths[0], "--key-hex", f.publicKeyHex}
	args = append(args, paths[1:]...)

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code == ExitVerified {
		t.Fatal("glob shape exited 0 while a tampered record was on the command line")
	}
}

// TestBatch_FlagAfterPath_IsRefused was found by running the tool, not by a
// test, which is why it is here now.
//
// Go's flag package stops parsing at the first non-flag argument. Once bare
// paths became records, `--record a.json b.json --json` silently lost --json
// AND added a record path called "--json": the flag did nothing and the tool
// tried to read a file that does not exist. Silently reinterpreting a flag as
// a filename is the same class of failure this stage exists to remove.
func TestBatch_FlagAfterPath_IsRefused(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 2, nil)

	var stdout, stderr bytes.Buffer
	args := []string{"--key-hex", f.publicKeyHex, "--record", paths[0], paths[1], "--json"}
	code := run(args, &stdout, &stderr)

	if code != ExitError {
		t.Fatalf("exit = %d, want %d: a flag after a path must be refused, not read as a file", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "--json") || !strings.Contains(stderr.String(), "Nothing was checked") {
		t.Errorf("stderr must name the misplaced flag and say nothing was checked.\ngot: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "signature valid") {
		t.Error("verified records despite a misparsed command line")
	}
}

// TestBatch_FlagsBeforePaths_Work is the other half: the documented invocation
// must actually apply the flag.
func TestBatch_FlagsBeforePaths_Work(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 2, nil)

	var stdout, stderr bytes.Buffer
	args := append([]string{"--key-hex", f.publicKeyHex, "--json"}, paths...)
	if code := run(args, &stdout, &stderr); code != ExitVerified {
		t.Fatalf("exit = %d, want 0.\n%s", code, stderr.String())
	}
	var results []VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("--json before the paths must produce a JSON array: %v\n%s", err, stdout.String())
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
}

// TestBatch_JSONNamesTheFile — without a path, a --json array is unusable. A
// record that could not be read has no record_id, and several copies of the
// same artifact share one, so a consumer could not map a verdict to a file.
func TestBatch_JSONNamesTheFile(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 2, nil)
	paths = append(paths, filepath.Join(t.TempDir(), "absent.json"))

	var stdout, stderr bytes.Buffer
	args := append([]string{"--key-hex", f.publicKeyHex, "--json"}, paths...)
	run(args, &stdout, &stderr)

	var results []VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("parse array: %v\n%s", err, stdout.String())
	}
	if len(results) != len(paths) {
		t.Fatalf("got %d results for %d records", len(results), len(paths))
	}
	for i, r := range results {
		if r.Path != paths[i] {
			t.Errorf("result[%d].path = %q, want %q: every verdict must name its file", i, r.Path, paths[i])
		}
	}
}

// TestBatch_TSRWithManyRecords_IsRefused — an RFC 3161 token commits to ONE
// record's hash. Applying one across a batch reports a MessageImprint mismatch
// on every record but the first, which reads as a timestamp failure on records
// that are sound: the same false accusation as reporting a wrong key as
// tampering.
func TestBatch_TSRWithManyRecords_IsRefused(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 2, nil)
	tsr := filepath.Join(t.TempDir(), "one.tsr")
	if err := os.WriteFile(tsr, []byte("irrelevant"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	args := append([]string{"--key-hex", f.publicKeyHex, "--tsr", tsr}, paths...)
	if code := run(args, &stdout, &stderr); code != ExitError {
		t.Fatalf("exit = %d, want %d: one token cannot cover several records", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "Nothing was checked") {
		t.Errorf("stderr must say nothing was checked.\ngot: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "signature valid") {
		t.Error("verified records despite refusing the invocation")
	}
}

// TestSingle_TSRStillAccepted — the refusal above must not over-reach.
func TestSingle_TSRStillAccepted(t *testing.T) {
	f := createSealedRecordFixture(t)
	paths := batchFixture(t, f, 1, nil)
	tsr := filepath.Join(t.TempDir(), "one.tsr")
	if err := os.WriteFile(tsr, []byte("irrelevant"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--key-hex", f.publicKeyHex, "--tsr", tsr, "--record", paths[0]}, &stdout, &stderr)
	if code == ExitError {
		t.Fatalf("a single record with --tsr must still be attempted, got exit %d: %s", code, stderr.String())
	}
}

// =============================================================================
// Stage 5, step 18: the cryptographic negatives, pinned AT THE CLI
// =============================================================================
//
// All four already worked, inherited from verifycore. Nothing in this package
// said so, which meant a future refactor that stopped routing through
// verifycore.VerifyWithPublicKey or CanonicalizeJSON would silently drop them
// and every test here would still pass.

// ed25519GroupOrder is L = 2^252 + 27742317777372353535851937790883648493.
func ed25519GroupOrder() *big.Int {
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return l
}

// TestCLI_SignatureMalleability_Rejected — a signature with S >= L verifies
// under a naive implementation while being a DIFFERENT encoding of the same
// signature. Accepting both would let an artifact carry two valid signatures,
// which breaks the assumption that a record hashes and signs to one thing.
func TestCLI_SignatureMalleability_Rejected(t *testing.T) {
	f := createSealedRecordFixture(t)

	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(tree["signing_attestation"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// S := S + L, little-endian, which is the canonical malleability case.
	sLE := make([]byte, 32)
	copy(sLE, sig[32:])
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		sLE[i], sLE[j] = sLE[j], sLE[i]
	}
	s := new(big.Int).SetBytes(sLE)
	s.Add(s, ed25519GroupOrder())
	mal := s.Bytes()
	if len(mal) > 32 {
		t.Skip("S+L overflows 32 bytes for this signature; not a malleable encoding")
	}
	padded := make([]byte, 32)
	copy(padded[32-len(mal):], mal)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		padded[i], padded[j] = padded[j], padded[i]
	}
	tree["signing_attestation"] = hex.EncodeToString(append(append([]byte{}, sig[:32]...), padded...))

	mutated, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "malleable.json")
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", path, "--key-hex", f.publicKeyHex}, &stdout, &stderr); code == ExitVerified {
		t.Fatal("a malleable signature (S >= L) verified; Ed25519 requires canonical S")
	}
}

// TestCLI_NonCanonicalPublicKey_Rejected — a 32-byte string is not a public
// key. Only some of them encode a curve point, and the rest must be refused
// cleanly rather than reduced, guessed at, or panicked on.
//
// The first version of this test built y+p and skipped when that exceeded 255
// bits, which is almost every key: p is just under 2^255, so y+p fits only for
// y < 19. It skipped rather than ran, and a test that never runs is worse than
// none because the suite reports it as covered.
//
// These cases are deterministic. y = p and y = p+1 are the genuinely
// non-canonical encodings (of y = 0 and y = 1); all-0xFF is y >= p and not a
// valid point; all-zero encodes a low-order point. None may verify, and none
// may crash.
func TestCLI_NonCanonicalPublicKey_Rejected(t *testing.T) {
	f := createSealedRecordFixture(t)
	path := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(path, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	p25519 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	leBytes := func(v *big.Int) string {
		b := v.Bytes()
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
		return hex.EncodeToString(out)
	}

	for name, keyHex := range map[string]string{
		"y = p (non-canonical zero)":     leBytes(p25519),
		"y = p+1 (non-canonical one)":    leBytes(new(big.Int).Add(p25519, big.NewInt(1))),
		"all 0xff (y >= p, not a point)": strings.Repeat("ff", 32),
		"all zero (low-order point)":     strings.Repeat("00", 32),
	} {
		var stdout, stderr bytes.Buffer
		code := func() (c int) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", name, r)
					c = -1
				}
			}()
			return run([]string{"--record", path, "--key-hex", keyHex}, &stdout, &stderr)
		}()
		if code == ExitVerified {
			t.Errorf("%s: verified a record; a malformed key must never verify", name)
		}
	}
}

// TestCLI_DuplicateJSONKey_Rejected — RFC 8785 forbids duplicate keys, and a
// last-wins parser is a classic differential-parsing attack: two readers of one
// document disagree about what it says.
func TestCLI_DuplicateJSONKey_Rejected(t *testing.T) {
	f := createSealedRecordFixture(t)
	raw := string(f.recordJSON)
	idx := strings.Index(raw, `"action_type":`)
	if idx == -1 {
		t.Skip("fixture shape changed")
	}
	dup := raw[:idx] + `"action_type":"wire_transfer",` + raw[idx:]

	path := filepath.Join(t.TempDir(), "dup.json")
	if err := os.WriteFile(path, []byte(dup), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", path, "--key-hex", f.publicKeyHex}, &stdout, &stderr); code == ExitVerified {
		t.Fatal("a record with a duplicate top-level key verified")
	}
}

// =============================================================================
// Stage 5, step 20: --tsa-root, end to end through the CLI
// =============================================================================
//
// loadTSARoots was at 0% coverage. verifyTSACertChain beneath it was tested,
// but the flag a user actually types was not, so the loader could have been
// broken in any way at all and every test would still have passed.

// writeTSARootPEM writes the mock TSA's self-signed certificate as a PEM file,
// which is what a caller passes to --tsa-root.
func writeTSARootPEM(t *testing.T, m *mockTSA, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "tsa-root.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw})
	if err := os.WriteFile(p, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCLI_TSARoot_AnchorsTheIssuer is the flag doing its job: with a trusted
// root the TSA's identity is established, and the result says so.
func TestCLI_TSARoot_AnchorsTheIssuer(t *testing.T) {
	f := createSealedRecordFixture(t)
	m := newMockTSA(t)
	defer m.server.Close()

	dir := t.TempDir()
	recPath := filepath.Join(dir, "r.json")
	if err := os.WriteFile(recPath, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := verifycore.RecordHashFromBytes(f.recordJSON)
	if err != nil {
		t.Fatal(err)
	}
	tsrPath := filepath.Join(dir, "r.tsr")
	if err := os.WriteFile(tsrPath, mintViaMock(t, m, hash), 0o644); err != nil {
		t.Fatal(err)
	}
	rootPath := writeTSARootPEM(t, m, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--record", recPath, "--key-hex", f.publicKeyHex,
		"--tsr", tsrPath, "--tsa-root", rootPath, "--json"}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("exit = %d, want 0.\n%s\n%s", code, stdout.String(), stderr.String())
	}
	var res VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.TimestampIssuerVerified == nil || !*res.TimestampIssuerVerified {
		t.Error("timestamp_issuer_verified is not true despite a matching --tsa-root")
	}
}

// TestCLI_TSARoot_ForeignRootIsRefused is the half that matters. Without
// anchoring, a self-signed .tsr passes, so the time proof is not
// forgery-resistant. A root that does not sign this token must fail.
func TestCLI_TSARoot_ForeignRootIsRefused(t *testing.T) {
	f := createSealedRecordFixture(t)
	signing := newMockTSA(t)
	defer signing.server.Close()
	foreign := newMockTSA(t)
	defer foreign.server.Close()

	dir := t.TempDir()
	recPath := filepath.Join(dir, "r.json")
	if err := os.WriteFile(recPath, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := verifycore.RecordHashFromBytes(f.recordJSON)
	if err != nil {
		t.Fatal(err)
	}
	tsrPath := filepath.Join(dir, "r.tsr")
	if err := os.WriteFile(tsrPath, mintViaMock(t, signing, hash), 0o644); err != nil {
		t.Fatal(err)
	}
	rootPath := writeTSARootPEM(t, foreign, dir)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", recPath, "--key-hex", f.publicKeyHex,
		"--tsr", tsrPath, "--tsa-root", rootPath}, &stdout, &stderr); code == ExitVerified {
		t.Fatal("a timestamp signed by one TSA verified against a different root")
	}
}

// TestCLI_TSARoot_LoaderErrors covers loadTSARoots itself: a missing file and a
// file with no certificate in it must both fail loudly. Silently proceeding
// with no roots would leave the issuer unverified while the caller believed
// they had anchored it, which is worse than not offering the flag.
func TestCLI_TSARoot_LoaderErrors(t *testing.T) {
	f := createSealedRecordFixture(t)
	dir := t.TempDir()
	recPath := filepath.Join(dir, "r.json")
	if err := os.WriteFile(recPath, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, root := range map[string]string{
		"missing file":         filepath.Join(dir, "absent.pem"),
		"no certificate in it": notPEM,
	} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--record", recPath, "--key-hex", f.publicKeyHex, "--tsa-root", root}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("%s: exit = %d, want %d: a bad --tsa-root must fail loudly, never be ignored", name, code, ExitError)
		}
		if strings.Contains(stdout.String(), "Result: VERIFIED") {
			t.Errorf("%s: reported VERIFIED with an unusable trust anchor", name)
		}
	}
}

// TestGenerateTSRFixtures writes the committed timestamp fixtures.
//
// Run with PLAINREAL_WRITE_TSR_FIXTURES=1. It is a generator rather than a
// check, which is why it is guarded: the fixtures are committed so a stranger
// can exercise the RFC 3161 path without a network, a TSA account, or this
// repository's test helpers.
//
//	PLAINREAL_WRITE_TSR_FIXTURES=1 go test ./cmd/plainreal-verify/ -run TestGenerateTSRFixtures
//
// The token is signed by a MOCK TSA generated here, and the fixtures say so in
// their README. It is deliberately NOT added to the browser page's samples: the
// page states that its sample carries no timestamp, and shipping a
// mock-authority token there would let a reader infer a time proof that does
// not exist.
func TestGenerateTSRFixtures(t *testing.T) {
	if os.Getenv("PLAINREAL_WRITE_TSR_FIXTURES") != "1" {
		t.Skip("generator; set PLAINREAL_WRITE_TSR_FIXTURES=1 to rewrite the committed fixtures")
	}
	f := createSealedRecordFixture(t)
	m := newMockTSA(t)
	defer m.server.Close()

	hash, err := verifycore.RecordHashFromBytes(f.recordJSON)
	if err != nil {
		t.Fatal(err)
	}
	dir := "testdata"
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("timestamped_record.json", f.recordJSON)
	write("timestamped_record.tsr", mintViaMock(t, m, hash))
	write("timestamped_record.pub.pem", f.publicKeyPEM)
	write("mock_tsa_root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw}))
	t.Logf("wrote timestamp fixtures for record_hash %s", hash)
}

// TestTSRFixtures_VerifyEndToEnd is the check that the committed fixtures
// actually work, which is what makes them worth shipping. If they rot, this
// fails rather than a stranger discovering it.
func TestTSRFixtures_VerifyEndToEnd(t *testing.T) {
	rec := filepath.Join("testdata", "timestamped_record.json")
	if _, err := os.Stat(rec); err != nil {
		t.Skip("timestamp fixtures not generated yet")
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--record", rec,
		"--key", filepath.Join("testdata", "timestamped_record.pub.pem"),
		"--tsr", filepath.Join("testdata", "timestamped_record.tsr"),
		"--tsa-root", filepath.Join("testdata", "mock_tsa_root.pem"),
		"--json",
	}, &stdout, &stderr)
	if code != ExitVerified {
		t.Fatalf("committed timestamp fixtures do not verify (exit %d).\n%s\n%s", code, stdout.String(), stderr.String())
	}
	var res VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.TimestampValid == nil || !*res.TimestampValid {
		t.Error("timestamp_valid is not true")
	}
	if res.TimestampIssuerVerified == nil || !*res.TimestampIssuerVerified {
		t.Error("timestamp_issuer_verified is not true despite --tsa-root")
	}
}

// TestCLI_ColourNeverLeaksIntoNonTerminalOutput — colour is an enhancement and
// never the only signal, so it must vanish when the output is not a terminal.
//
// An auditor's report attaches the piped output of this tool. Escape codes in
// that file would be noise at best and, in a system that renders them, a way to
// make a verdict read differently from what was computed.
func TestCLI_ColourNeverLeaksIntoNonTerminalOutput(t *testing.T) {
	f := createSealedRecordFixture(t)
	path := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(path, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	// bytes.Buffer is not an *os.File, so auto must resolve to no colour.
	for _, mode := range []string{"auto", "never"} {
		var stdout, stderr bytes.Buffer
		run([]string{"--record", path, "--key-hex", f.publicKeyHex, "--color", mode}, &stdout, &stderr)
		if strings.Contains(stdout.String(), "\x1b[") {
			t.Errorf("--color=%s emitted escape codes to a non-terminal writer", mode)
		}
	}
	var stdout, stderr bytes.Buffer
	run([]string{"--record", path, "--key-hex", f.publicKeyHex, "--color", "always"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "\x1b[") {
		t.Error("--color=always emitted no escape codes")
	}
}

// TestCLI_VerdictIsLegibleWithoutColour — the [x]/[!] markers and the verdict
// word must carry the result on their own, for a pipe, a log, or a reader who
// cannot see colour.
func TestCLI_VerdictIsLegibleWithoutColour(t *testing.T) {
	f := createSealedRecordFixture(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}
	tree["action_type"] = "tampered"
	bad := filepath.Join(dir, "bad.json")
	mutated, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, mutated, 0o644); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]string{good: "VERIFIED", bad: "FAILED"} {
		var stdout, stderr bytes.Buffer
		run([]string{"--record", path, "--key-hex", f.publicKeyHex, "--color", "never"}, &stdout, &stderr)
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("%s: plain output does not contain %q", filepath.Base(path), want)
		}
	}
}

// TestCLI_NamesTheOtherImplementation — each tool is the other's independent
// check, and that is worth nothing to a reader who does not know the other one
// exists.
func TestCLI_NamesTheOtherImplementation(t *testing.T) {
	f := createSealedRecordFixture(t)
	path := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(path, f.recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	run([]string{"--record", path, "--key-hex", f.publicKeyHex, "--color", "never"}, &stdout, &stderr)
	out := stdout.String()
	for _, want := range []string{"verify.plainreal.com", "github.com/plainreal/verify", "Nothing was contacted"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q", want)
		}
	}
}

// TestCLI_GarbageIsNotAccused — a file that is not JSON was never a record, so
// nothing was checked and there is nothing to accuse. It is an input problem
// (exit 2), not a verdict (exit 1).
//
// The browser page draws exactly this line and says why: crying tamper on
// garbage makes the real tamper result look like theatre, and dropping a random
// file in is the first thing a sceptical reader tries. The CLI reported FAILED
// for both until this test existed.
func TestCLI_GarbageIsNotAccused(t *testing.T) {
	f := createSealedRecordFixture(t)
	dir := t.TempDir()

	garbage := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(garbage, []byte("shopping list\nmilk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--record", garbage, "--key-hex", f.publicKeyHex}, &stdout, &stderr); code != ExitError {
		t.Errorf("a non-JSON file exited %d, want %d: it was never a record, so nothing was checked", code, ExitError)
	}
	if strings.Contains(stdout.String(), "FAILED") {
		t.Error("a shopping list was reported as FAILED; that reads as an accusation")
	}

	// But JSON that IS record-shaped and non-conformant WAS read and judged.
	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}
	tree["invented_field"] = "nope"
	mutated, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	nonconformant := filepath.Join(dir, "extra.json")
	if err := os.WriteFile(nonconformant, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--record", nonconformant, "--key-hex", f.publicKeyHex}, &stdout, &stderr); code != ExitFailed {
		t.Errorf("a non-conformant record exited %d, want %d: it was read and judged", code, ExitFailed)
	}
}

// TestCLI_RejectionMessageHasNoSentinelPrefix — the sentinel that marks an
// error as an artifact verdict must not appear in what the reader sees. It
// read "Reason: artifact rejected: parse record JSON in ..." while the line
// above already said FAILED.
func TestCLI_RejectionMessageHasNoSentinelPrefix(t *testing.T) {
	f := createSealedRecordFixture(t)
	var tree map[string]interface{}
	if err := json.Unmarshal(f.recordJSON, &tree); err != nil {
		t.Fatal(err)
	}
	tree["invented_field"] = "nope"
	mutated, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "extra.json")
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	run([]string{"--record", path, "--key-hex", f.publicKeyHex}, &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), "artifact rejected") {
		t.Error("the internal sentinel leaked into user-facing output")
	}
}
