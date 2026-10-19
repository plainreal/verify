// Package verifycore is the VERIFICATION-ONLY subset of the record model.
//
// # WHY THIS PACKAGE EXISTS
//
// The standalone plainreal-verify CLI is published under Apache-2.0, and
// Apache-2.0 section 3 grants a patent licence covering whatever the published
// code practices. That makes what ships a deliberate decision rather than a
// packaging detail. docs/PUBLICATION_BOUNDARY.md is the authority.
//
// The narrower problem it solves would be wrong on its own merits regardless:
// core carries Seal and SoftwareSigningService, which is record-signing and
// key-GENERATING code. An auditor building a verifier from source should not be
// compiling a sealer, and a public verification repository has no business
// containing one.
//
// So this package holds what a verifier needs and nothing more: the schema, the
// canonicalization and hashing, the signature check, and the invariants
// decidable from one artifact. core imports it and adds the producer half on
// top. The dependency runs core -> verifycore and never the other way.
//
// # THE BOUNDARY IS A COMPILE ERROR, NOT A CONVENTION
//
// Record lives here, so its methods must live here too. Seal, BindCausality and
// ComputeRecordHash are therefore FUNCTIONS in core rather than methods, and
// code importing only verifycore is structurally incapable of producing a
// signature. Not "must not". Cannot. That is the same principle the schema
// applies to itself: I6 acyclicity holds by construction, and retention_class
// is the source of the lock rather than a label describing it. Make the wrong
// thing unrepresentable rather than merely detectable.
//
// WHAT MUST NEVER BE ADDED HERE
//   - a sealer, or any code producing a signed record
//   - any code that signs, or generates, reads or writes a private key
//   - authorization-token issuance or input_hash pre-commitment binding
//   - WORM commitment, Object Lock sequencing, retention derivation
//   - RFC 3161 timestamp ACQUISITION (verifying one is Level 0 and fine)
//   - causality-chain traversal, or following an edge to a parent artifact
//   - renewal / re-anchoring checks, divergence adjudication, or forward
//     oversight verification through an index
//
// The last four are separately patent-pending and sit outside the Apache-2.0
// grant only while no code here practices them. The release preflight enforces
// this against the shipped payload; that check is the real guard and this
// comment is why it exists.
package verifycore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/sha3"
)

// HashSHA3256 computes NIST SHA3-256 (FIPS 202) hash of the input bytes.
// Returns 32-byte hash as a lowercase hex-encoded string (always 64 chars).
// This is NOT Keccak-256 (pre-standardization). Different padding, different output.
func HashSHA3256(data []byte) string {
	h := sha3.New256()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalizeJSON takes arbitrary JSON bytes and returns the RFC 8785 (JCS)
// canonical form. Ensures logically identical JSON inputs produce byte-identical
// output for cryptographic hashing.
//
// Returns an error if the input is not valid JSON, or if the JSON contains
// values that cannot be canonicalized (NaN, Infinity, out-of-range numbers).
func CanonicalizeJSON(input []byte) ([]byte, error) {
	// Reject duplicate object keys anywhere in the document. RFC 8785 forbids
	// them and the Python SDK rejects them at ingestion; Go's json.Decoder
	// would otherwise silently keep the LAST value, making the committed hash
	// depend on an undocumented last-wins rule and diverge from the Python
	// reference. json.Decoder.Decode does not detect duplicates, so scan the
	// token stream first.
	dupDec := json.NewDecoder(bytes.NewReader(input))
	dupDec.UseNumber()
	if err := rejectDuplicateKeys(dupDec); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()

	var parsed interface{}
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	// Reject trailing tokens after the top-level value.
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		return nil, fmt.Errorf("invalid JSON: unexpected trailing token %v", tok)
	}

	var buf bytes.Buffer
	if err := canonicalizeValue(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HashJSON computes SHA3-256 of the JCS-canonical form of the input JSON.
// Pipeline: input bytes → JCS canonicalize → SHA3-256 → lowercase hex.
// Used for input_hash, record_hash, policy_version_hash.
func HashJSON(jsonInput []byte) (string, error) {
	canonical, err := CanonicalizeJSON(jsonInput)
	if err != nil {
		return "", err
	}
	return HashSHA3256(canonical), nil
}

// NOTE: ComputeCausalityHash (SHA3-256(prev_hash + ":" + step_index)) is
// DELETED, not deprecated. §3.5 re-binds causality to
// SHA3-256(JCS(provenance)) — see core.ComputeCausalityChainHash.
//
// The old linear model could express only "step N of a line" and had no way to
// represent a node with two parents, which is the entire point of the 33-field
// provenance envelope. Nothing is released and no artifacts exist in the wild,
// so there is no compatibility path to keep: a bridge here would only let a
// caller produce a record whose causality means something the spec no longer
// defines.

// rejectDuplicateKeys reads exactly one JSON value from dec and returns an
// error if any object anywhere within it declares the same key twice. It is a
// recursive descent over json.Decoder tokens: on '{' it reads (key, value)
// pairs, tracking seen keys per object; on '[' it recurses over elements;
// scalars are consumed by the single Token() call. Malformed JSON surfaces as a
// token error here and is reported by the caller as invalid JSON (the main
// Decode pass reports the same class of error, so behavior is unchanged for
// non-duplicate malformed input).
func rejectDuplicateKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar (string / number / bool / null) — already consumed
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate key: %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateKeys(dec); err != nil { // the value
				return err
			}
		}
		_, err := dec.Token() // consume closing '}'
		return err
	case '[':
		for dec.More() {
			if err := rejectDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume closing ']'
		return err
	}
	return nil
}

func canonicalizeValue(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, val)
	case json.Number:
		s, err := canonicalizeNumber(val)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalizeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		type kv struct {
			key   string
			units []uint16
		}
		entries := make([]kv, 0, len(val))
		for k := range val {
			entries = append(entries, kv{k, utf16.Encode([]rune(k))})
		}
		sort.Slice(entries, func(i, j int) bool {
			return compareUTF16Units(entries[i].units, entries[j].units) < 0
		})
		buf.WriteByte('{')
		for i, e := range entries {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, e.key)
			buf.WriteByte(':')
			if err := canonicalizeValue(buf, val[e.key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value type: %T", v)
	}
	return nil
}

// compareUTF16 compares two strings by their UTF-16 code unit values
// (RFC 8785 key-sort rule). For ASCII-only strings this matches byte ordering.
// For non-BMP characters (above U+FFFF), surrogate pairs sort differently
// than raw Unicode code points — e.g. U+1D11E (D834 DD1E) < U+FFFD.
func compareUTF16(a, b string) int {
	return compareUTF16Units(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

func compareUTF16Units(a, b []uint16) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// writeCanonicalString writes s as a JSON string with minimal escaping per
// RFC 8785: only \", \\, and U+0000–U+001F are escaped. Forward slash is
// not escaped. Non-ASCII characters are emitted as raw UTF-8 bytes.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x20 {
			switch c {
			case '\b':
				buf.WriteString(`\b`)
			case '\t':
				buf.WriteString(`\t`)
			case '\n':
				buf.WriteString(`\n`)
			case '\f':
				buf.WriteString(`\f`)
			case '\r':
				buf.WriteString(`\r`)
			default:
				fmt.Fprintf(buf, `\u%04x`, c)
			}
			i++
			continue
		}
		switch c {
		case '"':
			buf.WriteString(`\"`)
			i++
			continue
		case '\\':
			buf.WriteString(`\\`)
			i++
			continue
		}
		// Any other byte (including high bits of multi-byte UTF-8) passes through.
		buf.WriteByte(c)
		i++
	}
	buf.WriteByte('"')
}

// MaxSafeInteger is the largest integer (2^53 - 1) that is exactly
// representable as an IEEE-754 double, i.e. ECMAScript Number.MAX_SAFE_INTEGER.
// JSON numbers whose value is an integer beyond this magnitude cannot be
// canonicalized without precision loss, so they are rejected rather than
// silently rounded — see canonicalizeNumber.
const MaxSafeInteger = 1<<53 - 1 // 9007199254740991

// maxSafeIntegerFloat is MaxSafeInteger as a float64. 2^53-1 is exactly
// representable, so this conversion is lossless.
const maxSafeIntegerFloat = float64(MaxSafeInteger)

// canonicalizeNumber applies ECMAScript Number.toString rules (RFC 8785 §3.2.2.3).
// Mathematical integers serialize without decimal point (1.0 → "1").
// Negative zero serializes as "0". NaN/Infinity return an error.
//
// A number whose VALUE is an integer with magnitude beyond MaxSafeInteger is
// REJECTED, not rounded — in ANY spelling: bare ("9007199254740993"), exponent
// ("1e19", "9.007199254740993e15"), or trailing-decimal ("...E0"). RFC 8785
// canonicalizes through IEEE-754 double precision, so such a value would round
// (e.g. ...993 → ...992) and the committed hash would no longer correspond to
// the caller's integer — silent evidence corruption. The check is on the parsed
// VALUE (math.Trunc), not the literal spelling, which is what closes the
// exponent/decimal bypass and stays byte-identical to the Python SDK, which
// applies the same value-based rule. Large identifiers (account numbers, claim
// IDs) must be sent as JSON strings, which canonicalize exactly in every
// language. Non-integer values (0.1, 2.5, 1.5e-10) are unaffected. See
// sdk/python/plainreal/_internal/jcs.py.
func canonicalizeNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return "", fmt.Errorf("invalid number %q: %w", n.String(), err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("NaN and Infinity are not valid JSON")
	}
	if f == math.Trunc(f) && math.Abs(f) > maxSafeIntegerFloat {
		return "", fmt.Errorf(
			"integer-valued number %s exceeds the safe range [-(2^53-1), 2^53-1]; represent large integers as JSON strings", n.String())
	}
	if f == 0 {
		return "0", nil
	}
	return ecmaNumberToString(f), nil
}

// ecmaNumberToString implements the ECMAScript 6.1.6.1.13 (NumberToString)
// algorithm for a non-zero finite float64. Produces the shortest-roundtrip
// decimal representation that matches JavaScript's (value).toString().
func ecmaNumberToString(f float64) string {
	negative := f < 0
	if negative {
		f = -f
	}

	// Go's 'e' format with -1 precision gives the shortest-roundtrip
	// scientific form: "D.FFFe±NN" or "De±NN".
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	eIdx := strings.IndexByte(sci, 'e')
	mantissa, expStr := sci[:eIdx], sci[eIdx+1:]
	E, err := strconv.Atoi(expStr)
	if err != nil {
		return sci
	}

	// Drop the decimal point from mantissa to get the digit string s.
	var s string
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		s = mantissa[:dot] + mantissa[dot+1:]
	} else {
		s = mantissa
	}
	k := len(s)
	n := E + 1

	var out string
	switch {
	case n >= k && n <= 21:
		// Integer with trailing zeros.
		out = s + strings.Repeat("0", n-k)
	case n > 0 && n <= 21:
		// Decimal with fractional part.
		out = s[:n] + "." + s[n:]
	case n > -6 && n <= 0:
		// Small decimal with leading zeros.
		out = "0." + strings.Repeat("0", -n) + s
	default:
		// Scientific notation. ECMAScript uses "+" for positive exponents.
		exponent := n - 1
		sign := "+"
		if exponent < 0 {
			sign = "-"
			exponent = -exponent
		}
		expDigits := strconv.Itoa(exponent)
		if k == 1 {
			out = s + "e" + sign + expDigits
		} else {
			out = s[:1] + "." + s[1:] + "e" + sign + expDigits
		}
	}

	if negative {
		return "-" + out
	}
	return out
}

// =============================================================================
// Signing — Ed25519 (FIPS 186-5)
// =============================================================================

// VerifyWithPublicKey verifies an Ed25519 signature using only a public key.
//
// This is the auditor's entry point. It has ZERO dependencies on PlainReal
// types, services, or infrastructure. It takes three hex strings and returns
// a boolean. It imports only crypto/ed25519, encoding/hex, and fmt.
//
// Parameters:
//   - publicKeyHex: Ed25519 public key, 64 hex chars (32 bytes)
//   - hash:         SHA3-256 hash, 64 hex chars (32 bytes)
//   - signature:    Ed25519 signature, 128 hex chars (64 bytes)
//
// Returns (valid, err). err is non-nil only when input format/length is wrong.
// A cryptographically-invalid signature returns (false, nil) — not an error.
//
// Usage by auditor:
//  1. Download plainreal-verify (single binary, no deps)
//  2. Obtain public key from keys.plainreal.com
//  3. Run against a sealed artifact; CLI calls this function under the hood
//  4. "VERIFIED" or "FAILED" — no PlainReal account required
func VerifyWithPublicKey(publicKeyHex, hash, signature string) (bool, error) {
	if len(publicKeyHex) != 64 {
		return false, fmt.Errorf("public key must be 64 hex chars (got %d)", len(publicKeyHex))
	}
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("public key not valid hex: %w", err)
	}
	if len(hash) != 64 {
		return false, fmt.Errorf("hash must be 64 hex chars (got %d)", len(hash))
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return false, fmt.Errorf("hash not valid hex: %w", err)
	}
	if len(signature) != 128 {
		return false, fmt.Errorf("signature must be 128 hex chars (got %d)", len(signature))
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("signature not valid hex: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), hashBytes, sigBytes), nil
}

// --- internal key-file helpers ---
