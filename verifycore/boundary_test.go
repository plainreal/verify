package verifycore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestVerifycoreCannotSign is the structural guard behind the whole split.
//
// The published plainreal-verify CLI is built from this package and nothing
// else, so whatever is reachable here is what an auditor compiles and what
// Apache-2.0 section 3 grants a patent licence over. Two things must stay true
// and neither can be left to reviewer memory:
//
//   - No signing. Not "we do not call it", but no import that could.
//   - No producer path. Seal, key generation and private-key handling live in
//     core, which this package must never import back.
//
// The type system already enforces most of this: Record lives here, Go requires
// a type's methods to live in its own package, and Seal is therefore a function
// in core. Code importing only verifycore cannot produce a signature. This test
// covers what the type system cannot see, which is a future import.
func TestVerifycoreCannotSign(t *testing.T) {
	banned := map[string]string{
		"crypto/rand":                            "randomness here means key or nonce generation, which is producer work",
		"github.com/plainreal/plainreal/core":    "would invert the dependency and pull the sealer back in",
		"github.com/plainreal/plainreal/storage": "WORM commitment is producer work",
		"github.com/plainreal/plainreal/auth":    "token issuance is producer work",
		"github.com/plainreal/plainreal/absa":    "binary attestation is substrate work",
		"net":                                    "a verifier contacts nothing",
		"net/http":                               "a verifier contacts nothing",
		"os/exec":                                "a verifier runs nothing",
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse verifycore: %v", err)
	}

	seen := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			seen++
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if why, bad := banned[path]; bad {
					t.Errorf("%s imports %q: %s", name, path, why)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("parsed no non-test files; the guard would pass vacuously")
	}
}

// TestVerifycoreDeclaresNoSigner is the second half: even with no banned import,
// a hand-rolled signer or a private key type would defeat the purpose. Names are
// a weaker signal than imports, which is why this is the backstop and the import
// check above is the gate.
func TestVerifycoreDeclaresNoSigner(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, _ := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	// SUBSTRING, not exact-match or suffix. The first version of this check
	// tested `ident == b || strings.HasSuffix(ident, b)` and was proven not to
	// catch either `SealRecord` or `recordSigner` -- producer names are at
	// least as likely to be prefixes as suffixes, so both escaped. A backstop
	// that misses the obvious spelling of the thing it guards is worse than
	// none, because it is believed.
	banned := []string{"Seal", "SigningService", "PrivateKey", "GenerateKey", "Signer"}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				var ident string
				switch d := n.(type) {
				case *ast.FuncDecl:
					ident = d.Name.Name
				case *ast.TypeSpec:
					ident = d.Name.Name
				default:
					return true
				}
				for _, b := range banned {
					if strings.Contains(ident, b) {
						t.Errorf("%s declares %q; producer-side names belong in core", name, ident)
					}
				}
				return true
			})
		}
	}
}

// TestVerifyRecordBytes covers the one exported VERIFICATION entry point that
// had no test at all.
//
// It surfaced as 0% in a merged coverage profile. The CLI does not call it --
// it hashes and verifies in two steps so it can report which step failed -- but
// it is exported from a published verification package, so a reader may well
// reach for it as the obvious one-call API. An exported, untested verification
// function is the thing a security reviewer looks for when they ask what the
// uncovered percentage actually contains.
func TestVerifyRecordBytes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestRecord()
	p.SigningKeyID = HashSHA3256(pub)
	p.SigningAttestation = ""

	unsigned, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := RecordHashFromBytes(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	p.SigningAttestation = hex.EncodeToString(ed25519.Sign(priv, hb))
	sealed, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	t.Run("valid", func(t *testing.T) {
		ok, gotHash, err := VerifyRecordBytes(sealed, pubHex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("a correctly sealed record did not verify")
		}
		if gotHash != hash {
			t.Errorf("record_hash = %s, want %s", gotHash, hash)
		}
	})

	t.Run("tampered", func(t *testing.T) {
		var tree map[string]interface{}
		if err := json.Unmarshal(sealed, &tree); err != nil {
			t.Fatal(err)
		}
		tree["action_type"] = "tampered"
		mutated, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		ok, _, err := VerifyRecordBytes(mutated, pubHex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("a tampered record verified")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ok, _, err := VerifyRecordBytes(sealed, hex.EncodeToString(other))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("a record verified under a key that did not sign it")
		}
	})

	t.Run("not a record", func(t *testing.T) {
		if _, _, err := VerifyRecordBytes([]byte(`{"hello":"world"}`), pubHex); err == nil {
			t.Error("a non-record returned no error")
		}
	})
}
