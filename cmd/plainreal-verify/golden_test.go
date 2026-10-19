package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden-output tests: assert the EXACT bytes a reader receives.
//
// WHY THESE EXIST
//
// Six defects reached a signed release or came close, and every one of them was
// a defect in the artifact a user receives rather than in a returned value:
// an internal sentinel leaking into "Reason:", a shopping list reported as
// FAILED, --json silently eaten when it followed a path, a batch array with no
// way to map a verdict back to a file, the footer printed before the
// explanation of what a failure means, and a line broken mid-noun-phrase.
//
// All six passed every test we had, because the suite asserted 203 return
// values and 59 "output contains X" substrings and NOTHING about what the
// output looked like. A substring assertion cannot see an unwanted prefix, a
// block in the wrong order, or a sentence that now reads as an accusation.
//
// A golden file can. Any change to what a reader sees fails loudly and a human
// has to look at a diff and decide whether the new output is better. That is
// the point: not to freeze the output, but to make changing it deliberate.
//
// Regenerate after an intentional change, and READ THE DIFF:
//
//	go test ./cmd/verify/ -run TestGolden -update

var update = flag.Bool("update", false, "rewrite the golden files from current output")

// goldenCases use committed fixtures and RELATIVE paths so the output is
// byte-identical on every machine. A temp dir would put a random path in the
// output and make the whole approach unusable.
var goldenCases = []struct {
	name string
	args []string
}{
	{"verified_with_timestamp", []string{
		"--record", "testdata/timestamped_record.json",
		"--key", "testdata/timestamped_record.pub.pem",
		"--tsr", "testdata/timestamped_record.tsr",
		"--tsa-root", "testdata/mock_tsa_root.pem",
	}},
	{"verified_no_timestamp", []string{
		"--record", "testdata/timestamped_record.json",
		"--key", "testdata/timestamped_record.pub.pem",
	}},
	{"timestamp_issuer_unanchored", []string{
		"--record", "testdata/timestamped_record.json",
		"--key", "testdata/timestamped_record.pub.pem",
		"--tsr", "testdata/timestamped_record.tsr",
	}},
	{"help", []string{"--help"}},
	{"version", []string{"--version"}},
	{"no_records", []string{"--key", "testdata/timestamped_record.pub.pem"}},

	// THE FAILURE PATHS.
	//
	// The first version of this file had none of these, which is the same
	// mistake that let the original defects through: coverage built around the
	// happy path. A golden file over a success case cannot see a sentinel
	// leaking into a Reason line, or a shopping list being called FAILED,
	// because neither happens when everything works.
	{"fail_tampered", badCase("tampered.json")},
	{"fail_missing_field", badCase("missing_field.json")},
	{"fail_unknown_version", badCase("unknown_version.json")},
	{"fail_extra_field", badCase("extra_field.json")},
	{"fail_unsafe_integer", badCase("unsafe_integer.json")},
	{"fail_duplicate_key", badCase("duplicate_key.json")},
	{"fail_malleable_signature", badCase("malleable_signature.json")},
	{"fail_not_json", badCase("not_json.txt")},
	{"fail_wrong_key", []string{
		"--record", "testdata/timestamped_record.json",
		"--key-hex", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
	}},
	{"fail_missing_file", []string{
		"--record", "testdata/bad/does_not_exist.json",
		"--key", "testdata/timestamped_record.pub.pem",
	}},
	{"batch_mixed", []string{
		"--key", "testdata/timestamped_record.pub.pem",
		"testdata/timestamped_record.json", "testdata/bad/tampered.json",
	}},
}

func badCase(name string) []string {
	return []string{
		"--record", filepath.Join("testdata", "bad", name),
		"--key", "testdata/timestamped_record.pub.pem",
	}
}

// goldenVersionSentinel stands in for the release version inside golden
// files. It is deliberately not a plausible version string.
const goldenVersionSentinel = "0.0.0-GOLDEN"

func TestGoldenOutput(t *testing.T) {
	// Pin the version for the duration.
	//
	// The report now names the build that produced it, so the golden files
	// would otherwise record whatever main.Version happened to be: "dev" for a
	// plain `go test`, but the real number if anyone ran the suite with
	// -ldflags "-X main.Version=...". Goldens that depend on how the test
	// binary was linked are not goldens. build-page.mjs substitutes the real
	// version for this sentinel when it injects these blocks into the README,
	// and a preflight check fails if the sentinel ever reaches the payload.
	savedVersion := Version
	Version = goldenVersionSentinel
	defer func() { Version = savedVersion }()

	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			// Colour off: a golden file full of escape codes is unreadable in a
			// diff, and the colour paths have their own tests.
			args := append([]string{"--color", "never"}, tc.args...)
			code := run(args, &stdout, &stderr)

			// The invocation is recorded IN the golden file.
			//
			// The README shows these outputs under a "$ plainreal-verify ..."
			// line, and those lines were written by hand. Two of the four were
			// wrong: the batch example said `records/*.json` above output
			// listing testdata/ paths, and the wrong-key example showed
			// `--key someone-elses-key.pem` when the case actually uses
			// --key-hex. Output that cannot drift sat under a command line that
			// already had, so the command travels with its own output now.
			//
			// tc.args, not args: the reader should not be told to pass
			// "--color never", which is this test's concern and not theirs.
			got := "argv " + strings.Join(tc.args, " ") + "\n" +
				"exit " + itoa(code) + "\n--- stdout ---\n" + stdout.String() +
				"--- stderr ---\n" + stderr.String()

			path := filepath.Join("testdata", "golden", tc.name+".txt")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated %s", path)
				return
			}
			wantBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("no golden file: %v\nRun: go test ./cmd/verify/ -run TestGolden -update", err)
			}
			if got != string(wantBytes) {
				t.Errorf("output changed for %q.\n\nIf the change is intended, run\n"+
					"  go test ./cmd/verify/ -run TestGolden -update\n"+
					"and READ THE DIFF before committing it.\n\n%s",
					tc.name, firstDifference(string(wantBytes), got))
			}
		})
	}
}

// firstDifference reports the first differing line with a little context, which
// is far more useful in a failure than two whole documents.
func firstDifference(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + itoa(i+1) + ":\n  want: " + wl + "\n  got:  " + gl
		}
	}
	return "(files differ only in trailing bytes)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
