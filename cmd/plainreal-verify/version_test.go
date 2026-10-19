package main

import (
	"runtime/debug"
	"testing"
)

// TestResolveVersion covers how a report decides what to call its own build.
//
// It matters more than its size suggests: the header line is what lets someone
// reading a stored verdict know which binary produced it. An installed binary
// reported "dev" until the build-info fallback landed, and "dev" names nothing.
func TestResolveVersion(t *testing.T) {
	bi := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: v}}, true
		}
	}
	cases := []struct {
		name    string
		current string
		read    func() (*debug.BuildInfo, bool)
		want    string
	}{
		{"ldflags wins over build info", "1.1.0", bi("v9.9.9"), "1.1.0"},
		{"installed by tag, v stripped", "dev", bi("v1.1.0"), "1.1.0"},
		{"pre-release tag kept intact", "dev", bi("v1.2.0-rc.1"), "1.2.0-rc.1"},
		{"working tree stays dev", "dev", bi("(devel)"), "dev"},
		{"empty module version stays dev", "dev", bi(""), "dev"},
		{"no build info at all", "dev", func() (*debug.BuildInfo, bool) { return nil, false }, "dev"},
		{"build info nil but ok", "dev", func() (*debug.BuildInfo, bool) { return nil, true }, "dev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveVersion(c.current, c.read); got != c.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", c.current, got, c.want)
			}
		})
	}
}
