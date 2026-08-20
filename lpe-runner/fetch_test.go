package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAlternateBranch(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://raw.githubusercontent.com/sagsooz/pa-root/main", "https://raw.githubusercontent.com/sagsooz/pa-root/master"},
		{"https://raw.githubusercontent.com/sagsooz/pa-root/master", "https://raw.githubusercontent.com/sagsooz/pa-root/main"},
		{"https://example.com/foo", "https://example.com/foo"},
	}
	for _, c := range cases {
		if got := alternateBranch(c.in); got != c.want {
			t.Errorf("alternateBranch(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanityCheck(t *testing.T) {
	dir := t.TempDir()
	tiny := filepath.Join(dir, "tiny")
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(tiny, make([]byte, 50), 0o644)
	_ = os.WriteFile(big, make([]byte, 5000), 0o644)
	if sanityCheck(tiny) {
		t.Error("tiny file should fail sanity check")
	}
	if !sanityCheck(big) {
		t.Error("big file should pass sanity check")
	}
	if sanityCheck("/nonexistent") {
		t.Error("missing file should fail sanity check")
	}
}

func TestFetchConfigure(t *testing.T) {
	fetchDisabled = false
	fetchRepo = defaultRepoURL
	fetchConfigure("https://example.com/x/", true)
	if !fetchDisabled {
		t.Error("fetchConfigure did not set fetchDisabled")
	}
	if fetchRepo != "https://example.com/x" {
		t.Errorf("fetchRepo = %q, want trimmed trailing slash", fetchRepo)
	}
	fetchConfigure("", false)
	if fetchRepo != defaultRepoURL {
		t.Errorf("fetchRepo = %q, want default", fetchRepo)
	}
}

func TestEnsureFileFetchDisabled(t *testing.T) {
	fetchConfigure("", true)
	if ensureFile("/nonexistent/path/to/file", false) {
		t.Error("ensureFile should return false when fetch disabled and file missing")
	}
}
