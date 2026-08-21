package main

import (
	"os"
	"path/filepath"
	"strings"
)

// cleanupBefore removes temp files that a single-use exploit would choke on.
// Patterns support a trailing "*" glob (e.g. "/tmp/.skp-dummy-*.deb").
// Missing files are silently ignored.
//
// This is critical: exploits like `exploit` create /tmp/loader + /var/tmp/.s
// and FAIL with "loader drop failed" / "helper drop failed" if those files
// already exist from a previous run. Cleaning them first makes re-runs work.
func cleanupBefore(patterns []string) {
	for _, pat := range patterns {
		if strings.HasSuffix(pat, "*") {
			// Glob: remove all matching files.
			dir := filepath.Dir(pat)
			base := filepath.Base(pat)
			prefix := strings.TrimSuffix(base, "*")
			ents, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, ent := range ents {
				if strings.HasPrefix(ent.Name(), prefix) {
					_ = os.RemoveAll(filepath.Join(dir, ent.Name()))
				}
			}
		} else {
			_ = os.RemoveAll(pat)
		}
	}
}

// cleanupExploit cleans the temp files of a single exploit entry before run.
func cleanupExploit(e *Exploit) {
	if len(e.Cleanup) == 0 {
		return
	}
	cleanupBefore(e.Cleanup)
}
