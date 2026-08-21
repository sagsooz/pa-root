package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// systemInfo holds recon results gathered once at startup.
type systemInfo struct {
	hostname string
	kernel   string
	kernMaj  int
	kernMin  int
	kernPat  int
	arch     string
	distro   string
	user     string
	uid      int
	gid      int
	hasWget  bool
	hasCurl  bool
	hasGcc   bool
	hasMake  bool
	hasPy3   bool
	hasPerl  bool
	hasDpkg  bool
	hasRpm   bool
}

func (s *systemInfo) kernelVersion() int {
	return s.kernMaj*10000 + s.kernMin*100 + s.kernPat
}

// inRange checks if the current kernel is within [lo..hi] (inclusive).
// nil lo/hi mean unbounded on that side.
func (s *systemInfo) inRange(lo, hi [3]int) bool {
	if lo != [3]int{} {
		loV := lo[0]*10000 + lo[1]*100 + lo[2]
		if s.kernelVersion() < loV {
			return false
		}
	}
	if hi != [3]int{} {
		hiV := hi[0]*10000 + hi[1]*100 + hi[2]
		if s.kernelVersion() > hiV {
			return false
		}
	}
	return true
}

// parseKernel parses "5.10.0-..." style strings into major.minor.patch.
func parseKernel(r string) (int, int, int) {
	re := regexp.MustCompile(`(\d+)\.(\d+)\.?(\d+)?`)
	m := re.FindStringSubmatch(r)
	if m == nil {
		return 0, 0, 0
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	return maj, min, pat
}

// cmdOut runs a command with a timeout and returns trimmed stdout.
func cmdOut(name string, args ...string) string {
	return cmdOutT(10, name, args...)
}

func cmdOutT(timeout int, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	out, _ := c.Output()
	return strings.TrimSpace(string(out))
}

// hasBin reports whether a binary exists on $PATH.
func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// hasFile reports whether a path exists.
func hasFile(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// detectDistro returns a short distro label.
func detectDistro() string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "ID=") {
				return strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
			}
		}
	}
	if hasFile("/etc/debian_version") {
		return "debian"
	}
	if hasFile("/etc/redhat-release") {
		return "rhel"
	}
	return "unknown"
}

// gatherRecon collects everything about the host once.
func gatherRecon() *systemInfo {
	s := &systemInfo{}
	s.hostname = cmdOut("hostname")
	s.kernel = cmdOut("uname", "-r")
	s.arch = cmdOut("uname", "-m")
	s.distro = detectDistro()
	s.kernMaj, s.kernMin, s.kernPat = parseKernel(s.kernel)
	s.user = os.Getenv("USER")
	if s.user == "" {
		s.user = cmdOut("whoami")
	}
	s.uid = os.Getuid()
	s.gid = os.Getgid()
	s.hasWget = hasBin("wget")
	s.hasCurl = hasBin("curl")
	s.hasGcc = hasBin("gcc")
	s.hasMake = hasBin("make")
	s.hasPy3 = hasBin("python3")
	s.hasPerl = hasBin("perl")
	s.hasDpkg = hasBin("dpkg-deb")
	s.hasRpm = hasBin("rpmbuild")
	return s
}

func (s *systemInfo) print() {
	fmt.Println()
	infof("System Recon")
	fmt.Printf("    Host     : %s\n", s.hostname)
	fmt.Printf("    Kernel   : %s  (parsed: %d.%d.%d)\n", s.kernel, s.kernMaj, s.kernMin, s.kernPat)
	fmt.Printf("    Arch     : %s\n", s.arch)
	fmt.Printf("    Distro   : %s\n", s.distro)
	fmt.Printf("    User     : %s (uid=%d gid=%d)\n", s.user, s.uid, s.gid)
	fmt.Printf("    Runner   : %s/%s  (Go runtime)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("    Tools    : wget=%v curl=%v gcc=%v make=%v python3=%v perl=%v dpkg=%v rpm=%v\n",
		s.hasWget, s.hasCurl, s.hasGcc, s.hasMake, s.hasPy3, s.hasPerl, s.hasDpkg, s.hasRpm)
	fmt.Println()
}

// abs resolves a path relative to the executable's own directory when it
// starts with "./" or is just a basename (typical when shipped next to the
// runner). Absolute paths are returned unchanged.
func absBin(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		if ab, err2 := filepath.Abs(p); err2 == nil {
			return ab
		}
		return p
	}
	dir := filepath.Dir(exe)
	return filepath.Join(dir, p)
}
