package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// helperWrite builds a small binary on disk and returns its path.
func helperWrite(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	// write C source
	csrc := bin + ".c"
	if err := os.WriteFile(csrc, []byte(src), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	cmd := exec.Command("gcc", "-O0", "-o", bin, csrc)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}
	return bin
}

// Test that a SIGSEGV-crashing child is caught and the parent survives.
func TestRunIsolatedSurvivesSegfault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crash test in short mode")
	}
	bin := helperWrite(t, "crash", `#include <signal.h>
int main(void){ raise(SIGSEGV); return 0; }`)

	r := runIsolated("crash-probe", "", []string{bin}, 10*time.Second)
	if !r.crashed {
		t.Fatalf("expected crashed=true, got %+v", r)
	}
	if r.signal != "segmentation fault" {
		t.Logf("signal=%s (acceptable)", r.signal)
	}
	t.Logf("result: exit=%d sig=%s crashed=%v elapsed=%s", r.exitCode, r.signal, r.crashed, r.elapsed)
}

// Test that a hanging exploit is killed by the timeout and parent survives.
func TestRunIsolatedTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	bin := helperWrite(t, "hang", `#include <unistd.h>
int main(void){ for(;;) pause(); return 0; }`)

	start := time.Now()
	r := runIsolated("hang-probe", "", []string{bin}, 2*time.Second)
	elapsed := time.Since(start)
	if !r.timedOut {
		t.Fatalf("expected timedOut=true, got %+v", r)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("took too long to kill the hung child: %s", elapsed)
	}
	t.Logf("timeout OK: killed in %s, result exit=%d", elapsed, r.exitCode)
}

// Test that a normal-exit child is reported as not-crashed.
func TestRunIsolatedNormalExit(t *testing.T) {
	bin := helperWrite(t, "ok", `int main(void){ return 0; }`)
	r := runIsolated("ok-probe", "", []string{bin}, 10*time.Second)
	if r.crashed {
		t.Fatalf("did not expect crash, got %+v", r)
	}
	if r.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", r.exitCode)
	}
}

// Test the kernel-range parser.
func TestParseKernel(t *testing.T) {
	cases := []struct {
		in                 string
		maj, min, pat int
	}{
		{"5.10.0-17-generic", 5, 10, 0},
		{"6.12.4", 6, 12, 4},
		{"6.12", 6, 12, 0},
		{"4.19.0-21", 4, 19, 0},
		{"garbage", 0, 0, 0},
	}
	for _, c := range cases {
		maj, min, pat := parseKernel(c.in)
		if maj != c.maj || min != c.min || pat != c.pat {
			t.Errorf("parseKernel(%q) = %d.%d.%d, want %d.%d.%d", c.in, maj, min, pat, c.maj, c.min, c.pat)
		}
	}
}

// Test the copyfail sed replacement logic.
func TestCopyAndSed(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "copyfail.py")
	if err := os.WriteFile(src, []byte("x=\"/usr/bin/su\"\nprint(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.py")
	if err := copyAndSed(src, dst, "s|/usr/bin/su|/bin/mount|g"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	want := "x=\"/bin/mount\"\nprint(x)\n"
	if string(b) != want {
		t.Fatalf("sed result = %q, want %q", string(b), want)
	}
}

// Test the kernel range eligibility.
func TestInRange(t *testing.T) {
	s := &systemInfo{kernMaj: 5, kernMin: 10, kernPat: 0}
	cases := []struct {
		lo, hi [3]int
		want   bool
	}{
		{[3]int{5, 0, 0}, [3]int{7, 1, 99}, true},
		{[3]int{5, 11, 0}, [3]int{}, false},       // 5.10 < 5.11
		{[3]int{}, [3]int{5, 16, 11}, true},        // 5.10 <= 5.16.11
		{[3]int{5, 8, 0}, [3]int{5, 16, 11}, true}, // 5.8 <= 5.10 <= 5.16.11
	}
	for i, c := range cases {
		got := s.inRange(c.lo, c.hi)
		if got != c.want {
			t.Errorf("case %d: inRange(%v,%v) = %v, want %v", i, c.lo, c.hi, got, c.want)
		}
	}
}

// Test the marker detection / SUID check don't panic on missing files.
func TestMarkerChecks(t *testing.T) {
	_ = isSUIDBash()
	_ = markerRooted()
	_ = isSUIDFile("/nonexistent/path")
}

// Ensure the registry compiles and has entries.
func TestRegistryNonEmpty(t *testing.T) {
	r := registry()
	if len(r) < 40 {
		t.Fatalf("registry too small: %d entries", len(r))
	}
	for _, e := range r {
		// Every exploit should have a name and a kind.
		if e.Name == "" {
			t.Fatalf("found exploit with empty name")
		}
		// eligible should not panic.
		_, _ = e.eligible(&systemInfo{})
	}
	fmt.Printf("registry has %d entries\n", len(r))
}
