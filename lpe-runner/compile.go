package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// compileAndRun handles kindCompile and kindDir exploits:
//   - kindCompile: gcc the .c file, run the result
//   - kindDir:     try a ready binary in the dir; else make/gcc inside it
//
// Everything runs through runIsolated so a compiler error or a crashing
// binary never propagates to the parent.
func compileAndRun(e Exploit, s *systemInfo) runResult {
	r := runResult{name: e.Name}

	switch e.Kind {
	case kindCompile:
		r = compileSource(e)
	case kindDir:
		r = runDir(e)
	}
	r.name = e.Name
	return r
}

// compileSource: gcc <file> -o /tmp/.lpe_<name> [extra libs] && run
func compileSource(e Exploit) runResult {
	src := absBin(e.Path)
	if !hasFile(src) {
		return runResult{name: e.Name, crashed: true, stderr: "source missing: " + src}
	}
	bin := fmt.Sprintf("/tmp/.lpe_%s", e.Name)
	// Link libs commonly required by the catalog's C sources.
	libs := guessLibs(e.Path)
	args := []string{"-O0", "-Wall", "-static", "-o", bin, src}
	args = append(args, libs...)

	infof("Compiling %s -> %s (gcc %s)", e.Path, bin, libs)
	compileCmd := exec.CommandContext(gccTimeoutCtx(), "gcc", args...)
	compileCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := compileCmd.CombinedOutput()
	if err != nil {
		return runResult{
			name:    e.Name,
			crashed: true,
			exitCode: -1,
			stderr:  fmt.Sprintf("gcc failed: %v\n%s", err, string(out)),
		}
	}
	_ = os.Chmod(bin, 0o755)
	to := defaultTimeout
	if e.Timeout > 0 {
		to = e.Timeout
	}
	res := runIsolated(e.Name, "", []string{bin}, durSec(to))
	res.cmd = fmt.Sprintf("gcc %s && %s", e.Path, bin)
	return res
}

// runDir: try a ready binary; else try `make`; else try gcc on the .c in src/.
func runDir(e Exploit) runResult {
	dir := absBin(e.Path)
	if !hasFile(dir) {
		return runResult{name: e.Name, crashed: true, stderr: "dir missing: " + dir}
	}
	// 1. ready binary?
	if b := findDirBinary(dir); b != "" {
		to := defaultTimeout
		if e.Timeout > 0 {
			to = e.Timeout
		}
		return runIsolated(e.Name, dir, []string{b}, durSec(to))
	}
	// 2. make?
	if hasBin("make") && hasFile(filepath.Join(dir, "Makefile")) {
		infof("Building %s via make", e.Name)
		mk := exec.CommandContext(gccTimeoutCtx(), "make")
		mk.Dir = dir
		mk.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		out, err := mk.CombinedOutput()
		if err != nil {
			return runResult{name: e.Name, crashed: true, stderr: fmt.Sprintf("make: %v\n%s", err, string(out))}
		}
		if b := findDirBinary(dir); b != "" {
			to := defaultTimeout
			if e.Timeout > 0 {
				to = e.Timeout
			}
			return runIsolated(e.Name, dir, []string{b}, durSec(to))
		}
	}
	// 3. gcc *.c in dir
	ents, err := os.ReadDir(dir)
	if err != nil {
		return runResult{name: e.Name, crashed: true, stderr: err.Error()}
	}
	for _, ent := range ents {
		if ent.IsDir() || !hasSuffix(ent.Name(), ".c") {
			continue
		}
		sub := Exploit{
			Name:    e.Name + "/" + ent.Name(),
			Kind:    kindCompile,
			Path:    filepath.Join(e.Path, ent.Name()),
			Timeout: e.Timeout,
		}
		r := compileSource(sub)
		r.name = e.Name
		if r.rootAfter || r.suidAfter {
			return r
		}
	}
	return runResult{name: e.Name, crashed: true, stderr: "no buildable target in dir"}
}

// guessLibs returns extra -l flags based on the source file name / heuristics.
func guessLibs(path string) []string {
	base := filepath.Base(path)
	var libs []string
	switch {
	case base == "dirty.c" || base == "dirty2.c":
		libs = append(libs, "-pthread", "-lcrypt")
	case base == "42887.c":
		libs = append(libs, "-pthread")
	default:
		libs = append(libs, "-lpthread")
	}
	return libs
}

// durSec converts seconds to time.Duration.
func durSec(sec int) time.Duration { return time.Duration(sec) * time.Second }

// gccTimeoutCtx returns a context that cancels after 90s — prevents a
// hung gcc/make from blocking a worker forever (e.g. stale NFS mount,
// pathological source file). 90s is generous: even -static links finish
// well under that on any healthy box.
func gccTimeoutCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	// fire-and-forget: the timer self-cancels via the deadline check
	// when gcc exits normally. The cancel call happens in a goroutine
	// to avoid leaking the timer if gcc finishes quickly.
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}
