package main

import (
	"context"
	"os"
)

// watchParentPipe cancels the returned context when the parent that launched
// this engine goes away, detected by end-of-file on stdin.
//
// Why this exists: banshee (the Python CLI) kills this child on its own way out,
// but that cleanup only runs when Python is given the chance to run it. A
// forceful kill — `taskkill /F`, Task Manager "End task", an OOM kill, a crash —
// grants no such chance, and an orphaned engine keeps sending probes long after
// the operator believes the scan stopped. For a scanner that is an authorization
// problem, not merely a leaked process: packets keep reaching the target under an
// authorization the operator has already withdrawn.
//
// Why the pipe and not the parent PID: polling os.Getppid() looks like the
// obvious answer and does not work on Windows, which never reparents an orphan —
// the recorded parent PID keeps pointing at the dead process forever, so the
// comparison never trips. A pipe is authoritative on every platform instead of
// only on Unix, because the OS closes the write end when the parent dies no
// matter how it died; SIGKILL cannot prevent it. banshee passes -watch-stdin and
// holds the write end open for exactly as long as it wants the scan to continue.
//
// The flag is required rather than inferred: without it, running the engine
// standalone with stdin redirected from a file or /dev/null would read EOF
// immediately and cancel the scan before it started.
//
// The engine run is cancelled rather than killed outright, so in-flight probes
// unwind the same way a Ctrl+C unwinds them and partial results still marshal.
func watchParentPipe(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		// Any outcome other than "more bytes arrived" means the parent is gone or
		// the channel is unusable, and in both cases scanning must stop. banshee
		// never writes on this pipe, so a read that returns data is unexpected but
		// harmless — keep waiting for the close that matters.
		buf := make([]byte, 256)
		for {
			// Any error at all ends the scan, io.EOF included: EOF means the parent
			// closed the pipe, and every other error means the pipe is unusable.
			// Neither case leaves a parent to be authorized by, so they share one
			// branch rather than being distinguished for no behavioural difference.
			if _, err := os.Stdin.Read(buf); err != nil {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()

	return ctx, cancel
}
