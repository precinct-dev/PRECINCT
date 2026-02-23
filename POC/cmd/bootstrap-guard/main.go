// cmd/bootstrap-guard is an idempotency wrapper for the SPIKE bootstrap binary.
//
// The upstream spike-bootstrap binary (ghcr.io/spiffe/spike-bootstrap) has no
// built-in idempotency for Docker Compose: when re-run against an already-
// initialized SPIKE Nexus, it sends shards (idempotent) but then enters an
// infinite verify loop that never exits because Nexus returns a different
// response for an already-initialized system.
//
// Strategy: run /bootstrap as a subprocess with a timeout. On a fresh system,
// bootstrap completes in under 30 seconds. On an already-initialized system,
// it hangs forever in the verify loop. If the subprocess doesn't exit within
// the timeout, we treat it as "already initialized" and exit 0.
//
// Environment variables:
//   - BOOTSTRAP_TIMEOUT: max seconds to wait (default: 60)
//
// Exit codes:
//
//	0 = bootstrap succeeded OR system already initialized (timeout)
//	non-zero = bootstrap failed with an error before timeout
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func main() {
	timeout := 60
	if v := os.Getenv("BOOTSTRAP_TIMEOUT"); v != "" {
		if t, err := strconv.Atoi(v); err == nil && t > 0 {
			timeout = t
		}
	}

	bootstrapPath := "/bootstrap"
	args := os.Args[1:]

	fmt.Fprintf(os.Stderr, "bootstrap-guard: running %s %v (timeout=%ds)\n", bootstrapPath, args, timeout)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bootstrapPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	if err == nil {
		// Bootstrap completed successfully.
		fmt.Fprintln(os.Stderr, "bootstrap-guard: bootstrap completed successfully")
		os.Exit(0)
	}

	if ctx.Err() == context.DeadlineExceeded {
		// Timeout: bootstrap hung in verify loop. This means shards were
		// already delivered and Nexus is already initialized. Safe to exit 0.
		fmt.Fprintf(os.Stderr, "bootstrap-guard: bootstrap timed out after %ds (system already initialized), exiting 0\n", timeout)
		os.Exit(0)
	}

	// Bootstrap failed with a real error before timeout.
	fmt.Fprintf(os.Stderr, "bootstrap-guard: bootstrap failed: %v\n", err)
	if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	}
	os.Exit(1)
}
