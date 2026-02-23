// cmd/tcp-healthcheck performs a TCP connection health check.
// It connects to a host:port and immediately closes -- no TLS, no HTTP.
// This is for distroless containers where the service's TLS authorizer
// rejects self-connections (e.g., SPIKE Keeper only allows Nexus/Bootstrap).
//
// The server logs "TLS handshake error from 127.0.0.1: EOF" each time
// because the connection closes before the TLS handshake begins. This is
// cosmetic noise, not a real error. It cannot be suppressed because:
//   - Go's http.Server unconditionally logs TLS handshake failures
//     (https://github.com/golang/go/issues/26918)
//   - SPIKE Keeper requires mTLS (ClientAuth: RequireAnyClientCert),
//     so a TLS-level handshake without a client cert also fails
//   - Presenting a client cert requires SPIRE SVID access, and the
//     Keeper's application-layer authorizer only allows Nexus/Bootstrap
//
// Environment variables:
//   - HEALTHCHECK_ADDR: TCP address to check (default: localhost:8443)
//
// Exit codes: 0 = healthy (port reachable), 1 = unhealthy.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("HEALTHCHECK_ADDR")
	if addr == "" {
		addr = "localhost:8443"
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcp-healthcheck: dial %s: %v\n", addr, err)
		os.Exit(1)
	}
	_ = conn.Close()
}
