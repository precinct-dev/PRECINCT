// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// cmd/mtls-healthcheck performs an mTLS health check using SPIRE Workload API.
// It connects to the SPIRE agent, obtains an X.509 SVID, and uses it to make
// an mTLS-authenticated request to the target service.
//
// The mTLS TLS handshake itself proves the service is alive AND that SPIRE
// SVID delivery works. Any HTTP response (even 4xx) indicates the service is
// serving TLS; only connection failures and 5xx are treated as unhealthy.
//
// Environment variables:
//   - HEALTHCHECK_URL: URL to check (default: https://localhost:8443/)
//   - SPIFFE_ENDPOINT_SOCKET: SPIRE agent socket (required, typically set by container)
//
// Exit codes: 0 = healthy, 1 = unhealthy or error.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	url := os.Getenv("HEALTHCHECK_URL")
	if url == "" {
		url = "https://localhost:8443/"
	}

	// SVID fetch can be slow on first call (agent needs to attest + deliver).
	// Docker's HEALTHCHECK --timeout governs the outer deadline; keep this generous.
	svidCtx, svidCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer svidCancel()

	x509Source, err := workloadapi.NewX509Source(svidCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: x509 source: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = x509Source.Close()
	}()

	tlsCfg := tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: GET %s: %v\n", url, err)
		os.Exit(1)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Any response proves mTLS works. Only 5xx indicates the service itself is unhealthy.
	if resp.StatusCode >= 500 {
		fmt.Fprintf(os.Stderr, "healthcheck: GET %s: status %d\n", url, resp.StatusCode)
		os.Exit(1)
	}
}

// Ensure TLS config is used (prevents unused import in case of future refactors).
var _ *tls.Config
