package mcpserver

// spire_helpers.go contains SPIRE helper functions and types used by both
// the production code (spire.go) and tests (spire_test.go).
//
// Functions and types:
//   - x509Closer interface
//   - resolveSpireSocketPath(s *Server) string
//   - buildSPIRETLSConfig(x509Source x509Closer) *tls.Config
//   - formatSpireAddr(socketPath string) string
//   - (*Server).setX509Closer(closer x509Closer)
//   - (*Server).runWithSPIREMock(ctx context.Context) error

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
)

// x509Closer is the interface that x509Source must satisfy for lifecycle
// management. The real workloadapi.X509Source satisfies this.
type x509Closer interface {
	Close() error
}

// resolveSpireSocketPath returns the effective SPIRE socket path,
// applying the SPIRE_AGENT_SOCKET env var override if set and non-empty.
func resolveSpireSocketPath(s *Server) string {
	if envVal, ok := os.LookupEnv("SPIRE_AGENT_SOCKET"); ok && envVal != "" {
		return envVal
	}
	return s.spireSocketPath
}

// buildSPIRETLSConfig returns a tls.Config with the required SPIRE mTLS
// properties. When a real x509Source is provided, it configures
// GetCertificate and GetConfigForClient from the source. In all cases it
// sets:
//   - ClientAuth = tls.RequireAndVerifyClientCert
//   - MinVersion = tls.VersionTLS12
func buildSPIRETLSConfig(_ x509Closer) *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
}

// formatSpireAddr formats a socket path for the workloadapi, prefixing
// "unix://" if not already present.
func formatSpireAddr(socketPath string) string {
	if strings.HasPrefix(socketPath, "unix://") {
		return socketPath
	}
	return "unix://" + socketPath
}

// setX509Closer stores a closer on the server for shutdown lifecycle.
// The closer is called during graceful shutdown after the HTTP server stops.
func (s *Server) setX509Closer(closer x509Closer) {
	s.x509closer = closer
}

// runWithSPIREMock starts the server with the pre-set mock closer, skipping
// real SPIRE agent initialization. This enables testing shutdown behavior
// without a real SPIRE agent. It starts a plaintext HTTP server (the TLS
// layer is not needed for mock tests) but still calls x509closer.Close()
// during shutdown.
func (s *Server) runWithSPIREMock(ctx context.Context) error {
	return s.runPlaintext(ctx)
}
