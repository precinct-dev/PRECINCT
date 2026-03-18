package mcpserver

// spire_helpers.go contains SPIRE contract stubs for the RED phase.
//
// These functions define the contracts for SPIRE integration. The GREEN
// phase will replace this file with spire.go containing the real
// implementation using go-spiffe workloadapi and tlsconfig.
//
// Contracts defined here:
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
// properties. In the GREEN phase, this will call
// tlsconfig.TLSServerConfig(x509Source) and apply overrides.
//
// Contract:
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
// The GREEN phase will add an x509Closer field to Server and store it.
func (s *Server) setX509Closer(_ x509Closer) {
	// Stub: GREEN phase will store the closer on Server.
}

// runWithSPIREMock starts the server with a mock X509Source, skipping
// real SPIRE agent initialization. This enables testing shutdown
// behavior without a real SPIRE agent.
func (s *Server) runWithSPIREMock(_ context.Context) error {
	// Stub: GREEN phase will implement this to start the server with
	// the pre-set mock closer, skipping workloadapi.NewX509Source.
	return nil
}
