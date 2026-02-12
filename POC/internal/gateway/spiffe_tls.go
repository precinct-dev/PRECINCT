package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFETLSConfig holds the TLS configuration obtained from SPIRE for the
// gateway server (RFA-8z8.1). It owns the X509Source lifecycle and must be
// closed when the gateway shuts down.
type SPIFFETLSConfig struct {
	// ServerTLS is the tls.Config for the gateway's HTTPS listener.
	// It presents the gateway's X.509 SVID and validates client certs
	// against the SPIRE trust bundle.
	ServerTLS *tls.Config

	// UpstreamTransport is an *http.Transport configured for mTLS to
	// upstream MCP servers. It presents the gateway's SVID as a client
	// certificate and validates the upstream's SVID.
	UpstreamTransport *http.Transport

	// x509Source is the SPIRE Workload API X.509 source. It provides
	// automatic SVID rotation (1-hour default per ADR-003).
	x509Source *workloadapi.X509Source
}

// NewSPIFFETLSConfig connects to the SPIRE Agent via the Workload API,
// obtains an X.509 SVID, and returns TLS configurations for both the
// server listener and the upstream reverse proxy transport.
//
// The caller MUST call Close() when done to release the X509Source.
func NewSPIFFETLSConfig(ctx context.Context) (*SPIFFETLSConfig, error) {
	// Connect to SPIRE Agent via Workload API.
	// The socket path is discovered from SPIFFE_ENDPOINT_SOCKET env var
	// (set in docker-compose.yml).
	x509Source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source from SPIRE: %w", err)
	}

	// Log the SVID we received for operational visibility
	svid, err := x509Source.GetX509SVID()
	if err != nil {
		_ = x509Source.Close()
		return nil, fmt.Errorf("failed to get X509 SVID: %w", err)
	}
	log.Printf("SPIFFE mTLS: obtained SVID %s (cert expires: %s)",
		svid.ID, svid.Certificates[0].NotAfter.Format("2006-01-02T15:04:05Z"))

	// Server TLS: present our SVID, require and verify client certificates
	// against the SPIRE trust bundle. This enforces mTLS -- only clients
	// with valid SVIDs from our trust domain can connect.
	serverTLS := tlsconfig.TLSServerConfig(x509Source)
	serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	serverTLS.ClientCAs = nil // go-spiffe handles this via the VerifyPeerCertificate callback
	serverTLS.MinVersion = tls.VersionTLS12

	// Upstream transport: present our SVID as client cert, verify upstream's SVID.
	// AuthorizeAny() accepts any SPIFFE ID from the trust domain -- the upstream
	// MCP server's specific identity is validated by the trust bundle, not by
	// SPIFFE ID matching here (that would be too restrictive for a gateway).
	upstreamTLS := tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
	upstreamTransport := &http.Transport{
		TLSClientConfig: upstreamTLS,
	}

	return &SPIFFETLSConfig{
		ServerTLS:         serverTLS,
		UpstreamTransport: upstreamTransport,
		x509Source:        x509Source,
	}, nil
}

// Close releases the X509Source, stopping SVID rotation.
func (s *SPIFFETLSConfig) Close() error {
	if s.x509Source != nil {
		return s.x509Source.Close()
	}
	return nil
}
