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
// upstreamAuthzAllowedSPIFFEIDs optionally pins upstream peer identities.
// When empty, upstream identity authorization falls back to trust-domain-wide
// acceptance (compatibility mode).
//
// The caller MUST call Close() when done to release the X509Source.
func NewSPIFFETLSConfig(ctx context.Context, upstreamAuthzAllowedSPIFFEIDs []string) (*SPIFFETLSConfig, error) {
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

	peerAuthz, err := buildSPIFFEPeerAuthorizer(upstreamAuthzAllowedSPIFFEIDs, "upstream")
	if err != nil {
		_ = x509Source.Close()
		return nil, fmt.Errorf("failed to configure upstream SPIFFE identity pinning: %w", err)
	}

	// Upstream transport: present our SVID as client cert, validate the upstream
	// certificate chain, and enforce explicit SPIFFE identity allowlists when
	// configured (or strict-profile defaults).
	upstreamTLS := tlsconfig.MTLSClientConfig(x509Source, x509Source, peerAuthz.authorizer)
	installPinnedPeerIdentityVerifier(upstreamTLS, peerAuthz.allowedIDs, "upstream")
	upstreamTransport := &http.Transport{
		TLSClientConfig: upstreamTLS,
	}
	if peerAuthz.mode == spiffePeerAuthorizationModeAllowlist {
		log.Printf("SPIFFE mTLS: upstream identity pinning enabled (allowed IDs: %v)", peerAuthz.allowedIDs)
	} else {
		log.Printf("SPIFFE mTLS: upstream identity pinning is permissive (no explicit IDs configured)")
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
