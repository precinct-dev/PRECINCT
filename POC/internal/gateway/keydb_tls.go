package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// KeyDBTLSConfig holds TLS configuration for connecting to KeyDB in
// SPIFFE_MODE=prod. KeyDB does not speak the SPIRE Workload API natively,
// so it receives filesystem-based certs via an init/sidecar that writes
// SVID PEM files to a shared volume.
//
// The gateway's go-redis client uses TLS to connect to KeyDB on port 6380
// (the TLS port), presenting its own SVID as a client certificate and
// validating KeyDB's SVID against the SPIRE trust bundle.
type KeyDBTLSConfig struct {
	TLSConfig *tls.Config
}

// NewKeyDBTLSConfigFromSPIRE creates a TLS configuration for the KeyDB client
// using the gateway's X509Source from SPIRE. This provides mTLS: the gateway
// presents its SVID as a client cert, and validates KeyDB's cert against the
// SPIRE trust bundle.
//
// The x509Source MUST be the same source used for the gateway's server TLS
// (created in SPIFFETLSConfig). This ensures a single SVID rotation lifecycle.
func NewKeyDBTLSConfigFromSPIRE(x509Source *workloadapi.X509Source) (*KeyDBTLSConfig, error) {
	if x509Source == nil {
		return nil, fmt.Errorf("x509Source is nil: SPIRE agent connection required for KeyDB TLS")
	}

	// Use go-spiffe's canonical MTLSClientConfig for the KeyDB connection.
	// AuthorizeAny() accepts any SPIFFE ID from the trust domain -- KeyDB's
	// specific identity is validated by the trust bundle, not by SPIFFE ID
	// matching (same pattern as upstream proxy transport in spiffe_tls.go).
	mtlsConfig := tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())

	return &KeyDBTLSConfig{
		TLSConfig: mtlsConfig,
	}, nil
}

// NewKeyDBTLSConfigFromPEM creates a TLS configuration for the KeyDB client
// from PEM-encoded certificate files. This is useful when SPIRE Workload API
// is not available (e.g., during testing or for external KeyDB instances).
func NewKeyDBTLSConfigFromPEM(certFile, keyFile, caFile string) (*KeyDBTLSConfig, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load KeyDB client cert/key: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read KeyDB CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse KeyDB CA cert")
	}

	return &KeyDBTLSConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS12,
		},
	}, nil
}

// NewKeyDBClientTLS creates a redis.Client configured for TLS connections.
// The url should use the rediss:// scheme or a plain host:port with TLS
// handled by the provided tls.Config.
//
// In SPIFFE_MODE=prod, the KeyDB URL changes from redis://keydb:6379 to
// rediss://keydb:6380 (TLS port).
func NewKeyDBClientTLS(url string, poolMin, poolMax int, tlsCfg *tls.Config) *redis.Client {
	opts, err := redis.ParseURL(url)
	if err != nil {
		// Fall back to simple address parsing for non-URL formats
		opts = &redis.Options{
			Addr: url,
		}
	}
	opts.MinIdleConns = poolMin
	opts.PoolSize = poolMax
	opts.TLSConfig = tlsCfg

	return redis.NewClient(opts)
}

// KeyDBURLForMode returns the appropriate KeyDB URL based on SPIFFE mode.
// In dev mode, it returns the original URL unchanged.
// In prod mode, it converts redis:// to rediss:// and port 6379 to 6380.
//
// This function is a convenience for the gateway startup code. It does NOT
// modify URLs that already use rediss:// or non-standard ports.
func KeyDBURLForMode(url, spiffeMode string) string {
	if spiffeMode != "prod" {
		return url
	}

	// Only convert standard redis:// URLs to TLS
	if len(url) >= 8 && url[:8] == "redis://" {
		// Replace redis:// with rediss://
		tlsURL := "rediss://" + url[8:]

		// Replace default port 6379 with TLS port 6380
		// Only replace the last occurrence to avoid replacing ports in passwords
		if len(tlsURL) >= 5 && tlsURL[len(tlsURL)-4:] == "6379" {
			tlsURL = tlsURL[:len(tlsURL)-4] + "6380"
		}

		return tlsURL
	}

	return url
}
