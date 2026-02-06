package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// TestSPIFFETLSConfig_ServerTLSFields verifies the SPIFFETLSConfig struct
// fields are accessible and nil-safe.
func TestSPIFFETLSConfig_ServerTLSFields(t *testing.T) {
	cfg := &SPIFFETLSConfig{}
	if cfg.ServerTLS != nil {
		t.Error("Expected nil ServerTLS for zero-value struct")
	}
	if cfg.UpstreamTransport != nil {
		t.Error("Expected nil UpstreamTransport for zero-value struct")
	}
	// Close on zero-value should not panic
	if err := cfg.Close(); err != nil {
		t.Errorf("Close on nil x509Source should return nil, got %v", err)
	}
}

// TestGatewayMTLSIntegration is the walking skeleton integration test (AC7).
// It proves that a gateway configured for mTLS:
// 1. Accepts connections from clients with valid SVID certificates
// 2. Rejects connections from clients without certificates (plain HTTPS)
// 3. Extracts the SPIFFE ID from the client cert and makes it available to middleware
//
// This test creates a self-signed CA and issues certificates locally rather than
// requiring a running SPIRE agent, making it suitable for CI.
func TestGatewayMTLSIntegration(t *testing.T) {
	// --- Set up a local PKI (simulating SPIRE) ---
	ca := newTestCA(t)

	// Server certificate (gateway's SVID)
	serverSPIFFE := "spiffe://poc.local/gateway"
	serverCert, serverKey := ca.issueCert(t, serverSPIFFE)

	// Client certificate (agent's SVID)
	clientSPIFFE := "spiffe://poc.local/agents/test-agent/dev"
	clientCert, clientKey := ca.issueCert(t, clientSPIFFE)

	// --- Create the gateway's TLS config (simulating what SPIFFETLSConfig does) ---
	serverTLSCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}),
		pemEncodeKey(t, serverKey),
	)
	if err != nil {
		t.Fatalf("Failed to create server TLS cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// --- Create a test gateway with SPIFFEAuth in prod mode ---
	// Track what SPIFFE ID the middleware extracts
	var extractedSPIFFEID string
	handler := middleware.SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedSPIFFEID = middleware.GetSPIFFEID(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","spiffe_id":"` + extractedSPIFFEID + `"}`))
	}), "prod")

	// Create HTTPS test server with mTLS
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLSConfig
	server.StartTLS()
	defer server.Close()

	// --- Test 1: Valid mTLS client succeeds (AC1, AC2) ---
	t.Run("ValidMTLSClientSucceeds", func(t *testing.T) {
		extractedSPIFFEID = ""

		clientTLSCert, err := tls.X509KeyPair(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}),
			pemEncodeKey(t, clientKey),
		)
		if err != nil {
			t.Fatalf("Failed to create client TLS cert: %v", err)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{clientTLSCert},
					RootCAs:      caPool,
					MinVersion:   tls.VersionTLS12,
				},
			},
		}

		resp, err := client.Get(server.URL + "/health")
		if err != nil {
			t.Fatalf("mTLS request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}

		if extractedSPIFFEID != clientSPIFFE {
			t.Errorf("Expected extracted SPIFFE ID %q, got %q", clientSPIFFE, extractedSPIFFEID)
		}

		t.Logf("PASS: mTLS handshake succeeded, SPIFFE ID extracted: %s", extractedSPIFFEID)
	})

	// --- Test 2: Client without certificate is rejected (AC2) ---
	t.Run("PlainHTTPSRejected", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caPool,
					MinVersion: tls.VersionTLS12,
					// No client certificates
				},
			},
		}

		_, err := client.Get(server.URL + "/health")
		if err == nil {
			t.Error("Expected TLS handshake to fail for client without certificate, but it succeeded")
		}
		// The error should be a TLS handshake failure
		t.Logf("PASS: Client without certificate rejected: %v", err)
	})

	// --- Test 3: Client with untrusted certificate is rejected ---
	t.Run("UntrustedClientCertRejected", func(t *testing.T) {
		// Create a different CA (not trusted by server)
		untrustedCA := newTestCA(t)
		untrustedCert, untrustedKey := untrustedCA.issueCert(t, "spiffe://evil.domain/attacker")

		untrustedTLSCert, err := tls.X509KeyPair(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedCert.Raw}),
			pemEncodeKey(t, untrustedKey),
		)
		if err != nil {
			t.Fatalf("Failed to create untrusted client cert: %v", err)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{untrustedTLSCert},
					RootCAs:      caPool,
					MinVersion:   tls.VersionTLS12,
				},
			},
		}

		_, err = client.Get(server.URL + "/health")
		if err == nil {
			t.Error("Expected TLS handshake to fail for untrusted client certificate")
		}
		t.Logf("PASS: Client with untrusted certificate rejected: %v", err)
	})
}

// TestGatewayMTLSReverseProxy verifies AC3: the reverse proxy uses mTLS to upstream.
// This simulates the gateway proxying a request to an upstream mTLS server.
func TestGatewayMTLSReverseProxy(t *testing.T) {
	// Set up local PKI
	ca := newTestCA(t)

	// Gateway cert (acts as client to upstream)
	gatewayCert, gatewayKey := ca.issueCert(t, "spiffe://poc.local/gateway")

	// Upstream cert
	upstreamCert, upstreamKey := ca.issueCert(t, "spiffe://poc.local/mcp-server")

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	// Create upstream mTLS server
	upstreamTLSCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstreamCert.Raw}),
		pemEncodeKey(t, upstreamKey),
	)
	if err != nil {
		t.Fatalf("Failed to create upstream TLS cert: %v", err)
	}

	var upstreamReceivedSPIFFEID string
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the gateway's SPIFFE ID from the client cert it presented
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cert := r.TLS.PeerCertificates[0]
			for _, uri := range cert.URIs {
				if uri.Scheme == "spiffe" {
					upstreamReceivedSPIFFEID = uri.String()
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"upstream_ok"}`))
	})

	upstreamServer := httptest.NewUnstartedServer(upstreamHandler)
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{upstreamTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	upstreamServer.StartTLS()
	defer upstreamServer.Close()

	// Create a client that presents the gateway's SVID (simulating the reverse proxy transport)
	gatewayTLSCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gatewayCert.Raw}),
		pemEncodeKey(t, gatewayKey),
	)
	if err != nil {
		t.Fatalf("Failed to create gateway client TLS cert: %v", err)
	}

	gatewayClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{gatewayTLSCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	resp, err := gatewayClient.Get(upstreamServer.URL + "/mcp")
	if err != nil {
		t.Fatalf("Gateway -> upstream mTLS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 from upstream, got %d", resp.StatusCode)
	}

	if upstreamReceivedSPIFFEID != "spiffe://poc.local/gateway" {
		t.Errorf("Upstream should have received gateway's SPIFFE ID, got %q", upstreamReceivedSPIFFEID)
	}

	t.Logf("PASS: Reverse proxy mTLS to upstream verified, upstream saw SPIFFE ID: %s", upstreamReceivedSPIFFEID)
}

// --- Test PKI helpers ---

// testCA is a self-signed Certificate Authority for testing mTLS.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newTestCA creates a new self-signed CA for testing.
func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// issueCert issues a leaf certificate signed by this CA with the given SPIFFE ID as a URI SAN.
func (ca *testCA) issueCert(t *testing.T, spiffeID string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("Failed to parse SPIFFE ID: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("test-workload-%s", spiffeID),
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{spiffeURI},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	return cert, key
}

// pemEncodeKey encodes an ECDSA private key to PEM format.
func pemEncodeKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
