package middleware

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// SPIKENexusRedeemer redeems SPIKE tokens by calling SPIKE Nexus via mTLS.
// It uses the SPIRE Workload API (go-spiffe) to obtain X.509 SVIDs for
// mutual TLS authentication. This is the production replacement for
// POCSecretRedeemer.
type SPIKENexusRedeemer struct {
	nexusURL   string                  // Base URL of SPIKE Nexus (e.g., https://spike-nexus:8443)
	httpClient *http.Client            // mTLS-configured HTTP client
	x509Source *workloadapi.X509Source // SPIRE X.509 SVID source for mTLS
	devMode    bool                    // When true, auto-populate OwnerID if Nexus doesn't return it (POC accommodation)
}

// spikeSecretRequest is the JSON body for POST /v1/store/secrets?action=get
type spikeSecretRequest struct {
	Path string `json:"path"`
}

// spikeSecretResponse is the JSON response from SPIKE Nexus
type spikeSecretResponse struct {
	Data map[string]string `json:"data"`
	Err  string            `json:"err,omitempty"`
}

// NewSPIKENexusRedeemer creates a new SPIKENexusRedeemer with mTLS via SPIRE.
// The x509Source provides automatic certificate rotation from the SPIRE Agent.
// If x509Source is nil, TLS is used without client certificates (useful for
// testing scenarios where SPIRE is unavailable).
// When devMode is true, the redeemer auto-populates OwnerID from the
// requesting agent's SPIFFE ID (via context) if SPIKE Nexus does not return
// owner metadata. This is a POC accommodation documented in ADR-001.
func NewSPIKENexusRedeemer(nexusURL string, x509Source *workloadapi.X509Source, devMode ...bool) *SPIKENexusRedeemer {
	var tlsConfig *tls.Config

	if x509Source != nil {
		// Production mode: use go-spiffe tlsconfig helper for mTLS.
		// X509Source implements both x509svid.Source and x509bundle.Source.
		// AuthorizeAny allows any SPIFFE ID from the trust domain (SPIKE Nexus
		// will present its own SPIFFE ID).
		tlsConfig = tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
	} else {
		// Testing/dev mode: skip TLS verification (no SPIRE available)
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Required for dev/test without SPIRE
			MinVersion:         tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	dm := len(devMode) > 0 && devMode[0]
	return &SPIKENexusRedeemer{
		nexusURL:   strings.TrimRight(nexusURL, "/"),
		httpClient: client,
		x509Source: x509Source,
		devMode:    dm,
	}
}

// NewSPIKENexusRedeemerWithClient creates a SPIKENexusRedeemer with a custom
// HTTP client. This is primarily for unit testing with httptest servers.
func NewSPIKENexusRedeemerWithClient(nexusURL string, client *http.Client) *SPIKENexusRedeemer {
	return &SPIKENexusRedeemer{
		nexusURL:   strings.TrimRight(nexusURL, "/"),
		httpClient: client,
	}
}

// RedeemSecret calls SPIKE Nexus to retrieve the actual secret value for a
// SPIKE token. The token's Ref field is used as the secret path in Nexus.
//
// The call is: POST <nexusURL>/v1/store/secrets?action=get
// Body: {"path": "<token.Ref>"}
// Response: {"data": {"value": "<secret>"}}
func (s *SPIKENexusRedeemer) RedeemSecret(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error) {
	if token == nil {
		return nil, fmt.Errorf("token is nil")
	}

	// Build request body
	reqBody := spikeSecretRequest{
		Path: token.Ref,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request.
	// SPIKE Nexus get-secret endpoint is POST /v1/store/secrets?action=get.
	url := fmt.Sprintf("%s/v1/store/secrets?action=get", s.nexusURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// RFA-m6j.3: Inject W3C Trace Context (traceparent/tracestate) into
	// outbound request headers. This enables distributed trace correlation
	// between the gateway and SPIKE Nexus.
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	// Execute request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call SPIKE Nexus: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SPIKE Nexus returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var spikeResp spikeSecretResponse
	if err := json.Unmarshal(respBody, &spikeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for error in response
	if spikeResp.Err != "" {
		return nil, fmt.Errorf("SPIKE Nexus error: %s", spikeResp.Err)
	}

	// Extract secret value from data map
	secretValue, ok := spikeResp.Data["value"]
	if !ok {
		return nil, fmt.Errorf("SPIKE Nexus response missing 'value' in data")
	}

	// Populate token.OwnerID from Nexus response metadata (RFA-7ct).
	// In production, SPIKE Nexus returns the owner SPIFFE ID that was
	// assigned at token issuance time. The gateway uses this for
	// defense-in-depth ownership validation after redemption.
	if owner, ok := spikeResp.Data["owner"]; ok {
		token.OwnerID = owner
	}

	// RFA-uln: In dev mode, if SPIKE Nexus did not return owner metadata,
	// auto-populate OwnerID from the requesting agent's SPIFFE ID (from
	// context). This prevents "empty OwnerID" rejection in POC mode where
	// SPIKE Nexus v0.8.0 does not track ownership. This is an explicit POC
	// accommodation; production deployments MUST have Nexus populate OwnerID.
	if s.devMode && token.OwnerID == "" {
		if spiffeID := GetSPIFFEID(ctx); spiffeID != "" {
			token.OwnerID = spiffeID
		}
	}

	return &SPIKESecret{
		Value:     secretValue,
		ExpiresAt: time.Now().Unix() + 3600, // Default 1 hour TTL
	}, nil
}

// Close releases resources held by the redeemer, including the X.509 source.
func (s *SPIKENexusRedeemer) Close() error {
	if s.x509Source != nil {
		return s.x509Source.Close()
	}
	return nil
}
