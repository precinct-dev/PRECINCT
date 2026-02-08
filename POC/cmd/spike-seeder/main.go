// cmd/spike-seeder seeds test secrets into SPIKE Nexus via mTLS.
//
// It connects to the SPIRE Agent via the Workload API, obtains an X.509
// SVID, and uses it to POST secrets to SPIKE Nexus. After seeding the
// secret, it creates an ACL policy granting read permission to the
// gateway's SPIFFE ID pattern.
//
// This is a one-shot init container for the Docker Compose POC.
//
// Environment variables:
//   - SPIKE_NEXUS_URL: Base URL of SPIKE Nexus (default: https://spike-nexus:8443)
//   - SPIFFE_ENDPOINT_SOCKET: SPIRE agent socket (required)
//   - SEED_REF: Secret reference/path (default: deadbeef)
//   - SEED_VALUE: Secret value (default: test-secret-value-12345)
//   - GATEWAY_SPIFFE_PATTERN: SPIFFE ID pattern for gateway read access
//     (default: spiffe://poc.local/gateways/.*)
//
// Exit codes: 0 = success, 1 = error.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIKE Nexus v0.8.0 PUT API expects {"path": "<ref>", "values": {"key": "val"}}.
// Note: the field is "values" (not "data"). The "data" field is only in the GET response.
// See spike-sdk-go/api/entity/v1/reqres/secret.go: SecretPutRequest.
type seedRequest struct {
	Path   string            `json:"path"`
	Values map[string]string `json:"values"`
}

// policyRequest matches spike-sdk-go/api/entity/v1/reqres/policy.go PolicyPutRequest.
type policyRequest struct {
	Name           string   `json:"name"`
	SPIFFEIDPattern string  `json:"spiffeIdPattern"`
	PathPattern    string   `json:"pathPattern"`
	Permissions    []string `json:"permissions"`
}

func main() {
	nexusURL := os.Getenv("SPIKE_NEXUS_URL")
	if nexusURL == "" {
		nexusURL = "https://spike-nexus:8443"
	}

	seedRef := os.Getenv("SEED_REF")
	if seedRef == "" {
		seedRef = "deadbeef"
	}

	seedValue := os.Getenv("SEED_VALUE")
	if seedValue == "" {
		seedValue = "test-secret-value-12345"
	}

	gatewayPattern := os.Getenv("GATEWAY_SPIFFE_PATTERN")
	if gatewayPattern == "" {
		gatewayPattern = "spiffe://poc.local/gateways/.*"
	}

	fmt.Printf("spike-seeder: seeding ref=%s into %s\n", seedRef, nexusURL)

	// Obtain X509Source from SPIRE Agent with generous timeout.
	// The agent may need a few seconds to deliver the SVID after attestation.
	svidCtx, svidCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer svidCancel()

	x509Source, err := workloadapi.NewX509Source(svidCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spike-seeder: failed to create X509Source: %v\n", err)
		os.Exit(1)
	}
	defer x509Source.Close()

	svid, err := x509Source.GetX509SVID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "spike-seeder: failed to get SVID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("spike-seeder: obtained SVID %s\n", svid.ID)

	// Create mTLS HTTP client
	mtlsConfig := tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: mtlsConfig,
		},
	}

	// Step 1: Seed the secret with retries (SPIKE Nexus may need a moment after startup)
	var lastErr error
	for attempt := 1; attempt <= 10; attempt++ {
		lastErr = seedSecret(client, nexusURL, seedRef, seedValue)
		if lastErr == nil {
			fmt.Printf("spike-seeder: successfully seeded ref=%s (attempt %d)\n", seedRef, attempt)
			break
		}
		fmt.Printf("spike-seeder: attempt %d failed: %v (retrying in 2s)\n", attempt, lastErr)
		time.Sleep(2 * time.Second)
	}

	if lastErr != nil {
		fmt.Fprintf(os.Stderr, "spike-seeder: all seed attempts failed: %v\n", lastErr)
		os.Exit(1)
	}

	// Step 2: Create ACL policy granting the gateway read access to all secrets.
	// SPIKE Nexus uses CheckAccess() with pattern-based policies. Without a policy,
	// only Pilot-role SPIFFE IDs can read secrets. The gateway needs read access
	// to perform token redemption.
	fmt.Printf("spike-seeder: creating ACL policy for gateway (%s)\n", gatewayPattern)
	if err := createPolicy(client, nexusURL, "gateway-read", gatewayPattern, ".*", []string{"read"}); err != nil {
		fmt.Fprintf(os.Stderr, "spike-seeder: WARNING: failed to create gateway policy: %v\n", err)
		fmt.Fprintf(os.Stderr, "spike-seeder: gateway may not be able to redeem SPIKE tokens\n")
		// Non-fatal -- the gateway can still function with POC fallback
	} else {
		fmt.Printf("spike-seeder: ACL policy 'gateway-read' created successfully\n")
	}

	os.Exit(0)
}

func seedSecret(client *http.Client, nexusURL, ref, value string) error {
	reqBody := seedRequest{
		Path:   ref,
		Values: map[string]string{"value": value},
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// SPIKE Nexus v0.8.0 PUT endpoint: POST /v1/store/secrets (no action param).
	// See spike-sdk-go/api/url/secret.go SecretPut() and config.go NexusSecrets.
	url := fmt.Sprintf("%s/v1/store/secrets", nexusURL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// SPIKE Nexus returns 200 for successful put operations
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}

func createPolicy(client *http.Client, nexusURL, name, spiffePattern, pathPattern string, permissions []string) error {
	reqBody := policyRequest{
		Name:           name,
		SPIFFEIDPattern: spiffePattern,
		PathPattern:    pathPattern,
		Permissions:    permissions,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// SPIKE Nexus v0.8.0 Policy endpoint: POST /v1/acl/policy (no action param for create).
	// See spike-sdk-go/api/url/policy.go PolicyCreate() and config.go NexusPolicy.
	url := fmt.Sprintf("%s/v1/acl/policy", nexusURL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}
