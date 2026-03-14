// +build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/spike"
)

func TestSPIKECLI_FullFlow(t *testing.T) {
	// This test verifies the complete flow:
	// 1. spike-cli put: Seed a secret
	// 2. spike-cli issue: Issue a token
	// 3. Gateway: Parse and validate token format

	tmpDir := t.TempDir()
	config := &spike.Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := spike.NewClient(config)

	// Step 1: Initialize (equivalent to spike-cli init)
	t.Run("init", func(t *testing.T) {
		if err := client.Init(); err != nil {
			t.Fatalf("Init() failed: %v", err)
		}

		// Verify storage was created
		if _, err := os.Stat(config.StoragePath); os.IsNotExist(err) {
			t.Error("Secrets storage file was not created")
		}
	})

	// Step 2: Seed a secret (equivalent to spike-cli put)
	t.Run("put", func(t *testing.T) {
		secret := &spike.Secret{
			Ref:      "7f3a9b2c",
			Value:    "sk-test-api-key-12345",
			SpiffeID: "spiffe://example.org/agent/test",
			Scope:    "tools.http.api.openai.com",
		}

		if err := client.Put(secret); err != nil {
			t.Fatalf("Put() failed: %v", err)
		}

		// Verify secret was stored
		retrieved, err := client.Get("7f3a9b2c")
		if err != nil {
			t.Fatalf("Get() failed after Put(): %v", err)
		}

		if retrieved.Value != secret.Value {
			t.Errorf("Retrieved value = %v, want %v", retrieved.Value, secret.Value)
		}
	})

	// Step 3: Issue a token (equivalent to spike-cli issue)
	var token string
	t.Run("issue", func(t *testing.T) {
		var err error
		token, err = client.Issue("7f3a9b2c", 300, "tools.http.api.openai.com")
		if err != nil {
			t.Fatalf("Issue() failed: %v", err)
		}

		expectedToken := "$SPIKE{ref:7f3a9b2c,exp:300,scope:tools.http.api.openai.com}"
		if token != expectedToken {
			t.Errorf("Issue() token = %v, want %v", token, expectedToken)
		}
	})

	// Step 4: Verify gateway can parse the token
	t.Run("gateway_parse", func(t *testing.T) {
		parsed, err := middleware.ParseSPIKEToken(token)
		if err != nil {
			t.Fatalf("Gateway ParseSPIKEToken() failed: %v", err)
		}

		if parsed.Ref != "7f3a9b2c" {
			t.Errorf("Parsed ref = %v, want 7f3a9b2c", parsed.Ref)
		}

		if parsed.Exp != 300 {
			t.Errorf("Parsed exp = %v, want 300", parsed.Exp)
		}

		if parsed.Scope != "tools.http.api.openai.com" {
			t.Errorf("Parsed scope = %v, want tools.http.api.openai.com", parsed.Scope)
		}
	})

	// Step 5: Verify gateway can validate token ownership
	t.Run("gateway_validate_ownership", func(t *testing.T) {
		parsed, _ := middleware.ParseSPIKEToken(token)

		// Set owner ID (simulating SPIKE Nexus response)
		parsed.OwnerID = "spiffe://example.org/agent/test"

		// Valid ownership
		if err := middleware.ValidateTokenOwnership(parsed, "spiffe://example.org/agent/test"); err != nil {
			t.Errorf("ValidateTokenOwnership() failed for valid owner: %v", err)
		}

		// Invalid ownership
		err := middleware.ValidateTokenOwnership(parsed, "spiffe://example.org/agent/wrong")
		if err == nil {
			t.Error("ValidateTokenOwnership() should fail for wrong owner")
		}
	})

	// Step 6: Verify gateway can validate token expiry
	t.Run("gateway_validate_expiry", func(t *testing.T) {
		parsed, _ := middleware.ParseSPIKEToken(token)

		// Token should not be expired (just issued)
		if err := middleware.ValidateTokenExpiry(parsed); err != nil {
			t.Errorf("ValidateTokenExpiry() failed for fresh token: %v", err)
		}
	})

	// Step 7: Verify gateway can validate token scope
	t.Run("gateway_validate_scope", func(t *testing.T) {
		parsed, _ := middleware.ParseSPIKEToken(token)

		// Valid scope
		if err := middleware.ValidateTokenScope(parsed, "tools", "http", "api.openai.com"); err != nil {
			t.Errorf("ValidateTokenScope() failed for valid scope: %v", err)
		}

		// Invalid scope
		err := middleware.ValidateTokenScope(parsed, "tools", "http", "wrong.com")
		if err == nil {
			t.Error("ValidateTokenScope() should fail for wrong destination")
		}
	})
}

func TestSPIKECLI_MultipleSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	config := &spike.Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := spike.NewClient(config)

	// Initialize
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	// Seed multiple secrets
	secrets := []*spike.Secret{
		{
			Ref:      "abc123",
			Value:    "openai-key",
			SpiffeID: "spiffe://example.org/agent/openai",
			Scope:    "tools.http.api.openai.com",
		},
		{
			Ref:      "def456",
			Value:    "github-token",
			SpiffeID: "spiffe://example.org/agent/github",
			Scope:    "tools.http.api.github.com",
		},
		{
			Ref:      "789abc",
			Value:    "docker-password",
			SpiffeID: "spiffe://example.org/agent/docker",
			Scope:    "tools.docker.write",
		},
	}

	for _, secret := range secrets {
		if err := client.Put(secret); err != nil {
			t.Fatalf("Put() failed for %s: %v", secret.Ref, err)
		}
	}

	// Issue tokens for each
	for _, secret := range secrets {
		token, err := client.Issue(secret.Ref, 300, secret.Scope)
		if err != nil {
			t.Fatalf("Issue() failed for %s: %v", secret.Ref, err)
		}

		// Verify token format
		parsed, err := middleware.ParseSPIKEToken(token)
		if err != nil {
			t.Fatalf("ParseSPIKEToken() failed for %s: %v", secret.Ref, err)
		}

		if parsed.Ref != secret.Ref {
			t.Errorf("Token ref mismatch: got %v, want %v", parsed.Ref, secret.Ref)
		}
	}
}

func TestSPIKECLI_TokenRedemption(t *testing.T) {
	// This test simulates the full redemption flow:
	// 1. Seed secret
	// 2. Issue token
	// 3. Gateway redeems token (POC simulation)

	tmpDir := t.TempDir()
	config := &spike.Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := spike.NewClient(config)

	// Initialize and seed
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	secret := &spike.Secret{
		Ref:      "abc123",
		Value:    "my-api-key",
		SpiffeID: "spiffe://example.org/agent/test",
		Scope:    "tools.http.api.openai.com",
	}

	if err := client.Put(secret); err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	// Issue token
	token, err := client.Issue("abc123", 300, "tools.http.api.openai.com")
	if err != nil {
		t.Fatalf("Issue() failed: %v", err)
	}

	// Simulate gateway redemption
	t.Run("redeem_valid", func(t *testing.T) {
		redeemed, err := client.RedeemToken(token, "spiffe://example.org/agent/test")
		if err != nil {
			t.Fatalf("RedeemToken() failed: %v", err)
		}

		if redeemed.Value != secret.Value {
			t.Errorf("Redeemed value = %v, want %v", redeemed.Value, secret.Value)
		}
	})

	t.Run("redeem_wrong_owner", func(t *testing.T) {
		_, err := client.RedeemToken(token, "spiffe://example.org/agent/wrong")
		if err == nil {
			t.Error("RedeemToken() should fail for wrong owner")
		}
	})
}

func TestSPIKECLI_HexValidation(t *testing.T) {
	// Verify that only hex characters are allowed in refs
	tmpDir := t.TempDir()
	config := &spike.Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := spike.NewClient(config)

	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"valid hex lowercase", "abc123", false},
		{"valid hex all digits", "123456", false},
		{"valid hex all letters", "abcdef", false},
		{"invalid uppercase", "ABC123", true},
		{"invalid with special chars", "abc-123", true},
		{"invalid with space", "abc 123", true},
		{"invalid with non-hex letter", "xyz123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &spike.Secret{
				Ref:   tt.ref,
				Value: "test-value",
			}

			err := client.Put(secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Put() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSPIKECLI_Persistence(t *testing.T) {
	// Verify secrets persist across client instances
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "secrets.json")

	// First client: init and put
	config1 := &spike.Config{StoragePath: storagePath}
	client1 := spike.NewClient(config1)

	if err := client1.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	secret := &spike.Secret{
		Ref:   "abc123",
		Value: "persistent-value",
	}

	if err := client1.Put(secret); err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	// Second client: verify can read
	config2 := &spike.Config{StoragePath: storagePath}
	client2 := spike.NewClient(config2)

	retrieved, err := client2.Get("abc123")
	if err != nil {
		t.Fatalf("Get() from second client failed: %v", err)
	}

	if retrieved.Value != secret.Value {
		t.Errorf("Value persistence failed: got %v, want %v", retrieved.Value, secret.Value)
	}
}
