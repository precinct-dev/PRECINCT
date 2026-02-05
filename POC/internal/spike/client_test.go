package spike

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClient_Init(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()
	config := &Config{
		StoragePath: filepath.Join(tmpDir, ".spike", "secrets.json"),
	}

	client := NewClient(config)

	// Test initialization
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	// Verify directory was created
	dir := filepath.Dir(config.StoragePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("Storage directory was not created: %s", dir)
	}

	// Verify secrets file was created
	if _, err := os.Stat(config.StoragePath); os.IsNotExist(err) {
		t.Errorf("Secrets file was not created: %s", config.StoragePath)
	}
}

func TestClient_Put(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := NewClient(config)

	// Initialize first
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	tests := []struct {
		name    string
		secret  *Secret
		wantErr bool
	}{
		{
			name: "valid secret",
			secret: &Secret{
				Ref:      "abc123",
				Value:    "secret-value",
				SpiffeID: "spiffe://example.org/agent/test",
				Scope:    "tools.http.api.openai.com",
			},
			wantErr: false,
		},
		{
			name: "valid secret without spiffe and scope",
			secret: &Secret{
				Ref:   "def456",
				Value: "another-secret",
			},
			wantErr: false,
		},
		{
			name: "empty ref",
			secret: &Secret{
				Ref:   "",
				Value: "secret",
			},
			wantErr: true,
		},
		{
			name: "empty value",
			secret: &Secret{
				Ref:   "abc",
				Value: "",
			},
			wantErr: true,
		},
		{
			name: "non-hex ref",
			secret: &Secret{
				Ref:   "xyz123",
				Value: "secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.Put(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Put() error = %v, wantErr %v", err, tt.wantErr)
			}

			// If no error expected, verify secret was stored
			if !tt.wantErr {
				stored, err := client.Get(tt.secret.Ref)
				if err != nil {
					t.Errorf("Get() failed after Put(): %v", err)
				}
				if stored.Value != tt.secret.Value {
					t.Errorf("Get() value = %v, want %v", stored.Value, tt.secret.Value)
				}
			}
		})
	}
}

func TestClient_Issue(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := NewClient(config)

	// Initialize and seed a secret
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	secret := &Secret{
		Ref:      "abc123",
		Value:    "my-secret-value",
		SpiffeID: "spiffe://example.org/agent/test",
		Scope:    "tools.http.api.openai.com",
	}
	if err := client.Put(secret); err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	tests := []struct {
		name      string
		ref       string
		exp       int64
		scope     string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "token with all fields",
			ref:       "abc123",
			exp:       300,
			scope:     "tools.http.api.openai.com",
			wantToken: "$SPIKE{ref:abc123,exp:300,scope:tools.http.api.openai.com}",
			wantErr:   false,
		},
		{
			name:      "token without expiry",
			ref:       "abc123",
			exp:       0,
			scope:     "tools.http.api.openai.com",
			wantToken: "$SPIKE{ref:abc123,scope:tools.http.api.openai.com}",
			wantErr:   false,
		},
		{
			name:      "token without scope",
			ref:       "abc123",
			exp:       300,
			scope:     "",
			wantToken: "$SPIKE{ref:abc123,exp:300}",
			wantErr:   false,
		},
		{
			name:      "token minimal",
			ref:       "abc123",
			exp:       0,
			scope:     "",
			wantToken: "$SPIKE{ref:abc123}",
			wantErr:   false,
		},
		{
			name:    "non-existent secret",
			ref:     "nonexistent",
			exp:     300,
			scope:   "tools.http.api.openai.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := client.Issue(tt.ref, tt.exp, tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("Issue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && token != tt.wantToken {
				t.Errorf("Issue() token = %v, want %v", token, tt.wantToken)
			}
		})
	}
}

func TestClient_Get(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := NewClient(config)

	// Initialize and seed a secret
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	secret := &Secret{
		Ref:      "abc123",
		Value:    "my-secret-value",
		SpiffeID: "spiffe://example.org/agent/test",
	}
	if err := client.Put(secret); err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	// Test Get
	retrieved, err := client.Get("abc123")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if retrieved.Value != secret.Value {
		t.Errorf("Get() value = %v, want %v", retrieved.Value, secret.Value)
	}

	// Test Get non-existent
	_, err = client.Get("nonexistent")
	if err == nil {
		t.Error("Get() should fail for non-existent secret")
	}
}

func TestClient_RedeemToken(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := NewClient(config)

	// Initialize and seed a secret
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	secret := &Secret{
		Ref:      "abc123",
		Value:    "my-secret-value",
		SpiffeID: "spiffe://example.org/agent/test",
	}
	if err := client.Put(secret); err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		spiffeID  string
		wantValue string
		wantErr   bool
	}{
		{
			name:      "valid redemption",
			token:     "$SPIKE{ref:abc123,exp:300,scope:tools.http.api.openai.com}",
			spiffeID:  "spiffe://example.org/agent/test",
			wantValue: "my-secret-value",
			wantErr:   false,
		},
		{
			name:      "valid redemption minimal token",
			token:     "$SPIKE{ref:abc123}",
			spiffeID:  "spiffe://example.org/agent/test",
			wantValue: "my-secret-value",
			wantErr:   false,
		},
		{
			name:     "ownership mismatch",
			token:    "$SPIKE{ref:abc123}",
			spiffeID: "spiffe://example.org/agent/wrong",
			wantErr:  true,
		},
		{
			name:     "invalid token format",
			token:    "invalid-token",
			spiffeID: "spiffe://example.org/agent/test",
			wantErr:  true,
		},
		{
			name:     "non-existent secret",
			token:    "$SPIKE{ref:nonexistent}",
			spiffeID: "spiffe://example.org/agent/test",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := client.RedeemToken(tt.token, tt.spiffeID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RedeemToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if retrieved.Value != tt.wantValue {
					t.Errorf("RedeemToken() value = %v, want %v", retrieved.Value, tt.wantValue)
				}
			}
		})
	}
}

func TestTokenFormat(t *testing.T) {
	// Test that issued tokens match the format expected by gateway
	tmpDir := t.TempDir()
	config := &Config{
		StoragePath: filepath.Join(tmpDir, "secrets.json"),
	}

	client := NewClient(config)

	// Initialize and seed
	if err := client.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	secret := &Secret{
		Ref:   "abc123",
		Value: "test-value",
	}
	if err := client.Put(secret); err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	// Issue token
	token, err := client.Issue("abc123", 300, "tools.http.api")
	if err != nil {
		t.Fatalf("Issue() failed: %v", err)
	}

	// Verify format matches gateway regex
	if !strings.HasPrefix(token, "$SPIKE{ref:") {
		t.Errorf("Token does not start with $SPIKE{ref:, got: %s", token)
	}
	if !strings.HasSuffix(token, "}") {
		t.Errorf("Token does not end with }, got: %s", token)
	}
	if !strings.Contains(token, "abc123") {
		t.Errorf("Token does not contain ref abc123, got: %s", token)
	}
}
