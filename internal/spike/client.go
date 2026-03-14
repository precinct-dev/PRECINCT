package spike

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Secret represents a secret stored in SPIKE Nexus
type Secret struct {
	Ref       string `json:"ref"`        // Hex reference to the secret
	Value     string `json:"value"`      // The actual secret value
	SpiffeID  string `json:"spiffe_id"`  // SPIFFE ID allowed to use this secret
	Scope     string `json:"scope"`      // Scope restrictions (location.operation.destination)
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp (0 = no expiry)
}

// Config represents the SPIKE client configuration
type Config struct {
	// NexusURL is the SPIKE Nexus API endpoint
	// For POC: unused (local file storage)
	// For production: https://spike-nexus:8443/api/v1
	NexusURL string

	// StoragePath is where secrets are stored locally (POC only)
	StoragePath string
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	return &Config{
		NexusURL:    "http://localhost:8443", // Placeholder for POC
		StoragePath: filepath.Join(homeDir, ".spike", "secrets.json"),
	}
}

// Client is the SPIKE Nexus client
type Client struct {
	config  *Config
	secrets map[string]*Secret
	mu      sync.RWMutex
}

// NewClient creates a new SPIKE client
func NewClient(config *Config) *Client {
	return &Client{
		config:  config,
		secrets: make(map[string]*Secret),
	}
}

// Init initializes SPIKE Nexus for local development
// POC: Creates the local storage directory
// Production: Would make API call to bootstrap root policy
func (c *Client) Init() error {
	// Create storage directory
	dir := filepath.Dir(c.config.StoragePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Initialize empty secrets file
	c.mu.Lock()
	defer c.mu.Unlock()

	c.secrets = make(map[string]*Secret)

	if err := c.saveSecrets(); err != nil {
		return fmt.Errorf("failed to initialize secrets storage: %w", err)
	}

	return nil
}

// Put seeds a secret into SPIKE Nexus
// POC: Stores in local file
// Production: Would make mTLS POST to /api/v1/secrets
func (c *Client) Put(secret *Secret) error {
	// Validate inputs
	if secret.Ref == "" {
		return fmt.Errorf("secret ref cannot be empty")
	}
	if secret.Value == "" {
		return fmt.Errorf("secret value cannot be empty")
	}

	// Validate ref is hex characters only
	for _, ch := range secret.Ref {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return fmt.Errorf("secret ref must contain only hex characters [0-9a-f]")
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Load existing secrets
	if err := c.loadSecrets(); err != nil {
		return fmt.Errorf("failed to load secrets: %w", err)
	}

	// Store secret
	c.secrets[secret.Ref] = secret

	// Save to disk
	if err := c.saveSecrets(); err != nil {
		return fmt.Errorf("failed to save secrets: %w", err)
	}

	return nil
}

// Issue generates a SPIKE token for testing
// Format: $SPIKE{ref:<hex>,exp:<seconds>,scope:<scope>}
func (c *Client) Issue(ref string, exp int64, scope string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Load secrets
	if err := c.loadSecrets(); err != nil {
		return "", fmt.Errorf("failed to load secrets: %w", err)
	}

	// Verify secret exists
	if _, ok := c.secrets[ref]; !ok {
		return "", fmt.Errorf("secret not found: %s", ref)
	}

	// Build token
	token := fmt.Sprintf("$SPIKE{ref:%s", ref)

	if exp > 0 {
		token += fmt.Sprintf(",exp:%d", exp)
	}

	if scope != "" {
		token += fmt.Sprintf(",scope:%s", scope)
	}

	token += "}"

	return token, nil
}

// Get retrieves a secret by ref (for internal use and testing)
func (c *Client) Get(ref string) (*Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if err := c.loadSecrets(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	secret, ok := c.secrets[ref]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", ref)
	}

	return secret, nil
}

// loadSecrets loads secrets from disk (must be called with lock held)
func (c *Client) loadSecrets() error {
	// Check if file exists
	if _, err := os.Stat(c.config.StoragePath); os.IsNotExist(err) {
		// File doesn't exist, start with empty map
		c.secrets = make(map[string]*Secret)
		return nil
	}

	// Read file
	data, err := os.ReadFile(c.config.StoragePath)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}

	// Parse JSON
	var secrets map[string]*Secret
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("failed to parse secrets file: %w", err)
	}

	c.secrets = secrets
	return nil
}

// saveSecrets saves secrets to disk (must be called with lock held)
func (c *Client) saveSecrets() error {
	// Marshal to JSON
	data, err := json.MarshalIndent(c.secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	// Write to file
	if err := os.WriteFile(c.config.StoragePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}

	return nil
}

// RedeemToken simulates SPIKE Nexus token redemption (for POC integration testing)
// Production: Would verify mTLS, check ownership, and return secret
func (c *Client) RedeemToken(tokenStr string, spiffeID string) (*Secret, error) {
	// This is a POC helper function to simulate what SPIKE Nexus would do
	// Parse the token to extract ref using regex (same pattern as gateway)
	tokenRegex := regexp.MustCompile(`\$SPIKE\{ref:([a-f0-9]+)(?:,exp:(\d+))?(?:,scope:([\w.]+))?\}`)
	matches := tokenRegex.FindStringSubmatch(tokenStr)

	if matches == nil {
		return nil, fmt.Errorf("invalid token format")
	}

	ref := matches[1]
	var exp int64
	if matches[2] != "" {
		parsedExp, err := strconv.ParseInt(matches[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid token expiry %q: %w", matches[2], err)
		}
		exp = parsedExp
	}

	// Load secret
	c.mu.RLock()
	defer c.mu.RUnlock()

	if err := c.loadSecrets(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	secret, ok := c.secrets[ref]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", ref)
	}

	// Verify ownership (if SpiffeID was specified during put)
	if secret.SpiffeID != "" && secret.SpiffeID != spiffeID {
		return nil, fmt.Errorf("ownership mismatch: expected %s, got %s", secret.SpiffeID, spiffeID)
	}

	// Check expiry (if present)
	if exp > 0 {
		// In production, IssuedAt would come from the token metadata
		// For POC, we assume token was just issued
		issuedAt := time.Now().Unix()
		expiryTime := issuedAt + exp

		if time.Now().Unix() > expiryTime {
			return nil, fmt.Errorf("token expired")
		}
	}

	return secret, nil
}
