// OC-xkkc: Token exchange endpoint for external credentials.
//
// POST /v1/auth/token-exchange allows third-party tools (without SPIFFE sidecars)
// to exchange an external credential for a short-lived JWT bound to a SPIFFE identity.
// The JWT is signed with HMAC-SHA256 and accepted by SPIFFEAuth middleware for
// subsequent MCP requests.
package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	tokenExchangeIssuer   = "precinct-gateway"
	tokenExchangeAudience = "precinct-gateway"

	defaultTokenExchangeTTL = 15 * time.Minute
	maxTokenExchangeTTL     = 1 * time.Hour

	// Environment variable for the HMAC signing key.
	tokenExchangeSigningKeyEnv = "TOKEN_EXCHANGE_SIGNING_KEY"
)

// TokenExchangeConfig holds the configuration for the token exchange endpoint.
type TokenExchangeConfig struct {
	Credentials []TokenExchangeCredential `yaml:"credentials"`
	DefaultTTL  string                    `yaml:"default_ttl"`
	MaxTTL      string                    `yaml:"max_ttl"`

	// Parsed durations (populated by LoadTokenExchangeConfig).
	defaultTTL time.Duration
	maxTTL     time.Duration

	// signingKey is loaded from TOKEN_EXCHANGE_SIGNING_KEY env var.
	signingKey []byte
}

// TokenExchangeCredential maps an external credential to a SPIFFE identity.
type TokenExchangeCredential struct {
	CredentialType string `yaml:"credential_type"`
	CredentialHash string `yaml:"credential_hash"`
	SPIFFEID       string `yaml:"spiffe_id"`
}

// TokenExchangeRequest is the JSON body for POST /v1/auth/token-exchange.
type TokenExchangeRequest struct {
	CredentialType string `json:"credential_type"`
	Credential     string `json:"credential"`
	RequestedTTL   string `json:"requested_ttl,omitempty"`
}

// TokenExchangeResponse is the JSON response from POST /v1/auth/token-exchange.
type TokenExchangeResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	TokenType string `json:"token_type"`
}

// TokenExchangeClaims are the JWT claims embedded in exchange tokens.
type TokenExchangeClaims struct {
	Jti                string `json:"jti"`
	Sub                string `json:"sub"`
	Iss                string `json:"iss"`
	Aud                string `json:"aud"`
	Exp                int64  `json:"exp"`
	Iat                int64  `json:"iat"`
	PrecinctAuthMethod string `json:"precinct_auth_method"`
}

// LoadTokenExchangeConfig reads the token exchange config from a YAML file
// and the signing key from the environment.
func LoadTokenExchangeConfig(path string) (*TokenExchangeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token exchange config: %w", err)
	}

	var cfg TokenExchangeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse token exchange config: %w", err)
	}

	// Parse TTL durations.
	if cfg.DefaultTTL != "" {
		cfg.defaultTTL, err = time.ParseDuration(cfg.DefaultTTL)
		if err != nil {
			return nil, fmt.Errorf("parse default_ttl %q: %w", cfg.DefaultTTL, err)
		}
	} else {
		cfg.defaultTTL = defaultTokenExchangeTTL
	}

	if cfg.MaxTTL != "" {
		cfg.maxTTL, err = time.ParseDuration(cfg.MaxTTL)
		if err != nil {
			return nil, fmt.Errorf("parse max_ttl %q: %w", cfg.MaxTTL, err)
		}
	} else {
		cfg.maxTTL = maxTokenExchangeTTL
	}

	// Validate that all credentials have bcrypt hashes.
	for i, c := range cfg.Credentials {
		if c.CredentialHash == "" {
			return nil, fmt.Errorf("credential[%d]: credential_hash is required", i)
		}
		if c.CredentialType == "" {
			return nil, fmt.Errorf("credential[%d]: credential_type is required", i)
		}
		if c.SPIFFEID == "" {
			return nil, fmt.Errorf("credential[%d]: spiffe_id is required", i)
		}
	}

	// Load signing key from environment.
	signingKeyRaw := os.Getenv(tokenExchangeSigningKeyEnv)
	if signingKeyRaw == "" {
		return nil, fmt.Errorf("environment variable %s is required", tokenExchangeSigningKeyEnv)
	}
	cfg.signingKey = []byte(signingKeyRaw)

	return &cfg, nil
}

// LoadTokenExchangeConfigForTest creates a config from values without file or env.
// Used only by tests.
func LoadTokenExchangeConfigForTest(credentials []TokenExchangeCredential, signingKey string, defaultTTL, maxTTL time.Duration) *TokenExchangeConfig {
	return &TokenExchangeConfig{
		Credentials: credentials,
		defaultTTL:  defaultTTL,
		maxTTL:      maxTTL,
		signingKey:  []byte(signingKey),
	}
}

// LookupCredential resolves a credential to a SPIFFE ID by comparing the
// plaintext credential against bcrypt hashes in the configuration.
// Returns the SPIFFE ID and true if found, empty string and false otherwise.
func (c *TokenExchangeConfig) LookupCredential(credType, credential string) (string, bool) {
	for _, entry := range c.Credentials {
		if entry.CredentialType != credType {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(entry.CredentialHash), []byte(credential)) == nil {
			return entry.SPIFFEID, true
		}
	}
	return "", false
}

// ResolveTTL resolves the requested TTL against defaults and maximums.
func (c *TokenExchangeConfig) ResolveTTL(requested string) (time.Duration, error) {
	if requested == "" {
		return c.defaultTTL, nil
	}

	ttl, err := time.ParseDuration(requested)
	if err != nil {
		return 0, fmt.Errorf("invalid requested_ttl %q: %w", requested, err)
	}

	if ttl <= 0 {
		return 0, fmt.Errorf("requested_ttl must be positive, got %s", ttl)
	}

	if ttl > c.maxTTL {
		return c.maxTTL, nil // Silently clamp to max
	}

	return ttl, nil
}

// MintToken creates a signed JWT for the given SPIFFE ID and TTL.
func (c *TokenExchangeConfig) MintToken(spiffeID string, ttl time.Duration) (string, error) {
	return mintExchangeToken(spiffeID, ttl, c.signingKey, time.Now)
}

// mintExchangeToken is the internal minting function with injectable time.
func mintExchangeToken(spiffeID string, ttl time.Duration, signingKey []byte, now func() time.Time) (string, error) {
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	t := now()
	claims := TokenExchangeClaims{
		Jti:                jti,
		Sub:                spiffeID,
		Iss:                tokenExchangeIssuer,
		Aud:                tokenExchangeAudience,
		Exp:                t.Add(ttl).Unix(),
		Iat:                t.Unix(),
		PrecinctAuthMethod: "token_exchange",
	}

	return signJWTHS256(claims, signingKey)
}

// generateJTI produces a cryptographically random 16-byte hex token ID.
func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateExchangeToken validates a JWT that was issued by the token exchange
// endpoint. Returns the claims if valid, or an error if invalid.
func ValidateExchangeToken(tokenStr string, signingKey []byte) (*TokenExchangeClaims, error) {
	return validateExchangeToken(tokenStr, signingKey, time.Now)
}

// validateExchangeToken is the internal validation function with injectable time.
func validateExchangeToken(tokenStr string, signingKey []byte, now func() time.Time) (*TokenExchangeClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Verify header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported algorithm %q, expected HS256", header.Alg)
	}
	if header.Typ != "JWT" {
		return nil, fmt.Errorf("unsupported type %q, expected JWT", header.Typ)
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	expectedSig := computeHS256(signingInput, signingKey)
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("invalid JWT signature")
	}

	// Decode and validate claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims TokenExchangeClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	// Validate issuer.
	if claims.Iss != tokenExchangeIssuer {
		return nil, fmt.Errorf("invalid issuer %q, expected %q", claims.Iss, tokenExchangeIssuer)
	}

	// Validate audience.
	if claims.Aud != tokenExchangeAudience {
		return nil, fmt.Errorf("invalid audience %q, expected %q", claims.Aud, tokenExchangeAudience)
	}

	// Validate auth method marker.
	if claims.PrecinctAuthMethod != "token_exchange" {
		return nil, fmt.Errorf("invalid precinct_auth_method %q", claims.PrecinctAuthMethod)
	}

	// Check expiry.
	if now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired at %d", claims.Exp)
	}

	return &claims, nil
}

// jwtHeader is the minimal JWT header for HMAC-SHA256.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// signJWTHS256 creates a JWT signed with HMAC-SHA256.
func signJWTHS256(claims TokenExchangeClaims, signingKey []byte) (string, error) {
	header := jwtHeader{Alg: "HS256", Typ: "JWT"}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := computeHS256(signingInput, signingKey)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// computeHS256 computes HMAC-SHA256 of the input with the given key.
func computeHS256(input string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

// tokenExchangeHandler returns the HTTP handler for POST /v1/auth/token-exchange.
func tokenExchangeHandler(cfg *TokenExchangeConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeTokenExchangeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
			return
		}

		if r.Body == nil {
			writeTokenExchangeError(w, http.StatusBadRequest, "missing_body", "Request body is required")
			return
		}

		var req TokenExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeTokenExchangeError(w, http.StatusBadRequest, "invalid_body", "Invalid JSON request body")
			return
		}

		if req.CredentialType == "" || req.Credential == "" {
			writeTokenExchangeError(w, http.StatusBadRequest, "missing_fields", "credential_type and credential are required")
			return
		}

		// Look up credential.
		spiffeID, ok := cfg.LookupCredential(req.CredentialType, req.Credential)
		if !ok {
			slog.Warn("token exchange: unknown credential",
				"credential_type", req.CredentialType,
			)
			writeTokenExchangeError(w, http.StatusUnauthorized, middleware.ErrAuthCredentialRejected, "Unknown or invalid credential")
			return
		}

		// Resolve TTL.
		ttl, err := cfg.ResolveTTL(req.RequestedTTL)
		if err != nil {
			writeTokenExchangeError(w, http.StatusBadRequest, "invalid_ttl", err.Error())
			return
		}

		// Mint token.
		token, err := cfg.MintToken(spiffeID, ttl)
		if err != nil {
			slog.Error("token exchange: failed to mint token", "error", err)
			writeTokenExchangeError(w, http.StatusInternalServerError, "mint_failed", "Failed to issue token")
			return
		}

		resp := TokenExchangeResponse{
			Token:     token,
			ExpiresIn: int(ttl.Seconds()),
			TokenType: "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// tokenExchangeErrorResponse is the error envelope for token exchange errors.
type tokenExchangeErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeTokenExchangeError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(tokenExchangeErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}
