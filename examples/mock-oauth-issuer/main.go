// mock-oauth-issuer -- deterministic OAuth test helper for compose-based integration tests.
//
// Provides:
// - GET /jwks.json
// - POST /token
// - POST /introspect
//
// The service intentionally uses an in-memory opaque token store. It is designed for
// integration test determinism, not production-grade security hardening.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort       = "8088"
	defaultKeyID      = "mock-oauth-issuer-key"
	defaultTTL        = 3600
	opaqueTokenPrefix = "opaque-"
)

type issuer struct {
	kid         string
	signingKey  []byte
	issuer      string
	opaqueStore struct {
		mu      sync.RWMutex
		records map[string]opaqueRecord
	}
}

type opaqueRecord struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
}

type jwkResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	K   string `json:"k"`
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope,omitempty"`
	IssuedTokenType  string `json:"issued_token_type,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type tokenRequest struct {
	ClientID   string `json:"client_id"`
	Subject    string `json:"subject"`
	Scope      string `json:"scope"`
	Audience   string `json:"audience"`
	TokenType  string `json:"token_type"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type introspectResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	ExpiresIn int64  `json:"expires_in,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorDesc string `json:"error_description,omitempty"`
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform startup healthcheck and exit with status")
	flag.Parse()

	port := getEnv("MOCK_OAUTH_ISSUER_PORT", defaultPort)
	issuer := getEnv("MOCK_OAUTH_ISSUER", "http://"+defaultHost()+":"+port)
	kid := getEnv("MOCK_OAUTH_KEY_ID", defaultKeyID)

	instance := newIssuer(issuer, kid)

	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1:" + port + "/health")
		if err != nil {
			log.Printf("healthcheck failed: %v", err)
			os.Exit(1)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("healthcheck failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
			os.Exit(1)
		}
		os.Exit(0)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", instance.handleHealth)
	mux.HandleFunc("/jwks.json", instance.handleJWKS)
	mux.HandleFunc("/token", instance.handleToken)
	mux.HandleFunc("/introspect", instance.handleIntrospect)

	addr := ":" + port
	log.Printf("[mock-oauth-issuer] listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func newIssuer(issuerURL, kid string) *issuer {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Errorf("generate signing key: %w", err))
	}
	return &issuer{
		kid:        kid,
		signingKey: key,
		issuer:     issuerURL,
		opaqueStore: struct {
			mu      sync.RWMutex
			records map[string]opaqueRecord
		}{
			records: make(map[string]opaqueRecord),
		},
	}
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func defaultHost() string {
	host, ok := os.LookupEnv("HOSTNAME")
	if !ok || strings.TrimSpace(host) == "" {
		return "mock-oauth-issuer"
	}
	return host
}

func (s *issuer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "mock-oauth-issuer",
	})
}

func (s *issuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	key := jwkKey{
		Kty: "oct",
		Alg: "HS256",
		Use: "sig",
		Kid: s.kid,
		K:   base64.RawURLEncoding.EncodeToString(s.signingKey),
	}
	writeJSON(w, http.StatusOK, jwkResponse{Keys: []jwkKey{key}})
}

func (s *issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, tokenResponse{
			Error:            "invalid_method",
			ErrorDescription: "POST /token is required",
		})
		return
	}

	req, err := parseTokenRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, tokenResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = defaultTTL
	}
	clientID := req.ClientID
	if clientID == "" {
		clientID = "mock-client"
	}
	subject := req.Subject
	if subject == "" {
		subject = "demo-subject"
	}
	audience := req.Audience
	if audience == "" {
		audience = "demo-audience"
	}
	scope := strings.TrimSpace(req.Scope)

	tokenType := strings.ToLower(strings.TrimSpace(req.TokenType))
	if tokenType == "" {
		tokenType = "jwt"
	}
	now := time.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	expiresIn := int64(ttl)

	switch tokenType {
	case "opaque":
		tok, err := randomOpaque()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, tokenResponse{
				Error:            "server_error",
				ErrorDescription: "failed to mint opaque token",
			})
			return
		}
		s.saveOpaque(tok, opaqueRecord{
			Active:    true,
			Scope:     scope,
			ClientID:  clientID,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: expiresAt.Unix(),
		})
		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken:     tok,
			TokenType:       "Bearer",
			ExpiresIn:       expiresIn,
			Scope:           scope,
			IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		})
	default:
		tok, err := s.signJWT(subject, audience, scope, clientID, now, expiresAt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, tokenResponse{
				Error:            "server_error",
				ErrorDescription: "failed to mint jwt",
			})
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken: tok,
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
			Scope:       scope,
		})
	}
}

func (s *issuer) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, introspectResponse{
			Error:     "invalid_method",
			ErrorDesc: "POST /introspect is required",
		})
		return
	}
	token, err := parseTokenParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, introspectResponse{
			Error:     "invalid_request",
			ErrorDesc: err.Error(),
		})
		return
	}

	record, ok := s.lookupOpaque(token)
	if !ok {
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}
	if record.ExpiresAt <= time.Now().Unix() {
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}

	remaining := record.ExpiresAt - time.Now().Unix()
	if remaining < 0 {
		remaining = 0
	}

	writeJSON(w, http.StatusOK, introspectResponse{
		Active:    true,
		TokenType: "opaque",
		Sub:       record.Subject,
		Aud:       record.Audience,
		Scope:     record.Scope,
		ClientID:  record.ClientID,
		Exp:       record.ExpiresAt,
		ExpiresIn: remaining,
		Issuer:    s.issuer,
	})
}

func (s *issuer) signJWT(subject, audience, scope, clientID string, now time.Time, expiresAt time.Time) (string, error) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
		"kid": s.kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"iss":       s.issuer,
		"sub":       subject,
		"aud":       audience,
		"scope":     scope,
		"client_id": clientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       expiresAt.Unix(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signed := strings.TrimRight(base64.RawURLEncoding.EncodeToString(headerJSON), "=") + "." + strings.TrimRight(base64.RawURLEncoding.EncodeToString(payloadJSON), "=")
	mac := hmac.New(sha256.New, s.signingKey)
	_, err = mac.Write([]byte(signed))
	if err != nil {
		return "", err
	}
	signature := mac.Sum(nil)
	return signed + "." + strings.TrimRight(base64.RawURLEncoding.EncodeToString(signature), "="), nil
}

func (s *issuer) saveOpaque(token string, rec opaqueRecord) {
	s.opaqueStore.mu.Lock()
	defer s.opaqueStore.mu.Unlock()
	s.opaqueStore.records[token] = rec
}

func (s *issuer) lookupOpaque(token string) (opaqueRecord, bool) {
	s.opaqueStore.mu.RLock()
	defer s.opaqueStore.mu.RUnlock()
	rec, ok := s.opaqueStore.records[token]
	return rec, ok && rec.Active
}

func parseTokenParam(r *http.Request) (string, error) {
	if r.Method != http.MethodPost {
		return "", errors.New("invalid method")
	}

	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token != "" {
		return token, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	_ = r.Body.Close()
	if len(body) == 0 {
		return "", errors.New("missing token")
	}
	var bodyObj map[string]any
	if err := json.Unmarshal(body, &bodyObj); err == nil {
		if t := strings.TrimSpace(extractString(bodyObj, "token")); t != "" {
			return t, nil
		}
	}

	return "", errors.New("missing token")
}

func parseTokenRequest(r *http.Request) (tokenRequest, error) {
	var req tokenRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return req, fmt.Errorf("read request: %w", err)
	}
	defer func() { _ = r.Body.Close() }()

	if len(body) == 0 {
		return req, errors.New("missing request body")
	}
	if err := json.Unmarshal(body, &req); err == nil {
		return req, nil
	}
	return req, fmt.Errorf("invalid request body: expected JSON object")
}

func randomOpaque() (string, error) {
	raw := make([]byte, 12)
	_, err := rand.Read(raw)
	if err != nil {
		return "", err
	}
	return opaqueTokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func extractString(m map[string]any, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	asString, ok := raw.(string)
	if !ok {
		return ""
	}
	return asString
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(value)
}
