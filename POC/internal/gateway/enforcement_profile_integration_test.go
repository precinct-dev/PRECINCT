package gateway

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

func writeSignedStrictToolRegistryFixture(t *testing.T) (configPath, publicKeyPath string) {
	t.Helper()

	projectRoot := testutil.ProjectRoot()
	sourceRegistry := filepath.Join(projectRoot, "config", "tool-registry.yaml")
	registryBytes, err := os.ReadFile(sourceRegistry)
	if err != nil {
		t.Fatalf("read source tool registry: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate attestation key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal attestation public key: %v", err)
	}

	fixtureDir := t.TempDir()
	configPath = filepath.Join(fixtureDir, "tool-registry.yaml")
	if err := os.WriteFile(configPath, registryBytes, 0644); err != nil {
		t.Fatalf("write signed registry fixture: %v", err)
	}
	sig := ed25519.Sign(priv, registryBytes)
	if err := os.WriteFile(configPath+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0644); err != nil {
		t.Fatalf("write registry signature: %v", err)
	}

	publicKeyPath = filepath.Join(fixtureDir, "attestation-ed25519.pub")
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		t.Fatalf("write attestation public key: %v", err)
	}

	return configPath, publicKeyPath
}

func setStrictAttestationFixtureEnv(t *testing.T) {
	t.Helper()

	projectRoot := testutil.ProjectRoot()
	toolRegistryPath, registryAttestationPubKey := writeSignedStrictToolRegistryFixture(t)
	projectAttestationPubKey := filepath.Join(projectRoot, "config", "attestation-ed25519.pub")
	modelCatalogPath := filepath.Join(projectRoot, "config", "model-provider-catalog.v2.yaml")
	guardArtifactPath := filepath.Join(projectRoot, "config", "guard-artifact.bin")
	destinationsPath := filepath.Join(projectRoot, "config", "destinations.yaml")
	riskThresholdsPath := filepath.Join(projectRoot, "config", "risk_thresholds.yaml")

	guardBytes, err := os.ReadFile(guardArtifactPath)
	if err != nil {
		t.Fatalf("read guard artifact fixture: %v", err)
	}
	guardSum := sha256.Sum256(guardBytes)
	guardDigest := hex.EncodeToString(guardSum[:])

	t.Setenv("TOOL_REGISTRY_CONFIG_PATH", toolRegistryPath)
	t.Setenv("TOOL_REGISTRY_PUBLIC_KEY", registryAttestationPubKey)
	t.Setenv("OPA_POLICY_PUBLIC_KEY", registryAttestationPubKey)
	t.Setenv("MODEL_PROVIDER_CATALOG_PATH", modelCatalogPath)
	t.Setenv("MODEL_PROVIDER_CATALOG_PUBLIC_KEY", projectAttestationPubKey)
	t.Setenv("GUARD_ARTIFACT_PATH", guardArtifactPath)
	t.Setenv("GUARD_ARTIFACT_SHA256", guardDigest)
	t.Setenv("GUARD_ARTIFACT_SIGNATURE_PATH", guardArtifactPath+".sig")
	t.Setenv("GUARD_ARTIFACT_PUBLIC_KEY", projectAttestationPubKey)
	t.Setenv("DESTINATIONS_CONFIG_PATH", destinationsPath)
	t.Setenv("RISK_THRESHOLDS_PATH", riskThresholdsPath)
	t.Setenv("ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS", "spiffe://poc.local/admin/security")
}

func TestEnforcementProfile_StrictStartupFailsFastWithoutApprovalSigningKey(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "")

	cfg := ConfigFromEnv()
	if cfg.ApprovalSigningKey != "" {
		t.Fatalf("expected empty approval signing key from env, got %q", cfg.ApprovalSigningKey)
	}

	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when APPROVAL_SIGNING_KEY is missing")
	}
	if !strings.Contains(err.Error(), "approval_signing_key must be set") {
		t.Fatalf("expected missing approval signing key error, got: %v", err)
	}
}

func TestEnforcementProfile_StrictStartupPassesWithStrongApprovalSigningKey(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	if cfg.ApprovalSigningKey == "" {
		t.Fatal("expected APPROVAL_SIGNING_KEY to be loaded from env")
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("expected strict startup success with strong APPROVAL_SIGNING_KEY: %v", err)
	}
	defer func() {
		_ = gw.Close()
	}()
}

func TestEnforcementProfile_StrictStartupFailsWithoutAdminAllowlist(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS", "")
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	if len(cfg.AdminAuthzAllowedSPIFFEIDs) != 0 {
		t.Fatalf("expected empty admin authz allowlist from env, got %v", cfg.AdminAuthzAllowedSPIFFEIDs)
	}

	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS is missing")
	}
	if !strings.Contains(err.Error(), "admin_authz_allowed_spiffe_ids must be set") {
		t.Fatalf("expected missing admin authz allowlist error, got: %v", err)
	}
}

func TestEnforcementProfile_StrictProdDeniesDevResearcherAdminIdentity(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS", "spiffe://poc.local/admin/security")
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("new strict gateway: %v", err)
	}
	defer func() { _ = gw.Close() }()

	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	gw.sessionStore = middleware.NewInMemoryStore()
	gw.sessionContext = middleware.NewSessionContext(gw.sessionStore)

	req := httptest.NewRequest(http.MethodGet, "/admin/circuit-breakers", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			createStrictTestClientCert(t, "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"),
		},
	}
	rec := httptest.NewRecorder()

	gw.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for dev researcher identity in strict prod config, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, rec.Body.String())
	}
	if got, _ := body["code"].(string); got != middleware.ErrAuthzPolicyDenied {
		t.Fatalf("expected code=%q, got %q body=%v", middleware.ErrAuthzPolicyDenied, got, body)
	}
}

func TestEnforcementProfile_StrictStartupFailsWithUnsignedToolRegistry(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tmpRegistryPath, _ := writeSignedStrictToolRegistryFixture(t)
	if err := os.Remove(tmpRegistryPath + ".sig"); err != nil {
		t.Fatalf("remove temporary tool registry signature: %v", err)
	}

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("TOOL_REGISTRY_CONFIG_PATH", tmpRegistryPath)
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when tool registry signature is missing")
	}
	if !strings.Contains(err.Error(), "strict tool registry attestation verification failed") {
		t.Fatalf("expected strict registry attestation failure, got: %v", err)
	}
}

func TestEnforcementProfile_StrictStartupFailsWhenDestinationAllowlistFallbackWouldBeUsed(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("DESTINATIONS_CONFIG_PATH", filepath.Join(t.TempDir(), "missing-destinations.yaml"))
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when destination allowlist fallback would be required")
	}
	if !strings.Contains(err.Error(), "strict profile forbids fallback for destinations_config_path") {
		t.Fatalf("expected strict destinations fallback error, got: %v", err)
	}
}

func TestEnforcementProfile_StrictStartupFailsWhenRiskThresholdFallbackWouldBeUsed(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("RISK_THRESHOLDS_PATH", filepath.Join(t.TempDir(), "missing-risk-thresholds.yaml"))
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when risk threshold fallback would be required")
	}
	if !strings.Contains(err.Error(), "strict profile forbids fallback for risk_thresholds_path") {
		t.Fatalf("expected strict risk fallback error, got: %v", err)
	}
}

func TestEnforcementProfile_DevAllowsFallbackToDefaults(t *testing.T) {
	cfg := &Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           filepath.Join(t.TempDir(), "audit.jsonl"),
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		EnforcementProfile:     enforcementProfileDev,
		DestinationsConfigPath: filepath.Join(t.TempDir(), "missing-destinations.yaml"),
		RiskThresholdsPath:     filepath.Join(t.TempDir(), "missing-risk-thresholds.yaml"),
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("expected dev profile startup to allow fallback defaults, got: %v", err)
	}
	defer func() { _ = gw.Close() }()
}

func createStrictTestClientCert(t *testing.T, rawSPIFFEID string) *x509.Certificate {
	t.Helper()

	spiffeURI, err := url.Parse(rawSPIFFEID)
	if err != nil {
		t.Fatalf("parse SPIFFE ID: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "strict-admin-authz-test-client",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		URIs:      []*url.URL{spiffeURI},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}
