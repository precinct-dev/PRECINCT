package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
	"github.com/precinct-dev/PRECINCT/POC/internal/testutil"
	"github.com/xeipuuv/gojsonschema"
)

const (
	FixtureSchemaVersion = "conformance.fixture.v1"
	ReportSchemaVersion  = "conformance.report.v1"
	HarnessVersion       = "v2.4"

	defaultGatewayURL = "http://localhost:9090"
	defaultSPIFFEID   = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
)

var requiredSuites = []string{"contracts", "connectors", "ruleops", "profiles"}

type Fixture struct {
	SchemaVersion string         `json:"schema_version"`
	Suite         string         `json:"suite"`
	Name          string         `json:"name"`
	CaseID        string         `json:"case_id"`
	Expect        string         `json:"expect"`
	Params        map[string]any `json:"params,omitempty"`
}

type CheckResult struct {
	Name     string `json:"name"`
	CaseID   string `json:"case_id"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type SuiteResult struct {
	Suite  string        `json:"suite"`
	Status string        `json:"status"`
	Checks []CheckResult `json:"checks"`
}

type Summary struct {
	TotalSuites int `json:"total_suites"`
	SuitePass   int `json:"suite_pass"`
	SuiteFail   int `json:"suite_fail"`
	TotalChecks int `json:"total_checks"`
	CheckPass   int `json:"check_pass"`
	CheckFail   int `json:"check_fail"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Harness       string        `json:"harness"`
	GeneratedAt   string        `json:"generated_at"`
	Suites        []SuiteResult `json:"suites"`
	Summary       Summary       `json:"summary"`
}

type RunOptions struct {
	FixtureDir string
	GatewayURL string
	Live       bool
	SPIFFEID   string
	Now        func() time.Time
}

func DefaultRunOptions() RunOptions {
	return RunOptions{
		FixtureDir: DefaultFixtureDir(),
		GatewayURL: defaultGatewayURL,
		SPIFFEID:   defaultSPIFFEID,
		Now:        time.Now,
	}
}

func DefaultFixtureDir() string {
	return filepath.Join(moduleRoot(), "tests", "conformance", "fixtures")
}

func DefaultReportSchemaPath() string {
	return filepath.Join(moduleRoot(), "tests", "conformance", "report.schema.v1.json")
}

func DefaultReportOutputPath() string {
	return filepath.Join(moduleRoot(), "build", "conformance", "conformance-report.json")
}

func LoadFixtures(dir string) ([]Fixture, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("fixture directory is required")
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob fixtures: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no fixture files found in %s", dir)
	}

	fixtures := make([]Fixture, 0, len(entries))
	for _, path := range entries {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", path, err)
		}
		var fx Fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			return nil, fmt.Errorf("parse fixture %s: %w", path, err)
		}
		if strings.TrimSpace(fx.SchemaVersion) != FixtureSchemaVersion {
			return nil, fmt.Errorf("fixture %s schema_version=%q, expected %q", path, fx.SchemaVersion, FixtureSchemaVersion)
		}
		fx.Suite = strings.ToLower(strings.TrimSpace(fx.Suite))
		fx.Expect = strings.ToLower(strings.TrimSpace(fx.Expect))
		if fx.Expect != "pass" && fx.Expect != "fail" {
			return nil, fmt.Errorf("fixture %s expect must be pass|fail, got %q", path, fx.Expect)
		}
		if strings.TrimSpace(fx.Suite) == "" || strings.TrimSpace(fx.CaseID) == "" || strings.TrimSpace(fx.Name) == "" {
			return nil, fmt.Errorf("fixture %s missing suite/name/case_id", path)
		}
		fixtures = append(fixtures, fx)
	}

	sort.Slice(fixtures, func(i, j int) bool {
		if fixtures[i].Suite == fixtures[j].Suite {
			if fixtures[i].Name == fixtures[j].Name {
				return fixtures[i].CaseID < fixtures[j].CaseID
			}
			return fixtures[i].Name < fixtures[j].Name
		}
		return fixtures[i].Suite < fixtures[j].Suite
	})
	return fixtures, nil
}

func Run(opts RunOptions) (Report, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if strings.TrimSpace(opts.SPIFFEID) == "" {
		opts.SPIFFEID = defaultSPIFFEID
	}
	if strings.TrimSpace(opts.GatewayURL) == "" {
		opts.GatewayURL = defaultGatewayURL
	}
	if strings.TrimSpace(opts.FixtureDir) == "" {
		opts.FixtureDir = DefaultFixtureDir()
	}

	fixtures, err := LoadFixtures(opts.FixtureDir)
	if err != nil {
		return Report{}, err
	}
	if opts.Live {
		if err := checkGatewayReachable(opts.GatewayURL); err != nil {
			return Report{}, err
		}
	}

	checksBySuite := map[string][]CheckResult{}
	for _, suite := range requiredSuites {
		checksBySuite[suite] = []CheckResult{}
	}

	for _, fx := range fixtures {
		actual, message, err := EvaluateFixture(fx, opts)
		if err != nil {
			actual = "fail"
			if message == "" {
				message = err.Error()
			} else {
				message = fmt.Sprintf("%s: %v", message, err)
			}
		}
		if actual != "pass" && actual != "fail" {
			actual = "fail"
			if message == "" {
				message = "fixture evaluator returned invalid actual outcome"
			}
		}

		checkStatus := "pass"
		if actual != fx.Expect {
			checkStatus = "fail"
		}
		checksBySuite[fx.Suite] = append(checksBySuite[fx.Suite], CheckResult{
			Name:     fx.Name,
			CaseID:   fx.CaseID,
			Expected: fx.Expect,
			Actual:   actual,
			Status:   checkStatus,
			Message:  message,
		})
	}

	suiteKeys := append([]string{}, requiredSuites...)
	sort.Strings(suiteKeys)
	suites := make([]SuiteResult, 0, len(suiteKeys))
	summary := Summary{}

	for _, suite := range suiteKeys {
		checks := checksBySuite[suite]
		suiteStatus := "pass"
		for _, c := range checks {
			summary.TotalChecks++
			if c.Status == "pass" {
				summary.CheckPass++
			} else {
				summary.CheckFail++
				suiteStatus = "fail"
			}
		}
		if len(checks) == 0 {
			suiteStatus = "fail"
			checks = append(checks, CheckResult{
				Name:     "missing-fixtures",
				CaseID:   "missing-fixtures",
				Expected: "pass",
				Actual:   "fail",
				Status:   "fail",
				Message:  "suite has no fixture coverage",
			})
			summary.TotalChecks++
			summary.CheckFail++
		}

		hasExpectedPass := false
		hasExpectedFail := false
		for _, c := range checks {
			if c.Expected == "pass" {
				hasExpectedPass = true
			}
			if c.Expected == "fail" {
				hasExpectedFail = true
			}
		}
		if !hasExpectedPass || !hasExpectedFail {
			suiteStatus = "fail"
			checks = append(checks, CheckResult{
				Name:     "fixture-balance",
				CaseID:   "fixture-balance",
				Expected: "pass",
				Actual:   "fail",
				Status:   "fail",
				Message:  "suite must include at least one pass and one fail fixture",
			})
			summary.TotalChecks++
			summary.CheckFail++
		}

		suites = append(suites, SuiteResult{Suite: suite, Status: suiteStatus, Checks: checks})
		summary.TotalSuites++
		if suiteStatus == "pass" {
			summary.SuitePass++
		} else {
			summary.SuiteFail++
		}
	}

	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Harness:       HarnessVersion,
		GeneratedAt:   opts.Now().UTC().Format(time.RFC3339),
		Suites:        suites,
		Summary:       summary,
	}
	return report, nil
}

func EvaluateFixture(fx Fixture, opts RunOptions) (actual string, message string, err error) {
	switch fx.Suite {
	case "contracts":
		return evalContractsFixture(fx)
	case "connectors":
		return evalConnectorsFixture(fx, opts)
	case "ruleops":
		return evalRuleOpsFixture(fx, opts)
	case "profiles":
		return evalProfilesFixture(fx)
	default:
		return "fail", "", fmt.Errorf("unsupported suite %q", fx.Suite)
	}
}

func ValidateReportSchema(report Report, schemaPath string) error {
	reportBytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
	documentLoader := gojsonschema.NewBytesLoader(reportBytes)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("validate report schema: %w", err)
	}
	if result.Valid() {
		return nil
	}
	errs := make([]string, 0, len(result.Errors()))
	for _, verr := range result.Errors() {
		errs = append(errs, verr.String())
	}
	sort.Strings(errs)
	return fmt.Errorf("report schema violations: %s", strings.Join(errs, "; "))
}

func WriteReport(path string, report Report) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("report output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func evalContractsFixture(fx Fixture) (string, string, error) {
	switch fx.CaseID {
	case "artifact_exists":
		path := strings.TrimSpace(getParamString(fx.Params, "path"))
		if path == "" {
			return "fail", "", errors.New("contracts.artifact_exists requires params.path")
		}
		fullPath := path
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(moduleRoot(), fullPath)
		}
		info, err := os.Stat(fullPath)
		if err != nil {
			return "fail", fmt.Sprintf("artifact missing at %s", path), nil
		}
		if info.IsDir() {
			return "fail", fmt.Sprintf("artifact path is a directory: %s", path), nil
		}
		if info.Size() == 0 {
			return "fail", fmt.Sprintf("artifact is empty: %s", path), nil
		}
		return "pass", fmt.Sprintf("artifact present: %s", path), nil
	default:
		return "fail", "", fmt.Errorf("unsupported contracts case_id %q", fx.CaseID)
	}
}

func evalConnectorsFixture(fx Fixture, opts RunOptions) (string, string, error) {
	baseURL, cleanup, err := resolveGatewayURL(opts)
	if err != nil {
		return "fail", "", err
	}
	defer cleanup()

	switch fx.CaseID {
	case "lifecycle_success":
		connectorID := fmt.Sprintf("conformance-connector-%d", time.Now().UnixNano())
		expectedSig, err := registerConnector(baseURL, connectorID, opts.SPIFFEID, "", opts.Live)
		if err != nil {
			return "fail", err.Error(), nil
		}
		_, err = registerConnector(baseURL, connectorID, opts.SPIFFEID, expectedSig, opts.Live)
		if err != nil {
			return "fail", err.Error(), nil
		}
		for _, op := range []string{"validate", "approve", "activate"} {
			code, body, err := postJSONWithRetry(baseURL, "/v1/connectors/"+op, opts.SPIFFEID, map[string]any{"connector_id": connectorID}, opts.Live)
			if err != nil {
				return "fail", fmt.Sprintf("connector %s failed: %v", op, err), nil
			}
			if code != http.StatusOK {
				return "fail", fmt.Sprintf("connector %s expected 200, got %d body=%v", op, code, body), nil
			}
		}
		return "pass", "connector lifecycle completed (register->validate->approve->activate)", nil
	case "invalid_transition_denied":
		connectorID := fmt.Sprintf("conformance-connector-invalid-%d", time.Now().UnixNano())
		expectedSig, err := registerConnector(baseURL, connectorID, opts.SPIFFEID, "", opts.Live)
		if err != nil {
			return "fail", err.Error(), nil
		}
		_, err = registerConnector(baseURL, connectorID, opts.SPIFFEID, expectedSig, opts.Live)
		if err != nil {
			return "fail", err.Error(), nil
		}
		code, body, err := postJSONWithRetry(baseURL, "/v1/connectors/activate", opts.SPIFFEID, map[string]any{"connector_id": connectorID}, opts.Live)
		if err != nil {
			return "fail", fmt.Sprintf("connector invalid transition request failed: %v", err), nil
		}
		if code >= 400 {
			return "fail", fmt.Sprintf("invalid transition denied as expected (code=%d body=%v)", code, body), nil
		}
		return "pass", fmt.Sprintf("invalid transition unexpectedly allowed (code=%d)", code), nil
	default:
		return "fail", "", fmt.Errorf("unsupported connectors case_id %q", fx.CaseID)
	}
}

func evalRuleOpsFixture(fx Fixture, opts RunOptions) (string, string, error) {
	baseURL, cleanup, err := resolveGatewayURL(opts)
	if err != nil {
		return "fail", "", err
	}
	defer cleanup()

	switch fx.CaseID {
	case "signed_promotion_success":
		rulesetID := fmt.Sprintf("conformance-ruleops-%d", time.Now().UnixNano())
		expectedSig, msg, ok := createValidateApproveRuleSet(baseURL, opts.SPIFFEID, rulesetID, opts.Live)
		if !ok {
			return "fail", msg, nil
		}

		signCode, signBody, err := postJSONWithRetry(baseURL, "/admin/dlp/rulesets/sign", opts.SPIFFEID, map[string]any{
			"ruleset_id": rulesetID,
			"signature":  expectedSig,
		}, opts.Live)
		if err != nil {
			return "fail", fmt.Sprintf("sign failed: %v", err), nil
		}
		if signCode != http.StatusOK {
			return "fail", fmt.Sprintf("sign expected 200, got %d body=%v", signCode, signBody), nil
		}

		promoteCode, promoteBody, err := postJSONWithRetry(baseURL, "/admin/dlp/rulesets/promote", opts.SPIFFEID, map[string]any{
			"ruleset_id": rulesetID,
			"mode":       "active",
		}, opts.Live)
		if err != nil {
			return "fail", fmt.Sprintf("promote failed: %v", err), nil
		}
		if promoteCode != http.StatusOK {
			return "fail", fmt.Sprintf("promote expected 200, got %d body=%v", promoteCode, promoteBody), nil
		}
		return "pass", "signed ruleset promotion succeeded", nil
	case "unsigned_promotion_denied":
		rulesetID := fmt.Sprintf("conformance-ruleops-unsigned-%d", time.Now().UnixNano())
		if _, msg, ok := createValidateApproveRuleSet(baseURL, opts.SPIFFEID, rulesetID, opts.Live); !ok {
			return "fail", msg, nil
		}
		code, body, err := postJSONWithRetry(baseURL, "/admin/dlp/rulesets/promote", opts.SPIFFEID, map[string]any{
			"ruleset_id": rulesetID,
			"mode":       "active",
		}, opts.Live)
		if err != nil {
			return "fail", fmt.Sprintf("unsigned promote failed: %v", err), nil
		}
		if code >= 400 {
			return "fail", fmt.Sprintf("unsigned promotion denied as expected (code=%d body=%v)", code, body), nil
		}
		return "pass", fmt.Sprintf("unsigned promotion unexpectedly allowed (code=%d)", code), nil
	default:
		return "fail", "", fmt.Errorf("unsupported ruleops case_id %q", fx.CaseID)
	}
}

func evalProfilesFixture(fx Fixture) (string, string, error) {
	switch fx.CaseID {
	case "dev_profile_boot":
		cfg, cleanup, err := newProfileGatewayConfig("dev")
		if err != nil {
			return "fail", "", err
		}
		defer cleanup()
		cfg.MCPTransportMode = "mcp"
		cfg.EnforcementProfile = "dev"
		gw, err := gateway.New(cfg)
		if err != nil {
			return "fail", fmt.Sprintf("dev profile boot failed: %v", err), nil
		}
		_ = gw
		return "pass", "dev profile booted successfully", nil
	case "prod_profile_requires_mediation":
		cfg, cleanup, err := newProfileGatewayConfig("prod")
		if err != nil {
			return "fail", "", err
		}
		defer cleanup()
		cfg.MCPTransportMode = "mcp"
		cfg.EnforcementProfile = "prod_standard"
		cfg.EnforceModelMediationGate = false
		cfg.EnforceHIPAAPromptSafetyGate = true
		cfg.EnforcementControlOverrides = true
		_, err = gateway.New(cfg)
		if err != nil {
			return "fail", "prod profile startup gate denied misconfigured mediation control", nil
		}
		return "pass", "prod profile boot unexpectedly allowed missing mediation control", nil
	case "hipaa_profile_prompt_safety_reason_codes":
		cfg, cleanup, err := newProfileGatewayConfig("dev")
		if err != nil {
			return "fail", "", err
		}
		defer cleanup()
		cfg.MCPTransportMode = "mcp"
		cfg.EnforcementProfile = "dev"
		cfg.EnforceModelMediationGate = true
		cfg.EnforceHIPAAPromptSafetyGate = true
		cfg.EnforcementControlOverrides = true
		gw, err := gateway.New(cfg)
		if err != nil {
			return "fail", fmt.Sprintf("hipaa profile boot failed: %v", err), nil
		}
		srv := httptest.NewServer(gw.Handler())
		defer srv.Close()

		buildPayload := func(runID string, attrs map[string]any) map[string]any {
			return map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      "conformance-hipaa-profile-session",
					"tenant":          "tenant-a",
					"actor_spiffe_id": defaultSPIFFEID,
					"plane":           "model",
				},
				"policy": map[string]any{
					"envelope": map[string]any{
						"run_id":          runID,
						"session_id":      "conformance-hipaa-profile-session",
						"tenant":          "tenant-a",
						"actor_spiffe_id": defaultSPIFFEID,
						"plane":           "model",
					},
					"action":     "model.call",
					"resource":   "model/inference",
					"attributes": attrs,
				},
			}
		}

		tokenizeAttrs := map[string]any{
			"provider":           "openai",
			"model":              "gpt-4o",
			"compliance_profile": "hipaa",
			"prompt_action":      "tokenize",
			"prompt_has_phi":     true,
			"prompt":             "Patient record contains SSN 123-45-6789",
		}
		tokenizeCode, tokenizeBody, err := postJSON(srv.URL, "/v1/model/call", defaultSPIFFEID, buildPayload("conformance-hipaa-tokenize", tokenizeAttrs))
		if err != nil {
			return "fail", fmt.Sprintf("hipaa tokenize request failed: %v", err), nil
		}
		tokenizeReason, _ := tokenizeBody["reason_code"].(string)
		tokenizeDecision, _ := tokenizeBody["decision"].(string)
		if tokenizeCode != http.StatusForbidden || tokenizeReason != "PROMPT_SAFETY_TOKENIZATION_APPLIED" || tokenizeDecision != "quarantine" {
			return "fail", fmt.Sprintf("hipaa tokenize expected 403/quarantine/PROMPT_SAFETY_TOKENIZATION_APPLIED, got code=%d decision=%q reason=%q", tokenizeCode, tokenizeDecision, tokenizeReason), nil
		}

		rawAttrs := map[string]any{
			"provider":           "openai",
			"model":              "gpt-4o",
			"compliance_profile": "hipaa",
			"prompt_has_phi":     true,
			"prompt":             "Patient record contains SSN 123-45-6789",
		}
		rawCode, rawBody, err := postJSON(srv.URL, "/v1/model/call", defaultSPIFFEID, buildPayload("conformance-hipaa-raw", rawAttrs))
		if err != nil {
			return "fail", fmt.Sprintf("hipaa raw request failed: %v", err), nil
		}
		rawReason, _ := rawBody["reason_code"].(string)
		rawDecision, _ := rawBody["decision"].(string)
		if rawCode != http.StatusForbidden || rawReason != "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED" || rawDecision != "deny" {
			return "fail", fmt.Sprintf("hipaa raw expected 403/deny/PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED, got code=%d decision=%q reason=%q", rawCode, rawDecision, rawReason), nil
		}
		return "pass", "hipaa profile enforces raw deny and tokenize quarantine reason-codes", nil
	default:
		return "fail", "", fmt.Errorf("unsupported profiles case_id %q", fx.CaseID)
	}
}

func newProfileGatewayConfig(spiffeMode string) (*gateway.Config, func(), error) {
	tmpDir, err := os.MkdirTemp("", "conformance-profile-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create profile temp dir: %w", err)
	}
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0o644); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("write profile destinations config: %w", err)
	}

	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             spiffeMode,
		DestinationsConfigPath: destinationsPath,
		RateLimitRPM:           100000,
		RateLimitBurst:         100000,
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}
	return cfg, cleanup, nil
}

func createValidateApproveRuleSet(baseURL, spiffeID, rulesetID string, live bool) (expectedSignature string, message string, ok bool) {
	createCode, createBody, err := postJSONWithRetry(baseURL, "/admin/dlp/rulesets/create", spiffeID, map[string]any{
		"ruleset_id": rulesetID,
		"created_by": "conformance@test",
		"content": map[string]any{
			"rules": []any{
				map[string]any{"id": "deny-creds", "action": "deny"},
			},
		},
	}, live)
	if err != nil {
		return "", fmt.Sprintf("create failed: %v", err), false
	}
	if createCode != http.StatusOK {
		return "", fmt.Sprintf("create expected 200, got %d body=%v", createCode, createBody), false
	}

	validateCode, validateBody, err := postJSONWithRetry(baseURL, "/admin/dlp/rulesets/validate", spiffeID, map[string]any{"ruleset_id": rulesetID}, live)
	if err != nil {
		return "", fmt.Sprintf("validate failed: %v", err), false
	}
	if validateCode != http.StatusOK {
		return "", fmt.Sprintf("validate expected 200, got %d body=%v", validateCode, validateBody), false
	}

	approveCode, approveBody, err := postJSONWithRetry(baseURL, "/admin/dlp/rulesets/approve", spiffeID, map[string]any{
		"ruleset_id":  rulesetID,
		"approved_by": "conformance@test",
	}, live)
	if err != nil {
		return "", fmt.Sprintf("approve failed: %v", err), false
	}
	if approveCode != http.StatusOK {
		return "", fmt.Sprintf("approve expected 200, got %d body=%v", approveCode, approveBody), false
	}
	expectedSignature = nestedField(approveBody, "record", "expected_signature")
	if expectedSignature == "" {
		return "", "approve response missing expected_signature", false
	}
	return expectedSignature, "", true
}

func registerConnector(baseURL, connectorID, spiffeID, signature string, live bool) (string, error) {
	manifest := map[string]any{
		"connector_id":     connectorID,
		"connector_type":   "webhook",
		"source_principal": spiffeID,
		"version":          "1.0",
		"capabilities":     []string{"ingress.submit"},
	}
	if signature != "" {
		manifest["signature"] = map[string]any{
			"algorithm": "sha256-manifest-v1",
			"value":     signature,
		}
	}
	code, body, err := postJSONWithRetry(baseURL, "/v1/connectors/register", spiffeID, map[string]any{
		"connector_id": connectorID,
		"manifest":     manifest,
	}, live)
	if err != nil {
		return "", fmt.Errorf("connector register failed: %w", err)
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("connector register expected 200, got %d body=%v", code, body)
	}
	expectedSig := nestedField(body, "record", "expected_signature")
	if expectedSig == "" {
		return "", fmt.Errorf("connector register response missing expected_signature")
	}
	return expectedSig, nil
}

func resolveGatewayURL(opts RunOptions) (baseURL string, cleanup func(), err error) {
	if opts.Live {
		return strings.TrimRight(opts.GatewayURL, "/"), func() {}, nil
	}
	tmpDir, err := os.MkdirTemp("", "conformance-harness-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0o644); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("write destinations config: %w", err)
	}

	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		AdminAuthzAllowedSPIFFEIDs: []string{
			opts.SPIFFEID,
		},
		DestinationsConfigPath: destinationsPath,
		RateLimitRPM:           100000,
		RateLimitBurst:         100000,
	}
	gw, err := gateway.New(cfg)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("new gateway: %w", err)
	}
	srv := httptest.NewServer(gw.Handler())
	cleanup = func() {
		srv.Close()
		_ = os.RemoveAll(tmpDir)
	}
	return strings.TrimRight(srv.URL, "/"), cleanup, nil
}

func postJSON(baseURL, path, spiffeID string, payload map[string]any) (int, map[string]any, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewBuffer(raw))
	if err != nil {
		return 0, nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if spiffeID != "" {
		req.Header.Set("X-SPIFFE-ID", spiffeID)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("post request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out == nil {
		out = map[string]any{}
	}
	return resp.StatusCode, out, nil
}

func postJSONWithRetry(baseURL, path, spiffeID string, payload map[string]any, live bool) (int, map[string]any, error) {
	maxAttempts := 1
	if live {
		maxAttempts = 3
	}
	var (
		lastCode int
		lastBody map[string]any
		lastErr  error
	)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		code, body, err := postJSON(baseURL, path, spiffeID, payload)
		lastCode, lastBody, lastErr = code, body, err
		if err != nil {
			return code, body, err
		}
		if code != http.StatusTooManyRequests || !live {
			return code, body, nil
		}
		retryAfter := retryAfterSeconds(body)
		if retryAfter <= 0 || attempt == maxAttempts-1 {
			return code, body, nil
		}
		time.Sleep(time.Duration(retryAfter+1) * time.Second)
	}
	return lastCode, lastBody, lastErr
}

func retryAfterSeconds(body map[string]any) int {
	if body == nil {
		return 0
	}
	details, ok := body["details"].(map[string]any)
	if !ok {
		return 0
	}
	switch v := details["retry_after_seconds"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func nestedField(root map[string]any, parent, key string) string {
	if root == nil {
		return ""
	}
	nested, ok := root[parent].(map[string]any)
	if !ok {
		return ""
	}
	val, _ := nested[key].(string)
	return val
}

func getParamString(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, _ := params[key].(string)
	return v
}

func checkGatewayReachable(gatewayURL string) error {
	url := strings.TrimRight(gatewayURL, "/") + "/health"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("live gateway unreachable at %s: %w", gatewayURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("live gateway health check returned %d", resp.StatusCode)
	}
	return nil
}

func moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to resolve harness caller path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
