//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	"gopkg.in/yaml.v3"
)

func TestGatewayAdminPolicyReloadIntegration_ModifyRegistryAndReload(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	configPath := filepath.Join(pocDir(), "config", "tool-registry.yaml")
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read tool-registry.yaml: %v", err)
	}

	t.Cleanup(func() {
		_ = os.WriteFile(configPath, original, 0644)
		_, _ = triggerPolicyReload()
	})

	var cfg middleware.ToolRegistryConfig
	if err := yaml.Unmarshal(original, &cfg); err != nil {
		t.Fatalf("unmarshal registry yaml: %v", err)
	}

	probeTool := "integration_reload_probe"
	for _, tool := range cfg.Tools {
		if tool.Name == probeTool {
			t.Fatalf("probe tool %q already exists in baseline config", probeTool)
		}
	}

	cfg.Tools = append(cfg.Tools, middleware.ToolDefinition{
		Name:        probeTool,
		Description: "integration reload probe tool",
		Hash:        "integration-reload-probe-hash",
		InputSchema: map[string]interface{}{"type": "object"},
	})

	updatedYAML, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal updated registry yaml: %v", err)
	}
	if err := os.WriteFile(configPath, updatedYAML, 0644); err != nil {
		t.Fatalf("write updated registry yaml: %v", err)
	}

	reloadResp, err := triggerPolicyReload()
	if err != nil {
		t.Fatalf("POST /admin/policy/reload: %v", err)
	}
	if reloadResp.StatusCode != http.StatusOK {
		t.Fatalf("expected reload status 200, got %d", reloadResp.StatusCode)
	}
	defer reloadResp.Body.Close()

	var reloadBody struct {
		Status        string `json:"status"`
		RegistryTools int    `json:"registry_tools"`
		OPAPolicies   int    `json:"opa_policies"`
	}
	if err := json.NewDecoder(reloadResp.Body).Decode(&reloadBody); err != nil {
		t.Fatalf("decode reload response: %v", err)
	}
	if reloadBody.Status != "reloaded" {
		t.Fatalf("expected status=reloaded, got %q", reloadBody.Status)
	}
	if reloadBody.RegistryTools < len(cfg.Tools) {
		t.Fatalf("expected registry_tools >= %d, got %d", len(cfg.Tools), reloadBody.RegistryTools)
	}
	if reloadBody.OPAPolicies <= 0 {
		t.Fatalf("expected opa_policies > 0, got %d", reloadBody.OPAPolicies)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	listResp, err := client.Get(gatewayURL + "/admin/circuit-breakers")
	if err != nil {
		t.Fatalf("GET /admin/circuit-breakers: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("expected circuit-breakers status 200, got %d", listResp.StatusCode)
	}

	var listed struct {
		CircuitBreakers []struct {
			Tool string `json:"tool"`
		} `json:"circuit_breakers"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode /admin/circuit-breakers response: %v", err)
	}

	found := false
	for _, entry := range listed.CircuitBreakers {
		if entry.Tool == probeTool {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected reloaded registry to include %q; got %+v", probeTool, listed.CircuitBreakers)
	}
}

func triggerPolicyReload() (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/admin/policy/reload", nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
