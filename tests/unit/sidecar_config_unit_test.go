package unit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Unit tests for the Envoy SPIFFE Identity Sidecar configuration artifacts.
// Story: OC-ofhi
//
// These tests validate:
//   - Envoy config is parseable YAML with correct v3 API structure
//   - SPIRE registration script generates correct commands for both modes
//   - Compose example is valid docker-compose YAML integrating with main stack
//   - K8s patch is valid strategic merge patch YAML
// ---------------------------------------------------------------------------

func sidecarDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(pocRoot(t), "deploy", "sidecar")
}

// --- AC1: Envoy sidecar config validation ---

func TestEnvoySidecarConfigIsValidYAML(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "envoy-sidecar.yaml"))
	if err != nil {
		t.Fatalf("failed to read envoy-sidecar.yaml: %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("envoy-sidecar.yaml is not valid YAML: %v", err)
	}
}

func TestEnvoySidecarConfigHasCorrectListener(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "envoy-sidecar.yaml"))
	if err != nil {
		t.Fatalf("failed to read envoy-sidecar.yaml: %v", err)
	}

	content := string(data)

	// AC1: Listens on 127.0.0.1:9090
	if !strings.Contains(content, "127.0.0.1") {
		t.Error("envoy-sidecar.yaml must listen on 127.0.0.1")
	}
	if !strings.Contains(content, "port_value: 9090") {
		t.Error("envoy-sidecar.yaml must listen on port 9090")
	}
}

func TestEnvoySidecarConfigInjectsSPIFFEIdentity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "envoy-sidecar.yaml"))
	if err != nil {
		t.Fatalf("failed to read envoy-sidecar.yaml: %v", err)
	}

	content := string(data)

	// AC1: Injects SPIFFE identity via X-SPIFFE-ID header
	if !strings.Contains(content, "X-SPIFFE-ID") {
		t.Error("envoy-sidecar.yaml must inject X-SPIFFE-ID header")
	}
	if !strings.Contains(content, "SPIFFE_ID") {
		t.Error("envoy-sidecar.yaml must reference SPIFFE_ID environment variable")
	}
}

func TestEnvoySidecarConfigForwardsToGateway(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "envoy-sidecar.yaml"))
	if err != nil {
		t.Fatalf("failed to read envoy-sidecar.yaml: %v", err)
	}

	content := string(data)

	// AC1: Forwards to gateway
	if !strings.Contains(content, "precinct-gateway") || !strings.Contains(content, "precinct_gateway") {
		t.Error("envoy-sidecar.yaml must forward to precinct-gateway")
	}
}

func TestEnvoySidecarConfigUsesV3API(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "envoy-sidecar.yaml"))
	if err != nil {
		t.Fatalf("failed to read envoy-sidecar.yaml: %v", err)
	}

	content := string(data)

	// AC1: Uses Envoy v3 API
	if !strings.Contains(content, "envoy.extensions.filters.network.http_connection_manager.v3") {
		t.Error("envoy-sidecar.yaml must use Envoy v3 API HttpConnectionManager")
	}
	if !strings.Contains(content, "envoy.filters.http.lua") {
		t.Error("envoy-sidecar.yaml must use Lua HTTP filter for SPIFFE ID injection")
	}
}

func TestEnvoySidecarConfigHasSPIREAgentCluster(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "envoy-sidecar.yaml"))
	if err != nil {
		t.Fatalf("failed to read envoy-sidecar.yaml: %v", err)
	}

	content := string(data)

	// SDS cluster for SPIRE agent socket
	if !strings.Contains(content, "/tmp/spire-agent/public/api.sock") {
		t.Error("envoy-sidecar.yaml must reference SPIRE agent socket path")
	}
}

// --- AC2: SPIRE registration template validation ---

func TestSPIRERegistrationTemplateExists(t *testing.T) {
	scriptPath := filepath.Join(sidecarDir(t), "spire-registration-template.sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("spire-registration-template.sh does not exist: %v", err)
	}

	// Check executable permission
	if info.Mode()&0111 == 0 {
		t.Error("spire-registration-template.sh must be executable")
	}
}

func TestSPIRERegistrationTemplateComposeMode(t *testing.T) {
	scriptPath := filepath.Join(sidecarDir(t), "spire-registration-template.sh")
	cmd := exec.Command("sh", scriptPath, "--tool-name", "test-tool", "--env", "dev", "--mode", "compose")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed in compose mode: %v\noutput:\n%s", err, string(out))
	}

	output := string(out)

	// AC2: Creates valid entries for Compose
	if !strings.Contains(output, "spiffe://poc.local/agents/mcp-client/test-tool/dev") {
		t.Error("compose mode must generate correct SPIFFE ID")
	}
	if !strings.Contains(output, "docker:label:spiffe-id:test-tool") {
		t.Error("compose mode must use docker:label selector")
	}
}

func TestSPIRERegistrationTemplateK8sMode(t *testing.T) {
	scriptPath := filepath.Join(sidecarDir(t), "spire-registration-template.sh")
	cmd := exec.Command("sh", scriptPath, "--tool-name", "test-tool", "--env", "dev", "--mode", "k8s", "--namespace", "agents", "--sa", "test-tool-sa")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed in k8s mode: %v\noutput:\n%s", err, string(out))
	}

	output := string(out)

	// AC2: Creates valid entries for K8s
	if !strings.Contains(output, "spiffe://poc.local/agents/mcp-client/test-tool/dev") {
		t.Error("k8s mode must generate correct SPIFFE ID")
	}
	if !strings.Contains(output, "k8s:ns:agents") {
		t.Error("k8s mode must use k8s:ns selector")
	}
	if !strings.Contains(output, "k8s:sa:test-tool-sa") {
		t.Error("k8s mode must use k8s:sa selector")
	}
}

func TestSPIRERegistrationTemplateRequiresToolName(t *testing.T) {
	scriptPath := filepath.Join(sidecarDir(t), "spire-registration-template.sh")
	cmd := exec.Command("sh", scriptPath, "--env", "dev")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("script should fail without --tool-name")
	}

	output := string(out)
	if !strings.Contains(output, "--tool-name is required") {
		t.Errorf("expected error about missing --tool-name, got: %s", output)
	}
}

func TestSPIRERegistrationTemplateCustomTrustDomain(t *testing.T) {
	scriptPath := filepath.Join(sidecarDir(t), "spire-registration-template.sh")
	cmd := exec.Command("sh", scriptPath, "--tool-name", "my-tool", "--trust-domain", "custom.domain", "--mode", "compose")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed with custom trust domain: %v\noutput:\n%s", err, string(out))
	}

	output := string(out)
	if !strings.Contains(output, "spiffe://custom.domain/agents/mcp-client/my-tool/dev") {
		t.Error("must use custom trust domain in SPIFFE ID")
	}
}

// --- AC3: Docker Compose sidecar example validation ---

// sidecarComposeFile is a minimal struct for parsing the sidecar compose example.
type sidecarComposeFile struct {
	Services map[string]sidecarComposeService `yaml:"services"`
	Networks map[string]interface{}           `yaml:"networks"`
}

type sidecarComposeService struct {
	Image       string                 `yaml:"image"`
	NetworkMode string                 `yaml:"network_mode"`
	Volumes     []string               `yaml:"volumes"`
	Environment []string               `yaml:"environment"`
	Labels      []string               `yaml:"labels"`
	Networks    map[string]interface{}  `yaml:"networks"`
	DependsOn   map[string]interface{} `yaml:"depends_on"`
	Healthcheck interface{}            `yaml:"healthcheck"`
}

func TestComposeExampleIsValidYAML(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "docker-compose.sidecar-example.yml"))
	if err != nil {
		t.Fatalf("failed to read compose example: %v", err)
	}

	var cf sidecarComposeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("docker-compose.sidecar-example.yml is not valid YAML: %v", err)
	}
}

func TestComposeExampleHasEnvoySidecar(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "docker-compose.sidecar-example.yml"))
	if err != nil {
		t.Fatalf("failed to read compose example: %v", err)
	}

	var cf sidecarComposeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// AC3: Has envoy sidecar service
	sidecar, ok := cf.Services["envoy-sidecar"]
	if !ok {
		t.Fatal("compose example must have envoy-sidecar service")
	}

	if !strings.Contains(sidecar.Image, "envoyproxy/envoy") {
		t.Errorf("envoy-sidecar must use envoyproxy/envoy image, got: %s", sidecar.Image)
	}
}

func TestComposeExampleHasClientService(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "docker-compose.sidecar-example.yml"))
	if err != nil {
		t.Fatalf("failed to read compose example: %v", err)
	}

	var cf sidecarComposeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// AC3: Has client service with shared network
	client, ok := cf.Services["sidecar-client"]
	if !ok {
		t.Fatal("compose example must have sidecar-client service")
	}

	// Shared network namespace
	if !strings.Contains(client.NetworkMode, "service:envoy-sidecar") {
		t.Errorf("sidecar-client must share network with envoy-sidecar via network_mode, got: %s", client.NetworkMode)
	}
}

func TestComposeExampleHasSPIREAgentSocket(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "docker-compose.sidecar-example.yml"))
	if err != nil {
		t.Fatalf("failed to read compose example: %v", err)
	}

	content := string(data)

	// AC3: SPIRE agent socket volume mount
	if !strings.Contains(content, "spire-agent-socket") {
		t.Error("compose example must mount SPIRE agent socket")
	}
}

func TestComposeExampleUsesAgenticNet(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "docker-compose.sidecar-example.yml"))
	if err != nil {
		t.Fatalf("failed to read compose example: %v", err)
	}

	var cf sidecarComposeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// AC3: Connected to agentic-net
	_, hasNet := cf.Networks["agentic-net"]
	if !hasNet {
		t.Error("compose example must declare agentic-net network")
	}
}

func TestComposeExampleHasDockerLabelsForSPIRE(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "docker-compose.sidecar-example.yml"))
	if err != nil {
		t.Fatalf("failed to read compose example: %v", err)
	}

	content := string(data)

	// AC3: Docker labels for SPIRE attestation
	if !strings.Contains(content, "spiffe-id=") {
		t.Error("compose example must have spiffe-id Docker labels for SPIRE attestation")
	}
}

// --- AC4: K8s sidecar patch validation ---

func TestK8sPatchIsValidYAML(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "k8s-sidecar-patch.yaml"))
	if err != nil {
		t.Fatalf("failed to read k8s-sidecar-patch.yaml: %v", err)
	}

	var patch map[string]interface{}
	if err := yaml.Unmarshal(data, &patch); err != nil {
		t.Fatalf("k8s-sidecar-patch.yaml is not valid YAML: %v", err)
	}
}

func TestK8sPatchIsStrategicMergePatch(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "k8s-sidecar-patch.yaml"))
	if err != nil {
		t.Fatalf("failed to read k8s-sidecar-patch.yaml: %v", err)
	}

	var patch map[string]interface{}
	if err := yaml.Unmarshal(data, &patch); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// AC4: Must be a Deployment resource
	apiVersion, ok := patch["apiVersion"]
	if !ok || apiVersion != "apps/v1" {
		t.Errorf("k8s patch must have apiVersion: apps/v1, got: %v", apiVersion)
	}

	kind, ok := patch["kind"]
	if !ok || kind != "Deployment" {
		t.Errorf("k8s patch must have kind: Deployment, got: %v", kind)
	}
}

func TestK8sPatchHasEnvoySidecarContainer(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "k8s-sidecar-patch.yaml"))
	if err != nil {
		t.Fatalf("failed to read k8s-sidecar-patch.yaml: %v", err)
	}

	content := string(data)

	// AC4: Contains envoy sidecar container
	if !strings.Contains(content, "envoy-sidecar") {
		t.Error("k8s patch must contain envoy-sidecar container")
	}
	if !strings.Contains(content, "envoyproxy/envoy") {
		t.Error("k8s patch must use envoyproxy/envoy image")
	}
}

func TestK8sPatchMountsSPIRESocket(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "k8s-sidecar-patch.yaml"))
	if err != nil {
		t.Fatalf("failed to read k8s-sidecar-patch.yaml: %v", err)
	}

	content := string(data)

	// AC4: Volume mount for SPIRE agent socket
	if !strings.Contains(content, "spire-agent-socket") {
		t.Error("k8s patch must mount spire-agent-socket volume")
	}
	if !strings.Contains(content, "/run/spire/sockets") {
		t.Error("k8s patch must use /run/spire/sockets path (matching agent-daemonset.yaml)")
	}
}

func TestK8sPatchHasSPIFFEIDEnvVar(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "k8s-sidecar-patch.yaml"))
	if err != nil {
		t.Fatalf("failed to read k8s-sidecar-patch.yaml: %v", err)
	}

	content := string(data)

	// AC4: SPIFFE_ID env var for identity injection
	if !strings.Contains(content, "SPIFFE_ID") {
		t.Error("k8s patch must set SPIFFE_ID environment variable")
	}
}

func TestK8sPatchHasSecurityContext(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sidecarDir(t), "k8s-sidecar-patch.yaml"))
	if err != nil {
		t.Fatalf("failed to read k8s-sidecar-patch.yaml: %v", err)
	}

	content := string(data)

	// Security hardening: non-root, read-only, drop capabilities
	if !strings.Contains(content, "runAsNonRoot: true") {
		t.Error("k8s patch envoy sidecar must run as non-root")
	}
	if !strings.Contains(content, "readOnlyRootFilesystem: true") {
		t.Error("k8s patch envoy sidecar must have read-only root filesystem")
	}
	if !strings.Contains(content, "allowPrivilegeEscalation: false") {
		t.Error("k8s patch envoy sidecar must disallow privilege escalation")
	}
}

// --- AC5: Documentation validation ---

func TestDocumentationExists(t *testing.T) {
	docPath := filepath.Join(pocRoot(t), "docs", "sidecar-identity.md")
	if _, err := os.Stat(docPath); err != nil {
		t.Fatalf("docs/sidecar-identity.md does not exist: %v", err)
	}
}

func TestDocumentationCoversComposeAndK8s(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pocRoot(t), "docs", "sidecar-identity.md"))
	if err != nil {
		t.Fatalf("failed to read documentation: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "Docker Compose") {
		t.Error("documentation must cover Docker Compose deployment")
	}
	if !strings.Contains(content, "Kubernetes") {
		t.Error("documentation must cover Kubernetes deployment")
	}
}

func TestDocumentationCoversSPIRERegistration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pocRoot(t), "docs", "sidecar-identity.md"))
	if err != nil {
		t.Fatalf("failed to read documentation: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "SPIRE") {
		t.Error("documentation must cover SPIRE registration")
	}
	if !strings.Contains(content, "spire-registration-template") {
		t.Error("documentation must reference spire-registration-template.sh")
	}
}

func TestDocumentationCoversTroubleshooting(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pocRoot(t), "docs", "sidecar-identity.md"))
	if err != nil {
		t.Fatalf("failed to read documentation: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "Troubleshooting") {
		t.Error("documentation must have a Troubleshooting section")
	}
	if !strings.Contains(content, "SVID") {
		t.Error("documentation must cover verifying SVID issuance")
	}
}
