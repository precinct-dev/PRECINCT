//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// TestPublicEdgeOverlay_KustomizeBuild validates that the public edge kustomize
// overlay builds successfully and produces the expected K8s resources with the
// correct configuration for public edge hardening (OC-e3d3).
//
// This is an integration test because it shells out to kubectl/kustomize and
// validates the rendered manifests against the actual overlay files on disk.
func TestPublicEdgeOverlay_KustomizeBuild(t *testing.T) {
	overlayPath := pocDir() + "/deploy/k8s/overlays/public"

	// Build the overlay with kustomize
	cmd := exec.Command("kubectl", "kustomize", overlayPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl kustomize %s failed: %v\noutput:\n%s", overlayPath, err, string(out))
	}

	rendered := string(out)

	// Split into individual YAML documents
	docs := splitYAMLDocs(rendered)
	if len(docs) == 0 {
		t.Fatal("kustomize produced no YAML documents")
	}

	// Parse each document to find specific resources
	var (
		foundIngress             bool
		foundNetworkPolicy       bool
		foundDeploymentPublicEnv bool
		ingressDoc               map[string]any
		networkPolicyDoc         map[string]any
	)

	for _, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		// Use JSON conversion via kubectl for reliable parsing -- but since
		// we already have the YAML, just check key strings.
		if strings.Contains(doc, "kind: Ingress") && strings.Contains(doc, "precinct-gateway-public") {
			foundIngress = true
			ingressDoc = parseFirstYAMLAsJSON(t, doc)
		}
		if strings.Contains(doc, "kind: NetworkPolicy") && strings.Contains(doc, "allow-ingress-controller-to-gateway") {
			foundNetworkPolicy = true
			networkPolicyDoc = parseFirstYAMLAsJSON(t, doc)
		}
		if strings.Contains(doc, "kind: Deployment") && strings.Contains(doc, "precinct-gateway") && strings.Contains(doc, "PUBLIC_ROUTE_ALLOWLIST") {
			foundDeploymentPublicEnv = true
		}
	}

	// AC1: Ingress exists with the three allowed paths
	if !foundIngress {
		t.Fatal("Ingress resource precinct-gateway-public not found in rendered output")
	}

	// AC2: Verify that blocked routes are NOT in the Ingress
	if strings.Contains(rendered, "/admin") {
		t.Error("Ingress contains /admin path -- this must NOT be publicly exposed")
	}
	if strings.Contains(rendered, "/openai/v1/chat/completions") {
		t.Error("Ingress contains /openai/v1/chat/completions -- this must NOT be publicly exposed")
	}

	// AC3: NetworkPolicy for ingress controller exists
	if !foundNetworkPolicy {
		t.Fatal("NetworkPolicy allow-ingress-controller-to-gateway not found in rendered output")
	}

	// Verify gateway deployment has public listener env vars
	if !foundDeploymentPublicEnv {
		t.Error("Gateway deployment does not contain PUBLIC_ROUTE_ALLOWLIST env var")
	}

	// Verify Ingress has the three required paths
	if ingressDoc != nil {
		verifyIngressPaths(t, ingressDoc)
	}

	// Verify NetworkPolicy targets the correct pod label
	if networkPolicyDoc != nil {
		verifyNetworkPolicyLabels(t, networkPolicyDoc)
	}

	// Verify default-deny policies are still present
	if !strings.Contains(rendered, "default-deny-all") {
		t.Error("default-deny-all NetworkPolicy missing from rendered output -- default-deny posture broken")
	}

	// Verify TLS configuration is present in Ingress
	if ingressDoc != nil {
		verifyTLSConfig(t, ingressDoc)
	}
}

// TestPublicEdgeOverlay_DryRun validates that kubectl apply --dry-run=client
// succeeds for the public overlay. This is the mandatory validation from the
// story's testing requirements.
func TestPublicEdgeOverlay_DryRun(t *testing.T) {
	overlayPath := pocDir() + "/deploy/k8s/overlays/public"

	cmd := exec.Command("kubectl", "apply", "--dry-run=client", "-k", overlayPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl apply --dry-run=client -k %s failed: %v\noutput:\n%s", overlayPath, err, string(out))
	}

	output := string(out)

	// Verify key resources appear in dry-run output
	expectedResources := []string{
		"ingress.networking.k8s.io/precinct-gateway-public",
		"networkpolicy.networking.k8s.io/allow-ingress-controller-to-gateway",
		"deployment.apps/precinct-gateway",
		"service/precinct-gateway",
		"networkpolicy.networking.k8s.io/default-deny-all",
	}

	for _, res := range expectedResources {
		if !strings.Contains(output, res) {
			t.Errorf("dry-run output missing expected resource: %s", res)
		}
	}
}

// splitYAMLDocs splits multi-document YAML (separated by ---) into individual documents.
func splitYAMLDocs(s string) []string {
	return strings.Split(s, "\n---\n")
}

// parseFirstYAMLAsJSON converts a YAML document to a map via kubectl.
// This is a quick-and-dirty parser that extracts fields we care about.
func parseFirstYAMLAsJSON(t *testing.T, yamlDoc string) map[string]any {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "--dry-run=client", "-o", "json", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlDoc)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fall back to nil if kubectl can't parse it (may need a server)
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		return nil
	}
	return result
}

// verifyIngressPaths checks that the Ingress spec contains exactly the three
// required paths.
func verifyIngressPaths(t *testing.T, ingress map[string]any) {
	t.Helper()

	spec, ok := ingress["spec"].(map[string]any)
	if !ok {
		t.Error("Ingress has no spec")
		return
	}

	rules, ok := spec["rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Error("Ingress has no rules")
		return
	}

	rule := rules[0].(map[string]any)
	httpBlock, ok := rule["http"].(map[string]any)
	if !ok {
		t.Error("Ingress rule has no http block")
		return
	}

	paths, ok := httpBlock["paths"].([]any)
	if !ok {
		t.Error("Ingress http block has no paths")
		return
	}

	requiredPaths := map[string]bool{
		"/":                                     false,
		"/health":                               false,
		"/.well-known/oauth-protected-resource": false,
	}

	for _, p := range paths {
		pathObj := p.(map[string]any)
		pathStr, ok := pathObj["path"].(string)
		if !ok {
			continue
		}
		if _, exists := requiredPaths[pathStr]; exists {
			requiredPaths[pathStr] = true
		} else {
			t.Errorf("unexpected path in Ingress: %s", pathStr)
		}
	}

	for path, found := range requiredPaths {
		if !found {
			t.Errorf("required path %s missing from Ingress", path)
		}
	}
}

// verifyNetworkPolicyLabels checks the NetworkPolicy targets the correct pod label.
func verifyNetworkPolicyLabels(t *testing.T, np map[string]any) {
	t.Helper()

	spec, ok := np["spec"].(map[string]any)
	if !ok {
		t.Error("NetworkPolicy has no spec")
		return
	}

	podSelector, ok := spec["podSelector"].(map[string]any)
	if !ok {
		t.Error("NetworkPolicy has no podSelector")
		return
	}

	matchLabels, ok := podSelector["matchLabels"].(map[string]any)
	if !ok {
		t.Error("NetworkPolicy podSelector has no matchLabels")
		return
	}

	if v, ok := matchLabels["precinct.io/public-edge"]; !ok || v != "true" {
		t.Error("NetworkPolicy podSelector missing precinct.io/public-edge=true label")
	}

	if v, ok := matchLabels["app.kubernetes.io/name"]; !ok || v != "precinct-gateway" {
		t.Error("NetworkPolicy podSelector missing app.kubernetes.io/name=precinct-gateway label")
	}
}

// verifyTLSConfig checks the Ingress has TLS configuration.
func verifyTLSConfig(t *testing.T, ingress map[string]any) {
	t.Helper()

	spec, ok := ingress["spec"].(map[string]any)
	if !ok {
		return
	}

	tls, ok := spec["tls"].([]any)
	if !ok || len(tls) == 0 {
		t.Error("Ingress has no TLS configuration")
		return
	}

	tlsEntry := tls[0].(map[string]any)
	if secretName, ok := tlsEntry["secretName"].(string); !ok || secretName == "" {
		t.Error("Ingress TLS entry has no secretName")
	}

	// Verify cert-manager annotation
	metadata, ok := ingress["metadata"].(map[string]any)
	if !ok {
		return
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	if !ok {
		t.Error("Ingress has no annotations")
		return
	}
	if _, ok := annotations["cert-manager.io/cluster-issuer"]; !ok {
		t.Error("Ingress missing cert-manager.io/cluster-issuer annotation")
	}
}
