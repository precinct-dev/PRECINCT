// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package manifestpolicy

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	RuleProdImageDigestRequired  = "prod_image_digest_required"
	RuleProdImageLatestForbidden = "prod_image_latest_forbidden"
	RuleProdNodePortForbidden    = "prod_nodeport_forbidden"
	RuleProdHostPathForbidden    = "prod_hostpath_forbidden"
	RuleProdPrivilegedForbidden  = "prod_privileged_forbidden"
)

type Violation struct {
	Rule    string
	File    string
	Message string
}

type Result struct {
	CheckedFiles int
	Violations   []Violation
}

var (
	allowedNodePortPaths = map[string]string{
		"deploy/k8s/base/observability/phoenix/phoenix-service.yaml":  "operator diagnostics UI exception",
		"deploy/terraform/observability/phoenix/phoenix-service.yaml": "operator diagnostics UI exception",
		"infra/eks/observability/phoenix/phoenix-service.yaml":        "operator diagnostics UI exception",
	}
	allowedHostPathPaths = map[string]string{
		"deploy/k8s/base/gateway/gateway-deployment.yaml":                                      "spire workload socket mount",
		"deploy/k8s/base/mcp-server/mcp-server-deployment.yaml":                                "spire workload socket mount",
		"deploy/terraform/gateway/control-deployment.yaml":                                     "spire workload socket mount",
		"deploy/terraform/gateway/gateway-deployment.yaml":                                     "spire workload socket mount",
		"deploy/terraform/mcp-server/mcp-server-deployment.yaml":                               "spire workload socket mount",
		"deploy/terraform/observability/opensearch/opensearch-audit-forwarder-deployment.yaml": "audit forwarder host log access and SPIRE socket mount",
		"deploy/terraform/observability/opensearch/opensearch-dashboards-deployment.yaml":      "spire workload socket mount",
		"deploy/terraform/observability/opensearch/opensearch-statefulset.yaml":                "spire workload socket mount",
		"deploy/terraform/s3-mcp-server/s3-mcp-server-deployment.yaml":                         "spire workload socket mount",
		"deploy/terraform/spike/bootstrap-job.yaml":                                            "spire workload socket mount",
		"deploy/terraform/spike/keeper-2-deployment.yaml":                                      "spire workload socket mount",
		"deploy/terraform/spike/keeper-3-deployment.yaml":                                      "spire workload socket mount",
		"deploy/terraform/spike/keeper-deployment.yaml":                                        "spire workload socket mount",
		"deploy/terraform/spike/nexus-deployment.yaml":                                         "spire workload socket mount",
		"deploy/terraform/spike/seeder-job.yaml":                                               "spire workload socket mount",
		"deploy/terraform/spire/agent-daemonset.yaml":                                          "spire agent socket exposure",
		"infra/eks/gateway/gateway-deployment.yaml":                                            "spire workload socket mount",
		"infra/eks/mcp-server/mcp-server-deployment.yaml":                                      "spire workload socket mount",
		"infra/eks/s3-mcp-server/s3-mcp-server-deployment.yaml":                                "spire workload socket mount",
		"infra/eks/spike/keeper-deployment.yaml":                                               "spire workload socket mount",
		"infra/eks/spike/nexus-deployment.yaml":                                                "spire workload socket mount",
		"infra/eks/spike/seeder-job.yaml":                                                      "spire workload socket mount",
		"infra/eks/spike/bootstrap-job.yaml":                                                   "spire workload socket mount",
		"infra/eks/spire/agent-daemonset.yaml":                                                 "spire agent socket exposure",
	}
	allowedPrivilegedPaths = map[string]string{}
)

var manifestRoots = []string{
	"deploy/k8s",
	"deploy/terraform",
	"infra/eks",
}

// CheckRepo validates production-intent manifest hardening controls.
func CheckRepo(root string) (Result, error) {
	result := Result{}
	if root == "" {
		root = "."
	}

	envPath := filepath.Join(root, "config", "compose-production-intent.env")
	envViolations, err := checkProductionIntentEnv(envPath)
	if err != nil {
		return result, err
	}
	result.Violations = append(result.Violations, envViolations...)

	for _, manifestRoot := range manifestRoots {
		scanRoot := filepath.Join(root, filepath.FromSlash(manifestRoot))
		if _, err := os.Stat(scanRoot); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return result, err
		}
		if err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if !isYAMLFile(path) {
				return nil
			}
			rel := slash(filepath.ToSlash(mustRel(root, path)))
			if shouldSkipManifestPath(rel) {
				return nil
			}
			result.CheckedFiles++
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			violations := checkKubernetesManifest(rel, data)
			result.Violations = append(result.Violations, violations...)
			return nil
		}); err != nil {
			return result, err
		}
	}

	return result, nil
}

func shouldSkipManifestPath(rel string) bool {
	switch {
	case strings.Contains(rel, "deploy/k8s/overlays/local/"):
		return true
	case strings.Contains(rel, "deploy/k8s/overlays/dev/"):
		return true
	case strings.Contains(rel, "deploy/terraform/overlays/local/"):
		return true
	case strings.Contains(rel, "infra/eks/overlays/local/"):
		return true
	default:
		return false
	}
}

func checkProductionIntentEnv(path string) ([]Violation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read production-intent env: %w", err)
	}
	lines := strings.Split(string(raw), "\n")
	out := make([]Violation, 0)

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if !strings.HasPrefix(key, "PROD_") || !strings.HasSuffix(key, "_IMAGE") {
			continue
		}
		if !strings.Contains(val, "@sha256:") {
			out = append(out, Violation{
				Rule:    RuleProdImageDigestRequired,
				File:    "config/compose-production-intent.env",
				Message: fmt.Sprintf("%s must be digest-pinned (@sha256), line %d", key, idx+1),
			})
		}
		if imageUsesLatestTag(val) {
			out = append(out, Violation{
				Rule:    RuleProdImageLatestForbidden,
				File:    "config/compose-production-intent.env",
				Message: fmt.Sprintf("%s must not use mutable :latest tag, line %d", key, idx+1),
			})
		}
	}

	return out, nil
}

func checkKubernetesManifest(relPath string, data []byte) []Violation {
	out := make([]Violation, 0)
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if err != nil {
			if err == io.EOF {
				break
			}
			out = append(out, Violation{
				Rule:    "manifest_parse_error",
				File:    relPath,
				Message: "unable to parse YAML document",
			})
			break
		}
		if len(doc) == 0 {
			continue
		}
		kind := strings.TrimSpace(stringValue(doc["kind"]))
		if strings.EqualFold(kind, "Service") && serviceTypeNodePort(doc) {
			if _, ok := allowedNodePortPaths[relPath]; !ok {
				out = append(out, Violation{
					Rule:    RuleProdNodePortForbidden,
					File:    relPath,
					Message: "NodePort service is forbidden in prod manifests unless explicitly allowlisted",
				})
			}
		}
		if containsHostPath(doc) {
			if _, ok := allowedHostPathPaths[relPath]; !ok {
				out = append(out, Violation{
					Rule:    RuleProdHostPathForbidden,
					File:    relPath,
					Message: "hostPath usage is forbidden in prod manifests unless explicitly allowlisted",
				})
			}
		}
		if containsPrivilegedTrue(doc) {
			if _, ok := allowedPrivilegedPaths[relPath]; !ok {
				out = append(out, Violation{
					Rule:    RuleProdPrivilegedForbidden,
					File:    relPath,
					Message: "privileged=true is forbidden in prod manifests unless explicitly allowlisted",
				})
			}
		}
	}

	return out
}

func serviceTypeNodePort(doc map[string]any) bool {
	spec, ok := doc["spec"].(map[string]any)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(stringValue(spec["type"])), "NodePort")
}

func containsHostPath(node any) bool {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "hostPath" {
				return true
			}
			if containsHostPath(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if containsHostPath(child) {
				return true
			}
		}
	}
	return false
}

func containsPrivilegedTrue(node any) bool {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "privileged" {
				if b, ok := child.(bool); ok && b {
					return true
				}
				if strings.EqualFold(strings.TrimSpace(stringValue(child)), "true") {
					return true
				}
			}
			if containsPrivilegedTrue(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if containsPrivilegedTrue(child) {
				return true
			}
		}
	}
	return false
}

func imageUsesLatestTag(imageRef string) bool {
	noDigest := imageRef
	if at := strings.Index(noDigest, "@"); at >= 0 {
		noDigest = noDigest[:at]
	}
	lastSeg := noDigest
	if slashIdx := strings.LastIndex(lastSeg, "/"); slashIdx >= 0 {
		lastSeg = lastSeg[slashIdx+1:]
	}
	return strings.HasSuffix(lastSeg, ":latest")
}

func isYAMLFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

func mustRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return rel
}

func slash(path string) string {
	return strings.TrimPrefix(strings.ReplaceAll(path, "\\", "/"), "./")
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}
