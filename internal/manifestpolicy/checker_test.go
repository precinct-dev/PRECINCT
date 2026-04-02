package manifestpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeBaselineProdEnv(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, "config/compose-production-intent.env", "PROD_GATEWAY_IMAGE=ghcr.io/example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
}

func TestCheckRepo_DetectsNonDigestAndLatestProdImage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "config/compose-production-intent.env", "PROD_GATEWAY_IMAGE=ghcr.io/example/gateway:latest\n")

	result, err := CheckRepo(root)
	if err != nil {
		t.Fatalf("CheckRepo returned error: %v", err)
	}
	if len(result.Violations) < 2 {
		t.Fatalf("expected digest + latest violations, got %d (%v)", len(result.Violations), result.Violations)
	}
}

func TestCheckRepo_DetectsNodePortOutsideAllowlist(t *testing.T) {
	root := t.TempDir()
	writeBaselineProdEnv(t, root)
	writeFile(t, root, "deploy/terraform/gateway/bad-nodeport.yaml", `
apiVersion: v1
kind: Service
metadata:
  name: bad
spec:
  type: NodePort
`)

	result, err := CheckRepo(root)
	if err != nil {
		t.Fatalf("CheckRepo returned error: %v", err)
	}
	if len(result.Violations) == 0 {
		t.Fatal("expected NodePort violation")
	}
}

func TestCheckRepo_AllowsNodePortInApprovedException(t *testing.T) {
	root := t.TempDir()
	writeBaselineProdEnv(t, root)
	writeFile(t, root, "deploy/k8s/base/observability/phoenix/phoenix-service.yaml", `
apiVersion: v1
kind: Service
metadata:
  name: phoenix
spec:
  type: NodePort
`)

	result, err := CheckRepo(root)
	if err != nil {
		t.Fatalf("CheckRepo returned error: %v", err)
	}
	for _, v := range result.Violations {
		if v.Rule == RuleProdNodePortForbidden {
			t.Fatalf("expected NodePort exception to pass, got violation: %+v", v)
		}
	}
}

func TestCheckRepo_DetectsHostPathAndPrivilegedOutsideAllowlist(t *testing.T) {
	root := t.TempDir()
	writeBaselineProdEnv(t, root)
	writeFile(t, root, "deploy/terraform/gateway/bad-deploy.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      containers:
        - name: bad
          securityContext:
            privileged: true
      volumes:
        - name: sock
          hostPath:
            path: /tmp/host.sock
`)

	result, err := CheckRepo(root)
	if err != nil {
		t.Fatalf("CheckRepo returned error: %v", err)
	}
	if len(result.Violations) < 2 {
		t.Fatalf("expected hostPath + privileged violations, got %d (%v)", len(result.Violations), result.Violations)
	}
}

func TestCheckRepo_SkipsLocalOverlays(t *testing.T) {
	root := t.TempDir()
	writeBaselineProdEnv(t, root)
	writeFile(t, root, "deploy/terraform/overlays/local/bad.yaml", `
apiVersion: v1
kind: Service
metadata:
  name: local-nodeport
spec:
  type: NodePort
`)

	result, err := CheckRepo(root)
	if err != nil {
		t.Fatalf("CheckRepo returned error: %v", err)
	}
	if result.CheckedFiles != 0 {
		t.Fatalf("expected local overlays to be skipped, checked_files=%d", result.CheckedFiles)
	}
	for _, v := range result.Violations {
		if v.Rule == RuleProdNodePortForbidden {
			t.Fatalf("expected local overlay nodeport to be skipped, got violation: %+v", v)
		}
	}
}
