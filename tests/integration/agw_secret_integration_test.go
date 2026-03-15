//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAgwSecretIntegration_ListAndPut(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	listBefore := exec.Command("go", "run", "./cli/agw", "secret", "list", "--format", "json")
	listBefore.Dir = pocDir()
	var listBeforeOut, listBeforeErr bytes.Buffer
	listBefore.Stdout = &listBeforeOut
	listBefore.Stderr = &listBeforeErr
	if err := listBefore.Run(); err != nil {
		t.Fatalf("agw secret list failed: %v stdout=%q stderr=%q", err, listBeforeOut.String(), listBeforeErr.String())
	}

	var beforeParsed struct {
		Secrets []struct {
			Ref string `json:"ref"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(listBeforeOut.Bytes(), &beforeParsed); err != nil {
		t.Fatalf("invalid list json: %v raw=%q", err, listBeforeOut.String())
	}
	if len(beforeParsed.Secrets) == 0 {
		t.Fatalf("expected at least one seeded secret ref, got %+v", beforeParsed)
	}

	ref := fmt.Sprintf("agw%08x", time.Now().UnixNano()&0xffffffff)
	value := "integration-secret-value"

	putCmd := exec.Command("go", "run", "./cli/agw", "secret", "put", ref, value, "--confirm", "--format", "json")
	putCmd.Dir = pocDir()
	var putOut, putErr bytes.Buffer
	putCmd.Stdout = &putOut
	putCmd.Stderr = &putErr
	if err := putCmd.Run(); err != nil {
		t.Fatalf("agw secret put failed: %v stdout=%q stderr=%q", err, putOut.String(), putErr.String())
	}
	if strings.Contains(putOut.String(), value) || strings.Contains(putErr.String(), value) {
		t.Fatalf("secret value leaked by agw output: stdout=%q stderr=%q", putOut.String(), putErr.String())
	}

	var putParsed struct {
		Status string `json:"status"`
		Ref    string `json:"ref"`
	}
	if err := json.Unmarshal(putOut.Bytes(), &putParsed); err != nil {
		t.Fatalf("invalid put json: %v raw=%q", err, putOut.String())
	}
	if putParsed.Status != "stored" || putParsed.Ref != ref {
		t.Fatalf("unexpected put output: %+v", putParsed)
	}

	// Verify persistence through SPIKE directly (no value should be emitted by agw).
	verifyGet := exec.Command(
		"docker", "compose", "run", "--rm", "--no-deps",
		"--entrypoint", "/usr/local/bin/spike",
		"spike-secret-seeder", "secret", "get", ref,
	)
	verifyGet.Dir = pocDir()
	verifyOut, err := verifyGet.CombinedOutput()
	if err != nil {
		t.Fatalf("verify secret get failed: %v output=%q", err, string(verifyOut))
	}
	if !strings.Contains(string(verifyOut), "value: "+value) {
		t.Fatalf("expected persisted value from SPIKE secret get, got %q", string(verifyOut))
	}
}
