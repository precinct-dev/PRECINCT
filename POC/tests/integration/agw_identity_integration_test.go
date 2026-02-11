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

func TestAgwIdentityIntegration_ListAndRegister(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// List existing identities first.
	listCmd := exec.Command("go", "run", "./cmd/agw", "identity", "list", "--format", "json")
	listCmd.Dir = pocDir()
	var listOut, listErr bytes.Buffer
	listCmd.Stdout = &listOut
	listCmd.Stderr = &listErr
	if err := listCmd.Run(); err != nil {
		t.Fatalf("agw identity list failed: %v stdout=%q stderr=%q", err, listOut.String(), listErr.String())
	}

	var listParsed struct {
		Entries []struct {
			SPIFFEID string `json:"spiffe_id"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(listOut.Bytes(), &listParsed); err != nil {
		t.Fatalf("invalid list json: %v raw=%q", err, listOut.String())
	}
	if len(listParsed.Entries) == 0 {
		t.Fatalf("expected at least one SPIRE entry, got %+v", listParsed)
	}

	name := fmt.Sprintf("agw-int-%x", time.Now().UnixNano()&0xfffffff)
	selector := fmt.Sprintf("docker:label:spiffe-id:%s", name)

	registerCmd := exec.Command(
		"go", "run", "./cmd/agw", "identity", "register", name,
		"--confirm",
		"--selector", selector,
		"--format", "json",
	)
	registerCmd.Dir = pocDir()
	var registerOut, registerErr bytes.Buffer
	registerCmd.Stdout = &registerOut
	registerCmd.Stderr = &registerErr
	if err := registerCmd.Run(); err != nil {
		t.Fatalf("agw identity register failed: %v stdout=%q stderr=%q", err, registerOut.String(), registerErr.String())
	}

	var registerParsed struct {
		EntryID  string `json:"entry_id"`
		SPIFFEID string `json:"spiffe_id"`
		ParentID string `json:"parent_id"`
	}
	if err := json.Unmarshal(registerOut.Bytes(), &registerParsed); err != nil {
		t.Fatalf("invalid register json: %v raw=%q", err, registerOut.String())
	}
	if registerParsed.EntryID == "" {
		t.Fatalf("expected entry_id in register output, got %+v", registerParsed)
	}
	if registerParsed.ParentID != "spiffe://poc.local/agent/local" {
		t.Fatalf("expected parent id spiffe://poc.local/agent/local, got %+v", registerParsed)
	}

	t.Cleanup(func() {
		del := exec.Command(
			"docker", "compose", "exec", "-T", "spire-server",
			"/opt/spire/bin/spire-server", "entry", "delete",
			"-socketPath", "/tmp/spire-server/private/api.sock",
			"-entryID", registerParsed.EntryID,
		)
		del.Dir = pocDir()
		_, _ = del.CombinedOutput()
	})

	verifyList := exec.Command("go", "run", "./cmd/agw", "identity", "list", "--format", "json")
	verifyList.Dir = pocDir()
	var verifyOut, verifyErr bytes.Buffer
	verifyList.Stdout = &verifyOut
	verifyList.Stderr = &verifyErr
	if err := verifyList.Run(); err != nil {
		t.Fatalf("agw identity list verify failed: %v stdout=%q stderr=%q", err, verifyOut.String(), verifyErr.String())
	}

	if !strings.Contains(verifyOut.String(), fmt.Sprintf(`"spiffe_id": "spiffe://poc.local/agents/%s/dev"`, name)) {
		t.Fatalf("expected new SPIFFE ID in identity list output, got %q", verifyOut.String())
	}
}
