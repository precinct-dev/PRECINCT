package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
	"github.com/alicebob/miniredis/v2"
)

func newDistributedStateGateway(t *testing.T, keydbURL string, handleTTLSeconds int) *Gateway {
	t.Helper()

	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations.yaml: %v", err)
	}

	cfg := &Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		KeyDBURL:               keydbURL,
		KeyDBPoolMin:           1,
		KeyDBPoolMax:           5,
		SessionTTL:             3600,
		HandleTTL:              handleTTLSeconds,
		ApprovalSigningKey:     "distributed-approval-signing-key-material-12345",
		DestinationsConfigPath: destinationsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("new distributed gateway: %v", err)
	}
	return gw
}

func TestDistributedState_MultiInstanceConsistency(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	keydbURL := "redis://" + mr.Addr()
	gwA := newDistributedStateGateway(t, keydbURL, 2)
	defer func() { _ = gwA.Close() }()
	gwB := newDistributedStateGateway(t, keydbURL, 2)
	defer func() { _ = gwB.Close() }()

	scope := middleware.ApprovalScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		SessionID:     "distributed-approval-session",
	}
	created, err := gwA.approvalCapabilities.CreateRequest(middleware.ApprovalRequestInput{
		Scope:       scope,
		RequestedBy: "integration@test",
		TTLSeconds:  120,
	})
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	grant, err := gwA.approvalCapabilities.GrantRequest(middleware.ApprovalGrantInput{
		RequestID:  created.RequestID,
		ApprovedBy: "security@test",
	})
	if err != nil {
		t.Fatalf("grant approval request: %v", err)
	}
	if _, err := gwB.approvalCapabilities.ValidateAndConsume(grant.Token, scope); err != nil {
		t.Fatalf("expected gwB to consume token minted by gwA: %v", err)
	}
	if _, err := gwA.approvalCapabilities.ValidateAndConsume(grant.Token, scope); !errors.Is(err, middleware.ErrApprovalTokenConsumed) {
		t.Fatalf("expected second consume to fail with consumed error, got: %v", err)
	}

	bgRecord, err := gwA.breakGlass.request(breakGlassRequestInput{
		IncidentID: "INC-DIST-001",
		Scope: breakGlassScope{
			Action:        "model.call",
			Resource:      "gpt-4o",
			ActorSPIFFEID: scope.ActorSPIFFEID,
		},
		RequestedBy: "integration@test",
		TTLSeconds:  120,
	})
	if err != nil {
		t.Fatalf("breakglass request: %v", err)
	}
	if _, err := gwA.breakGlass.approve(breakGlassApprovalInput{RequestID: bgRecord.RequestID, ApprovedBy: "approver-a@test"}); err != nil {
		t.Fatalf("breakglass approve A: %v", err)
	}
	if _, err := gwB.breakGlass.approve(breakGlassApprovalInput{RequestID: bgRecord.RequestID, ApprovedBy: "approver-b@test"}); err != nil {
		t.Fatalf("breakglass approve B: %v", err)
	}
	if _, err := gwB.breakGlass.activate(breakGlassActivateInput{RequestID: bgRecord.RequestID, ActivatedBy: "incident-commander@test"}); err != nil {
		t.Fatalf("breakglass activate: %v", err)
	}
	if _, ok := gwA.breakGlass.activeOverride(breakGlassScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: scope.ActorSPIFFEID,
	}); !ok {
		t.Fatal("expected gwA to observe active breakglass override activated by gwB")
	}

	handleRef, err := gwA.handleStore.Store([]byte(`{"sensitive":"payload"}`), scope.ActorSPIFFEID, "database_query")
	if err != nil {
		t.Fatalf("store handle on gwA: %v", err)
	}
	entry := gwB.handleStore.Get(handleRef)
	if entry == nil {
		t.Fatal("expected gwB to dereference handle stored by gwA")
	}
	if string(entry.RawData) != `{"sensitive":"payload"}` {
		t.Fatalf("unexpected handle payload: %s", string(entry.RawData))
	}

	near, exhausted := gwA.modelPlanePolicy.reserveBudget("tenant-distributed", "tiny", 1)
	if near || exhausted {
		t.Fatalf("first budget consume expected allow, got near=%v exhausted=%v", near, exhausted)
	}
	near, exhausted = gwB.modelPlanePolicy.reserveBudget("tenant-distributed", "tiny", 1)
	if !near || exhausted {
		t.Fatalf("second budget consume expected near-limit, got near=%v exhausted=%v", near, exhausted)
	}
	near, exhausted = gwA.modelPlanePolicy.reserveBudget("tenant-distributed", "tiny", 1)
	if !exhausted {
		t.Fatalf("third budget consume expected exhaustion, got near=%v exhausted=%v", near, exhausted)
	}
}

func TestDistributedState_ConcurrencyAndTTL(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	keydbURL := "redis://" + mr.Addr()
	gwA := newDistributedStateGateway(t, keydbURL, 1)
	defer func() { _ = gwA.Close() }()
	gwB := newDistributedStateGateway(t, keydbURL, 1)
	defer func() { _ = gwB.Close() }()

	scope := middleware.ApprovalScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		SessionID:     "distributed-concurrency-session",
	}
	created, err := gwA.approvalCapabilities.CreateRequest(middleware.ApprovalRequestInput{
		Scope:      scope,
		TTLSeconds: 30,
	})
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	grant, err := gwA.approvalCapabilities.GrantRequest(middleware.ApprovalGrantInput{
		RequestID:  created.RequestID,
		ApprovedBy: "security@test",
	})
	if err != nil {
		t.Fatalf("grant approval request: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	go func() {
		defer wg.Done()
		_, consumeErr := gwA.approvalCapabilities.ValidateAndConsume(grant.Token, scope)
		errs <- consumeErr
	}()
	go func() {
		defer wg.Done()
		_, consumeErr := gwB.approvalCapabilities.ValidateAndConsume(grant.Token, scope)
		errs <- consumeErr
	}()
	wg.Wait()
	close(errs)

	success := 0
	consumed := 0
	for consumeErr := range errs {
		switch {
		case consumeErr == nil:
			success++
		case errors.Is(consumeErr, middleware.ErrApprovalTokenConsumed):
			consumed++
		default:
			t.Fatalf("unexpected consume result: %v", consumeErr)
		}
	}
	if success != 1 || consumed != 1 {
		t.Fatalf("expected one success and one consumed error, got success=%d consumed=%d", success, consumed)
	}

	ref, err := gwA.handleStore.Store([]byte("ttl-check"), scope.ActorSPIFFEID, "tool")
	if err != nil {
		t.Fatalf("store handle: %v", err)
	}
	if gwB.handleStore.Get(ref) == nil {
		t.Fatal("expected handle present before TTL expiry")
	}
	mr.FastForward(2 * time.Second)
	if gwB.handleStore.Get(ref) != nil {
		t.Fatal("expected handle to expire across replicas after TTL")
	}
}
