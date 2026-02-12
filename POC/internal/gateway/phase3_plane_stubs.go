package gateway

import (
	"sync"
	"time"
)

// NOTE: These Phase 3 plane policy engines are scaffolding to keep the POC
// implementation compile-safe while we incrementally wire enforcement into
// specific ingress/context/loop/tool paths. The "hard controls" remain in
// existing middleware (OPA, DLP, deep scan, step-up gating, rate limiting).

type ingressPlanePolicyEngine struct{}

func newIngressPlanePolicyEngine() *ingressPlanePolicyEngine {
	return &ingressPlanePolicyEngine{}
}

type contextPlanePolicyEngine struct{}

func newContextPlanePolicyEngine() *contextPlanePolicyEngine {
	return &contextPlanePolicyEngine{}
}

type loopRunRecord struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

type loopPlanePolicyEngine struct {
	mu   sync.Mutex
	runs []loopRunRecord
}

func newLoopPlanePolicyEngine() *loopPlanePolicyEngine {
	return &loopPlanePolicyEngine{
		runs: make([]loopRunRecord, 0),
	}
}

func (l *loopPlanePolicyEngine) listRuns() []loopRunRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]loopRunRecord, len(l.runs))
	copy(out, l.runs)
	return out
}

type toolPlanePolicyEngine struct {
	capabilityRegistryV2Path string
}

func newToolPlanePolicyEngine(capabilityRegistryV2Path string) *toolPlanePolicyEngine {
	return &toolPlanePolicyEngine{capabilityRegistryV2Path: capabilityRegistryV2Path}
}

type rlmGovernanceEngine struct{}

func newRLMGovernanceEngine() *rlmGovernanceEngine {
	return &rlmGovernanceEngine{}
}
