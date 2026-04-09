// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"
	"time"
)

type ingressReplayGuard struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	window    time.Duration
	maxFuture time.Duration
}

func newIngressReplayGuard(window, maxFuture time.Duration) *ingressReplayGuard {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if maxFuture <= 0 {
		maxFuture = 15 * time.Second
	}
	return &ingressReplayGuard{
		seen:      make(map[string]time.Time),
		window:    window,
		maxFuture: maxFuture,
	}
}

func (g *ingressReplayGuard) fresh(now time.Time, eventTime time.Time) bool {
	if g == nil {
		return true
	}
	age := now.Sub(eventTime)
	if age < 0 {
		return -age <= g.maxFuture
	}
	return age <= g.window
}

func (g *ingressReplayGuard) checkAndMark(replayKey string, now time.Time) bool {
	if g == nil {
		return false
	}
	key := strings.TrimSpace(replayKey)
	if key == "" {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if seenAt, exists := g.seen[key]; exists && now.Sub(seenAt) <= g.window {
		return true
	}
	g.seen[key] = now

	// Opportunistic cleanup keeps memory bounded for long-lived runtimes.
	cutoff := now.Add(-g.window)
	for k, seenAt := range g.seen {
		if seenAt.Before(cutoff) {
			delete(g.seen, k)
		}
	}
	return false
}

func ingressReplayKey(connectorID string, attrs map[string]any) string {
	if attrs == nil {
		return ""
	}
	eventID := getStringAttr(attrs, "event_id", "")
	if eventID != "" {
		return connectorID + "|event_id|" + eventID
	}
	nonce := getStringAttr(attrs, "nonce", "")
	if nonce != "" {
		return connectorID + "|nonce|" + nonce
	}
	return ""
}
