// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Package metrics defines and registers OTel application metrics for the
// PRECINCT Gateway's key operational signals. Metrics are exposed via
// the global OTel MeterProvider, matching the existing tracing pattern.
package metrics

import (
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all OTel meter instruments for the gateway.
// It is created once at startup and passed (or accessed via package-level
// variable) by middleware to record operational signals.
type Metrics struct {
	// RequestTotal counts all requests processed by the gateway.
	// Attributes: method, path, status_code, spiffe_id
	RequestTotal metric.Int64Counter

	// DenialTotal counts requests denied by any middleware.
	// Attributes: middleware (opa|dlp|rate_limit|deep_scan|spiffe|circuit_breaker), reason, spiffe_id
	DenialTotal metric.Int64Counter

	// RateLimiterUtilization records the current rate limiter utilization
	// as a fraction 0.0-1.0.
	// Attributes: spiffe_id, limiter_name
	RateLimiterUtilization metric.Float64Gauge

	// CircuitBreakerState records the circuit breaker state as an integer.
	// 0=closed, 1=half-open, 2=open.
	// Attributes: circuit_name
	CircuitBreakerState metric.Int64Gauge

	// DeepScanLatencyMs records deep scan call latency in milliseconds.
	// Attributes: model, outcome (allowed|blocked|error)
	DeepScanLatencyMs metric.Float64Histogram

	// DLPFindingsTotal counts DLP pattern matches.
	// Attributes: pattern_name, action (redact|block)
	DLPFindingsTotal metric.Int64Counter
}

// NewMetrics creates all metric instruments from the given meter.
// Returns an error if any instrument creation fails.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	requestTotal, err := meter.Int64Counter("gateway.request_total",
		metric.WithDescription("Total requests processed by the gateway"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	denialTotal, err := meter.Int64Counter("gateway.denial_total",
		metric.WithDescription("Requests denied by middleware"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	rateLimiterUtilization, err := meter.Float64Gauge("gateway.rate_limiter_utilization",
		metric.WithDescription("Rate limiter utilization as fraction 0.0-1.0"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	circuitBreakerState, err := meter.Int64Gauge("gateway.circuit_breaker_state",
		metric.WithDescription("Circuit breaker state: 0=closed, 1=half-open, 2=open"),
		metric.WithUnit("{state}"),
	)
	if err != nil {
		return nil, err
	}

	deepScanLatencyMs, err := meter.Float64Histogram("gateway.deep_scan_latency_ms",
		metric.WithDescription("Deep scan call latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	dlpFindingsTotal, err := meter.Int64Counter("gateway.dlp_findings_total",
		metric.WithDescription("DLP pattern matches"),
		metric.WithUnit("{finding}"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		RequestTotal:           requestTotal,
		DenialTotal:            denialTotal,
		RateLimiterUtilization: rateLimiterUtilization,
		CircuitBreakerState:    circuitBreakerState,
		DeepScanLatencyMs:      deepScanLatencyMs,
		DLPFindingsTotal:       dlpFindingsTotal,
	}, nil
}
