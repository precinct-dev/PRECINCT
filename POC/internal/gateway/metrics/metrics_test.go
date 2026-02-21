package metrics

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestNewMetrics verifies that NewMetrics creates all 6 instruments without error.
func TestNewMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	meter := mp.Meter("test")
	m, err := NewMetrics(meter)
	if err != nil {
		t.Fatalf("NewMetrics() returned error: %v", err)
	}
	if m == nil {
		t.Fatal("NewMetrics() returned nil")
	}

	// Verify all instruments are non-nil
	if m.RequestTotal == nil {
		t.Error("RequestTotal instrument is nil")
	}
	if m.DenialTotal == nil {
		t.Error("DenialTotal instrument is nil")
	}
	if m.RateLimiterUtilization == nil {
		t.Error("RateLimiterUtilization instrument is nil")
	}
	if m.CircuitBreakerState == nil {
		t.Error("CircuitBreakerState instrument is nil")
	}
	if m.DeepScanLatencyMs == nil {
		t.Error("DeepScanLatencyMs instrument is nil")
	}
	if m.DLPFindingsTotal == nil {
		t.Error("DLPFindingsTotal instrument is nil")
	}
}

// TestMetricsRecordWithoutPanic verifies that recording each metric does not panic.
func TestMetricsRecordWithoutPanic(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	meter := mp.Meter("test")
	m, err := NewMetrics(meter)
	if err != nil {
		t.Fatalf("NewMetrics() returned error: %v", err)
	}

	ctx := context.Background()

	// Record each metric -- should not panic
	m.RequestTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("method", "POST"),
			attribute.String("path", "/test"),
			attribute.String("status_code", "200"),
			attribute.String("spiffe_id", "spiffe://test/agent"),
		),
	)

	m.DenialTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("middleware", "opa"),
			attribute.String("reason", "policy_denied"),
			attribute.String("spiffe_id", "spiffe://test/agent"),
		),
	)

	m.RateLimiterUtilization.Record(ctx, 0.75,
		metric.WithAttributes(
			attribute.String("spiffe_id", "spiffe://test/agent"),
			attribute.String("limiter_name", "default"),
		),
	)

	m.CircuitBreakerState.Record(ctx, 0,
		metric.WithAttributes(
			attribute.String("circuit_name", "default"),
		),
	)

	m.DeepScanLatencyMs.Record(ctx, 150.5,
		metric.WithAttributes(
			attribute.String("model", "test-model"),
			attribute.String("outcome", "allowed"),
		),
	)

	m.DLPFindingsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("pattern_name", "credentials"),
			attribute.String("action", "block"),
		),
	)
}

// TestMetricsCounterDataPoints verifies that recorded counter values appear in
// the ManualReader's collected data.
func TestMetricsCounterDataPoints(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	meter := mp.Meter("test")
	m, err := NewMetrics(meter)
	if err != nil {
		t.Fatalf("NewMetrics() returned error: %v", err)
	}

	ctx := context.Background()

	// Record some data
	m.RequestTotal.Add(ctx, 3,
		metric.WithAttributes(
			attribute.String("method", "POST"),
			attribute.String("path", "/mcp"),
			attribute.String("status_code", "200"),
			attribute.String("spiffe_id", "spiffe://test/agent"),
		),
	)

	m.DenialTotal.Add(ctx, 2,
		metric.WithAttributes(
			attribute.String("middleware", "dlp"),
			attribute.String("reason", "credentials_detected"),
			attribute.String("spiffe_id", "spiffe://test/agent"),
		),
	)

	m.DLPFindingsTotal.Add(ctx, 5,
		metric.WithAttributes(
			attribute.String("pattern_name", "pii"),
			attribute.String("action", "flag"),
		),
	)

	// Collect and verify
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("reader.Collect() returned error: %v", err)
	}

	// Verify we got scope metrics
	if len(rm.ScopeMetrics) == 0 {
		t.Fatal("expected at least one ScopeMetrics, got none")
	}

	// Build a map of metric name -> metric for easy lookup
	metricsByName := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricsByName[m.Name] = m
		}
	}

	// Verify request_total
	if rt, ok := metricsByName["gateway.request_total"]; ok {
		if sum, ok := rt.Data.(metricdata.Sum[int64]); ok {
			found := false
			for _, dp := range sum.DataPoints {
				if dp.Value == 3 {
					found = true
					break
				}
			}
			if !found {
				t.Error("gateway.request_total: expected data point with value 3")
			}
		} else {
			t.Errorf("gateway.request_total: unexpected data type %T", rt.Data)
		}
	} else {
		t.Error("gateway.request_total metric not found in collected data")
	}

	// Verify denial_total
	if dt, ok := metricsByName["gateway.denial_total"]; ok {
		if sum, ok := dt.Data.(metricdata.Sum[int64]); ok {
			found := false
			for _, dp := range sum.DataPoints {
				if dp.Value == 2 {
					found = true
					break
				}
			}
			if !found {
				t.Error("gateway.denial_total: expected data point with value 2")
			}
		} else {
			t.Errorf("gateway.denial_total: unexpected data type %T", dt.Data)
		}
	} else {
		t.Error("gateway.denial_total metric not found in collected data")
	}

	// Verify dlp_findings_total
	if df, ok := metricsByName["gateway.dlp_findings_total"]; ok {
		if sum, ok := df.Data.(metricdata.Sum[int64]); ok {
			found := false
			for _, dp := range sum.DataPoints {
				if dp.Value == 5 {
					found = true
					break
				}
			}
			if !found {
				t.Error("gateway.dlp_findings_total: expected data point with value 5")
			}
		} else {
			t.Errorf("gateway.dlp_findings_total: unexpected data type %T", df.Data)
		}
	} else {
		t.Error("gateway.dlp_findings_total metric not found in collected data")
	}
}

// TestMetricsHistogramDataPoints verifies that recorded histogram values appear
// in the ManualReader's collected data.
func TestMetricsHistogramDataPoints(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	meter := mp.Meter("test")
	m, err := NewMetrics(meter)
	if err != nil {
		t.Fatalf("NewMetrics() returned error: %v", err)
	}

	ctx := context.Background()

	// Record histogram data
	m.DeepScanLatencyMs.Record(ctx, 100.0,
		metric.WithAttributes(
			attribute.String("model", "llama-guard"),
			attribute.String("outcome", "allowed"),
		),
	)
	m.DeepScanLatencyMs.Record(ctx, 250.0,
		metric.WithAttributes(
			attribute.String("model", "llama-guard"),
			attribute.String("outcome", "blocked"),
		),
	)

	// Collect and verify
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("reader.Collect() returned error: %v", err)
	}

	metricsByName := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricsByName[m.Name] = m
		}
	}

	if dl, ok := metricsByName["gateway.deep_scan_latency_ms"]; ok {
		if hist, ok := dl.Data.(metricdata.Histogram[float64]); ok {
			if len(hist.DataPoints) < 1 {
				t.Error("gateway.deep_scan_latency_ms: expected at least 1 data point")
			}
			// Verify count: we recorded 2 data points across 2 attribute sets
			totalCount := uint64(0)
			for _, dp := range hist.DataPoints {
				totalCount += dp.Count
			}
			if totalCount != 2 {
				t.Errorf("gateway.deep_scan_latency_ms: expected total count 2, got %d", totalCount)
			}
		} else {
			t.Errorf("gateway.deep_scan_latency_ms: unexpected data type %T", dl.Data)
		}
	} else {
		t.Error("gateway.deep_scan_latency_ms metric not found in collected data")
	}
}

// TestMetricsGaugeDataPoints verifies that recorded gauge values appear
// in the ManualReader's collected data.
func TestMetricsGaugeDataPoints(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	meter := mp.Meter("test")
	m, err := NewMetrics(meter)
	if err != nil {
		t.Fatalf("NewMetrics() returned error: %v", err)
	}

	ctx := context.Background()

	// Record gauge data
	m.CircuitBreakerState.Record(ctx, 2, // Open
		metric.WithAttributes(
			attribute.String("circuit_name", "default"),
		),
	)

	m.RateLimiterUtilization.Record(ctx, 0.85,
		metric.WithAttributes(
			attribute.String("spiffe_id", "spiffe://test/agent"),
			attribute.String("limiter_name", "default"),
		),
	)

	// Collect and verify
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("reader.Collect() returned error: %v", err)
	}

	metricsByName := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricsByName[m.Name] = m
		}
	}

	// Verify circuit_breaker_state
	if cb, ok := metricsByName["gateway.circuit_breaker_state"]; ok {
		if gauge, ok := cb.Data.(metricdata.Gauge[int64]); ok {
			found := false
			for _, dp := range gauge.DataPoints {
				if dp.Value == 2 {
					found = true
					break
				}
			}
			if !found {
				t.Error("gateway.circuit_breaker_state: expected data point with value 2 (open)")
			}
		} else {
			t.Errorf("gateway.circuit_breaker_state: unexpected data type %T", cb.Data)
		}
	} else {
		t.Error("gateway.circuit_breaker_state metric not found in collected data")
	}

	// Verify rate_limiter_utilization
	if rl, ok := metricsByName["gateway.rate_limiter_utilization"]; ok {
		if gauge, ok := rl.Data.(metricdata.Gauge[float64]); ok {
			found := false
			for _, dp := range gauge.DataPoints {
				if dp.Value >= 0.84 && dp.Value <= 0.86 { // float tolerance
					found = true
					break
				}
			}
			if !found {
				t.Error("gateway.rate_limiter_utilization: expected data point near 0.85")
			}
		} else {
			t.Errorf("gateway.rate_limiter_utilization: unexpected data type %T", rl.Data)
		}
	} else {
		t.Error("gateway.rate_limiter_utilization metric not found in collected data")
	}
}
