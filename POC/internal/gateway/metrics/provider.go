package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// InitMeterProvider initializes the OTel MeterProvider with an OTLP gRPC exporter.
// When endpoint is empty, no MeterProvider is registered and the default no-op
// meter is used -- metric recordings are silently discarded.
//
// Returns a shutdown function that flushes pending metrics and releases resources.
// The caller MUST invoke the shutdown function during graceful shutdown.
func InitMeterProvider(ctx context.Context, endpoint, serviceName string) (func(context.Context) error, error) {
	if endpoint == "" {
		// No endpoint configured -- return a no-op shutdown.
		return func(context.Context) error { return nil }, nil
	}

	if serviceName == "" {
		serviceName = "mcp-security-gateway"
	}

	// Create OTLP gRPC metric exporter targeting the OTel Collector.
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(endpoint),
		otlpmetricgrpc.WithInsecure(), // Collector is on the internal Docker network
		otlpmetricgrpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
	}

	// Build resource with service identity attributes (same as tracing).
	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", serviceName),
			attribute.String("service.version", "2.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTel resource: %w", err)
	}

	// Create MeterProvider with periodic reader for production throughput.
	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(exporter, metric.WithInterval(10*time.Second))),
		metric.WithResource(res),
	)

	// Register as the global MeterProvider so middleware meter picks it up.
	otel.SetMeterProvider(mp)

	return mp.Shutdown, nil
}
