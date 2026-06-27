// Package telemetry provides OpenTelemetry integration for R3TRIVE,
// emitting traces, metrics, and structured logs.
//
// See SYSTEM_ARCHITECTURE.md §4.10 for metrics specification.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config holds telemetry configuration.
type Config struct {
	Enabled  bool
	Endpoint string
}

var (
	traceProvider *sdktrace.TracerProvider
	meterProvider *sdkmetric.MeterProvider

	// Metrics
	EventsTotal      metric.Int64Counter
	EventsPerSecond  metric.Float64Gauge
	AlertsTotal      metric.Int64Counter
	IncidentsActive  metric.Int64Gauge
	DetectionLatency metric.Float64Histogram
	CorrelationLat   metric.Float64Histogram
	AIRequestDur     metric.Float64Histogram
	SensorHealth     metric.Int64Gauge
)

// Init initializes OpenTelemetry exporters and instruments.
// If telemetry is disabled, this is a no-op.
func Init(cfg Config) error {
	if !cfg.Enabled {
		slog.Debug("telemetry disabled")
		return nil
	}

	slog.Info("initializing telemetry", "endpoint", cfg.Endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", "r3trive"),
			attribute.String("service.version", "1.0.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Trace provider
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(cfg.Endpoint), otlptracegrpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}
	traceProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(traceProvider)

	// Meter provider
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpoint(cfg.Endpoint), otlpmetricgrpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}
	meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	// Initialize instruments
	meter := meterProvider.Meter("r3trive")

	EventsTotal, _ = meter.Int64Counter("r3trive.events.total", metric.WithDescription("Total events processed"))
	EventsPerSecond, _ = meter.Float64Gauge("r3trive.events.per_second", metric.WithDescription("Events processed per second"))
	AlertsTotal, _ = meter.Int64Counter("r3trive.alerts.total", metric.WithDescription("Total alerts generated"))
	IncidentsActive, _ = meter.Int64Gauge("r3trive.incidents.active", metric.WithDescription("Currently active incidents"))
	DetectionLatency, _ = meter.Float64Histogram("r3trive.detection.latency", metric.WithDescription("Latency of detection pipeline (ms)"))
	CorrelationLat, _ = meter.Float64Histogram("r3trive.correlation.latency", metric.WithDescription("Latency of correlation engine (ms)"))
	AIRequestDur, _ = meter.Float64Histogram("r3trive.ai.request.duration", metric.WithDescription("Duration of AI requests (ms)"))
	SensorHealth, _ = meter.Int64Gauge("r3trive.sensor.health", metric.WithDescription("Health status of sensors (1=ok, 0=error)"))

	return nil
}

// Shutdown gracefully shuts down telemetry exporters.
func Shutdown() {
	if traceProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := traceProvider.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown trace provider", "error", err)
		}
	}
	if meterProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := meterProvider.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown meter provider", "error", err)
		}
	}
	slog.Debug("telemetry shutdown")
}
