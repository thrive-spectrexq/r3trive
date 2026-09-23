// Package telemetry provides OpenTelemetry integration for R3TRIVE,
// emitting traces, metrics, and structured logs.
//
// See SYSTEM_ARCHITECTURE.md §4.10 for metrics specification.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
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

	// Internal atomic metrics for Prometheus scraping & resilient fallback
	promEventsTotal       atomic.Int64
	promAlertsTotal       atomic.Int64
	promIncidentsActive   atomic.Int64
	promSensorHealth      atomic.Int64
	promDetectionLatSum   atomic.Int64
	promDetectionLatCount atomic.Int64
	promCorrelationLatSum atomic.Int64
	promCorrelationCount  atomic.Int64
)

func init() {
	promSensorHealth.Store(1) // Default healthy
}

// RecordEvent safely records processed events count.
func RecordEvent(ctx context.Context, count int64) {
	promEventsTotal.Add(count)
	if EventsTotal != nil {
		EventsTotal.Add(ctx, count)
	}
}

// RecordAlert safely records generated alerts count.
func RecordAlert(ctx context.Context, count int64) {
	promAlertsTotal.Add(count)
	if AlertsTotal != nil {
		AlertsTotal.Add(ctx, count)
	}
}

// RecordIncident safely updates active incident gauge.
func RecordIncident(ctx context.Context, active int64) {
	promIncidentsActive.Store(active)
	if IncidentsActive != nil {
		IncidentsActive.Record(ctx, active)
	}
}

// RecordDetectionLatency safely records detection pipeline duration in ms.
func RecordDetectionLatency(ctx context.Context, ms float64) {
	promDetectionLatSum.Add(int64(ms))
	promDetectionLatCount.Add(1)
	if DetectionLatency != nil {
		DetectionLatency.Record(ctx, ms)
	}
}

// RecordCorrelationLatency safely records correlation engine duration in ms.
func RecordCorrelationLatency(ctx context.Context, ms float64) {
	promCorrelationLatSum.Add(int64(ms))
	promCorrelationCount.Add(1)
	if CorrelationLat != nil {
		CorrelationLat.Record(ctx, ms)
	}
}

// RecordAIRequestDuration safely records AI request duration in ms.
func RecordAIRequestDuration(ctx context.Context, ms float64) {
	if AIRequestDur != nil {
		AIRequestDur.Record(ctx, ms)
	}
}

// RecordSensorHealth safely updates sensor health status.
func RecordSensorHealth(ctx context.Context, healthy bool) {
	var val int64
	if healthy {
		val = 1
	}
	promSensorHealth.Store(val)
	if SensorHealth != nil {
		SensorHealth.Record(ctx, val)
	}
}

// PrometheusHandler returns an HTTP handler that exposes metrics in Prometheus text exposition format.
func PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP r3trive_events_total Total events processed\n")
		fmt.Fprintf(w, "# TYPE r3trive_events_total counter\n")
		fmt.Fprintf(w, "r3trive_events_total %d\n", promEventsTotal.Load())

		fmt.Fprintf(w, "# HELP r3trive_alerts_total Total alerts generated\n")
		fmt.Fprintf(w, "# TYPE r3trive_alerts_total counter\n")
		fmt.Fprintf(w, "r3trive_alerts_total %d\n", promAlertsTotal.Load())

		fmt.Fprintf(w, "# HELP r3trive_incidents_active Currently active incidents\n")
		fmt.Fprintf(w, "# TYPE r3trive_incidents_active gauge\n")
		fmt.Fprintf(w, "r3trive_incidents_active %d\n", promIncidentsActive.Load())

		fmt.Fprintf(w, "# HELP r3trive_sensor_health Health status of sensors (1=ok, 0=error)\n")
		fmt.Fprintf(w, "# TYPE r3trive_sensor_health gauge\n")
		fmt.Fprintf(w, "r3trive_sensor_health %d\n", promSensorHealth.Load())

		fmt.Fprintf(w, "# HELP r3trive_detection_latency_ms Detection pipeline latency in milliseconds\n")
		fmt.Fprintf(w, "# TYPE r3trive_detection_latency_ms summary\n")
		fmt.Fprintf(w, "r3trive_detection_latency_ms_sum %d\n", promDetectionLatSum.Load())
		fmt.Fprintf(w, "r3trive_detection_latency_ms_count %d\n", promDetectionLatCount.Load())

		fmt.Fprintf(w, "# HELP r3trive_correlation_latency_ms Correlation engine latency in milliseconds\n")
		fmt.Fprintf(w, "# TYPE r3trive_correlation_latency_ms summary\n")
		fmt.Fprintf(w, "r3trive_correlation_latency_ms_sum %d\n", promCorrelationLatSum.Load())
		fmt.Fprintf(w, "r3trive_correlation_latency_ms_count %d\n", promCorrelationCount.Load())
	}
}

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
