//! OpenTelemetry tracing (Session Twenty-One, Design §14; OTEL-CONTRACT).
//!
//! The Gateway is the **trace root**: the stock `ssh` client cannot emit a
//! `traceparent`, so the Gateway mints the root span (`gateway.session`) when it
//! accepts an outer-leg connection, and injects the W3C context into the outbound
//! CP gRPC metadata on every RPC so the CP's `cp.authorize` / `cp.cert_sign`
//! spans join the same trace. One trace ties `client -> Gateway -> CP -> node`.
//!
//! **Off by default.** The OTLP exporter is enabled ONLY when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise only the existing local
//! `tracing`/fmt logging runs, unchanged. When enabled the exporter uses the
//! **tonic/ring** transport (no `openssl`, per the deny.toml supply-chain policy).
//!
//! **Carries correlation, never content (OTEL-CONTRACT §5).** Spans carry IDs,
//! enums, counts, durations and outcomes only. SSH plaintext, keys, OTP, tokens,
//! device codes, PINs and recording bytes NEVER enter a span, attribute, event or
//! log — a test greps rendered spans for known secret markers.

use opentelemetry::propagation::{Injector, TextMapPropagator};
// `with_endpoint` on the OTLP exporter builder is provided by this trait.
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

/// Standard, non-content span attribute keys (OTEL-CONTRACT §4). Only IDs, enums,
/// outcomes — never secret content.
pub mod attr {
    /// The session UUID (`sessionlayer.session_id`).
    pub const SESSION_ID: &str = "sessionlayer.session_id";
    /// The correlation id tying the approve→connect→run chain (defaults to the session id).
    pub const CORRELATION_ID: &str = "sessionlayer.correlation_id";
    /// The target node's server-authoritative id (`sessionlayer.node_id`).
    pub const NODE_ID: &str = "sessionlayer.node_id";
    /// The access model (standing / jit / break-glass), an enum — never content.
    pub const ACCESS_MODEL: &str = "sessionlayer.access_model";
    /// The session outcome (an enum / §7.1 reason), never content.
    pub const OUTCOME: &str = "sessionlayer.outcome";
}

/// The environment variable that turns the OTLP exporter on (unset ⇒ off).
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
/// The service-name override; defaults to `sessionlayer-gateway`.
const SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const DEFAULT_SERVICE_NAME: &str = "sessionlayer-gateway";

/// A tonic client channel wrapped with the W3C trace-context injector. Every CP
/// RPC issued over this channel carries the current span's `traceparent`.
pub type TracedChannel = InterceptedService<Channel, TraceContextInjector>;

/// Wrap a CP channel so every RPC injects the current trace context (OTEL-CONTRACT
/// §2.1). Cheap: `InterceptedService` only defers the metadata write to call time.
pub fn trace_channel(channel: Channel) -> TracedChannel {
    InterceptedService::new(channel, TraceContextInjector)
}

/// A tonic interceptor that injects the W3C `traceparent`/`tracestate` of the
/// **current tracing span** into a request's gRPC metadata (OTEL-CONTRACT §2.1).
///
/// When no OTLP exporter is installed the current span has no valid OTel context,
/// so the propagator injects nothing — the header is simply absent (safe no-op).
/// It never injects anything but the two standard W3C keys, so no application data
/// (let alone secret data) can leak through it.
#[derive(Clone, Copy, Default)]
pub struct TraceContextInjector;

impl tonic::service::Interceptor for TraceContextInjector {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let cx = tracing::Span::current().context();
        TraceContextPropagator::new()
            .inject_context(&cx, &mut MetadataInjectorMut(request.metadata_mut()));
        Ok(request)
    }
}

/// Adapts a tonic [`MetadataMap`] to the OTel [`Injector`] trait. Only ASCII keys
/// and values are inserted; anything else is silently skipped (the propagator only
/// ever sets `traceparent`/`tracestate`, which are always valid ASCII).
struct MetadataInjectorMut<'a>(&'a mut MetadataMap);

impl Injector for MetadataInjectorMut<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(k), Ok(v)) = (
            MetadataKey::from_bytes(key.as_bytes()),
            MetadataValue::try_from(value),
        ) {
            self.0.insert(k, v);
        }
    }
}

/// A live telemetry pipeline. Dropping it flushes and shuts the exporter down so a
/// clean process exit does not lose the last spans/metrics. Cheap when the
/// exporter is off.
pub struct TelemetryGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(p) = self.provider.take() {
            let _ = p.shutdown();
        }
        if let Some(m) = self.meter_provider.take() {
            let _ = m.shutdown();
        }
    }
}

/// Install the tracing subscriber (fmt), and — only when
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set — an OpenTelemetry OTLP export layer plus
/// the global W3C propagator. Honours `RUST_LOG` (default `info`) exactly as
/// before; the OTLP layer is purely additive.
///
/// Telemetry is observability, not a security control: an unreachable/misconfigured
/// collector **degrades to local logging** (a warning) rather than aborting the
/// Tier-0 data plane. It must be called once, early, inside the tokio runtime.
pub fn init() -> TelemetryGuard {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer().with_target(false);

    let endpoint = std::env::var(OTLP_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    let Some(endpoint) = endpoint else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .init();
        return TelemetryGuard {
            provider: None,
            meter_provider: None,
        };
    };

    match build_provider(&endpoint) {
        Ok(provider) => {
            use opentelemetry::trace::TracerProvider as _;
            let tracer = provider.tracer(service_name());
            opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
            opentelemetry::global::set_tracer_provider(provider.clone());
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
            // Metrics ride the SAME OTLP endpoint via a push-only PeriodicReader —
            // no inbound listener on the Tier-0 box. A failure here degrades to
            // traces+logs only (telemetry is observability, not a security control).
            let meter_provider = match build_meter_provider(&endpoint) {
                Ok(mp) => {
                    opentelemetry::global::set_meter_provider(mp.clone());
                    Some(mp)
                }
                Err(e) => {
                    tracing::warn!(error = %e, endpoint = %endpoint, "OTLP metric exporter setup failed; continuing without native gauges");
                    None
                }
            };
            tracing::info!(
                endpoint = %endpoint,
                service = %service_name(),
                metrics = meter_provider.is_some(),
                "OpenTelemetry OTLP export enabled (tonic/ring)"
            );
            TelemetryGuard {
                provider: Some(provider),
                meter_provider,
            }
        }
        Err(e) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
            tracing::warn!(error = %e, endpoint = %endpoint, "OTLP exporter setup failed; continuing with local logging only (telemetry is not fail-closed)");
            TelemetryGuard {
                provider: None,
                meter_provider: None,
            }
        }
    }
}

fn service_name() -> String {
    std::env::var(SERVICE_NAME_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string())
}

fn build_provider(
    endpoint: &str,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider, Box<dyn std::error::Error>> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name())
        .build();
    Ok(opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}

fn build_meter_provider(
    endpoint: &str,
) -> Result<opentelemetry_sdk::metrics::SdkMeterProvider, Box<dyn std::error::Error>> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name())
        .build();
    Ok(opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .with_resource(resource)
        .build())
}

/// The two native saturation gauges (S24 Part C; CARRYFORWARDS B5) — the RED spans
/// cannot derive these. Registered on the global meter (inert when the OTLP
/// endpoint is unset). Observable/pull: the callbacks read live state on export,
/// so there is no push loop and nothing new to seccomp-allow.
///
/// * `sessionlayer.gateway.live_sessions` — active outer-leg sessions.
/// * `sessionlayer.gateway.lock_feed_healthy` — 1 iff the lock feed is healthy, else 0
///   (0 ⇒ the Gateway is failing new privileged channel-opens closed, FR-CHAN-4).
pub fn register_gateway_gauges(
    live_sessions: std::sync::Arc<crate::ssh::locks::LiveSessionRegistry>,
    lock_set: std::sync::Arc<crate::ssh::locks::LockSet>,
) {
    let meter = opentelemetry::global::meter(DEFAULT_SERVICE_NAME);
    register_gateway_gauges_on(
        &meter,
        move || live_sessions.len() as u64,
        move || u64::from(lock_set.healthy()),
    );
}

/// Register the gauges against an explicit meter with explicit value sources — the
/// seam a test drives with a `ManualReader` to prove the emitted values track state.
pub fn register_gateway_gauges_on<L, H>(
    meter: &opentelemetry::metrics::Meter,
    live_sessions: L,
    lock_feed_healthy: H,
) where
    L: Fn() -> u64 + Send + Sync + 'static,
    H: Fn() -> u64 + Send + Sync + 'static,
{
    meter
        .u64_observable_gauge("sessionlayer.gateway.live_sessions")
        .with_description("Active outer-leg SSH sessions on this Gateway.")
        .with_callback(move |obs| obs.observe(live_sessions(), &[]))
        .build();
    meter
        .u64_observable_gauge("sessionlayer.gateway.lock_feed_healthy")
        .with_description("1 iff the CP lock feed is healthy, else 0 (fail-closed re-validate).")
        .with_callback(move |obs| obs.observe(lock_feed_healthy(), &[]))
        .build();
}

/// The span attribute keys the fail-closed marker sets (also declared `Empty` on
/// the `gateway.session` root so they can be recorded after creation).
pub const OTEL_STATUS_CODE: &str = "otel.status_code";

/// Mark a session span as a fail-closed / error outcome (S24 Part C, S23 A8): sets
/// the OTel span **status to error** so the span-metrics RED error-rate actually
/// reflects denials (a recorded `sessionlayer.outcome` alone leaves status Unset,
/// so the derived error-rate was blind to fail-closed denials). `outcome` is a
/// stable enum label — never content. No-op cost when the exporter is off.
///
/// **RED coverage (OTEL-CONTRACT §4, SEC-F2):** the error-rate deliberately covers
/// the connect-phase denials (via `close_with`) **and** CP-down at the auth phase
/// (via `note_cp_down`) — the genuine fail-closed faults. It excludes ordinary
/// auth-phase rejections (`SourceBlocked`/`AuthFailed`/`DeviceFlowTimeout`), which
/// are normal internet noise, not faults; erroring those would peg the rate near
/// 100% and destroy the SLO signal. That is why [`SshOutcome::span_label`]
/// enumerates all 7 outcomes but only the fault outcomes reach this function.
pub fn record_span_fail_closed(span: &tracing::Span, outcome: &str) {
    span.record(attr::OUTCOME, outcome);
    span.record(OTEL_STATUS_CODE, "error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::propagation::Injector;

    #[test]
    fn metadata_injector_sets_only_valid_ascii_keys() {
        let mut md = MetadataMap::new();
        let mut inj = MetadataInjectorMut(&mut md);
        inj.set("traceparent", "00-abc-def-01".to_string());
        // A non-ASCII key is skipped, never panics.
        inj.set("tráce", "x".to_string());
        assert_eq!(
            md.get("traceparent")
                .map(|v| v.to_str().unwrap().to_string()),
            Some("00-abc-def-01".to_string())
        );
        assert!(md.get("tráce").is_none());
    }

    #[test]
    fn service_name_defaults_when_unset() {
        // Do not clobber a real env in CI; only assert the default path shape.
        if std::env::var(SERVICE_NAME_ENV).is_err() {
            assert_eq!(service_name(), DEFAULT_SERVICE_NAME);
        }
    }

    /// S23 A8 fix: the fail-closed / error path MUST set the span **status to
    /// error**, or the span-metrics RED error-rate is blind to denials (recording
    /// only `sessionlayer.outcome` leaves the status Unset). Read the exported span
    /// back and assert the status the `spanmetrics` connector reads.
    #[test]
    fn fail_closed_path_sets_span_status_error() {
        use opentelemetry::trace::{Status, TracerProvider as _};
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::prelude::*;

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));

        tracing::subscriber::with_default(subscriber, || {
            // A `gateway.session`-shaped root that declares the two fields the marker
            // records after creation (exactly as the real handler span does).
            let span = tracing::info_span!(
                "gateway.session",
                sessionlayer.outcome = tracing::field::Empty,
                otel.status_code = tracing::field::Empty,
            );
            let entered = span.enter();
            record_span_fail_closed(&span, "policy_denied");
            drop(entered);
        });

        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        let s = spans
            .iter()
            .find(|s| s.name == "gateway.session")
            .expect("the session span was exported");
        assert_eq!(
            s.status,
            Status::error(""),
            "a fail-closed denial must mark the span status error (RED error-rate)"
        );
        assert!(
            s.attributes
                .iter()
                .any(|kv| kv.key.as_str() == attr::OUTCOME),
            "the fail-closed outcome enum is recorded on the span (never content)"
        );
    }

    /// SEC-F2: a CP outage at the AUTH phase (`note_cp_down`, before any channel) is a
    /// genuine fail-closed fault and MUST error the span so a CP-down storm shows in
    /// the RED error-rate; an ordinary auth rejection (`AuthFailed`, never passed to
    /// `record_span_fail_closed`) must NOT error the span, or the rate pegs on
    /// internet noise and the SLO signal is lost.
    #[test]
    fn cp_down_at_auth_errors_the_span_but_auth_noise_does_not() {
        use opentelemetry::trace::{Status, TracerProvider as _};
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::prelude::*;

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));

        tracing::subscriber::with_default(subscriber, || {
            // CP-down at auth: exactly what `note_cp_down` does.
            let cp_down = tracing::info_span!(
                "gateway.session",
                marker = "cp_down",
                sessionlayer.outcome = tracing::field::Empty,
                otel.status_code = tracing::field::Empty,
            );
            {
                let _e = cp_down.enter();
                record_span_fail_closed(&cp_down, "cp_unavailable");
            }
            // Ordinary AuthFailed: russh rejects, `close_with` never runs, and nothing
            // marks the span — it ends Unset (normal noise, not a fault).
            let auth_noise = tracing::info_span!(
                "gateway.session",
                marker = "auth_noise",
                sessionlayer.outcome = tracing::field::Empty,
                otel.status_code = tracing::field::Empty,
            );
            let _e = auth_noise.enter();
        });

        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        let by_marker = |m: &str| {
            spans
                .iter()
                .find(|s| {
                    s.attributes.iter().any(|kv| {
                        kv.key.as_str() == "marker"
                            && matches!(&kv.value, opentelemetry::Value::String(v) if v.as_str() == m)
                    })
                })
                .unwrap_or_else(|| panic!("span {m} exported"))
        };
        assert_eq!(
            by_marker("cp_down").status,
            Status::error(""),
            "CP-down at the auth phase must error the span so it is visible in RED error-rate"
        );
        assert_eq!(
            by_marker("auth_noise").status,
            Status::Unset,
            "an ordinary auth rejection must NOT error the span (preserve the SLO signal)"
        );
    }

    /// The two native saturation gauges (S24 Part C; CARRYFORWARDS B5) emit the
    /// live state on export: a session raises `live_sessions`, and an unhealthy
    /// lock feed drops `lock_feed_healthy` to 0. Drive a real [`LockSet`] as the
    /// health source (exactly what `register_gateway_gauges` wires) and read the
    /// values back through an in-memory exporter.
    #[test]
    fn native_gauges_reflect_live_state() {
        use opentelemetry::metrics::MeterProvider as _;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
        use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_periodic_exporter(exporter.clone())
            .build();
        let meter = provider.meter("test");

        // `live` is an atomic the test bumps to stand in for the registry length
        // (production wires `live_sessions.len()`); `lock` is the REAL LockSet whose
        // `healthy()` the production gauge reads verbatim.
        let live = Arc::new(AtomicU64::new(0));
        let lock = Arc::new(crate::ssh::locks::LockSet::new(30, 30));
        let live_src = live.clone();
        let lock_src = lock.clone();
        register_gateway_gauges_on(
            &meter,
            move || live_src.load(Ordering::SeqCst),
            move || u64::from(lock_src.healthy()),
        );

        let read = |name: &str| -> u64 {
            exporter.reset();
            provider.force_flush().unwrap();
            let rms: Vec<ResourceMetrics> = exporter.get_finished_metrics().unwrap();
            for rm in &rms {
                for sm in rm.scope_metrics() {
                    for m in sm.metrics() {
                        if m.name() == name {
                            if let AggregatedMetrics::U64(MetricData::Gauge(g)) = m.data() {
                                return g.data_points().next().map(|dp| dp.value()).unwrap_or(0);
                            }
                        }
                    }
                }
            }
            0
        };

        // Empty registry + a disconnected feed → 0 / 0.
        assert_eq!(read("sessionlayer.gateway.live_sessions"), 0);
        assert_eq!(read("sessionlayer.gateway.lock_feed_healthy"), 0);

        // A live session raises live_sessions; a snapshot makes the feed healthy → 1.
        live.store(3, Ordering::SeqCst);
        lock.replace_snapshot(Vec::new(), 1);
        assert_eq!(read("sessionlayer.gateway.live_sessions"), 3);
        assert_eq!(read("sessionlayer.gateway.lock_feed_healthy"), 1);

        // The feed drops (disconnect) → lock_feed_healthy back to 0 (fail-closed signal).
        lock.mark_disconnected();
        assert_eq!(read("sessionlayer.gateway.lock_feed_healthy"), 0);
    }
}
