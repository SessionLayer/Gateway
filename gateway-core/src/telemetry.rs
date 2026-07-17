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
/// clean process exit does not lose the last spans. Cheap when the exporter is off.
pub struct TelemetryGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(p) = self.provider.take() {
            let _ = p.shutdown();
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
        return TelemetryGuard { provider: None };
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
            tracing::info!(
                endpoint = %endpoint,
                service = %service_name(),
                "OpenTelemetry OTLP trace export enabled (tonic/ring)"
            );
            TelemetryGuard {
                provider: Some(provider),
            }
        }
        Err(e) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
            tracing::warn!(error = %e, endpoint = %endpoint, "OTLP exporter setup failed; continuing with local logging only (telemetry is not fail-closed)");
            TelemetryGuard { provider: None }
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
}
