//! Native OTel counters for the HA / node-reachability plane. They export through the
//! SAME meter provider [`super::init`] installs (one OTLP path, no second mechanism) and
//! **complement** the structured log lines — the logs keep the diagnostic detail.
//!
//! Cardinality is an operational hazard, not a style question: every attribute value here
//! comes from a closed Rust enum. A session id, node id, node name, agent id, lock id or
//! source IP MUST NOT reach a metric attribute — those stay on the log line.

use std::sync::OnceLock;

use opentelemetry::metrics::Counter;
use opentelemetry::KeyValue;

pub const NODE_UNREACHABLE: &str = "sessionlayer.gateway.node_unreachable";
pub const PEER_RELAYS_SERVED: &str = "sessionlayer.gateway.peer_relays_served";
pub const PEER_RELAYS_CLOSED: &str = "sessionlayer.gateway.peer_relays_closed";
pub const PEER_RELAYS_DECLINED: &str = "sessionlayer.gateway.peer_relays_declined";
pub const PRESENCE_TRANSITIONS: &str = "sessionlayer.gateway.presence_transitions";
pub const PRESENCE_HEARTBEAT_FAILURES: &str = "sessionlayer.gateway.presence_heartbeat_failures";

pub const ATTR_REASON: &str = "reason";
pub const ATTR_LAYER: &str = "layer";
pub const ATTR_TRANSITION: &str = "transition";

/// The `outcome=` log label for a fail-closed node-reachability failure. It is private on
/// purpose: a call site can only obtain it from [`Counted::outcome`], which only
/// [`node_unreachable`] can mint — so the log label and the counter cannot drift apart.
const OUTCOME_NODE_UNREACHABLE: &str = "node_unreachable";

/// Where the failure was detected. Derived from the reason, never passed in, so no site can
/// mislabel it. Summing across layers double-counts one session (a `route`/`dial` cause also
/// surfaces as a `session` outcome); `layer="session"` is the user-visible failure count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// HA owner selection and the peer relay (`ha::connector`).
    Route,
    /// Reaching the node itself: outbound-agent dial-back and agent-channel loss.
    Dial,
    /// The SSH surface — what the client's session actually ended as.
    Session,
}

impl Layer {
    const fn as_str(self) -> &'static str {
        match self {
            Layer::Route => "route",
            Layer::Dial => "dial",
            Layer::Session => "session",
        }
    }
}

/// Bounded causes for a fail-closed node-unreachable event; one variant per call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableReason {
    NoFreshOwner,
    RelayLedgerFull,
    CoordinationPublishFailed,
    RelayRejected,
    RelayTimeout,

    NoAgentRegistered,
    LockFeedUnhealthy,
    AgentLocked,
    AgentSignalSaturated,
    AgentDisconnected,
    AgentRefusedOrLocalDialFailed,
    DialBackTimeout,
    MissedHeartbeats,

    NoNodeConnection,
    NoHostVerificationMaterial,
    AgentNodeWithoutName,
    NodeConnectFailed,
    InnerKeypairFailed,
    InnerCertRejected,
    InnerCertUnparseable,
    InnerKeyUnusable,
    HostVerificationFailed,
    InnerHandshakeFailed,
    ChannelOpenFailed,
    OuterChannelLost,
    LocalForwardDialFailed,
    RemoteForwardBindFailed,
    HostCertUnavailable,
}

impl UnreachableReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            UnreachableReason::NoFreshOwner => "no_fresh_owner",
            UnreachableReason::RelayLedgerFull => "relay_ledger_full",
            UnreachableReason::CoordinationPublishFailed => "coordination_publish_failed",
            UnreachableReason::RelayRejected => "relay_rejected",
            UnreachableReason::RelayTimeout => "relay_timeout",

            UnreachableReason::NoAgentRegistered => "no_agent_registered",
            UnreachableReason::LockFeedUnhealthy => "lock_feed_unhealthy",
            UnreachableReason::AgentLocked => "agent_locked",
            UnreachableReason::AgentSignalSaturated => "agent_signal_saturated",
            UnreachableReason::AgentDisconnected => "agent_disconnected",
            UnreachableReason::AgentRefusedOrLocalDialFailed => {
                "agent_refused_or_local_dial_failed"
            }
            UnreachableReason::DialBackTimeout => "dial_back_timeout",
            UnreachableReason::MissedHeartbeats => "missed_heartbeats",

            UnreachableReason::NoNodeConnection => "no_node_connection",
            UnreachableReason::NoHostVerificationMaterial => "no_host_verification_material",
            UnreachableReason::AgentNodeWithoutName => "agent_node_without_name",
            UnreachableReason::NodeConnectFailed => "node_connect_failed",
            UnreachableReason::InnerKeypairFailed => "inner_keypair_failed",
            UnreachableReason::InnerCertRejected => "inner_cert_rejected",
            UnreachableReason::InnerCertUnparseable => "inner_cert_unparseable",
            UnreachableReason::InnerKeyUnusable => "inner_key_unusable",
            UnreachableReason::HostVerificationFailed => "host_verification_failed",
            UnreachableReason::InnerHandshakeFailed => "inner_handshake_failed",
            UnreachableReason::ChannelOpenFailed => "channel_open_failed",
            UnreachableReason::OuterChannelLost => "outer_channel_lost",
            UnreachableReason::LocalForwardDialFailed => "local_forward_dial_failed",
            UnreachableReason::RemoteForwardBindFailed => "remote_forward_bind_failed",
            UnreachableReason::HostCertUnavailable => "host_cert_unavailable",
        }
    }

    pub const fn layer(self) -> Layer {
        match self {
            UnreachableReason::NoFreshOwner
            | UnreachableReason::RelayLedgerFull
            | UnreachableReason::CoordinationPublishFailed
            | UnreachableReason::RelayRejected
            | UnreachableReason::RelayTimeout => Layer::Route,

            UnreachableReason::NoAgentRegistered
            | UnreachableReason::LockFeedUnhealthy
            | UnreachableReason::AgentLocked
            | UnreachableReason::AgentSignalSaturated
            | UnreachableReason::AgentDisconnected
            | UnreachableReason::AgentRefusedOrLocalDialFailed
            | UnreachableReason::DialBackTimeout
            | UnreachableReason::MissedHeartbeats => Layer::Dial,

            UnreachableReason::NoNodeConnection
            | UnreachableReason::NoHostVerificationMaterial
            | UnreachableReason::AgentNodeWithoutName
            | UnreachableReason::NodeConnectFailed
            | UnreachableReason::InnerKeypairFailed
            | UnreachableReason::InnerCertRejected
            | UnreachableReason::InnerCertUnparseable
            | UnreachableReason::InnerKeyUnusable
            | UnreachableReason::HostVerificationFailed
            | UnreachableReason::InnerHandshakeFailed
            | UnreachableReason::ChannelOpenFailed
            | UnreachableReason::OuterChannelLost
            | UnreachableReason::LocalForwardDialFailed
            | UnreachableReason::RemoteForwardBindFailed
            | UnreachableReason::HostCertUnavailable => Layer::Session,
        }
    }
}

/// Proof that a node-unreachable event was counted, and the only source of its two log
/// labels. Its field is private to this module, so `SshOutcome::NodeUnreachable` cannot be
/// constructed anywhere in the crate without going through [`node_unreachable`] — a new
/// fail-closed site cannot forget the counter, and the compiler says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counted(UnreachableReason);

impl Counted {
    pub const fn outcome(self) -> &'static str {
        OUTCOME_NODE_UNREACHABLE
    }

    pub const fn reason(self) -> &'static str {
        self.0.as_str()
    }
}

#[must_use = "the Counted labels belong on the log line that reports this failure"]
pub fn node_unreachable(reason: UnreachableReason) -> Counted {
    counters().node_unreachable.add(
        1,
        &[
            KeyValue::new(ATTR_REASON, reason.as_str()),
            KeyValue::new(ATTR_LAYER, reason.layer().as_str()),
        ],
    );
    Counted(reason)
}

/// Why an owner declined a peer's dial-back signal. Every variant is fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDecline {
    NotOwner,
    StaleNonce,
    PerNodeCap,
    LocalDial,
    Connect,
    Handshake,
    Tls,
}

impl RelayDecline {
    const fn as_str(self) -> &'static str {
        match self {
            RelayDecline::NotOwner => "not_owner",
            RelayDecline::StaleNonce => "stale_nonce",
            RelayDecline::PerNodeCap => "per_node_cap",
            RelayDecline::LocalDial => "local_dial",
            RelayDecline::Connect => "connect",
            RelayDecline::Handshake => "handshake",
            RelayDecline::Tls => "tls",
        }
    }
}

pub fn peer_relay_served() {
    counters().peer_relays_served.add(1, &[]);
}

pub fn peer_relay_closed() {
    counters().peer_relays_closed.add(1, &[]);
}

pub fn peer_relay_declined(reason: RelayDecline) {
    counters()
        .peer_relays_declined
        .add(1, &[KeyValue::new(ATTR_REASON, reason.as_str())]);
}

/// A change in this Gateway's CP-confirmed ownership of a node — not the per-tick log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceTransition {
    /// This Gateway now owns a node it did not own last tick.
    Acquired,
    /// A peer now owns a node this Gateway owned (failover away from us).
    Standby,
    /// Ownership handed back on drain or on the agent channel dropping.
    Released,
    /// The release RPC failed: ownership lingers until the CP staleness TTL expires.
    ReleaseFailed,
}

impl PresenceTransition {
    const fn as_str(self) -> &'static str {
        match self {
            PresenceTransition::Acquired => "acquired",
            PresenceTransition::Standby => "standby",
            PresenceTransition::Released => "released",
            PresenceTransition::ReleaseFailed => "release_failed",
        }
    }
}

pub fn presence_transition(transition: PresenceTransition) {
    counters()
        .presence_transitions
        .add(1, &[KeyValue::new(ATTR_TRANSITION, transition.as_str())]);
}

/// Coarse CP-failure class. The gRPC status code stays in the log line (`error = %e`);
/// promoting it to an attribute would widen the series for no alerting gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpFailure {
    Unreachable,
    CircuitOpen,
    Timeout,
    Rpc,
}

impl CpFailure {
    const fn as_str(self) -> &'static str {
        match self {
            CpFailure::Unreachable => "unreachable",
            CpFailure::CircuitOpen => "circuit_open",
            CpFailure::Timeout => "timeout",
            CpFailure::Rpc => "rpc",
        }
    }
}

pub fn presence_heartbeat_failure(cause: CpFailure) {
    counters()
        .presence_heartbeat_failures
        .add(1, &[KeyValue::new(ATTR_REASON, cause.as_str())]);
}

struct GatewayCounters {
    node_unreachable: Counter<u64>,
    peer_relays_served: Counter<u64>,
    peer_relays_closed: Counter<u64>,
    peer_relays_declined: Counter<u64>,
    presence_transitions: Counter<u64>,
    presence_heartbeat_failures: Counter<u64>,
}

impl GatewayCounters {
    fn new(meter: &opentelemetry::metrics::Meter) -> Self {
        Self {
            node_unreachable: meter
                .u64_counter(NODE_UNREACHABLE)
                .with_description(
                    "Fail-closed node-reachability failures, by cause and by the layer that detected them.",
                )
                .build(),
            peer_relays_served: meter
                .u64_counter(PEER_RELAYS_SERVED)
                .with_description(
                    "Peer relays this Gateway began serving as the owner of a node (HA cross-gateway sessions).",
                )
                .build(),
            peer_relays_closed: meter
                .u64_counter(PEER_RELAYS_CLOSED)
                .with_description(
                    "Peer relays that finished; served minus closed is the in-flight relay count.",
                )
                .build(),
            peer_relays_declined: meter
                .u64_counter(PEER_RELAYS_DECLINED)
                .with_description(
                    "Dial-back signals this Gateway refused to serve (fail-closed; the ingress times out).",
                )
                .build(),
            presence_transitions: meter
                .u64_counter(PRESENCE_TRANSITIONS)
                .with_description(
                    "Changes in this Gateway's CP-confirmed ownership of a node (acquired/standby/released).",
                )
                .build(),
            presence_heartbeat_failures: meter
                .u64_counter(PRESENCE_HEARTBEAT_FAILURES)
                .with_description(
                    "Presence heartbeats that failed; the Gateway does not own the node for that tick (fail-closed).",
                )
                .build(),
        }
    }
}

static COUNTERS: OnceLock<GatewayCounters> = OnceLock::new();

fn counters() -> &'static GatewayCounters {
    COUNTERS.get_or_init(|| {
        GatewayCounters::new(&opentelemetry::global::meter(super::DEFAULT_SERVICE_NAME))
    })
}

/// Bind the counters to `meter`; returns whether THIS call bound them. Binding is one-shot
/// per process because an instrument holds its provider — production binds right after
/// [`super::init`] installs the OTLP meter provider, and a test must bind before any counter
/// is touched (`cargo nextest` gives one process per test; a shared-process runner cannot
/// isolate a process-global provider).
pub fn install(meter: &opentelemetry::metrics::Meter) -> bool {
    let mut installed = false;
    COUNTERS.get_or_init(|| {
        installed = true;
        GatewayCounters::new(meter)
    });
    installed
}

pub(super) fn install_from_global() {
    install(&opentelemetry::global::meter(super::DEFAULT_SERVICE_NAME));
}

#[cfg(test)]
pub(crate) mod testutil {
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};

    /// A real SDK meter provider feeding an in-memory exporter, with the Gateway counters
    /// bound to it — the same wiring production gets from an OTLP provider.
    pub struct CounterProbe {
        exporter: InMemoryMetricExporter,
        provider: SdkMeterProvider,
    }

    impl CounterProbe {
        pub fn install() -> Self {
            use opentelemetry::metrics::MeterProvider as _;
            let exporter = InMemoryMetricExporter::default();
            let provider = SdkMeterProvider::builder()
                .with_periodic_exporter(exporter.clone())
                .build();
            assert!(
                super::install(&provider.meter("test")),
                "the counters were already bound in this process: these tests need one \
                 process per test (cargo nextest, which scripts/gate.sh runs)"
            );
            Self { exporter, provider }
        }

        /// The cumulative value of `name` for the data point carrying exactly `attrs`, or
        /// `None` when no such series has been recorded. `None` and `Some(0)` are different
        /// answers on purpose: an absent series is what a typo'd instrument name looks like.
        pub fn read(&self, name: &str, attrs: &[(&str, &str)]) -> Option<u64> {
            self.exporter.reset();
            self.provider.force_flush().unwrap();
            let rms: Vec<ResourceMetrics> = self.exporter.get_finished_metrics().unwrap();
            for rm in &rms {
                for sm in rm.scope_metrics() {
                    for m in sm.metrics().filter(|m| m.name() == name) {
                        let AggregatedMetrics::U64(MetricData::Sum(sum)) = m.data() else {
                            continue;
                        };
                        for dp in sum.data_points() {
                            let matches = attrs.iter().all(|(k, v)| {
                                dp.attributes().any(|kv| {
                                    kv.key.as_str() == *k
                                        && matches!(&kv.value,
                                            opentelemetry::Value::String(s) if s.as_str() == *v)
                                })
                            });
                            if matches {
                                return Some(dp.value());
                            }
                        }
                    }
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::CounterProbe;
    use super::*;

    /// The session-layer counter moves on the real minting path, the reader can tell an
    /// unrecorded series from a recorded one, and the log labels an operator greps come from
    /// the same mint. Also pins the guarantee the [`Counted`] token exists for: the
    /// `SshOutcome` variant cannot be built without it.
    #[test]
    fn node_unreachable_counts_at_the_mint_and_carries_the_log_labels() {
        let probe = CounterProbe::install();
        let relay_timeout = [(ATTR_REASON, "relay_timeout"), (ATTR_LAYER, "route")];
        let no_conn = [(ATTR_REASON, "no_node_connection"), (ATTR_LAYER, "session")];

        // Nothing recorded yet: absent, not zero.
        assert_eq!(probe.read(NODE_UNREACHABLE, &no_conn), None);
        assert_eq!(probe.read(NODE_UNREACHABLE, &relay_timeout), None);

        let counted = node_unreachable(UnreachableReason::NoNodeConnection);
        assert_eq!(counted.outcome(), "node_unreachable");
        assert_eq!(counted.reason(), "no_node_connection");
        assert_eq!(
            crate::ssh::outcome::SshOutcome::NodeUnreachable(counted).span_label(),
            "node_unreachable",
            "the span label must not drift from the counted outcome"
        );

        // The SAME reader that returned None now sees the increment — so a None above is a
        // real absence, not a broken lookup.
        assert_eq!(probe.read(NODE_UNREACHABLE, &no_conn), Some(1));
        assert_eq!(
            probe.read(NODE_UNREACHABLE, &relay_timeout),
            None,
            "an unrelated reason must not be credited"
        );

        let _ = node_unreachable(UnreachableReason::NoNodeConnection);
        let _ = node_unreachable(UnreachableReason::RelayTimeout);
        assert_eq!(probe.read(NODE_UNREACHABLE, &no_conn), Some(2));
        assert_eq!(probe.read(NODE_UNREACHABLE, &relay_timeout), Some(1));

        // A misspelled instrument name is indistinguishable from a real absence, which is
        // exactly why the assertions above pair None with a later Some.
        assert_eq!(
            probe.read("sessionlayer.gateway.node_unreachables", &no_conn),
            None
        );
    }

    #[test]
    fn every_reason_is_a_distinct_bounded_label_in_the_right_layer() {
        use std::collections::HashSet;
        let all = [
            UnreachableReason::NoFreshOwner,
            UnreachableReason::RelayLedgerFull,
            UnreachableReason::CoordinationPublishFailed,
            UnreachableReason::RelayRejected,
            UnreachableReason::RelayTimeout,
            UnreachableReason::NoAgentRegistered,
            UnreachableReason::LockFeedUnhealthy,
            UnreachableReason::AgentLocked,
            UnreachableReason::AgentSignalSaturated,
            UnreachableReason::AgentDisconnected,
            UnreachableReason::AgentRefusedOrLocalDialFailed,
            UnreachableReason::DialBackTimeout,
            UnreachableReason::MissedHeartbeats,
            UnreachableReason::NoNodeConnection,
            UnreachableReason::NoHostVerificationMaterial,
            UnreachableReason::AgentNodeWithoutName,
            UnreachableReason::NodeConnectFailed,
            UnreachableReason::InnerKeypairFailed,
            UnreachableReason::InnerCertRejected,
            UnreachableReason::InnerCertUnparseable,
            UnreachableReason::InnerKeyUnusable,
            UnreachableReason::HostVerificationFailed,
            UnreachableReason::InnerHandshakeFailed,
            UnreachableReason::ChannelOpenFailed,
            UnreachableReason::OuterChannelLost,
            UnreachableReason::LocalForwardDialFailed,
            UnreachableReason::RemoteForwardBindFailed,
            UnreachableReason::HostCertUnavailable,
        ];
        let labels: HashSet<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), all.len(), "reason labels must be distinct");
        assert_eq!(UnreachableReason::RelayTimeout.layer(), Layer::Route);
        assert_eq!(UnreachableReason::DialBackTimeout.layer(), Layer::Dial);
        assert_eq!(
            UnreachableReason::InnerKeypairFailed.layer(),
            Layer::Session
        );
    }

    /// The `outcome = "node_unreachable"` label may exist in exactly one place: this module.
    /// Anywhere else it would be a log line with no counter behind it — the drift this whole
    /// item exists to stop. The [`Counted`] token blocks that for `SshOutcome` sites at
    /// compile time; this guards the log-only sites, which the compiler cannot see.
    #[test]
    fn the_outcome_label_is_minted_in_exactly_one_place() {
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let mut walk = vec![src.clone()];
        while let Some(dir) = walk.pop() {
            for entry in std::fs::read_dir(&dir).expect("src is readable") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                scanned += 1;
                let text = std::fs::read_to_string(&path).expect("source is utf-8");
                if !text.contains("\"node_unreachable\"") {
                    continue;
                }
                let rel = path.strip_prefix(&src).unwrap().to_path_buf();
                if rel != std::path::Path::new("telemetry/metrics.rs") {
                    offenders.push(rel);
                }
            }
        }
        assert!(
            scanned > 20,
            "the scan found only {scanned} source files; it is not looking where it thinks"
        );
        assert!(
            offenders.is_empty(),
            "the node_unreachable outcome label must come from Counted::outcome(); \
             literal(s) found in {offenders:?}"
        );
    }

    #[test]
    fn relay_and_presence_labels_are_bounded_and_distinct() {
        use std::collections::HashSet;
        let declines = [
            RelayDecline::NotOwner,
            RelayDecline::StaleNonce,
            RelayDecline::PerNodeCap,
            RelayDecline::LocalDial,
            RelayDecline::Connect,
            RelayDecline::Handshake,
            RelayDecline::Tls,
        ];
        let labels: HashSet<&str> = declines.iter().map(|d| d.as_str()).collect();
        assert_eq!(labels.len(), declines.len());

        let transitions = [
            PresenceTransition::Acquired,
            PresenceTransition::Standby,
            PresenceTransition::Released,
            PresenceTransition::ReleaseFailed,
        ];
        let labels: HashSet<&str> = transitions.iter().map(|t| t.as_str()).collect();
        assert_eq!(labels.len(), transitions.len());

        let causes = [
            CpFailure::Unreachable,
            CpFailure::CircuitOpen,
            CpFailure::Timeout,
            CpFailure::Rpc,
        ];
        let labels: HashSet<&str> = causes.iter().map(|c| c.as_str()).collect();
        assert_eq!(labels.len(), causes.len());
    }
}
