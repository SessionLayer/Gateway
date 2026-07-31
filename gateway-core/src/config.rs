use crate::asyncio::IoBackend;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Gateway configuration; `deny_unknown_fields` fails misconfiguration closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    pub io_backend: IoBackend,
    pub cp_endpoint: String,
    pub cp_mtls_endpoint: String,
    pub data_dir: PathBuf,
    pub bootstrap: Option<BootstrapConfig>,
    pub identity: IdentityConfig,
    pub ssh: SshServerConfig,
    pub ha: HaConfig,
    pub hardening: HardeningConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            io_backend: IoBackend::Epoll,
            cp_endpoint: "http://127.0.0.1:9090".to_string(),
            cp_mtls_endpoint: "https://127.0.0.1:9443".to_string(),
            data_dir: PathBuf::from("/var/lib/sessionlayer-gateway"),
            bootstrap: None,
            identity: IdentityConfig::default(),
            ssh: SshServerConfig::default(),
            ha: HaConfig::default(),
            hardening: HardeningConfig::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading gateway config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing gateway config {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

impl GatewayConfig {
    pub const CONFIG_ENV: &'static str = "SL_GATEWAY_CONFIG";

    pub fn load(explicit: Option<&Path>) -> Result<Self, ConfigError> {
        let from_env = std::env::var_os(Self::CONFIG_ENV).map(PathBuf::from);
        match explicit.map(Path::to_path_buf).or(from_env) {
            Some(path) => Self::load_from_path(&path),
            None => Ok(Self::default()),
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HaConfig {
    pub mode: HaMode,
    pub coordination: CoordinationConfig,
    pub peer_relay_advertise_addr: String,
    pub presence: PresenceConfig,
    pub routing: RoutingConfig,
    pub drain: DrainConfig,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            mode: HaMode::SingleInstance,
            coordination: CoordinationConfig::default(),
            peer_relay_advertise_addr: String::new(),
            presence: PresenceConfig::default(),
            routing: RoutingConfig::default(),
            drain: DrainConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaMode {
    SingleInstance,
    Ha,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinationConfig {
    #[default]
    InProcess,
    Nats {
        url: String,
        #[serde(default = "default_subject_prefix")]
        subject_prefix: String,
    },
}

fn default_subject_prefix() -> String {
    "sl".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PresenceConfig {
    pub heartbeat_interval_secs: u64,
    pub staleness_ttl_secs: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            staleness_ttl_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    pub relay_timeout_secs: u64,
    pub cache_ttl_secs: u64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            relay_timeout_secs: 25,
            cache_ttl_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DrainConfig {
    pub pre_drain_grace_secs: u64,
    pub deadline_secs: u64,
    pub readyz_addr: String,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            pre_drain_grace_secs: 5,
            deadline_secs: 30,
            readyz_addr: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshServerConfig {
    pub listen_addr: String,
    pub host_key_path: PathBuf,
    pub login_grace_secs: u64,
    pub handshake_timeout_secs: u64,
    pub max_connections: usize,
    pub max_auth_attempts: usize,
    pub proxy: ProxyProtocolConfig,
    pub source_ip_allowlist: Vec<String>,
    pub target_separator: char,
    pub node_dns_suffixes: Vec<String>,
    pub proxy_jump: ProxyJumpConfig,
    pub device_flow: DeviceFlowConfig,
    pub cp_connect_timeout_secs: u64,
    pub cp_rpc_timeout_secs: u64,
    pub inner: InnerLegServerConfig,
    pub recorder: RecorderConfig,
    pub reeval: ReevalConfig,
    pub break_glass: BreakGlassConfig,
    pub agent: AgentTransportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentTransportConfig {
    pub listen_addr: String,
    pub advertise_url: String,
    pub heartbeat_interval_secs: u64,
    pub max_frame_bytes: usize,
    pub dial_back_token_ttl_secs: i64,
    pub dial_back_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub max_agents: usize,
    pub max_connections: usize,
}

impl Default for AgentTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            advertise_url: String::new(),
            heartbeat_interval_secs: 20,
            max_frame_bytes: 64 * 1024,
            dial_back_token_ttl_secs: 30,
            dial_back_timeout_secs: 10,
            handshake_timeout_secs: 10,
            max_agents: 1024,
            max_connections: 4096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BreakGlassConfig {
    pub enabled: bool,
    pub mid_session_expiry: MidSessionExpiryMode,
}

impl Default for BreakGlassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mid_session_expiry: MidSessionExpiryMode::GraceThenKill,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReevalConfig {
    pub max_decision_ttl_secs: i64,
    pub grant_expiry_skew_secs: i64,
    pub lock_expiry_skew_secs: i64,
    pub lock_feed_unhealthy_after_secs: u64,
    pub lock_feed_connect_timeout_secs: u64,
    pub mid_session_expiry: MidSessionExpiryMode,
    pub mid_session_grace_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MidSessionExpiryMode {
    RunToTtl,
    GraceThenKill,
    HardKill,
}

impl Default for ReevalConfig {
    fn default() -> Self {
        Self {
            max_decision_ttl_secs: 60,
            grant_expiry_skew_secs: 30,
            lock_expiry_skew_secs: 30,
            lock_feed_unhealthy_after_secs: 30,
            lock_feed_connect_timeout_secs: 5,
            mid_session_expiry: MidSessionExpiryMode::RunToTtl,
            mid_session_grace_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecorderConfig {
    pub strict: bool,
    pub spool_dir: Option<PathBuf>,
    pub spool_memory_threshold_bytes: usize,
    pub max_object_bytes: u64,
    pub frame_plaintext_bytes: usize,
    pub upload_timeout_secs: u64,
    pub upload_max_attempts: u32,
    pub require_https: bool,
    pub upload_ca_pem_path: Option<PathBuf>,
    pub finalize_max_attempts: u32,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            strict: true,
            spool_dir: None,
            spool_memory_threshold_bytes: 8 * 1024 * 1024,
            max_object_bytes: 4 * 1024 * 1024 * 1024,
            frame_plaintext_bytes: 16 * 1024,
            upload_timeout_secs: 30,
            upload_max_attempts: 4,
            require_https: true,
            upload_ca_pem_path: None,
            // By the time this call runs, the object is already durably in WORM storage
            // (the upload itself already retried) -- only the metadata commit is
            // missing, and unlike NotifySessionEnd there is no CP-side reaper to
            // self-heal a lost one, so it's worth retrying harder than a one-shot
            // best-effort signal.
            finalize_max_attempts: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InnerLegServerConfig {
    pub connect_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub window_bytes: u32,
    pub max_packet_bytes: u32,
    pub max_session_idle_secs: u64,
    pub max_channels_per_connection: usize,
}

impl Default for InnerLegServerConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 5,
            handshake_timeout_secs: 10,
            window_bytes: 2 * 1024 * 1024,
            max_packet_bytes: 32 * 1024,
            max_session_idle_secs: 900,
            max_channels_per_connection: 16,
        }
    }
}

impl Default for SshServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            host_key_path: PathBuf::new(),
            login_grace_secs: 300,
            handshake_timeout_secs: 10,
            max_connections: 512,
            max_auth_attempts: 6,
            proxy: ProxyProtocolConfig::default(),
            source_ip_allowlist: Vec::new(),
            target_separator: '%',
            node_dns_suffixes: Vec::new(),
            proxy_jump: ProxyJumpConfig::default(),
            device_flow: DeviceFlowConfig::default(),
            cp_connect_timeout_secs: 5,
            cp_rpc_timeout_secs: 10,
            inner: InnerLegServerConfig::default(),
            recorder: RecorderConfig::default(),
            reeval: ReevalConfig::default(),
            break_glass: BreakGlassConfig::default(),
            agent: AgentTransportConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    pub lb_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyJumpConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceFlowConfig {
    pub heartbeat_interval_secs: u64,
    pub poll_timeout_secs: u64,
}

impl Default for DeviceFlowConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            poll_timeout_secs: 180,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapConfig {
    #[serde(with = "crate::secret::serde_zeroizing_string")]
    pub enrollment_token: Zeroizing<String>,
    pub ca_cert_path: PathBuf,
    pub gateway_name: String,
    pub server_name: String,
}

impl std::fmt::Debug for BootstrapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the bearer token.
        f.debug_struct("BootstrapConfig")
            .field("enrollment_token", &"<redacted>")
            .field("ca_cert_path", &self.ca_cert_path)
            .field("gateway_name", &self.gateway_name)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enrollment_token: Zeroizing::new(String::new()),
            ca_cert_path: PathBuf::new(),
            gateway_name: String::new(),
            server_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    pub renew_ahead_fraction: f64,
    pub renew_jitter_fraction: f64,
    pub startup_renew_below_fraction: f64,
    pub connect_timeout_secs: u64,
    pub rpc_timeout_secs: u64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            startup_renew_below_fraction: 0.5,
            connect_timeout_secs: 5,
            rpc_timeout_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HardeningConfig {
    pub run_as_user: String,
    pub run_as_group: String,
    pub landlock: LandlockConfig,
    pub seccomp: SeccompConfig,
    pub disable_coredumps: bool,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            run_as_user: String::new(),
            run_as_group: String::new(),
            landlock: LandlockConfig::default(),
            seccomp: SeccompConfig::default(),
            disable_coredumps: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LandlockConfig {
    pub enabled: bool,
    pub required: bool,
    pub read_only_paths: Vec<PathBuf>,
    pub read_write_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SeccompConfig {
    pub mode: SeccompMode,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            mode: SeccompMode::Off,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompMode {
    Off,
    Log,
    Enforce,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_epoll_on_dev_endpoint_unenrolled() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.io_backend, IoBackend::Epoll);
        assert_eq!(cfg.cp_endpoint, "http://127.0.0.1:9090");
        assert_eq!(cfg.cp_mtls_endpoint, "https://127.0.0.1:9443");
        assert!(cfg.bootstrap.is_none(), "un-enrolled by default");
        assert!((cfg.identity.renew_ahead_fraction - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(cfg.identity.connect_timeout_secs, 5);
    }

    #[test]
    fn deserialises_partial_config_with_defaults() {
        // Only io_backend given; the rest fall back to defaults.
        let cfg: GatewayConfig = serde_json::from_str(r#"{"io_backend":"uring"}"#).unwrap();
        assert_eq!(cfg.io_backend, IoBackend::Uring);
        assert_eq!(cfg.cp_mtls_endpoint, "https://127.0.0.1:9443");
    }

    #[test]
    fn deserialises_bootstrap_block() {
        let cfg: GatewayConfig = serde_json::from_str(
            r#"{"bootstrap":{"enrollment_token":"t","ca_cert_path":"/etc/cp-ca.pem","gateway_name":"gw-1","server_name":"cp.internal"}}"#,
        )
        .unwrap();
        let b = cfg.bootstrap.expect("bootstrap present");
        assert_eq!(b.gateway_name, "gw-1");
        assert_eq!(b.server_name, "cp.internal");
    }

    #[test]
    fn unknown_key_fails_closed() {
        // A misspelled key must error, not be silently dropped.
        let result: Result<GatewayConfig, _> = serde_json::from_str(r#"{"io_back_end":"uring"}"#);
        assert!(result.is_err(), "unknown config key must be rejected");
    }

    #[test]
    fn hardening_sandbox_off_but_coredumps_disabled_by_default() {
        let cfg = GatewayConfig::default();
        // The sandbox steps are opt-in...
        assert!(cfg.hardening.run_as_user.is_empty(), "no privilege drop");
        assert!(!cfg.hardening.landlock.enabled, "landlock off");
        assert_eq!(cfg.hardening.seccomp.mode, SeccompMode::Off, "seccomp off");
        // ...but coredump-disable (low-risk, directly protects secrets) is ON.
        assert!(
            cfg.hardening.disable_coredumps,
            "coredumps disabled by default"
        );
    }

    #[test]
    fn hardening_parses_and_rejects_unknown_nested_key() {
        let cfg: GatewayConfig = serde_json::from_str(
            r#"{"hardening":{"run_as_user":"sessionlayer","landlock":{"enabled":true,"read_write_paths":["/var/lib/sessionlayer-gateway"]},"seccomp":{"mode":"enforce"}}}"#,
        )
        .unwrap();
        assert_eq!(cfg.hardening.run_as_user, "sessionlayer");
        assert!(cfg.hardening.landlock.enabled);
        assert_eq!(
            cfg.hardening.landlock.read_write_paths,
            vec![PathBuf::from("/var/lib/sessionlayer-gateway")]
        );
        assert_eq!(cfg.hardening.seccomp.mode, SeccompMode::Enforce);

        let bad: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"hardening":{"seccomp":{"level":"enforce"}}}"#);
        assert!(bad.is_err(), "unknown hardening key must fail closed");
    }

    #[test]
    fn unknown_nested_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"identity":{"renew_ahead":0.5}}"#);
        assert!(result.is_err(), "unknown nested key must be rejected");
    }

    #[test]
    fn ssh_defaults_are_disabled_with_safe_bounds() {
        let cfg = GatewayConfig::default();
        assert!(cfg.ssh.listen_addr.is_empty(), "SSH server off by default");
        assert_eq!(cfg.ssh.target_separator, '%');
        assert!(
            cfg.ssh.node_dns_suffixes.is_empty(),
            "wildcard DNS off by default"
        );
        assert!(cfg.ssh.proxy.lb_cidrs.is_empty(), "PROXY off by default");
        assert!(
            cfg.ssh.source_ip_allowlist.is_empty(),
            "gate off by default"
        );
        // The device flow must fit inside the login grace window.
        assert!(cfg.ssh.device_flow.poll_timeout_secs < cfg.ssh.login_grace_secs);
        assert_eq!(cfg.ssh.device_flow.heartbeat_interval_secs, 10);
    }

    #[test]
    fn wildcard_dns_suffixes_parse_and_deny_unknown_keys() {
        // The wildcard-DNS node domains parse from config.
        let cfg: GatewayConfig =
            serde_json::from_str(r#"{"ssh":{"node_dns_suffixes":["ssh.corp",".db.internal"]}}"#)
                .unwrap();
        assert_eq!(
            cfg.ssh.node_dns_suffixes,
            vec!["ssh.corp".to_string(), ".db.internal".to_string()]
        );
        // A misspelled key still fails closed (deny_unknown_fields).
        assert!(serde_json::from_str::<GatewayConfig>(
            r#"{"ssh":{"node_dns_suffix":["ssh.corp"]}}"#
        )
        .is_err());
    }

    #[test]
    fn ssh_unknown_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"listen_port":22}}"#);
        assert!(result.is_err(), "unknown ssh key must be rejected");
    }

    #[test]
    fn recorder_defaults_are_strict() {
        // Recording is mandatory: the recorder defaults to strict (fail closed) and
        // to an in-memory ciphertext spool (no plaintext ever touches disk).
        let cfg = GatewayConfig::default();
        assert!(cfg.ssh.recorder.strict, "recording must default to strict");
        assert!(cfg.ssh.recorder.spool_dir.is_none());
        assert!(cfg.ssh.recorder.upload_ca_pem_path.is_none());
        assert!(cfg.ssh.recorder.frame_plaintext_bytes > 0);
        assert!(cfg.ssh.recorder.upload_timeout_secs > 0);
    }

    #[test]
    fn recorder_unknown_key_fails_closed() {
        // A misspelled recorder key must error (fail closed), not leave the default
        // (possibly security-relevant, e.g. `strict`) silently in place.
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"recorder":{"strickt":false}}}"#);
        assert!(result.is_err(), "unknown recorder key must be rejected");
    }

    #[test]
    fn break_glass_defaults_enabled_grace_then_kill() {
        let cfg = GatewayConfig::default();
        assert!(cfg.ssh.break_glass.enabled, "break-glass on by default");
        assert_eq!(
            cfg.ssh.break_glass.mid_session_expiry,
            MidSessionExpiryMode::GraceThenKill
        );
    }

    #[test]
    fn break_glass_unknown_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"break_glass":{"enable":false}}}"#);
        assert!(result.is_err(), "unknown break_glass key must be rejected");
    }

    #[test]
    fn agent_transport_is_off_by_default_with_fail_closed_bounds() {
        let a = GatewayConfig::default().ssh.agent;
        assert!(a.listen_addr.is_empty(), "agent transport off by default");
        assert_eq!(a.heartbeat_interval_secs, 20);
        assert_eq!(a.max_frame_bytes, 64 * 1024);
        assert_eq!(a.dial_back_token_ttl_secs, 30);
        assert_eq!(a.dial_back_timeout_secs, 10);
        assert_eq!(a.max_agents, 1024);
        assert_eq!(a.max_connections, 4096);
        assert!(
            a.max_connections >= a.max_agents,
            "room for one socket per node"
        );
        // The two ordering invariants validate_config enforces hold at the defaults.
        assert!((a.dial_back_timeout_secs as i64) < a.dial_back_token_ttl_secs);
        assert!(a.max_frame_bytes > InnerLegServerConfig::default().max_packet_bytes as usize);
        // …and the defaults sit inside the wire-contract §3 ranges the Agent also enforces,
        // so an out-of-the-box Gateway is one every Agent will accept.
        assert!(crate::agent::MAX_FRAME_BYTES_RANGE.contains(&a.max_frame_bytes));
        assert!(crate::agent::HEARTBEAT_INTERVAL_SECS_RANGE.contains(&a.heartbeat_interval_secs));
    }

    #[test]
    fn agent_unknown_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"agent":{"listen_address":"0.0.0.0:9444"}}}"#);
        assert!(result.is_err(), "unknown agent key must be rejected");
    }

    #[test]
    fn recorder_strict_can_be_disabled_explicitly() {
        let cfg: GatewayConfig =
            serde_json::from_str(r#"{"ssh":{"recorder":{"strict":false}}}"#).unwrap();
        assert!(!cfg.ssh.recorder.strict);
        // The rest of the recorder block keeps its (strict-adjacent) defaults.
        assert!(cfg.ssh.recorder.spool_dir.is_none());
    }

    #[test]
    fn ha_defaults_to_single_instance_in_process_zero_deps() {
        let ha = GatewayConfig::default().ha;
        assert_eq!(ha.mode, HaMode::SingleInstance);
        assert_eq!(ha.coordination, CoordinationConfig::InProcess);
        assert!(ha.peer_relay_advertise_addr.is_empty());
        assert_eq!(ha.presence.heartbeat_interval_secs, 10);
        assert_eq!(ha.presence.staleness_ttl_secs, 30);
        assert_eq!(ha.routing.relay_timeout_secs, 25);
        assert_eq!(ha.routing.cache_ttl_secs, 30);
        assert_eq!(ha.drain.pre_drain_grace_secs, 5);
        assert_eq!(ha.drain.deadline_secs, 30);
        // The relay deadline must sit under the SSH login grace so a hung peer never hangs the
        // handshake — AND above the owner's worst-case establish budget (dial-back + handshake,
        // ~20s) so a slow-but-healthy owner is not abandoned (L1).
        assert!((ha.routing.relay_timeout_secs) < GatewayConfig::default().ssh.login_grace_secs);
        assert!(ha.routing.relay_timeout_secs > 20);
    }

    #[test]
    fn ha_nats_backend_parses_with_prefix_default() {
        let cfg: GatewayConfig = serde_json::from_str(
            r#"{"ha":{"mode":"ha","coordination":{"backend":"nats","url":"nats://n:4222"}}}"#,
        )
        .unwrap();
        assert_eq!(cfg.ha.mode, HaMode::Ha);
        assert_eq!(
            cfg.ha.coordination,
            CoordinationConfig::Nats {
                url: "nats://n:4222".into(),
                subject_prefix: "sl".into(),
            }
        );
    }

    #[test]
    fn ha_unknown_key_fails_closed() {
        // A stray key anywhere in the HA block is rejected, not silently ignored.
        for bad in [
            r#"{"ha":{"moed":"ha"}}"#,
            r#"{"ha":{"routing":{"relay_timeout":10}}}"#,
            r#"{"ha":{"coordination":{"backend":"nats","url":"x","extra":1}}}"#,
        ] {
            assert!(
                serde_json::from_str::<GatewayConfig>(bad).is_err(),
                "unknown HA key must be rejected: {bad}"
            );
        }
    }

    #[test]
    fn load_from_path_reads_json_and_denies_unknown_keys() {
        let dir = std::env::temp_dir();
        let good = dir.join(format!("sl-gw-cfg-good-{}.json", std::process::id()));
        std::fs::write(&good, r#"{"io_backend":"uring","ha":{"mode":"ha"}}"#).unwrap();
        let cfg = GatewayConfig::load_from_path(&good).unwrap();
        assert_eq!(cfg.io_backend, IoBackend::Uring);
        assert_eq!(cfg.ha.mode, HaMode::Ha);
        std::fs::remove_file(&good).ok();

        let bad = dir.join(format!("sl-gw-cfg-bad-{}.json", std::process::id()));
        std::fs::write(&bad, r#"{"io_back_end":"uring"}"#).unwrap();
        assert!(matches!(
            GatewayConfig::load_from_path(&bad),
            Err(ConfigError::Parse { .. })
        ));
        std::fs::remove_file(&bad).ok();

        // A named-but-missing file is a fail-closed error, never a silent default.
        assert!(matches!(
            GatewayConfig::load_from_path(Path::new("/nonexistent/sl-gw.json")),
            Err(ConfigError::Read { .. })
        ));
    }

    #[test]
    fn load_without_a_path_is_the_default() {
        // `load(None)` with the env unset yields the built-in default.
        let cfg = GatewayConfig::load(None).unwrap();
        assert_eq!(cfg.ha.mode, HaMode::SingleInstance);
    }
}
