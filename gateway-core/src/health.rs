//! Minimal health/version surface for the Gateway (Session One).
//!
//! Enough to satisfy a liveness/readiness probe and to report the build's SemVer
//! and supported protocol range. Real dependency checks (CP channel, recorder,
//! node connectors) are added as those subsystems land.

use crate::version;
use serde::Serialize;

/// Liveness/readiness status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Up and able to serve.
    Ok,
    /// Not ready to serve.
    Unready,
}

/// A point-in-time health/version report, JSON-serialisable for a probe.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Formal component name.
    pub component: String,
    /// Build SemVer.
    pub semver: String,
    /// Supported CP <-> Gateway protocol range, e.g. `1.0-1.0`.
    pub protocol_range: String,
    /// Liveness/readiness.
    pub status: Status,
}

/// Report current health/version. Session One has no dependencies to probe, so
/// readiness is [`Status::Ok`] once the process is running.
pub fn report() -> Health {
    Health {
        component: version::COMPONENT_NAME.to_string(),
        semver: version::SEMVER.to_string(),
        protocol_range: version::protocol_range(),
        status: Status::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_ok_and_advertises_version() {
        let health = report();
        assert_eq!(health.status, Status::Ok);
        assert_eq!(health.component, "SessionLayer Gateway");
        assert_eq!(health.semver, env!("CARGO_PKG_VERSION"));
        assert_eq!(health.protocol_range, "1.0-1.0");
    }

    #[test]
    fn report_serialises_to_json() {
        let json = serde_json::to_string(&report()).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"protocol_range\":\"1.0-1.0\""));
    }
}
