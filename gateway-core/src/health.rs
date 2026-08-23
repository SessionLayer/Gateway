use crate::version;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Unready,
}

#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub component: String,
    pub semver: String,
    pub protocol_range: String,
    pub status: Status,
}

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
        assert_eq!(health.protocol_range, "1.0-1.1");
    }

    #[test]
    fn report_serialises_to_json() {
        let json = serde_json::to_string(&report()).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"protocol_range\":\"1.0-1.1\""));
    }
}
