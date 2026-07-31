//! Protocol versioning (N-1 window: 1.0–1.1; no common version fails closed).

use crate::pb::{ComponentInfo, ProtocolVersion};

pub const COMPONENT_NAME: &str = "SessionLayer Gateway";

pub const SEMVER: &str = env!("CARGO_PKG_VERSION");

pub const PROTOCOL_MIN: (u32, u32) = (1, 0);

pub const PROTOCOL_MAX: (u32, u32) = (1, 1);

pub fn protocol_version((major, minor): (u32, u32)) -> ProtocolVersion {
    ProtocolVersion { major, minor }
}

pub fn format_version(v: &ProtocolVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

pub fn protocol_range() -> String {
    format!(
        "{}.{}-{}.{}",
        PROTOCOL_MIN.0, PROTOCOL_MIN.1, PROTOCOL_MAX.0, PROTOCOL_MAX.1
    )
}

pub fn component_info() -> ComponentInfo {
    ComponentInfo {
        name: COMPONENT_NAME.to_string(),
        semver: SEMVER.to_string(),
        protocol_min: Some(protocol_version(PROTOCOL_MIN)),
        protocol_max: Some(protocol_version(PROTOCOL_MAX)),
    }
}

pub fn resolve_common_version(
    a_min: (u32, u32),
    a_max: (u32, u32),
    b_min: (u32, u32),
    b_max: (u32, u32),
) -> Option<(u32, u32)> {
    debug_assert_eq!(a_min.0, a_max.0, "peer A range must not span majors");
    debug_assert_eq!(b_min.0, b_max.0, "peer B range must not span majors");

    let lower = a_min.max(b_min);
    let upper = a_max.min(b_max);
    (lower <= upper).then_some(upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_component_info_advertises_1_0_to_1_1_range() {
        let info = component_info();
        assert_eq!(info.name, "SessionLayer Gateway");
        assert_eq!(
            info.protocol_min,
            Some(ProtocolVersion { major: 1, minor: 0 })
        );
        assert_eq!(
            info.protocol_max,
            Some(ProtocolVersion { major: 1, minor: 1 })
        );
    }

    #[test]
    fn protocol_range_renders_1_0_to_1_1() {
        assert_eq!(protocol_range(), "1.0-1.1");
    }

    #[test]
    fn resolves_identical_ranges() {
        assert_eq!(
            resolve_common_version((1, 0), (1, 0), (1, 0), (1, 0)),
            Some((1, 0))
        );
    }

    #[test]
    fn resolves_to_highest_common_minor() {
        // Client [1.0, 1.0] vs server [1.0, 1.2] -> 1.0 (order-independent).
        assert_eq!(
            resolve_common_version((1, 0), (1, 0), (1, 0), (1, 2)),
            Some((1, 0))
        );
        assert_eq!(
            resolve_common_version((1, 0), (1, 2), (1, 0), (1, 0)),
            Some((1, 0))
        );
        // Both support up to 1.3 -> pick 1.3.
        assert_eq!(
            resolve_common_version((1, 0), (1, 3), (1, 1), (1, 3)),
            Some((1, 3))
        );
    }

    #[test]
    fn n_minus_one_window_overlaps() {
        // A 1.1 peer keeps min at 1.0 so it still talks to a 1.0 peer.
        assert_eq!(
            resolve_common_version((1, 0), (1, 1), (1, 0), (1, 0)),
            Some((1, 0))
        );
    }

    #[test]
    fn disjoint_major_has_no_common_version() {
        assert_eq!(resolve_common_version((1, 0), (1, 0), (2, 0), (2, 0)), None);
        assert_eq!(resolve_common_version((2, 0), (2, 5), (1, 0), (1, 9)), None);
    }
}
