//! Protocol/version constants for the CP <-> Gateway gRPC plane, plus the pure
//! highest-common-version resolver.
//!
//! Implements FR-HA-9 / Design D33 / §16A and mirrors the resolution rule in
//! `ControlPlane-API/contracts/VERSIONING.md` §3. Session One's baseline was the
//! single version **1.0**; **Session Four bumps to `[1.0, 1.1]`** — the first
//! MINOR bump (VERSIONING.md §6). 1.1 adds three additive services carried over
//! the new mTLS transport (`GatewayIdentity` enroll/renew, `SessionSigning`).
//! Keeping `protocol_min = 1.0` makes the N-1 window (VERSIONING.md §4)
//! load-bearing now: a 1.1 build still negotiates 1.0 with a peer that has not
//! upgraded, and vice-versa. No common version still **fails closed**.

use crate::pb::{ComponentInfo, ProtocolVersion};

/// Formal component name advertised in the handshake (matches the contract).
pub const COMPONENT_NAME: &str = "SessionLayer Gateway";

/// This build's SemVer (the crate version) — the artifact identity, distinct
/// from the protocol version (the wire contract identity).
pub const SEMVER: &str = env!("CARGO_PKG_VERSION");

/// Lowest CP <-> Gateway protocol version this build speaks, as `(major, minor)`.
pub const PROTOCOL_MIN: (u32, u32) = (1, 0);

/// Highest CP <-> Gateway protocol version this build speaks, as `(major, minor)`.
/// Session Four: `1.1` (the enroll/renew/sign additions). `PROTOCOL_MIN` stays
/// `1.0` to hold the N-1 window open.
pub const PROTOCOL_MAX: (u32, u32) = (1, 1);

/// Build a [`ProtocolVersion`] message from a `(major, minor)` pair.
pub fn protocol_version((major, minor): (u32, u32)) -> ProtocolVersion {
    ProtocolVersion { major, minor }
}

/// Format a [`ProtocolVersion`] as `major.minor` (e.g. `1.0`).
pub fn format_version(v: &ProtocolVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

/// The inclusive protocol range this build supports, as `min-max`
/// (e.g. `1.0-1.0`).
pub fn protocol_range() -> String {
    format!(
        "{}.{}-{}.{}",
        PROTOCOL_MIN.0, PROTOCOL_MIN.1, PROTOCOL_MAX.0, PROTOCOL_MAX.1
    )
}

/// This Gateway's [`ComponentInfo`] for the handshake `ClientHello`.
pub fn component_info() -> ComponentInfo {
    ComponentInfo {
        name: COMPONENT_NAME.to_string(),
        semver: SEMVER.to_string(),
        protocol_min: Some(protocol_version(PROTOCOL_MIN)),
        protocol_max: Some(protocol_version(PROTOCOL_MAX)),
    }
}

/// Resolve the highest common protocol version of two `[min, max]` ranges.
///
/// A pure, order-independent function (VERSIONING.md §3): the greatest `v` with
/// `v <= min(a_max, b_max)` and `v >= max(a_min, b_min)`. `(major, minor)`
/// tuples order lexicographically, which is exactly semantic `major.minor`
/// ordering. Returns `None` when the ranges do not overlap — the peers share no
/// version and the caller MUST fail closed.
///
/// PRECONDITION: each peer's advertised range lies within a single MAJOR line
/// (`min.major == max.major`). A MAJOR change is a hard break (`common.proto`),
/// not an additive step, so a range must never straddle majors. Enforced by
/// `debug_assert!` — in release the lexicographic resolution would otherwise
/// treat the space as contiguous across a major boundary.
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
        // Session Four: max bumped to 1.1, min held at 1.0 for the N-1 window.
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
