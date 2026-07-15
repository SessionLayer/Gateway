//! Wire-version advertisement gate (Session Fifteen; F5, the S14 F-wireversion-1 class).
//!
//! The Agent↔Gateway (and Gateway↔Gateway relay) WIRE protocol is a SEPARATE version line from
//! the CP↔Gateway gRPC plane. The Gateway is the side that regressed in S14 (it advertised wire
//! 1.1 by reusing the gRPC constant), so this gate fails the build if anyone re-couples them:
//! the wire max MUST stay 1.0 and MUST stay strictly below the gRPC max. Mirrors
//! `Agent/tests/version.rs`.

use gateway_core::pb::ProtocolVersion;
use gateway_core::{agent, version};

#[test]
fn wire_protocol_max_is_exactly_1_0() {
    assert_eq!(agent::WIRE_PROTOCOL_MIN, (1, 0));
    assert_eq!(agent::WIRE_PROTOCOL_MAX, (1, 0));
    assert_eq!(agent::WIRE_PROTOCOL_MIN, agent::WIRE_PROTOCOL_MAX);

    // The wire HELLO advertises exactly (1, 0) — never the gRPC minor.
    let info = agent::wire_component_info();
    assert_eq!(
        info.protocol_min,
        Some(ProtocolVersion { major: 1, minor: 0 })
    );
    assert_eq!(
        info.protocol_max,
        Some(ProtocolVersion { major: 1, minor: 0 })
    );
}

#[test]
fn the_wire_version_is_decoupled_from_the_grpc_version() {
    // The gRPC plane is already at 1.1; the wire must NOT follow it. Strictly-below is the
    // load-bearing assertion — recoupling them (wire := gRPC max) fails right here.
    assert_eq!(version::PROTOCOL_MAX, (1, 1));
    assert!(
        agent::WIRE_PROTOCOL_MAX < version::PROTOCOL_MAX,
        "the wire protocol max must stay strictly below the gRPC protocol max"
    );

    // And the two advertisements carry different maxima (belt-and-braces: the wire HELLO and the
    // gRPC ComponentInfo cannot silently converge).
    let wire = agent::wire_component_info().protocol_max.unwrap();
    let grpc = version::protocol_version(version::PROTOCOL_MAX);
    assert_ne!(wire, grpc);
}
