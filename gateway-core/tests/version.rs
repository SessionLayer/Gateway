use gateway_core::pb::ProtocolVersion;
use gateway_core::{agent, version};

#[test]
fn wire_protocol_max_is_exactly_1_0() {
    assert_eq!(agent::WIRE_PROTOCOL_MIN, (1, 0));
    assert_eq!(agent::WIRE_PROTOCOL_MAX, (1, 0));
    assert_eq!(agent::WIRE_PROTOCOL_MIN, agent::WIRE_PROTOCOL_MAX);

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
    assert_eq!(version::PROTOCOL_MAX, (1, 1));
    assert!(
        agent::WIRE_PROTOCOL_MAX < version::PROTOCOL_MAX,
        "the wire protocol max must stay strictly below the gRPC protocol max"
    );

    let wire = agent::wire_component_info().protocol_max.unwrap();
    let grpc = version::protocol_version(version::PROTOCOL_MAX);
    assert_ne!(wire, grpc);
}
