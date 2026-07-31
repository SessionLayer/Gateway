//! Build script: generate gRPC client from vendored contract proto.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gateway-core/.. == repo root, which holds the vendored `proto/`.
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway-core manifest dir has a parent (the workspace root)")
        .join("proto");

    let common = proto_root.join("sessionlayer/controlplane/v1/common.proto");
    let handshake = proto_root.join("sessionlayer/controlplane/v1/handshake.proto");
    let identity = proto_root.join("sessionlayer/controlplane/v1/identity.proto");
    let signing = proto_root.join("sessionlayer/controlplane/v1/signing.proto");
    let authz = proto_root.join("sessionlayer/controlplane/v1/authz.proto");
    let auth = proto_root.join("sessionlayer/controlplane/v1/auth.proto");
    let recording = proto_root.join("sessionlayer/controlplane/v1/recording.proto");
    let lock = proto_root.join("sessionlayer/controlplane/v1/lock.proto");
    let agent_wire = proto_root.join("sessionlayer/agent/v1/wire.proto");
    let presence = proto_root.join("sessionlayer/controlplane/v1/presence.proto");
    let coordination = proto_root.join("sessionlayer/gateway/v1/coordination.proto");

    for p in [
        &common,
        &handshake,
        &identity,
        &signing,
        &authz,
        &auth,
        &recording,
        &lock,
        &presence,
        &agent_wire,
        &coordination,
    ] {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[
                handshake,
                identity,
                signing,
                authz,
                auth,
                recording,
                lock,
                presence,
                common.clone(),
            ],
            std::slice::from_ref(&proto_root),
        )?;

    // The wire payloads carry `ComponentInfo` / `ProtocolVersion` from the CP
    // package. `extern_path` points those at the types already generated above
    // (`crate::pb`) instead of emitting a second, incompatible copy.
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false)
        .extern_path(".sessionlayer.controlplane.v1", "crate::pb")
        .compile_protos(&[agent_wire], std::slice::from_ref(&proto_root))?;

    // Gateway<->Gateway coordination payloads (messages only; no CP types, so no
    // extern_path). Generated into its own module (crate::pbgw via lib.rs).
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false)
        .compile_protos(&[coordination], std::slice::from_ref(&proto_root))?;

    Ok(())
}
