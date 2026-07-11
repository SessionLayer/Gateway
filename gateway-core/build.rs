//! Build script: generate the CP <-> Gateway gRPC client (and a server stub used
//! only by the in-process negotiation test) from the VENDORED contract proto.
//!
//! The authoritative proto lives in `ControlPlane-API/contracts/proto/` (Design
//! §13). Because the parent `SessionLayer/` folder is not a git repo and CI
//! checks out THIS repo alone, a committed copy is vendored under `proto/`
//! (re-sync via `scripts/sync-contracts.sh`; see CLAUDE.md). We generate from
//! the vendored copy so the build is hermetic.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gateway-core/.. == repo root, which holds the vendored `proto/`.
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway-core manifest dir has a parent (the workspace root)")
        .join("proto");

    let common = proto_root.join("sessionlayer/controlplane/v1/common.proto");
    let handshake = proto_root.join("sessionlayer/controlplane/v1/handshake.proto");
    // Session Four additions (frozen upstream in ControlPlane-API/contracts):
    // the Gateway identity lifecycle (enroll/renew) and the session-bound signer.
    let identity = proto_root.join("sessionlayer/controlplane/v1/identity.proto");
    let signing = proto_root.join("sessionlayer/controlplane/v1/signing.proto");

    // Regenerate only when the vendored contract (or this script) changes.
    for p in [&common, &handshake, &identity, &signing] {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_client(true)
        // The server side is generated so tests can stand up an in-process mock
        // CP (mTLS + enroll/renew/sign); the Gateway itself is a client of these
        // services.
        .build_server(true)
        .compile_protos(&[handshake, identity, signing, common], &[proto_root])?;

    Ok(())
}
