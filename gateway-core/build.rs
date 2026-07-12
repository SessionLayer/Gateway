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
    // Session Five addition (frozen upstream): the connect-time decision service
    // (Authorization: Authorize). Compiled here so the vendored contract stays
    // consistent; the Gateway does not call it yet (S7/S8/S10 own that flow).
    let authz = proto_root.join("sessionlayer/controlplane/v1/authz.proto");
    // Session Seven addition (frozen upstream): the outer-leg authentication
    // service (OuterLegAuth: ResolveUserCert / ResolvePin / ResolveOtp /
    // Begin+PollDeviceFlow). The Gateway is a client of these; the server side is
    // generated for the in-process mock CP used by the integration tests.
    let auth = proto_root.join("sessionlayer/controlplane/v1/auth.proto");
    // Session Nine addition (frozen upstream): the recorder register/finalize
    // service (Recording: BeginRecording / FinalizeRecording) that issues WORM
    // upload credentials and holds recording metadata. The Gateway is a client;
    // the server side is generated for the in-process mock CP.
    let recording = proto_root.join("sessionlayer/controlplane/v1/recording.proto");
    // Session Ten addition (frozen upstream): the actively-pushed lock deny-list
    // (LockFeed: StreamLocks — server-streaming). The Gateway is a client; the
    // server side is generated for the in-process mock CP.
    let lock = proto_root.join("sessionlayer/controlplane/v1/lock.proto");

    // Regenerate only when the vendored contract (or this script) changes.
    for p in [
        &common, &handshake, &identity, &signing, &authz, &auth, &recording, &lock,
    ] {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_client(true)
        // The server side is generated so tests can stand up an in-process mock
        // CP (mTLS + enroll/renew/sign); the Gateway itself is a client of these
        // services.
        .build_server(true)
        .compile_protos(
            &[handshake, identity, signing, authz, auth, recording, lock, common],
            &[proto_root],
        )?;

    Ok(())
}
