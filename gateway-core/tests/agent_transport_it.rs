//! Session Fourteen, Parts A/B/C: the agent transport against the **real** WSS + mTLS
//! server, in-process (no Docker).
//!
//! Every test here drives the frozen wire contract over a genuine TLS 1.3 connection
//! with a genuine client certificate issued by the mock CP's internal mTLS CA. The
//! adversarial cases (a locked agent, a foreign CA, a replayed token, a token stolen by
//! another agent, an expired token, an oversized frame, an unknown path, no common
//! protocol version) all assert the Gateway **fails closed**.
#![cfg(feature = "test-agent")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::agent::registry::AgentRegistry;
use gateway_core::agent::testclient::AgentClient;
use gateway_core::agent::token::{DialBackBinding, DialBackSigner, PendingDialBacks};
use gateway_core::agent::wire::{self, MsgType};
use gateway_core::agent::{server, CONTROL_PATH, DIALBACK_PATH};
use gateway_core::cpauth::{CpAuthClient, CpChannelFactory};
use gateway_core::identity;
use gateway_core::pb::{Lock, LockTarget};
use gateway_core::pbagent::WireErrorCode;
use gateway_core::ssh::connector::{NodeConnectError, NodeConnector, NodeDial};
use gateway_core::ssh::locks::LockSet;
use support::MockCp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NODE: &str = "node-a";
const AGENT: &str = "agent-a";

/// A bound agent transport plus everything needed to drive it as a client.
struct Harness {
    cp: MockCp,
    endpoint: String,
    gateway_name: String,
    registry: Arc<AgentRegistry>,
    pending: Arc<PendingDialBacks>,
    signer: Arc<DialBackSigner>,
    lock_set: Arc<LockSet>,
    gateway_id: String,
    ca_der: Vec<Vec<u8>>,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

impl Harness {
    async fn start() -> Harness {
        Harness::start_inner(true).await
    }

    /// Start with the lock feed **not yet confirmed** — the deny-set is empty AND unhealthy,
    /// so the transport's readiness gate should refuse to serve agents until a snapshot lands
    /// (F-agentlock-1). Call `h.lock_set.replace_snapshot(..)` to make it ready.
    async fn start_unready() -> Harness {
        Harness::start_inner(false).await
    }

    async fn start_inner(feed_ready: bool) -> Harness {
        let cp = MockCp::start().await;
        let dir = tempfile::tempdir().unwrap();
        let store = identity::IdentityStore::open(dir.path()).unwrap();
        let params = cp.channel_params(Duration::from_secs(5), Duration::from_secs(10));
        let cred = identity::enroll(
            &store,
            &params,
            &cp.bootstrap_anchors(),
            &cp.mint_enrollment_token(),
            "gw-agent-it",
        )
        .await
        .unwrap();

        let factory = Arc::new(CpChannelFactory::fixed(
            params,
            cred.identity.clone(),
            cred.ca_chain_der.clone(),
        ));
        let cpauth = Arc::new(CpAuthClient::new(factory, Duration::from_secs(10)));

        let registry = Arc::new(AgentRegistry::new(16));
        let pending = Arc::new(PendingDialBacks::default());
        let signer = Arc::new(DialBackSigner::generate());
        let lock_set = Arc::new(LockSet::new(30, 30));
        if feed_ready {
            lock_set.replace_snapshot(Vec::new(), 1); // healthy, empty
        }

        let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let transport = server::bind(
            server::AgentTransportDeps {
                cpauth,
                gateway_id: cred.gateway_id.clone(),
                gateway_name: cred.gateway_name.clone(),
                registry: registry.clone(),
                pending: pending.clone(),
                signer: signer.clone(),
                lock_set: lock_set.clone(),
                peer_relay: None,
                config: gateway_core::config::AgentTransportConfig {
                    listen_addr: "127.0.0.1:0".into(),
                    heartbeat_interval_secs: 1,
                    dial_back_timeout_secs: 3,
                    dial_back_token_ttl_secs: 10,
                    handshake_timeout_secs: 5,
                    ..Default::default()
                },
            },
            sd_rx.clone(),
        )
        .await
        .expect("agent transport binds");
        let endpoint = format!("wss://{}", transport.local_addr());

        let mut sd = sd_rx;
        tokio::spawn(transport.run(async move {
            let _ = sd.wait_for(|v| *v).await;
        }));

        Harness {
            endpoint,
            gateway_name: cred.gateway_name.clone(),
            gateway_id: cred.gateway_id.clone(),
            ca_der: cred.ca_chain_der.clone(),
            registry,
            pending,
            signer,
            lock_set,
            cp,
            _shutdown: sd_tx,
        }
    }

    /// A well-behaved agent client with a real CP-issued identity.
    fn agent(&self, agent_id: &str, node_name: &str) -> AgentClient {
        let leaf = self.cp.issue_agent_identity(agent_id, node_name);
        AgentClient {
            endpoint: self.endpoint.clone(),
            server_name: self.gateway_name.clone(),
            ca_der: self.ca_der.clone(),
            cert_der: leaf.cert_der,
            key_pkcs8_der: leaf.key_pkcs8_der,
            node_name: node_name.to_string(),
            splice_addr: "127.0.0.1:1".into(),
            max_frame_bytes: 65536,
        }
    }

    fn dialer(&self) -> gateway_core::agent::dial::AgentDial {
        gateway_core::agent::dial::AgentDial::new(
            self.registry.clone(),
            self.pending.clone(),
            self.signer.clone(),
            self.lock_set.clone(),
            self.gateway_id.clone(),
            self.endpoint.clone(),
            10,
            Duration::from_secs(3),
        )
    }

    /// Spawn `client`'s control channel — single-shot (no auto-reconnect), so a test can
    /// reason about exactly which connection owns the node. The join handle resolves when
    /// the Gateway closes that connection (e.g. because a newer one superseded it).
    fn spawn_control(
        &self,
        client: &AgentClient,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let c = client.clone();
        let task = tokio::spawn(async move {
            let _ = c
                .run_control(async move {
                    let _ = rx.wait_for(|v| *v).await;
                })
                .await;
        });
        (task, tx)
    }

    async fn await_registered(&self, node_name: &str) {
        for _ in 0..200 {
            if self.registry.lookup(node_name).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("agent never registered for {node_name}");
    }

    /// Spawn `client`'s control channel and wait until it is registered.
    async fn register(&self, client: &AgentClient) -> tokio::sync::watch::Sender<bool> {
        let (_task, tx) = self.spawn_control(client);
        self.await_registered(&client.node_name).await;
        tx
    }
}

fn node_dial(node_name: &str, session_id: &str) -> NodeDial {
    NodeDial {
        node_id: "node-uuid".into(),
        dial_address: String::new(),
        connector_kind: gateway_core::pb::ConnectorKind::OutboundAgent as i32,
        node_name: node_name.into(),
        session_id: session_id.into(),
        principal: "deploy".into(),
        ..Default::default()
    }
}

/// A stand-in node `sshd`: echoes whatever is written to it.
async fn echo_listener() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, handle)
}

// ── Part A: registration, identity, liveness ────────────────────────────────

#[tokio::test]
async fn an_agent_registers_over_real_mtls_and_the_dial_back_splices_bytes() {
    let h = Harness::start().await;
    let (node_addr, _echo) = echo_listener().await;

    let mut client = h.agent(AGENT, NODE);
    client.splice_addr = node_addr; // the Agent's OWN local config, never the wire
    let _sd = h.register(&client).await;

    // The connector signals the Agent, which dials back and splices. What comes out is
    // an ordinary byte stream — exactly what the S8 inner leg consumes.
    let mut stream = h
        .dialer()
        .connect(&node_dial(NODE, "sess-1"))
        .await
        .expect("dial-back must splice");
    stream.write_all(b"SSH-2.0-probe\r\n").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 15];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        &buf, b"SSH-2.0-probe\r\n",
        "bytes cross the splice verbatim"
    );

    // The token was consumed by the dial-back: nothing is left redeemable.
    assert!(h.pending.is_empty());
}

#[tokio::test]
async fn a_locked_agent_cannot_register() {
    let h = Harness::start().await;
    // The S12 clone-detection lock: an agent identity the CP has locked.
    h.lock_set.add(Lock {
        lock_id: "l1".into(),
        target: Some(LockTarget {
            identities: vec![AGENT.into()],
            ..Default::default()
        }),
        expires_at_epoch_seconds: 0,
        created_at_epoch_seconds: 0,
        reason: "clone detected".into(),
        ..Default::default()
    });

    let client = h.agent(AGENT, NODE);
    let mut ws = client.connect(&h.endpoint, CONTROL_PATH).await.unwrap();
    let negotiated = client.hello(&mut ws).await.unwrap();

    // Deny wins: the coarse UNAUTHORIZED, and no registration.
    let frame = client.next_frame(&mut ws, negotiated.ver).await.unwrap();
    assert_eq!(frame.msg_type, MsgType::Error);
    assert_eq!(
        wire::as_wire_error(&frame).unwrap().code,
        WireErrorCode::Unauthorized as i32
    );
    assert!(
        h.registry.is_empty(),
        "a locked agent must not be registered"
    );

    // …and its node is therefore simply offline.
    assert!(matches!(
        h.dialer().connect(&node_dial(NODE, "sess-1")).await,
        Err(NodeConnectError::NoAgent)
    ));
}

#[tokio::test]
async fn the_transport_does_not_serve_agents_until_the_lock_feed_is_ready() {
    // F-agentlock-1 readiness gate: a Gateway that cannot yet confirm the deny-set must not
    // serve agents (a locked agent reconnecting during boot must not be admitted). Deny
    // fails closed → the node is simply "offline" until the feed lands.
    let h = Harness::start_unready().await;
    let client = h.agent(AGENT, NODE);
    let (_task, _sd) = h.spawn_control(&client);

    // While the feed is unconfirmed the transport is not accepting: no registration.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        h.registry.is_empty(),
        "no agent may register before the lock feed confirms the deny-set"
    );

    // Once the feed delivers its first snapshot, the transport starts accepting and the
    // client's connection — queued in the listener backlog this whole time — completes its
    // handshake and registers.
    h.lock_set.replace_snapshot(Vec::new(), 1);
    h.await_registered(NODE).await;
}

#[tokio::test]
async fn a_dropped_lock_feed_refuses_new_registration_and_dial_back_redemption() {
    // The feed WAS healthy (so the transport is serving), then the CP stream drops mid-life:
    // a lock raised at the CP during the outage never arrives, so an empty set is not
    // evidence the agent is unlocked. Both a new registration and a dial-back redemption of
    // a token issued while healthy must fail closed.
    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);

    // A live token, captured while the feed is healthy.
    let req = capture_dial_back(&h, &client, "sess-drop").await;

    // The CP lock stream drops.
    h.lock_set.mark_disconnected();
    assert!(!h.lock_set.healthy());

    // (a) Redeeming the already-issued token is refused (the exploitable half).
    assert_unauthorized(&redeem(&h, &client, &req).await);
    assert_eq!(
        h.pending.len(),
        1,
        "an unconfirmable redemption does not consume it"
    );

    // (b) A brand-new registration is refused too.
    let other = h.agent("agent-b", "node-b");
    let mut ws = other.connect(&h.endpoint, CONTROL_PATH).await.unwrap();
    let negotiated = other.hello(&mut ws).await.unwrap();
    let frame = other.next_frame(&mut ws, negotiated.ver).await.unwrap();
    assert_eq!(frame.msg_type, MsgType::Error);
    assert_eq!(
        wire::as_wire_error(&frame).unwrap().code,
        WireErrorCode::Unauthorized as i32
    );
    assert!(
        h.registry.lookup("node-b").is_err(),
        "no registration while the feed is down"
    );
}

#[tokio::test]
async fn an_agent_that_stops_answering_heartbeats_is_deregistered() {
    // F-agentliveness-1(a): the "two missed heartbeats => dead" path had no coverage. Register
    // an agent, then stop answering PINGs (drain but never PONG) — the node must go
    // unreachable within a bounded time (heartbeat is 1s in the harness).
    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);
    let mut ws = client.connect(&h.endpoint, CONTROL_PATH).await.unwrap();
    let _n = client.hello(&mut ws).await.unwrap();
    h.await_registered(NODE).await;

    // Drain incoming frames (incl. PINGs) so the socket does not back up, but never answer.
    let drain = tokio::spawn(async move {
        use futures_util::StreamExt;
        while ws.next().await.transpose().ok().flatten().is_some() {}
    });

    let mut dead = false;
    for _ in 0..100 {
        if h.registry.is_empty() {
            dead = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        dead,
        "an agent that stops answering heartbeats must be deregistered"
    );
    drain.abort();
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused_at_the_tls_handshake() {
    let h = Harness::start().await;
    // A perfectly well-formed agent certificate — from a CA the Gateway does not pin.
    let rogue_ca = support::TestCa::generate("Rogue CA");
    let leaf = rogue_ca.issue_agent_leaf(AGENT, NODE);
    let client = AgentClient {
        cert_der: leaf.cert_der,
        key_pkcs8_der: leaf.key_pkcs8_der,
        ..h.agent(AGENT, NODE)
    };
    assert!(
        client.connect(&h.endpoint, CONTROL_PATH).await.is_err(),
        "an unchained client certificate must not reach the wire protocol at all"
    );
    assert!(h.registry.is_empty());
}

#[tokio::test]
async fn a_reconnect_replaces_the_control_channel_and_still_serves_dial_backs() {
    let h = Harness::start().await;
    let (node_addr, _echo) = echo_listener().await;

    let mut first = h.agent(AGENT, NODE);
    first.splice_addr = node_addr.clone();
    let (first_task, _sd1) = h.spawn_control(&first);
    h.await_registered(NODE).await;

    // A second connection for the same node — the partition case. The NEWER one wins, and
    // the older is closed by the Gateway: a stale channel must not lock the node out
    // until a TCP timeout expires.
    let mut second = h.agent(AGENT, NODE);
    second.splice_addr = node_addr;
    let (_second_task, _sd2) = h.spawn_control(&second);

    tokio::time::timeout(Duration::from_secs(5), first_task)
        .await
        .expect("the superseded connection must be closed by the Gateway")
        .unwrap();
    assert_eq!(h.registry.len(), 1, "exactly one live channel per node");

    // …and the survivor is the one that serves the next session.
    let mut stream = h
        .dialer()
        .connect(&node_dial(NODE, "sess-2"))
        .await
        .expect("the surviving channel must serve the dial-back");
    stream.write_all(b"after-reconnect").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 15];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after-reconnect");
}

// ── Part C: the dial-back token, against the real server ────────────────────

/// Register `client`'s control channel by hand and capture the `DIAL_BACK_REQUEST` the
/// Gateway sends — **without serving it**, so the token stays pending and the test owns
/// it. The connector keeps waiting in the background (its deadline has not elapsed), which
/// is what makes the replay / theft / lock cases meaningful: the token they present is a
/// real, live, still-redeemable one.
async fn capture_dial_back(
    h: &Harness,
    client: &AgentClient,
    session_id: &str,
) -> gateway_core::pbagent::DialBackRequest {
    let mut ws = client.connect(&h.endpoint, CONTROL_PATH).await.unwrap();
    let negotiated = client.hello(&mut ws).await.unwrap();
    for _ in 0..200 {
        if h.registry.lookup(&client.node_name).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let dialer = h.dialer();
    let d = node_dial(&client.node_name, session_id);
    // Deliberately NOT awaited: awaiting it to completion would let its deadline elapse
    // and abandon the very token under test.
    tokio::spawn(async move {
        let _ = dialer.connect(&d).await;
    });

    let req = loop {
        let frame = client.next_frame(&mut ws, negotiated.ver).await.unwrap();
        match frame.msg_type {
            MsgType::Ping => continue,
            MsgType::DialBackRequest => break wire::as_dial_back_request(&frame).unwrap(),
            other => panic!("unexpected control frame {other:?}"),
        }
    };
    // Hold the control channel open: dropping it would deregister the agent.
    tokio::spawn(async move {
        let _keep = ws;
        std::future::pending::<()>().await;
    });
    assert!(
        !h.pending.is_empty(),
        "the captured token must still be live"
    );
    req
}

/// Present `token` on a fresh dial-back connection and return the Gateway's reply frame.
async fn redeem(
    h: &Harness,
    client: &AgentClient,
    req: &gateway_core::pbagent::DialBackRequest,
) -> gateway_core::agent::wire::Frame {
    let mut ws = client.connect(&h.endpoint, DIALBACK_PATH).await.unwrap();
    let n = client.hello(&mut ws).await.unwrap();
    client
        .send_frame(
            &mut ws,
            n.ver,
            MsgType::DialBackAuth,
            &prost::Message::encode_to_vec(&gateway_core::pbagent::DialBackAuth {
                token: req.token.clone(),
                request_id: req.request_id.clone(),
            }),
        )
        .await
        .unwrap();
    client.next_frame(&mut ws, n.ver).await.unwrap()
}

fn assert_unauthorized(frame: &gateway_core::agent::wire::Frame) {
    assert_eq!(frame.msg_type, MsgType::Error);
    assert_eq!(
        wire::as_wire_error(frame).unwrap().code,
        WireErrorCode::Unauthorized as i32,
        "the peer learns only UNAUTHORIZED — never which check failed"
    );
}

#[tokio::test]
async fn a_replayed_dial_back_token_is_refused() {
    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);
    let req = capture_dial_back(&h, &client, "sess-replay").await;

    // First redemption: accepted — and the jti is consumed by that acceptance.
    let frame = redeem(&h, &client, &req).await;
    assert_eq!(frame.msg_type, MsgType::DialBackAccept);
    assert!(h.pending.is_empty(), "acceptance consumes the token");

    // Replay the SAME token: still well-formed, still signature-valid, still unexpired —
    // and worthless, because removal from the pending ledger IS consumption.
    assert_unauthorized(&redeem(&h, &client, &req).await);
}

#[tokio::test]
async fn a_token_stolen_by_another_agent_is_worthless_to_it() {
    let h = Harness::start().await;
    let victim = h.agent(AGENT, NODE);

    // A second, entirely VALID and UNLOCKED agent, registered for its own node.
    let thief = h.agent("agent-b", "node-b");
    let _sd_b = h.register(&thief).await;

    // The thief somehow obtains the live token issued for {agent-a, node-a}.
    let req = capture_dial_back(&h, &victim, "sess-steal").await;
    assert_unauthorized(&redeem(&h, &thief, &req).await);

    // The victim's token is still pending: a thief cannot even burn it (the agent check
    // runs BEFORE consumption, so a rogue presentation is not a denial-of-service).
    assert_eq!(h.pending.len(), 1);
    // …and the rightful agent can still redeem it.
    let frame = redeem(&h, &victim, &req).await;
    assert_eq!(frame.msg_type, MsgType::DialBackAccept);
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);
    let _sd = h.register(&client).await;

    let binding = DialBackBinding {
        node_name: NODE.into(),
        session_id: "sess-old".into(),
        principal: "deploy".into(),
        agent_id: AGENT.into(),
    };
    let now = gateway_core::agent::token::now_epoch_secs();
    // Minted an hour ago with a 30s TTL: signature-valid and still in the pending ledger,
    // but long dead. The window is checked independently of the ledger.
    let (jti, token) = h.signer.mint(&h.gateway_id, &binding, 30, now - 3600);
    let (tx, _rx) = tokio::sync::oneshot::channel();
    h.pending
        .insert(jti, "req-old".into(), binding, now + 30, tx);

    let req = gateway_core::pbagent::DialBackRequest {
        request_id: "req-old".into(),
        token,
        ..Default::default()
    };
    assert_unauthorized(&redeem(&h, &client, &req).await);
}

#[tokio::test]
async fn a_locked_agent_cannot_redeem_a_dial_back_issued_before_the_lock() {
    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);

    // A token issued while the agent was healthy…
    let req = capture_dial_back(&h, &client, "sess-lock").await;

    // …and a lock pushed before it is redeemed. Deny wins at the dial-back too, which is
    // why the lock is re-checked here and not only at registration.
    h.lock_set.add(Lock {
        lock_id: "l2".into(),
        target: Some(LockTarget {
            identities: vec![AGENT.into()],
            ..Default::default()
        }),
        expires_at_epoch_seconds: 0,
        created_at_epoch_seconds: 0,
        reason: "locked mid-flight".into(),
        ..Default::default()
    });

    assert_unauthorized(&redeem(&h, &client, &req).await);
    assert_eq!(
        h.pending.len(),
        1,
        "a locked redemption does not consume it"
    );
}

// ── Framing / protocol guards ───────────────────────────────────────────────

#[tokio::test]
async fn an_unknown_request_path_is_rejected() {
    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);
    assert!(
        client
            .connect(&h.endpoint, "/agent/v1/admin")
            .await
            .is_err(),
        "only the two contracted paths exist"
    );
    assert!(client.connect(&h.endpoint, "/").await.is_err());
    assert!(h.registry.is_empty());
}

#[tokio::test]
async fn an_oversized_frame_is_rejected_without_buffering_it() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::{Bytes as WsBytes, Message};

    let h = Harness::start().await;
    // A hostile peer whose OWN limits are generous, so it can actually put an oversized
    // frame on the wire; the Gateway's bound is what must reject it.
    let client = AgentClient {
        max_frame_bytes: 1 << 20,
        ..h.agent(AGENT, NODE)
    };
    let mut ws = client.connect(&h.endpoint, CONTROL_PATH).await.unwrap();
    let n = client.hello(&mut ws).await.unwrap();
    assert_eq!(n.max_frame_bytes, 65536, "the Gateway fixes the bound");

    // A frame past the negotiated bound. The Gateway's WebSocket layer refuses it at the
    // length header (max_message_size), so the payload is never buffered.
    let huge = vec![0u8; n.max_frame_bytes + 1024];
    ws.send(Message::Binary(WsBytes::from(wire::encode(
        n.ver,
        MsgType::StreamData,
        &huge,
    ))))
    .await
    .expect("the peer can put it on the wire");

    // The Gateway answers with the coarse PROTOCOL error and closes — it never delivers
    // the frame. (Heartbeat PINGs may arrive first.)
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.next_frame(&mut ws, n.ver).await {
                Ok(f) if f.msg_type == MsgType::Ping => continue,
                Ok(f) if f.msg_type == MsgType::Error => {
                    assert_eq!(
                        wire::as_wire_error(&f).unwrap().code,
                        WireErrorCode::Protocol as i32
                    );
                    // …and the connection is closed straight after.
                    assert!(client.next_frame(&mut ws, n.ver).await.is_err());
                    return;
                }
                Ok(f) => panic!("gateway accepted an oversized frame: {:?}", f.msg_type),
                // A hard close without the courtesy error is equally fail-closed.
                Err(_) => return,
            }
        }
    })
    .await;
    assert!(
        outcome.is_ok(),
        "an oversized frame must kill the connection, not hang it"
    );
}

#[tokio::test]
async fn a_peer_with_no_common_protocol_version_is_rejected() {
    use futures_util::SinkExt;
    use gateway_core::pb::{ComponentInfo, ProtocolVersion};
    use tokio_tungstenite::tungstenite::{Bytes as WsBytes, Message};

    let h = Harness::start().await;
    let client = h.agent(AGENT, NODE);
    let mut ws = client.connect(&h.endpoint, CONTROL_PATH).await.unwrap();

    // An Agent from a future major line: no overlap ⇒ VERSION_REJECT, never a guess.
    let hello = gateway_core::pbagent::AgentHello {
        component: Some(ComponentInfo {
            name: "SessionLayer Agent".into(),
            semver: "9.0.0".into(),
            protocol_min: Some(ProtocolVersion { major: 2, minor: 0 }),
            protocol_max: Some(ProtocolVersion { major: 2, minor: 0 }),
        }),
    };
    ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
        2,
        MsgType::Hello,
        &hello,
    ))))
    .await
    .unwrap();

    let frame = client.next_frame(&mut ws, 1).await.unwrap();
    assert_eq!(frame.msg_type, MsgType::VersionReject);
    let reject = wire::as_version_reject(&frame).unwrap();
    assert_eq!(reject.gateway_max.unwrap().major, 1);
    assert!(h.registry.is_empty());
}

#[tokio::test]
async fn a_node_whose_agent_never_connected_is_offline_immediately() {
    let h = Harness::start().await;
    // No agent has ever registered: the connector fails closed at once (it does not
    // wait out the dial-back deadline).
    let started = std::time::Instant::now();
    assert!(matches!(
        h.dialer().connect(&node_dial("node-ghost", "sess-x")).await,
        Err(NodeConnectError::NoAgent)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
}
