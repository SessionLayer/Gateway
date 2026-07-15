//! The Agent <-> Gateway frame codec (contract §2/§4).
//!
//! `VER(1) | TYPE(1) | LENGTH(u32 BE) | PAYLOAD`, one frame per WebSocket **binary**
//! message. Every payload is the protobuf message named in §4 except
//! [`MsgType::StreamData`], whose payload is raw opaque bytes — the session hot path
//! pays no encoding cost and the Agent has no decoder for what it carries.

use bytes::Bytes;
use prost::Message;

use crate::pbagent::{
    AgentHello, DialBackAccept, DialBackAuth, DialBackRequest, DialBackResult, GatewayHelloAck,
    Ping, Pong, StreamClose, StreamOpen, VersionReject, WireError, WireErrorCode,
};
// The HA relay payloads (0x24-0x26) live in the gateway package; the framing is the
// shared Agent<->Gateway v1 wire (gateway-relay-v1.md §3 reuses it verbatim).
use crate::pbgw::{RelayAccept, RelayOpen, RelayReject};

/// Fixed frame header length: `VER | TYPE | LENGTH(u32 BE)`.
pub const HEADER_LEN: usize = 6;

/// Wire message types (contract §4). Numbers are **stable**: once assigned, never
/// reused for a different meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// `AgentHello` — opens either role.
    Hello = 0x01,
    /// `GatewayHelloAck` — accepts the connection and fixes the negotiated bounds.
    HelloAck = 0x02,
    /// `VersionReject` — no common protocol version; fail closed.
    VersionReject = 0x03,
    /// `Ping` — application-level liveness (control role).
    Ping = 0x10,
    /// `Pong` — echoes a `Ping` nonce.
    Pong = 0x11,
    /// `DialBackRequest` — Gateway asks the owning Agent to dial back.
    DialBackRequest = 0x20,
    /// `DialBackResult` — the Agent's fast-fail; NEVER readiness.
    DialBackResult = 0x21,
    /// `DialBackAuth` — first frame on a dial-back connection (carries the token).
    DialBackAuth = 0x22,
    /// `DialBackAccept` — the token verified and was atomically consumed.
    DialBackAccept = 0x23,
    /// `RelayOpen` — owner→ingress, presents the SLGW1 relay token (HA, S15).
    RelayOpen = 0x24,
    /// `RelayAccept` — ingress→owner, the relay token verified; bytes may flow.
    RelayAccept = 0x25,
    /// `RelayReject` — ingress→owner, a relay binding failed; close (fail closed).
    RelayReject = 0x26,
    /// `StreamOpen` — the Agent's loopback splice is live.
    StreamOpen = 0x30,
    /// `StreamData` — **raw bytes** (SSH-layer ciphertext), no protobuf.
    StreamData = 0x31,
    /// `StreamClose` — ends a spliced stream.
    StreamClose = 0x32,
    /// `WireError` — a typed protocol error; the sender closes immediately after.
    Error = 0x7E,
}

impl MsgType {
    /// Parse a type byte. Reserved/unknown types are `None` — a protocol error
    /// until they are defined (contract §4).
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::Hello,
            0x02 => Self::HelloAck,
            0x03 => Self::VersionReject,
            0x10 => Self::Ping,
            0x11 => Self::Pong,
            0x20 => Self::DialBackRequest,
            0x21 => Self::DialBackResult,
            0x22 => Self::DialBackAuth,
            0x23 => Self::DialBackAccept,
            0x24 => Self::RelayOpen,
            0x25 => Self::RelayAccept,
            0x26 => Self::RelayReject,
            0x30 => Self::StreamOpen,
            0x31 => Self::StreamData,
            0x32 => Self::StreamClose,
            0x7E => Self::Error,
            _ => return None,
        })
    }
}

/// A decoded frame. `payload` is protobuf bytes for every type except
/// [`MsgType::StreamData`], where it is the raw session ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The negotiated protocol major carried in the `VER` byte.
    pub ver: u8,
    /// The message type.
    pub msg_type: MsgType,
    /// The payload bytes (`LENGTH` of them).
    pub payload: Bytes,
}

/// A framing / protocol violation. Every variant is fail-closed at the call site:
/// the peer gets a coarse [`WireErrorCode::Protocol`] and the connection closes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// The message is shorter than the fixed header.
    #[error("frame shorter than the {HEADER_LEN}-byte header")]
    Short,
    /// `LENGTH` does not equal the remaining message bytes (short or trailing garbage).
    #[error("frame length field does not match the message body")]
    LengthMismatch,
    /// The payload exceeds the negotiated `max_frame_bytes`.
    #[error("frame payload exceeds the negotiated maximum")]
    TooLarge,
    /// The `VER` byte is not the negotiated protocol major.
    #[error("frame version does not match the negotiated protocol major")]
    BadVersion,
    /// An unknown or still-reserved type byte.
    #[error("unknown or reserved message type")]
    UnknownType,
    /// The payload did not decode as the protobuf message its type names.
    #[error("payload did not decode as its declared protobuf message")]
    BadPayload,
    /// A WebSocket text message (the protocol is binary-only).
    #[error("text WebSocket message on a binary-only protocol")]
    NotBinary,
}

impl FrameError {
    /// The coarse code reported to the peer. Deliberately never says which check
    /// failed (§7.1 non-disclosure applies to this surface too).
    pub fn code(&self) -> WireErrorCode {
        WireErrorCode::Protocol
    }
}

/// Encode one frame. `payload` must already be the right encoding for `msg_type`.
pub fn encode(ver: u8, msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(ver);
    out.push(msg_type as u8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encode a protobuf-payload frame.
pub fn encode_msg<M: Message>(ver: u8, msg_type: MsgType, msg: &M) -> Vec<u8> {
    encode(ver, msg_type, &msg.encode_to_vec())
}

/// Encode a `WireError` frame (the only frame a peer may send before closing).
pub fn encode_error(ver: u8, code: WireErrorCode, message: &str) -> Vec<u8> {
    encode_msg(
        ver,
        MsgType::Error,
        &WireError {
            code: code as i32,
            message: message.to_string(),
        },
    )
}

/// Decode one frame, enforcing `max_frame_bytes` and the negotiated `expect_ver`.
///
/// The oversize guard here is the *second* line of defence: the WebSocket layer is
/// configured with the same bound (see [`ws_config`](super::ws_config)), so an
/// oversized frame is refused at its length header and never buffered (contract §2).
pub fn decode(bytes: Bytes, max_frame_bytes: usize, expect_ver: u8) -> Result<Frame, FrameError> {
    if bytes.len() < HEADER_LEN {
        return Err(FrameError::Short);
    }
    let ver = bytes[0];
    if ver != expect_ver {
        return Err(FrameError::BadVersion);
    }
    let msg_type = MsgType::from_u8(bytes[1]).ok_or(FrameError::UnknownType)?;
    let len = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge);
    }
    if bytes.len() - HEADER_LEN != len {
        return Err(FrameError::LengthMismatch);
    }
    Ok(Frame {
        ver,
        msg_type,
        payload: bytes.slice(HEADER_LEN..),
    })
}

/// Decode a frame's payload as the protobuf message its type names.
pub fn decode_payload<M: Message + Default>(frame: &Frame) -> Result<M, FrameError> {
    M::decode(frame.payload.as_ref()).map_err(|_| FrameError::BadPayload)
}

/// Payload decoders for the typed messages, so call sites read as intent rather
/// than turbofish.
macro_rules! payload_decoder {
    ($name:ident, $ty:ty) => {
        /// Decode this frame's payload as the named message.
        pub fn $name(frame: &Frame) -> Result<$ty, FrameError> {
            decode_payload::<$ty>(frame)
        }
    };
}

payload_decoder!(as_hello, AgentHello);
payload_decoder!(as_hello_ack, GatewayHelloAck);
payload_decoder!(as_version_reject, VersionReject);
payload_decoder!(as_ping, Ping);
payload_decoder!(as_pong, Pong);
payload_decoder!(as_dial_back_request, DialBackRequest);
payload_decoder!(as_dial_back_result, DialBackResult);
payload_decoder!(as_dial_back_auth, DialBackAuth);
payload_decoder!(as_dial_back_accept, DialBackAccept);
payload_decoder!(as_stream_open, StreamOpen);
payload_decoder!(as_stream_close, StreamClose);
payload_decoder!(as_wire_error, WireError);
payload_decoder!(as_relay_open, RelayOpen);
payload_decoder!(as_relay_accept, RelayAccept);
payload_decoder!(as_relay_reject, RelayReject);

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 65536;

    #[test]
    fn round_trips_a_protobuf_frame() {
        let ping = Ping { nonce: 42 };
        let bytes = Bytes::from(encode_msg(1, MsgType::Ping, &ping));
        let frame = decode(bytes, MAX, 1).unwrap();
        assert_eq!(frame.msg_type, MsgType::Ping);
        assert_eq!(as_ping(&frame).unwrap().nonce, 42);
    }

    #[test]
    fn round_trips_raw_stream_data() {
        // 0x31 carries raw bytes: they must survive byte-for-byte (no protobuf).
        let raw: Vec<u8> = (0u8..=255).collect();
        let bytes = Bytes::from(encode(1, MsgType::StreamData, &raw));
        let frame = decode(bytes, MAX, 1).unwrap();
        assert_eq!(frame.msg_type, MsgType::StreamData);
        assert_eq!(frame.payload.as_ref(), raw.as_slice());
    }

    #[test]
    fn empty_payload_is_valid() {
        let bytes = Bytes::from(encode(1, MsgType::StreamOpen, &[]));
        let frame = decode(bytes, MAX, 1).unwrap();
        assert!(frame.payload.is_empty());
        assert!(as_stream_open(&frame).is_ok());
    }

    #[test]
    fn short_frame_is_rejected() {
        for len in 0..HEADER_LEN {
            let bytes = Bytes::from(vec![1u8; len]);
            assert_eq!(decode(bytes, MAX, 1), Err(FrameError::Short));
        }
    }

    #[test]
    fn oversized_frame_is_rejected_by_the_length_header() {
        // The declared LENGTH alone rejects it — the body is never inspected.
        let mut bytes = vec![1u8, MsgType::StreamData as u8];
        bytes.extend_from_slice(&(MAX as u32 + 1).to_be_bytes());
        assert_eq!(
            decode(Bytes::from(bytes), MAX, 1),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn length_must_match_the_body_exactly() {
        // Truncated body.
        let mut short = encode(1, MsgType::StreamData, &[1, 2, 3, 4]);
        short.pop();
        assert_eq!(
            decode(Bytes::from(short), MAX, 1),
            Err(FrameError::LengthMismatch)
        );
        // Trailing garbage after a well-formed frame.
        let mut trailing = encode(1, MsgType::StreamData, &[1, 2, 3, 4]);
        trailing.push(0xff);
        assert_eq!(
            decode(Bytes::from(trailing), MAX, 1),
            Err(FrameError::LengthMismatch)
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let bytes = Bytes::from(encode(2, MsgType::Ping, &[]));
        assert_eq!(decode(bytes, MAX, 1), Err(FrameError::BadVersion));
    }

    #[test]
    fn ha_relay_types_are_defined_and_round_trip() {
        // 0x24-0x26 were free slots in the shared registry; the HA relay profile
        // (gateway-relay-v1.md §4) defines them additively without moving the version.
        assert_eq!(MsgType::from_u8(0x24), Some(MsgType::RelayOpen));
        assert_eq!(MsgType::from_u8(0x25), Some(MsgType::RelayAccept));
        assert_eq!(MsgType::from_u8(0x26), Some(MsgType::RelayReject));
        let open = RelayOpen {
            token: "SLGW1.x.y".into(),
        };
        let frame = decode(
            Bytes::from(encode_msg(1, MsgType::RelayOpen, &open)),
            MAX,
            1,
        )
        .unwrap();
        assert_eq!(frame.msg_type, MsgType::RelayOpen);
        assert_eq!(as_relay_open(&frame).unwrap().token, "SLGW1.x.y");
    }

    #[test]
    fn unknown_and_reserved_types_are_rejected() {
        // 0x40 NODE_STATUS, 0x50 CREDENTIAL_ROTATE and 0x7F GOAWAY are RESERVED:
        // they must be protocol errors until they are defined (contract §4).
        for t in [0x00u8, 0x40, 0x50, 0x7f, 0xff] {
            let mut bytes = vec![1u8, t];
            bytes.extend_from_slice(&0u32.to_be_bytes());
            assert_eq!(
                decode(Bytes::from(bytes), MAX, 1),
                Err(FrameError::UnknownType),
                "type {t:#x} must not decode"
            );
        }
    }

    #[test]
    fn garbage_payload_for_a_typed_frame_fails_closed() {
        // A well-framed message whose payload is not the protobuf it claims.
        let bytes = Bytes::from(encode(1, MsgType::DialBackAuth, &[0xff, 0xff, 0xff, 0xff]));
        let frame = decode(bytes, MAX, 1).unwrap();
        assert_eq!(as_dial_back_auth(&frame), Err(FrameError::BadPayload));
    }

    #[test]
    fn every_error_reports_the_coarse_protocol_code() {
        // Non-disclosure: the peer learns only PROTOCOL, never which check failed.
        for e in [
            FrameError::Short,
            FrameError::TooLarge,
            FrameError::BadVersion,
            FrameError::UnknownType,
            FrameError::BadPayload,
        ] {
            assert_eq!(e.code(), WireErrorCode::Protocol);
        }
    }
}
