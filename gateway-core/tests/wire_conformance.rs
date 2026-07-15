//! Wire-conformance: run the FROZEN golden frames (`contracts/wire/conformance/frames.json`,
//! vendored) through the Gateway's OWN codec, so the Gateway CI catches wire drift on its own
//! (closes the F-wireversion-1 class here). No peer binary needed. The golden set includes the
//! HA `RELAY_OPEN/ACCEPT/REJECT` types (0x24-0x26), so the codec + those types are pinned
//! together byte-for-byte. Generated + self-checked by `contracts/wire/conformance/framegen`;
//! never hand-edit the JSON.

use gateway_core::agent::wire::{self, FrameError, MsgType};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proto/wire-conformance/frames.json"
));

/// The negotiated `max_frame_bytes` the golden `oversized` negative is pinned against.
const MAX: usize = 65536;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn golden_frames_decode_and_reencode_byte_exact() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).expect("parse frames.json");
    let frames = v["frames"].as_array().expect("frames[]");
    assert!(!frames.is_empty());

    for f in frames {
        let name = f["name"].as_str().unwrap();
        let ver = f["ver"].as_u64().unwrap() as u8;
        let type_byte = f["type"].as_u64().unwrap() as u8;
        let payload_hex = f["payload_hex"].as_str().unwrap();
        let frame_hex = f["frame_hex"].as_str().unwrap();

        let frame_bytes = unhex(frame_hex);
        let decoded = wire::decode(bytes::Bytes::from(frame_bytes), MAX, ver)
            .unwrap_or_else(|e| panic!("{name}: golden frame must decode, got {e:?}"));

        assert_eq!(decoded.msg_type as u8, type_byte, "{name}: type byte");
        assert_eq!(decoded.ver, ver, "{name}: ver byte");
        let got_payload: String = decoded.payload.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got_payload, payload_hex, "{name}: payload bytes");

        // Re-frame from the pieces the codec exposes → byte-identical to the golden frame.
        let reframed = wire::encode(ver, decoded.msg_type, &decoded.payload);
        let reframed_hex: String = reframed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            reframed_hex, frame_hex,
            "{name}: re-encode must match the golden frame"
        );
    }
}

#[test]
fn decoder_rejects_the_negative_vectors() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).expect("parse frames.json");
    for n in v["decode_negatives"]
        .as_array()
        .expect("decode_negatives[]")
    {
        let name = n["name"].as_str().unwrap();
        let expect = n["expect"].as_str().unwrap();
        let bytes = unhex(n["hex"].as_str().unwrap());
        // Every negative is pinned at ver=1 except `wrong_version` (which carries ver=2); decode
        // is told to expect the negotiated major 1 in all cases.
        let err = wire::decode(bytes::Bytes::from(bytes), MAX, 1)
            .expect_err(&format!("{name}: must be rejected"));
        let got = match err {
            FrameError::Short => "Short",
            FrameError::LengthMismatch => "LengthMismatch",
            FrameError::TooLarge => "TooLarge",
            FrameError::BadVersion => "BadVersion",
            FrameError::UnknownType => "UnknownType",
            FrameError::BadPayload => "BadPayload",
            FrameError::NotBinary => "NotBinary",
        };
        assert_eq!(got, expect, "{name}: wrong rejection reason");
    }
}

/// Guard the RELAY_* type-byte assignments the golden set encodes, so a codec renumbering is
/// caught in this repo even if the JSON were stale.
#[test]
fn relay_type_bytes_are_pinned() {
    assert_eq!(MsgType::RelayOpen as u8, 0x24);
    assert_eq!(MsgType::RelayAccept as u8, 0x25);
    assert_eq!(MsgType::RelayReject as u8, 0x26);
}
