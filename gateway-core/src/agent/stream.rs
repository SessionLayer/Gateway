use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{Bytes as WsBytes, Message};
use tokio_tungstenite::WebSocketStream;

use crate::agent::wire::{self, FrameError, MsgType, HEADER_LEN};
use crate::pbagent::{StreamClose, StreamCloseReason};

pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    ver: u8,
    max_frame_bytes: usize,
    pending: Bytes,
    read_eof: bool,
    close_sent: bool,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: WebSocketStream<S>, ver: u8, max_frame_bytes: usize) -> Self {
        Self {
            ws,
            ver,
            max_frame_bytes,
            pending: Bytes::new(),
            read_eof: false,
            close_sent: false,
        }
    }

    /// The largest `STREAM_DATA` payload the Gateway puts in one frame.
    ///
    /// Deliberately `max_frame_bytes − HEADER_LEN`, whereas the Agent chunks to the full
    /// `max_frame_bytes` (the negotiated bound is on the PAYLOAD). The asymmetry is safe
    /// and intentional: each side's *receive* guard bounds the payload inclusively at
    /// `max_frame_bytes`, and each side's WebSocket message ceiling is
    /// `max_frame_bytes + HEADER_LEN` (see [`ws_config`](super::ws_config)) - so an
    /// Agent-sized frame (header + full payload) still clears the Gateway's receive limits.
    /// The Gateway staying a header under the bound just means its own frames never sit
    /// exactly on the ceiling; do not "align" it and churn the frozen wire behaviour for a
    /// purely cosmetic symmetry.
    fn max_payload(&self) -> usize {
        self.max_frame_bytes.saturating_sub(HEADER_LEN).max(1)
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn frame_err(e: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsByteStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.pending.is_empty() {
                let n = me.pending.len().min(buf.remaining());
                buf.put_slice(&me.pending[..n]);
                me.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if me.read_eof {
                return Poll::Ready(Ok(()));
            }
            let msg = match ready!(Pin::new(&mut me.ws).poll_next(cx)) {
                Some(Ok(msg)) => msg,
                Some(Err(e)) => return Poll::Ready(Err(ws_err(e))),
                None => {
                    me.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
            };
            match msg {
                Message::Binary(bytes) => {
                    let frame =
                        wire::decode(bytes, me.max_frame_bytes, me.ver).map_err(frame_err)?;
                    match frame.msg_type {
                        MsgType::StreamData => me.pending = frame.payload,
                        MsgType::StreamClose => {
                            me.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        _ => return Poll::Ready(Err(frame_err(FrameError::UnknownType))),
                    }
                }
                Message::Close(_) => {
                    me.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) => return Poll::Ready(Err(frame_err(FrameError::NotBinary))),
                Message::Frame(_) => return Poll::Ready(Err(frame_err(FrameError::UnknownType))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.close_sent {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        // The backpressure gate: Pending here means the socket is not draining, so
        // the bridge stops pulling from the other leg rather than buffering.
        ready!(Pin::new(&mut me.ws).poll_ready(cx)).map_err(ws_err)?;

        let n = buf.len().min(me.max_payload());
        let frame = wire::encode(me.ver, MsgType::StreamData, &buf[..n]);
        Pin::new(&mut me.ws)
            .start_send(Message::Binary(WsBytes::from(frame)))
            .map_err(ws_err)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.ws).poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.close_sent {
            ready!(Pin::new(&mut me.ws).poll_ready(cx)).map_err(ws_err)?;
            let close = wire::encode_msg(
                me.ver,
                MsgType::StreamClose,
                &StreamClose {
                    reason: StreamCloseReason::Eof as i32,
                },
            );
            Pin::new(&mut me.ws)
                .start_send(Message::Binary(WsBytes::from(close)))
                .map_err(ws_err)?;
            me.close_sent = true;
        }
        ready!(Pin::new(&mut me.ws).poll_flush(cx)).map_err(ws_err)?;
        Pin::new(&mut me.ws).poll_close(cx).map_err(ws_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    const VER: u8 = 1;
    const MAX: usize = 64;

    async fn pair() -> (
        WsByteStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(1024);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        (WsByteStream::new(server, VER, MAX), client)
    }

    fn data(payload: &[u8]) -> Message {
        Message::Binary(WsBytes::from(wire::encode(
            VER,
            MsgType::StreamData,
            payload,
        )))
    }

    #[tokio::test]
    async fn reads_reassemble_across_frames_and_partial_reads() {
        let (mut stream, mut peer) = pair().await;
        peer.send(data(b"hello ")).await.unwrap();
        peer.send(data(b"world")).await.unwrap();

        let mut got = Vec::new();
        let mut buf = [0u8; 4];
        while got.len() < 11 {
            let n = stream.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "must not EOF mid-stream");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, b"hello world");
    }

    #[tokio::test]
    async fn writes_are_chunked_to_the_frame_bound() {
        let (mut stream, mut peer) = pair().await;
        let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();

        let mut got = Vec::new();
        while got.len() < payload.len() {
            let msg = peer.next().await.unwrap().unwrap();
            let Message::Binary(b) = msg else {
                panic!("expected a binary frame")
            };
            assert!(b.len() <= MAX, "frame must respect max_frame_bytes");
            let frame = wire::decode(Bytes::copy_from_slice(&b), MAX, VER).unwrap();
            assert_eq!(frame.msg_type, MsgType::StreamData);
            got.extend_from_slice(&frame.payload);
        }
        assert_eq!(got, payload, "the byte stream is carried verbatim");
    }

    #[tokio::test]
    async fn stream_close_and_websocket_close_are_both_eof() {
        let mut buf = [0u8; 8];

        let (mut stream, mut peer) = pair().await;
        peer.send(Message::Binary(WsBytes::from(wire::encode_msg(
            VER,
            MsgType::StreamClose,
            &StreamClose {
                reason: StreamCloseReason::Eof as i32,
            },
        ))))
        .await
        .unwrap();
        assert_eq!(
            stream.read(&mut buf).await.unwrap(),
            0,
            "STREAM_CLOSE = EOF"
        );

        let (mut stream, mut peer) = pair().await;
        peer.close(None).await.unwrap();
        assert_eq!(
            stream.read(&mut buf).await.unwrap(),
            0,
            "a closed peer is EOF"
        );
    }

    #[tokio::test]
    async fn an_abrupt_peer_reset_is_an_error_not_a_silent_eof() {
        let (mut stream, peer) = pair().await;
        drop(peer);
        let mut buf = [0u8; 8];
        assert!(stream.read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_sends_stream_close() {
        let (mut stream, mut peer) = pair().await;
        stream.shutdown().await.unwrap();
        let msg = peer.next().await.unwrap().unwrap();
        let Message::Binary(b) = msg else {
            panic!("expected a binary frame")
        };
        let frame = wire::decode(Bytes::copy_from_slice(&b), MAX, VER).unwrap();
        assert_eq!(frame.msg_type, MsgType::StreamClose);
    }

    #[tokio::test]
    async fn an_unexpected_frame_type_on_a_live_splice_fails_closed() {
        let (mut stream, mut peer) = pair().await;
        peer.send(Message::Binary(WsBytes::from(wire::encode(
            VER,
            MsgType::DialBackAuth,
            b"x",
        ))))
        .await
        .unwrap();
        let mut buf = [0u8; 8];
        assert!(
            stream.read(&mut buf).await.is_err(),
            "only STREAM_DATA/STREAM_CLOSE are legal once the splice is live"
        );
    }

    #[tokio::test]
    async fn a_text_message_is_a_protocol_error() {
        let (mut stream, mut peer) = pair().await;
        peer.send(Message::Text("nope".into())).await.unwrap();
        let mut buf = [0u8; 8];
        assert!(stream.read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn writes_apply_backpressure_instead_of_buffering() {
        let (a, _b) = tokio::io::duplex(512);
        let ws =
            WebSocketStream::from_raw_socket(a, Role::Server, Some(super::super::ws_config(MAX)))
                .await;
        let mut stream = WsByteStream::new(ws, VER, MAX);

        let mut written = 0usize;
        let chunk = [7u8; 32];
        let result = tokio::time::timeout(std::time::Duration::from_millis(300), async {
            loop {
                stream.write_all(&chunk).await?;
                stream.flush().await?;
                written += chunk.len();
                if written > 1024 * 1024 {
                    return Ok::<(), io::Error>(());
                }
            }
        })
        .await;
        assert!(
            result.is_err(),
            "the write must block on backpressure, not buffer {written} bytes"
        );
        assert!(
            written < 512 * 1024,
            "far less than the attempted volume must have been accepted; got {written}"
        );
    }
}
