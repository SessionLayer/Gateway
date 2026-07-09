//! The async-I/O seam.
//!
//! The Gateway's data plane copies SSH plaintext between the outer leg (the
//! user) and the inner leg (the node) on a hot path. That copy is abstracted
//! behind [`AsyncIo`] so the reactor can be chosen per deployment:
//!
//! - [`EpollIo`] — the portable epoll/tokio reactor. Always available; the
//!   default and the fallback. Maximises ecosystem compatibility (russh, tonic,
//!   hyper all assume a tokio reactor).
//! - [`UringIo`] — an io_uring reactor (Linux, behind the `io-uring` feature).
//!   Lower syscall overhead on the byte-copy hot path; selected only when it is
//!   actually available.
//!
//! Session One ships the seam only — the trait, both backends, and the
//! [`select_io`] selector proven by unit tests. No SSH bytes move yet; the
//! copy methods land with the SSH legs in a later session.

use serde::{Deserialize, Serialize};

/// Which async reactor backs an [`AsyncIo`] implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IoBackend {
    /// Portable epoll/tokio reactor. Always available; the default and the
    /// fallback when io_uring is unavailable.
    #[default]
    Epoll,
    /// io_uring reactor (Linux, `io-uring` feature). Selected only when it is
    /// actually available; otherwise a request for it degrades to [`Epoll`].
    ///
    /// [`Epoll`]: IoBackend::Epoll
    Uring,
}

/// The reactor-agnostic async byte-I/O seam for the SSH bridge.
///
/// Session One defines only [`AsyncIo::backend`]; the byte-copy methods are
/// added with the SSH legs in a later session. Kept object-safe so
/// [`select_io`] can return a `Box<dyn AsyncIo>` chosen at runtime from config.
pub trait AsyncIo: Send + Sync {
    /// The reactor backing this implementation.
    fn backend(&self) -> IoBackend;
}

/// Epoll/tokio implementation of [`AsyncIo`] — the portable default and fallback.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollIo;

impl EpollIo {
    /// Construct the epoll backend.
    pub fn new() -> Self {
        Self
    }
}

impl AsyncIo for EpollIo {
    fn backend(&self) -> IoBackend {
        IoBackend::Epoll
    }
}

/// io_uring implementation of [`AsyncIo`] (Linux, `io-uring` feature).
#[derive(Clone, Copy, Debug, Default)]
pub struct UringIo;

impl UringIo {
    /// Construct the io_uring backend.
    pub fn new() -> Self {
        Self
    }

    /// Whether the io_uring reactor is usable in this build: it requires Linux
    /// *and* the `io-uring` cargo feature. When false, [`select_io`] degrades a
    /// `Uring` request to [`EpollIo`] rather than failing — the fast path is an
    /// optimisation, never a hard dependency.
    pub const fn available() -> bool {
        cfg!(all(target_os = "linux", feature = "io-uring"))
    }
}

impl AsyncIo for UringIo {
    fn backend(&self) -> IoBackend {
        IoBackend::Uring
    }
}

/// io_uring runtime entrypoint, present when the reactor is available.
///
/// This wires and type-checks the `tokio-uring` dependency from Session One so
/// its supply chain is under cargo-audit/cargo-deny now. It is intentionally
/// NOT exercised this session: there is no SSH I/O yet, and CI sandboxes may
/// lack the io_uring syscalls. The real hot-path copy lands with the SSH bridge.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
impl UringIo {
    /// Run `future` to completion on a thread-local io_uring runtime.
    ///
    /// PRECONDITION: must be called on a dedicated OS thread that is NOT already
    /// inside a tokio runtime — `tokio_uring::start` spins up its own runtime and
    /// panics ("Cannot start a runtime from within a runtime") if nested. The
    /// SSH bridge will drive this on its own thread; it is not called from the
    /// process's multi-threaded tokio runtime.
    pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio_uring::start(future)
    }
}

/// Select an [`AsyncIo`] backend for `requested`.
///
/// Honours the request when possible and degrades a `Uring` request to the
/// portable [`EpollIo`] when io_uring is unavailable in this build (see
/// [`UringIo::available`]). Deny-safe by construction: an unavailable fast path
/// never fails the Gateway, it falls back to epoll.
pub fn select_io(requested: IoBackend) -> Box<dyn AsyncIo> {
    match requested {
        IoBackend::Epoll => Box::new(EpollIo::new()),
        IoBackend::Uring if UringIo::available() => Box::new(UringIo::new()),
        IoBackend::Uring => Box::new(EpollIo::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoll_is_always_selected_for_epoll() {
        assert_eq!(select_io(IoBackend::Epoll).backend(), IoBackend::Epoll);
    }

    #[test]
    fn uring_selected_when_available_else_falls_back_to_epoll() {
        let got = select_io(IoBackend::Uring).backend();
        if UringIo::available() {
            assert_eq!(
                got,
                IoBackend::Uring,
                "io_uring available -> Uring must be selected"
            );
        } else {
            assert_eq!(
                got,
                IoBackend::Epoll,
                "io_uring unavailable -> must fall back to Epoll"
            );
        }
    }

    #[test]
    fn availability_matches_build_cfg() {
        assert_eq!(
            UringIo::available(),
            cfg!(all(target_os = "linux", feature = "io-uring"))
        );
    }

    #[test]
    fn backend_serde_is_kebab_case() {
        assert_eq!(
            serde_json::to_string(&IoBackend::Uring).unwrap(),
            "\"uring\""
        );
        assert_eq!(
            serde_json::to_string(&IoBackend::Epoll).unwrap(),
            "\"epoll\""
        );
        let parsed: IoBackend = serde_json::from_str("\"epoll\"").unwrap();
        assert_eq!(parsed, IoBackend::Epoll);
    }
}
