use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IoBackend {
    #[default]
    Epoll,
    Uring,
}

pub trait AsyncIo: Send + Sync {
    fn backend(&self) -> IoBackend;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EpollIo;

impl EpollIo {
    pub fn new() -> Self {
        Self
    }
}

impl AsyncIo for EpollIo {
    fn backend(&self) -> IoBackend {
        IoBackend::Epoll
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UringIo;

impl UringIo {
    pub fn new() -> Self {
        Self
    }

    pub const fn available() -> bool {
        cfg!(all(target_os = "linux", feature = "io-uring"))
    }
}

impl AsyncIo for UringIo {
    fn backend(&self) -> IoBackend {
        IoBackend::Uring
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
impl UringIo {
    pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio_uring::start(future)
    }
}

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
