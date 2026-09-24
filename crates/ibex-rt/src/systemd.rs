use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::OnceLock;

static NOTIFY_ADDR: OnceLock<Option<SocketAddr>> = OnceLock::new();

fn get_notify_addr() -> Option<SocketAddr> {
    NOTIFY_ADDR
        .get_or_init(|| {
            let sock_str = std::env::var("NOTIFY_SOCKET").ok()?;
            std::env::remove_var("NOTIFY_SOCKET");
            if sock_str.starts_with('@') {
                SocketAddr::from_abstract_name(sock_str[1..].as_bytes()).ok()
            } else if sock_str.starts_with('/') {
                SocketAddr::from_pathname(&sock_str).ok()
            } else {
                None
            }
        })
        .clone()
}

pub fn notify(message: &str) -> std::io::Result<()> {
    if let Some(addr) = get_notify_addr() {
        let sock = UnixDatagram::unbound()?;
        sock.send_to_addr(message.as_bytes(), &addr)?;
    }
    Ok(())
}

pub fn notify_ready() -> std::io::Result<()> {
    let pid = std::process::id();
    notify(&format!("READY=1\nMAINPID={pid}\nSTATUS=Ready.\n"))
}

pub fn notify_stopping() -> std::io::Result<()> {
    notify("STOPPING=1")
}

pub fn notify_reload_failed() -> std::io::Result<()> {
    notify("READY=1\nSTATUS=Reload failed!\n")
}

/// Sends `STOPPING=1` once per process, however many workers begin a soft stop.
pub fn notify_stopping_once() {
    static SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SENT.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let _ = notify_stopping();
    }
}
