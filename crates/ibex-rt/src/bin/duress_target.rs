use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ibex_quic::QuicConfig;
use ibex_quic::listener::QuicListener;

fn main() {
    let port_str = std::env::args().nth(1).unwrap_or_else(|| "4433".to_string());
    let port: u16 = port_str.parse().unwrap();
    let cert_path = "/home/bhenc/project-ibex/examples/certs/localhost.pem";

    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path)
        .expect("load cert");
    let mut listener = QuicListener::bind_with_server_config(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        server_config,
    )
    .expect("bind listener");

    println!("{}", listener.addr().port());
    use std::io::Write;
    std::io::stdout().flush().unwrap();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    }).expect("Error setting Ctrl-C handler");

    while running.load(Ordering::Relaxed) {
        let now = Instant::now();
        let _ = listener.handle_read(now);
        let _ = listener.handle_write(now);

        if let Some(timeout) = listener.poll_timeout() {
            if timeout <= now {
                listener.handle_timeout(now);
            }
        }

        while let Some(_evt) = listener.poll_event() {
            // Drop events
        }

        let timeout_ms = match listener.poll_timeout() {
            Some(deadline) => {
                let now = Instant::now();
                if deadline <= now {
                    0
                } else {
                    let diff = (deadline - now).as_millis().min(50) as i32;
                    diff.max(1)
                }
            }
            None => 50,
        };

        use std::os::fd::AsFd;
        let mut poll_fds = [rustix::event::PollFd::from_borrowed_fd(
            listener.socket().as_fd(),
            rustix::event::PollFlags::IN,
        )];
        let _ = rustix::event::poll(&mut poll_fds, timeout_ms);
    }
}
