mod common;

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;


fn slow_backend(delay: Option<Duration>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                match delay {
                    Some(d) => {
                        thread::sleep(d);
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow",
                        );
                    }
                    None => thread::sleep(Duration::from_secs(30)),
                }
            });
        }
    });
    addr
}

fn keepalive_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0
                        || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Ibex {
    fn start(cfg: &str, fe: SocketAddr) -> Self {
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(fe).is_err() {
            assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
            thread::sleep(Duration::from_millis(20));
        }
        Self { child, _cfg: f }
    }

    fn signal(&self, sig: Signal) {
        let pid = Pid::from_raw(i32::try_from(self.child.id()).expect("pid")).expect("pid");
        kill_process(pid, sig).expect("kill");
    }

    fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(st) = self.child.try_wait().expect("try_wait") {
                return Some(st);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http_config(fe: SocketAddr, be: SocketAddr, global: &str) -> String {
    format!(
        "global\n{global}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe} proto h2\n  default_backend be\n\
         backend be\n  server s1 {be}\n"
    )
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86];
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

fn recv_h2_frames(s: &mut TcpStream, timeout: Duration) -> Vec<(u8, u8, u32, Vec<u8>)> {
    s.set_read_timeout(Some(timeout)).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let start = Instant::now();
    while start.elapsed() < timeout {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 9 <= buf.len() {
        let len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | (buf[i + 2] as usize);
        let ftype = buf[i + 3];
        let flags = buf[i + 4];
        let sid = u32::from_be_bytes([buf[i + 5] & 0x7f, buf[i + 6], buf[i + 7], buf[i + 8]]);
        if i + 9 + len > buf.len() {
            break;
        }
        let payload = buf[i + 9..i + 9 + len].to_vec();
        frames.push((ftype, flags, sid, payload));
        i += 9 + len;
    }
    frames
}

#[test]
fn h2_sigusr1_finishes_the_request_in_flight_then_exits() {
    let be = slow_backend(Some(Duration::from_millis(1200)));
    let fe = common::reserve_addr();
    let mut ibex = Ibex::start(&http_config(fe, be, ""), fe);

    let mut client = TcpStream::connect(fe).expect("connect");
    client.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    client.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    client.write_all(&frame(0x01, 0x05, 1, &hpack_get("/"))).expect("headers");
    
    thread::sleep(Duration::from_millis(200));

    ibex.signal(Signal::Usr1);
    thread::sleep(Duration::from_millis(300));

    assert!(
        TcpStream::connect(fe).is_err(),
        "a soft-stopping process must stop accepting new connections"
    );

    let frames = recv_h2_frames(&mut client, Duration::from_secs(4));
    let has_data = frames.iter().any(|(ftype, _, _, _)| *ftype == 0x00);
    assert!(has_data, "the in-flight request must complete through a soft stop, received frames: {frames:?}");

    let st = ibex.wait_exit(Duration::from_secs(3));
    assert!(
        st.is_some_and(|s| s.success()),
        "after draining, the process must exit cleanly; got {st:?}"
    );
}

#[test]
fn h2_an_idle_keepalive_connection_does_not_hold_a_soft_stop_open() {
    let be = keepalive_backend();
    let fe = common::reserve_addr();
    let mut ibex = Ibex::start(&http_config(fe, be, ""), fe);

    let mut client = TcpStream::connect(fe).expect("connect");
    client.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    client.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    client.write_all(&frame(0x01, 0x05, 1, &hpack_get("/"))).expect("headers");
    
    let frames = recv_h2_frames(&mut client, Duration::from_secs(2));
    let has_data = frames.iter().any(|(ftype, _, _, _)| *ftype == 0x00);
    assert!(has_data, "setup: must receive first response");
    
    // At this point, the connection is idle and open.
    let started = Instant::now();
    ibex.signal(Signal::Usr1);
    
    let frames = recv_h2_frames(&mut client, Duration::from_secs(2));
    let has_goaway = frames.iter().any(|(ftype, _, _, _)| *ftype == 0x07);
    assert!(has_goaway, "idle h2 connection must receive GOAWAY when soft stopping");

    let st = ibex.wait_exit(Duration::from_secs(3));
    assert!(
        st.is_some_and(|s| s.success()),
        "an idle h2 connection held the soft stop open; got {st:?} after {:?}",
        started.elapsed()
    );
}
