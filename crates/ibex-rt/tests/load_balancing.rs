pub mod engine {
    pub use ibex_rt::engine::*;
}
pub mod check {
    pub use ibex_rt::check::*;
}

#[path = "../src/lb.rs"]
pub mod lb;

use ibex_config::parse_str;
use std::sync::atomic::Ordering;

fn get_proxy(config_str: &str) -> engine::Engine {
    let config = parse_str(config_str).unwrap();
    engine::Engine::new(&config, 1024).unwrap()
}

#[test]
fn test_leastconn() {
    let cfg = "
backend test_be
    mode http
    server s1 127.0.0.1:8001 weight 1 maxconn 100
    server s2 127.0.0.1:8002 weight 2 maxconn 100
    server s3 127.0.0.1:8003 weight 1 maxconn 100
";
    let mut eng = get_proxy(cfg);
    let proxy = &mut eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    proxy.server_actconn[0].store(5, Ordering::Relaxed);
    proxy.server_actconn[1].store(10, Ordering::Relaxed);
    proxy.server_actconn[2].store(5, Ordering::Relaxed);
    
    assert_eq!(lb::leastconn(proxy), Some(1));
    
    proxy.server_weights[2] = 2;
    assert_eq!(lb::leastconn(proxy), Some(2));
    
    proxy.server_actconn[1].store(2, Ordering::Relaxed);
    assert_eq!(lb::leastconn(proxy), Some(1));
}

#[test]
fn test_static_rr() {
    let cfg = "
backend test_be
    mode http
    server s1 127.0.0.1:8001 weight 2
    server s2 127.0.0.1:8002 weight 1
";
    let mut eng = get_proxy(cfg);
    let proxy = &mut eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    let mut counts = vec![0; 2];
    for _ in 0..600 {
        if let Some(idx) = lb::static_rr(proxy) {
            counts[idx] += 1;
        }
    }
    
    assert_eq!(counts[0], 400); 
    assert_eq!(counts[1], 200); 
}

#[test]
fn test_balance_uri() {
    let cfg = "
backend test_be
    mode http
    server s1 127.0.0.1:8001 weight 1
    server s2 127.0.0.1:8002 weight 1
    server s3 127.0.0.1:8003 weight 1
";
    let mut eng = get_proxy(cfg);
    let proxy = &mut eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    let uri1 = "/api/v1/users";
    let server_for_uri1 = lb::balance_uri(proxy, uri1).unwrap();
    
    for _ in 0..100 {
        assert_eq!(lb::balance_uri(proxy, uri1).unwrap(), server_for_uri1);
    }
    
    let mut counts = vec![0; 3];
    for i in 0..100 {
        let uri = format!("/api/v1/resource/{}", i);
        let idx = lb::balance_uri(proxy, &uri).unwrap();
        counts[idx] += 1;
    }
    
    assert!(counts[0] > 10);
    assert!(counts[1] > 10);
    assert!(counts[2] > 10);
}
