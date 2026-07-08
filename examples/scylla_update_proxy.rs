/// CQL protocol proxy that sits between a client and a real ScyllaDB,
/// injecting the SCYLLA_DRIVER_UPDATE extension to enable the full
/// driver update flow with an unmodified ScyllaDB server.
///
/// Usage:
///   cargo run --example scylla_update_proxy -- [scylla_host:port] [listen_port] [driver_dir]
///
/// Then connect through the proxy:
///   SCYLLA_URI=127.0.0.1:9043 cargo run --example driver_update_demo
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

const CQL_RESPONSE: u8 = 0x84;
const OP_STARTUP: u8 = 1;
const OP_READY: u8 = 2;
const OP_OPTIONS: u8 = 5;
const OP_SUPPORTED: u8 = 6;
const OP_QUERY: u8 = 7;
const OP_RESULT: u8 = 8;
const FLAG_CUSTOM_PAYLOAD: u8 = 0x04;

struct ProxyConfig {
    scylla_addr: String,
    driver_binary: Vec<u8>,
    driver_signature: Vec<u8>,
    driver_hash: String,
}

fn read_frame(s: &mut TcpStream) -> Option<(u8, u8, u16, u8, Vec<u8>)> {
    let mut h = [0u8; 9];
    s.read_exact(&mut h).ok()?;
    let len = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) as usize;
    let mut body = vec![0u8; len];
    if len > 0 { s.read_exact(&mut body).ok()?; }
    Some((h[0], h[1], u16::from_be_bytes([h[2], h[3]]), h[4], body))
}

fn write_frame(s: &mut TcpStream, ver: u8, flags: u8, stream_id: u16, op: u8, body: &[u8]) {
    let mut f = Vec::with_capacity(9 + body.len());
    f.push(ver);
    f.push(flags);
    f.extend_from_slice(&stream_id.to_be_bytes());
    f.push(op);
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    let _ = s.write_all(&f);
}

fn forward_frame(src: &mut TcpStream, dst: &mut TcpStream) -> Option<(u8, u8, u16, u8, Vec<u8>)> {
    let (ver, flags, sid, op, body) = read_frame(src)?;
    write_frame(dst, ver, flags, sid, op, &body);
    Some((ver, flags, sid, op, body))
}

fn inject_driver_update_into_supported(original_body: &[u8]) -> Vec<u8> {
    // Parse string_multimap, add SCYLLA_DRIVER_UPDATE, re-serialize
    let mut pos = 0;
    let n = u16::from_be_bytes([original_body[pos], original_body[pos + 1]]) as usize;
    pos += 2;

    let mut entries: Vec<(String, Vec<String>)> = Vec::new();
    for _ in 0..n {
        let klen = u16::from_be_bytes([original_body[pos], original_body[pos + 1]]) as usize;
        pos += 2;
        let key = String::from_utf8_lossy(&original_body[pos..pos + klen]).to_string();
        pos += klen;
        let vcount = u16::from_be_bytes([original_body[pos], original_body[pos + 1]]) as usize;
        pos += 2;
        let mut vals = Vec::new();
        for _ in 0..vcount {
            let vlen = u16::from_be_bytes([original_body[pos], original_body[pos + 1]]) as usize;
            pos += 2;
            vals.push(String::from_utf8_lossy(&original_body[pos..pos + vlen]).to_string());
            pos += vlen;
        }
        entries.push((key, vals));
    }

    // Add our extension
    entries.push(("SCYLLA_DRIVER_UPDATE".to_string(), vec!["".to_string()]));

    // Re-serialize
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (key, vals) in &entries {
        out.extend_from_slice(&(key.len() as u16).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(vals.len() as u16).to_be_bytes());
        for v in vals {
            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            out.extend_from_slice(v.as_bytes());
        }
    }
    out
}

fn build_ready_with_update_payload() -> Vec<u8> {
    let mut buf = Vec::new();
    // string_bytes_map with driver_update_needed=true
    let entries: Vec<(&str, &[u8])> = vec![
        ("driver_update_needed", b"true"),
    ];
    buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (k, v) in &entries {
        buf.extend_from_slice(&(k.len() as u16).to_be_bytes());
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(&(v.len() as i32).to_be_bytes());
        buf.extend_from_slice(v);
    }
    buf
}

fn build_download_result(binary: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&2i32.to_be_bytes()); // ROWS
    r.extend_from_slice(&1i32.to_be_bytes()); // GLOBAL_TABLES_SPEC
    r.extend_from_slice(&2i32.to_be_bytes()); // 2 columns
    for s in &["system", "driver_download"] {
        r.extend_from_slice(&(s.len() as u16).to_be_bytes());
        r.extend_from_slice(s.as_bytes());
    }
    for (name, typ) in &[("binary", 0x0003u16), ("signature", 0x0003u16)] {
        r.extend_from_slice(&(name.len() as u16).to_be_bytes());
        r.extend_from_slice(name.as_bytes());
        r.extend_from_slice(&typ.to_be_bytes());
    }
    r.extend_from_slice(&1i32.to_be_bytes()); // 1 row
    r.extend_from_slice(&(binary.len() as i32).to_be_bytes());
    r.extend_from_slice(binary);
    r.extend_from_slice(&(signature.len() as i32).to_be_bytes());
    r.extend_from_slice(signature);
    r
}

fn read_query_string(body: &[u8]) -> String {
    if body.len() < 4 { return String::new(); }
    let len = i32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + len { return String::new(); }
    String::from_utf8_lossy(&body[4..4 + len]).to_string()
}

fn handle_client(mut client: TcpStream, config: &ProxyConfig) {
    let peer = client.peer_addr().unwrap();
    println!("  [proxy] Client connected from {peer}");

    let mut scylla = match TcpStream::connect(&config.scylla_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [proxy] Cannot connect to ScyllaDB at {}: {e}", config.scylla_addr);
            return;
        }
    };
    println!("  [proxy] Connected to ScyllaDB at {}", config.scylla_addr);

    let mut driver_update_negotiated = false;

    loop {
        // Read frame from client
        let Some((ver, flags, sid, op, body)) = read_frame(&mut client) else { break };

        match op {
            OP_OPTIONS => {
                // Forward to ScyllaDB, then inject our extension into the response
                write_frame(&mut scylla, ver, flags, sid, op, &body);
                let Some((rver, rflags, rsid, rop, rbody)) = read_frame(&mut scylla) else { break };
                assert_eq!(rop, OP_SUPPORTED);

                let modified = inject_driver_update_into_supported(&rbody);
                println!("  [proxy] OPTIONS -> SUPPORTED (injected SCYLLA_DRIVER_UPDATE)");
                write_frame(&mut client, rver, rflags, rsid, rop, &modified);
            }
            OP_STARTUP => {
                // Check if client sends SCYLLA_DRIVER_UPDATE
                let body_str = String::from_utf8_lossy(&body);
                driver_update_negotiated = body_str.contains("SCYLLA_DRIVER_UPDATE");

                // Forward STARTUP to ScyllaDB
                write_frame(&mut scylla, ver, flags, sid, op, &body);
                let Some((_rver, _rflags, rsid, rop, _rbody)) = read_frame(&mut scylla) else { break };

                if rop == OP_READY && driver_update_negotiated {
                    // Replace READY with one that has custom_payload
                    let payload = build_ready_with_update_payload();
                    println!("  [proxy] STARTUP -> READY (injected driver_update_needed=true)");
                    write_frame(&mut client, CQL_RESPONSE, FLAG_CUSTOM_PAYLOAD, rsid, OP_READY, &payload);
                } else {
                    // Forward as-is (e.g., AUTHENTICATE)
                    write_frame(&mut client, _rver, _rflags, rsid, rop, &_rbody);
                    // Handle auth flow by proxying remaining frames until READY
                    if rop != OP_READY {
                        loop {
                            // Forward client -> scylla
                            let Some((cv, cf, cs, co, cb)) = read_frame(&mut client) else { return };
                            write_frame(&mut scylla, cv, cf, cs, co, &cb);
                            // Forward scylla -> client
                            let Some((sv, sf, ss, so2, sb)) = read_frame(&mut scylla) else { return };
                            if so2 == OP_READY {
                                if driver_update_negotiated {
                                    let payload = build_ready_with_update_payload();
                                    println!("  [proxy] AUTH complete -> READY (injected driver_update_needed=true)");
                                    write_frame(&mut client, CQL_RESPONSE, FLAG_CUSTOM_PAYLOAD, ss, OP_READY, &payload);
                                } else {
                                    write_frame(&mut client, sv, sf, ss, so2, &sb);
                                }
                                break;
                            }
                            write_frame(&mut client, sv, sf, ss, so2, &sb);
                        }
                    }
                }
            }
            OP_QUERY if driver_update_negotiated => {
                let query = read_query_string(&body);
                if query.contains("SCYLLA.DRIVER_DOWNLOAD") {
                    println!("  [proxy] QUERY SCYLLA.DRIVER_DOWNLOAD -> serving {} bytes + sig",
                             config.driver_binary.len());
                    let result = build_download_result(&config.driver_binary, &config.driver_signature);
                    write_frame(&mut client, CQL_RESPONSE, 0, sid, OP_RESULT, &result);
                } else {
                    // Forward to real ScyllaDB
                    write_frame(&mut scylla, ver, flags, sid, op, &body);
                    let Some((rv, rf, rs, ro, rb)) = read_frame(&mut scylla) else { break };
                    write_frame(&mut client, rv, rf, rs, ro, &rb);
                }
            }
            _ => {
                // Transparent proxy: forward to ScyllaDB and back
                write_frame(&mut scylla, ver, flags, sid, op, &body);
                let Some((rv, rf, rs, ro, rb)) = read_frame(&mut scylla) else { break };
                write_frame(&mut client, rv, rf, rs, ro, &rb);
            }
        }
    }
    println!("  [proxy] Client {peer} disconnected");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let scylla_addr = args.get(1).cloned().unwrap_or_else(|| "172.42.0.2:9042".to_string());
    let listen_port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(9043);
    let driver_dir = args.get(3).cloned().unwrap_or_else(|| ".".to_string());

    // Find driver binary and signature
    let so_path = ["target/debug/libscylla_driver_impl.so",
                    "target/release/libscylla_driver_impl.so"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            let p = PathBuf::from(&driver_dir).join("libscylla_driver_impl.so");
            if p.exists() { p } else {
                eprintln!("ERROR: Cannot find libscylla_driver_impl.so");
                eprintln!("Run: cargo build -p scylla-driver-impl");
                std::process::exit(1);
            }
        });

    let sig_path = so_path.with_extension("so.sig");
    if !sig_path.exists() {
        eprintln!("ERROR: Signature not found: {}", sig_path.display());
        eprintln!("Run: cargo run -p sign-driver -- sign scylla/keys/scylla_driver_signing_key.key {}", so_path.display());
        std::process::exit(1);
    }

    let driver_binary = std::fs::read(&so_path).expect("read .so");
    let driver_signature = std::fs::read(&sig_path).expect("read .sig");
    let driver_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&driver_binary))
    };

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  ScyllaDB Driver Update Proxy                               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  ScyllaDB backend:  {scylla_addr}");
    println!("  Listening on:      127.0.0.1:{listen_port}");
    println!("  Driver binary:     {} ({:.1} MB)", so_path.display(),
             driver_binary.len() as f64 / 1_000_000.0);
    println!("  Driver signature:  {}", sig_path.display());
    println!("  SHA-256:           {}...", &driver_hash[..16]);
    println!();
    println!("  Connect with:");
    println!("    SCYLLA_URI=127.0.0.1:{listen_port} cargo run --example driver_update_demo");
    println!();

    let config = Arc::new(ProxyConfig {
        scylla_addr,
        driver_binary,
        driver_signature,
        driver_hash,
    });

    let listener = TcpListener::bind(format!("127.0.0.1:{listen_port}")).expect("bind");
    println!("  [proxy] Waiting for connections...");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let cfg = config.clone();
                thread::spawn(move || handle_client(client, &cfg));
            }
            Err(e) => eprintln!("  [proxy] Accept error: {e}"),
        }
    }
}
