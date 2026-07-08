/// Full server-push demo: a mock CQL server stores a signed driver binary,
/// the client connects, downloads it, verifies the signature, loads it via
/// dlopen, and calls get_driver_version() to prove new functionality arrived.
///
/// Run:
///   cargo build -p scylla-driver-impl
///   cargo run -p sign-driver -- sign scylla/keys/scylla_driver_signing_key.key target/debug/libscylla_driver_impl.so
///   cargo run --example server_push_demo
use scylla_driver_abi::{DriverVtable, InitFn, ENTRY_SYMBOL, ABI_VERSION_MAJOR, MIN_DRIVER_BUILD_NUMBER};
use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

// ═══════════════════════════════════════════════════════════════════════
// CQL v4 binary protocol helpers (just enough for the demo)
// ═══════════════════════════════════════════════════════════════════════

const CQL_VERSION: u8 = 0x04;
const CQL_RESPONSE: u8 = 0x84; // version byte for responses

// Opcodes
const OP_STARTUP: u8 = 1;
const OP_READY: u8 = 2;
const OP_OPTIONS: u8 = 5;
const OP_SUPPORTED: u8 = 6;
const OP_QUERY: u8 = 7;
const OP_RESULT: u8 = 8;

// Flags
const FLAG_CUSTOM_PAYLOAD: u8 = 0x04;

fn read_frame(stream: &mut TcpStream) -> Option<(u8, u8, u16, u8, Vec<u8>)> {
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).ok()?;
    let version = header[0];
    let flags = header[1];
    let stream_id = u16::from_be_bytes([header[2], header[3]]);
    let opcode = header[4];
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut body = vec![0u8; length];
    if length > 0 {
        stream.read_exact(&mut body).ok()?;
    }
    Some((version, flags, stream_id, opcode, body))
}

fn write_frame(stream: &mut TcpStream, flags: u8, stream_id: u16, opcode: u8, body: &[u8]) {
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.push(CQL_RESPONSE);
    frame.push(flags);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    let _ = stream.write_all(&frame);
}

// Write a CQL string_multimap to a buffer
fn write_string_multimap(buf: &mut Vec<u8>, map: &[(&str, &[&str])]) {
    // number of entries
    buf.extend_from_slice(&(map.len() as u16).to_be_bytes());
    for (key, values) in map {
        // key
        buf.extend_from_slice(&(key.len() as u16).to_be_bytes());
        buf.extend_from_slice(key.as_bytes());
        // values list
        buf.extend_from_slice(&(values.len() as u16).to_be_bytes());
        for val in *values {
            buf.extend_from_slice(&(val.len() as u16).to_be_bytes());
            buf.extend_from_slice(val.as_bytes());
        }
    }
}

// Write a CQL string_bytes_map (for custom_payload)
fn write_string_bytes_map(buf: &mut Vec<u8>, map: &[(&str, &[u8])]) {
    buf.extend_from_slice(&(map.len() as u16).to_be_bytes());
    for (key, value) in map {
        buf.extend_from_slice(&(key.len() as u16).to_be_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&(value.len() as i32).to_be_bytes());
        buf.extend_from_slice(value);
    }
}

// Read a CQL string_map from a buffer (for STARTUP)
fn read_string_map(body: &[u8]) -> Vec<(String, String)> {
    let mut pos = 0;
    let n = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let mut result = Vec::new();
    for _ in 0..n {
        let klen = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let key = String::from_utf8_lossy(&body[pos..pos + klen]).to_string();
        pos += klen;
        let vlen = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let val = String::from_utf8_lossy(&body[pos..pos + vlen]).to_string();
        pos += vlen;
        result.push((key, val));
    }
    result
}

// Read a CQL long_string from body (for QUERY)
fn read_long_string(body: &[u8]) -> String {
    let len = i32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    String::from_utf8_lossy(&body[4..4 + len]).to_string()
}

// ═══════════════════════════════════════════════════════════════════════
// Mock CQL Server
// ═══════════════════════════════════════════════════════════════════════

struct MockServer {
    driver_binary: Vec<u8>,
    driver_signature: Vec<u8>,
    driver_hash: String,
}

impl MockServer {
    fn handle_client(&self, mut stream: TcpStream) {
        println!("  [server] Client connected from {}", stream.peer_addr().unwrap());

        loop {
            let Some((_version, _flags, stream_id, opcode, body)) = read_frame(&mut stream) else {
                break;
            };

            match opcode {
                OP_OPTIONS => {
                    println!("  [server] <- OPTIONS");
                    println!("  [server] -> SUPPORTED (advertising SCYLLA_DRIVER_UPDATE)");
                    let mut resp = Vec::new();
                    write_string_multimap(&mut resp, &[
                        ("CQL_VERSION", &["3.3.1"]),
                        ("COMPRESSION", &["lz4", "snappy"]),
                        ("SCYLLA_DRIVER_UPDATE", &[""]),
                    ]);
                    write_frame(&mut stream, 0, stream_id, OP_SUPPORTED, &resp);
                }
                OP_STARTUP => {
                    let options = read_string_map(&body);
                    let has_update = options.iter().any(|(k, _)| k == "SCYLLA_DRIVER_UPDATE");
                    let client_arch = options.iter().find(|(k, _)| k == "SCYLLA_CLIENT_ARCH")
                        .map(|(_, v)| v.as_str()).unwrap_or("unknown");
                    let client_os = options.iter().find(|(k, _)| k == "SCYLLA_CLIENT_OS")
                        .map(|(_, v)| v.as_str()).unwrap_or("unknown");
                    let client_hash = options.iter().find(|(k, _)| k == "SCYLLA_DRIVER_HASH")
                        .map(|(_, v)| v.as_str()).unwrap_or("");

                    println!("  [server] <- STARTUP (update={has_update}, arch={client_arch}, os={client_os})");

                    if has_update {
                        let update_needed = client_hash != self.driver_hash;
                        println!("  [server]    Client hash: {}", if client_hash.is_empty() { "(none)" } else { client_hash });
                        println!("  [server]    Server hash: {}", &self.driver_hash[..16]);
                        println!("  [server]    Update needed: {update_needed}");

                        // Send READY with custom_payload indicating update available
                        let mut payload_buf = Vec::new();
                        let needed_str = if update_needed { b"true" as &[u8] } else { b"false" };
                        write_string_bytes_map(&mut payload_buf, &[
                            ("driver_update_needed", needed_str),
                            ("driver_hash", self.driver_hash.as_bytes()),
                            ("driver_size", format!("{}", self.driver_binary.len()).as_bytes()),
                        ]);
                        println!("  [server] -> READY (custom_payload: driver_update_needed={update_needed})");
                        write_frame(&mut stream, FLAG_CUSTOM_PAYLOAD, stream_id, OP_READY, &payload_buf);
                    } else {
                        println!("  [server] -> READY (no update)");
                        write_frame(&mut stream, 0, stream_id, OP_READY, &[]);
                    }
                }
                OP_QUERY => {
                    let query = read_long_string(&body);

                    if query.contains("SCYLLA.DRIVER_DOWNLOAD") {
                        println!("  [server] <- QUERY \"SCYLLA.DRIVER_DOWNLOAD\"");
                        println!("  [server]    Sending {} bytes binary + {} bytes signature",
                                 self.driver_binary.len(), self.driver_signature.len());

                        // Build RESULT ROWS response with 2 columns: binary, signature
                        let mut resp = Vec::new();
                        // Result kind = ROWS (0x0002)
                        resp.extend_from_slice(&2i32.to_be_bytes());
                        // Metadata flags = GLOBAL_TABLES_SPEC (0x0001)
                        resp.extend_from_slice(&1i32.to_be_bytes());
                        // Column count = 2
                        resp.extend_from_slice(&2i32.to_be_bytes());
                        // Global keyspace
                        let ks = b"system";
                        resp.extend_from_slice(&(ks.len() as u16).to_be_bytes());
                        resp.extend_from_slice(ks);
                        // Global table
                        let tbl = b"driver_download";
                        resp.extend_from_slice(&(tbl.len() as u16).to_be_bytes());
                        resp.extend_from_slice(tbl);
                        // Column 1: name="binary", type=blob(0x0003)
                        let col1 = b"binary";
                        resp.extend_from_slice(&(col1.len() as u16).to_be_bytes());
                        resp.extend_from_slice(col1);
                        resp.extend_from_slice(&0x0003u16.to_be_bytes());
                        // Column 2: name="signature", type=blob(0x0003)
                        let col2 = b"signature";
                        resp.extend_from_slice(&(col2.len() as u16).to_be_bytes());
                        resp.extend_from_slice(col2);
                        resp.extend_from_slice(&0x0003u16.to_be_bytes());
                        // Row count = 1
                        resp.extend_from_slice(&1i32.to_be_bytes());
                        // Row 1, Col 1: binary blob
                        resp.extend_from_slice(&(self.driver_binary.len() as i32).to_be_bytes());
                        resp.extend_from_slice(&self.driver_binary);
                        // Row 1, Col 2: signature blob
                        resp.extend_from_slice(&(self.driver_signature.len() as i32).to_be_bytes());
                        resp.extend_from_slice(&self.driver_signature);

                        println!("  [server] -> RESULT (ROWS: 1 row, 2 cols)");
                        write_frame(&mut stream, 0, stream_id, OP_RESULT, &resp);
                    } else {
                        println!("  [server] <- QUERY \"{query}\" (not handled, closing)");
                        break;
                    }
                }
                _ => {
                    println!("  [server] <- Unknown opcode {opcode}, ignoring");
                    break;
                }
            }
        }
        println!("  [server] Client disconnected");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Client: connect, download, verify, load
// ═══════════════════════════════════════════════════════════════════════

fn client_connect_and_download(addr: &str) -> anyhow::Result<()> {
    println!("  [client] Connecting to {addr}...");
    let mut stream = TcpStream::connect(addr)?;

    // 1. Send OPTIONS
    println!("  [client] -> OPTIONS");
    write_frame(&mut stream, 0, 1, OP_OPTIONS, &[]);

    // 2. Read SUPPORTED
    let (_, _, _, opcode, body) = read_frame(&mut stream).unwrap();
    assert_eq!(opcode, OP_SUPPORTED);
    let has_driver_update = String::from_utf8_lossy(&body)
        .contains("SCYLLA_DRIVER_UPDATE");
    println!("  [client] <- SUPPORTED (SCYLLA_DRIVER_UPDATE = {has_driver_update})");

    // 3. Send STARTUP with driver update opts
    let mut startup_body = Vec::new();
    let startup_opts: Vec<(&str, &str)> = vec![
        ("CQL_VERSION", "3.3.1"),
        ("SCYLLA_DRIVER_UPDATE", "1"),
        ("SCYLLA_CLIENT_ARCH", std::env::consts::ARCH),
        ("SCYLLA_CLIENT_OS", std::env::consts::OS),
        ("SCYLLA_DRIVER_HASH", ""),
    ];
    startup_body.extend_from_slice(&(startup_opts.len() as u16).to_be_bytes());
    for (k, v) in &startup_opts {
        startup_body.extend_from_slice(&(k.len() as u16).to_be_bytes());
        startup_body.extend_from_slice(k.as_bytes());
        startup_body.extend_from_slice(&(v.len() as u16).to_be_bytes());
        startup_body.extend_from_slice(v.as_bytes());
    }
    println!("  [client] -> STARTUP (SCYLLA_DRIVER_UPDATE=1, arch={}, os={})",
             std::env::consts::ARCH, std::env::consts::OS);
    write_frame(&mut stream, 0, 2, OP_STARTUP, &startup_body);

    // 4. Read READY with custom_payload
    let (_, flags, _, opcode, body) = read_frame(&mut stream).unwrap();
    assert_eq!(opcode, OP_READY);
    let has_payload = (flags & FLAG_CUSTOM_PAYLOAD) != 0;
    println!("  [client] <- READY (custom_payload={has_payload})");

    if !has_payload {
        println!("  [client] No driver update available");
        return Ok(());
    }

    // Parse custom_payload to find driver_update_needed
    // (simplified: just check if body contains "true")
    let update_needed = body.windows(4).any(|w| w == b"true");
    println!("  [client]    driver_update_needed = {update_needed}");

    if !update_needed {
        println!("  [client] Driver is up to date");
        return Ok(());
    }

    // 5. Send SCYLLA.DRIVER_DOWNLOAD query
    let query = "SCYLLA.DRIVER_DOWNLOAD";
    let mut query_body = Vec::new();
    query_body.extend_from_slice(&(query.len() as i32).to_be_bytes());
    query_body.extend_from_slice(query.as_bytes());
    // Query parameters: consistency=ONE, flags=0
    query_body.extend_from_slice(&1u16.to_be_bytes()); // consistency ONE
    query_body.push(0); // query flags
    println!("  [client] -> QUERY \"SCYLLA.DRIVER_DOWNLOAD\"");
    write_frame(&mut stream, 0, 3, OP_QUERY, &query_body);

    // 6. Read RESULT with binary + signature
    let (_, _, _, opcode, body) = read_frame(&mut stream).unwrap();
    assert_eq!(opcode, OP_RESULT);

    // Parse the ROWS result to extract binary and signature blobs
    let (binary, signature) = parse_download_result(&body)?;
    println!("  [client] <- RESULT ({} bytes binary, {} bytes signature)",
             binary.len(), signature.len());

    // 7. Verify signature
    println!("  [client] Verifying Ed25519 signature...");
    use ed25519_dalek::{Verifier, VerifyingKey, Signature};
    use sha2::{Digest, Sha256};

    let pub_key_bytes: [u8; 32] = *include_bytes!("../scylla/keys/scylla_driver_signing_key.pub");
    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .map_err(|e| anyhow::anyhow!("Bad public key: {e}"))?;

    let hash = Sha256::digest(&binary);
    let sig = Signature::from_slice(&signature)
        .map_err(|e| anyhow::anyhow!("Bad signature format: {e}"))?;

    verifying_key.verify(&hash, &sig)
        .map_err(|e| anyhow::anyhow!("Signature INVALID: {e}"))?;
    println!("  [client] Signature VALID (SHA-256: {}...)", hex::encode(&hash[..8]));

    // 8. Write to temp file and dlopen
    let tmp_dir = std::env::temp_dir().join("scylla-driver-demo");
    std::fs::create_dir_all(&tmp_dir)?;
    let so_path = tmp_dir.join("libscylla_driver_impl.so");
    std::fs::write(&so_path, &binary)?;
    println!("  [client] Cached to: {}", so_path.display());

    println!("  [client] Loading via dlopen...");
    let lib = unsafe { libloading::Library::new(&so_path) }
        .map_err(|e| anyhow::anyhow!("dlopen failed: {e}"))?;
    let init_fn: libloading::Symbol<InitFn> = unsafe { lib.get(ENTRY_SYMBOL.as_bytes()) }
        .map_err(|e| anyhow::anyhow!("Symbol lookup failed: {e}"))?;

    let vtable_ptr = unsafe { init_fn() };
    assert!(!vtable_ptr.is_null());
    let vtable: &DriverVtable = unsafe { &*vtable_ptr };

    // Verify ABI
    let driver_major = vtable.abi_version / 1000;
    assert_eq!(driver_major, ABI_VERSION_MAJOR, "ABI major version mismatch");
    assert!(vtable.build_number >= MIN_DRIVER_BUILD_NUMBER, "Build number too old");

    // 9. Call get_driver_version
    let version_ptr = unsafe { (vtable.get_driver_version)() };
    let version = unsafe { CStr::from_ptr(version_ptr) }.to_str()?;

    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  get_driver_version() = {:?}  ║", version);
    println!("  ╠═══════════════════════════════════════════════════════════╣");
    println!("  ║  ABI version:  {} (major={}, minor={})               ║",
             vtable.abi_version, vtable.abi_version / 1000, vtable.abi_version % 1000);
    println!("  ║  Build number: {}                                       ║", vtable.build_number);
    println!("  ║  Vtable size:  {} bytes                                 ║", vtable.vtable_size);
    println!("  ╚═══════════════════════════════════════════════════════════╝");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);
    drop(lib);

    Ok(())
}

fn parse_download_result(body: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut pos = 0;
    // Result kind (4 bytes) = ROWS
    let _kind = i32::from_be_bytes([body[pos], body[pos+1], body[pos+2], body[pos+3]]);
    pos += 4;
    // Metadata flags (4 bytes)
    let flags = i32::from_be_bytes([body[pos], body[pos+1], body[pos+2], body[pos+3]]);
    pos += 4;
    // Column count (4 bytes)
    let col_count = i32::from_be_bytes([body[pos], body[pos+1], body[pos+2], body[pos+3]]);
    pos += 4;

    // If GLOBAL_TABLES_SPEC flag is set, skip keyspace + table
    if (flags & 0x0001) != 0 {
        let ks_len = u16::from_be_bytes([body[pos], body[pos+1]]) as usize;
        pos += 2 + ks_len;
        let tbl_len = u16::from_be_bytes([body[pos], body[pos+1]]) as usize;
        pos += 2 + tbl_len;
    }

    // Skip column definitions
    for _ in 0..col_count {
        let name_len = u16::from_be_bytes([body[pos], body[pos+1]]) as usize;
        pos += 2 + name_len;
        pos += 2; // type id
    }

    // Row count (4 bytes)
    let _row_count = i32::from_be_bytes([body[pos], body[pos+1], body[pos+2], body[pos+3]]);
    pos += 4;

    // Row 1, Col 1: binary blob
    let bin_len = i32::from_be_bytes([body[pos], body[pos+1], body[pos+2], body[pos+3]]) as usize;
    pos += 4;
    let binary = body[pos..pos + bin_len].to_vec();
    pos += bin_len;

    // Row 1, Col 2: signature blob
    let sig_len = i32::from_be_bytes([body[pos], body[pos+1], body[pos+2], body[pos+3]]) as usize;
    pos += 4;
    let signature = body[pos..pos + sig_len].to_vec();

    Ok((binary, signature))
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

fn main() -> anyhow::Result<()> {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Server-Push Driver Update Demo                             ║");
    println!("║  Full CQL protocol flow: server stores binary, client       ║");
    println!("║  connects, downloads, verifies, loads, runs new code        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    // Load the driver binary and signature
    let so_path = find_driver_so();
    let sig_path = so_path.with_extension("so.sig");

    if !sig_path.exists() {
        eprintln!("ERROR: Signature file not found: {}", sig_path.display());
        eprintln!("Run: cargo run -p sign-driver -- sign scylla/keys/scylla_driver_signing_key.key {}",
                  so_path.display());
        std::process::exit(1);
    }

    let driver_binary = std::fs::read(&so_path)?;
    let driver_signature = std::fs::read(&sig_path)?;

    let hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&driver_binary))
    };

    println!();
    println!("━━━ Step 1: Admin stores signed driver on the server ━━━━━━━━━");
    println!("  Binary:    {} ({:.1} MB)", so_path.display(), driver_binary.len() as f64 / 1_000_000.0);
    println!("  Signature: {} ({} bytes)", sig_path.display(), driver_signature.len());
    println!("  SHA-256:   {}...", &hash[..16]);

    // Start mock CQL server
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    println!();
    println!("━━━ Step 2: Server starts (mock CQL on port {port}) ━━━━━━━━━━");

    let server = Arc::new(MockServer {
        driver_binary,
        driver_signature,
        driver_hash: hash,
    });

    let server_clone = server.clone();
    let server_thread = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            server_clone.handle_client(stream);
        }
    });

    println!();
    println!("━━━ Step 3: Client connects and negotiates ━━━━━━━━━━━━━━━━━━━");
    println!();

    let addr = format!("127.0.0.1:{port}");
    client_connect_and_download(&addr)?;

    server_thread.join().unwrap();

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Demo complete!                                             ║");
    println!("║                                                             ║");
    println!("║  1. Server stored a signed driver binary (.so + .sig)       ║");
    println!("║  2. Client connected via CQL protocol                       ║");
    println!("║  3. Server advertised SCYLLA_DRIVER_UPDATE in SUPPORTED     ║");
    println!("║  4. Client sent arch/OS/hash in STARTUP                     ║");
    println!("║  5. Server responded with driver_update_needed=true         ║");
    println!("║  6. Client sent SCYLLA.DRIVER_DOWNLOAD query                ║");
    println!("║  7. Server returned binary + signature via RESULT           ║");
    println!("║  8. Client verified Ed25519 signature over SHA-256          ║");
    println!("║  9. Client loaded .so via dlopen, called get_driver_version ║");
    println!("║ 10. NEW FUNCTIONALITY CONFIRMED                             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

fn find_driver_so() -> PathBuf {
    for path in &[
        "target/debug/libscylla_driver_impl.so",
        "target/release/libscylla_driver_impl.so",
        "target/debug/libscylla_driver_impl.dylib",
    ] {
        let p = PathBuf::from(path);
        if p.exists() { return p; }
    }
    eprintln!("ERROR: Build the driver first: cargo build -p scylla-driver-impl");
    std::process::exit(1);
}
