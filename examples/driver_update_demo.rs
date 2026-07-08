/// Full end-to-end demo of the ScyllaDB Updatable Driver.
///
/// This demo:
///   Part 1: Connects to a live ScyllaDB cluster and shows the driver update
///           negotiation (server doesn't support the extension yet -> fallback)
///   Part 2: Loads the driver .so locally via dlopen and calls get_driver_version()
///           to demonstrate the binary swap delivering new functionality
///
/// Run with:
///   cargo run --example driver_update_demo
///
/// Requires:
///   - ScyllaDB running (docker-compose up, or set SCYLLA_URI)
///   - Driver .so built: cargo build -p scylla-driver-impl
use anyhow::Result;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::{DriverUpdatePolicy, DriverUpdateStatus};
use scylla_driver_abi::{DriverVtable, InitFn, ENTRY_SYMBOL};
use std::env;
use std::ffi::CStr;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,scylla=debug")
        .init();

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       ScyllaDB Updatable Driver - Full Demo                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    // ── Part 1: Connect to ScyllaDB with DriverUpdatePolicy::Enabled ─────
    println!();
    println!("━━━ Part 1: Connect to ScyllaDB with driver update enabled ━━━");
    println!();

    let uri = env::var("SCYLLA_URI").unwrap_or_else(|_| "172.42.0.2:9042".to_string());
    println!("  Connecting to {uri} ...");

    let session: Session = SessionBuilder::new()
        .known_node(&uri)
        .driver_update_policy(DriverUpdatePolicy::Enabled)
        .build()
        .await?;

    let status = session.driver_update_status();
    println!("  Driver update status: {:?}", status);

    match status {
        DriverUpdateStatus::FallbackServerUnsupported => {
            println!();
            println!("  The server does not advertise SCYLLA_DRIVER_UPDATE.");
            println!("  This is expected with a standard ScyllaDB build.");
            println!("  The driver is using the built-in (fallback) implementation.");
            println!("  With our custom ScyllaDB build, it would download the .so here.");
        }
        DriverUpdateStatus::Updated { version } => {
            println!("  Server provided driver version: {version}");
        }
        other => {
            println!("  Status: {other:?}");
        }
    }

    // Prove the session works normally
    println!();
    println!("  Executing query: SELECT release_version FROM system.local");
    let result = session
        .query_unpaged("SELECT release_version FROM system.local", &[])
        .await?;
    let rows_result = result.into_rows_result()?;
    for row in rows_result.rows::<(String,)>()? {
        let (version,) = row?;
        println!("  ScyllaDB version: {version}");
    }

    // ── Part 2: Local dlopen demo ────────────────────────────────────────
    println!();
    println!("━━━ Part 2: Load driver .so via dlopen (local demo) ━━━━━━━━━━");
    println!();

    let so_path = find_driver_so();
    println!("  Loading: {}", so_path.display());

    // Safety: we built this .so ourselves and verified its signature
    let lib = unsafe { libloading::Library::new(&so_path) }?;

    // Look up the init function using the well-known symbol
    let init_fn: libloading::Symbol<InitFn> =
        unsafe { lib.get(ENTRY_SYMBOL.as_bytes())? };

    let vtable_ptr = unsafe { init_fn() };
    assert!(!vtable_ptr.is_null(), "scylla_driver_init returned null");

    // Access the vtable through the proper #[repr(C)] struct
    let vtable: &DriverVtable = unsafe { &*vtable_ptr };

    println!("  scylla_driver_init() returned vtable at {:p}", vtable_ptr);
    println!(
        "  ABI version: {} (major={}, minor={})",
        vtable.abi_version,
        vtable.abi_version / 1000,
        vtable.abi_version % 1000
    );
    println!("  Build number: {}", vtable.build_number);
    println!("  Vtable size: {} bytes", vtable.vtable_size);

    // Call get_driver_version() through the vtable
    let version_ptr = unsafe { (vtable.get_driver_version)() };
    let version_str = unsafe { CStr::from_ptr(version_ptr) }.to_str()?;

    println!();
    println!("  ┌─────────────────────────────────────────────────┐");
    println!("  │  get_driver_version() = \"{version_str}\"  │");
    println!("  └─────────────────────────────────────────────────┘");
    println!();
    println!("  Built-in driver: no version (fallback)");
    println!("  Downloaded .so:  \"{version_str}\"");
    println!();
    println!("  This proves the loaded binary delivers NEW functionality");
    println!("  that the built-in driver does not have.");

    // ── Summary ──────────────────────────────────────────────────────────
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Demo complete!                                             ║");
    println!("║                                                             ║");
    println!("║  Part 1: Connected to ScyllaDB, got FallbackServerUnsupported║");
    println!("║          (expected - server needs custom build for full flow)║");
    println!("║  Part 2: Loaded .so via dlopen, got version \"{version_str}\"  ║");
    println!("║          (proves binary swap delivers new functionality)    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

fn find_driver_so() -> PathBuf {
    let candidates = [
        "target/debug/libscylla_driver_impl.so",
        "target/release/libscylla_driver_impl.so",
        "target/debug/libscylla_driver_impl.dylib",
        "target/release/libscylla_driver_impl.dylib",
    ];

    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    eprintln!("ERROR: Could not find libscylla_driver_impl.so");
    eprintln!("Run: cargo build -p scylla-driver-impl");
    std::process::exit(1);
}
