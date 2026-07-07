pub mod types;

use std::os::raw::c_char;

use types::{CallbackCtx, OpaqueSession, ResultCallback, SessionConfigBytes};

/// Major ABI version. Incremented on breaking changes.
pub const ABI_VERSION_MAJOR: u32 = 1;

/// Minor ABI version. Incremented on backwards-compatible additions.
pub const ABI_VERSION_MINOR: u32 = 0;

/// Combined ABI version: major * 1000 + minor.
pub const ABI_VERSION: u32 = ABI_VERSION_MAJOR * 1000 + ABI_VERSION_MINOR;

/// Minimum driver build number accepted by the host.
pub const MIN_DRIVER_BUILD_NUMBER: u64 = 0;

/// The well-known symbol name that a driver shared library must export.
pub const ENTRY_SYMBOL: &str = "scylla_driver_init";

/// Signature of the entry-point function exported by the driver shared library.
///
/// # Safety
/// The caller must ensure that the returned `DriverVtable` pointer is valid
/// for the lifetime of the loaded library.
pub type InitFn = unsafe extern "C" fn() -> *const DriverVtable;

/// The virtual function table that a loaded driver exposes to the host.
///
/// All function pointers use the C calling convention. Async operations
/// (create_session, query_unpaged, prepare, execute_unpaged) signal
/// completion through a `ResultCallback`.
#[repr(C)]
pub struct DriverVtable {
    /// Must equal [`ABI_VERSION`] (or a compatible value).
    pub abi_version: u32,

    /// Size of this struct in bytes, for forward-compatibility checks.
    pub vtable_size: usize,

    /// Monotonically increasing build number of the driver.
    pub build_number: u64,

    /// Create a new session from serialized configuration bytes.
    ///
    /// On completion the callback receives a `QueryResult` whose `data` field
    /// points to an `OpaqueSession` on success.
    pub create_session: unsafe extern "C" fn(
        config: *const SessionConfigBytes,
        ctx: *mut CallbackCtx,
        cb: ResultCallback,
    ),

    /// Destroy a session previously created via `create_session`.
    pub destroy_session: unsafe extern "C" fn(session: *mut OpaqueSession),

    /// Execute a one-shot CQL query (unpaged).
    pub query_unpaged: unsafe extern "C" fn(
        session: *mut OpaqueSession,
        query: *const c_char,
        query_len: usize,
        ctx: *mut CallbackCtx,
        cb: ResultCallback,
    ),

    /// Prepare a CQL statement for later execution.
    pub prepare: unsafe extern "C" fn(
        session: *mut OpaqueSession,
        query: *const c_char,
        query_len: usize,
        ctx: *mut CallbackCtx,
        cb: ResultCallback,
    ),

    /// Execute a previously prepared statement (unpaged).
    pub execute_unpaged: unsafe extern "C" fn(
        session: *mut OpaqueSession,
        prepared_id: *const u8,
        prepared_id_len: usize,
        values: *const u8,
        values_len: usize,
        ctx: *mut CallbackCtx,
        cb: ResultCallback,
    ),

    /// Return a pointer to a null-terminated string describing the driver version.
    ///
    /// The returned pointer must remain valid for the lifetime of the loaded library.
    pub get_driver_version: unsafe extern "C" fn() -> *const c_char,
}
