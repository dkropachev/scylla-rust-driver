use std::os::raw::c_char;

/// Error codes returned by driver operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Ok = 0,
    InvalidConfig = 1,
    ConnectionFailed = 2,
    QueryFailed = 3,
    Timeout = 4,
    InternalError = 5,
    InvalidArgument = 6,
}

/// Opaque handle to a driver session. The caller must not inspect its contents.
#[repr(C)]
pub struct OpaqueSession {
    _opaque: [u8; 0],
}

/// A borrowed byte buffer passed across the FFI boundary for session configuration.
#[repr(C)]
pub struct SessionConfigBytes {
    pub data: *const u8,
    pub len: usize,
}

/// Result of a query or execute operation, returned via callback.
#[repr(C)]
pub struct QueryResult {
    pub error_code: ErrorCode,
    pub data: *const u8,
    pub data_len: usize,
    pub error_message: *const c_char,
    pub error_message_len: usize,
}

/// Opaque context pointer threaded through async callbacks.
#[repr(C)]
pub struct CallbackCtx {
    _opaque: [u8; 0],
}

/// Callback invoked when an async operation completes.
///
/// # Safety
/// The implementor must ensure that `ctx` is valid for the duration of the call
/// and that the `QueryResult` is read before the callback returns.
pub type ResultCallback = unsafe extern "C" fn(ctx: *mut CallbackCtx, result: *const QueryResult);
