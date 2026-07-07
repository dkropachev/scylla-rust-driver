use scylla_driver_abi::types::*;
use scylla_driver_abi::*;
use std::ffi::CStr;
use std::os::raw::c_char;

static DRIVER_VERSION: &CStr = c"0.2.0-updated";

static VTABLE: DriverVtable = DriverVtable {
    abi_version: ABI_VERSION,
    vtable_size: std::mem::size_of::<DriverVtable>(),
    build_number: 1,
    create_session: impl_create_session,
    destroy_session: impl_destroy_session,
    query_unpaged: impl_query_unpaged,
    prepare: impl_prepare,
    execute_unpaged: impl_execute_unpaged,
    get_driver_version: impl_get_driver_version,
};

#[no_mangle]
pub unsafe extern "C" fn scylla_driver_init() -> *const DriverVtable {
    &VTABLE
}

unsafe extern "C" fn impl_create_session(
    _config: *const SessionConfigBytes,
    ctx: *mut CallbackCtx,
    cb: ResultCallback,
) {
    // For the MVP, just signal success with a dummy session handle
    let result = QueryResult {
        error_code: ErrorCode::Ok,
        data: std::ptr::null(),
        data_len: 0,
        error_message: std::ptr::null(),
        error_message_len: 0,
    };
    cb(ctx, &result);
}

unsafe extern "C" fn impl_destroy_session(_session: *mut OpaqueSession) {
    // No-op for MVP
}

unsafe extern "C" fn impl_query_unpaged(
    _session: *mut OpaqueSession,
    _query: *const c_char,
    _query_len: usize,
    ctx: *mut CallbackCtx,
    cb: ResultCallback,
) {
    let result = QueryResult {
        error_code: ErrorCode::Ok,
        data: std::ptr::null(),
        data_len: 0,
        error_message: std::ptr::null(),
        error_message_len: 0,
    };
    cb(ctx, &result);
}

unsafe extern "C" fn impl_prepare(
    _session: *mut OpaqueSession,
    _query: *const c_char,
    _query_len: usize,
    ctx: *mut CallbackCtx,
    cb: ResultCallback,
) {
    let result = QueryResult {
        error_code: ErrorCode::Ok,
        data: std::ptr::null(),
        data_len: 0,
        error_message: std::ptr::null(),
        error_message_len: 0,
    };
    cb(ctx, &result);
}

unsafe extern "C" fn impl_execute_unpaged(
    _session: *mut OpaqueSession,
    _prepared_id: *const u8,
    _prepared_id_len: usize,
    _values: *const u8,
    _values_len: usize,
    ctx: *mut CallbackCtx,
    cb: ResultCallback,
) {
    let result = QueryResult {
        error_code: ErrorCode::Ok,
        data: std::ptr::null(),
        data_len: 0,
        error_message: std::ptr::null(),
        error_message_len: 0,
    };
    cb(ctx, &result);
}

unsafe extern "C" fn impl_get_driver_version() -> *const c_char {
    DRIVER_VERSION.as_ptr()
}
