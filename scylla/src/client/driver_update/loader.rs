//! Dynamic loading of driver shared libraries via dlopen.

use std::ffi::CStr;
use std::sync::Arc;

use scylla_driver_abi::{
    ABI_VERSION, ABI_VERSION_MAJOR, DriverVtable, ENTRY_SYMBOL, InitFn, MIN_DRIVER_BUILD_NUMBER,
};

use super::DriverUpdateStatus;

/// A loaded driver library with its vtable.
pub(crate) struct LoadedDriver {
    /// The library handle — must stay alive as long as vtable is used.
    _lib: Arc<libloading::Library>,
    /// The driver's vtable.
    vtable: &'static DriverVtable,
}

impl std::fmt::Debug for LoadedDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedDriver")
            .field("abi_version", &self.vtable.abi_version)
            .field("build_number", &self.vtable.build_number)
            .finish()
    }
}

impl LoadedDriver {
    /// Load a driver from a shared library file path.
    ///
    /// Verifies ABI version compatibility and minimum build number.
    pub(crate) fn load(path: &std::path::Path) -> Result<Self, DriverUpdateStatus> {
        // Safety: loading a shared library can execute arbitrary code in constructors.
        // This is acceptable because we've already verified the binary's cryptographic
        // signature before reaching this point.
        let lib = unsafe { libloading::Library::new(path) }.map_err(|e| {
            tracing::error!("Failed to dlopen driver library: {}", e);
            DriverUpdateStatus::FallbackDownloadFailed {
                reason: format!("dlopen failed: {e}"),
            }
        })?;

        // Look up the init function
        let init_fn: InitFn = unsafe {
            let sym: libloading::Symbol<InitFn> =
                lib.get(ENTRY_SYMBOL.as_bytes()).map_err(|e| {
                    tracing::error!("Failed to find {} symbol: {}", ENTRY_SYMBOL, e);
                    DriverUpdateStatus::FallbackDownloadFailed {
                        reason: format!("Symbol lookup failed: {e}"),
                    }
                })?;
            *sym
        };

        // Call init to get the vtable
        let vtable_ptr = unsafe { init_fn() };
        if vtable_ptr.is_null() {
            tracing::error!("scylla_driver_init() returned null");
            return Err(DriverUpdateStatus::FallbackDownloadFailed {
                reason: "init returned null".to_string(),
            });
        }

        let vtable: &'static DriverVtable = unsafe { &*vtable_ptr };

        // Check ABI version
        let driver_major = vtable.abi_version / 1000;
        let shim_major = ABI_VERSION_MAJOR;
        if driver_major != shim_major {
            tracing::warn!(
                "Driver ABI major version mismatch: driver={}, shim={}",
                driver_major,
                shim_major
            );
            return Err(DriverUpdateStatus::FallbackAbiMismatch {
                server_abi: vtable.abi_version,
                client_abi: ABI_VERSION,
            });
        }

        // Check minimum build number (guard for when MIN_DRIVER_BUILD_NUMBER > 0)
        #[allow(clippy::absurd_extreme_comparisons)]
        if vtable.build_number < MIN_DRIVER_BUILD_NUMBER {
            tracing::warn!(
                "Driver build number {} below minimum {}",
                vtable.build_number,
                MIN_DRIVER_BUILD_NUMBER
            );
            return Err(DriverUpdateStatus::FallbackDownloadFailed {
                reason: format!(
                    "Build number {} below minimum {}",
                    vtable.build_number, MIN_DRIVER_BUILD_NUMBER
                ),
            });
        }

        let version = unsafe {
            let ptr = (vtable.get_driver_version)();
            if ptr.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };

        tracing::info!("Successfully loaded driver version: {}", version);

        Ok(LoadedDriver {
            _lib: Arc::new(lib),
            vtable,
        })
    }

    /// Get the driver's vtable.
    pub(crate) fn vtable(&self) -> &'static DriverVtable {
        self.vtable
    }

    /// Get the driver version string.
    pub(crate) fn version(&self) -> String {
        unsafe {
            let ptr = (self.vtable.get_driver_version)();
            if ptr.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn find_cdylib() -> PathBuf {
        // Look for the built cdylib in target/debug
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();

        let so_path = workspace_root.join("target/debug/libscylla_driver_impl.so");
        if so_path.exists() {
            return so_path;
        }

        let dylib_path = workspace_root.join("target/debug/libscylla_driver_impl.dylib");
        if dylib_path.exists() {
            return dylib_path;
        }

        panic!(
            "Could not find libscylla_driver_impl.so or .dylib. \
             Run `cargo build -p scylla-driver-impl` first."
        );
    }

    #[test]
    fn test_load_driver_and_get_version() {
        let path = find_cdylib();
        let driver = LoadedDriver::load(&path).expect("Failed to load driver");

        // The driver-impl crate returns "0.2.0-updated"
        assert_eq!(driver.version(), "0.2.0-updated");
    }

    #[test]
    fn test_load_driver_abi_version() {
        let path = find_cdylib();
        let driver = LoadedDriver::load(&path).expect("Failed to load driver");

        let vtable = driver.vtable();
        assert_eq!(vtable.abi_version, scylla_driver_abi::ABI_VERSION);
        assert!(vtable.vtable_size > 0);
        assert!(vtable.build_number >= MIN_DRIVER_BUILD_NUMBER);
    }

    #[test]
    fn test_load_nonexistent_library() {
        let result = LoadedDriver::load(std::path::Path::new("/nonexistent/libfoo.so"));
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverUpdateStatus::FallbackDownloadFailed { reason } => {
                assert!(reason.contains("dlopen"));
            }
            other => panic!("Expected FallbackDownloadFailed, got {:?}", other),
        }
    }
}
