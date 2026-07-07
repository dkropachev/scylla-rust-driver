//! Driver update mechanism — download, verify, cache, and load
//! server-distributed driver binaries.

#[allow(dead_code)]
pub(crate) mod cache;
#[allow(dead_code)]
pub(crate) mod loader;
#[allow(dead_code)]
pub(crate) mod signature;

/// Policy for driver updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DriverUpdatePolicy {
    /// Download and use server-provided driver if available, fall back to built-in.
    #[default]
    Enabled,
    /// Always use built-in driver, never attempt update.
    Disabled,
    /// Require server-provided driver. Fail session creation if unavailable.
    Required,
}

/// Status of the driver update for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriverUpdateStatus {
    /// Successfully loaded a server-provided driver.
    Updated {
        /// Version string of the loaded driver.
        version: String,
    },
    /// Server doesn't support driver updates.
    FallbackServerUnsupported,
    /// Already running the latest driver version.
    FallbackUpToDate,
    /// Download failed, using built-in.
    FallbackDownloadFailed {
        /// Reason for the failure.
        reason: String,
    },
    /// Signature verification failed, using built-in.
    FallbackSignatureFailed,
    /// ABI version mismatch, using built-in.
    FallbackAbiMismatch {
        /// Server driver ABI version.
        server_abi: u32,
        /// Client shim ABI version.
        client_abi: u32,
    },
    /// Driver update is disabled by policy.
    Disabled,
}
