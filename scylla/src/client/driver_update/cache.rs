//! Local filesystem caching of downloaded driver binaries.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::signature::sha256_hex;

/// Default cache directory.
const DEFAULT_CACHE_DIR: &str = ".cache/scylla-driver";

/// Get the cache directory path, creating it if necessary.
pub(crate) fn cache_dir() -> io::Result<PathBuf> {
    let dir = if let Ok(cache) = std::env::var("SCYLLA_DRIVER_CACHE") {
        PathBuf::from(cache)
    } else if let Some(home) = dirs_home() {
        home.join(DEFAULT_CACHE_DIR)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Cannot determine cache directory",
        ));
    };

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        // Set permissions to 0700 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
    }

    Ok(dir)
}

/// Try to load a cached binary by its hash.
/// Returns None if not cached or if integrity check fails.
pub(crate) fn load_cached(hash: &str) -> Option<Vec<u8>> {
    let dir = cache_dir().ok()?;
    let path = cached_path(&dir, hash);

    if !path.exists() {
        return None;
    }

    // Verify it's a regular file (not a symlink)
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() {
        tracing::warn!("Cached driver binary is not a regular file, ignoring");
        return None;
    }

    let data = fs::read(&path).ok()?;

    // Re-verify hash matches filename
    let actual_hash = sha256_hex(&data);
    if actual_hash != hash {
        tracing::warn!("Cached driver binary hash mismatch, deleting");
        let _ = fs::remove_file(&path);
        return None;
    }

    Some(data)
}

/// Save a binary to the cache directory.
pub(crate) fn save_to_cache(hash: &str, data: &[u8]) -> io::Result<()> {
    let dir = cache_dir()?;
    let path = cached_path(&dir, hash);

    // Write to a temp file first, then rename atomically
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, data)?;
    fs::rename(&tmp_path, &path)?;

    Ok(())
}

fn cached_path(dir: &Path, hash: &str) -> PathBuf {
    dir.join(format!("libscylla_driver_{hash}.so"))
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
