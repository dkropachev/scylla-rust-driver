//! Ed25519 signature verification for downloaded driver binaries.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Embedded ScyllaDB release public keys (keyring).
/// In production, these would be the actual ScyllaDB release signing keys.
const SCYLLA_PUBLIC_KEYS: &[&[u8; 32]] = &[
    include_bytes!("../../../keys/scylla_driver_signing_key.pub"),
];

/// Errors that can occur during signature verification.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SignatureError {
    /// The signature bytes are not a valid Ed25519 signature.
    #[error("Invalid signature format")]
    InvalidSignature,
    /// A public key in the keyring is invalid.
    #[error("Invalid public key in keyring")]
    InvalidKey,
    /// No public key in the keyring matches the signature.
    #[error("Signature does not match any key in the keyring")]
    NoMatchingKey,
}

/// Verify that the given binary was signed by one of the embedded public keys.
///
/// The signature is verified against the SHA-256 hash of the binary content.
pub(crate) fn verify_binary(binary: &[u8], signature_bytes: &[u8]) -> Result<(), SignatureError> {
    let hash = Sha256::digest(binary);

    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| SignatureError::InvalidSignature)?;

    for key_bytes in SCYLLA_PUBLIC_KEYS {
        if let Ok(key) = VerifyingKey::from_bytes(key_bytes) {
            if key.verify(&hash, &signature).is_ok() {
                return Ok(());
            }
        }
    }

    Err(SignatureError::NoMatchingKey)
}

/// Compute the SHA-256 hash of binary content, returned as a hex string.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}
