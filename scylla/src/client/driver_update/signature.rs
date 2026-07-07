//! Ed25519 signature verification for downloaded driver binaries.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Embedded ScyllaDB release public keys (keyring).
/// In production, these would be the actual ScyllaDB release signing keys.
const SCYLLA_PUBLIC_KEYS: &[&[u8; 32]] = &[include_bytes!(
    "../../../keys/scylla_driver_signing_key.pub"
)];

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
        if let Ok(key) = VerifyingKey::from_bytes(key_bytes)
            && key.verify(&hash, &signature).is_ok()
        {
            return Ok(());
        }
    }

    Err(SignatureError::NoMatchingKey)
}

/// Compute the SHA-256 hash of binary content, returned as a hex string.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_verify_with_matching_key() {
        // Load the test private key and sign some data
        let key_bytes: [u8; 32] = *include_bytes!("../../../keys/scylla_driver_signing_key.key");
        let signing_key = SigningKey::from_bytes(&key_bytes);

        let data = b"test driver binary content";
        let hash = Sha256::digest(data);
        let signature = signing_key.sign(&hash);

        // Verify should succeed
        assert!(verify_binary(data, &signature.to_bytes()).is_ok());
    }

    #[test]
    fn test_verify_with_wrong_data() {
        let key_bytes: [u8; 32] = *include_bytes!("../../../keys/scylla_driver_signing_key.key");
        let signing_key = SigningKey::from_bytes(&key_bytes);

        let data = b"test driver binary content";
        let hash = Sha256::digest(data);
        let signature = signing_key.sign(&hash);

        // Verify with different data should fail
        let wrong_data = b"tampered content";
        assert!(verify_binary(wrong_data, &signature.to_bytes()).is_err());
    }

    #[test]
    fn test_verify_with_invalid_signature() {
        let data = b"test driver binary content";
        // 64 bytes of zeros is a validly-formatted but wrong signature
        assert!(verify_binary(data, &[0u8; 64]).is_err());
    }

    #[test]
    fn test_verify_with_short_signature() {
        let data = b"test driver binary content";
        // Too short to be a valid signature
        assert!(verify_binary(data, &[0u8; 10]).is_err());
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
