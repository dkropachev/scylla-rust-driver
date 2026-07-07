use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("generate-keypair") => {
            if args.len() != 3 {
                eprintln!("Usage: sign-driver generate-keypair <output-prefix>");
                eprintln!(
                    "  Generates <output-prefix>.key (private) and <output-prefix>.pub (public)"
                );
                std::process::exit(1);
            }
            generate_keypair(&args[2]);
        }
        Some("sign") => {
            if args.len() != 4 {
                eprintln!("Usage: sign-driver sign <private-key-file> <binary-file>");
                eprintln!("  Creates <binary-file>.sig with the Ed25519 signature");
                std::process::exit(1);
            }
            sign_binary(&args[2], &args[3]);
        }
        Some("verify") => {
            if args.len() != 5 {
                eprintln!(
                    "Usage: sign-driver verify <public-key-file> <binary-file> <signature-file>"
                );
                std::process::exit(1);
            }
            verify_binary(&args[2], &args[3], &args[4]);
        }
        _ => {
            eprintln!("ScyllaDB Driver Binary Signing Tool");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  generate-keypair <prefix>  Generate Ed25519 keypair");
            eprintln!("  sign <key> <binary>        Sign a driver binary");
            eprintln!("  verify <pub> <bin> <sig>    Verify a signature");
            std::process::exit(1);
        }
    }
}

fn generate_keypair(prefix: &str) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let key_path = format!("{prefix}.key");
    let pub_path = format!("{prefix}.pub");

    fs::write(&key_path, signing_key.to_bytes()).expect("Failed to write private key");
    fs::write(&pub_path, verifying_key.to_bytes()).expect("Failed to write public key");

    println!("Generated keypair:");
    println!("  Private key: {key_path}");
    println!("  Public key:  {pub_path}");
    println!(
        "  Public key hex: {}",
        hex::encode(verifying_key.to_bytes())
    );
}

fn sign_binary(key_path: &str, binary_path: &str) {
    let key_bytes = fs::read(key_path).expect("Failed to read private key");
    if key_bytes.len() != 32 {
        eprintln!(
            "Private key must be exactly 32 bytes, got {}",
            key_bytes.len()
        );
        std::process::exit(1);
    }

    let signing_key = SigningKey::from_bytes(&key_bytes.try_into().unwrap());
    let binary = fs::read(binary_path).expect("Failed to read binary");

    let hash = Sha256::digest(&binary);
    let signature = signing_key.sign(&hash);

    let sig_path = format!("{binary_path}.sig");
    fs::write(&sig_path, signature.to_bytes()).expect("Failed to write signature");

    println!("Signed: {binary_path}");
    println!("  SHA-256: {}", hex::encode(hash));
    println!("  Signature: {sig_path}");
}

fn verify_binary(pub_path: &str, binary_path: &str, sig_path: &str) {
    let pub_bytes = fs::read(pub_path).expect("Failed to read public key");
    if pub_bytes.len() != 32 {
        eprintln!(
            "Public key must be exactly 32 bytes, got {}",
            pub_bytes.len()
        );
        std::process::exit(1);
    }

    let verifying_key =
        VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap()).expect("Invalid public key");

    let binary = fs::read(binary_path).expect("Failed to read binary");
    let sig_bytes = fs::read(sig_path).expect("Failed to read signature");

    if sig_bytes.len() != 64 {
        eprintln!(
            "Signature must be exactly 64 bytes, got {}",
            sig_bytes.len()
        );
        std::process::exit(1);
    }

    let hash = Sha256::digest(&binary);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

    match verifying_key.verify(&hash, &signature) {
        Ok(()) => {
            println!("Signature VALID");
            println!("  SHA-256: {}", hex::encode(hash));
        }
        Err(e) => {
            eprintln!("Signature INVALID: {e}");
            std::process::exit(1);
        }
    }
}
