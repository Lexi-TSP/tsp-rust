//! SHA-256 hex of a UTF-8 string, matching the reference core.
use sha2::{Digest, Sha256};

pub fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}
