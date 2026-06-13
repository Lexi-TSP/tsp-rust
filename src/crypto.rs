//! Ed25519 verification via `ed25519-dalek`.
//!
//! Verification only -- this module holds no private keys. Matches the reference
//! core's behavior: JWK `x` is base64url (no padding), signatures are standard
//! base64. Fail-closed on any decode or length error.
use base64::engine::general_purpose;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

pub fn b64url_decode(value: &str) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|e| e.to_string())
}

pub fn base64_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD.decode(value).map_err(|e| e.to_string())
}

pub fn import_public_key_jwk(jwk: &Value) -> Result<VerifyingKey, String> {
    let obj = jwk.as_object().ok_or("public key JWK must be OKP/Ed25519")?;
    if obj.get("kty").and_then(|v| v.as_str()) != Some("OKP")
        || obj.get("crv").and_then(|v| v.as_str()) != Some("Ed25519")
    {
        return Err("public key JWK must be OKP/Ed25519".to_string());
    }
    let x = obj
        .get("x")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("public key JWK is missing x")?;
    let bytes = b64url_decode(x)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

pub fn verify_ed25519(public_key: &VerifyingKey, signature: &[u8], data: &[u8]) -> bool {
    let arr: [u8; 64] = match signature.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&arr);
    public_key.verify(data, &sig).is_ok()
}
