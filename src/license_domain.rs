//! TSP License Artifact v1 signing-domain construction -- SINGLE SOURCE.
//!
//! Rust port of the gateway's license-domain.js (ADR-0010). A license is a
//! SIBLING artifact reusing the TSP crypto substrate (canonicalize / Ed25519)
//! and nothing of the TrustEnvelope semantics. The license and issuer-credential
//! bodies are CLOSED allowlists (see license_schema.rs), so each signature
//! covers its ENTIRE validated body -- schema validation MUST run before
//! signature verification so an injected unknown field is rejected structurally.
use serde_json::Value;

/// Domain for the issuer-signed license signature: the whole license body.
pub fn build_license_signing_domain(license: &Value) -> &Value {
    license
}

/// Domain for the root-signed issuer-credential signature: the whole credential body.
pub fn build_issuer_credential_signing_domain(credential: &Value) -> &Value {
    credential
}
