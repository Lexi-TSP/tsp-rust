//! TSP License Artifact v1 structural/shape validation (ADR-0010).
//!
//! Rust port of the gateway's license-schema.js: a closed-allowlist validator
//! for tsp.license-bundle.v1 and its two signed bodies. Independent of
//! validate_trust_envelope_shape() -- never merge the two.
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

const LICENSE_ARTIFACT: &str = "tsp.license.v1";
const ISSUER_CRED_ARTIFACT: &str = "tsp.license-issuer-credential.v1";
const BUNDLE_ARTIFACT: &str = "tsp.license-bundle.v1";
const EDITIONS: &[&str] = &["trial", "pro", "enterprise"];
const PRIVATE_JWK_PARAMS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

fn re_datetime() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$").unwrap())
}

fn has_only(value: &Map<String, Value>, path: &str, allowed: &[&str], errors: &mut Vec<String>) {
    for key in value.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{path}.{key} is not allowed"));
        }
    }
}

fn record_at<'a>(parent: &'a Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) -> Option<&'a Map<String, Value>> {
    match parent.get(key).and_then(|v| v.as_object()) {
        Some(m) => Some(m),
        None => {
            errors.push(format!("{path}.{key} must be an object"));
            None
        }
    }
}

fn string_at<'a>(parent: &'a Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) -> Option<&'a str> {
    match parent.get(key).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Some(s),
        _ => {
            errors.push(format!("{path}.{key} must be a non-empty string"));
            None
        }
    }
}

fn datetime_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if let Some(s) = string_at(parent, key, path, errors) {
        if !re_datetime().is_match(s) {
            errors.push(format!("{path}.{key} must be an ISO-8601 date-time string"));
        }
    }
}

fn optional_datetime_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if parent.contains_key(key) {
        datetime_at(parent, key, path, errors);
    }
}

fn string_array_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>, optional: bool) {
    match parent.get(key) {
        None if optional => {}
        Some(Value::Array(arr)) => {
            for (i, e) in arr.iter().enumerate() {
                if !e.is_string() {
                    errors.push(format!("{path}.{key}[{i}] must be a string"));
                }
            }
        }
        _ => errors.push(format!("{path}.{key} must be an array")),
    }
}

fn ed25519_public_jwk_at(parent: &Map<String, Value>, key: &str, parent_path: &str, errors: &mut Vec<String>) {
    let path = format!("{parent_path}.{key}");
    let jwk = match parent.get(key).and_then(|v| v.as_object()) {
        Some(m) => m,
        None => {
            errors.push(format!("{path} must be an object"));
            return;
        }
    };
    has_only(jwk, &path, &["kty", "crv", "x", "alg", "use", "kid", "ext", "key_ops"], errors);
    let priv_present: Vec<&str> = PRIVATE_JWK_PARAMS.iter().copied().filter(|k| jwk.contains_key(*k)).collect();
    if !priv_present.is_empty() {
        errors.push(format!("{path} must not contain private JWK parameter(s): {}", priv_present.join(", ")));
    }
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("OKP") {
        errors.push(format!("{path}.kty must be OKP for Ed25519 public keys"));
    }
    if jwk.get("crv").and_then(|v| v.as_str()) != Some("Ed25519") {
        errors.push(format!("{path}.crv must be Ed25519"));
    }
    match jwk.get("x").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => {}
        _ => errors.push(format!("{path}.x must be a non-empty public key value")),
    }
    if let Some(alg) = jwk.get("alg").and_then(|v| v.as_str()) {
        if alg != "Ed25519" && alg != "EdDSA" {
            errors.push(format!("{path}.alg must be Ed25519 or EdDSA when present"));
        }
    }
}

fn signature_block_at(parent: &Map<String, Value>, key: &str, parent_path: &str, errors: &mut Vec<String>) {
    let path = format!("{parent_path}.{key}");
    let block = match parent.get(key).and_then(|v| v.as_object()) {
        Some(m) => m,
        None => {
            errors.push(format!("{path} must be an object"));
            return;
        }
    };
    has_only(block, &path, &["algorithm", "signature"], errors);
    if let Some(alg) = string_at(block, "algorithm", &path, errors) {
        if alg != "ed25519" {
            errors.push(format!("{path}.algorithm must be ed25519"));
        }
    }
    string_at(block, "signature", &path, errors);
}

fn validate_license_body(license: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let license = match license {
        Some(m) => m,
        None => return,
    };
    has_only(
        license,
        "license",
        &["artifact_type", "license_id", "issuer_id", "subject", "edition", "modules", "features", "issuedAt", "validFrom", "validUntil", "graceUntil"],
        errors,
    );
    if let Some(at) = string_at(license, "artifact_type", "license", errors) {
        if at != LICENSE_ARTIFACT {
            errors.push(format!("license.artifact_type must be \"{LICENSE_ARTIFACT}\""));
        }
    }
    string_at(license, "license_id", "license", errors);
    string_at(license, "issuer_id", "license", errors);
    if let Some(subject) = record_at(license, "subject", "license", errors) {
        has_only(subject, "license.subject", &["origin", "allowedOrigins", "organization"], errors);
        string_at(subject, "origin", "license.subject", errors);
        string_at(subject, "organization", "license.subject", errors);
        string_array_at(subject, "allowedOrigins", "license.subject", errors, true);
    }
    if let Some(edition) = string_at(license, "edition", "license", errors) {
        if !EDITIONS.contains(&edition) {
            errors.push("license.edition must be trial, pro, or enterprise".to_string());
        }
    }
    string_array_at(license, "modules", "license", errors, false);
    string_array_at(license, "features", "license", errors, true);
    datetime_at(license, "issuedAt", "license", errors);
    datetime_at(license, "validFrom", "license", errors);
    datetime_at(license, "validUntil", "license", errors);
    optional_datetime_at(license, "graceUntil", "license", errors);
}

fn validate_issuer_credential(ic: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let ic = match ic {
        Some(m) => m,
        None => return,
    };
    has_only(ic, "issuerCredential", &["credential", "rootSignature"], errors);
    if let Some(cred) = record_at(ic, "credential", "issuerCredential", errors) {
        has_only(cred, "issuerCredential.credential", &["artifact_type", "issuer_id", "issuerPublicKey", "validFrom", "validUntil", "rootKeyId"], errors);
        if let Some(at) = string_at(cred, "artifact_type", "issuerCredential.credential", errors) {
            if at != ISSUER_CRED_ARTIFACT {
                errors.push(format!("issuerCredential.credential.artifact_type must be \"{ISSUER_CRED_ARTIFACT}\""));
            }
        }
        string_at(cred, "issuer_id", "issuerCredential.credential", errors);
        ed25519_public_jwk_at(cred, "issuerPublicKey", "issuerCredential.credential", errors);
        datetime_at(cred, "validFrom", "issuerCredential.credential", errors);
        datetime_at(cred, "validUntil", "issuerCredential.credential", errors);
        string_at(cred, "rootKeyId", "issuerCredential.credential", errors);
    }
    signature_block_at(ic, "rootSignature", "issuerCredential", errors);
}

/// Closed-allowlist shape validation for a tsp.license-bundle.v1. Returns error strings.
pub fn validate_license_bundle_shape(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let bundle = match value.as_object() {
        Some(m) => m,
        None => return vec!["bundle must be an object".to_string()],
    };
    has_only(bundle, "bundle", &["artifact_type", "license", "licenseSignature", "issuerCredential"], &mut errors);
    if let Some(at) = string_at(bundle, "artifact_type", "bundle", &mut errors) {
        if at != BUNDLE_ARTIFACT {
            errors.push(format!("bundle.artifact_type must be \"{BUNDLE_ARTIFACT}\""));
        }
    }
    validate_license_body(record_at(bundle, "license", "bundle", &mut errors), &mut errors);
    signature_block_at(bundle, "licenseSignature", "bundle", &mut errors);
    validate_issuer_credential(record_at(bundle, "issuerCredential", "bundle", &mut errors), &mut errors);
    errors
}
