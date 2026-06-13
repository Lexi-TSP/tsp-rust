//! License verifier unit tests (ADR-0010), against the vendored license-v1 snapshot.
use serde_json::{json, Value};
use std::path::PathBuf;
use tsp_verify::verify_license;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance").join("spec-snapshot").join("fixtures").join("license-v1")
}

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join(name)).unwrap()).unwrap()
}

fn roots() -> Value {
    let rf = load("license-root-key.json");
    json!([{ "rootKeyId": rf["rootKeyId"], "publicKey": rf["publicKey"] }])
}

fn cfg(origin: &str, required: Value) -> Value {
    json!({ "origin": origin, "trustedRootKeys": roots(), "requiredModules": required })
}

#[test]
fn valid_pro() {
    let r = verify_license(&load("valid-pro.json"), &cfg("https://customer.example", json!([])), "2026-07-01T00:00:00.000Z").unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["reason"], "valid");
}

#[test]
fn allowed_origin_and_module_gate() {
    let staging = verify_license(&load("valid-pro.json"), &cfg("https://staging.customer.example", json!([])), "2026-07-01T00:00:00.000Z").unwrap();
    assert_eq!(staging["ok"], true);
    let denied = verify_license(&load("valid-pro.json"), &cfg("https://customer.example", json!(["enterprise-policy"])), "2026-07-01T00:00:00.000Z").unwrap();
    assert_eq!(denied["reason"], "module_not_licensed");
}

#[test]
fn failure_modes() {
    let cases = [
        ("valid-pro.json", "https://evil.example", "2026-07-01T00:00:00.000Z", "origin_mismatch"),
        ("valid-pro.json", "https://customer.example", "2026-10-01T00:00:00.000Z", "license_expired"),
        ("valid-pro.json", "https://customer.example", "2027-01-01T00:00:00.000Z", "issuer_expired"),
        ("tampered-license.json", "https://customer.example", "2026-07-01T00:00:00.000Z", "license_signature_invalid"),
        ("untrusted-root.json", "https://customer.example", "2026-07-01T00:00:00.000Z", "untrusted_root"),
        ("issuer-mismatch.json", "https://customer.example", "2026-07-01T00:00:00.000Z", "issuer_mismatch"),
        ("schema-invalid.json", "https://customer.example", "2026-07-01T00:00:00.000Z", "schema_invalid"),
    ];
    for (file, origin, now, want) in cases {
        let r = verify_license(&load(file), &cfg(origin, json!([])), now).unwrap();
        assert_eq!(r["reason"], want, "{file}");
    }
}

#[test]
fn grace() {
    let r = verify_license(&load("in-grace.json"), &cfg("https://customer.example", json!([])), "2026-06-10T00:00:00.000Z").unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["reason"], "valid_in_grace");
    assert_eq!(r["in_grace"], true);
}

#[test]
fn misconfig_is_err() {
    assert!(verify_license(&load("valid-pro.json"), &json!({ "origin": "", "trustedRootKeys": roots() }), "2026-07-01T00:00:00.000Z").is_err());
    assert!(verify_license(&load("valid-pro.json"), &json!({ "origin": "https://x", "trustedRootKeys": [] }), "2026-07-01T00:00:00.000Z").is_err());
}
