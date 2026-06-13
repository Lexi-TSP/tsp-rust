//! TSP v3.0 local verification -- Rust port of the reference verifier core.
//!
//! Same check vocabulary and granular profiles as the JS core; conformant
//! because it reproduces the spec fixture verdicts, never because it is trusted.
//! Local-only mode: `signature.keyRef` is carried but NOT authenticated -- key
//! binding to a published manifest is an online-mode property.
use serde_json::{json, Map, Value};

use crate::canonical::canonicalize;
use crate::crypto::{base64_to_bytes, import_public_key_jwk, verify_ed25519};
use crate::domains::{build_ledger_domain, build_signature_domain};
use crate::hash::sha256_hex;
use crate::schema::validate_trust_envelope_shape;

fn passed(detail: &str) -> Value {
    json!({"status": "passed", "detail": detail})
}
fn failed(detail: &str) -> Value {
    json!({"status": "failed", "detail": detail})
}
fn skipped(detail: &str) -> Value {
    json!({"status": "skipped", "detail": detail})
}

fn canon_hash(value: &Value) -> String {
    match canonicalize(value) {
        Ok(s) => sha256_hex(&s),
        Err(_) => String::new(), // fail closed: empty hash will mismatch
    }
}

pub fn verify_local(envelope: &Value, known_public_key: &Value) -> Value {
    let mut checks = Map::new();
    checks.insert("schema".into(), skipped("not yet checked"));
    checks.insert("contentHash".into(), skipped("not yet checked"));
    checks.insert("ledgerHash".into(), skipped("not yet checked"));
    checks.insert("manifestFetch".into(), skipped("local-only mode: manifest fetch not performed"));
    checks.insert("rootSignature".into(), skipped("local-only mode: root signature not verified"));
    checks.insert("certChain".into(), skipped("local-only mode: cert chain not validated"));
    checks.insert("certValidity".into(), skipped("local-only mode: cert validity not checked"));
    checks.insert("revocation".into(), skipped("local-only mode: revocation not checked"));
    checks.insert("tsa".into(), skipped("local-only mode: TSA token not verified"));
    checks.insert("signatures".into(), Value::Array(vec![]));
    let mut warnings: Vec<Value> = Vec::new();

    let schema_errors = validate_trust_envelope_shape(envelope);
    if !schema_errors.is_empty() {
        let joined = schema_errors.join("; ");
        checks.insert(
            "schema".into(),
            json!({
                "status": "failed",
                "detail": format!("schema validation failed: {joined}"),
                "evidence": schema_errors,
            }),
        );
        return json!({"valid": false, "envelope": envelope, "checks": Value::Object(checks), "warnings": warnings});
    }
    checks.insert("schema".into(), passed("schema is well-formed"));

    let env = envelope.as_object().expect("schema passed implies object");

    // contentHash
    let content = env.get("content").and_then(|v| v.as_object());
    let content_value = content
        .and_then(|c| c.get("value"))
        .cloned()
        .unwrap_or(Value::Null);
    let claimed_content = content
        .and_then(|c| c.get("hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_content_hash = canon_hash(&content_value);
    if expected_content_hash == claimed_content {
        checks.insert("contentHash".into(), passed("content hash matches canonical(value)"));
    } else {
        checks.insert(
            "contentHash".into(),
            failed(&format!(
                "content hash mismatch: claimed {claimed_content}, computed {expected_content_hash}"
            )),
        );
    }

    // ledgerHash
    let claimed_ledger = env
        .get("ledger")
        .and_then(|v| v.as_object())
        .and_then(|l| l.get("hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_ledger_hash = canon_hash(&build_ledger_domain(env));
    if expected_ledger_hash == claimed_ledger {
        checks.insert("ledgerHash".into(), passed("ledger hash matches canonical(envelope without ledger.hash)"));
    } else {
        checks.insert(
            "ledgerHash".into(),
            failed(&format!(
                "ledger hash mismatch: claimed {claimed_ledger}, computed {expected_ledger_hash}"
            )),
        );
    }

    // signatures
    let sig_domain_bytes = match canonicalize(&build_signature_domain(env)) {
        Ok(s) => s.into_bytes(),
        Err(_) => Vec::new(),
    };
    let mut sig_results: Vec<Value> = Vec::new();
    if let Some(signatures) = env.get("signatures").and_then(|v| v.as_array()) {
        for signature in signatures {
            let alg = signature.get("algorithm").and_then(|v| v.as_str());
            if alg != Some("ed25519") {
                let shown = alg.unwrap_or("null");
                sig_results.push(failed(&format!("unsupported algorithm: {shown}")));
                continue;
            }
            let public_key = match import_public_key_jwk(known_public_key) {
                Ok(k) => k,
                Err(e) => {
                    sig_results.push(failed(&format!("could not import known public key: {e}")));
                    continue;
                }
            };
            let sig_str = signature.get("signature").and_then(|v| v.as_str()).unwrap_or("");
            let signature_bytes = match base64_to_bytes(sig_str) {
                Ok(b) => b,
                Err(e) => {
                    sig_results.push(failed(&format!("signature is not valid base64: {e}")));
                    continue;
                }
            };
            let role = signature.get("role").and_then(|v| v.as_str()).unwrap_or("null");
            if verify_ed25519(&public_key, &signature_bytes, &sig_domain_bytes) {
                sig_results.push(passed(&format!(
                    "signature valid (role={role}, algorithm=ed25519)"
                )));
            } else {
                sig_results.push(failed(&format!(
                    "signature invalid (role={role}, algorithm=ed25519)"
                )));
            }
        }
    }
    checks.insert("signatures".into(), Value::Array(sig_results.clone()));

    warnings.push(json!("local-only verify: manifest, cert-chain, TSA, DANE, and revocation checks are not performed"));
    warnings.push(json!("local-only verify: signature.keyRef is carried but NOT authenticated -- key-ref binding is an online-mode property"));

    let status_of = |v: &Value| v.get("status").and_then(|s| s.as_str()).unwrap_or("") == "passed";
    let mut valid = status_of(&checks["schema"])
        && status_of(&checks["contentHash"])
        && status_of(&checks["ledgerHash"]);
    for sr in &sig_results {
        valid = valid && status_of(sr);
    }

    json!({"valid": valid, "envelope": envelope, "checks": Value::Object(checks), "warnings": warnings})
}
