//! Trust manifest validation, ported with the reference error vocabulary.
//!
//! Key-material rule: public manifests must never contain private JWK
//! parameters or symmetric key material -- presence alone is rejected.
use serde_json::{json, Map, Value};
use std::sync::OnceLock;
use regex::Regex;

const PRIVATE_JWK_PARAMETERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];
const MANIFEST_FIELDS: &[&str] = &[
    "tsp", "organization", "rootKey", "instances", "revoked", "sequence",
    "issuedAt", "acceptableAge", "rootSignatureOverManifest",
];
const PUBLIC_JWK_FIELDS: &[&str] = &["kty", "crv", "x", "alg", "use", "kid", "ext", "key_ops"];

fn re_iso() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$").unwrap()
    })
}

fn obj(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}

fn nonempty_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty())
}

fn has_only(value: &Map<String, Value>, path: &str, allowed: &[&str], errors: &mut Vec<String>) {
    for key in value.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{path}.{key} is not allowed"));
        }
    }
}

fn require_record<'a>(parent: &'a Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) -> Option<&'a Map<String, Value>> {
    match parent.get(key).and_then(obj) {
        Some(m) => Some(m),
        None => {
            errors.push(format!("{path}.{key} must be an object"));
            None
        }
    }
}

fn require_string(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if !nonempty_str(parent.get(key)) {
        errors.push(format!("{path}.{key} must be a non-empty string"));
    }
}

fn parseable_iso(v: &str) -> bool {
    // Mirror schema::parseable_date range checks for ISO date-times.
    if v.len() < 19 {
        return false;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    let (y, mo, d) = match (num(&v[0..4]), num(&v[5..7]), num(&v[8..10])) {
        (Some(y), Some(m), Some(d)) => (y, m, d),
        _ => return false,
    };
    let (hh, mi, ss) = match (num(&v[11..13]), num(&v[14..16]), num(&v[17..19])) {
        (Some(h), Some(m), Some(s)) => (h, m, s),
        _ => return false,
    };
    if mo < 1 || mo > 12 || d < 1 {
        return false;
    }
    let max_day = match mo {
        2 => if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 },
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    d <= max_day && hh < 24 && mi < 60 && ss < 60
}

fn require_iso_datetime(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    match parent.get(key) {
        Some(Value::String(s)) if !s.is_empty() => {
            if !re_iso().is_match(s) || !parseable_iso(s) {
                errors.push(format!("{path}.{key} must be an ISO-8601 date-time string"));
            }
        }
        _ => errors.push(format!("{path}.{key} must be a non-empty string")),
    }
}

fn validate_public_jwk(jwk: &Value, path: &str, errors: &mut Vec<String>) {
    let jwk = match obj(jwk) {
        Some(j) => j,
        None => {
            errors.push(format!("{path} must be an object"));
            return;
        }
    };
    has_only(jwk, path, PUBLIC_JWK_FIELDS, errors);
    let private: Vec<&str> = PRIVATE_JWK_PARAMETERS
        .iter()
        .copied()
        .filter(|p| jwk.contains_key(*p))
        .collect();
    if !private.is_empty() {
        errors.push(format!("{path} must not contain private JWK parameter(s): {}", private.join(", ")));
    }
    if jwk.get("kty").and_then(|v| v.as_str()) == Some("oct") || jwk.contains_key("k") {
        errors.push(format!("{path} must not contain symmetric key material"));
    }
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("OKP") {
        errors.push(format!("{path}.kty must be OKP for Ed25519 public keys"));
    }
    if jwk.get("crv").and_then(|v| v.as_str()) != Some("Ed25519") {
        errors.push(format!("{path}.crv must be Ed25519"));
    }
    if !nonempty_str(jwk.get("x")) {
        errors.push(format!("{path}.x must be a non-empty public key value"));
    }
    if let Some(alg) = jwk.get("alg") {
        let ok = matches!(alg.as_str(), Some("Ed25519") | Some("EdDSA"));
        if !ok {
            errors.push(format!("{path}.alg must be Ed25519 or EdDSA when present"));
        }
    }
}

pub fn validate_trust_manifest(manifest: &Value) -> Value {
    let mut errors: Vec<String> = Vec::new();
    let manifest = match obj(manifest) {
        Some(m) => m,
        None => return json!({"errors": ["manifest must be a JSON object"], "ok": false}),
    };

    has_only(manifest, "manifest", MANIFEST_FIELDS, &mut errors);
    if manifest.get("tsp").and_then(|v| v.as_str()) != Some("3.0") {
        errors.push("manifest.tsp must be \"3.0\"".to_string());
    }

    if let Some(org) = require_record(manifest, "organization", "manifest", &mut errors) {
        has_only(org, "manifest.organization", &["name", "domain"], &mut errors);
        require_string(org, "name", "manifest.organization", &mut errors);
        require_string(org, "domain", "manifest.organization", &mut errors);
    }

    let null = Value::Null;
    validate_public_jwk(manifest.get("rootKey").unwrap_or(&null), "manifest.rootKey", &mut errors);

    match manifest.get("instances").and_then(|v| v.as_array()) {
        Some(instances) if !instances.is_empty() => {
            let mut seen: Vec<String> = Vec::new();
            for (i, instance) in instances.iter().enumerate() {
                let path = format!("manifest.instances[{i}]");
                match obj(instance) {
                    None => errors.push(format!("{path} must be an object")),
                    Some(inst) => {
                        has_only(inst, &path, &["id", "publicKey", "validFrom", "validUntil", "rootSignature"], &mut errors);
                        require_string(inst, "id", &path, &mut errors);
                        validate_public_jwk(inst.get("publicKey").unwrap_or(&null), &format!("{path}.publicKey"), &mut errors);
                        require_iso_datetime(inst, "validFrom", &path, &mut errors);
                        require_iso_datetime(inst, "validUntil", &path, &mut errors);
                        require_string(inst, "rootSignature", &path, &mut errors);
                        if let Some(id) = inst.get("id").and_then(|v| v.as_str()) {
                            if seen.contains(&id.to_string()) {
                                errors.push(format!("manifest.instances contains duplicate instance id \"{id}\""));
                            }
                            seen.push(id.to_string());
                        }
                    }
                }
            }
        }
        _ => errors.push("manifest.instances must be a non-empty array".to_string()),
    }

    match manifest.get("revoked").and_then(|v| v.as_array()) {
        Some(revoked) => {
            for (i, entry) in revoked.iter().enumerate() {
                let path = format!("manifest.revoked[{i}]");
                match obj(entry) {
                    None => errors.push(format!("{path} must be an object")),
                    Some(e) => {
                        has_only(e, &path, &["id", "revokedAt", "reason"], &mut errors);
                        require_string(e, "id", &path, &mut errors);
                        require_iso_datetime(e, "revokedAt", &path, &mut errors);
                        require_string(e, "reason", &path, &mut errors);
                    }
                }
            }
        }
        None => errors.push("manifest.revoked must be an array".to_string()),
    }

    let seq_ok = match manifest.get("sequence") {
        Some(Value::Number(n)) => (n.is_i64() || n.is_u64()) && n.as_i64().map(|x| x >= 0).unwrap_or(n.is_u64()),
        _ => false,
    };
    if !seq_ok {
        errors.push("manifest.sequence must be a non-negative integer".to_string());
    }

    require_iso_datetime(manifest, "issuedAt", "manifest", &mut errors);
    if let Some(age) = require_record(manifest, "acceptableAge", "manifest", &mut errors) {
        has_only(age, "manifest.acceptableAge", &["seconds"], &mut errors);
        let pos = matches!(age.get("seconds"), Some(Value::Number(n)) if n.as_f64().map(|f| f > 0.0).unwrap_or(false));
        if !pos {
            errors.push("manifest.acceptableAge.seconds must be a positive number".to_string());
        }
    }
    require_string(manifest, "rootSignatureOverManifest", "manifest", &mut errors);

    let ok = errors.is_empty();
    json!({"errors": errors, "ok": ok})
}
