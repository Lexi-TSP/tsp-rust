//! TrustEnvelope shape validation, ported with the reference error vocabulary.
//!
//! Allowlist-only (unknown fields rejected); error strings match the JS core so
//! the conformance suite's `errorContains` vectors hold across all ports.
use serde_json::{Map, Value};
use std::sync::OnceLock;
use regex::Regex;

pub const TSP_V3_VERSION: &str = "3.0";

fn re_sha256() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[a-f0-9]{64}$").unwrap())
}
fn re_datetime() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$").unwrap()
    })
}
fn re_lower_hex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[a-f0-9]+$").unwrap())
}

const SOURCE_TYPES: &[&str] = &[
    "legal-database", "government-website", "official-document", "academic-paper",
    "verified-website", "model-knowledge", "user-input", "unknown",
];
const CONTENT_TYPES: &[&str] = &["text", "document", "structured"];
const SEVERITIES: &[&str] = &["low", "med", "high"];
const SIGNATURE_ROLES: &[&str] = &["instance", "human-reviewer"];

fn obj(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}

/// A parseable ISO-8601 date-time, beyond the regex shape: validate field ranges
/// (the reference additionally parses; for the v3.0 fixtures range checks match).
fn parseable_date(v: &str) -> bool {
    // Expect YYYY-MM-DDThh:mm:ss[.frac][Z|±hh:mm]
    let bytes = v.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    let (year, month, day) = match (num(&v[0..4]), num(&v[5..7]), num(&v[8..10])) {
        (Some(y), Some(m), Some(d)) => (y, m, d),
        _ => return false,
    };
    let (hh, mm, ss) = match (num(&v[11..13]), num(&v[14..16]), num(&v[17..19])) {
        (Some(h), Some(mi), Some(s)) => (h, mi, s),
        _ => return false,
    };
    if month < 1 || month > 12 || day < 1 || day > 31 {
        return false;
    }
    let max_day = match month {
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= max_day && hh < 24 && mm < 60 && ss < 60
}

fn has_only(value: &Map<String, Value>, path: &str, allowed: &[&str], errors: &mut Vec<String>) {
    for key in value.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{path}.{key} is not allowed"));
        }
    }
}

fn record_at<'a>(parent: &'a Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) -> Option<&'a Map<String, Value>> {
    match parent.get(key).and_then(obj) {
        Some(m) => Some(m),
        None => {
            errors.push(format!("{path}.{key} must be an object"));
            None
        }
    }
}

fn array_at<'a>(parent: &'a Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) -> Option<&'a Vec<Value>> {
    match parent.get(key).and_then(|v| v.as_array()) {
        Some(a) => Some(a),
        None => {
            errors.push(format!("{path}.{key} must be an array"));
            None
        }
    }
}

fn string_at<'a>(parent: &'a Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) -> Option<&'a str> {
    match parent.get(key).and_then(|v| v.as_str()) {
        Some(s) => Some(s),
        None => {
            errors.push(format!("{path}.{key} must be a string"));
            None
        }
    }
}

fn optional_string_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if let Some(v) = parent.get(key) {
        if !v.is_string() {
            errors.push(format!("{path}.{key} must be a string"));
        }
    }
}

fn boolean_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if !matches!(parent.get(key), Some(Value::Bool(_))) {
        errors.push(format!("{path}.{key} must be a boolean"));
    }
}

fn is_finite_number(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.as_f64().map(|f| f.is_finite()).unwrap_or(false))
}

fn is_integer(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => {
            n.is_i64() || n.is_u64() || n.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false)
        }
        _ => false,
    }
}

fn number_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if !is_finite_number(parent.get(key)) {
        errors.push(format!("{path}.{key} must be a finite number"));
    }
}

fn integer_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if !is_integer(parent.get(key)) {
        errors.push(format!("{path}.{key} must be an integer"));
    }
}

fn sha256_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if let Some(v) = string_at(parent, key, path, errors) {
        if !re_sha256().is_match(v) {
            errors.push(format!("{path}.{key} must be a lowercase sha256 hex string"));
        }
    }
}

fn datetime_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if let Some(v) = string_at(parent, key, path, errors) {
        if !re_datetime().is_match(v) || !parseable_date(v) {
            errors.push(format!("{path}.{key} must be an ISO-8601 date-time string"));
        }
    }
}

fn lowercase_hex_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    if let Some(v) = string_at(parent, key, path, errors) {
        if !re_lower_hex().is_match(v) {
            errors.push(format!("{path}.{key} must be lowercase hexadecimal"));
        }
    }
}

fn uri_at(parent: &Map<String, Value>, key: &str, path: &str, errors: &mut Vec<String>) {
    let v = match string_at(parent, key, path, errors) {
        Some(v) => v,
        None => return,
    };
    // A scheme is present iff the value starts with `<alpha><alnum+.-*>:`.
    let has_scheme = {
        let mut chars = v.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() => {
                let rest: String = chars.collect();
                if let Some(idx) = rest.find(':') {
                    rest[..idx].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
                } else {
                    false
                }
            }
            _ => false,
        }
    };
    if !has_scheme {
        errors.push(format!("{path}.{key} must be a URI"));
    }
}

pub fn validate_trust_envelope_shape(value: &Value) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let root = match obj(value) {
        Some(m) => m,
        None => return vec!["envelope must be an object".to_string()],
    };

    has_only(root, "envelope", &["tsp", "content", "declaration", "process", "alignment", "timestamp", "ledger", "signatures", "executionProvenance"], &mut errors);

    if let Some(tsp) = string_at(root, "tsp", "envelope", &mut errors) {
        if tsp != TSP_V3_VERSION {
            errors.push(format!("envelope.tsp must be \"{TSP_V3_VERSION}\""));
        }
    }

    let content = record_at(root, "content", "envelope", &mut errors);
    validate_content(content, &mut errors);
    let declaration = record_at(root, "declaration", "envelope", &mut errors);
    validate_declaration(declaration, &mut errors);
    let process = record_at(root, "process", "envelope", &mut errors);
    validate_process(process, &mut errors);
    let alignment = record_at(root, "alignment", "envelope", &mut errors);
    validate_alignment(alignment, &mut errors);
    let timestamp = record_at(root, "timestamp", "envelope", &mut errors);
    validate_timestamp(timestamp, &mut errors);
    let ledger = record_at(root, "ledger", "envelope", &mut errors);
    validate_ledger(ledger, &mut errors);

    if let Some(signatures) = array_at(root, "signatures", "envelope", &mut errors) {
        if signatures.is_empty() {
            errors.push("envelope.signatures must contain at least one entry".to_string());
        }
        for (i, entry) in signatures.iter().enumerate() {
            validate_signature(entry, &format!("envelope.signatures[{i}]"), &mut errors);
        }
    }

    if root.contains_key("executionProvenance") {
        let ep = record_at(root, "executionProvenance", "envelope", &mut errors);
        validate_execution_provenance(ep, &mut errors);
    }

    errors
}

fn skip_empty(value: Option<&Map<String, Value>>) -> Option<&Map<String, Value>> {
    match value {
        Some(m) if !m.is_empty() => Some(m),
        _ => None,
    }
}

fn validate_content(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "content", &["type", "value", "hash"], errors);
    if let Some(t) = string_at(value, "type", "content", errors) {
        if !CONTENT_TYPES.contains(&t) {
            errors.push("content.type must be text, document, or structured".to_string());
        }
    }
    string_at(value, "value", "content", errors);
    sha256_at(value, "hash", "content", errors);
}

fn validate_declaration(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "declaration", &["primarySource", "citations"], errors);
    if let Some(ps) = record_at(value, "primarySource", "declaration", errors) {
        has_only(ps, "declaration.primarySource", &["type", "url", "title", "retrieved"], errors);
        if let Some(t) = string_at(ps, "type", "declaration.primarySource", errors) {
            if !SOURCE_TYPES.contains(&t) {
                errors.push("declaration.primarySource.type is not a v3 source type".to_string());
            }
        }
        optional_string_at(ps, "url", "declaration.primarySource", errors);
        string_at(ps, "title", "declaration.primarySource", errors);
        if ps.contains_key("retrieved") {
            datetime_at(ps, "retrieved", "declaration.primarySource", errors);
        }
    }
    if let Some(citations) = array_at(value, "citations", "declaration", errors) {
        for (i, entry) in citations.iter().enumerate() {
            let path = format!("declaration.citations[{i}]");
            match obj(entry) {
                None => errors.push(format!("{path} must be an object")),
                Some(c) => {
                    has_only(c, &path, &["url", "paragraph", "quote", "retrieved"], errors);
                    string_at(c, "url", &path, errors);
                    string_at(c, "paragraph", &path, errors);
                    string_at(c, "quote", &path, errors);
                    datetime_at(c, "retrieved", &path, errors);
                }
            }
        }
    }
}

fn validate_process(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "process", &["model", "systemPrompt", "pipeline"], errors);
    if let Some(model) = record_at(value, "model", "process", errors) {
        has_only(model, "process.model", &["provider", "name", "version", "temperature", "contextWindow"], errors);
        string_at(model, "provider", "process.model", errors);
        string_at(model, "name", "process.model", errors);
        string_at(model, "version", "process.model", errors);
        number_at(model, "temperature", "process.model", errors);
        integer_at(model, "contextWindow", "process.model", errors);
        if let Some(Value::Number(n)) = model.get("contextWindow") {
            if let Some(f) = n.as_f64() {
                if f < 0.0 {
                    errors.push("process.model.contextWindow must be non-negative".to_string());
                }
            }
        }
    }
    let sp = record_at(value, "systemPrompt", "process", errors);
    validate_system_prompt(sp, errors);
}

fn validate_system_prompt(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    sha256_at(value, "hash", "process.systemPrompt", errors);
    if value.contains_key("text") {
        has_only(value, "process.systemPrompt", &["hash", "text"], errors);
        string_at(value, "text", "process.systemPrompt", errors);
        return;
    }
    has_only(value, "process.systemPrompt", &["hash", "redacted", "reason"], errors);
    if value.get("redacted") != Some(&Value::Bool(true)) {
        errors.push("process.systemPrompt.redacted must be true".to_string());
    }
    string_at(value, "reason", "process.systemPrompt", errors);
}

fn validate_alignment(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "alignment", &["uncertainty", "flags", "humanReviewRequired", "policy", "refusal"], errors);
    if let Some(uncertainty) = array_at(value, "uncertainty", "alignment", errors) {
        for (i, entry) in uncertainty.iter().enumerate() {
            let path = format!("alignment.uncertainty[{i}]");
            match obj(entry) {
                None => errors.push(format!("{path} must be an object")),
                Some(u) => {
                    has_only(u, &path, &["field", "reason", "severity"], errors);
                    string_at(u, "field", &path, errors);
                    string_at(u, "reason", &path, errors);
                    if let Some(sev) = string_at(u, "severity", &path, errors) {
                        if !SEVERITIES.contains(&sev) {
                            errors.push(format!("{path}.severity must be low, med, or high"));
                        }
                    }
                }
            }
        }
    }
    boolean_at(value, "humanReviewRequired", "alignment", errors);
    if let Some(policy) = record_at(value, "policy", "alignment", errors) {
        has_only(policy, "alignment.policy", &["id", "version"], errors);
        string_at(policy, "id", "alignment.policy", errors);
        string_at(policy, "version", "alignment.policy", errors);
    }
}

fn validate_timestamp(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "timestamp", &["claimed", "tsaToken", "tsaUrl"], errors);
    datetime_at(value, "claimed", "timestamp", errors);
    string_at(value, "tsaToken", "timestamp", errors);
    uri_at(value, "tsaUrl", "timestamp", errors);
}

fn validate_ledger(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "ledger", &["id", "prevHash", "hash"], errors);
    string_at(value, "id", "ledger", errors);
    sha256_at(value, "prevHash", "ledger", errors);
    sha256_at(value, "hash", "ledger", errors);
}

fn validate_signature(value: &Value, path: &str, errors: &mut Vec<String>) {
    let value = match obj(value) {
        Some(v) => v,
        None => {
            errors.push(format!("{path} must be an object"));
            return;
        }
    };
    has_only(value, path, &["role", "algorithm", "keyRef", "signature", "certChain"], errors);
    if let Some(role) = string_at(value, "role", path, errors) {
        if !SIGNATURE_ROLES.contains(&role) {
            errors.push(format!("{path}.role must be instance or human-reviewer"));
        }
    }
    if let Some(alg) = string_at(value, "algorithm", path, errors) {
        if alg != "ed25519" {
            errors.push(format!("{path}.algorithm must be ed25519"));
        }
    }
    uri_at(value, "keyRef", path, errors);
    string_at(value, "signature", path, errors);
    if let Some(cert_chain) = array_at(value, "certChain", path, errors) {
        for (i, entry) in cert_chain.iter().enumerate() {
            if !entry.is_string() {
                errors.push(format!("{path}.certChain[{i}] must be a string"));
            }
        }
    }
}

fn validate_execution_provenance(value: Option<&Map<String, Value>>, errors: &mut Vec<String>) {
    let value = match skip_empty(value) { Some(v) => v, None => return };
    has_only(value, "executionProvenance", &["spatialBoundary", "temporalBoundary", "deterministicOutput"], errors);
    if let Some(sb) = record_at(value, "spatialBoundary", "executionProvenance", errors) {
        has_only(sb, "executionProvenance.spatialBoundary", &["gateway", "toolsMounted", "toolsIsolated", "o1ConstraintMet"], errors);
        string_at(sb, "gateway", "executionProvenance.spatialBoundary", errors);
        if let Some(tools) = array_at(sb, "toolsMounted", "executionProvenance.spatialBoundary", errors) {
            for (i, entry) in tools.iter().enumerate() {
                if !entry.is_string() {
                    errors.push(format!("executionProvenance.spatialBoundary.toolsMounted[{i}] must be a string"));
                }
            }
        }
        boolean_at(sb, "toolsIsolated", "executionProvenance.spatialBoundary", errors);
        boolean_at(sb, "o1ConstraintMet", "executionProvenance.spatialBoundary", errors);
    }
    if let Some(tb) = record_at(value, "temporalBoundary", "executionProvenance", errors) {
        has_only(tb, "executionProvenance.temporalBoundary", &["engine", "tier1AnchorHash", "totalContextTokens", "driftDetected"], errors);
        string_at(tb, "engine", "executionProvenance.temporalBoundary", errors);
        lowercase_hex_at(tb, "tier1AnchorHash", "executionProvenance.temporalBoundary", errors);
        integer_at(tb, "totalContextTokens", "executionProvenance.temporalBoundary", errors);
        if let Some(Value::Number(n)) = tb.get("totalContextTokens") {
            if let Some(f) = n.as_f64() {
                if f < 0.0 {
                    errors.push("executionProvenance.temporalBoundary.totalContextTokens must be non-negative".to_string());
                }
            }
        }
        boolean_at(tb, "driftDetected", "executionProvenance.temporalBoundary", errors);
    }
    if let Some(det) = record_at(value, "deterministicOutput", "executionProvenance", errors) {
        has_only(det, "executionProvenance.deterministicOutput", &["status", "payloadHash"], errors);
        string_at(det, "status", "executionProvenance.deterministicOutput", errors);
        lowercase_hex_at(det, "payloadHash", "executionProvenance.deterministicOutput", errors);
    }
}
