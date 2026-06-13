//! Canonical signing/ledger domain construction -- SINGLE SOURCE for this port.
//!
//! The domain rule is a crypto invariant (ADR-0002): executionProvenance is
//! bound into both domains; optional envelope fields are included iff present.
//! Normative authority is tsp-spec per ADR-0008.
use serde_json::{Map, Value};

fn get(m: &Map<String, Value>, k: &str) -> Value {
    m.get(k).cloned().unwrap_or(Value::Null)
}

fn ledger_sub(envelope: &Map<String, Value>) -> Value {
    let ledger = envelope.get("ledger").and_then(|v| v.as_object());
    let mut sub = Map::new();
    match ledger {
        Some(l) => {
            sub.insert("id".into(), get(l, "id"));
            sub.insert("prevHash".into(), get(l, "prevHash"));
        }
        None => {
            sub.insert("id".into(), Value::Null);
            sub.insert("prevHash".into(), Value::Null);
        }
    }
    Value::Object(sub)
}

pub fn build_ledger_domain(envelope: &Map<String, Value>) -> Value {
    let mut d = Map::new();
    d.insert("tsp".into(), get(envelope, "tsp"));
    d.insert("content".into(), get(envelope, "content"));
    d.insert("process".into(), get(envelope, "process"));
    d.insert("signatures".into(), get(envelope, "signatures"));
    d.insert("ledger".into(), ledger_sub(envelope));
    for key in ["declaration", "alignment", "timestamp", "executionProvenance"] {
        if envelope.contains_key(key) {
            d.insert(key.into(), get(envelope, key));
        }
    }
    Value::Object(d)
}

pub fn build_signature_domain(envelope: &Map<String, Value>) -> Value {
    let mut d = Map::new();
    d.insert("tsp".into(), get(envelope, "tsp"));
    d.insert("content".into(), get(envelope, "content"));
    d.insert("process".into(), get(envelope, "process"));
    d.insert("ledger".into(), ledger_sub(envelope));
    for key in ["declaration", "alignment"] {
        if envelope.contains_key(key) {
            d.insert(key.into(), get(envelope, key));
        }
    }
    if let Some(ts) = envelope.get("timestamp").and_then(|v| v.as_object()) {
        let mut tsd = Map::new();
        tsd.insert("claimed".into(), get(ts, "claimed"));
        tsd.insert("tsaUrl".into(), get(ts, "tsaUrl"));
        d.insert("timestamp".into(), Value::Object(tsd));
    } else if envelope.contains_key("timestamp") {
        // timestamp present but not an object: mirror dict.get -> nulls
        let mut tsd = Map::new();
        tsd.insert("claimed".into(), Value::Null);
        tsd.insert("tsaUrl".into(), Value::Null);
        d.insert("timestamp".into(), Value::Object(tsd));
    }
    if envelope.contains_key("executionProvenance") {
        d.insert("executionProvenance".into(), get(envelope, "executionProvenance"));
    }
    Value::Object(d)
}
