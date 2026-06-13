//! TSP canonicalization (RFC 8785-style JCS), ported from the reference core.
//!
//! The two traps, reproduced exactly:
//! - Numbers serialize as ECMAScript `Number::toString` (shortest round-trip;
//!   integral values without a trailing ".0"; exponential form only at >= 1e21
//!   or < 1e-6). All JSON numbers are treated as IEEE-754 doubles, matching the
//!   normative JS reference (not Python's int/float split); integers beyond 2^53
//!   are not representable and are absent from the v3.0 fixtures.
//! - Object keys sort by UTF-16 code units (JS string comparison), not Unicode
//!   code points. Sorting by the UTF-16 encoding reproduces JS for astral chars.
//!
//! Fail-closed: non-finite numbers and unsupported values return an error.
use serde_json::Value;

#[derive(Debug)]
pub struct CanonicalError(pub String);

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CanonicalError {}

fn canonical_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Serialize a finite f64 exactly as ECMAScript `Number::toString`.
pub fn es_number(value: f64) -> Result<String, CanonicalError> {
    if value.is_nan() || value.is_infinite() {
        return Err(CanonicalError(format!(
            "canonicalize: non-finite number not allowed: {value}"
        )));
    }
    if value == 0.0 {
        return Ok("0".to_string()); // covers -0.0, matching the reference core
    }
    let neg = value < 0.0;
    let abs = value.abs();
    // Rust's `{:e}` gives shortest round-trip digits in scientific form, e.g.
    // "1.5e22", "7e0", "3.14159e0", "1e-7".
    let sci = format!("{abs:e}");
    let (mantissa, exp_str) = sci.split_once('e').expect("scientific form has 'e'");
    let exp: i32 = exp_str.parse().expect("valid exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1; // mantissa is d.ddd: first significant digit is at 10^exp
    let body = format_es(&digits, k, n);
    Ok(if neg { format!("-{body}") } else { body })
}

fn format_es(digits: &str, k: i32, n: i32) -> String {
    if k <= n && n <= 21 {
        let mut s = String::from(digits);
        s.push_str(&"0".repeat((n - k) as usize));
        s
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        format!("{}.{}", &digits[..split], &digits[split..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let sign = if e >= 0 { "+" } else { "-" };
        let mag = e.abs();
        if k == 1 {
            format!("{digits}e{sign}{mag}")
        } else {
            format!("{}.{}e{sign}{mag}", &digits[..1], &digits[1..])
        }
    }
}

pub fn canonicalize(value: &Value) -> Result<String, CanonicalError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        Value::Number(n) => {
            let f = n
                .as_f64()
                .ok_or_else(|| CanonicalError("canonicalize: non-numeric number".to_string()))?;
            es_number(f)
        }
        Value::String(s) => Ok(canonical_string(s)),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(canonicalize(item)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let v = canonicalize(&map[key])?;
                parts.push(format!("{}:{}", canonical_string(key), v));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}
