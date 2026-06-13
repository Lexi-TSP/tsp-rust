//! verify_license() -- TSP License Artifact v1 offline verifier (ADR-0010).
//!
//! Rust port of the gateway's verify-license.js. Normative invariant: a license
//! MUST be verifiable WITHOUT contacting LexiCo -- this performs no network I/O.
//! Validates a tsp.license-bundle.v1 through the two-tier offline trust hierarchy
//! (license -> issuer -> pinned license-root), reusing the TSP crypto substrate.
//! Independent of verify_local() / the TrustEnvelope schema, which are untouched.
//!
//! Returns Ok(json!{"ok", "reason", "detail", ...}) in a CLOSED reason
//! vocabulary; Err(String) is reserved for caller misconfiguration (the analog
//! of the JS/Python throw): missing origin, empty pinned root set, or an
//! unparseable `now`.
use serde_json::{json, Value};

use crate::canonical::canonicalize;
use crate::crypto::{base64_to_bytes, import_public_key_jwk, verify_ed25519};
use crate::license_domain::{build_issuer_credential_signing_domain, build_license_signing_domain};
use crate::license_schema::validate_license_bundle_shape;

fn fail(reason: &str, detail: &str) -> Value {
    json!({ "ok": false, "reason": reason, "detail": detail })
}

fn verify_canonical_ed25519(public_jwk: &Value, signature_b64: &str, body: &Value) -> Result<bool, String> {
    let key = import_public_key_jwk(public_jwk)?;
    let sig = base64_to_bytes(signature_b64)?;
    let data = canonicalize(body).map_err(|e| e.to_string())?;
    Ok(verify_ed25519(&key, &sig, data.as_bytes()))
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse an ISO-8601 date-time (UTC `Z` or `±HH:MM` offset) to POSIX milliseconds.
fn to_epoch_ms(s: &str) -> Result<i64, String> {
    let bad = || format!("unparseable date-time: {s}");
    if s.len() < 19 {
        return Err(bad());
    }
    let num = |a: usize, z: usize| -> Result<i64, String> {
        s.get(a..z).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad)
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);

    let rest = &s[19..];
    let rb = rest.as_bytes();
    let mut frac_ms: i64 = 0;
    let mut idx = 0usize;
    if !rb.is_empty() && rb[0] == b'.' {
        let mut j = 1;
        while j < rb.len() && rb[j].is_ascii_digit() {
            j += 1;
        }
        let mut f = rest[1..j].to_string();
        f.truncate(3);
        while f.len() < 3 {
            f.push('0');
        }
        frac_ms = f.parse::<i64>().unwrap_or(0);
        idx = j;
    }
    let tz = &rest[idx..];
    let offset_min: i64 = if tz.is_empty() || tz == "Z" || tz == "z" {
        0
    } else {
        let tb = tz.as_bytes();
        let sign = match tb[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return Err(format!("bad timezone: {tz}")),
        };
        let oh = tz.get(1..3).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad)?;
        let om = tz.get(4..6).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad)?;
        sign * (oh * 60 + om)
    };

    let secs = days_from_civil(year, month, day) * 86400 + hh * 3600 + mm * 60 + ss - offset_min * 60;
    Ok(secs * 1000 + frac_ms)
}

/// Verify a tsp.license-bundle.v1 fully offline.
///
/// `config` is `{ "origin": str, "trustedRootKeys": [{ "rootKeyId", "publicKey" }],
/// "requiredModules": [str] }`. `now` is an ISO-8601 date-time.
pub fn verify_license(bundle: &Value, config: &Value, now: &str) -> Result<Value, String> {
    let origin = config
        .get("origin")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("verify_license: config.origin is required")?
        .to_string();
    let roots = config
        .get("trustedRootKeys")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or("verify_license: config.trustedRootKeys must be a non-empty pinned root set")?;
    let required: Vec<String> = config
        .get("requiredModules")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let now_ms = to_epoch_ms(now)?;

    let errors = validate_license_bundle_shape(bundle);
    if !errors.is_empty() {
        return Ok(fail("schema_invalid", &errors.join("; ")));
    }

    let license = &bundle["license"];
    let cred = &bundle["issuerCredential"]["credential"];

    if license["artifact_type"].as_str() != Some("tsp.license.v1") {
        return Ok(fail("unsupported_artifact", "license.artifact_type is not supported"));
    }

    // license signature against the bundled issuer key
    match verify_canonical_ed25519(
        &cred["issuerPublicKey"],
        bundle["licenseSignature"]["signature"].as_str().unwrap_or(""),
        build_license_signing_domain(license),
    ) {
        Ok(true) => {}
        Ok(false) => return Ok(fail("license_signature_invalid", "license signature does not verify against the bundled issuer key")),
        Err(e) => return Ok(fail("license_signature_invalid", &e)),
    }

    // issuer credential against the pinned license-root
    let root_key_id = cred["rootKeyId"].as_str().unwrap_or("");
    let root = match roots.iter().find(|r| r["rootKeyId"].as_str() == Some(root_key_id)) {
        Some(r) => r,
        None => return Ok(fail("untrusted_root", &format!("issuer credential references root \"{root_key_id}\" which is not in the pinned root set"))),
    };
    match verify_canonical_ed25519(
        &root["publicKey"],
        bundle["issuerCredential"]["rootSignature"]["signature"].as_str().unwrap_or(""),
        build_issuer_credential_signing_domain(cred),
    ) {
        Ok(true) => {}
        Ok(false) => return Ok(fail("issuer_credential_invalid", "issuer credential does not verify against the pinned license-root")),
        Err(e) => return Ok(fail("issuer_credential_invalid", &e)),
    }

    // issuer <-> license binding
    if license["issuer_id"].as_str() != cred["issuer_id"].as_str() {
        return Ok(fail("issuer_mismatch", "license issuer_id does not match credential issuer_id"));
    }

    // issuer validity window
    let issuer_from = to_epoch_ms(cred["validFrom"].as_str().unwrap_or(""))?;
    let issuer_until = to_epoch_ms(cred["validUntil"].as_str().unwrap_or(""))?;
    if now_ms < issuer_from {
        return Ok(fail("issuer_not_yet_valid", "issuer credential not yet valid"));
    }
    if now_ms > issuer_until {
        return Ok(fail("issuer_expired", "issuer credential expired"));
    }

    // license validity window, with signed-only grace
    let license_from = to_epoch_ms(license["validFrom"].as_str().unwrap_or(""))?;
    let license_until = to_epoch_ms(license["validUntil"].as_str().unwrap_or(""))?;
    if now_ms < license_from {
        return Ok(fail("license_not_yet_valid", "license not yet valid"));
    }
    let mut in_grace = false;
    if now_ms > license_until {
        match license.get("graceUntil").and_then(|v| v.as_str()) {
            Some(gu) if now_ms <= to_epoch_ms(gu)? => in_grace = true,
            _ => return Ok(fail("license_expired", "license expired")),
        }
    }

    // per-origin binding (tamper-evident, not copy-proof)
    let mut allowed: Vec<String> = vec![license["subject"]["origin"].as_str().unwrap_or("").to_string()];
    if let Some(ao) = license["subject"]["allowedOrigins"].as_array() {
        for o in ao {
            if let Some(s) = o.as_str() {
                allowed.push(s.to_string());
            }
        }
    }
    if !allowed.contains(&origin) {
        return Ok(fail("origin_mismatch", &format!("configured origin \"{origin}\" is not in the license subject origin(s)")));
    }

    // module entitlement -- default-deny per feature
    let modules: Vec<String> = license["modules"]
        .as_array()
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let missing: Vec<String> = required.iter().filter(|m| !modules.contains(*m)).cloned().collect();
    if !missing.is_empty() {
        return Ok(fail("module_not_licensed", &format!("required module(s) not licensed: {}", missing.join(", "))));
    }

    Ok(json!({
        "ok": true,
        "reason": if in_grace { "valid_in_grace" } else { "valid" },
        "detail": if in_grace { "license valid (in signed grace)" } else { "license verified offline" },
        "in_grace": in_grace,
    }))
}
