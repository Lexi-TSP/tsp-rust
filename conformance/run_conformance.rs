//! TSP conformance runner for the Rust port.
//!
//! Runs the checksum-pinned tsp-spec fixture suites through this port: the v3.0
//! TrustEnvelope vectors AND the tsp.license.v1 vectors (ADR-0010), each a
//! SEPARATE checksum-pinned track, never mixed. Exit 0 only if every snapshot is
//! intact AND every vector matches. A failure here means THIS PORT is wrong
//! (ADR-0008) -- fix the port, never the fixtures.
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::exit;
use tsp_verify::{canonicalize, sha256_hex, validate_trust_envelope_shape, verify_license, verify_local};

fn snapshot_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance").join("spec-snapshot")
}

fn read_json(path: &Path) -> Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn sha256_file_hex(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().iter().map(|b| format!("{:02x}", b)).collect())
}

/// Verify a SHA256SUMS file; relative paths are resolved against `snapshot`.
fn verify_sums(snapshot: &Path, sums_path: &Path) -> (usize, Vec<String>) {
    let sums = std::fs::read_to_string(sums_path).expect("read SHA256SUMS");
    let mut mismatches = Vec::new();
    let mut count = 0usize;
    for line in sums.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        count += 1;
        let mut parts = line.splitn(2, char::is_whitespace);
        let expected = parts.next().unwrap_or("").trim();
        let rel = parts.next().unwrap_or("").trim();
        if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) || rel.is_empty() {
            mismatches.push(format!("unparseable SHA256SUMS line: {line}"));
            continue;
        }
        let mut target = snapshot.to_path_buf();
        for seg in rel.split('/') {
            target.push(seg);
        }
        match sha256_file_hex(&target) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => mismatches.push(format!("{rel}: checksum drift -- expected {expected}, got {actual}")),
            Err(e) => mismatches.push(format!("{rel}: cannot read ({e})")),
        }
    }
    (count, mismatches)
}

fn root_keys_in_document_order(raw: &str) -> Vec<String> {
    let chars: Vec<char> = raw.chars().collect();
    let n = chars.len();
    let mut keys = Vec::new();
    let mut depth: i32 = 0;
    let mut i = 0usize;
    while i < n {
        let ch = chars[i];
        if ch == '"' {
            let mut j = i + 1;
            let mut escaped = false;
            while j < n {
                let c = chars[j];
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    break;
                }
                j += 1;
            }
            if depth == 1 {
                let mut m = j + 1;
                while m < n && chars[m].is_whitespace() {
                    m += 1;
                }
                if m < n && chars[m] == ':' {
                    keys.push(chars[i + 1..j].iter().collect());
                }
            }
            i = j;
        } else if ch == '{' || ch == '[' {
            depth += 1;
        } else if ch == '}' || ch == ']' {
            depth -= 1;
        }
        i += 1;
    }
    keys
}

fn utf16_sorted(keys: &[String]) -> Vec<String> {
    let mut v = keys.to_vec();
    v.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    v
}

fn status_at<'a>(result: &'a Value, name: &str) -> Option<&'a str> {
    result["checks"][name]["status"].as_str()
}

fn run_vector(fixtures: &Path, vec: &Value) -> Vec<String> {
    let file = vec["file"].as_str().unwrap();
    let kind = vec["kind"].as_str().unwrap();
    let mut fails = Vec::new();

    match kind {
        "cryptographic" => {
            let envelope = read_json(&fixtures.join(file));
            let key = read_json(&fixtures.join(vec["key"].as_str().unwrap()));
            let result = verify_local(&envelope, &key);
            let expect = &vec["expect"];
            if result["valid"] != expect["valid"] {
                fails.push(format!("valid: expected {}, got {}", expect["valid"], result["valid"]));
            }
            for (name, want) in expect["checks"].as_object().unwrap() {
                if name == "signatures" {
                    for (i, w) in want.as_array().unwrap().iter().enumerate() {
                        let got = result["checks"]["signatures"].get(i).and_then(|s| s["status"].as_str());
                        if got != w.as_str() {
                            fails.push(format!("signatures[{i}]: expected {w}, got {got:?}"));
                        }
                    }
                } else {
                    let got = status_at(&result, name);
                    if got != want.as_str() {
                        fails.push(format!("{name}: expected {want}, got {got:?}"));
                    }
                }
            }
        }
        "canonical-hash" => {
            let envelope = read_json(&fixtures.join(file));
            let got = sha256_hex(&canonicalize(&envelope["content"]["value"]).unwrap());
            let want = vec["expect"]["contentValueHash"].as_str().unwrap();
            if got != want {
                fails.push(format!("sha256(canonicalize(content.value)): expected {want}, got {got}"));
            }
            if vec["expect"]["schema"].as_str() == Some("passed")
                && !validate_trust_envelope_shape(&envelope).is_empty()
            {
                fails.push("schema: expected passed, got failed".to_string());
            }
        }
        "canonical-equivalence" => {
            let envelope = read_json(&fixtures.join(file));
            let reference = read_json(&fixtures.join(vec["reference"].as_str().unwrap()));
            let a = canonicalize(&envelope).unwrap();
            let b = canonicalize(&reference).unwrap();
            if a != b {
                fails.push(format!("canonicalize({file}) != canonicalize({})", vec["reference"]));
            }
            if sha256_hex(&a) != sha256_hex(&b) {
                fails.push("sha256 of canonical forms differ".to_string());
            }
        }
        "schema-invalid" => {
            let envelope = read_json(&fixtures.join(file));
            let errors = validate_trust_envelope_shape(&envelope);
            if errors.is_empty() {
                fails.push("schema: expected failed, got passed".to_string());
            }
            if let Some(needle) = vec["expect"]["errorContains"].as_str() {
                if !errors.iter().any(|e| e.contains(needle)) {
                    fails.push(format!("expected a schema error containing \"{needle}\"; got: {}", errors.join("; ")));
                }
            }
        }
        "structural-unsorted" => {
            let raw = std::fs::read_to_string(fixtures.join(file)).unwrap();
            let keys = root_keys_in_document_order(&raw);
            if keys == utf16_sorted(&keys) {
                fails.push("document order equals canonical order -- JCS sort trap not exercised".to_string());
            }
        }
        other => fails.push(format!("unknown kind: {other}")),
    }
    fails
}

fn run_license_vector(fixtures: &Path, vector: &Value, roots: &Value) -> Vec<String> {
    let file = vector["file"].as_str().unwrap();
    let bundle = read_json(&fixtures.join(file));
    let mut config = Map::new();
    config.insert("origin".into(), vector["origin"].clone());
    config.insert("trustedRootKeys".into(), roots.clone());
    config.insert(
        "requiredModules".into(),
        vector.get("requiredModules").cloned().unwrap_or(Value::Array(Vec::new())),
    );
    let now = vector["now"].as_str().unwrap();
    let result = verify_license(&bundle, &Value::Object(config), now).expect("license verify config");
    let mut fails = Vec::new();
    if result["ok"] != vector["expect"]["ok"] {
        fails.push(format!(
            "ok: expected {}, got {} ({}: {})",
            vector["expect"]["ok"], result["ok"], result["reason"], result["detail"]
        ));
    }
    if result["reason"] != vector["expect"]["reason"] {
        fails.push(format!("reason: expected {}, got {}", vector["expect"]["reason"], result["reason"]));
    }
    fails
}

fn main() {
    let snapshot = snapshot_dir();
    let mut failed = 0;

    // ----- v3.0 TrustEnvelope suite -----
    let fixtures = snapshot.join("fixtures").join("v3.0");
    let spec = read_json(&snapshot.join("expectations.json"));
    println!(
        "TSP Rust-port conformance -- wire tsp \"{}\" - maturity \"{}\"",
        spec["tsp"].as_str().unwrap_or("?"),
        spec["specMaturity"].as_str().unwrap_or("?")
    );
    let (count, mismatches) = verify_sums(&snapshot, &fixtures.join("SHA256SUMS"));
    if !mismatches.is_empty() {
        println!("v3.0 snapshot integrity FAILED ({}/{count}):", mismatches.len());
        for m in &mismatches {
            println!("    {m}");
        }
        exit(1);
    }
    println!("integrity: {count} v3.0 fixtures match pinned SHA256SUMS");
    let vectors = spec["vectors"].as_array().unwrap();
    for vec in vectors {
        let fails = run_vector(&fixtures, vec);
        let file = vec["file"].as_str().unwrap();
        let kind = vec["kind"].as_str().unwrap();
        if fails.is_empty() {
            println!("PASS  {file}  [{kind}]");
        } else {
            failed += 1;
            println!("FAIL  {file}  [{kind}]");
            for f in &fails {
                println!("        {f}");
            }
        }
    }

    // ----- TSP License Artifact v1 suite (ADR-0010; separate track) -----
    let license_fixtures = snapshot.join("fixtures").join("license-v1");
    let lic = read_json(&snapshot.join("license-expectations.json"));
    println!("\nlicense conformance -- artifact \"{}\"", lic["artifact"].as_str().unwrap_or("?"));
    let (lcount, lmis) = verify_sums(&snapshot, &license_fixtures.join("SHA256SUMS"));
    if !lmis.is_empty() {
        println!("license snapshot integrity FAILED ({}/{lcount}):", lmis.len());
        for m in &lmis {
            println!("    {m}");
        }
        exit(1);
    }
    println!("integrity: {lcount} license fixtures match pinned SHA256SUMS");
    let root_file = read_json(&license_fixtures.join(lic["rootKey"].as_str().unwrap()));
    let roots = serde_json::json!([{ "rootKeyId": root_file["rootKeyId"], "publicKey": root_file["publicKey"] }]);
    let lvectors = lic["vectors"].as_array().unwrap();
    for vector in lvectors {
        let fails = run_license_vector(&license_fixtures, vector, &roots);
        let file = vector["file"].as_str().unwrap();
        let reason = vector["expect"]["reason"].as_str().unwrap_or("?");
        if fails.is_empty() {
            println!("PASS  {file}  [{reason}]");
        } else {
            failed += 1;
            println!("FAIL  {file}  [{reason}]");
            for f in &fails {
                println!("        {f}");
            }
        }
    }

    let total = vectors.len() + lvectors.len();
    if failed == 0 {
        println!("\nall {total} conformance vectors pass against the Rust port");
        exit(0);
    }
    println!("\n{failed}/{total} vectors diverge -- this port is wrong until fixed (ADR-0008)");
    exit(1);
}
