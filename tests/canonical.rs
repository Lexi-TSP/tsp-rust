//! Unit tests mirroring the Python port's test_canonical.py.
use serde_json::json;
use tsp_verify::canonical::{canonicalize, es_number};

#[test]
fn es_number_matches_javascript() {
    let cases: &[(f64, &str)] = &[
        (0.0, "0"), (-0.0, "0"), (1.0, "1"), (-7.0, "-7"),
        (0.7, "0.7"), (3.14159, "3.14159"), (1.5e-5, "0.000015"),
        (1e-6, "0.000001"), (1e-7, "1e-7"), (1.2e-8, "1.2e-8"),
        (1e21, "1e+21"), (1.5e22, "1.5e+22"),
        (123456789012345680000.0, "123456789012345680000"),
        (100000.0, "100000"), (1e20, "100000000000000000000"),
    ];
    for (value, expected) in cases {
        assert_eq!(&es_number(*value).unwrap(), expected, "for {value:?}");
    }
}

#[test]
fn non_finite_errors() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(es_number(bad).is_err(), "expected error for {bad:?}");
    }
}

#[test]
fn scalars_and_sorting() {
    assert_eq!(canonicalize(&json!(null)).unwrap(), "null");
    assert_eq!(canonicalize(&json!(true)).unwrap(), "true");
    assert_eq!(canonicalize(&json!({"b": 1, "a": "x"})).unwrap(), r#"{"a":"x","b":1}"#);
}

#[test]
fn escapes_match_reference() {
    // input chars: 'a', U+0009, 'b', U+000A, U+0001 -> control chars escaped
    let input = json!("a\tb\n\u{0001}");
    let expected = "\"a\\tb\\n\\u0001\"";
    assert_eq!(canonicalize(&input).unwrap(), expected);
}

#[test]
fn utf16_code_unit_sort() {
    // U+1D306 (astral) must sort BEFORE U+FF01 under UTF-16 order.
    let d = json!({"\u{FF01}": 1, "\u{1D306}": 2});
    assert_eq!(canonicalize(&d).unwrap(), "{\"\u{1D306}\":2,\"\u{FF01}\":1}");
}