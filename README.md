> ## ⚠️ TSP public alpha preview
>
> This repository contains historical TSP alpha-preview materials. It is not a final TSP release, is not certified for production use, and does not grant any right to claim TSP compatibility, TSP certification, TrustBadge authorization, or participation in the official TSP integrity domain.
>
> TSP v3.1+ is governed by the LexiCo TSP License and official conformance process.

<!-- tsp-alpha-banner:end -->

# tsp-verify — Rust port of the TSP reference verifier core

Verify [Trust Standard Protocol](https://truststandardprotocol.com) v3.0
evidence from Rust: canonicalization (RFC 8785-style, byte-identical to the
JS reference), trust envelope and trust manifest validation, and Ed25519
local verification with the granular check profile.

```rust
use serde_json::json;
use tsp_verify::verify_local;

let envelope = json!({ /* a TSP v3.0 trust envelope */ });
let public_key = json!({ /* an OKP/Ed25519 public-key JWK */ });

let result = verify_local(&envelope, &public_key);
println!("{}", result["valid"]);                 // true / false — fail-closed
println!("{}", result["checks"]["ledgerHash"]);  // granular per-check verdicts
```

## Conformance is the correctness claim

This port is correct because it reproduces the normative verdicts of the
[tsp-spec](https://github.com/Lexi-TSP/tsp-spec) fixture suite — including the
ADR-0002 tamper-rejection vectors and byte-identical canonical forms — not
because anyone says so. Prove it on your machine:

```bash
cargo run --bin conformance
# integrity: 10 fixtures match pinned SHA256SUMS
# ... all 7 conformance vectors pass against the Rust port
```

A failure of that runner is a bug in this port, never grounds to adjust the
fixtures (ADR-0008: the spec owns the truth).

## Dependencies, declared honestly

Verification needs real cryptography, so this port pins a small, well-audited
set: [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) (Ed25519),
[`sha2`](https://crates.io/crates/sha2) (SHA-256),
[`base64`](https://crates.io/crates/base64),
[`serde_json`](https://crates.io/crates/serde_json), and
[`regex`](https://crates.io/crates/regex). Canonicalization, schema, manifest,
and the domain rules are this crate's own code. Verification only: this crate
holds no private keys and signs nothing.

## Numbers follow the JS reference

All JSON numbers are treated as IEEE-754 doubles and serialized exactly as
ECMAScript `Number::toString`, matching the normative JS core (not a
language-native numeric model). Integers beyond 2^53 are not representable and
are absent from the v3.0 fixtures.

## Scope

Local verification (schema, content hash, ledger hash, signatures). The online
plane (manifest resolution, key binding, revocation, rollback) is specified by
tsp-spec's online vectors; an online port follows. Local-only caveat:
`signature.keyRef` is carried but **not** authenticated — key binding is an
online-mode property.

Trust is not earned. It is given — to what can be verified.
