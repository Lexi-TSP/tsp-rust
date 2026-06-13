//! tsp-verify -- Rust port of the TSP v3.0 reference verifier core.
//!
//! Normative authority is Lexi-TSP/tsp-spec (ADR-0008): this port is conformant
//! because it reproduces the spec's fixture verdicts, not because it is trusted.
//! Run the bundled `conformance` binary to prove it on your machine.
//!
//! Verification only: holds no keys, signs nothing.
pub mod canonical;
pub mod crypto;
pub mod domains;
pub mod hash;
pub mod manifest;
pub mod license_domain;
pub mod license_schema;
pub mod schema;
pub mod verify_license;
pub mod verify_local;

pub use canonical::canonicalize;
pub use hash::sha256_hex;
pub use manifest::validate_trust_manifest;
pub use schema::validate_trust_envelope_shape;
pub use verify_local::verify_local;
pub use license_schema::validate_license_bundle_shape;
pub use verify_license::verify_license;
