# tsp-spec fixture snapshot (Rust port)

Checksum-pinned copies from Lexi-TSP/tsp-spec. Source of truth is tsp-spec;
never edit fixtures here -- a failure against them is a divergence finding in
THIS port (ADR-0008).

- `fixtures/v3.0/` + `expectations.json` -- TrustEnvelope v3.0 suite
  (synced @ 41649b6, 2026-06-12).
- `fixtures/license-v1/` + `license-expectations.json` -- TSP License Artifact
  v1 suite (ADR-0010), synced @ 213b7e1 (2026-06-13). Separate track, separate
  SHA256SUMS; never mixed into the v3.0 vectors.
