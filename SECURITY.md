# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **["Report a vulnerability"](../../security/advisories/new)** (Security → Advisories) on this repository. This opens a private advisory visible only to the maintainers.

If you cannot use GitHub advisories, contact the maintainer at **security@truststandardprotocol.com**.

Please include:

- the affected component and version (commit SHA, tag, or package version),
- a description of the issue and its impact,
- reproduction steps or a proof-of-concept envelope/fixture where possible.

## Scope

This repository is part of the Trust Standard Protocol (TSP) verifier ecosystem. We are especially interested in reports that affect the **integrity of verification**, including:

- canonicalization (RFC 8785 JCS) divergences that change the signed bytes,
- signature-domain or ledger-hash construction errors,
- Ed25519 verification bypasses,
- manifest / certificate-chain / revocation / sequence-rollback handling in online verification,
- any path where a tampered or unauthorized envelope can return `valid: true`.

## What TSP does and does not claim

TSP proves an output came from a declared system under a declared policy and was not tampered with. **Verification is not a truth claim** — it does not certify an output is correct, lawful, authorized, or non-hallucinated. Reports premised on "TSP verified false content" that do not involve a cryptographic or canonicalization defect are out of scope.

## Response

We aim to acknowledge a valid report within **5 business days** and to agree a coordinated disclosure timeline with the reporter. Fixes that affect the signed-byte or verification semantics are released as conformance-gated changes against `tsp-spec`.

## Supported versions

The current public conformance profile is **TSP Public Profile 1.0-draft · TrustEnvelope Core v3.0**. Security fixes target the latest published core and the `main` branch. Earlier alphas are not maintained.
