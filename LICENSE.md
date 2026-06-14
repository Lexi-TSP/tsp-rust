# LexiCo TSP License
### Free to verify. Licensed to issue. Controlled to certify. Forbidden to counterfeit.

Version 1.0 — applies to **TSP v3.1 and later** SDK / verifier implementation
materials in this repository.
Copyright © 2026 LexiCo AS (Norway). All rights reserved.

This License governs the source code, build artifacts, and implementation
materials in this repository **as of TSP v3.1 and later** ("the Software"). It
does not revoke or alter any open-source license under which earlier TSP v3.0
alpha / public-preview snapshots were distributed; those notices are retained and
continue to govern those historical snapshots (see `DEPRECATED.md`).

## 1. Definitions

- **TSP** — the Trust Standard Protocol as specified by LexiCo AS.
- **TrustEnvelope** — a TSP-defined signed manifest artifact.
- **Verify** — to validate a TrustEnvelope or TSP license against the
  specification, without issuing or certifying.
- **Issue** — to construct and sign a TrustEnvelope or TSP license intended to be
  treated as authentic.
- **Certify** — to assert, or operate authority asserting, that a thing is
  TSP-compatible or TSP-certified.
- **Marks** — the trademarks listed in `TRADEMARK.md`.

## 2. Verification grant (free)

LexiCo AS grants you a perpetual, worldwide, royalty-free, non-exclusive license
to use, copy, and modify the Software **for the purpose of verifying** TSP
artifacts, and to run such verification offline and at no charge. This grant is
not conditioned on holding a TSP license. **TSP is free to verify.**

## 3. Issuance and certification (licensed / controlled)

Using the Software — or any derivative — to **Issue** TrustEnvelopes or TSP
licenses in production, or to **Certify**, requires a separate **LexiCo-authorized
TSP license**. Absent that authorization, no right to Issue or Certify is granted.
You must not remove, disable, or weaken the fail-closed license gate (including the
`402 unlicensed_platform` path) or the canonicalization used to bind signatures.

## 4. Redistribution

You may redistribute the Software and modifications provided you (a) retain this
License, `TRADEMARK.md`, `NOTICE.md`, and all historical notices; (b) mark changed
files; and (c) do not present the result as TSP-compatible, TSP-certified, or
TrustBadge-authorized except as permitted by `TRADEMARK.md`. Redistribution does
not grant Issue/Certify rights or any rights in the Marks.

## 5. Trademarks

No rights in the Marks are granted by this License. Mark use is governed solely by
`TRADEMARK.md`.

## 6. Prohibited conduct (counterfeiting)

You must not forge TrustEnvelopes, fabricate TrustBadges, or make false
TSP-compatible / TSP-certified claims. **TSP is forbidden to counterfeit.**

## 7. Termination

Rights under Sections 3–4 terminate automatically on breach of Sections 3, 5,
or 6. The Section 2 verification grant survives for conformant verification use.

## 8. Warranty / liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM
EXTENT PERMITTED BY LAW, LEXICO AS SHALL NOT BE LIABLE FOR ANY CLAIM OR DAMAGES
ARISING FROM THE SOFTWARE OR ITS USE.

## 9. Governing law

This License is governed by the laws of Norway, without regard to conflict-of-laws
rules.

Licensing & authorization: hello@truststandardprotocol.com
