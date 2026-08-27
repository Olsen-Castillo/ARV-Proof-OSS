# ARV Brand Architecture

## Canonical roles

| Identity | Role |
| --- | --- |
| ARV | Umbrella evidence architecture |
| ARV Snap | Capture and provenance layer |
| ARV Proof OSS | Domain-neutral cryptographic proof and verification layer |
| ProofOps | Operational event-chain, execution-proof, provenance, handoff, and chain-of-custody layer |

## Required distinctions

ARV documentation and interfaces must distinguish:

1. file integrity;
2. provenance;
3. cryptographic verification;
4. governance authorization;
5. official issuer or verifier status;
6. material truth.

A cryptographically valid record may still be incomplete, misleading, independently issued, unauthorized, or unrelated to material truth.

## Self-managed namespace

The `ARV-SM-*` namespace identifies self-managed issuance supported by the public reference implementation.

The namespace itself does not confer official ARV status.

## Language neutrality

Canonical identifiers, hashes, signatures, and verification semantics are language-neutral. Presentation language must not alter signed bytes or verification outcomes.

