# Security Policy

## Supported versions

Before v1.0, security fixes target the current `main` branch and the latest supported pre-1.0 release line.

## Reporting a vulnerability

Do not disclose exploit details, private keys, credentials, or confidential evidence in a public GitHub issue.

Use GitHub private vulnerability reporting when it is enabled for the repository.

If private reporting is unavailable, open only a minimal public request for a private contact channel and omit vulnerability details.

A useful private report includes:

- affected component and release or commit;
- vulnerability class and expected impact;
- minimal reproduction steps;
- relevant logs or proof-of-concept material;
- whether keys, signatures, trust state, or private data are involved.

## High-value security boundaries

Reports are especially relevant when they involve:

- canonical serialization;
- SHA-256 commitments or Merkle proofs;
- Ed25519 signing or verification;
- signature-domain separation;
- key lifecycle and recovery;
- trust-registry interpretation;
- checkpoint or witness validation;
- split-view detection;
- release or runtime attestation;
- incident adjudication;
- confusion between cryptographic validity and official authorization.

Cryptographic validity does not automatically establish material truth or official ARV status.

