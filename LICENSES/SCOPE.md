# ARV Proof OSS License Scope

ARV Proof OSS uses a deliberate multi-license model.

## Reference implementation

Except where a more specific license is stated, source code in this repository is licensed under GNU AGPL-3.0-only.

This includes the reference implementation, verification code, trust-verification code, Sovereign Proof Vault Core implementation, portable verification implementation, portal code, CLI tooling, and build tooling.

The complete AGPL-3.0-only text is available in the repository root LICENSE file and LICENSES/AGPL-3.0-only.txt.

## Protocol and schemas

Files under protocol/ are licensed under the Apache License, Version 2.0, unless a file states otherwise.

This separation is intentional: independent implementations may implement the published ARV Proof protocol without copying the AGPL reference implementation.

The complete Apache-2.0 text is available in protocol/LICENSE and LICENSES/Apache-2.0.txt.

## Brand and official status

Neither AGPL-3.0-only nor Apache-2.0 grants permission to represent an independent implementation, fork, issuer, verifier, service, key, signature, or evidence object as officially issued, operated, certified, authorized, or endorsed by ARV.

Protocol compatibility and cryptographic validity do not by themselves establish official ARV authority or material truth.

## Private and managed ARV layers

This repository does not license or distribute ARV private signing keys, managed trust-root operations, managed official issuance, ARV Proof Intelligence Vault logic, commercial dispute logic, private customer data, or proprietary managed-service infrastructure.
