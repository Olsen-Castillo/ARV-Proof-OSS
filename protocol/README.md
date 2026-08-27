# ARV Proof Protocol

This directory contains the public, vendor-neutral interoperability contracts for ARV Proof.

## Purpose

The protocol schemas are intended to support independent implementations, portable evidence, offline verification, interoperability, and conformance testing.

An implementation of these schemas does not need to use the AGPL reference implementation.

## License

Unless a file states otherwise, the contents of protocol/ are licensed under Apache-2.0.

See protocol/LICENSE and ../LICENSES/SCOPE.md.

## Authority boundary

Implementing an ARV Proof schema does not make an implementation, issuer, verifier, signature, key, registry, certificate, or evidence object official ARV.

Official status requires the applicable governance authorization and trust-state verification.

## Evidence boundary

Cryptographic integrity, provenance, governance authorization, and material truth are separate determinations.

Public verification does not require public disclosure of the underlying evidence payload.

Implementations should disclose only the minimum information required for the intended verification workflow.

## Data sovereignty

The protocol is designed to permit client-controlled, local, on-premises, and offline-first implementations without mandatory dependence on ARV-hosted infrastructure or a third-party cloud.
