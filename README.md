# ARV Proof OSS

Domain-neutral cryptographic proof and verification infrastructure for portable evidence, provenance, chain of custody, and independent verification.

**Candidate:** 0.2.2-rc.1

**Latest published release:** 0.2.1

**Status:** pre-1.0 public reference implementation. Interfaces and protocol contracts may evolve before v1.0.

## What ARV Proof OSS does

ARV Proof OSS provides open protocol schemas and reference implementations for creating, carrying, and independently verifying cryptographic evidence structures.

The current public surface includes:

- deterministic canonicalization and SHA-256 commitments;
- Ed25519 signing and verification;
- Merkle proof primitives;
- evidence envelopes;
- self-managed issuance using the ARV-SM namespace;
- Sovereign Proof Vault Core for local and on-premises custody;
- Portable Proof Manifest V1 for privacy-minimal whole-envelope commitments;
- trust-registry and trust-root verification;
- checkpoint and witness verification;
- release and runtime attestation;
- transparency and incident-adjudication verification;
- local and offline-first verification workflows.

## What it does not prove

Cryptographic validity is not the same thing as material truth.

A valid hash, signature, manifest, envelope, or trust result does not by itself prove that:

- an underlying statement is materially true;
- every relevant event or piece of evidence was captured;
- a signer was entitled to make a factual assertion;
- a self-managed proof was officially issued by ARV;
- an artifact has legal effect in a particular jurisdiction.

Integrity, provenance, cryptographic validity, governance authorization, official status, and material truth are separate determinations.

## Public scope

This repository publishes the ARV Proof protocol, reference verification code, and native self-managed Snap LOCAL_L0 experience. Snap can preserve the bytes supplied by a file selector or camera capture; it does not establish the provenance or truth of the depicted event.

The published files do not distribute managed official issuance, operational signing keys, customer evidence, or non-public service implementations.

## Quick start

Requirements:

- Node.js 20 or later;
- npm;
- Go 1.22 or later.

Install JavaScript dependencies:

```bash
npm ci
```

Run the public boundary validator:

```bash
npm run validate:public
```

Type-check and run the TypeScript reference tests:

```bash
npm run typecheck
npm test
```

Run the Go reference tests:

```bash
go test ./reference/go/...
go vet ./reference/go/...
```

## Repository map

- `protocol/` - Apache-2.0 protocol schemas and interoperability contracts.
- `reference/typescript/arv/` - AGPL TypeScript reference implementation and tests.
- `reference/go/` - AGPL Go cryptographic reference primitives.
- `trust/` - trust-verification documentation.
- `vault/sovereign/` - Sovereign Proof Vault Core documentation.
- `vault/portable/` - Portable Verification Vault documentation.
- `portal/` - zero-dependency local demonstration surface.
- `scripts/validate-public-surface.mjs` - fail-closed public boundary checks.

## Self-managed proof flow

A self-managed implementation can create an `ARV-SM-*` evidence envelope using its own Ed25519 key, preserve the result locally, and produce a Portable Proof Manifest that commits to the complete canonical envelope.

The manifest can optionally disclose the artifact SHA-256 digest. Later disclosure of the full envelope can be compared against the whole-envelope commitment.

The public namespace does not confer official ARV status. Officiality requires a separate applicable governance and trust determination.

## Static demo

The `portal/` demo runs entirely in the browser. It can inspect a Portable Proof Manifest, hash a selected artifact locally, and compare that hash with the disclosed artifact digest.

The demo makes no network requests and uploads no selected files.

It intentionally does not claim to perform complete signature, trust-registry, official-status, or material-truth verification.

## Licensing

The reference implementation and build tooling are distributed under GNU AGPL-3.0-only unless a more specific notice applies.

The protocol and schemas under `protocol/` are distributed under Apache-2.0.

See `LICENSES/SCOPE.md` for the authoritative repository licensing boundary.

Brand identity and official-status representations are separate from copyright licensing. See `TRADEMARKS.md`, `BRAND.md`, and `FORK_POLICY.md`.

## Security

Do not publish vulnerability details, real private keys, credentials, or confidential evidence in a public issue.

See `SECURITY.md`.


## Native Snap local verification

The [standalone local Snap page](portal/snap-verifier.html) creates self-managed LOCAL_L0 V2 packages from selected or captured bytes and verifies LOCAL_L0 V1 image packages and V2 original file bytes using only public reference source. Creation and verification run locally with no upload. See the [build and use guide](portal/SNAP.md), [package contract](protocol/snap-local-proof.md), [schema](protocol/schemas/v1/snap-local-proof.schema.json), and [synthetic vectors](protocol/test-vectors/snap/). `npm run build:snap` regenerates the public browser output; `npm run ci` checks build reproducibility and the public boundary before tests. PASS establishes local integrity for the included key; it does not establish trusted identity, official ARV status, or material truth. Browser support and device limits are documented in the build and use guide.
