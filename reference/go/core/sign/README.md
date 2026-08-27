# Sign Module - ARV Proof OSS Canon v1.0

Deterministic Ed25519 signing for audit-grade evidence.

## Overview
This module signs and verifies the Merkle root (or any SHA-256 digest) using Ed25519.
All inputs/outputs are canonical lowercase hex for deterministic audit workflows.

## Canon v1.0 Rules (Sign)

### Hash Input
- **Format**: 64-char lowercase hex
- **Meaning**: 32 raw bytes (SHA-256 digest)
- **Signing message**: the RAW 32 bytes decoded from hex (not ASCII of the hex string)

### Keys
- **Seed**: 32 bytes, encoded as 64-char lowercase hex
- **Public key**: 32 bytes, encoded as 64-char lowercase hex
- **Private key**: derived via `ed25519.NewKeyFromSeed(seed)` (64 bytes)
  - Not required for Canon I/O; stored only if needed.

### Signature
- **Size**: 64 bytes
- **Encoding**: 128-char lowercase hex

### Errors
- All malformed inputs return explicit errors (wrapped) and never silently coerce formats.
- Verification mismatch returns `ErrVerificationFailed`.

## API

### SignHashHex
```go
func SignHashHex(hashHex string, seedHex string) (sigHex string, pubHex string, err error)
