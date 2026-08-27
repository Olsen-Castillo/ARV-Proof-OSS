# Merkle module (ARV Proof OSS)

Deterministic Merkle tree for audit-grade evidence:

- Build root from ordered leaf hashes
- Generate proof for a leaf index
- Verify proof offline without rebuilding the full tree

## Determinism rules

- **Leaves:** SHA-256 lowercase hex strings (64 chars). Validated by regex.
- **Order:** tree is built in the given order—no sorting.
- **Concatenation:** decode 32-byte hashes and compute `SHA-256(left||right)` using byte concatenation. Do **not** concatenate strings.
- **Odd leaf count:** if a level has an odd number of nodes, **duplicate the last node** to form a pair. This ensures deterministic parent computation.
- **Single leaf:** root equals the leaf (no extra hashing).
- **Empty set:** returns error (no silent defaults).

## Proof format

```json
[
  {"hash":"<64-char hex>","position":"left|right"}
]

