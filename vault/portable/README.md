# Portable Verification Vault

The Portable Verification Vault is the user-controlled export boundary for independently verifiable evidence.

Portable does not mean public.

The design objective is minimum necessary disclosure, offline portability, explicit export, and independent verification without mandatory connectivity to ARV or a third-party service.

A portable bundle may contain only the artifacts required by the intended verification workflow, such as an evidence envelope, relevant public key material, verification receipts, trust-state material, checkpoints, or witness evidence.

Raw evidence content and sensitive assertion metadata must not be assumed public merely because a cryptographic proof is portable.

The final privacy-minimized export profile will be completed together with self-managed issuance and public verification projection hardening.

## Portable Proof Manifest V1

The Portable Verification Vault may carry a signed privacy-minimal manifest without publishing the full evidence envelope.

The manifest commits to the complete canonical envelope with SHA-256 over ARV-JSON-v1 canonical bytes. It may also disclose the artifact SHA-256 digest when the holder chooses to make artifact comparison possible.

This is a whole-envelope commitment, not selective disclosure. The manifest does not expose envelope claims, participants, asserted_by, subject, attributes, jurisdiction, occurred_at, the envelope signature value, or the envelope QR payload.

A valid manifest signature proves only the integrity and signer binding of the portable manifest. Matching a later envelope proves that the disclosed envelope corresponds to the earlier commitment. The normal ARV evidence verifier must still evaluate the internal cryptographic integrity of that envelope.

Official status and material truth are not inferred by this layer. They remain NOT_EVALUATED unless established by a separate trust or evidence process.
