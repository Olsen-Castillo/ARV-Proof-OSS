# Sovereign Proof Vault Core

The Sovereign Proof Vault Core is the client-controlled local evidence store for ARV Proof OSS.

Its purpose is data sovereignty rather than hosted custody.

## Core properties

- client-controlled storage;
- local and on-premises deployment;
- offline-first operation and verification;
- no mandatory ARV-hosted cloud;
- no mandatory third-party cloud;
- no automatic publication of evidence;
- no mandatory telemetry;
- no default transfer of customer evidence to ARV;
- export remains under client control.

An Evidence Envelope may contain claims, participants, identifiers, timestamps, jurisdiction information, or other potentially sensitive metadata.

Storing an envelope in a Sovereign Proof Vault does not make that information public.

The operator controls the storage location, keyring, evidence files, verification workflow, retention policy, backups, and disclosure decisions.

Operating a Sovereign Proof Vault does not create official ARV status.

Official ARV authorization is a separate governance and trust-registry determination.

The current v1 Evidence Envelope still uses the ARV-YYYY-NNNNNN validation identifier format. Self-managed issuance is therefore intentionally deferred until the public namespace and official-status distinction are versioned explicitly.
