import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { emitSelfManagedFixtureV1 } from './public-test-fixture-v1';
import { evaluateOfficialAuthorityV1 } from './official-authority-v1';
import {
  ARVIssuerAuthorizationV1,
  TrustAnchorV1,
  TrustRegistryV1,
  UnsignedTrustRegistryV1,
  canonicalTrustRegistryPayloadV1,
  trustRegistryHashV1
} from './trust-registry-v1';

const roots: string[] = [];
const registryRootPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(31));
const registryRootFingerprint = crypto
  .createHash('sha256')
  .update(Buffer.from(registryRootPair.publicKey))
  .digest('hex');

const anchor: TrustAnchorV1 = {
  schema: 'arv.trust-anchor',
  schema_version: 1,
  registry_id: 'ARV-TRUST-OFFICIAL-V1',
  algorithm: 'Ed25519',
  key_fingerprint: registryRootFingerprint,
  public_key_base64: encodeBase64(registryRootPair.publicKey)
};

function temporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'arv-public-authority-'));
  roots.push(root);
  return root;
}

function evidence(
  root: string,
  recordedAt = '2026-08-21T16:00:00Z'
) {
  return emitSelfManagedFixtureV1(
    root,
    {
      recorded_at: recordedAt,
      uuid: '17171717-1717-4171-8171-171717171717',
      key_fill: 17,
      content: 'public authority evidence bytes'
    }
  ).result;
}
function authorization(
  fingerprint: string,
  overrides: Partial<ARVIssuerAuthorizationV1> = {}
): ARVIssuerAuthorizationV1 {
  return {
    authorization_id: 'ARV-AUTH-PRIMARY-001',
    issuer_id: 'ARV-ISSUER-EXAMPLE-001',
    authority: 'SELF_MANAGED',
    systems: ['ARV Proof OSS'],
    roles: ['ISSUER'],
    products: ['ARV_PROOF_OSS', 'GENERIC'],
    environment: 'PRODUCTION',
    key_fingerprint: fingerprint,
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: null,
    status: 'ACTIVE',
    status_effective_at: null,
    compromise_effective_from: null,
    ...overrides
  };
}

function registry(
  entry: ARVIssuerAuthorizationV1,
  issuedAt = '2026-08-21T17:00:00Z'
): TrustRegistryV1 {
  const unsigned: UnsignedTrustRegistryV1 = {
    schema: 'arv.trust-registry',
    schema_version: 1,
    registry_id: anchor.registry_id,
    sequence: 1,
    issued_at: issuedAt,
    previous_registry_hash: null,
    authorizations: [entry]
  };
  return {
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      key_fingerprint: registryRootFingerprint,
      value: encodeBase64(
        nacl.sign.detached(
          Buffer.from(canonicalTrustRegistryPayloadV1(unsigned), 'utf8'),
          registryRootPair.secretKey
        )
      )
    }
  };
}

function evaluate(root: string, envelope: unknown, snapshot: TrustRegistryV1, evaluatedAt = '2026-08-22T00:00:00Z') {
  return evaluateOfficialAuthorityV1(
    envelope,
    snapshot,
    anchor,
    {
      registry_id: snapshot.registry_id,
      sequence: snapshot.sequence,
      registry_hash: trustRegistryHashV1(snapshot)
    },
    {
      product: 'ARV_PROOF_OSS',
      environment: 'PRODUCTION',
      evaluated_at: evaluatedAt,
      root_dir: root,
      evidence_checkpoint_verified: true
    }
  );
}

afterEach(() => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root) fs.rmSync(root, { recursive: true, force: true });
  }
});

describe('ARV Public official issuer authorization', () => {
  test('separately establishes cryptographic validity and official authority', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const result = evaluate(root, emitted.envelope, registry(authorization(fingerprint)));

    expect(result.status).toBe('OFFICIAL');
    expect(result.authority_at_recording).toBe(true);
    expect(result.current_key_status).toBe('ACTIVE');
    expect(result.cryptographic_integrity).toBe('VERIFIED');
    expect(result.material_truth).toBe('NOT_EVALUATED');
    expect(result.codes).toEqual([]);
  });

  test('classifies a valid signature from an unregistered key as unofficial', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const result = evaluate(root, emitted.envelope, registry(authorization('a'.repeat(24))));

    expect(result.cryptographic_integrity).toBe('VERIFIED');
    expect(result.status).toBe('UNOFFICIAL');
    expect(result.codes).toEqual(['AUTHORIZATION_NOT_FOUND']);
  });

  test('does not trust a registry modified after root signing', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const snapshot = registry(authorization(fingerprint));
    snapshot.authorizations[0].authority = 'Copied Authority';
    const result = evaluate(root, emitted.envelope, snapshot);

    expect(result.status).toBe('UNKNOWN');
    expect(result.codes).toContain('REGISTRY_NOT_TRUSTED');
    expect(result.registry.trust_codes).toContain('REGISTRY_SIGNATURE_INVALID');
  });

  test('preserves authorization at recording after a later revocation', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const entry = authorization(fingerprint, {
      status: 'REVOKED',
      status_effective_at: '2026-09-01T00:00:00Z'
    });
    const result = evaluate(
      root,
      emitted.envelope,
      registry(entry, '2026-09-01T01:00:00Z'),
      '2026-09-02T00:00:00Z'
    );

    expect(result.status).toBe('OFFICIAL');
    expect(result.authority_at_recording).toBe(true);
    expect(result.current_key_status).toBe('REVOKED');
    expect(result.codes).toContain('CURRENT_KEY_REVOKED_AFTER_RECORDING');
  });

  test('applies compromise_effective_from to affected historical records', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const entry = authorization(fingerprint, {
      status: 'REVOKED',
      status_effective_at: '2026-09-01T00:00:00Z',
      compromise_effective_from: '2026-08-20T00:00:00Z'
    });
    const result = evaluate(
      root,
      emitted.envelope,
      registry(entry, '2026-09-01T01:00:00Z'),
      '2026-09-02T00:00:00Z'
    );

    expect(result.status).toBe('REVOKED');
    expect(result.authority_at_recording).toBe(false);
    expect(result.codes).toContain('KEY_COMPROMISED_AT_RECORDING');
  });

  test('reports suspension effective at recording', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root, '2026-08-23T00:00:00Z');
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const entry = authorization(fingerprint, {
      status: 'SUSPENDED',
      status_effective_at: '2026-08-22T00:00:00Z'
    });
    const result = evaluate(
      root,
      emitted.envelope,
      registry(entry, '2026-08-22T01:00:00Z'),
      '2026-08-24T00:00:00Z'
    );

    expect(result.status).toBe('SUSPENDED');
    expect(result.codes).toContain('AUTHORIZATION_SUSPENDED_AT_RECORDING');
  });

  test('reports product scope independently from signature validity', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const entry = authorization(fingerprint, { products: ['ARV_SNAP'] });
    const result = evaluate(root, emitted.envelope, registry(entry));

    expect(result.status).toBe('OUT_OF_SCOPE');
    expect(result.codes).toEqual(['PRODUCT_OUT_OF_SCOPE']);
  });

  test('fails closed when the evidence signature is altered', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    emitted.envelope.proof.signature.value = encodeBase64(new Uint8Array(64).fill(5));
    emitted.envelope.proof.qr.signature = emitted.envelope.proof.signature.value;
    const result = evaluate(root, emitted.envelope, registry(authorization(fingerprint)));

    expect(result.status).toBe('UNKNOWN');
    expect(result.cryptographic_integrity).toBe('FAILED');
    expect(result.codes).toContain('CRYPTOGRAPHIC_PROOF_NOT_VERIFIED');
  });

  test('rejects a registry issued after the evaluation time', async () => {
    const root = temporaryRoot();
    const emitted = await evidence(root);
    const fingerprint = emitted.envelope.proof.signature.public_key_fingerprint as string;
    const result = evaluate(
      root,
      emitted.envelope,
      registry(authorization(fingerprint), '2026-08-25T00:00:00Z')
    );

    expect(result.status).toBe('UNKNOWN');
    expect(result.codes).toContain('REGISTRY_ISSUED_AFTER_EVALUATION');
  });
});
