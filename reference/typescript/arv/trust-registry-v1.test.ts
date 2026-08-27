import crypto from 'crypto';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import {
  TrustAnchorV1,
  TrustRegistryCheckpointV1,
  TrustRegistryV1,
  UnsignedTrustRegistryV1,
  assertTrustRegistryV1,
  canonicalTrustRegistryPayloadV1,
  trustRegistryHashV1,
  verifyTrustRegistryV1
} from './trust-registry-v1';

const rootPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(23));
const rootFingerprint = crypto
  .createHash('sha256')
  .update(Buffer.from(rootPair.publicKey))
  .digest('hex');

const anchor: TrustAnchorV1 = {
  schema: 'arv.trust-anchor',
  schema_version: 1,
  registry_id: 'ARV-TRUST-OFFICIAL-V1',
  algorithm: 'Ed25519',
  key_fingerprint: rootFingerprint,
  public_key_base64: encodeBase64(rootPair.publicKey)
};

function unsigned(
  sequence = 1,
  previousRegistryHash: string | null = null
): UnsignedTrustRegistryV1 {
  return {
    schema: 'arv.trust-registry',
    schema_version: 1,
    registry_id: anchor.registry_id,
    sequence,
    issued_at: '2026-08-21T20:00:00Z',
    previous_registry_hash: previousRegistryHash,
    authorizations: [
      {
        authorization_id: 'ARV-AUTH-PRIMARY-001',
        issuer_id: 'ARV-ISSUER-EXAMPLE-001',
        authority: 'Example Evidence Authority',
        systems: ['Example Evidence System'],
        roles: ['ISSUER', 'VERIFIER'],
        products: ['ARV_PROOF_OSS', 'GENERIC'],
        environment: 'PRODUCTION',
        key_fingerprint: 'a'.repeat(24),
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: null,
        status: 'ACTIVE',
        status_effective_at: null,
        compromise_effective_from: null
      }
    ]
  };
}

function sign(value: UnsignedTrustRegistryV1): TrustRegistryV1 {
  return {
    ...value,
    signature: {
      algorithm: 'Ed25519',
      key_fingerprint: rootFingerprint,
      value: encodeBase64(
        nacl.sign.detached(
          Buffer.from(canonicalTrustRegistryPayloadV1(value), 'utf8'),
          rootPair.secretKey
        )
      )
    }
  };
}

function checkpoint(registry: TrustRegistryV1): TrustRegistryCheckpointV1 {
  return {
    registry_id: registry.registry_id,
    sequence: registry.sequence,
    registry_hash: trustRegistryHashV1(registry)
  };
}

describe('ARV Public signed trust registry', () => {
  test('accepts a root-signed registry at the pinned checkpoint', () => {
    const registry = sign(unsigned());
    expect(assertTrustRegistryV1(registry)).toBe(registry);
    expect(verifyTrustRegistryV1(registry, anchor, checkpoint(registry))).toEqual({
      trusted: true,
      registry_id: registry.registry_id,
      sequence: 1,
      registry_hash: trustRegistryHashV1(registry),
      codes: []
    });
  });

  test('rejects a registry changed after signing', () => {
    const registry = sign(unsigned());
    registry.authorizations[0].authority = 'Copied Authority';
    const verified = verifyTrustRegistryV1(registry, anchor, {
      registry_id: registry.registry_id,
      sequence: 1,
      registry_hash: trustRegistryHashV1(registry)
    });
    expect(verified.trusted).toBe(false);
    expect(verified.codes).toContain('REGISTRY_SIGNATURE_INVALID');
  });

  test('fails closed without a trusted checkpoint', () => {
    const registry = sign(unsigned());
    const verified = verifyTrustRegistryV1(registry, anchor, null);
    expect(verified.trusted).toBe(false);
    expect(verified.codes).toEqual(['CHECKPOINT_UNAVAILABLE']);
  });

  test('detects rollback below a trusted sequence', () => {
    const registry = sign(unsigned());
    const verified = verifyTrustRegistryV1(registry, anchor, {
      registry_id: registry.registry_id,
      sequence: 2,
      registry_hash: 'b'.repeat(64)
    });
    expect(verified.codes).toContain('REGISTRY_ROLLBACK_DETECTED');
  });

  test('detects equivocation at the same sequence', () => {
    const registry = sign(unsigned());
    const verified = verifyTrustRegistryV1(registry, anchor, {
      registry_id: registry.registry_id,
      sequence: 1,
      registry_hash: 'c'.repeat(64)
    });
    expect(verified.codes).toContain('REGISTRY_EQUIVOCATION_DETECTED');
  });

  test('accepts exactly one correctly chained successor', () => {
    const first = sign(unsigned());
    const firstCheckpoint = checkpoint(first);
    const second = sign(unsigned(2, firstCheckpoint.registry_hash));
    expect(verifyTrustRegistryV1(second, anchor, firstCheckpoint).trusted).toBe(true);
  });

  test('rejects a direct successor with the wrong previous hash', () => {
    const first = sign(unsigned());
    const second = sign(unsigned(2, 'e'.repeat(64)));
    const verified = verifyTrustRegistryV1(second, anchor, checkpoint(first));
    expect(verified.trusted).toBe(false);
    expect(verified.codes).toContain('REGISTRY_CHAIN_MISMATCH');
  });

  test('rejects an unprovable sequence gap', () => {
    const first = sign(unsigned());
    const third = sign(unsigned(3, 'd'.repeat(64)));
    const verified = verifyTrustRegistryV1(third, anchor, checkpoint(first));
    expect(verified.codes).toContain('REGISTRY_CHAIN_GAP');
  });

  test('rejects private material and duplicate key authorizations', () => {
    const registry = sign(unsigned()) as unknown as Record<string, unknown>;
    expect(() => assertTrustRegistryV1({ ...registry, private_key: 'forbidden' })).toThrow();

    const duplicate = sign(unsigned());
    duplicate.authorizations.push({
      ...duplicate.authorizations[0],
      authorization_id: 'ARV-AUTH-PRIMARY-002'
    });
    expect(() => assertTrustRegistryV1(duplicate)).toThrow('key fingerprints must be unique');
  });
});
