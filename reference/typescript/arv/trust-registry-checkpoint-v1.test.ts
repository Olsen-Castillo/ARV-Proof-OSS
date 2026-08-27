import crypto from 'crypto';
import nacl from 'tweetnacl';
import {
  ARVTrustRootKeyV1,
  ARVTrustRootV1,
  fingerprintARVTrustRootPublicKeyV1,
  sha256ARVTrustRootV1
} from './trust-root-lifecycle-v1';
import {
  ARVTrustDistributionManifestV1,
  ARVTrustRegistryCheckpointV1,
  ARVTrustedRegistryCheckpointV1,
  canonicalARVTrustRegistryCheckpointSigningPayloadV1,
  sha256ARVTrustDistributionManifestV1,
  sha256ARVTrustRegistryCheckpointV1,
  verifyARVTrustRegistryCheckpointV1
} from './trust-registry-checkpoint-v1';

interface TestKey {
  descriptor: ARVTrustRootKeyV1;
  secret_key: Uint8Array;
}

function testKey(label: string): TestKey {
  const seed = crypto.createHash('sha256').update(`ARV-PUBLIC-TEST:${label}`).digest();
  const pair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
  return {
    descriptor: {
      key_id: fingerprintARVTrustRootPublicKeyV1(pair.publicKey),
      algorithm: 'Ed25519',
      public_key_base64: Buffer.from(pair.publicKey).toString('base64'),
      roles: ['ROOT', 'RECOVERY'],
      status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: null
    },
    secret_key: pair.secretKey
  };
}

const rootKeys = [testKey('ROOT-1'), testKey('ROOT-2'), testKey('ROOT-3')];

function trustRoot(): ARVTrustRootV1 {
  return {
    schema: 'arv.trust-root',
    schema_version: 1,
    root_id: 'ARV-ROOT-OFFICIAL',
    root_version: 1,
    epoch: 1,
    issued_at: '2026-01-01T00:00:00Z',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2028-01-01T00:00:00Z',
    threshold: 2,
    recovery_threshold: 1,
    previous_root_hash: null,
    policy_digest: crypto.createHash('sha256').update('ARV-PUBLIC-ROOT-POLICY').digest('hex'),
    keys: rootKeys.map((key) => key.descriptor)
  };
}

function registryBytes(version: number): string {
  return `${JSON.stringify({
    schema: 'arv.trust-registry',
    schema_version: 1,
    registry_id: 'ARV-TRUST-REGISTRY-OFFICIAL',
    registry_version: version,
    entries: []
  })}\n`;
}

function manifest(version: number, bytes: string): ARVTrustDistributionManifestV1 {
  return {
    schema: 'arv.trust-distribution-manifest',
    schema_version: 1,
    manifest_id: `ARV-TRUST-MANIFEST-${String(version).padStart(4, '0')}`,
    registry_id: 'ARV-TRUST-REGISTRY-OFFICIAL',
    registry_version: version,
    registry_path: `registry/arv-trust-registry-v${version}.json`,
    registry_media_type: 'application/json',
    registry_bytes: Buffer.from(bytes).length,
    registry_digest: crypto.createHash('sha256').update(bytes).digest('hex'),
    created_at: `2026-0${version}-01T00:00:00Z`
  };
}

function unsignedCheckpoint(
  root: ARVTrustRootV1,
  distribution: ARVTrustDistributionManifestV1,
  sequence: number,
  previous: string | null
): ARVTrustRegistryCheckpointV1 {
  return {
    schema: 'arv.trust-registry-checkpoint',
    schema_version: 1,
    checkpoint_id: `ARV-TRUST-CHECKPOINT-${String(sequence).padStart(4, '0')}`,
    sequence,
    registry_id: distribution.registry_id,
    registry_version: distribution.registry_version,
    registry_digest: distribution.registry_digest,
    root_id: root.root_id,
    root_version: root.root_version,
    root_epoch: root.epoch,
    root_hash: sha256ARVTrustRootV1(root),
    previous_checkpoint_hash: previous,
    manifest_digest: sha256ARVTrustDistributionManifestV1(distribution),
    issued_at: `2026-0${sequence}-01T00:00:00Z`,
    valid_from: `2026-0${sequence}-01T00:00:00Z`,
    expires_at: `2026-0${sequence + 1}-01T00:00:00Z`,
    signatures: []
  };
}

function authorize(checkpoint: ARVTrustRegistryCheckpointV1, signers: TestKey[]): ARVTrustRegistryCheckpointV1 {
  const payload = Buffer.from(canonicalARVTrustRegistryCheckpointSigningPayloadV1(checkpoint), 'utf8');
  return {
    ...checkpoint,
    signatures: signers.map((key) => ({
      algorithm: 'Ed25519' as const,
      key_id: key.descriptor.key_id,
      signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
    }))
  };
}

function fixture(
  version = 1,
  sequence = version,
  previous: string | null = sequence === 1 ? null : 'a'.repeat(64)
) {
  const root = trustRoot();
  const bytes = registryBytes(version);
  const distribution = manifest(version, bytes);
  const checkpoint = authorize(
    unsignedCheckpoint(root, distribution, sequence, previous),
    rootKeys.slice(0, 2)
  );
  return {
    trust_root: root,
    checkpoint,
    manifest: distribution,
    registry_bytes: bytes,
    trusted_checkpoint: null as ARVTrustedRegistryCheckpointV1 | null,
    evaluated_at: `2026-0${sequence}-15T00:00:00Z`
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('ARV Public trust-registry checkpoint distribution', () => {
  test('accepts a threshold-signed initial checkpoint offline', () => {
    const result = verifyARVTrustRegistryCheckpointV1(fixture());
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('CHECKPOINT_VALID');
    expect(result.trusted_checkpoint?.sequence).toBe(1);
    expect(result.authority_basis).toBe('PINNED_TRUST_ROOT');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });

  test('uses language-neutral signing bytes independent of signature order', () => {
    const data = fixture();
    const first = canonicalARVTrustRegistryCheckpointSigningPayloadV1(data.checkpoint);
    const reordered = { ...data.checkpoint, signatures: [...data.checkpoint.signatures].reverse() };
    expect(canonicalARVTrustRegistryCheckpointSigningPayloadV1(reordered)).toBe(first);
    expect(first.startsWith('ARV-TRUST-REGISTRY-CHECKPOINT-v1\n')).toBe(true);
  });

  test('accepts the next directly chained registry version', () => {
    const initial = fixture();
    const acceptedInitial = verifyARVTrustRegistryCheckpointV1(initial);
    const next = fixture(2, 2, acceptedInitial.checkpoint_hash);
    next.trusted_checkpoint = acceptedInitial.trusted_checkpoint;
    const result = verifyARVTrustRegistryCheckpointV1(next);
    expect(result.accepted).toBe(true);
    expect(result.trusted_checkpoint?.registry_version).toBe(2);
  });

  test('accepts an idempotent replay of the identical checkpoint', () => {
    const data = fixture();
    const first = verifyARVTrustRegistryCheckpointV1(data);
    data.trusted_checkpoint = first.trusted_checkpoint;
    const second = verifyARVTrustRegistryCheckpointV1(data);
    expect(second.accepted).toBe(true);
    expect(second.checkpoint_hash).toBe(first.checkpoint_hash);
  });

  test('rejects registry artifact digest mismatch', () => {
    const data = fixture();
    data.registry_bytes = data.registry_bytes.replace('OFFICIAL', 'TAMPERED');
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('REGISTRY_DIGEST_MISMATCH');
    expect(result.codes).toContain('REGISTRY_ARTIFACT_DIGEST_MISMATCH');
  });

  test('rejects a manifest not bound by its checkpoint', () => {
    const data = fixture();
    data.manifest.registry_path = 'registry/other.json';
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('MANIFEST_INVALID');
    expect(result.codes).toContain('MANIFEST_DIGEST_MISMATCH');
  });

  test('rejects a manifest created after checkpoint issuance', () => {
    const data = fixture();
    data.manifest.created_at = '2026-01-02T00:00:00Z';
    data.checkpoint.manifest_digest = sha256ARVTrustDistributionManifestV1(data.manifest);
    data.checkpoint = authorize(data.checkpoint, rootKeys.slice(0, 2));
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('MANIFEST_INVALID');
    expect(result.codes).toContain('MANIFEST_TIME_INVALID');
  });

  test('rejects a checkpoint bound to a different trust root hash', () => {
    const data = fixture();
    data.checkpoint.root_hash = 'f'.repeat(64);
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('ROOT_UNTRUSTED');
    expect(result.codes).toContain('ROOT_BINDING_MISMATCH');
  });

  test('rejects a checkpoint before its activation time', () => {
    const data = fixture();
    data.evaluated_at = '2025-12-31T23:59:59Z';
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('CHECKPOINT_NOT_YET_VALID');
    expect(result.codes).toContain('CHECKPOINT_NOT_ACTIVE');
  });

  test('rejects an expired checkpoint and therefore detects freeze', () => {
    const data = fixture();
    data.evaluated_at = '2027-01-01T00:00:00Z';
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('CHECKPOINT_EXPIRED');
    expect(result.codes).toContain('CHECKPOINT_EXPIRED_AT_EVALUATION');
  });

  test('rejects an insufficient root-signing threshold', () => {
    const data = fixture();
    data.checkpoint.signatures.pop();
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('INSUFFICIENT_THRESHOLD');
    expect(result.codes).toContain('ROOT_THRESHOLD_NOT_MET');
  });

  test('rejects an invalid signature even when the threshold is met', () => {
    const data = fixture();
    data.checkpoint.signatures.push({
      algorithm: 'Ed25519',
      key_id: rootKeys[2].descriptor.key_id,
      signature_base64: Buffer.alloc(nacl.sign.signatureLength).toString('base64')
    });
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('CHECKPOINT_INVALID');
    expect(result.codes).toContain('SIGNATURE_INVALID');
  });

  test('rejects a checkpoint sequence rollback', () => {
    const data = fixture();
    data.trusted_checkpoint = {
      checkpoint_id: 'ARV-TRUST-CHECKPOINT-0002',
      checkpoint_hash: 'b'.repeat(64),
      sequence: 2,
      registry_id: data.checkpoint.registry_id,
      registry_version: 2,
      registry_digest: 'c'.repeat(64),
      root_id: data.checkpoint.root_id,
      root_version: 1,
      root_epoch: 1
    };
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('CHECKPOINT_ROLLBACK');
    expect(result.codes).toContain('CHECKPOINT_SEQUENCE_ROLLBACK');
  });

  test('rejects a different statement at a trusted sequence as equivocation', () => {
    const original = fixture();
    const accepted = verifyARVTrustRegistryCheckpointV1(original);
    const conflicting = fixture();
    conflicting.registry_bytes = registryBytes(1).replace('"entries":[]', '"entries":[{}]');
    conflicting.manifest = manifest(1, conflicting.registry_bytes);
    conflicting.checkpoint = authorize(
      unsignedCheckpoint(conflicting.trust_root, conflicting.manifest, 1, null),
      rootKeys.slice(0, 2)
    );
    conflicting.trusted_checkpoint = accepted.trusted_checkpoint;
    const result = verifyARVTrustRegistryCheckpointV1(conflicting);
    expect(result.state).toBe('CHECKPOINT_EQUIVOCATION');
    expect(result.codes).toContain('CHECKPOINT_EQUIVOCATION_DETECTED');
  });

  test('rejects a checkpoint sequence gap', () => {
    const initial = fixture();
    const accepted = verifyARVTrustRegistryCheckpointV1(initial);
    const gap = fixture(3, 3, accepted.checkpoint_hash);
    gap.trusted_checkpoint = accepted.trusted_checkpoint;
    const result = verifyARVTrustRegistryCheckpointV1(gap);
    expect(result.state).toBe('CHECKPOINT_GAP');
    expect(result.codes).toContain('CHECKPOINT_CHAIN_GAP');
  });

  test('rejects a mismatched predecessor hash as equivocation', () => {
    const initial = fixture();
    const accepted = verifyARVTrustRegistryCheckpointV1(initial);
    const next = fixture(2, 2, 'e'.repeat(64));
    next.trusted_checkpoint = accepted.trusted_checkpoint;
    const result = verifyARVTrustRegistryCheckpointV1(next);
    expect(result.state).toBe('CHECKPOINT_EQUIVOCATION');
    expect(result.codes).toContain('PREVIOUS_CHECKPOINT_HASH_MISMATCH');
  });

  test('rejects registry version rollback on a later sequence', () => {
    const initial = fixture();
    const accepted = verifyARVTrustRegistryCheckpointV1(initial);
    const replayedVersion = fixture(1, 2, accepted.checkpoint_hash);
    replayedVersion.trusted_checkpoint = accepted.trusted_checkpoint;
    const result = verifyARVTrustRegistryCheckpointV1(replayedVersion);
    expect(result.state).toBe('CHECKPOINT_ROLLBACK');
    expect(result.codes).toContain('REGISTRY_VERSION_ROLLBACK');
  });

  test('does not allow a mirror path to become an authority input', () => {
    const data = fixture();
    const mirrored = clone(data.manifest);
    mirrored.registry_path = 'mirror-b/registry.json';
    data.manifest = mirrored;
    data.checkpoint.manifest_digest = sha256ARVTrustDistributionManifestV1(mirrored);
    data.checkpoint = authorize(data.checkpoint, rootKeys.slice(0, 2));
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.accepted).toBe(true);
    expect(result.transport_authority).toBe('NONE');
  });

  test('forbids private key material in checkpoint documents', () => {
    const data = fixture();
    const checkpoint = clone(data.checkpoint) as ARVTrustRegistryCheckpointV1 & { private_key?: string };
    checkpoint.private_key = 'forbidden';
    data.checkpoint = checkpoint;
    const result = verifyARVTrustRegistryCheckpointV1(data);
    expect(result.state).toBe('CHECKPOINT_INVALID');
    expect(result.codes).toContain('PRIVATE_KEY_MATERIAL_FORBIDDEN');
  });

  test('checkpoint chain hashes ignore signature ordering', () => {
    const data = fixture();
    const reversed = { ...data.checkpoint, signatures: [...data.checkpoint.signatures].reverse() };
    expect(sha256ARVTrustRegistryCheckpointV1(reversed)).toBe(
      sha256ARVTrustRegistryCheckpointV1(data.checkpoint)
    );
  });
});
