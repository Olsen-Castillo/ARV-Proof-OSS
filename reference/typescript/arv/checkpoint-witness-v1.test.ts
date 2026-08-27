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
  sha256ARVTrustRegistryCheckpointV1
} from './trust-registry-checkpoint-v1';
import {
  ARVCheckpointWitnessBundleV1,
  ARVCheckpointWitnessKeyV1,
  ARVCheckpointWitnessObservationV1,
  ARVCheckpointWitnessPolicyV1,
  ARVTrustedWitnessCheckpointV1,
  canonicalARVCheckpointWitnessObservationSigningPayloadV1,
  canonicalARVCheckpointWitnessPolicySigningPayloadV1,
  verifyARVCheckpointWitnessV1
} from './checkpoint-witness-v1';

interface RootTestKey {
  descriptor: ARVTrustRootKeyV1;
  secret_key: Uint8Array;
}

interface WitnessTestKey {
  descriptor: ARVCheckpointWitnessKeyV1;
  secret_key: Uint8Array;
}

function keyPair(label: string) {
  const seed = crypto.createHash('sha256').update(`ARV-PUBLIC-TEST:${label}`).digest();
  return nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
}

function rootTestKey(label: string): RootTestKey {
  const pair = keyPair(`ROOT:${label}`);
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

function witnessTestKey(label: string): WitnessTestKey {
  const pair = keyPair(`WITNESS:${label}`);
  return {
    descriptor: {
      witness_key_id: crypto.createHash('sha256').update(pair.publicKey).digest('hex').slice(0, 24),
      algorithm: 'Ed25519',
      public_key_base64: Buffer.from(pair.publicKey).toString('base64'),
      status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: null
    },
    secret_key: pair.secretKey
  };
}

const rootKeys = [rootTestKey('1'), rootTestKey('2'), rootTestKey('3')];
const witnessKeys = [witnessTestKey('1'), witnessTestKey('2'), witnessTestKey('3')];

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

function checkpoint(
  root: ARVTrustRootV1,
  distribution: ARVTrustDistributionManifestV1,
  sequence: number,
  previous: string | null
): ARVTrustRegistryCheckpointV1 {
  const value: ARVTrustRegistryCheckpointV1 = {
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
  const payload = Buffer.from(canonicalARVTrustRegistryCheckpointSigningPayloadV1(value), 'utf8');
  value.signatures = rootKeys.slice(0, 2).map((key) => ({
    algorithm: 'Ed25519',
    key_id: key.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
  }));
  return value;
}

function witnessPolicy(root: ARVTrustRootV1): ARVCheckpointWitnessPolicyV1 {
  const value: ARVCheckpointWitnessPolicyV1 = {
    schema: 'arv.checkpoint-witness-policy',
    schema_version: 1,
    policy_id: 'ARV-WITNESS-POLICY-OFFICIAL',
    policy_version: 1,
    root_id: root.root_id,
    root_version: root.root_version,
    root_epoch: root.epoch,
    root_hash: sha256ARVTrustRootV1(root),
    issued_at: '2026-01-01T00:00:00Z',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2027-01-01T00:00:00Z',
    threshold: 2,
    max_observation_age_seconds: 2678400,
    witnesses: witnessKeys.map((key) => ({ ...key.descriptor })),
    signatures: []
  };
  const payload = Buffer.from(canonicalARVCheckpointWitnessPolicySigningPayloadV1(value), 'utf8');
  value.signatures = rootKeys.slice(0, 2).map((key) => ({
    algorithm: 'Ed25519',
    key_id: key.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
  }));
  return value;
}

function observation(
  policy: ARVCheckpointWitnessPolicyV1,
  checkpointValue: ARVTrustRegistryCheckpointV1,
  key: WitnessTestKey,
  label: string
): ARVCheckpointWitnessObservationV1 {
  const value: ARVCheckpointWitnessObservationV1 = {
    schema: 'arv.checkpoint-witness-observation',
    schema_version: 1,
    observation_id: `ARV-WITNESS-OBSERVATION-${label}`,
    witness_policy_id: policy.policy_id,
    witness_policy_version: policy.policy_version,
    witness_key_id: key.descriptor.witness_key_id,
    checkpoint_id: checkpointValue.checkpoint_id,
    checkpoint_hash: sha256ARVTrustRegistryCheckpointV1(checkpointValue),
    sequence: checkpointValue.sequence,
    registry_id: checkpointValue.registry_id,
    registry_version: checkpointValue.registry_version,
    registry_digest: checkpointValue.registry_digest,
    previous_checkpoint_hash: checkpointValue.previous_checkpoint_hash,
    observed_at: `2026-0${checkpointValue.sequence}-02T00:00:00Z`,
    signature: { algorithm: 'Ed25519', signature_base64: Buffer.alloc(64).toString('base64') }
  };
  const payload = Buffer.from(canonicalARVCheckpointWitnessObservationSigningPayloadV1(value), 'utf8');
  value.signature.signature_base64 = Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64');
  return value;
}

function resignPolicy(policy: ARVCheckpointWitnessPolicyV1, signers = rootKeys.slice(0, 2)) {
  policy.signatures = [];
  const payload = Buffer.from(canonicalARVCheckpointWitnessPolicySigningPayloadV1(policy), 'utf8');
  policy.signatures = signers.map((key) => ({
    algorithm: 'Ed25519' as const,
    key_id: key.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
  }));
}

function resignObservation(value: ARVCheckpointWitnessObservationV1, key: WitnessTestKey) {
  const payload = Buffer.from(canonicalARVCheckpointWitnessObservationSigningPayloadV1(value), 'utf8');
  value.signature.signature_base64 = Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64');
}

function fixture(version = 1, sequence = version, previous: string | null = sequence === 1 ? null : 'a'.repeat(64)) {
  const root = trustRoot();
  const bytes = registryBytes(version);
  const distribution = manifest(version, bytes);
  const checkpointValue = checkpoint(root, distribution, sequence, previous);
  const policy = witnessPolicy(root);
  const observations = [
    observation(policy, checkpointValue, witnessKeys[0], `${sequence}-A`),
    observation(policy, checkpointValue, witnessKeys[1], `${sequence}-B`)
  ];
  const bundle: ARVCheckpointWitnessBundleV1 = {
    schema: 'arv.checkpoint-witness-bundle',
    schema_version: 1,
    bundle_id: `ARV-WITNESS-BUNDLE-${String(sequence).padStart(4, '0')}`,
    witness_policy_id: policy.policy_id,
    witness_policy_version: policy.policy_version,
    checkpoint_id: checkpointValue.checkpoint_id,
    checkpoint_hash: sha256ARVTrustRegistryCheckpointV1(checkpointValue),
    sequence,
    observations
  };
  return {
    trust_root: root,
    checkpoint: checkpointValue,
    manifest: distribution,
    registry_bytes: bytes,
    trusted_checkpoint: null as ARVTrustedRegistryCheckpointV1 | null,
    evaluated_at: `2026-0${sequence}-15T00:00:00Z`,
    witness_policy: policy,
    witness_bundle: bundle,
    trusted_witness_checkpoint: null as ARVTrustedWitnessCheckpointV1 | null
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('ARV Public checkpoint witness cosigning and split-view detection', () => {
  test('accepts an offline authorized witness quorum over a valid Public checkpoint', () => {
    const result = verifyARVCheckpointWitnessV1(fixture());
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('WITNESS_QUORUM_VALID');
    expect(result.witness_count).toBe(2);
    expect(result.witness_authority).toBe('DETECTION_ONLY');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });

  test('rejects an invalid underlying Public checkpoint before witness evaluation', () => {
    const data = fixture();
    data.registry_bytes = data.registry_bytes.replace('OFFICIAL', 'TAMPERED');
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('UNDERLYING_CHECKPOINT_INVALID');
    expect(result.codes).toContain('UNDERLYING_CHECKPOINT_REJECTED');
  });

  test('requires the witness policy to be threshold signed by the pinned root', () => {
    const data = fixture();
    data.witness_policy.signatures.pop();
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_POLICY_UNTRUSTED');
    expect(result.codes).toContain('WITNESS_POLICY_ROOT_THRESHOLD_NOT_MET');
  });

  test('rejects an invalid root signature even when policy threshold is met', () => {
    const data = fixture();
    data.witness_policy.signatures.push({
      algorithm: 'Ed25519',
      key_id: rootKeys[2].descriptor.key_id,
      signature_base64: Buffer.alloc(64).toString('base64')
    });
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_POLICY_UNTRUSTED');
    expect(result.codes).toContain('WITNESS_POLICY_SIGNATURE_INVALID');
  });

  test('canonical policy bytes ignore key and signature ordering', () => {
    const data = fixture();
    const first = canonicalARVCheckpointWitnessPolicySigningPayloadV1(data.witness_policy);
    const reordered = {
      ...data.witness_policy,
      witnesses: [...data.witness_policy.witnesses].reverse(),
      signatures: [...data.witness_policy.signatures].reverse()
    };
    expect(canonicalARVCheckpointWitnessPolicySigningPayloadV1(reordered)).toBe(first);
    expect(first.startsWith('ARV-CHECKPOINT-WITNESS-POLICY-v1\n')).toBe(true);
  });

  test('uses a language-neutral witness observation signing domain', () => {
    const data = fixture();
    const payload = canonicalARVCheckpointWitnessObservationSigningPayloadV1(
      data.witness_bundle.observations[0]
    );
    expect(payload.startsWith('ARV-CHECKPOINT-WITNESS-OBSERVATION-v1\n')).toBe(true);
    expect(payload).not.toContain('signature_base64');
  });

  test('rejects an insufficient independent witness quorum', () => {
    const data = fixture();
    data.witness_bundle.observations.pop();
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_QUORUM_INSUFFICIENT');
    expect(result.codes).toContain('WITNESS_THRESHOLD_NOT_MET');
  });

  test('rejects an invalid witness signature', () => {
    const data = fixture();
    data.witness_bundle.observations[1].signature.signature_base64 = Buffer.alloc(64).toString('base64');
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_SIGNATURE_INVALID');
    expect(result.codes).toContain('WITNESS_SIGNATURE_INVALID');
  });

  test('rejects a cryptographically valid observation from an unauthorized witness', () => {
    const data = fixture();
    const rogue = witnessTestKey('ROGUE');
    data.witness_bundle.observations[1] = observation(data.witness_policy, data.checkpoint, rogue, '1-ROGUE');
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_INVALID');
    expect(result.codes).toContain('WITNESS_NOT_AUTHORIZED');
  });

  test('rejects a revoked witness', () => {
    const data = fixture();
    data.witness_policy.witnesses[1].status = 'REVOKED';
    data.witness_policy.threshold = 1;
    resignPolicy(data.witness_policy);
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_INVALID');
    expect(result.codes).toContain('WITNESS_NOT_ACTIVE');
  });

  test('detects a validly signed conflicting view from another witness', () => {
    const data = fixture();
    const conflicting = clone(data.witness_bundle.observations[1]);
    conflicting.checkpoint_hash = 'f'.repeat(64);
    conflicting.observation_id = 'ARV-WITNESS-OBSERVATION-1-CONFLICT';
    resignObservation(conflicting, witnessKeys[1]);
    data.witness_bundle.observations[1] = conflicting;
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('SPLIT_VIEW_DETECTED');
    expect(result.codes).toContain('WITNESS_SPLIT_VIEW_DETECTED');
  });

  test('detects witness equivocation across two signed observations', () => {
    const data = fixture();
    const conflicting = clone(data.witness_bundle.observations[0]);
    conflicting.checkpoint_hash = 'e'.repeat(64);
    conflicting.observation_id = 'ARV-WITNESS-OBSERVATION-1-EQUIVOCATION';
    resignObservation(conflicting, witnessKeys[0]);
    data.witness_bundle.observations.splice(1, 0, conflicting);
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_EQUIVOCATION');
    expect(result.codes).toContain('WITNESS_EQUIVOCATION_DETECTED');
  });

  test('rejects witness history rollback', () => {
    const data = fixture();
    data.trusted_witness_checkpoint = {
      checkpoint_id: 'ARV-TRUST-CHECKPOINT-0002',
      checkpoint_hash: 'b'.repeat(64),
      sequence: 2,
      witness_policy_id: data.witness_policy.policy_id,
      witness_policy_version: 1,
      observed_at: '2026-02-02T00:00:00Z'
    };
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_ROLLBACK');
    expect(result.codes).toContain('WITNESS_SEQUENCE_ROLLBACK');
  });

  test('detects a split view at an already trusted sequence', () => {
    const data = fixture();
    data.trusted_witness_checkpoint = {
      checkpoint_id: data.checkpoint.checkpoint_id,
      checkpoint_hash: 'd'.repeat(64),
      sequence: 1,
      witness_policy_id: data.witness_policy.policy_id,
      witness_policy_version: 1,
      observed_at: '2026-01-02T00:00:00Z'
    };
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('SPLIT_VIEW_DETECTED');
    expect(result.codes).toContain('WITNESS_SPLIT_VIEW_DETECTED');
  });

  test('accepts an idempotent replay of an identical witnessed checkpoint', () => {
    const data = fixture();
    const first = verifyARVCheckpointWitnessV1(data);
    data.trusted_checkpoint = {
      checkpoint_id: data.checkpoint.checkpoint_id,
      checkpoint_hash: first.checkpoint_hash!,
      sequence: 1,
      registry_id: data.checkpoint.registry_id,
      registry_version: 1,
      registry_digest: data.checkpoint.registry_digest,
      root_id: data.checkpoint.root_id,
      root_version: 1,
      root_epoch: 1
    };
    data.trusted_witness_checkpoint = first.trusted_witness_checkpoint;
    const replay = verifyARVCheckpointWitnessV1(data);
    expect(replay.accepted).toBe(true);
    expect(replay.checkpoint_hash).toBe(first.checkpoint_hash);
  });

  test('detects a witness sequence gap after an independently valid Public advance', () => {
    const data = fixture(3, 3, 'b'.repeat(64));
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
    data.trusted_witness_checkpoint = {
      checkpoint_id: 'ARV-TRUST-CHECKPOINT-0001',
      checkpoint_hash: 'a'.repeat(64),
      sequence: 1,
      witness_policy_id: data.witness_policy.policy_id,
      witness_policy_version: 1,
      observed_at: '2026-01-02T00:00:00Z'
    };
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_GAP');
    expect(result.codes).toContain('WITNESS_SEQUENCE_GAP');
  });

  test('detects a predecessor inconsistent with witnessed history', () => {
    const data = fixture(2, 2, 'b'.repeat(64));
    data.trusted_checkpoint = {
      checkpoint_id: 'ARV-TRUST-CHECKPOINT-0001',
      checkpoint_hash: 'b'.repeat(64),
      sequence: 1,
      registry_id: data.checkpoint.registry_id,
      registry_version: 1,
      registry_digest: 'c'.repeat(64),
      root_id: data.checkpoint.root_id,
      root_version: 1,
      root_epoch: 1
    };
    data.trusted_witness_checkpoint = {
      checkpoint_id: 'ARV-TRUST-CHECKPOINT-0001',
      checkpoint_hash: 'a'.repeat(64),
      sequence: 1,
      witness_policy_id: data.witness_policy.policy_id,
      witness_policy_version: 1,
      observed_at: '2026-01-02T00:00:00Z'
    };
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('SPLIT_VIEW_DETECTED');
    expect(result.codes).toContain('WITNESS_PREDECESSOR_MISMATCH');
  });

  test('rejects stale witness observations without network fallback', () => {
    const data = fixture();
    data.witness_policy.max_observation_age_seconds = 60;
    resignPolicy(data.witness_policy);
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_STALE');
    expect(result.codes).toContain('WITNESS_OBSERVATION_STALE');
  });

  test('rejects an expired witness policy', () => {
    const data = fixture();
    data.witness_policy.expires_at = '2026-01-10T00:00:00Z';
    resignPolicy(data.witness_policy);
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_POLICY_UNTRUSTED');
    expect(result.codes).toContain('WITNESS_POLICY_EXPIRED');
  });

  test('forbids private key material in witness artifacts', () => {
    const data = fixture();
    const bundle = clone(data.witness_bundle) as ARVCheckpointWitnessBundleV1 & { private_key?: string };
    bundle.private_key = 'forbidden';
    data.witness_bundle = bundle;
    const result = verifyARVCheckpointWitnessV1(data);
    expect(result.state).toBe('WITNESS_INVALID');
    expect(result.codes).toContain('PRIVATE_KEY_MATERIAL_FORBIDDEN');
  });

  test('never promotes witnesses, mirrors or transport into ARV authority', () => {
    const result = verifyARVCheckpointWitnessV1(fixture());
    expect(result.authority_basis).toBe('PINNED_TRUST_ROOT');
    expect(result.witness_authority).toBe('DETECTION_ONLY');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });
});
