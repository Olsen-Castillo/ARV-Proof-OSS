import crypto from 'crypto';
import nacl from 'tweetnacl';
import {
  ARVTrustRootKeyV1,
  ARVTrustRootTransitionV1,
  ARVTrustRootV1,
  canonicalARVTrustRootTransitionSigningPayloadV1,
  fingerprintARVTrustRootPublicKeyV1,
  sha256ARVTrustRootV1
} from './trust-root-lifecycle-v1';
import {
  ARVTrustDistributionManifestV1,
  ARVTrustRegistryCheckpointV1,
  canonicalARVTrustRegistryCheckpointSigningPayloadV1,
  sha256ARVTrustDistributionManifestV1,
  sha256ARVTrustRegistryCheckpointV1
} from './trust-registry-checkpoint-v1';
import {
  ARVCheckpointWitnessBundleV1,
  ARVCheckpointWitnessKeyV1,
  ARVCheckpointWitnessObservationV1,
  ARVCheckpointWitnessPolicyV1,
  canonicalARVCheckpointWitnessObservationSigningPayloadV1,
  canonicalARVCheckpointWitnessPolicySigningPayloadV1
} from './checkpoint-witness-v1';
import {
  ARVVerifierBootstrapPinsV1,
  ARVVerifierTrustStateV1,
  EvaluateARVVerifierTrustStateOptionsV1,
  canonicalARVVerifierTrustStateV1,
  evaluateARVVerifierTrustStateV1,
  exportARVVerifierTrustStateV1,
  importARVVerifierTrustStateV1,
  serializeARVVerifierTrustStateEnvelopeV1,
  sha256ARVCheckpointWitnessPolicyForStateV1,
  sha256ARVVerifierTrustStateV1
} from './verifier-trust-state-v1';

interface RootTestKey {
  descriptor: ARVTrustRootKeyV1;
  secret_key: Uint8Array;
}

interface WitnessTestKey {
  descriptor: ARVCheckpointWitnessKeyV1;
  secret_key: Uint8Array;
}

function pair(label: string) {
  const seed = crypto.createHash('sha256').update(`ARV-PUBLIC-TEST:${label}`).digest();
  return nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
}

function rootKey(label: string): RootTestKey {
  const keyPair = pair(`ROOT:${label}`);
  return {
    descriptor: {
      key_id: fingerprintARVTrustRootPublicKeyV1(keyPair.publicKey),
      algorithm: 'Ed25519',
      public_key_base64: Buffer.from(keyPair.publicKey).toString('base64'),
      roles: ['ROOT', 'RECOVERY'],
      status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: null
    },
    secret_key: keyPair.secretKey
  };
}

function witnessKey(label: string): WitnessTestKey {
  const keyPair = pair(`WITNESS:${label}`);
  return {
    descriptor: {
      witness_key_id: crypto.createHash('sha256').update(keyPair.publicKey).digest('hex').slice(0, 24),
      algorithm: 'Ed25519',
      public_key_base64: Buffer.from(keyPair.publicKey).toString('base64'),
      status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: null
    },
    secret_key: keyPair.secretKey
  };
}

const rootKeysV1 = [rootKey('V1-1'), rootKey('V1-2'), rootKey('V1-3')];
const rootKeysV2 = [rootKey('V2-1'), rootKey('V2-2'), rootKey('V2-3')];
const witnessKeys = [witnessKey('1'), witnessKey('2'), witnessKey('3')];

function trustRoot(version = 1): ARVTrustRootV1 {
  const keys = version === 1 ? rootKeysV1 : rootKeysV2;
  const previous = version === 1 ? null : sha256ARVTrustRootV1(trustRoot(1));
  return {
    schema: 'arv.trust-root',
    schema_version: 1,
    root_id: 'ARV-ROOT-OFFICIAL',
    root_version: version,
    epoch: version,
    issued_at: version === 1 ? '2026-01-01T00:00:00Z' : '2026-07-01T00:00:00Z',
    valid_from: version === 1 ? '2026-01-01T00:00:00Z' : '2026-07-01T00:00:00Z',
    expires_at: '2030-01-01T00:00:00Z',
    threshold: 2,
    recovery_threshold: 2,
    previous_root_hash: previous,
    policy_digest: crypto.createHash('sha256').update('ARV-PUBLIC-ROOT-POLICY').digest('hex'),
    keys: keys.map((key) => key.descriptor)
  };
}

function registryBytes(version: number, epoch = 1): string {
  return `${JSON.stringify({
    schema: 'arv.trust-registry',
    schema_version: 1,
    registry_id: 'ARV-TRUST-REGISTRY-OFFICIAL',
    registry_version: version,
    epoch,
    entries: []
  })}\n`;
}

function manifest(version: number, bytes: string, month: number): ARVTrustDistributionManifestV1 {
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
    created_at: `2026-${String(month).padStart(2, '0')}-01T00:00:00Z`
  };
}

function checkpoint(
  root: ARVTrustRootV1,
  distribution: ARVTrustDistributionManifestV1,
  sequence: number,
  previous: string | null,
  month: number
): ARVTrustRegistryCheckpointV1 {
  const keys = root.root_version === 1 ? rootKeysV1 : rootKeysV2;
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
    issued_at: `2026-${String(month).padStart(2, '0')}-02T00:00:00Z`,
    valid_from: `2026-${String(month).padStart(2, '0')}-02T00:00:00Z`,
    expires_at: '2027-12-31T00:00:00Z',
    signatures: []
  };
  const payload = Buffer.from(canonicalARVTrustRegistryCheckpointSigningPayloadV1(value), 'utf8');
  value.signatures = keys.slice(0, 2).map((key) => ({
    algorithm: 'Ed25519',
    key_id: key.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
  }));
  return value;
}

function witnessPolicy(root: ARVTrustRootV1, version = 1): ARVCheckpointWitnessPolicyV1 {
  const keys = root.root_version === 1 ? rootKeysV1 : rootKeysV2;
  const value: ARVCheckpointWitnessPolicyV1 = {
    schema: 'arv.checkpoint-witness-policy',
    schema_version: 1,
    policy_id: 'ARV-WITNESS-POLICY-OFFICIAL',
    policy_version: version,
    root_id: root.root_id,
    root_version: root.root_version,
    root_epoch: root.epoch,
    root_hash: sha256ARVTrustRootV1(root),
    issued_at: root.root_version === 1 ? '2026-01-01T00:00:00Z' : '2026-07-01T00:00:00Z',
    valid_from: root.root_version === 1 ? '2026-01-01T00:00:00Z' : '2026-07-01T00:00:00Z',
    expires_at: '2027-12-31T00:00:00Z',
    threshold: 2,
    max_observation_age_seconds: 31536000,
    witnesses: witnessKeys.map((key) => ({ ...key.descriptor })),
    signatures: []
  };
  const payload = Buffer.from(canonicalARVCheckpointWitnessPolicySigningPayloadV1(value), 'utf8');
  value.signatures = keys.slice(0, 2).map((key) => ({
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
  label: string,
  month: number
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
    observed_at: `2026-${String(month).padStart(2, '0')}-03T00:00:00Z`,
    signature: { algorithm: 'Ed25519', signature_base64: Buffer.alloc(64).toString('base64') }
  };
  const payload = Buffer.from(canonicalARVCheckpointWitnessObservationSigningPayloadV1(value), 'utf8');
  value.signature.signature_base64 = Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64');
  return value;
}

function fixture(
  sequence = 1,
  previous: string | null = null,
  rootVersion = 1,
  policyVersion = 1,
  month = sequence
): EvaluateARVVerifierTrustStateOptionsV1 {
  const root = trustRoot(rootVersion);
  const bytes = registryBytes(sequence, rootVersion);
  const distribution = manifest(sequence, bytes, month);
  const checkpointValue = checkpoint(root, distribution, sequence, previous, month);
  const policy = witnessPolicy(root, policyVersion);
  const bundle: ARVCheckpointWitnessBundleV1 = {
    schema: 'arv.checkpoint-witness-bundle',
    schema_version: 1,
    bundle_id: `ARV-WITNESS-BUNDLE-${String(sequence).padStart(4, '0')}`,
    witness_policy_id: policy.policy_id,
    witness_policy_version: policy.policy_version,
    checkpoint_id: checkpointValue.checkpoint_id,
    checkpoint_hash: sha256ARVTrustRegistryCheckpointV1(checkpointValue),
    sequence,
    observations: [
      observation(policy, checkpointValue, witnessKeys[0], `${rootVersion}-${sequence}-A`, month),
      observation(policy, checkpointValue, witnessKeys[1], `${rootVersion}-${sequence}-B`, month)
    ]
  };
  return {
    state_id: 'ARV-VERIFIER-STATE-OFFICIAL-01',
    verifier_id: 'ARV-VERIFIER-OFFICIAL-01',
    current_state: null,
    expected_current_state_hash: null,
    bootstrap_pins: null,
    recovery_authorization: null,
    trust_root: root,
    checkpoint: checkpointValue,
    manifest: distribution,
    registry_bytes: bytes,
    witness_policy: policy,
    witness_bundle: bundle,
    evaluated_at: `2026-${String(month).padStart(2, '0')}-15T00:00:00Z`,
    updated_at: `2026-${String(month).padStart(2, '0')}-15T00:00:01Z`
  };
}

function pins(data: EvaluateARVVerifierTrustStateOptionsV1): ARVVerifierBootstrapPinsV1 {
  const root = data.trust_root as ARVTrustRootV1;
  const policy = data.witness_policy as ARVCheckpointWitnessPolicyV1;
  const checkpointValue = data.checkpoint as ARVTrustRegistryCheckpointV1;
  return {
    schema: 'arv.verifier-bootstrap-pins',
    schema_version: 1,
    root_id: root.root_id,
    root_version: root.root_version,
    root_epoch: root.epoch,
    root_hash: sha256ARVTrustRootV1(root),
    witness_policy_id: policy.policy_id,
    witness_policy_version: policy.policy_version,
    witness_policy_hash: sha256ARVCheckpointWitnessPolicyForStateV1(policy),
    checkpoint_id: checkpointValue.checkpoint_id,
    checkpoint_hash: sha256ARVTrustRegistryCheckpointV1(checkpointValue),
    checkpoint_sequence: checkpointValue.sequence,
    registry_id: checkpointValue.registry_id,
    registry_version: checkpointValue.registry_version,
    registry_digest: checkpointValue.registry_digest
  };
}

function bootstrap() {
  const data = fixture();
  data.bootstrap_pins = pins(data);
  const result = evaluateARVVerifierTrustStateV1(data);
  if (!result.accepted || result.next_state === null || result.next_state_hash === null) throw new Error('bootstrap fixture failed');
  return { data, result, state: result.next_state, stateHash: result.next_state_hash };
}

function advance(current: ARVVerifierTrustStateV1, policyVersion = 1) {
  const data = fixture(2, current.checkpoint_hash, 1, policyVersion, 2);
  data.current_state = current;
  data.expected_current_state_hash = sha256ARVVerifierTrustStateV1(current);
  return data;
}

function rootTransition(current: ARVTrustRootV1, successor: ARVTrustRootV1) {
  const transition: ARVTrustRootTransitionV1 = {
    schema: 'arv.trust-root-transition',
    schema_version: 1,
    transition_id: 'ARV-ROOT-TRANSITION-RECOVERY-0001',
    transition_type: 'RECOVERY',
    from_root_id: current.root_id,
    from_version: current.root_version,
    from_root_hash: sha256ARVTrustRootV1(current),
    to_root_id: successor.root_id,
    to_version: successor.root_version,
    to_root_hash: sha256ARVTrustRootV1(successor),
    effective_at: '2026-07-01T00:00:00Z',
    compromise_effective_from: '2026-06-15T00:00:00Z',
    reason_code: 'CONFIRMED_KEY_COMPROMISE',
    current_authorizations: [],
    successor_authorizations: []
  };
  const payload = Buffer.from(canonicalARVTrustRootTransitionSigningPayloadV1(transition), 'utf8');
  const sign = (key: RootTestKey) => ({
    algorithm: 'Ed25519' as const,
    key_id: key.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
  });
  transition.current_authorizations = rootKeysV1.slice(0, 2).map(sign);
  transition.successor_authorizations = rootKeysV2.slice(0, 2).map(sign);
  return transition;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('ARV Public verifier trust-state pinning and safe bootstrap', () => {
  test('accepts explicit first-use bootstrap only after the complete Public chain', () => {
    const { result } = bootstrap();
    expect(result.state).toBe('BOOTSTRAP_ACCEPTED');
    expect(result.operation).toBe('BOOTSTRAP');
    expect(result.next_state?.generation).toBe(1);
    expect(result.commit_precondition_hash).toBeNull();
  });

  test('rejects silent trust-on-first-use without explicit bootstrap pins', () => {
    const result = evaluateARVVerifierTrustStateV1(fixture());
    expect(result.state).toBe('BOOTSTRAP_REQUIRED');
    expect(result.codes).toContain('BOOTSTRAP_PINS_REQUIRED');
  });

  test('rejects a mismatched pinned root during bootstrap', () => {
    const data = fixture();
    const bootstrapPins = pins(data);
    bootstrapPins.root_hash = 'a'.repeat(64);
    data.bootstrap_pins = bootstrapPins;
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('BOOTSTRAP_PIN_MISMATCH');
    expect(result.codes).toContain('BOOTSTRAP_ROOT_PIN_MISMATCH');
  });

  test('rejects a mismatched pinned witness policy during bootstrap', () => {
    const data = fixture();
    const bootstrapPins = pins(data);
    bootstrapPins.witness_policy_hash = 'b'.repeat(64);
    data.bootstrap_pins = bootstrapPins;
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.codes).toContain('BOOTSTRAP_POLICY_PIN_MISMATCH');
  });

  test('rejects a mismatched pinned checkpoint during bootstrap', () => {
    const data = fixture();
    const bootstrapPins = pins(data);
    bootstrapPins.checkpoint_hash = 'c'.repeat(64);
    data.bootstrap_pins = bootstrapPins;
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.codes).toContain('BOOTSTRAP_CHECKPOINT_PIN_MISMATCH');
  });

  test('rejects an invalid underlying witness bundle before state creation', () => {
    const data = fixture();
    data.bootstrap_pins = pins(data);
    (data.witness_bundle as ARVCheckpointWitnessBundleV1).observations.pop();
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('UNDERLYING_WITNESS_REJECTED');
    expect(result.next_state).toBeNull();
  });

  test('advances exactly one checkpoint and preserves a hash-linked state chain', () => {
    const { state, stateHash } = bootstrap();
    const result = evaluateARVVerifierTrustStateV1(advance(state));
    expect(result.state).toBe('ADVANCE_ACCEPTED');
    expect(result.next_state?.generation).toBe(2);
    expect(result.next_state?.previous_state_hash).toBe(stateHash);
    expect(result.commit_precondition_hash).toBe(stateHash);
  });

  test('accepts an identical checkpoint as an idempotent replay without changing state hash', () => {
    const { data, state, stateHash } = bootstrap();
    data.current_state = state;
    data.expected_current_state_hash = stateHash;
    data.bootstrap_pins = null;
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('REPLAY_ACCEPTED');
    expect(result.next_state_hash).toBe(stateHash);
    expect(result.next_state?.generation).toBe(1);
  });

  test('rejects an absent compare-and-swap hash for existing state', () => {
    const { state } = bootstrap();
    const data = advance(state);
    data.expected_current_state_hash = null;
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('STATE_HASH_MISMATCH');
    expect(result.codes).toContain('CURRENT_STATE_HASH_REQUIRED');
  });

  test('rejects a stale compare-and-swap hash without producing a commit candidate', () => {
    const { state } = bootstrap();
    const data = advance(state);
    data.expected_current_state_hash = 'd'.repeat(64);
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.codes).toContain('CURRENT_STATE_HASH_MISMATCH');
    expect(result.next_state_hash).toBeNull();
  });

  test('forbids bootstrap pins from replacing an existing state', () => {
    const { state } = bootstrap();
    const data = advance(state);
    data.bootstrap_pins = pins(data);
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('BOOTSTRAP_REUSE_FORBIDDEN');
  });

  test('rejects a verifier identity substitution', () => {
    const { state } = bootstrap();
    const data = advance(state);
    data.verifier_id = 'ARV-VERIFIER-ROGUE-01';
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.codes).toContain('VERIFIER_ID_MISMATCH');
  });

  test('rejects checkpoint rollback across executions', () => {
    const { data, state } = bootstrap();
    const advanced = evaluateARVVerifierTrustStateV1(advance(state));
    const nextState = advanced.next_state!;
    data.current_state = nextState;
    data.expected_current_state_hash = sha256ARVVerifierTrustStateV1(nextState);
    data.bootstrap_pins = null;
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('STATE_ROLLBACK');
    expect(result.codes).toContain('STATE_SEQUENCE_ROLLBACK');
    expect(result.next_state).toBeNull();
  });

  test('rejects a checkpoint sequence gap across executions', () => {
    const { state } = bootstrap();
    const data = fixture(3, state.checkpoint_hash, 1, 1, 3);
    data.current_state = state;
    data.expected_current_state_hash = sha256ARVVerifierTrustStateV1(state);
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('STATE_GAP');
    expect(result.codes).toContain('STATE_SEQUENCE_GAP');
  });

  test('rejects same-version witness policy equivocation', () => {
    const { state } = bootstrap();
    const data = advance(state);
    const policy = data.witness_policy as ARVCheckpointWitnessPolicyV1;
    policy.max_observation_age_seconds += 1;
    const payload = Buffer.from(canonicalARVCheckpointWitnessPolicySigningPayloadV1(policy), 'utf8');
    policy.signatures = rootKeysV1.slice(0, 2).map((key) => ({
      algorithm: 'Ed25519',
      key_id: key.descriptor.key_id,
      signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
    }));
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('POLICY_EQUIVOCATION');
    expect(result.codes).toContain('POLICY_HASH_EQUIVOCATION');
  });

  test('rejects a witness policy version gap', () => {
    const { state } = bootstrap();
    const result = evaluateARVVerifierTrustStateV1(advance(state, 3));
    expect(result.state).toBe('POLICY_GAP');
    expect(result.codes).toContain('POLICY_VERSION_GAP');
  });

  test('requires a Public authorization when the pinned root changes', () => {
    const { state } = bootstrap();
    const data = fixture(1, null, 2, 1, 8);
    data.current_state = state;
    data.expected_current_state_hash = sha256ARVVerifierTrustStateV1(state);
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('ROOT_TRANSITION_REQUIRED');
    expect(result.codes).toContain('RECOVERY_AUTHORIZATION_REQUIRED');
  });

  test('accepts a recovery reset only through a valid preauthorized Public quorum', () => {
    const { state } = bootstrap();
    const data = fixture(1, null, 2, 1, 8);
    const current = trustRoot(1);
    const successor = data.trust_root as ARVTrustRootV1;
    data.current_state = state;
    data.expected_current_state_hash = sha256ARVVerifierTrustStateV1(state);
    data.recovery_authorization = {
      current_root: current,
      transition: rootTransition(current, successor),
      root_checkpoint: {
        root_id: current.root_id,
        root_version: current.root_version,
        epoch: current.epoch,
        root_hash: sha256ARVTrustRootV1(current)
      }
    };
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('RECOVERY_ACCEPTED');
    expect(result.next_state?.recovery_count).toBe(1);
    expect(result.next_state?.previous_state_hash).toBe(sha256ARVVerifierTrustStateV1(state));
  });

  test('rejects a forged Public recovery authorization', () => {
    const { state } = bootstrap();
    const data = fixture(1, null, 2, 1, 8);
    const current = trustRoot(1);
    const successor = data.trust_root as ARVTrustRootV1;
    const transition = rootTransition(current, successor);
    transition.current_authorizations[0].signature_base64 = Buffer.alloc(64).toString('base64');
    data.current_state = state;
    data.expected_current_state_hash = sha256ARVVerifierTrustStateV1(state);
    data.recovery_authorization = {
      current_root: current,
      transition,
      root_checkpoint: {
        root_id: current.root_id,
        root_version: current.root_version,
        epoch: current.epoch,
        root_hash: sha256ARVTrustRootV1(current)
      }
    };
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('ROOT_RECOVERY_INVALID');
    expect(result.next_state).toBeNull();
  });

  test('exports and imports deterministic state only with an external state hash pin', () => {
    const { state, stateHash } = bootstrap();
    const envelope = exportARVVerifierTrustStateV1(state, '2026-01-15T00:00:02Z');
    const serialized = serializeARVVerifierTrustStateEnvelopeV1(envelope);
    expect(importARVVerifierTrustStateV1(serialized, stateHash)).toEqual(state);
    expect(serialized.endsWith('\n')).toBe(true);
  });

  test('rejects a tampered exported state envelope', () => {
    const { state, stateHash } = bootstrap();
    const envelope = exportARVVerifierTrustStateV1(state, '2026-01-15T00:00:02Z');
    const tampered = clone(envelope);
    tampered.state.registry_digest = 'e'.repeat(64);
    expect(() => importARVVerifierTrustStateV1(JSON.stringify(tampered), stateHash)).toThrow('STATE_ENVELOPE_HASH_MISMATCH');
  });

  test('requires the externally pinned hash even for an internally consistent envelope', () => {
    const { state } = bootstrap();
    const envelope = exportARVVerifierTrustStateV1(state, '2026-01-15T00:00:02Z');
    expect(() => importARVVerifierTrustStateV1(JSON.stringify(envelope), 'f'.repeat(64))).toThrow('EXTERNAL_STATE_PIN_REQUIRED');
  });

  test('canonical state bytes are language neutral and stable', () => {
    const { state } = bootstrap();
    const canonical = canonicalARVVerifierTrustStateV1(state);
    expect(canonical.startsWith('ARV-VERIFIER-TRUST-STATE-v1\n')).toBe(true);
    expect(sha256ARVVerifierTrustStateV1(clone(state))).toBe(sha256ARVVerifierTrustStateV1(state));
  });

  test('forbids private key material in persisted state inputs', () => {
    const { state } = bootstrap();
    const data = advance(state) as EvaluateARVVerifierTrustStateOptionsV1 & { private_key?: string };
    data.private_key = 'forbidden';
    const result = evaluateARVVerifierTrustStateV1(data);
    expect(result.state).toBe('PRIVATE_KEY_MATERIAL_FORBIDDEN');
  });

  test('never promotes local state, storage or transport into ARV authority', () => {
    const { result } = bootstrap();
    expect(result.authority_basis).toBe('PINNED_TRUST_ROOT');
    expect(result.local_state_authority).toBe('CONTINUITY_ONLY');
    expect(result.storage_authority).toBe('NONE');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });
});
