import crypto from 'crypto';
import nacl from 'tweetnacl';
import {
  ARVTrustRootKeyV1,
  ARVTrustRootTransitionV1,
  ARVTrustRootV1,
  assertARVTrustRootV1,
  canonicalARVTrustRootTransitionSigningPayloadV1,
  fingerprintARVTrustRootPublicKeyV1,
  sha256ARVTrustRootV1,
  verifyARVTrustRootTransitionV1
} from './trust-root-lifecycle-v1';

interface TestKey {
  descriptor: ARVTrustRootKeyV1;
  secret_key: Uint8Array;
}

function testKey(label: string, roles: Array<'ROOT' | 'RECOVERY'>): TestKey {
  const seed = crypto.createHash('sha256').update(`ARV-PUBLIC-TEST:${label}`).digest();
  const pair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
  return {
    descriptor: {
      key_id: fingerprintARVTrustRootPublicKeyV1(pair.publicKey),
      algorithm: 'Ed25519',
      public_key_base64: Buffer.from(pair.publicKey).toString('base64'),
      roles,
      status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: null
    },
    secret_key: pair.secretKey
  };
}

const currentKeys = [
  testKey('CURRENT-ROOT-1', ['ROOT']),
  testKey('CURRENT-ROOT-2', ['ROOT']),
  testKey('CURRENT-RECOVERY-1', ['RECOVERY']),
  testKey('CURRENT-RECOVERY-2', ['RECOVERY'])
];

const successorKeys = [
  testKey('SUCCESSOR-ROOT-1', ['ROOT']),
  testKey('SUCCESSOR-ROOT-2', ['ROOT']),
  testKey('SUCCESSOR-RECOVERY-1', ['RECOVERY']),
  testKey('SUCCESSOR-RECOVERY-2', ['RECOVERY'])
];

function policyDigest(label: string): string {
  return crypto.createHash('sha256').update(label).digest('hex');
}

function currentRoot(): ARVTrustRootV1 {
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
    recovery_threshold: 2,
    previous_root_hash: null,
    policy_digest: policyDigest('ARV-PUBLIC-POLICY-V1'),
    keys: currentKeys.map((key) => key.descriptor)
  };
}

function successorRoot(current: ARVTrustRootV1): ARVTrustRootV1 {
  return {
    schema: 'arv.trust-root',
    schema_version: 1,
    root_id: current.root_id,
    root_version: 2,
    epoch: 2,
    issued_at: '2026-06-01T00:00:00Z',
    valid_from: '2026-07-01T00:00:00Z',
    expires_at: '2029-07-01T00:00:00Z',
    threshold: 2,
    recovery_threshold: 2,
    previous_root_hash: sha256ARVTrustRootV1(current),
    policy_digest: policyDigest('ARV-PUBLIC-POLICY-V1'),
    keys: successorKeys.map((key) => key.descriptor)
  };
}

function transition(
  current: ARVTrustRootV1,
  successor: ARVTrustRootV1,
  type: 'ROTATION' | 'RECOVERY' = 'ROTATION'
): ARVTrustRootTransitionV1 {
  return {
    schema: 'arv.trust-root-transition',
    schema_version: 1,
    transition_id: `ARV-ROOT-TRANSITION-${type}-0001`,
    transition_type: type,
    from_root_id: current.root_id,
    from_version: current.root_version,
    from_root_hash: sha256ARVTrustRootV1(current),
    to_root_id: successor.root_id,
    to_version: successor.root_version,
    to_root_hash: sha256ARVTrustRootV1(successor),
    effective_at: '2026-07-01T00:00:00Z',
    compromise_effective_from: type === 'RECOVERY' ? '2026-06-15T00:00:00Z' : null,
    reason_code: type === 'RECOVERY' ? 'CONFIRMED_KEY_COMPROMISE' : 'SCHEDULED_ROTATION',
    current_authorizations: [],
    successor_authorizations: []
  };
}

function authorize(
  candidate: ARVTrustRootTransitionV1,
  currentSigners: TestKey[],
  successorSigners: TestKey[]
): ARVTrustRootTransitionV1 {
  const payload = Buffer.from(canonicalARVTrustRootTransitionSigningPayloadV1(candidate), 'utf8');
  const sign = (key: TestKey) => ({
    algorithm: 'Ed25519' as const,
    key_id: key.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(payload, key.secret_key)).toString('base64')
  });
  return {
    ...candidate,
    current_authorizations: currentSigners.map(sign),
    successor_authorizations: successorSigners.map(sign)
  };
}

function fixture(type: 'ROTATION' | 'RECOVERY' = 'ROTATION') {
  const current = currentRoot();
  const successor = successorRoot(current);
  const currentSigners = type === 'RECOVERY' ? currentKeys.slice(2, 4) : currentKeys.slice(0, 2);
  const signed = authorize(transition(current, successor, type), currentSigners, successorKeys.slice(0, 2));
  return {
    current_root: current,
    successor_root: successor,
    transition: signed,
    checkpoint: {
      root_id: current.root_id,
      root_version: current.root_version,
      epoch: current.epoch,
      root_hash: sha256ARVTrustRootV1(current)
    },
    evaluated_at: '2026-08-01T00:00:00Z'
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('ARV Public official trust-root lifecycle', () => {
  test('accepts a threshold-authorized ordinary rotation', () => {
    const result = verifyARVTrustRootTransitionV1(fixture());
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('ROOT_VALID');
    expect(result.trusted_root_version).toBe(2);
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });

  test('canonical signing bytes do not depend on authorization order or language', () => {
    const data = fixture();
    const first = canonicalARVTrustRootTransitionSigningPayloadV1(data.transition);
    const reordered = {
      ...data.transition,
      current_authorizations: [...data.transition.current_authorizations].reverse(),
      successor_authorizations: [...data.transition.successor_authorizations].reverse()
    };
    expect(canonicalARVTrustRootTransitionSigningPayloadV1(reordered)).toBe(first);
    expect(first.startsWith('ARV-TRUST-ROOT-TRANSITION-v1\n')).toBe(true);
  });

  test('rejects a root below the trusted checkpoint as rollback', () => {
    const data = fixture();
    data.checkpoint.root_version = 2;
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('ROOT_ROLLBACK');
    expect(result.codes).toContain('ROOT_VERSION_ROLLBACK');
  });

  test('rejects a different hash at the trusted version as equivocation', () => {
    const data = fixture();
    data.checkpoint.root_hash = 'f'.repeat(64);
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('ROOT_EQUIVOCATION');
    expect(result.codes).toContain('ROOT_EQUIVOCATION_DETECTED');
  });

  test('rejects version and epoch gaps', () => {
    const data = fixture();
    data.successor_root.root_version = 3;
    data.successor_root.epoch = 3;
    data.transition.to_version = 3;
    data.transition.to_root_hash = sha256ARVTrustRootV1(data.successor_root);
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('UNTRUSTED_SUCCESSOR');
    expect(result.codes).toContain('ROOT_CHAIN_GAP');
  });

  test('rejects a successor not bound to the trusted predecessor', () => {
    const data = fixture();
    data.successor_root.previous_root_hash = 'a'.repeat(64);
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('UNTRUSTED_SUCCESSOR');
    expect(result.codes).toContain('ROOT_CHAIN_MISMATCH');
  });

  test('rejects transition hash mismatch as equivocation', () => {
    const data = fixture();
    data.transition.to_root_hash = 'b'.repeat(64);
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('ROOT_EQUIVOCATION');
    expect(result.codes).toContain('TRANSITION_HASH_MISMATCH');
  });

  test('rejects insufficient authorization from the current root', () => {
    const data = fixture();
    data.transition.current_authorizations.pop();
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('INSUFFICIENT_THRESHOLD');
    expect(result.codes).toContain('CURRENT_THRESHOLD_NOT_MET');
  });

  test('rejects insufficient proof of possession by the successor root', () => {
    const data = fixture();
    data.transition.successor_authorizations.pop();
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('INSUFFICIENT_THRESHOLD');
    expect(result.codes).toContain('SUCCESSOR_THRESHOLD_NOT_MET');
  });

  test('rejects an invalid signature even when other signatures meet threshold', () => {
    const data = fixture();
    const invalid = clone(data.transition.current_authorizations[0]);
    invalid.key_id = currentKeys[2].descriptor.key_id;
    invalid.signature_base64 = Buffer.alloc(nacl.sign.signatureLength).toString('base64');
    data.transition.current_authorizations.push(invalid);
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('ROOT_INVALID');
    expect(result.codes).toContain('SIGNATURE_INVALID');
  });

  test('accepts compromise recovery only through pre-authorized recovery quorum', () => {
    const result = verifyARVTrustRootTransitionV1(fixture('RECOVERY'));
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('RECOVERY_VALID');
  });

  test('requires compromise_effective_from for recovery', () => {
    const data = fixture('RECOVERY');
    data.transition.compromise_effective_from = null;
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('COMPROMISE_RECOVERY_REQUIRED');
    expect(result.codes).toContain('COMPROMISE_EFFECTIVE_FROM_REQUIRED');
  });

  test('does not accept ordinary ROOT signatures as recovery authority', () => {
    const data = fixture('RECOVERY');
    data.transition = authorize(
      transition(data.current_root, data.successor_root, 'RECOVERY'),
      currentKeys.slice(0, 2),
      successorKeys.slice(0, 2)
    );
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('INSUFFICIENT_THRESHOLD');
    expect(result.codes).toContain('RECOVERY_THRESHOLD_NOT_MET');
  });

  test('rejects an expired successor and therefore detects freeze', () => {
    const data = fixture();
    data.evaluated_at = '2030-01-01T00:00:00Z';
    const result = verifyARVTrustRootTransitionV1(data);
    expect(result.state).toBe('ROOT_EXPIRED');
    expect(result.codes).toContain('ROOT_EXPIRED_AT_EVALUATION');
  });

  test('forbids private material in root documents', () => {
    const root = clone(currentRoot()) as ARVTrustRootV1 & { private_key?: string };
    root.private_key = 'forbidden';
    expect(() => assertARVTrustRootV1(root)).toThrow('PRIVATE_KEY_MATERIAL_FORBIDDEN');
  });
});
