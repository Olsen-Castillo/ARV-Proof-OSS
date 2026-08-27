import crypto from 'crypto';
import {
  ARVVerifierActivationPinV1,
  ARVVerifierRuntimeMeasurementV1,
  ARVVerifierRuntimeVerificationV1,
  sha256ARVVerifierActivationPinV1,
  sha256ARVVerifierRuntimeMeasurementV1,
  verifyARVVerifierRuntimeIntegrityV1
} from './verifier-runtime-integrity-v1';
import {
  ARVVerifierRuntimeAttestationPolicyV1,
  ARVVerifierRuntimeAttestationPinV1,
  ARVVerifierRuntimeAttestationV1,
  ARVVerifierSecurityEventChainV1,
  ARVVerifierSecurityEventV1,
  VerifyARVVerifierRuntimeAttestationOptionsV1,
  assertARVVerifierRuntimeAttestationPinV1,
  assertARVVerifierRuntimeAttestationPolicyV1,
  assertARVVerifierRuntimeAttestationV1,
  assertARVVerifierSecurityEventChainV1,
  canonicalARVVerifierRuntimeAttestationSigningBytesV1,
  sha256ARVVerifierRuntimeAttestationPinV1,
  sha256ARVVerifierRuntimeAttestationPolicyV1,
  sha256ARVVerifierSecurityEventChainV1,
  sha256ARVVerifierSecurityEventV1,
  verifyARVVerifierRuntimeAttestationV1
} from './verifier-runtime-attestation-v1';

jest.mock('./verifier-runtime-integrity-v1', () => {
  const actual = jest.requireActual('./verifier-runtime-integrity-v1');
  return { ...actual, verifyARVVerifierRuntimeIntegrityV1: jest.fn() };
});

const mockedRuntimeVerifier = verifyARVVerifierRuntimeIntegrityV1 as jest.MockedFunction<typeof verifyARVVerifierRuntimeIntegrityV1>;
const digest = (value: string) => value.repeat(64).slice(0, 64);

interface Fixture {
  policy: ARVVerifierRuntimeAttestationPolicyV1;
  attestation: ARVVerifierRuntimeAttestationV1;
  chain: ARVVerifierSecurityEventChainV1;
  event: ARVVerifierSecurityEventV1;
  activationPin: ARVVerifierActivationPinV1;
  measurement: ARVVerifierRuntimeMeasurementV1;
  runtimeResult: ARVVerifierRuntimeVerificationV1;
  options: VerifyARVVerifierRuntimeAttestationOptionsV1;
  signingKeys: crypto.KeyObject[];
}

function fixture(): Fixture {
  const signingKeys: crypto.KeyObject[] = [];
  const attestors = ['111111111111111111111111', '222222222222222222222222'].map((keyId, index) => {
    const pair = crypto.generateKeyPairSync('ed25519');
    signingKeys.push(pair.privateKey);
    return {
      attestor_id: `ARV-RUNTIME-ATTESTOR-NODE-${index + 1}`,
      key_id: keyId,
      algorithm: 'Ed25519' as const,
      public_key_spki_base64: (pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64'),
      status: 'ACTIVE' as const,
      valid_from: '2026-01-01T00:00:00Z',
      expires_at: '2028-01-01T00:00:00Z'
    };
  });
  const policy: ARVVerifierRuntimeAttestationPolicyV1 = {
    schema: 'arv.verifier-runtime-attestation-policy', schema_version: 1,
    policy_id: 'ARV-VERIFIER-RUNTIME-ATTESTATION-POLICY-PROD', verifier_id: 'ARV-VERIFIER-PROD', policy_version: 1,
    root_id: 'ARV-ROOT-PROD', root_version: 1, root_epoch: 1, root_hash: digest('a'),
    attestation_threshold: 2, max_attestation_age_seconds: 300, max_clock_skew_seconds: 30,
    allowed_event_types: ['BOOT','DRIFT_DETECTED','INCIDENT_REPORTED','QUARANTINE_ENTERED','QUARANTINE_RELEASED','RUNTIME_CHECK','SHUTDOWN','UPDATE_ACTIVATED'],
    attestors, issued_at: '2026-01-01T00:00:00Z'
  };
  const measurement: ARVVerifierRuntimeMeasurementV1 = {
    schema: 'arv.verifier-runtime-measurement', schema_version: 1,
    measurement_id: 'ARV-VERIFIER-RUNTIME-MEASUREMENT-NODE-1', verifier_id: policy.verifier_id,
    instance_id: 'ARV-VERIFIER-INSTANCE-NODE-1', activation_sequence: 1, installation_hash: digest('b'),
    release_manifest_hash: digest('c'), runtime_profile_hash: digest('d'), observed_artifact_set_digest: digest('e'),
    executable_digest: digest('f'), configuration_digest: digest('1'), policy_bundle_digest: digest('2'),
    schema_bundle_digest: digest('3'), dependency_set_digest: digest('4'), loaded_module_set_digest: digest('5'),
    environment_constraints_digest: digest('6'), measured_at: '2026-02-01T00:00:00Z'
  };
  const activationPin: ARVVerifierActivationPinV1 = {
    schema: 'arv.verifier-activation-pin', schema_version: 1, pin_id: 'ARV-VERIFIER-ACTIVATION-PIN-NODE-1',
    verifier_id: policy.verifier_id, instance_id: measurement.instance_id, generation: 1, activation_sequence: 1,
    release_sequence: 1, release_manifest_hash: measurement.release_manifest_hash, release_pin_hash: digest('7'),
    installation_hash: measurement.installation_hash, runtime_profile_hash: measurement.runtime_profile_hash,
    runtime_baseline_hash: digest('8'), activated_at: '2026-02-01T00:00:10Z', previous_pin_hash: null
  };
  const activationHash = sha256ARVVerifierActivationPinV1(activationPin);
  const measurementHash = sha256ARVVerifierRuntimeMeasurementV1(measurement);
  const event: ARVVerifierSecurityEventV1 = {
    schema: 'arv.verifier-security-event', schema_version: 1, event_id: 'ARV-VERIFIER-SECURITY-EVENT-NODE-1',
    verifier_id: policy.verifier_id, instance_id: measurement.instance_id, event_sequence: 1, event_type: 'BOOT', severity: 'INFO',
    activation_pin_hash: activationHash, runtime_measurement_hash: measurementHash, details_digest: digest('9'),
    observed_at: '2026-02-01T00:01:00Z', previous_event_hash: null
  };
  const chain: ARVVerifierSecurityEventChainV1 = {
    schema: 'arv.verifier-security-event-chain', schema_version: 1, chain_id: 'ARV-VERIFIER-SECURITY-EVENT-CHAIN-NODE-1',
    verifier_id: policy.verifier_id, instance_id: measurement.instance_id, first_event_sequence: 1, last_event_sequence: 1,
    previous_chain_hash: null, events: [event], closed_at: '2026-02-01T00:01:10Z'
  };
  const policyHash = sha256ARVVerifierRuntimeAttestationPolicyV1(policy);
  const attestation: ARVVerifierRuntimeAttestationV1 = {
    schema: 'arv.verifier-runtime-attestation', schema_version: 1,
    attestation_id: 'ARV-VERIFIER-RUNTIME-ATTESTATION-NODE-1', verifier_id: policy.verifier_id,
    instance_id: measurement.instance_id, attestation_sequence: 1, activation_sequence: 1,
    release_manifest_hash: measurement.release_manifest_hash, activation_pin_hash: activationHash,
    runtime_measurement_hash: measurementHash, security_event_chain_hash: sha256ARVVerifierSecurityEventChainV1(chain),
    challenge_nonce: 'ab'.repeat(32), policy_id: policy.policy_id, policy_version: policy.policy_version, policy_hash: policyHash,
    root_id: policy.root_id, root_version: policy.root_version, root_epoch: policy.root_epoch, root_hash: policy.root_hash,
    issued_at: '2026-02-01T00:01:20Z', expires_at: '2026-02-01T00:06:20Z', previous_attestation_hash: null, signatures: []
  };
  sign(attestation, policy, signingKeys);
  const runtimeResult = {
    accepted: true, quarantined: false, state: 'RUNTIME_VERIFIED', operation: 'VERIFY',
    next_activation_pin: activationPin
  } as unknown as ARVVerifierRuntimeVerificationV1;
  const options: VerifyARVVerifierRuntimeAttestationOptionsV1 = {
    runtime_verification_options: { runtime_measurement: measurement } as never,
    attestation_policy: policy, runtime_attestation: attestation, security_event_chain: chain,
    current_attestation_pin: null, expected_current_attestation_pin_hash: null, bootstrap_policy_hash: policyHash,
    expected_challenge_nonce: attestation.challenge_nonce, attestation_pin_id: 'ARV-VERIFIER-RUNTIME-ATTESTATION-PIN-NODE-1',
    evaluated_at: '2026-02-01T00:01:30Z'
  };
  return { policy, attestation, chain, event, activationPin, measurement, runtimeResult, options, signingKeys };
}

function sign(attestation: ARVVerifierRuntimeAttestationV1, policy: ARVVerifierRuntimeAttestationPolicyV1, keys: crypto.KeyObject[]): void {
  attestation.signatures = [];
  const bytes = canonicalARVVerifierRuntimeAttestationSigningBytesV1(attestation);
  attestation.signatures = policy.attestors.map((attestor, index) => ({
    algorithm: 'Ed25519', key_id: attestor.key_id, signature_base64: crypto.sign(null, bytes, keys[index]).toString('base64')
  }));
}

beforeEach(() => mockedRuntimeVerifier.mockReset());

describe('ARV Public official verifier runtime attestation and security-event evidence', () => {
  test('accepts a challenge-bound, threshold-signed bootstrap attestation', () => {
    const value = fixture(); mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    const result = verifyARVVerifierRuntimeAttestationV1(value.options);
    expect(result.accepted).toBe(true); expect(result.quarantined).toBe(false);
    expect(result.state).toBe('BOOTSTRAP_ACCEPTED'); expect(result.valid_attestation_signatures).toBe(2);
    expect(result.next_attestation_pin?.last_event_hash).toBe(sha256ARVVerifierSecurityEventV1(value.event));
  });

  test('accepts an exact replay idempotently', () => {
    const value = fixture(); mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    const first = verifyARVVerifierRuntimeAttestationV1(value.options);
    const pin = first.next_attestation_pin as ARVVerifierRuntimeAttestationPinV1;
    value.options.current_attestation_pin = pin; value.options.expected_current_attestation_pin_hash = sha256ARVVerifierRuntimeAttestationPinV1(pin); value.options.bootstrap_policy_hash = null;
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('REPLAY_ACCEPTED');
  });

  test('accepts a continuous update and advances both chains atomically', () => {
    const value = fixture(); mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    const first = verifyARVVerifierRuntimeAttestationV1(value.options);
    const pin = first.next_attestation_pin as ARVVerifierRuntimeAttestationPinV1;
    const nextEvent: ARVVerifierSecurityEventV1 = { ...value.event, event_id: 'ARV-VERIFIER-SECURITY-EVENT-NODE-2', event_sequence: 2, event_type: 'RUNTIME_CHECK', previous_event_hash: pin.last_event_hash, observed_at: '2026-02-01T00:02:00Z' };
    value.chain = { ...value.chain, chain_id: 'ARV-VERIFIER-SECURITY-EVENT-CHAIN-NODE-2', first_event_sequence: 2, last_event_sequence: 2, previous_chain_hash: pin.security_event_chain_hash, events: [nextEvent], closed_at: '2026-02-01T00:02:10Z' };
    value.attestation = { ...value.attestation, attestation_id: 'ARV-VERIFIER-RUNTIME-ATTESTATION-NODE-2', attestation_sequence: 2, previous_attestation_hash: pin.attestation_hash, security_event_chain_hash: sha256ARVVerifierSecurityEventChainV1(value.chain), issued_at: '2026-02-01T00:02:20Z', expires_at: '2026-02-01T00:07:20Z', signatures: [] };
    sign(value.attestation, value.policy, value.signingKeys);
    Object.assign(value.options, { runtime_attestation: value.attestation, security_event_chain: value.chain, current_attestation_pin: pin, expected_current_attestation_pin_hash: sha256ARVVerifierRuntimeAttestationPinV1(pin), bootstrap_policy_hash: null, evaluated_at: '2026-02-01T00:02:30Z' });
    const updated = verifyARVVerifierRuntimeAttestationV1(value.options);
    expect(updated.state).toBe('UPDATE_ACCEPTED'); expect(updated.next_attestation_pin?.generation).toBe(2);
  });

  test('fails closed if Public does not accept the measured runtime', () => {
    const value = fixture(); mockedRuntimeVerifier.mockReturnValue({ ...value.runtimeResult, accepted: false, quarantined: true });
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('RUNTIME_REJECTED');
  });

  test('rejects silent trust-on-first-use without an explicit policy pin', () => {
    const value = fixture(); value.options.bootstrap_policy_hash = null; mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('POLICY_PIN_REQUIRED');
  });

  test('rejects challenge replay under another relying-party nonce', () => {
    const value = fixture(); value.options.expected_challenge_nonce = 'cd'.repeat(32); mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('CHALLENGE_MISMATCH');
  });

  test('rejects a signature set below the root-authorized threshold', () => {
    const value = fixture(); value.attestation.signatures = value.attestation.signatures.slice(0, 1); value.options.runtime_attestation = value.attestation; mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('SIGNATURE_QUORUM_NOT_MET');
  });

  test('rejects stale runtime attestations even when signatures are valid', () => {
    const value = fixture(); value.options.evaluated_at = '2026-02-01T01:01:30Z'; mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('ATTESTATION_TIME_INVALID');
  });

  test('rejects event sequence gaps', () => {
    const value = fixture();
    const skipped: ARVVerifierSecurityEventV1 = { ...value.event, event_id: 'ARV-VERIFIER-SECURITY-EVENT-NODE-3', event_sequence: 3, previous_event_hash: sha256ARVVerifierSecurityEventV1(value.event) };
    value.chain.last_event_sequence = 3; value.chain.events = [value.event, skipped];
    value.attestation.security_event_chain_hash = sha256ARVVerifierSecurityEventChainV1(value.chain); sign(value.attestation, value.policy, value.signingKeys);
    value.options.security_event_chain = value.chain; value.options.runtime_attestation = value.attestation; mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('EVENT_CHAIN_GAP');
  });

  test('rejects same-sequence attestation equivocation', () => {
    const value = fixture(); mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    const first = verifyARVVerifierRuntimeAttestationV1(value.options); const pin = first.next_attestation_pin as ARVVerifierRuntimeAttestationPinV1;
    value.attestation.challenge_nonce = 'cd'.repeat(32); value.options.expected_challenge_nonce = value.attestation.challenge_nonce; sign(value.attestation, value.policy, value.signingKeys);
    Object.assign(value.options, { runtime_attestation: value.attestation, current_attestation_pin: pin, expected_current_attestation_pin_hash: sha256ARVVerifierRuntimeAttestationPinV1(pin), bootstrap_policy_hash: null });
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('ATTESTATION_EQUIVOCATION');
  });

  test('rejects any private-key-shaped material in verification input', () => {
    const value = fixture(); (value.options as unknown as Record<string, unknown>).private_key = 'forbidden'; mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
    expect(verifyARVVerifierRuntimeAttestationV1(value.options).state).toBe('PRIVATE_KEY_MATERIAL_FORBIDDEN');
  });

  test('strict assertions and domain-separated hashes are deterministic', () => {
    const value = fixture();
    expect(assertARVVerifierRuntimeAttestationPolicyV1(value.policy)).toEqual(value.policy);
    expect(assertARVVerifierRuntimeAttestationV1(value.attestation)).toEqual(value.attestation);
    expect(assertARVVerifierSecurityEventChainV1(value.chain)).toEqual(value.chain);
    const pin = verifyWithRuntime(value).next_attestation_pin as ARVVerifierRuntimeAttestationPinV1;
    expect(assertARVVerifierRuntimeAttestationPinV1(pin)).toEqual(pin);
    expect(sha256ARVVerifierRuntimeAttestationPinV1(pin)).toMatch(/^[a-f0-9]{64}$/);
  });
});

function verifyWithRuntime(value: Fixture) {
  mockedRuntimeVerifier.mockReturnValue(value.runtimeResult);
  return verifyARVVerifierRuntimeAttestationV1(value.options);
}
