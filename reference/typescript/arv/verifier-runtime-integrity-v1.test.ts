import {
  ARVVerifierReleaseManifestV1,
  ARVVerifierReleasePinV1,
  ARVVerifierReleaseVerificationV1,
  sha256ARVVerifierArtifactSetV1,
  sha256ARVVerifierReleaseManifestV1,
  sha256ARVVerifierReleasePinV1,
  verifyARVVerifierReleaseV1
} from './verifier-release-attestation-v1';
import {
  ARVVerifierActivationPinV1,
  ARVVerifierInstallationEvidenceV1,
  ARVVerifierRuntimeMeasurementV1,
  ARVVerifierRuntimeProfileV1,
  VerifyARVVerifierRuntimeOptionsV1,
  assertARVVerifierActivationPinV1,
  assertARVVerifierInstallationEvidenceV1,
  assertARVVerifierRuntimeMeasurementV1,
  assertARVVerifierRuntimeProfileV1,
  sha256ARVVerifierActivationPinV1,
  sha256ARVVerifierInstallationEvidenceV1,
  sha256ARVVerifierRuntimeMeasurementV1,
  sha256ARVVerifierRuntimeProfileV1,
  verifyARVVerifierRuntimeIntegrityV1
} from './verifier-runtime-integrity-v1';

jest.mock('./verifier-release-attestation-v1', () => {
  const actual = jest.requireActual('./verifier-release-attestation-v1');
  return { ...actual, verifyARVVerifierReleaseV1: jest.fn() };
});

const mockedReleaseVerifier = verifyARVVerifierReleaseV1 as jest.MockedFunction<typeof verifyARVVerifierReleaseV1>;
const digest = (value: string) => value.repeat(64).slice(0, 64);
const signature = Buffer.alloc(64, 7).toString('base64');
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

interface Fixture {
  profile: ARVVerifierRuntimeProfileV1;
  manifest: ARVVerifierReleaseManifestV1;
  releasePin: ARVVerifierReleasePinV1;
  installation: ARVVerifierInstallationEvidenceV1;
  measurement: ARVVerifierRuntimeMeasurementV1;
  options: VerifyARVVerifierRuntimeOptionsV1;
  releaseResult: ARVVerifierReleaseVerificationV1;
}

function fixture(): Fixture {
  const profile: ARVVerifierRuntimeProfileV1 = {
    schema: 'arv.verifier-runtime-profile',
    schema_version: 1,
    profile_id: 'ARV-VERIFIER-RUNTIME-PROFILE-PROD-1',
    verifier_id: 'ARV-VERIFIER-PROD',
    release_sequence: 1,
    platform: 'win32-x64',
    executable_path: 'bin/arv-verifier.exe',
    required_artifact_paths: ['bin/arv-verifier.exe', 'runtime/profile.json'],
    executable_digest: digest('a'),
    configuration_digest: digest('b'),
    policy_bundle_digest: digest('c'),
    schema_bundle_digest: digest('d'),
    dependency_set_digest: digest('e'),
    allowed_module_set_digest: digest('f'),
    environment_constraints_digest: digest('1')
  };
  const profileHash = sha256ARVVerifierRuntimeProfileV1(profile);
  const artifacts = [
    { path: 'bin/arv-verifier.exe', media_type: 'application/octet-stream', bytes: 4096, sha256: profile.executable_digest },
    { path: 'runtime/profile.json', media_type: 'application/json', bytes: 2048, sha256: profileHash }
  ];
  const manifest: ARVVerifierReleaseManifestV1 = {
    schema: 'arv.verifier-release-manifest',
    schema_version: 1,
    manifest_id: 'ARV-VERIFIER-RELEASE-MANIFEST-PROD-1',
    verifier_id: profile.verifier_id,
    release_sequence: 1,
    release_version: '1.0.0',
    channel: 'STABLE',
    platform: profile.platform,
    source_commit: '1'.repeat(40),
    source_tree_digest: digest('2'),
    build_recipe_digest: digest('3'),
    toolchain_digest: digest('4'),
    sbom_digest: digest('5'),
    artifact_set_digest: sha256ARVVerifierArtifactSetV1(artifacts),
    artifacts,
    policy_id: 'ARV-VERIFIER-RELEASE-POLICY-PROD',
    policy_version: 1,
    policy_hash: digest('6'),
    root_id: 'ARV-ROOT-PROD',
    root_version: 1,
    root_epoch: 1,
    root_hash: digest('7'),
    previous_release_hash: null,
    issued_at: '2026-01-01T00:00:00Z',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2028-01-01T00:00:00Z',
    signatures: [{ algorithm: 'Ed25519', key_id: '1'.repeat(24), signature_base64: signature }]
  };
  const manifestHash = sha256ARVVerifierReleaseManifestV1(manifest);
  const releasePin: ARVVerifierReleasePinV1 = {
    schema: 'arv.verifier-release-pin',
    schema_version: 1,
    pin_id: 'ARV-VERIFIER-RELEASE-PIN-PROD',
    verifier_id: profile.verifier_id,
    generation: 1,
    release_sequence: 1,
    release_version: '1.0.0',
    manifest_id: manifest.manifest_id,
    manifest_hash: manifestHash,
    policy_id: manifest.policy_id,
    policy_version: 1,
    policy_hash: manifest.policy_hash,
    trusted_state_hash: digest('8'),
    installed_at: '2026-02-01T00:00:00Z',
    previous_pin_hash: null
  };
  const releasePinHash = sha256ARVVerifierReleasePinV1(releasePin);
  const installation: ARVVerifierInstallationEvidenceV1 = {
    schema: 'arv.verifier-installation-evidence',
    schema_version: 1,
    installation_id: 'ARV-VERIFIER-INSTALLATION-PROD-1',
    verifier_id: profile.verifier_id,
    instance_id: 'ARV-VERIFIER-INSTANCE-NODE-1',
    activation_sequence: 1,
    release_sequence: 1,
    release_version: '1.0.0',
    release_manifest_hash: manifestHash,
    release_pin_hash: releasePinHash,
    runtime_profile_path: 'runtime/profile.json',
    runtime_profile_hash: profileHash,
    observed_artifact_set_digest: manifest.artifact_set_digest,
    observed_artifacts: clone(artifacts),
    installed_at: '2026-02-01T00:00:00Z'
  };
  const installationHash = sha256ARVVerifierInstallationEvidenceV1(installation);
  const measurement: ARVVerifierRuntimeMeasurementV1 = {
    schema: 'arv.verifier-runtime-measurement',
    schema_version: 1,
    measurement_id: 'ARV-VERIFIER-RUNTIME-MEASUREMENT-NODE-1',
    verifier_id: profile.verifier_id,
    instance_id: installation.instance_id,
    activation_sequence: 1,
    installation_hash: installationHash,
    release_manifest_hash: manifestHash,
    runtime_profile_hash: profileHash,
    observed_artifact_set_digest: installation.observed_artifact_set_digest,
    executable_digest: profile.executable_digest,
    configuration_digest: profile.configuration_digest,
    policy_bundle_digest: profile.policy_bundle_digest,
    schema_bundle_digest: profile.schema_bundle_digest,
    dependency_set_digest: profile.dependency_set_digest,
    loaded_module_set_digest: profile.allowed_module_set_digest,
    environment_constraints_digest: profile.environment_constraints_digest,
    measured_at: '2026-02-01T00:01:00Z'
  };
  const releaseResult: ARVVerifierReleaseVerificationV1 = {
    schema: 'arv.verifier-release-verification', schema_version: 1, accepted: true,
    state: 'BOOTSTRAP_ACCEPTED', operation: 'BOOTSTRAP', trusted_state_hash: digest('8'),
    current_pin_hash: null, commit_precondition_hash: null, manifest_hash: manifestHash,
    next_pin_hash: releasePinHash, next_pin: releasePin, valid_builder_attestations: 2, codes: [],
    authority_basis: 'PINNED_VERIFIER_TRUST_STATE', release_authority: 'ROOT_AUTHORIZED_RELEASE_POLICY',
    build_authority: 'INDEPENDENT_ATTESTATION_ONLY', storage_authority: 'NONE', transport_authority: 'NONE',
    material_truth: 'NOT_EVALUATED'
  };
  const options: VerifyARVVerifierRuntimeOptionsV1 = {
    release_verification_options: { release_manifest: manifest } as never,
    runtime_profile: profile,
    installation_evidence: installation,
    runtime_measurement: measurement,
    current_activation_pin: null,
    expected_current_activation_pin_hash: null,
    bootstrap_installation_hash: installationHash,
    activation_pin_id: 'ARV-VERIFIER-ACTIVATION-PIN-NODE-1',
    activated_at: '2026-02-01T00:02:00Z',
    evaluated_at: '2026-02-01T00:02:00Z'
  };
  return { profile, manifest, releasePin, installation, measurement, options, releaseResult };
}

beforeEach(() => mockedReleaseVerifier.mockReset());

describe('ARV Public verifier installation activation and runtime integrity', () => {
  test('accepts a Public-authorized measured bootstrap activation', () => {
    const value = fixture();
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(result.accepted).toBe(true);
    expect(result.quarantined).toBe(false);
    expect(result.state).toBe('BOOTSTRAP_ACTIVATED');
    expect(result.operation).toBe('BOOTSTRAP');
    expect(result.next_activation_pin?.generation).toBe(1);
  });

  test('accepts an exact replay idempotently', () => {
    const value = fixture();
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const first = verifyARVVerifierRuntimeIntegrityV1(value.options);
    const pin = first.next_activation_pin as ARVVerifierActivationPinV1;
    const pinHash = sha256ARVVerifierActivationPinV1(pin);
    value.releaseResult.operation = 'REPLAY';
    value.releaseResult.state = 'REPLAY_ACCEPTED';
    value.releaseResult.next_pin = null;
    value.releaseResult.next_pin_hash = null;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    value.options.release_verification_options.current_release_pin = value.releasePin;
    value.options.current_activation_pin = pin;
    value.options.expected_current_activation_pin_hash = pinHash;
    value.options.bootstrap_installation_hash = null;
    const replay = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(replay.state).toBe('REPLAY_VERIFIED');
    expect(replay.operation).toBe('REPLAY');
    expect(replay.next_activation_pin).toBeNull();
  });

  test('fails closed when Public rejects the release', () => {
    const value = fixture();
    mockedReleaseVerifier.mockReturnValue({ ...value.releaseResult, accepted: false, state: 'MANIFEST_UNAUTHORIZED', operation: 'NONE' });
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(result.state).toBe('RELEASE_REJECTED');
    expect(result.quarantined).toBe(true);
  });

  test('requires an explicitly pinned bootstrap installation hash', () => {
    const value = fixture();
    value.options.bootstrap_installation_hash = null;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(result.state).toBe('BOOTSTRAP_PIN_REQUIRED');
  });

  test('rejects a mismatched bootstrap installation hash', () => {
    const value = fixture();
    value.options.bootstrap_installation_hash = digest('9');
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('BOOTSTRAP_PIN_MISMATCH');
  });

  test('requires the runtime profile to be an artifact signed by Public', () => {
    const value = fixture();
    value.installation.runtime_profile_path = 'runtime/missing.json';
    value.options.installation_evidence = value.installation;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('RUNTIME_PROFILE_UNSIGNED');
  });

  test('rejects profile digest substitution', () => {
    const value = fixture();
    value.manifest.artifacts[1].sha256 = digest('9');
    value.manifest.artifact_set_digest = sha256ARVVerifierArtifactSetV1(value.manifest.artifacts);
    value.releaseResult.manifest_hash = sha256ARVVerifierReleaseManifestV1(value.manifest);
    value.options.release_verification_options.release_manifest = value.manifest;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('RUNTIME_PROFILE_UNSIGNED');
  });

  test('rejects an observed artifact-set mismatch', () => {
    const value = fixture();
    value.installation.observed_artifacts[0].sha256 = digest('9');
    value.options.installation_evidence = value.installation;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(result.state).toBe('INSTALLATION_ARTIFACT_MISMATCH');
  });

  test.each([
    ['executable_digest', 'RUNTIME_EXECUTABLE_DIGEST_MISMATCH'],
    ['configuration_digest', 'RUNTIME_CONFIGURATION_DIGEST_MISMATCH'],
    ['policy_bundle_digest', 'RUNTIME_POLICY_BUNDLE_DIGEST_MISMATCH'],
    ['schema_bundle_digest', 'RUNTIME_SCHEMA_BUNDLE_DIGEST_MISMATCH'],
    ['dependency_set_digest', 'RUNTIME_DEPENDENCY_SET_DIGEST_MISMATCH'],
    ['loaded_module_set_digest', 'RUNTIME_MODULE_SET_DIGEST_MISMATCH'],
    ['environment_constraints_digest', 'RUNTIME_ENVIRONMENT_DIGEST_MISMATCH']
  ])('quarantines runtime drift in %s', (field, code) => {
    const value = fixture();
    (value.measurement as unknown as Record<string, unknown>)[field] = digest('9');
    value.options.runtime_measurement = value.measurement;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(result.state).toBe('RUNTIME_DRIFT_DETECTED');
    expect(result.codes).toContain(code);
    expect(result.quarantined).toBe(true);
  });

  test('rejects measurement binding to another installation', () => {
    const value = fixture();
    value.measurement.installation_hash = digest('9');
    value.options.runtime_measurement = value.measurement;
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).codes).toContain('RUNTIME_MEASUREMENT_BINDING_MISMATCH');
  });

  test('rejects a missing current activation pin when a CAS precondition exists', () => {
    const value = fixture();
    value.options.expected_current_activation_pin_hash = digest('9');
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('CURRENT_ACTIVATION_PIN_REQUIRED');
  });

  test('rejects an activation-pin CAS mismatch', () => {
    const value = fixture();
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const first = verifyARVVerifierRuntimeIntegrityV1(value.options);
    value.options.current_activation_pin = first.next_activation_pin;
    value.options.expected_current_activation_pin_hash = digest('9');
    value.options.bootstrap_installation_hash = null;
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('CURRENT_ACTIVATION_PIN_HASH_MISMATCH');
  });

  test('rejects activation rollback, gaps and same-sequence equivocation', () => {
    const value = fixture();
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const first = verifyARVVerifierRuntimeIntegrityV1(value.options);
    const pin = first.next_activation_pin as ARVVerifierActivationPinV1;
    const pinHash = sha256ARVVerifierActivationPinV1(pin);
    value.options.current_activation_pin = pin;
    value.options.expected_current_activation_pin_hash = pinHash;
    value.options.bootstrap_installation_hash = null;

    const rollback = clone(value.installation);
    rollback.activation_sequence = 1;
    const equivocation = clone(rollback);
    equivocation.installation_id = 'ARV-VERIFIER-INSTALLATION-PROD-EQUIVOCATION';
    value.options.installation_evidence = equivocation;
    value.measurement.installation_hash = sha256ARVVerifierInstallationEvidenceV1(equivocation);
    value.options.runtime_measurement = value.measurement;
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('ACTIVATION_EQUIVOCATION');

    const gap = clone(value.installation);
    gap.activation_sequence = 3;
    value.options.installation_evidence = gap;
    value.measurement.activation_sequence = 3;
    value.measurement.installation_hash = sha256ARVVerifierInstallationEvidenceV1(gap);
    value.options.runtime_measurement = value.measurement;
    expect(verifyARVVerifierRuntimeIntegrityV1(value.options).state).toBe('ACTIVATION_GAP');
  });

  test('rejects private-key material anywhere in the request', () => {
    const value = fixture();
    (value.options as unknown as Record<string, unknown>).private_key = 'forbidden';
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    expect(result.state).toBe('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    expect(result.quarantined).toBe(true);
  });

  test('assertions and domain-separated hashes are deterministic', () => {
    const value = fixture();
    expect(assertARVVerifierRuntimeProfileV1(value.profile)).toEqual(value.profile);
    expect(assertARVVerifierInstallationEvidenceV1(value.installation)).toEqual(value.installation);
    expect(assertARVVerifierRuntimeMeasurementV1(value.measurement)).toEqual(value.measurement);
    expect(sha256ARVVerifierRuntimeProfileV1(value.profile)).toHaveLength(64);
    expect(sha256ARVVerifierInstallationEvidenceV1(value.installation)).toHaveLength(64);
    expect(sha256ARVVerifierRuntimeMeasurementV1(value.measurement)).toHaveLength(64);
  });

  test('activation pins enforce predecessor continuity', () => {
    const value = fixture();
    mockedReleaseVerifier.mockReturnValue(value.releaseResult);
    const result = verifyARVVerifierRuntimeIntegrityV1(value.options);
    const pin = result.next_activation_pin as ARVVerifierActivationPinV1;
    expect(assertARVVerifierActivationPinV1(pin)).toEqual(pin);
    expect(() => assertARVVerifierActivationPinV1({ ...pin, generation: 2, previous_pin_hash: null })).toThrow();
  });
});
