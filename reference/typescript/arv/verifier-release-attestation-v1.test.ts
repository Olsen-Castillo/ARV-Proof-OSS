import crypto from 'crypto';
import nacl from 'tweetnacl';
import {
  ARVTrustRootKeyV1,
  ARVTrustRootV1,
  fingerprintARVTrustRootPublicKeyV1,
  sha256ARVTrustRootV1
} from './trust-root-lifecycle-v1';
import {
  ARVVerifierTrustStateV1,
  sha256ARVVerifierTrustStateV1
} from './verifier-trust-state-v1';
import {
  ARVVerifierBuildAttestationV1,
  ARVVerifierReleaseAuthorizationPolicyV1,
  ARVVerifierReleaseManifestV1,
  ARVVerifierReleasePinV1,
  ARVVerifierReleasePublicKeyV1,
  VerifyARVVerifierReleaseOptionsV1,
  canonicalARVVerifierBuildAttestationSigningPayloadV1,
  canonicalARVVerifierReleaseManifestSigningPayloadV1,
  canonicalARVVerifierReleasePolicySigningPayloadV1,
  sha256ARVVerifierArtifactSetV1,
  sha256ARVVerifierReleaseManifestV1,
  sha256ARVVerifierReleasePinV1,
  sha256ARVVerifierReleasePolicyV1,
  verifyARVVerifierReleaseV1
} from './verifier-release-attestation-v1';

interface TestKey {
  descriptor: ARVVerifierReleasePublicKeyV1;
  secret: Uint8Array;
}

function key(label: string): TestKey {
  const seed = crypto.createHash('sha256').update(`ARV-PUBLIC-TEST:${label}`).digest();
  const pair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
  return {
    descriptor: {
      key_id: fingerprintARVTrustRootPublicKeyV1(pair.publicKey),
      algorithm: 'Ed25519',
      public_key_base64: Buffer.from(pair.publicKey).toString('base64'),
      status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: null
    },
    secret: pair.secretKey
  };
}

const rootKeys = [key('ROOT-1'), key('ROOT-2'), key('ROOT-3')];
const releaseKeys = [key('RELEASE-1'), key('RELEASE-2'), key('RELEASE-3')];
const builderKeys = [key('BUILDER-1'), key('BUILDER-2'), key('BUILDER-3')];

function root(): ARVTrustRootV1 {
  return {
    schema: 'arv.trust-root',
    schema_version: 1,
    root_id: 'ARV-ROOT-OFFICIAL',
    root_version: 1,
    epoch: 1,
    issued_at: '2026-01-01T00:00:00Z',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2030-01-01T00:00:00Z',
    threshold: 2,
    recovery_threshold: 2,
    previous_root_hash: null,
    policy_digest: crypto.createHash('sha256').update('ARV-PUBLIC-ROOT-POLICY').digest('hex'),
    keys: rootKeys.map((item): ARVTrustRootKeyV1 => ({
      ...item.descriptor,
      roles: ['ROOT', 'RECOVERY']
    }))
  };
}

function trustState(trustRoot = root()): ARVVerifierTrustStateV1 {
  return {
    schema: 'arv.verifier-trust-state',
    schema_version: 1,
    state_id: 'ARV-VERIFIER-STATE-OFFICIAL-01',
    verifier_id: 'ARV-VERIFIER-OFFICIAL-01',
    generation: 7,
    recovery_count: 0,
    bootstrap_mode: 'EXPLICIT_PIN',
    status: 'ACTIVE',
    last_operation: 'ADVANCE',
    root_id: trustRoot.root_id,
    root_version: trustRoot.root_version,
    root_epoch: trustRoot.epoch,
    root_hash: sha256ARVTrustRootV1(trustRoot),
    witness_policy_id: 'ARV-WITNESS-POLICY-OFFICIAL',
    witness_policy_version: 1,
    witness_policy_hash: crypto.createHash('sha256').update('WITNESS-POLICY').digest('hex'),
    checkpoint_id: 'ARV-TRUST-CHECKPOINT-0007',
    checkpoint_hash: crypto.createHash('sha256').update('CHECKPOINT-7').digest('hex'),
    checkpoint_sequence: 7,
    registry_id: 'ARV-TRUST-REGISTRY-OFFICIAL',
    registry_version: 7,
    registry_digest: crypto.createHash('sha256').update('REGISTRY-7').digest('hex'),
    observed_at: '2026-08-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-08-01T00:00:00Z',
    previous_state_hash: crypto.createHash('sha256').update('STATE-6').digest('hex')
  };
}

function signature(payload: string, signer: TestKey) {
  return {
    algorithm: 'Ed25519' as const,
    key_id: signer.descriptor.key_id,
    signature_base64: Buffer.from(nacl.sign.detached(Buffer.from(payload, 'utf8'), signer.secret)).toString('base64')
  };
}

function policy(trustRoot = root(), version = 1): ARVVerifierReleaseAuthorizationPolicyV1 {
  const value: ARVVerifierReleaseAuthorizationPolicyV1 = {
    schema: 'arv.verifier-release-authorization-policy',
    schema_version: 1,
    policy_id: 'ARV-VERIFIER-RELEASE-POLICY-OFFICIAL',
    policy_version: version,
    root_id: trustRoot.root_id,
    root_version: trustRoot.root_version,
    root_epoch: trustRoot.epoch,
    root_hash: sha256ARVTrustRootV1(trustRoot),
    issued_at: '2026-01-01T00:00:00Z',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2028-01-01T00:00:00Z',
    release_threshold: 2,
    builder_threshold: 2,
    release_keys: releaseKeys.map((item) => ({ ...item.descriptor })),
    builder_keys: builderKeys.map((item) => ({ ...item.descriptor })),
    root_authorizations: []
  };
  const payload = canonicalARVVerifierReleasePolicySigningPayloadV1(value);
  value.root_authorizations = rootKeys.slice(0, 2).map((item) => signature(payload, item));
  return value;
}

function manifest(
  releasePolicy: ARVVerifierReleaseAuthorizationPolicyV1,
  sequence = 1,
  previous: string | null = null
): ARVVerifierReleaseManifestV1 {
  const artifacts = [
    {
      path: 'bin/arv-verifier.exe',
      media_type: 'application/vnd.microsoft.portable-executable',
      bytes: 4096,
      sha256: crypto.createHash('sha256').update(`BIN-${sequence}`).digest('hex')
    },
    {
      path: 'share/sbom.cdx.json',
      media_type: 'application/vnd.cyclonedx+json',
      bytes: 2048,
      sha256: crypto.createHash('sha256').update(`SBOM-${sequence}`).digest('hex')
    }
  ];
  const value: ARVVerifierReleaseManifestV1 = {
    schema: 'arv.verifier-release-manifest',
    schema_version: 1,
    manifest_id: `ARV-VERIFIER-RELEASE-MANIFEST-${String(sequence).padStart(4, '0')}`,
    verifier_id: 'ARV-VERIFIER-OFFICIAL-01',
    release_sequence: sequence,
    release_version: `1.0.${sequence - 1}`,
    channel: 'STABLE',
    platform: 'win32-x64',
    source_commit: crypto.createHash('sha1').update(`SOURCE-${sequence}`).digest('hex'),
    source_tree_digest: crypto.createHash('sha256').update(`TREE-${sequence}`).digest('hex'),
    build_recipe_digest: crypto.createHash('sha256').update('RECIPE-V1').digest('hex'),
    toolchain_digest: crypto.createHash('sha256').update('TOOLCHAIN-V1').digest('hex'),
    sbom_digest: artifacts[1].sha256,
    artifact_set_digest: sha256ARVVerifierArtifactSetV1(artifacts),
    artifacts,
    policy_id: releasePolicy.policy_id,
    policy_version: releasePolicy.policy_version,
    policy_hash: sha256ARVVerifierReleasePolicyV1(releasePolicy),
    root_id: releasePolicy.root_id,
    root_version: releasePolicy.root_version,
    root_epoch: releasePolicy.root_epoch,
    root_hash: releasePolicy.root_hash,
    previous_release_hash: previous,
    issued_at: '2026-08-01T00:00:00Z',
    valid_from: '2026-08-01T00:00:00Z',
    expires_at: '2027-08-01T00:00:00Z',
    signatures: []
  };
  const payload = canonicalARVVerifierReleaseManifestSigningPayloadV1(value);
  value.signatures = releaseKeys.slice(0, 2).map((item) => signature(payload, item));
  return value;
}

function attestations(value: ARVVerifierReleaseManifestV1): ARVVerifierBuildAttestationV1[] {
  const manifestHash = sha256ARVVerifierReleaseManifestV1(value);
  return builderKeys.slice(0, 2).map((builder, index) => {
    const item: ARVVerifierBuildAttestationV1 = {
      schema: 'arv.verifier-build-attestation',
      schema_version: 1,
      attestation_id: `ARV-VERIFIER-BUILD-ATTESTATION-${index + 1}-${value.release_sequence}`,
      builder_key_id: builder.descriptor.key_id,
      manifest_id: value.manifest_id,
      manifest_hash: manifestHash,
      verifier_id: value.verifier_id,
      release_sequence: value.release_sequence,
      source_commit: value.source_commit,
      build_recipe_digest: value.build_recipe_digest,
      toolchain_digest: value.toolchain_digest,
      artifact_set_digest: value.artifact_set_digest,
      built_at: '2026-08-01T01:00:00Z',
      signature: {
        algorithm: 'Ed25519',
        key_id: builder.descriptor.key_id,
        signature_base64: Buffer.alloc(64).toString('base64')
      }
    };
    item.signature = signature(canonicalARVVerifierBuildAttestationSigningPayloadV1(item), builder);
    return item;
  });
}

function fixture(): VerifyARVVerifierReleaseOptionsV1 {
  const trustRoot = root();
  const state = trustState(trustRoot);
  const releasePolicy = policy(trustRoot);
  const releaseManifest = manifest(releasePolicy);
  return {
    trusted_verifier_state: state,
    expected_trusted_state_hash: sha256ARVVerifierTrustStateV1(state),
    trust_root: trustRoot,
    release_policy: releasePolicy,
    release_manifest: releaseManifest,
    build_attestations: attestations(releaseManifest),
    current_release_pin: null,
    expected_current_release_pin_hash: null,
    bootstrap_release_hash: sha256ARVVerifierReleaseManifestV1(releaseManifest),
    pin_id: 'ARV-VERIFIER-RELEASE-PIN-OFFICIAL-01',
    installed_at: '2026-08-02T00:00:00Z',
    evaluated_at: '2026-08-02T00:00:00Z'
  };
}

function bootstrap(): { options: VerifyARVVerifierReleaseOptionsV1; pin: ARVVerifierReleasePinV1 } {
  const options = fixture();
  const verification = verifyARVVerifierReleaseV1(options);
  if (!verification.next_pin) throw new Error('bootstrap fixture failed');
  return { options, pin: verification.next_pin };
}

function updateFixture(): VerifyARVVerifierReleaseOptionsV1 {
  const { options, pin } = bootstrap();
  const releasePolicy = options.release_policy as ARVVerifierReleaseAuthorizationPolicyV1;
  const nextManifest = manifest(releasePolicy, 2, pin.manifest_hash);
  return {
    ...options,
    release_manifest: nextManifest,
    build_attestations: attestations(nextManifest),
    current_release_pin: pin,
    expected_current_release_pin_hash: sha256ARVVerifierReleasePinV1(pin),
    bootstrap_release_hash: null,
    installed_at: '2026-09-02T00:00:00Z',
    evaluated_at: '2026-09-02T00:00:00Z'
  };
}

describe('ARV Public official verifier release attestation and anti-rollback update', () => {
  test('accepts explicit hash-pinned bootstrap with release and independent builder quorums', () => {
    const result = verifyARVVerifierReleaseV1(fixture());
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('BOOTSTRAP_ACCEPTED');
    expect(result.operation).toBe('BOOTSTRAP');
    expect(result.valid_builder_attestations).toBe(2);
  });

  test('rejects silent trust on first use without an explicit bootstrap release hash', () => {
    const value = fixture();
    value.bootstrap_release_hash = null;
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('BOOTSTRAP_RELEASE_HASH_REQUIRED');
  });

  test('rejects a mismatched bootstrap release hash', () => {
    const value = fixture();
    value.bootstrap_release_hash = '0'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).state).toBe('BOOTSTRAP_PIN_MISMATCH');
  });

  test('rejects an absent external Public trusted state pin', () => {
    const value = fixture();
    value.expected_trusted_state_hash = null;
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('TRUST_STATE_PIN_REQUIRED');
  });

  test('rejects a stale external Public trusted state pin', () => {
    const value = fixture();
    value.expected_trusted_state_hash = '1'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('TRUST_STATE_PIN_MISMATCH');
  });

  test('rejects a trust root not bound by the Public state', () => {
    const value = fixture();
    const changed = root();
    changed.policy_digest = '2'.repeat(64);
    value.trust_root = changed;
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('TRUST_ROOT_HASH_MISMATCH');
  });

  test('rejects a release policy without the Public root quorum', () => {
    const value = fixture();
    const releasePolicy = value.release_policy as ARVVerifierReleaseAuthorizationPolicyV1;
    releasePolicy.root_authorizations = releasePolicy.root_authorizations.slice(0, 1);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_POLICY_THRESHOLD_NOT_MET');
  });

  test('rejects an expired release authorization policy', () => {
    const value = fixture();
    const releasePolicy = value.release_policy as ARVVerifierReleaseAuthorizationPolicyV1;
    releasePolicy.expires_at = '2026-08-01T12:00:00Z';
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_POLICY_TIME_INVALID');
  });

  test('rejects a manifest not bound to the authorized policy', () => {
    const value = fixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.policy_hash = '3'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_MANIFEST_POLICY_MISMATCH');
  });

  test('rejects insufficient release signatures', () => {
    const value = fixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.signatures = releaseManifest.signatures.slice(0, 1);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_MANIFEST_THRESHOLD_NOT_MET');
  });

  test('rejects a forged release signature', () => {
    const value = fixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.signatures[0].signature_base64 = Buffer.alloc(64).toString('base64');
    expect(verifyARVVerifierReleaseV1(value).state).toBe('MANIFEST_UNAUTHORIZED');
  });

  test('rejects an expired release manifest', () => {
    const value = fixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.expires_at = '2026-08-01T12:00:00Z';
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_MANIFEST_TIME_INVALID');
  });

  test('rejects an artifact set digest mismatch', () => {
    const value = fixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.artifact_set_digest = '4'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).state).toBe('MANIFEST_INVALID');
  });

  test('rejects insufficient independent builder attestations', () => {
    const value = fixture();
    value.build_attestations = (value.build_attestations as ARVVerifierBuildAttestationV1[]).slice(0, 1);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('BUILD_ATTESTATION_THRESHOLD_NOT_MET');
  });

  test('rejects a builder attestation bound to different artifacts', () => {
    const value = fixture();
    const builds = value.build_attestations as ARVVerifierBuildAttestationV1[];
    builds[0].artifact_set_digest = '5'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('BUILD_ATTESTATION_BINDING_MISMATCH');
  });

  test('accepts exactly one monotonic release update', () => {
    const result = verifyARVVerifierReleaseV1(updateFixture());
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('UPDATE_ACCEPTED');
    expect(result.next_pin?.generation).toBe(2);
  });

  test('accepts idempotent replay without mutating the release pin', () => {
    const { options, pin } = bootstrap();
    options.current_release_pin = pin;
    options.expected_current_release_pin_hash = sha256ARVVerifierReleasePinV1(pin);
    options.bootstrap_release_hash = null;
    const result = verifyARVVerifierReleaseV1(options);
    expect(result.state).toBe('REPLAY_ACCEPTED');
    expect(result.next_pin).toBeNull();
  });

  test('rejects an absent compare-and-swap pin hash', () => {
    const value = updateFixture();
    value.expected_current_release_pin_hash = null;
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('CURRENT_RELEASE_PIN_HASH_REQUIRED');
  });

  test('rejects a stale compare-and-swap pin hash', () => {
    const value = updateFixture();
    value.expected_current_release_pin_hash = '6'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('CURRENT_RELEASE_PIN_HASH_MISMATCH');
  });

  test('rejects verifier identity substitution', () => {
    const value = updateFixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.verifier_id = 'ARV-VERIFIER-OTHER-01';
    expect(verifyARVVerifierReleaseV1(value).accepted).toBe(false);
  });

  test('rejects release rollback', () => {
    const value = updateFixture();
    const pin = value.current_release_pin as ARVVerifierReleasePinV1;
    pin.release_sequence = 3;
    value.expected_current_release_pin_hash = sha256ARVVerifierReleasePinV1(pin);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_SEQUENCE_ROLLBACK');
  });

  test('rejects a release sequence gap', () => {
    const value = updateFixture();
    const releasePolicy = value.release_policy as ARVVerifierReleaseAuthorizationPolicyV1;
    const pin = value.current_release_pin as ARVVerifierReleasePinV1;
    const releaseManifest = manifest(releasePolicy, 4, pin.manifest_hash);
    value.release_manifest = releaseManifest;
    value.build_attestations = attestations(releaseManifest);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_SEQUENCE_GAP');
  });

  test('rejects same-sequence manifest equivocation', () => {
    const { options, pin } = bootstrap();
    const releasePolicy = options.release_policy as ARVVerifierReleaseAuthorizationPolicyV1;
    const conflicting = manifest(releasePolicy, 1, null);
    conflicting.source_commit = '7'.repeat(40);
    const payload = canonicalARVVerifierReleaseManifestSigningPayloadV1(conflicting);
    conflicting.signatures = releaseKeys.slice(0, 2).map((item) => signature(payload, item));
    options.release_manifest = conflicting;
    options.build_attestations = attestations(conflicting);
    options.current_release_pin = pin;
    options.expected_current_release_pin_hash = sha256ARVVerifierReleasePinV1(pin);
    options.bootstrap_release_hash = null;
    expect(verifyARVVerifierReleaseV1(options).state).toBe('RELEASE_EQUIVOCATION');
  });

  test('rejects a release with the wrong predecessor hash', () => {
    const value = updateFixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    releaseManifest.previous_release_hash = '8'.repeat(64);
    expect(verifyARVVerifierReleaseV1(value).accepted).toBe(false);
  });

  test('rejects same-version release-policy hash equivocation', () => {
    const value = updateFixture();
    const pin = value.current_release_pin as ARVVerifierReleasePinV1;
    pin.policy_hash = '9'.repeat(64);
    value.expected_current_release_pin_hash = sha256ARVVerifierReleasePinV1(pin);
    expect(verifyARVVerifierReleaseV1(value).codes).toContain('RELEASE_POLICY_HASH_EQUIVOCATION');
  });

  test('forbids private key material and never grants authority to storage or transport', () => {
    const value = fixture() as VerifyARVVerifierReleaseOptionsV1 & { private_key?: string };
    value.private_key = 'forbidden';
    const result = verifyARVVerifierReleaseV1(value);
    expect(result.state).toBe('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    expect(result.storage_authority).toBe('NONE');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });

  test('canonical hashes are language neutral and stable across serialization order', () => {
    const value = fixture();
    const releaseManifest = value.release_manifest as ARVVerifierReleaseManifestV1;
    const first = sha256ARVVerifierReleaseManifestV1(releaseManifest);
    releaseManifest.signatures.reverse();
    expect(sha256ARVVerifierReleaseManifestV1(releaseManifest)).toBe(first);
  });
});
