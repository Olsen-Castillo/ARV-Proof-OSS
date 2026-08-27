import crypto from 'crypto';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';
import { assertNoARVPrivateKeyMaterialV1 } from './trust-root-lifecycle-v1';
import {
  ARVVerifierReleaseArtifactV1,
  ARVVerifierReleaseManifestV1,
  ARVVerifierReleasePinV1,
  ARVVerifierReleaseVerificationV1,
  VerifyARVVerifierReleaseOptionsV1,
  assertARVVerifierReleaseManifestV1,
  assertARVVerifierReleasePinV1,
  sha256ARVVerifierArtifactSetV1,
  sha256ARVVerifierReleaseManifestV1,
  sha256ARVVerifierReleasePinV1,
  verifyARVVerifierReleaseV1
} from './verifier-release-attestation-v1';

export const ARV_VERIFIER_RUNTIME_PROFILE_SCHEMA = 'arv.verifier-runtime-profile' as const;
export const ARV_VERIFIER_INSTALLATION_EVIDENCE_SCHEMA = 'arv.verifier-installation-evidence' as const;
export const ARV_VERIFIER_ACTIVATION_PIN_SCHEMA = 'arv.verifier-activation-pin' as const;
export const ARV_VERIFIER_RUNTIME_MEASUREMENT_SCHEMA = 'arv.verifier-runtime-measurement' as const;
export const ARV_VERIFIER_RUNTIME_SCHEMA_VERSION = 1 as const;

export const ARV_VERIFIER_RUNTIME_STATES = [
  'BOOTSTRAP_ACTIVATED',
  'UPDATE_ACTIVATED',
  'RUNTIME_VERIFIED',
  'REPLAY_VERIFIED',
  'RELEASE_REJECTED',
  'RELEASE_BINDING_INVALID',
  'RUNTIME_PROFILE_INVALID',
  'RUNTIME_PROFILE_UNSIGNED',
  'INSTALLATION_INVALID',
  'INSTALLATION_ARTIFACT_MISMATCH',
  'MEASUREMENT_INVALID',
  'RUNTIME_DRIFT_DETECTED',
  'CURRENT_ACTIVATION_PIN_REQUIRED',
  'CURRENT_ACTIVATION_PIN_INVALID',
  'CURRENT_ACTIVATION_PIN_HASH_REQUIRED',
  'CURRENT_ACTIVATION_PIN_HASH_MISMATCH',
  'ACTIVATION_ROLLBACK',
  'ACTIVATION_GAP',
  'ACTIVATION_EQUIVOCATION',
  'BOOTSTRAP_PIN_REQUIRED',
  'BOOTSTRAP_PIN_MISMATCH',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export const ARV_VERIFIER_RUNTIME_OPERATIONS = ['NONE', 'BOOTSTRAP', 'UPDATE', 'VERIFY', 'REPLAY'] as const;

export const ARV_VERIFIER_RUNTIME_CODES = [
  'RELEASE_NOT_ACCEPTED',
  'RELEASE_MANIFEST_INVALID',
  'RELEASE_MANIFEST_HASH_MISMATCH',
  'RELEASE_PIN_INVALID',
  'RELEASE_PIN_HASH_MISMATCH',
  'RUNTIME_PROFILE_SCHEMA_INVALID',
  'RUNTIME_PROFILE_ARTIFACT_NOT_SIGNED',
  'RUNTIME_PROFILE_DIGEST_MISMATCH',
  'RUNTIME_PROFILE_PATH_INVALID',
  'INSTALLATION_EVIDENCE_SCHEMA_INVALID',
  'INSTALLATION_RELEASE_BINDING_MISMATCH',
  'INSTALLATION_ARTIFACT_SET_MISMATCH',
  'INSTALLATION_REQUIRED_ARTIFACT_MISSING',
  'RUNTIME_MEASUREMENT_SCHEMA_INVALID',
  'RUNTIME_MEASUREMENT_BINDING_MISMATCH',
  'RUNTIME_EXECUTABLE_DIGEST_MISMATCH',
  'RUNTIME_CONFIGURATION_DIGEST_MISMATCH',
  'RUNTIME_POLICY_BUNDLE_DIGEST_MISMATCH',
  'RUNTIME_SCHEMA_BUNDLE_DIGEST_MISMATCH',
  'RUNTIME_DEPENDENCY_SET_DIGEST_MISMATCH',
  'RUNTIME_MODULE_SET_DIGEST_MISMATCH',
  'RUNTIME_ENVIRONMENT_DIGEST_MISMATCH',
  'CURRENT_ACTIVATION_PIN_REQUIRED',
  'CURRENT_ACTIVATION_PIN_SCHEMA_INVALID',
  'CURRENT_ACTIVATION_PIN_HASH_REQUIRED',
  'CURRENT_ACTIVATION_PIN_HASH_MISMATCH',
  'VERIFIER_INSTANCE_MISMATCH',
  'ACTIVATION_SEQUENCE_ROLLBACK',
  'ACTIVATION_SEQUENCE_GAP',
  'ACTIVATION_HASH_EQUIVOCATION',
  'BOOTSTRAP_INSTALLATION_HASH_REQUIRED',
  'BOOTSTRAP_INSTALLATION_HASH_MISMATCH',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVVerifierRuntimeStateV1 = typeof ARV_VERIFIER_RUNTIME_STATES[number];
export type ARVVerifierRuntimeOperationV1 = typeof ARV_VERIFIER_RUNTIME_OPERATIONS[number];
export type ARVVerifierRuntimeCodeV1 = typeof ARV_VERIFIER_RUNTIME_CODES[number];

export interface ARVVerifierRuntimeProfileV1 {
  schema: typeof ARV_VERIFIER_RUNTIME_PROFILE_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RUNTIME_SCHEMA_VERSION;
  profile_id: string;
  verifier_id: string;
  release_sequence: number;
  platform: string;
  executable_path: string;
  required_artifact_paths: string[];
  executable_digest: string;
  configuration_digest: string;
  policy_bundle_digest: string;
  schema_bundle_digest: string;
  dependency_set_digest: string;
  allowed_module_set_digest: string;
  environment_constraints_digest: string;
}

export interface ARVVerifierInstallationEvidenceV1 {
  schema: typeof ARV_VERIFIER_INSTALLATION_EVIDENCE_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RUNTIME_SCHEMA_VERSION;
  installation_id: string;
  verifier_id: string;
  instance_id: string;
  activation_sequence: number;
  release_sequence: number;
  release_version: string;
  release_manifest_hash: string;
  release_pin_hash: string;
  runtime_profile_path: string;
  runtime_profile_hash: string;
  observed_artifact_set_digest: string;
  observed_artifacts: ARVVerifierReleaseArtifactV1[];
  installed_at: string;
}

export interface ARVVerifierRuntimeMeasurementV1 {
  schema: typeof ARV_VERIFIER_RUNTIME_MEASUREMENT_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RUNTIME_SCHEMA_VERSION;
  measurement_id: string;
  verifier_id: string;
  instance_id: string;
  activation_sequence: number;
  installation_hash: string;
  release_manifest_hash: string;
  runtime_profile_hash: string;
  observed_artifact_set_digest: string;
  executable_digest: string;
  configuration_digest: string;
  policy_bundle_digest: string;
  schema_bundle_digest: string;
  dependency_set_digest: string;
  loaded_module_set_digest: string;
  environment_constraints_digest: string;
  measured_at: string;
}

export interface ARVVerifierActivationPinV1 {
  schema: typeof ARV_VERIFIER_ACTIVATION_PIN_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RUNTIME_SCHEMA_VERSION;
  pin_id: string;
  verifier_id: string;
  instance_id: string;
  generation: number;
  activation_sequence: number;
  release_sequence: number;
  release_manifest_hash: string;
  release_pin_hash: string;
  installation_hash: string;
  runtime_profile_hash: string;
  runtime_baseline_hash: string;
  activated_at: string;
  previous_pin_hash: string | null;
}

export interface VerifyARVVerifierRuntimeOptionsV1 {
  release_verification_options: VerifyARVVerifierReleaseOptionsV1;
  runtime_profile: unknown;
  installation_evidence: unknown;
  runtime_measurement: unknown;
  current_activation_pin: unknown | null;
  expected_current_activation_pin_hash: string | null;
  bootstrap_installation_hash: string | null;
  activation_pin_id: string;
  activated_at: string;
  evaluated_at: string;
}

export interface ARVVerifierRuntimeVerificationV1 {
  schema: 'arv.verifier-runtime-integrity-verification';
  schema_version: 1;
  accepted: boolean;
  quarantined: boolean;
  state: ARVVerifierRuntimeStateV1;
  operation: ARVVerifierRuntimeOperationV1;
  release_verification_state: ARVVerifierReleaseVerificationV1['state'] | null;
  release_manifest_hash: string | null;
  release_pin_hash: string | null;
  installation_hash: string | null;
  runtime_profile_hash: string | null;
  runtime_measurement_hash: string | null;
  current_activation_pin_hash: string | null;
  commit_precondition_hash: string | null;
  next_activation_pin_hash: string | null;
  next_activation_pin: ARVVerifierActivationPinV1 | null;
  codes: ARVVerifierRuntimeCodeV1[];
  release_authority: 'VERIFIED_RELEASE';
  activation_authority: 'MEASURED_RELEASE_BOUND_INSTALLATION';
  operating_system_authority: 'NONE';
  installer_authority: 'NONE';
  app_store_authority: 'NONE';
  storage_authority: 'NONE';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

const sha256Pattern = /^[a-f0-9]{64}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const verifierIdPattern = /^ARV-VERIFIER-[A-Z0-9-]+$/;
const profileIdPattern = /^ARV-VERIFIER-RUNTIME-PROFILE-[A-Z0-9-]+$/;
const installationIdPattern = /^ARV-VERIFIER-INSTALLATION-[A-Z0-9-]+$/;
const instanceIdPattern = /^ARV-VERIFIER-INSTANCE-[A-Z0-9-]+$/;
const measurementIdPattern = /^ARV-VERIFIER-RUNTIME-MEASUREMENT-[A-Z0-9-]+$/;
const activationPinIdPattern = /^ARV-VERIFIER-ACTIVATION-PIN-[A-Z0-9-]+$/;
const artifactPathPattern = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

function record(value: unknown, location: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${location} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: string[], location: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${location} contains unexpected or missing fields`);
  }
}

function text(value: unknown, pattern: RegExp, location: string): asserts value is string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${location} is invalid`);
}

function digest(value: unknown, location: string): asserts value is string {
  text(value, sha256Pattern, location);
}

function timestamp(value: unknown, location: string): asserts value is string {
  text(value, timestampPattern, location);
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${location} must be a valid UTC timestamp`);
}

function positiveInteger(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 1) throw new Error(`${location} must be a positive integer`);
}

function uniqueSorted(values: unknown, location: string): string[] {
  if (!Array.isArray(values) || values.length === 0) throw new Error(`${location} must be a non-empty array`);
  values.forEach((value, index) => text(value, artifactPathPattern, `${location}[${index}]`));
  const typed = values as string[];
  const sorted = [...typed].sort();
  if (new Set(typed).size !== typed.length || typed.some((value, index) => value !== sorted[index])) {
    throw new Error(`${location} must be unique and sorted`);
  }
  return typed;
}

function sha256Domain(domain: string, value: unknown): string {
  return crypto.createHash('sha256').update(`${domain}\n${canonicalizeARVJsonV1(value)}`, 'utf8').digest('hex');
}

export function assertARVVerifierRuntimeProfileV1(value: unknown): ARVVerifierRuntimeProfileV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = record(value, '$runtime_profile');
  exactKeys(input, [
    'schema', 'schema_version', 'profile_id', 'verifier_id', 'release_sequence', 'platform',
    'executable_path', 'required_artifact_paths', 'executable_digest', 'configuration_digest',
    'policy_bundle_digest', 'schema_bundle_digest', 'dependency_set_digest',
    'allowed_module_set_digest', 'environment_constraints_digest'
  ], '$runtime_profile');
  if (input.schema !== ARV_VERIFIER_RUNTIME_PROFILE_SCHEMA || input.schema_version !== 1) throw new Error('$runtime_profile schema is invalid');
  text(input.profile_id, profileIdPattern, '$runtime_profile.profile_id');
  text(input.verifier_id, verifierIdPattern, '$runtime_profile.verifier_id');
  positiveInteger(input.release_sequence, '$runtime_profile.release_sequence');
  text(input.platform, /^[a-z0-9][a-z0-9._-]{1,63}$/, '$runtime_profile.platform');
  text(input.executable_path, artifactPathPattern, '$runtime_profile.executable_path');
  const paths = uniqueSorted(input.required_artifact_paths, '$runtime_profile.required_artifact_paths');
  if (!paths.includes(input.executable_path as string)) throw new Error('$runtime_profile executable must be required');
  ['executable_digest', 'configuration_digest', 'policy_bundle_digest', 'schema_bundle_digest', 'dependency_set_digest', 'allowed_module_set_digest', 'environment_constraints_digest']
    .forEach((field) => digest(input[field], `$runtime_profile.${field}`));
  return input as unknown as ARVVerifierRuntimeProfileV1;
}

function assertArtifacts(value: unknown, location: string): ARVVerifierReleaseArtifactV1[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${location} must be a non-empty array`);
  const artifacts = value.map((item, index) => {
    const artifact = record(item, `${location}[${index}]`);
    exactKeys(artifact, ['path', 'media_type', 'bytes', 'sha256'], `${location}[${index}]`);
    text(artifact.path, artifactPathPattern, `${location}[${index}].path`);
    text(artifact.media_type, /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/, `${location}[${index}].media_type`);
    positiveInteger(artifact.bytes, `${location}[${index}].bytes`);
    digest(artifact.sha256, `${location}[${index}].sha256`);
    return artifact as unknown as ARVVerifierReleaseArtifactV1;
  });
  const paths = artifacts.map((artifact) => artifact.path);
  const sorted = [...paths].sort();
  if (new Set(paths).size !== paths.length || paths.some((path, index) => path !== sorted[index])) throw new Error(`${location} must be unique and sorted by path`);
  return artifacts;
}

export function assertARVVerifierInstallationEvidenceV1(value: unknown): ARVVerifierInstallationEvidenceV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = record(value, '$installation_evidence');
  exactKeys(input, [
    'schema', 'schema_version', 'installation_id', 'verifier_id', 'instance_id', 'activation_sequence',
    'release_sequence', 'release_version', 'release_manifest_hash', 'release_pin_hash', 'runtime_profile_path',
    'runtime_profile_hash', 'observed_artifact_set_digest', 'observed_artifacts', 'installed_at'
  ], '$installation_evidence');
  if (input.schema !== ARV_VERIFIER_INSTALLATION_EVIDENCE_SCHEMA || input.schema_version !== 1) throw new Error('$installation_evidence schema is invalid');
  text(input.installation_id, installationIdPattern, '$installation_evidence.installation_id');
  text(input.verifier_id, verifierIdPattern, '$installation_evidence.verifier_id');
  text(input.instance_id, instanceIdPattern, '$installation_evidence.instance_id');
  positiveInteger(input.activation_sequence, '$installation_evidence.activation_sequence');
  positiveInteger(input.release_sequence, '$installation_evidence.release_sequence');
  text(input.release_version, semverPattern, '$installation_evidence.release_version');
  digest(input.release_manifest_hash, '$installation_evidence.release_manifest_hash');
  digest(input.release_pin_hash, '$installation_evidence.release_pin_hash');
  text(input.runtime_profile_path, artifactPathPattern, '$installation_evidence.runtime_profile_path');
  digest(input.runtime_profile_hash, '$installation_evidence.runtime_profile_hash');
  digest(input.observed_artifact_set_digest, '$installation_evidence.observed_artifact_set_digest');
  const artifacts = assertArtifacts(input.observed_artifacts, '$installation_evidence.observed_artifacts');
  timestamp(input.installed_at, '$installation_evidence.installed_at');
  return { ...input, observed_artifacts: artifacts } as unknown as ARVVerifierInstallationEvidenceV1;
}

export function assertARVVerifierRuntimeMeasurementV1(value: unknown): ARVVerifierRuntimeMeasurementV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = record(value, '$runtime_measurement');
  exactKeys(input, [
    'schema', 'schema_version', 'measurement_id', 'verifier_id', 'instance_id', 'activation_sequence',
    'installation_hash', 'release_manifest_hash', 'runtime_profile_hash', 'observed_artifact_set_digest',
    'executable_digest', 'configuration_digest', 'policy_bundle_digest', 'schema_bundle_digest',
    'dependency_set_digest', 'loaded_module_set_digest', 'environment_constraints_digest', 'measured_at'
  ], '$runtime_measurement');
  if (input.schema !== ARV_VERIFIER_RUNTIME_MEASUREMENT_SCHEMA || input.schema_version !== 1) throw new Error('$runtime_measurement schema is invalid');
  text(input.measurement_id, measurementIdPattern, '$runtime_measurement.measurement_id');
  text(input.verifier_id, verifierIdPattern, '$runtime_measurement.verifier_id');
  text(input.instance_id, instanceIdPattern, '$runtime_measurement.instance_id');
  positiveInteger(input.activation_sequence, '$runtime_measurement.activation_sequence');
  ['installation_hash', 'release_manifest_hash', 'runtime_profile_hash', 'observed_artifact_set_digest', 'executable_digest', 'configuration_digest', 'policy_bundle_digest', 'schema_bundle_digest', 'dependency_set_digest', 'loaded_module_set_digest', 'environment_constraints_digest']
    .forEach((field) => digest(input[field], `$runtime_measurement.${field}`));
  timestamp(input.measured_at, '$runtime_measurement.measured_at');
  return input as unknown as ARVVerifierRuntimeMeasurementV1;
}

export function assertARVVerifierActivationPinV1(value: unknown): ARVVerifierActivationPinV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = record(value, '$activation_pin');
  exactKeys(input, [
    'schema', 'schema_version', 'pin_id', 'verifier_id', 'instance_id', 'generation', 'activation_sequence',
    'release_sequence', 'release_manifest_hash', 'release_pin_hash', 'installation_hash', 'runtime_profile_hash',
    'runtime_baseline_hash', 'activated_at', 'previous_pin_hash'
  ], '$activation_pin');
  if (input.schema !== ARV_VERIFIER_ACTIVATION_PIN_SCHEMA || input.schema_version !== 1) throw new Error('$activation_pin schema is invalid');
  text(input.pin_id, activationPinIdPattern, '$activation_pin.pin_id');
  text(input.verifier_id, verifierIdPattern, '$activation_pin.verifier_id');
  text(input.instance_id, instanceIdPattern, '$activation_pin.instance_id');
  positiveInteger(input.generation, '$activation_pin.generation');
  positiveInteger(input.activation_sequence, '$activation_pin.activation_sequence');
  positiveInteger(input.release_sequence, '$activation_pin.release_sequence');
  ['release_manifest_hash', 'release_pin_hash', 'installation_hash', 'runtime_profile_hash', 'runtime_baseline_hash']
    .forEach((field) => digest(input[field], `$activation_pin.${field}`));
  timestamp(input.activated_at, '$activation_pin.activated_at');
  if (input.previous_pin_hash !== null) digest(input.previous_pin_hash, '$activation_pin.previous_pin_hash');
  if (input.generation === 1 && input.previous_pin_hash !== null) throw new Error('$activation_pin bootstrap predecessor must be null');
  if (input.generation > 1 && input.previous_pin_hash === null) throw new Error('$activation_pin predecessor is required');
  return input as unknown as ARVVerifierActivationPinV1;
}

export function sha256ARVVerifierRuntimeProfileV1(value: ARVVerifierRuntimeProfileV1): string {
  return sha256Domain('ARV-VERIFIER-RUNTIME-PROFILE-v1', value);
}

export function sha256ARVVerifierInstallationEvidenceV1(value: ARVVerifierInstallationEvidenceV1): string {
  return sha256Domain('ARV-VERIFIER-INSTALLATION-EVIDENCE-v1', value);
}

export function sha256ARVVerifierRuntimeMeasurementV1(value: ARVVerifierRuntimeMeasurementV1): string {
  return sha256Domain('ARV-VERIFIER-RUNTIME-MEASUREMENT-v1', value);
}

export function sha256ARVVerifierActivationPinV1(value: ARVVerifierActivationPinV1): string {
  return sha256Domain('ARV-VERIFIER-ACTIVATION-PIN-v1', value);
}

function sameArtifacts(left: ARVVerifierReleaseArtifactV1[], right: ARVVerifierReleaseArtifactV1[]): boolean {
  return canonicalizeARVJsonV1(left) === canonicalizeARVJsonV1(right);
}

function runtimeBaselineHash(profile: ARVVerifierRuntimeProfileV1): string {
  return sha256Domain('ARV-VERIFIER-RUNTIME-BASELINE-v1', {
    executable_digest: profile.executable_digest,
    configuration_digest: profile.configuration_digest,
    policy_bundle_digest: profile.policy_bundle_digest,
    schema_bundle_digest: profile.schema_bundle_digest,
    dependency_set_digest: profile.dependency_set_digest,
    allowed_module_set_digest: profile.allowed_module_set_digest,
    environment_constraints_digest: profile.environment_constraints_digest
  });
}

function output(
  accepted: boolean,
  quarantined: boolean,
  state: ARVVerifierRuntimeStateV1,
  operation: ARVVerifierRuntimeOperationV1,
  codes: ARVVerifierRuntimeCodeV1[],
  release: ARVVerifierReleaseVerificationV1 | null,
  manifestHash: string | null,
  releasePinHash: string | null,
  installationHash: string | null,
  profileHash: string | null,
  measurementHash: string | null,
  currentPinHash: string | null,
  precondition: string | null,
  nextPin: ARVVerifierActivationPinV1 | null
): ARVVerifierRuntimeVerificationV1 {
  return {
    schema: 'arv.verifier-runtime-integrity-verification',
    schema_version: 1,
    accepted,
    quarantined,
    state,
    operation,
    release_verification_state: release ? release.state : null,
    release_manifest_hash: manifestHash,
    release_pin_hash: releasePinHash,
    installation_hash: installationHash,
    runtime_profile_hash: profileHash,
    runtime_measurement_hash: measurementHash,
    current_activation_pin_hash: currentPinHash,
    commit_precondition_hash: precondition,
    next_activation_pin_hash: nextPin ? sha256ARVVerifierActivationPinV1(nextPin) : null,
    next_activation_pin: nextPin,
    codes: Array.from(new Set(codes)).sort(),
    release_authority: 'VERIFIED_RELEASE',
    activation_authority: 'MEASURED_RELEASE_BOUND_INSTALLATION',
    operating_system_authority: 'NONE',
    installer_authority: 'NONE',
    app_store_authority: 'NONE',
    storage_authority: 'NONE',
    transport_authority: 'NONE',
    material_truth: 'NOT_EVALUATED'
  };
}

function effectiveReleasePin(
  verification: ARVVerifierReleaseVerificationV1,
  options: VerifyARVVerifierReleaseOptionsV1
): ARVVerifierReleasePinV1 | null {
  if (verification.next_pin) return verification.next_pin;
  if (verification.operation !== 'REPLAY' || options.current_release_pin === null) return null;
  try {
    return assertARVVerifierReleasePinV1(options.current_release_pin);
  } catch {
    return null;
  }
}

export function verifyARVVerifierRuntimeIntegrityV1(options: VerifyARVVerifierRuntimeOptionsV1): ARVVerifierRuntimeVerificationV1 {
  try {
    assertNoARVPrivateKeyMaterialV1(options);
  } catch {
    return output(false, true, 'PRIVATE_KEY_MATERIAL_FORBIDDEN', 'NONE', ['PRIVATE_KEY_MATERIAL_FORBIDDEN'], null, null, null, null, null, null, null, options.expected_current_activation_pin_hash, null);
  }
  timestamp(options.activated_at, '$options.activated_at');
  timestamp(options.evaluated_at, '$options.evaluated_at');
  text(options.activation_pin_id, activationPinIdPattern, '$options.activation_pin_id');

  const release = verifyARVVerifierReleaseV1(options.release_verification_options);
  if (!release.accepted) {
    return output(false, true, 'RELEASE_REJECTED', 'NONE', ['RELEASE_NOT_ACCEPTED'], release, release.manifest_hash, null, null, null, null, null, options.expected_current_activation_pin_hash, null);
  }

  let manifest: ARVVerifierReleaseManifestV1;
  try {
    manifest = assertARVVerifierReleaseManifestV1(options.release_verification_options.release_manifest);
  } catch {
    return output(false, true, 'RELEASE_BINDING_INVALID', 'NONE', ['RELEASE_MANIFEST_INVALID'], release, release.manifest_hash, null, null, null, null, null, options.expected_current_activation_pin_hash, null);
  }
  const manifestHash = sha256ARVVerifierReleaseManifestV1(manifest);
  if (release.manifest_hash !== manifestHash) {
    return output(false, true, 'RELEASE_BINDING_INVALID', 'NONE', ['RELEASE_MANIFEST_HASH_MISMATCH'], release, manifestHash, null, null, null, null, null, options.expected_current_activation_pin_hash, null);
  }

  const releasePin = effectiveReleasePin(release, options.release_verification_options);
  if (!releasePin) {
    return output(false, true, 'RELEASE_BINDING_INVALID', 'NONE', ['RELEASE_PIN_INVALID'], release, manifestHash, null, null, null, null, null, options.expected_current_activation_pin_hash, null);
  }
  const releasePinHash = sha256ARVVerifierReleasePinV1(releasePin);

  let profile: ARVVerifierRuntimeProfileV1;
  try {
    profile = assertARVVerifierRuntimeProfileV1(options.runtime_profile);
  } catch {
    return output(false, true, 'RUNTIME_PROFILE_INVALID', 'NONE', ['RUNTIME_PROFILE_SCHEMA_INVALID'], release, manifestHash, releasePinHash, null, null, null, null, options.expected_current_activation_pin_hash, null);
  }
  const profileHash = sha256ARVVerifierRuntimeProfileV1(profile);
  const profileArtifact = manifest.artifacts.find((artifact) => artifact.path === (options.installation_evidence as Record<string, unknown>)?.runtime_profile_path);
  if (!profileArtifact) {
    return output(false, true, 'RUNTIME_PROFILE_UNSIGNED', 'NONE', ['RUNTIME_PROFILE_ARTIFACT_NOT_SIGNED'], release, manifestHash, releasePinHash, null, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }
  if (profileArtifact.sha256 !== profileHash) {
    return output(false, true, 'RUNTIME_PROFILE_UNSIGNED', 'NONE', ['RUNTIME_PROFILE_DIGEST_MISMATCH'], release, manifestHash, releasePinHash, null, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }

  let installation: ARVVerifierInstallationEvidenceV1;
  try {
    installation = assertARVVerifierInstallationEvidenceV1(options.installation_evidence);
  } catch {
    return output(false, true, 'INSTALLATION_INVALID', 'NONE', ['INSTALLATION_EVIDENCE_SCHEMA_INVALID'], release, manifestHash, releasePinHash, null, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }
  const installationHash = sha256ARVVerifierInstallationEvidenceV1(installation);
  if (
    installation.verifier_id !== manifest.verifier_id ||
    installation.verifier_id !== profile.verifier_id ||
    installation.release_sequence !== manifest.release_sequence ||
    installation.release_sequence !== profile.release_sequence ||
    installation.release_version !== manifest.release_version ||
    installation.release_manifest_hash !== manifestHash ||
    installation.release_pin_hash !== releasePinHash ||
    installation.runtime_profile_hash !== profileHash ||
    profile.platform !== manifest.platform
  ) {
    return output(false, true, 'INSTALLATION_INVALID', 'NONE', ['INSTALLATION_RELEASE_BINDING_MISMATCH'], release, manifestHash, releasePinHash, installationHash, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }
  if (!sameArtifacts(installation.observed_artifacts, manifest.artifacts) ||
      installation.observed_artifact_set_digest !== sha256ARVVerifierArtifactSetV1(manifest.artifacts)) {
    return output(false, true, 'INSTALLATION_ARTIFACT_MISMATCH', 'NONE', ['INSTALLATION_ARTIFACT_SET_MISMATCH'], release, manifestHash, releasePinHash, installationHash, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }
  const observedPaths = new Set(installation.observed_artifacts.map((artifact) => artifact.path));
  if (profile.required_artifact_paths.some((path) => !observedPaths.has(path))) {
    return output(false, true, 'INSTALLATION_ARTIFACT_MISMATCH', 'NONE', ['INSTALLATION_REQUIRED_ARTIFACT_MISSING'], release, manifestHash, releasePinHash, installationHash, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }

  let measurement: ARVVerifierRuntimeMeasurementV1;
  try {
    measurement = assertARVVerifierRuntimeMeasurementV1(options.runtime_measurement);
  } catch {
    return output(false, true, 'MEASUREMENT_INVALID', 'NONE', ['RUNTIME_MEASUREMENT_SCHEMA_INVALID'], release, manifestHash, releasePinHash, installationHash, profileHash, null, null, options.expected_current_activation_pin_hash, null);
  }
  const measurementHash = sha256ARVVerifierRuntimeMeasurementV1(measurement);
  if (
    measurement.verifier_id !== installation.verifier_id ||
    measurement.instance_id !== installation.instance_id ||
    measurement.activation_sequence !== installation.activation_sequence ||
    measurement.installation_hash !== installationHash ||
    measurement.release_manifest_hash !== manifestHash ||
    measurement.runtime_profile_hash !== profileHash ||
    measurement.observed_artifact_set_digest !== installation.observed_artifact_set_digest
  ) {
    return output(false, true, 'RUNTIME_DRIFT_DETECTED', 'NONE', ['RUNTIME_MEASUREMENT_BINDING_MISMATCH'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, options.expected_current_activation_pin_hash, null);
  }
  const driftCodes: ARVVerifierRuntimeCodeV1[] = [];
  if (measurement.executable_digest !== profile.executable_digest) driftCodes.push('RUNTIME_EXECUTABLE_DIGEST_MISMATCH');
  if (measurement.configuration_digest !== profile.configuration_digest) driftCodes.push('RUNTIME_CONFIGURATION_DIGEST_MISMATCH');
  if (measurement.policy_bundle_digest !== profile.policy_bundle_digest) driftCodes.push('RUNTIME_POLICY_BUNDLE_DIGEST_MISMATCH');
  if (measurement.schema_bundle_digest !== profile.schema_bundle_digest) driftCodes.push('RUNTIME_SCHEMA_BUNDLE_DIGEST_MISMATCH');
  if (measurement.dependency_set_digest !== profile.dependency_set_digest) driftCodes.push('RUNTIME_DEPENDENCY_SET_DIGEST_MISMATCH');
  if (measurement.loaded_module_set_digest !== profile.allowed_module_set_digest) driftCodes.push('RUNTIME_MODULE_SET_DIGEST_MISMATCH');
  if (measurement.environment_constraints_digest !== profile.environment_constraints_digest) driftCodes.push('RUNTIME_ENVIRONMENT_DIGEST_MISMATCH');
  if (driftCodes.length > 0) {
    return output(false, true, 'RUNTIME_DRIFT_DETECTED', 'NONE', driftCodes, release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, options.expected_current_activation_pin_hash, null);
  }

  const baselineHash = runtimeBaselineHash(profile);
  if (options.current_activation_pin === null) {
    if (options.expected_current_activation_pin_hash !== null) {
      return output(false, true, 'CURRENT_ACTIVATION_PIN_REQUIRED', 'NONE', ['CURRENT_ACTIVATION_PIN_REQUIRED'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, options.expected_current_activation_pin_hash, null);
    }
    if (options.bootstrap_installation_hash === null) {
      return output(false, true, 'BOOTSTRAP_PIN_REQUIRED', 'NONE', ['BOOTSTRAP_INSTALLATION_HASH_REQUIRED'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, null, null);
    }
    if (options.bootstrap_installation_hash !== installationHash) {
      return output(false, true, 'BOOTSTRAP_PIN_MISMATCH', 'NONE', ['BOOTSTRAP_INSTALLATION_HASH_MISMATCH'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, null, null);
    }
    const nextPin: ARVVerifierActivationPinV1 = {
      schema: ARV_VERIFIER_ACTIVATION_PIN_SCHEMA,
      schema_version: 1,
      pin_id: options.activation_pin_id,
      verifier_id: installation.verifier_id,
      instance_id: installation.instance_id,
      generation: 1,
      activation_sequence: installation.activation_sequence,
      release_sequence: installation.release_sequence,
      release_manifest_hash: manifestHash,
      release_pin_hash: releasePinHash,
      installation_hash: installationHash,
      runtime_profile_hash: profileHash,
      runtime_baseline_hash: baselineHash,
      activated_at: options.activated_at,
      previous_pin_hash: null
    };
    return output(true, false, 'BOOTSTRAP_ACTIVATED', 'BOOTSTRAP', [], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, null, nextPin);
  }

  let currentPin: ARVVerifierActivationPinV1;
  let currentPinHash: string;
  try {
    currentPin = assertARVVerifierActivationPinV1(options.current_activation_pin);
    currentPinHash = sha256ARVVerifierActivationPinV1(currentPin);
  } catch {
    return output(false, true, 'CURRENT_ACTIVATION_PIN_INVALID', 'NONE', ['CURRENT_ACTIVATION_PIN_SCHEMA_INVALID'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, null, options.expected_current_activation_pin_hash, null);
  }
  if (options.expected_current_activation_pin_hash === null) {
    return output(false, true, 'CURRENT_ACTIVATION_PIN_HASH_REQUIRED', 'NONE', ['CURRENT_ACTIVATION_PIN_HASH_REQUIRED'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, null, null);
  }
  if (options.expected_current_activation_pin_hash !== currentPinHash) {
    return output(false, true, 'CURRENT_ACTIVATION_PIN_HASH_MISMATCH', 'NONE', ['CURRENT_ACTIVATION_PIN_HASH_MISMATCH'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, options.expected_current_activation_pin_hash, null);
  }
  if (currentPin.verifier_id !== installation.verifier_id || currentPin.instance_id !== installation.instance_id) {
    return output(false, true, 'CURRENT_ACTIVATION_PIN_INVALID', 'NONE', ['VERIFIER_INSTANCE_MISMATCH'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, currentPinHash, null);
  }
  if (installation.activation_sequence < currentPin.activation_sequence) {
    return output(false, true, 'ACTIVATION_ROLLBACK', 'NONE', ['ACTIVATION_SEQUENCE_ROLLBACK'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, currentPinHash, null);
  }
  if (installation.activation_sequence === currentPin.activation_sequence) {
    if (installationHash !== currentPin.installation_hash || manifestHash !== currentPin.release_manifest_hash || profileHash !== currentPin.runtime_profile_hash || baselineHash !== currentPin.runtime_baseline_hash) {
      return output(false, true, 'ACTIVATION_EQUIVOCATION', 'NONE', ['ACTIVATION_HASH_EQUIVOCATION'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, currentPinHash, null);
    }
    return output(true, false, 'REPLAY_VERIFIED', 'REPLAY', [], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, currentPinHash, null);
  }
  if (installation.activation_sequence !== currentPin.activation_sequence + 1) {
    return output(false, true, 'ACTIVATION_GAP', 'NONE', ['ACTIVATION_SEQUENCE_GAP'], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, currentPinHash, null);
  }
  const nextPin: ARVVerifierActivationPinV1 = {
    schema: ARV_VERIFIER_ACTIVATION_PIN_SCHEMA,
    schema_version: 1,
    pin_id: currentPin.pin_id,
    verifier_id: installation.verifier_id,
    instance_id: installation.instance_id,
    generation: currentPin.generation + 1,
    activation_sequence: installation.activation_sequence,
    release_sequence: installation.release_sequence,
    release_manifest_hash: manifestHash,
    release_pin_hash: releasePinHash,
    installation_hash: installationHash,
    runtime_profile_hash: profileHash,
    runtime_baseline_hash: baselineHash,
    activated_at: options.activated_at,
    previous_pin_hash: currentPinHash
  };
  return output(true, false, 'UPDATE_ACTIVATED', 'UPDATE', [], release, manifestHash, releasePinHash, installationHash, profileHash, measurementHash, currentPinHash, currentPinHash, nextPin);
}
