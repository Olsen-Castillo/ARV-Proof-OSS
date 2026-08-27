import crypto from 'crypto';
import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';
import {
  ARVTrustRootSignatureV1,
  ARVTrustRootV1,
  assertARVTrustRootV1,
  assertNoARVPrivateKeyMaterialV1,
  fingerprintARVTrustRootPublicKeyV1,
  sha256ARVTrustRootV1
} from './trust-root-lifecycle-v1';
import {
  ARVVerifierTrustStateV1,
  assertARVVerifierTrustStateV1,
  sha256ARVVerifierTrustStateV1
} from './verifier-trust-state-v1';

export const ARV_VERIFIER_RELEASE_POLICY_SCHEMA = 'arv.verifier-release-authorization-policy' as const;
export const ARV_VERIFIER_RELEASE_MANIFEST_SCHEMA = 'arv.verifier-release-manifest' as const;
export const ARV_VERIFIER_BUILD_ATTESTATION_SCHEMA = 'arv.verifier-build-attestation' as const;
export const ARV_VERIFIER_RELEASE_PIN_SCHEMA = 'arv.verifier-release-pin' as const;
export const ARV_VERIFIER_RELEASE_SCHEMA_VERSION = 1 as const;
export const ARV_VERIFIER_RELEASE_STATES = [
  'BOOTSTRAP_ACCEPTED',
  'UPDATE_ACCEPTED',
  'REPLAY_ACCEPTED',
  'TRUST_STATE_INVALID',
  'TRUST_STATE_HASH_MISMATCH',
  'ROOT_MISMATCH',
  'POLICY_INVALID',
  'POLICY_UNAUTHORIZED',
  'POLICY_ROLLBACK',
  'POLICY_GAP',
  'POLICY_EQUIVOCATION',
  'MANIFEST_INVALID',
  'MANIFEST_UNAUTHORIZED',
  'BUILD_ATTESTATION_INVALID',
  'BUILD_QUORUM_NOT_MET',
  'BOOTSTRAP_PIN_REQUIRED',
  'BOOTSTRAP_PIN_MISMATCH',
  'CURRENT_PIN_REQUIRED',
  'CURRENT_PIN_INVALID',
  'CURRENT_PIN_HASH_REQUIRED',
  'CURRENT_PIN_HASH_MISMATCH',
  'RELEASE_ROLLBACK',
  'RELEASE_GAP',
  'RELEASE_EQUIVOCATION',
  'RELEASE_PREDECESSOR_MISMATCH',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;
export const ARV_VERIFIER_RELEASE_OPERATIONS = ['NONE', 'BOOTSTRAP', 'UPDATE', 'REPLAY'] as const;
export const ARV_VERIFIER_RELEASE_CODES = [
  'TRUST_STATE_SCHEMA_INVALID',
  'TRUST_STATE_PIN_REQUIRED',
  'TRUST_STATE_PIN_MISMATCH',
  'TRUST_ROOT_SCHEMA_INVALID',
  'TRUST_ROOT_HASH_MISMATCH',
  'TRUST_ROOT_VERSION_MISMATCH',
  'RELEASE_POLICY_SCHEMA_INVALID',
  'RELEASE_POLICY_ROOT_MISMATCH',
  'RELEASE_POLICY_SIGNATURE_INVALID',
  'RELEASE_POLICY_THRESHOLD_NOT_MET',
  'RELEASE_POLICY_TIME_INVALID',
  'RELEASE_MANIFEST_SCHEMA_INVALID',
  'RELEASE_MANIFEST_POLICY_MISMATCH',
  'RELEASE_MANIFEST_SIGNATURE_INVALID',
  'RELEASE_MANIFEST_THRESHOLD_NOT_MET',
  'RELEASE_MANIFEST_TIME_INVALID',
  'BUILD_ATTESTATION_SCHEMA_INVALID',
  'BUILD_ATTESTATION_BINDING_MISMATCH',
  'BUILD_ATTESTATION_SIGNATURE_INVALID',
  'BUILD_ATTESTATION_THRESHOLD_NOT_MET',
  'BOOTSTRAP_RELEASE_HASH_REQUIRED',
  'BOOTSTRAP_RELEASE_HASH_MISMATCH',
  'CURRENT_RELEASE_PIN_REQUIRED',
  'CURRENT_RELEASE_PIN_SCHEMA_INVALID',
  'CURRENT_RELEASE_PIN_HASH_REQUIRED',
  'CURRENT_RELEASE_PIN_HASH_MISMATCH',
  'VERIFIER_ID_MISMATCH',
  'RELEASE_SEQUENCE_ROLLBACK',
  'RELEASE_SEQUENCE_GAP',
  'RELEASE_HASH_EQUIVOCATION',
  'RELEASE_PREDECESSOR_HASH_MISMATCH',
  'RELEASE_POLICY_VERSION_ROLLBACK',
  'RELEASE_POLICY_VERSION_GAP',
  'RELEASE_POLICY_HASH_EQUIVOCATION',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVVerifierReleaseStateV1 = typeof ARV_VERIFIER_RELEASE_STATES[number];
export type ARVVerifierReleaseOperationV1 = typeof ARV_VERIFIER_RELEASE_OPERATIONS[number];
export type ARVVerifierReleaseCodeV1 = typeof ARV_VERIFIER_RELEASE_CODES[number];

export interface ARVVerifierReleasePublicKeyV1 {
  key_id: string;
  algorithm: 'Ed25519';
  public_key_base64: string;
  status: 'ACTIVE' | 'REVOKED' | 'RETIRED';
  valid_from: string;
  valid_until: string | null;
}

export interface ARVVerifierReleaseAuthorizationPolicyV1 {
  schema: typeof ARV_VERIFIER_RELEASE_POLICY_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RELEASE_SCHEMA_VERSION;
  policy_id: string;
  policy_version: number;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  release_threshold: number;
  builder_threshold: number;
  release_keys: ARVVerifierReleasePublicKeyV1[];
  builder_keys: ARVVerifierReleasePublicKeyV1[];
  root_authorizations: ARVTrustRootSignatureV1[];
}

export interface ARVVerifierReleaseArtifactV1 {
  path: string;
  media_type: string;
  bytes: number;
  sha256: string;
}

export interface ARVVerifierReleaseSignatureV1 {
  algorithm: 'Ed25519';
  key_id: string;
  signature_base64: string;
}

export interface ARVVerifierReleaseManifestV1 {
  schema: typeof ARV_VERIFIER_RELEASE_MANIFEST_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RELEASE_SCHEMA_VERSION;
  manifest_id: string;
  verifier_id: string;
  release_sequence: number;
  release_version: string;
  channel: 'STABLE' | 'SECURITY';
  platform: string;
  source_commit: string;
  source_tree_digest: string;
  build_recipe_digest: string;
  toolchain_digest: string;
  sbom_digest: string;
  artifact_set_digest: string;
  artifacts: ARVVerifierReleaseArtifactV1[];
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  previous_release_hash: string | null;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  signatures: ARVVerifierReleaseSignatureV1[];
}

export interface ARVVerifierBuildAttestationV1 {
  schema: typeof ARV_VERIFIER_BUILD_ATTESTATION_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RELEASE_SCHEMA_VERSION;
  attestation_id: string;
  builder_key_id: string;
  manifest_id: string;
  manifest_hash: string;
  verifier_id: string;
  release_sequence: number;
  source_commit: string;
  build_recipe_digest: string;
  toolchain_digest: string;
  artifact_set_digest: string;
  built_at: string;
  signature: ARVVerifierReleaseSignatureV1;
}

export interface ARVVerifierReleasePinV1 {
  schema: typeof ARV_VERIFIER_RELEASE_PIN_SCHEMA;
  schema_version: typeof ARV_VERIFIER_RELEASE_SCHEMA_VERSION;
  pin_id: string;
  verifier_id: string;
  generation: number;
  release_sequence: number;
  release_version: string;
  manifest_id: string;
  manifest_hash: string;
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  trusted_state_hash: string;
  installed_at: string;
  previous_pin_hash: string | null;
}

export interface VerifyARVVerifierReleaseOptionsV1 {
  trusted_verifier_state: unknown;
  expected_trusted_state_hash: string | null;
  trust_root: unknown;
  release_policy: unknown;
  release_manifest: unknown;
  build_attestations: unknown;
  current_release_pin: unknown | null;
  expected_current_release_pin_hash: string | null;
  bootstrap_release_hash: string | null;
  pin_id: string;
  installed_at: string;
  evaluated_at: string;
}

export interface ARVVerifierReleaseVerificationV1 {
  schema: 'arv.verifier-release-verification';
  schema_version: 1;
  accepted: boolean;
  state: ARVVerifierReleaseStateV1;
  operation: ARVVerifierReleaseOperationV1;
  trusted_state_hash: string | null;
  current_pin_hash: string | null;
  commit_precondition_hash: string | null;
  manifest_hash: string | null;
  next_pin_hash: string | null;
  next_pin: ARVVerifierReleasePinV1 | null;
  valid_builder_attestations: number;
  codes: ARVVerifierReleaseCodeV1[];
  authority_basis: 'PINNED_VERIFIER_TRUST_STATE';
  release_authority: 'ROOT_AUTHORIZED_RELEASE_POLICY';
  build_authority: 'INDEPENDENT_ATTESTATION_ONLY';
  storage_authority: 'NONE';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

const sha256Pattern = /^[a-f0-9]{64}$/;
const sourceCommitPattern = /^[a-f0-9]{40}$/;
const keyIdPattern = /^[a-f0-9]{24}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const policyIdPattern = /^ARV-VERIFIER-RELEASE-POLICY-[A-Z0-9-]+$/;
const manifestIdPattern = /^ARV-VERIFIER-RELEASE-MANIFEST-[A-Z0-9-]+$/;
const attestationIdPattern = /^ARV-VERIFIER-BUILD-ATTESTATION-[A-Z0-9-]+$/;
const verifierIdPattern = /^ARV-VERIFIER-[A-Z0-9-]+$/;
const pinIdPattern = /^ARV-VERIFIER-RELEASE-PIN-[A-Z0-9-]+$/;
const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const platformPattern = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const artifactPathPattern = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function object(value: unknown, location: string): Record<string, unknown> {
  if (!isObject(value)) throw new Error(`${location} must be an object`);
  return value;
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], location: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${location} fields are invalid`);
}

function timestamp(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !timestampPattern.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${location} must be a UTC ISO-8601 timestamp`);
  }
}

function positiveInteger(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || Number(value) < 1) throw new Error(`${location} must be a positive integer`);
}

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function assertSha256(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !sha256Pattern.test(value)) throw new Error(`${location} must be a lowercase SHA-256 digest`);
}

function base64Bytes(value: unknown, length: number, location: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${location} is invalid`);
  let decoded: Uint8Array;
  try {
    decoded = decodeBase64(value);
  } catch {
    throw new Error(`${location} is invalid`);
  }
  if (decoded.length !== length) throw new Error(`${location} has an invalid length`);
  return decoded;
}

function assertTimeWindow(validFrom: string, expiresAt: string, evaluatedAt: string, location: string): void {
  if (Date.parse(validFrom) >= Date.parse(expiresAt)) throw new Error(`${location} time window is invalid`);
  if (Date.parse(evaluatedAt) < Date.parse(validFrom) || Date.parse(evaluatedAt) >= Date.parse(expiresAt)) {
    throw new Error(`${location} is not valid at evaluation time`);
  }
}

function assertReleaseKey(value: unknown, location: string): ARVVerifierReleasePublicKeyV1 {
  const key = object(value, location);
  exactKeys(key, ['key_id', 'algorithm', 'public_key_base64', 'status', 'valid_from', 'valid_until'], location);
  if (typeof key.key_id !== 'string' || !keyIdPattern.test(key.key_id)) throw new Error(`${location}.key_id is invalid`);
  if (key.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  const publicKey = base64Bytes(key.public_key_base64, nacl.sign.publicKeyLength, `${location}.public_key_base64`);
  if (fingerprintARVTrustRootPublicKeyV1(publicKey) !== key.key_id) throw new Error(`${location}.key_id does not match public key`);
  if (!['ACTIVE', 'REVOKED', 'RETIRED'].includes(String(key.status))) throw new Error(`${location}.status is invalid`);
  timestamp(key.valid_from, `${location}.valid_from`);
  if (key.valid_until !== null) {
    timestamp(key.valid_until, `${location}.valid_until`);
    if (Date.parse(key.valid_until) <= Date.parse(String(key.valid_from))) throw new Error(`${location}.valid_until is invalid`);
  }
  return key as unknown as ARVVerifierReleasePublicKeyV1;
}

function assertSignature(value: unknown, location: string): ARVVerifierReleaseSignatureV1 {
  const signature = object(value, location);
  exactKeys(signature, ['algorithm', 'key_id', 'signature_base64'], location);
  if (signature.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  if (typeof signature.key_id !== 'string' || !keyIdPattern.test(signature.key_id)) throw new Error(`${location}.key_id is invalid`);
  base64Bytes(signature.signature_base64, nacl.sign.signatureLength, `${location}.signature_base64`);
  return signature as unknown as ARVVerifierReleaseSignatureV1;
}

export function assertARVVerifierReleaseAuthorizationPolicyV1(value: unknown): ARVVerifierReleaseAuthorizationPolicyV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const policy = object(value, '$release_policy');
  exactKeys(policy, [
    'schema', 'schema_version', 'policy_id', 'policy_version', 'root_id', 'root_version', 'root_epoch',
    'root_hash', 'issued_at', 'valid_from', 'expires_at', 'release_threshold', 'builder_threshold',
    'release_keys', 'builder_keys', 'root_authorizations'
  ], '$release_policy');
  if (policy.schema !== ARV_VERIFIER_RELEASE_POLICY_SCHEMA || policy.schema_version !== 1) throw new Error('$release_policy schema is invalid');
  if (typeof policy.policy_id !== 'string' || !policyIdPattern.test(policy.policy_id)) throw new Error('$release_policy.policy_id is invalid');
  positiveInteger(policy.policy_version, '$release_policy.policy_version');
  if (typeof policy.root_id !== 'string' || !/^ARV-ROOT-[A-Z0-9-]+$/.test(policy.root_id)) throw new Error('$release_policy.root_id is invalid');
  positiveInteger(policy.root_version, '$release_policy.root_version');
  positiveInteger(policy.root_epoch, '$release_policy.root_epoch');
  assertSha256(policy.root_hash, '$release_policy.root_hash');
  timestamp(policy.issued_at, '$release_policy.issued_at');
  timestamp(policy.valid_from, '$release_policy.valid_from');
  timestamp(policy.expires_at, '$release_policy.expires_at');
  if (Date.parse(String(policy.issued_at)) > Date.parse(String(policy.valid_from))) throw new Error('$release_policy timestamps are invalid');
  positiveInteger(policy.release_threshold, '$release_policy.release_threshold');
  positiveInteger(policy.builder_threshold, '$release_policy.builder_threshold');
  if (!Array.isArray(policy.release_keys) || policy.release_keys.length === 0) throw new Error('$release_policy.release_keys is invalid');
  if (!Array.isArray(policy.builder_keys) || policy.builder_keys.length === 0) throw new Error('$release_policy.builder_keys is invalid');
  const releaseKeys = policy.release_keys.map((item, index) => assertReleaseKey(item, `$release_policy.release_keys[${index}]`));
  const builderKeys = policy.builder_keys.map((item, index) => assertReleaseKey(item, `$release_policy.builder_keys[${index}]`));
  if (new Set(releaseKeys.map((key) => key.key_id)).size !== releaseKeys.length) throw new Error('$release_policy.release_keys contains duplicates');
  if (new Set(builderKeys.map((key) => key.key_id)).size !== builderKeys.length) throw new Error('$release_policy.builder_keys contains duplicates');
  if (Number(policy.release_threshold) > releaseKeys.length) throw new Error('$release_policy.release_threshold is impossible');
  if (Number(policy.builder_threshold) > builderKeys.length) throw new Error('$release_policy.builder_threshold is impossible');
  if (!Array.isArray(policy.root_authorizations) || policy.root_authorizations.length === 0) throw new Error('$release_policy.root_authorizations is invalid');
  policy.root_authorizations.map((item, index) => assertSignature(item, `$release_policy.root_authorizations[${index}]`));
  return policy as unknown as ARVVerifierReleaseAuthorizationPolicyV1;
}

function assertArtifact(value: unknown, index: number): ARVVerifierReleaseArtifactV1 {
  const location = `$release_manifest.artifacts[${index}]`;
  const artifact = object(value, location);
  exactKeys(artifact, ['path', 'media_type', 'bytes', 'sha256'], location);
  if (typeof artifact.path !== 'string' || !artifactPathPattern.test(artifact.path) || artifact.path.includes('..')) throw new Error(`${location}.path is invalid`);
  if (typeof artifact.media_type !== 'string' || artifact.media_type.length < 3) throw new Error(`${location}.media_type is invalid`);
  positiveInteger(artifact.bytes, `${location}.bytes`);
  assertSha256(artifact.sha256, `${location}.sha256`);
  return artifact as unknown as ARVVerifierReleaseArtifactV1;
}

export function canonicalARVVerifierArtifactSetV1(artifacts: ARVVerifierReleaseArtifactV1[]): string {
  const sorted = [...artifacts].sort((left, right) => left.path.localeCompare(right.path));
  return `ARV-VERIFIER-ARTIFACT-SET-v1\n${canonicalizeARVJsonV1(sorted)}`;
}

export function sha256ARVVerifierArtifactSetV1(artifacts: ARVVerifierReleaseArtifactV1[]): string {
  return sha256(canonicalARVVerifierArtifactSetV1(artifacts));
}

export function assertARVVerifierReleaseManifestV1(value: unknown): ARVVerifierReleaseManifestV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const manifest = object(value, '$release_manifest');
  exactKeys(manifest, [
    'schema', 'schema_version', 'manifest_id', 'verifier_id', 'release_sequence', 'release_version',
    'channel', 'platform', 'source_commit', 'source_tree_digest', 'build_recipe_digest', 'toolchain_digest',
    'sbom_digest', 'artifact_set_digest', 'artifacts', 'policy_id', 'policy_version', 'policy_hash',
    'root_id', 'root_version', 'root_epoch', 'root_hash', 'previous_release_hash', 'issued_at',
    'valid_from', 'expires_at', 'signatures'
  ], '$release_manifest');
  if (manifest.schema !== ARV_VERIFIER_RELEASE_MANIFEST_SCHEMA || manifest.schema_version !== 1) throw new Error('$release_manifest schema is invalid');
  if (typeof manifest.manifest_id !== 'string' || !manifestIdPattern.test(manifest.manifest_id)) throw new Error('$release_manifest.manifest_id is invalid');
  if (typeof manifest.verifier_id !== 'string' || !verifierIdPattern.test(manifest.verifier_id)) throw new Error('$release_manifest.verifier_id is invalid');
  positiveInteger(manifest.release_sequence, '$release_manifest.release_sequence');
  if (typeof manifest.release_version !== 'string' || !semverPattern.test(manifest.release_version)) throw new Error('$release_manifest.release_version is invalid');
  if (!['STABLE', 'SECURITY'].includes(String(manifest.channel))) throw new Error('$release_manifest.channel is invalid');
  if (typeof manifest.platform !== 'string' || !platformPattern.test(manifest.platform)) throw new Error('$release_manifest.platform is invalid');
  if (typeof manifest.source_commit !== 'string' || !sourceCommitPattern.test(manifest.source_commit)) throw new Error('$release_manifest.source_commit is invalid');
  for (const field of ['source_tree_digest', 'build_recipe_digest', 'toolchain_digest', 'sbom_digest', 'artifact_set_digest', 'policy_hash', 'root_hash']) {
    assertSha256(manifest[field], `$release_manifest.${field}`);
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error('$release_manifest.artifacts is invalid');
  const artifacts = manifest.artifacts.map((item, index) => assertArtifact(item, index));
  if (new Set(artifacts.map((item) => item.path)).size !== artifacts.length) throw new Error('$release_manifest.artifacts contains duplicate paths');
  if (sha256ARVVerifierArtifactSetV1(artifacts) !== manifest.artifact_set_digest) throw new Error('$release_manifest.artifact_set_digest is invalid');
  if (typeof manifest.policy_id !== 'string' || !policyIdPattern.test(manifest.policy_id)) throw new Error('$release_manifest.policy_id is invalid');
  positiveInteger(manifest.policy_version, '$release_manifest.policy_version');
  if (typeof manifest.root_id !== 'string' || !/^ARV-ROOT-[A-Z0-9-]+$/.test(manifest.root_id)) throw new Error('$release_manifest.root_id is invalid');
  positiveInteger(manifest.root_version, '$release_manifest.root_version');
  positiveInteger(manifest.root_epoch, '$release_manifest.root_epoch');
  if (Number(manifest.release_sequence) === 1 && manifest.previous_release_hash !== null) throw new Error('$release_manifest initial predecessor is invalid');
  if (Number(manifest.release_sequence) > 1) assertSha256(manifest.previous_release_hash, '$release_manifest.previous_release_hash');
  timestamp(manifest.issued_at, '$release_manifest.issued_at');
  timestamp(manifest.valid_from, '$release_manifest.valid_from');
  timestamp(manifest.expires_at, '$release_manifest.expires_at');
  if (Date.parse(String(manifest.issued_at)) > Date.parse(String(manifest.valid_from))) throw new Error('$release_manifest timestamps are invalid');
  if (!Array.isArray(manifest.signatures) || manifest.signatures.length === 0) throw new Error('$release_manifest.signatures is invalid');
  manifest.signatures.map((item, index) => assertSignature(item, `$release_manifest.signatures[${index}]`));
  return manifest as unknown as ARVVerifierReleaseManifestV1;
}

export function assertARVVerifierBuildAttestationV1(value: unknown): ARVVerifierBuildAttestationV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const attestation = object(value, '$build_attestation');
  exactKeys(attestation, [
    'schema', 'schema_version', 'attestation_id', 'builder_key_id', 'manifest_id', 'manifest_hash',
    'verifier_id', 'release_sequence', 'source_commit', 'build_recipe_digest', 'toolchain_digest',
    'artifact_set_digest', 'built_at', 'signature'
  ], '$build_attestation');
  if (attestation.schema !== ARV_VERIFIER_BUILD_ATTESTATION_SCHEMA || attestation.schema_version !== 1) throw new Error('$build_attestation schema is invalid');
  if (typeof attestation.attestation_id !== 'string' || !attestationIdPattern.test(attestation.attestation_id)) throw new Error('$build_attestation.attestation_id is invalid');
  if (typeof attestation.builder_key_id !== 'string' || !keyIdPattern.test(attestation.builder_key_id)) throw new Error('$build_attestation.builder_key_id is invalid');
  if (typeof attestation.manifest_id !== 'string' || !manifestIdPattern.test(attestation.manifest_id)) throw new Error('$build_attestation.manifest_id is invalid');
  assertSha256(attestation.manifest_hash, '$build_attestation.manifest_hash');
  if (typeof attestation.verifier_id !== 'string' || !verifierIdPattern.test(attestation.verifier_id)) throw new Error('$build_attestation.verifier_id is invalid');
  positiveInteger(attestation.release_sequence, '$build_attestation.release_sequence');
  if (typeof attestation.source_commit !== 'string' || !sourceCommitPattern.test(attestation.source_commit)) throw new Error('$build_attestation.source_commit is invalid');
  assertSha256(attestation.build_recipe_digest, '$build_attestation.build_recipe_digest');
  assertSha256(attestation.toolchain_digest, '$build_attestation.toolchain_digest');
  assertSha256(attestation.artifact_set_digest, '$build_attestation.artifact_set_digest');
  timestamp(attestation.built_at, '$build_attestation.built_at');
  const signature = assertSignature(attestation.signature, '$build_attestation.signature');
  if (signature.key_id !== attestation.builder_key_id) throw new Error('$build_attestation signature key mismatch');
  return attestation as unknown as ARVVerifierBuildAttestationV1;
}

export function assertARVVerifierReleasePinV1(value: unknown): ARVVerifierReleasePinV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const pin = object(value, '$release_pin');
  exactKeys(pin, [
    'schema', 'schema_version', 'pin_id', 'verifier_id', 'generation', 'release_sequence',
    'release_version', 'manifest_id', 'manifest_hash', 'policy_id', 'policy_version', 'policy_hash',
    'trusted_state_hash', 'installed_at', 'previous_pin_hash'
  ], '$release_pin');
  if (pin.schema !== ARV_VERIFIER_RELEASE_PIN_SCHEMA || pin.schema_version !== 1) throw new Error('$release_pin schema is invalid');
  if (typeof pin.pin_id !== 'string' || !pinIdPattern.test(pin.pin_id)) throw new Error('$release_pin.pin_id is invalid');
  if (typeof pin.verifier_id !== 'string' || !verifierIdPattern.test(pin.verifier_id)) throw new Error('$release_pin.verifier_id is invalid');
  positiveInteger(pin.generation, '$release_pin.generation');
  positiveInteger(pin.release_sequence, '$release_pin.release_sequence');
  if (typeof pin.release_version !== 'string' || !semverPattern.test(pin.release_version)) throw new Error('$release_pin.release_version is invalid');
  if (typeof pin.manifest_id !== 'string' || !manifestIdPattern.test(pin.manifest_id)) throw new Error('$release_pin.manifest_id is invalid');
  assertSha256(pin.manifest_hash, '$release_pin.manifest_hash');
  if (typeof pin.policy_id !== 'string' || !policyIdPattern.test(pin.policy_id)) throw new Error('$release_pin.policy_id is invalid');
  positiveInteger(pin.policy_version, '$release_pin.policy_version');
  assertSha256(pin.policy_hash, '$release_pin.policy_hash');
  assertSha256(pin.trusted_state_hash, '$release_pin.trusted_state_hash');
  timestamp(pin.installed_at, '$release_pin.installed_at');
  if (Number(pin.generation) === 1 && pin.previous_pin_hash !== null) throw new Error('$release_pin initial predecessor is invalid');
  if (Number(pin.generation) > 1) assertSha256(pin.previous_pin_hash, '$release_pin.previous_pin_hash');
  return pin as unknown as ARVVerifierReleasePinV1;
}

export function canonicalARVVerifierReleasePolicySigningPayloadV1(policy: ARVVerifierReleaseAuthorizationPolicyV1): string {
  const { root_authorizations: _rootAuthorizations, ...unsigned } = policy;
  return `ARV-VERIFIER-RELEASE-POLICY-v1\n${canonicalizeARVJsonV1(unsigned)}`;
}

export function canonicalARVVerifierReleaseManifestSigningPayloadV1(manifest: ARVVerifierReleaseManifestV1): string {
  const { signatures: _signatures, ...unsigned } = manifest;
  return `ARV-VERIFIER-RELEASE-MANIFEST-v1\n${canonicalizeARVJsonV1(unsigned)}`;
}

export function canonicalARVVerifierBuildAttestationSigningPayloadV1(attestation: ARVVerifierBuildAttestationV1): string {
  const { signature: _signature, ...unsigned } = attestation;
  return `ARV-VERIFIER-BUILD-ATTESTATION-v1\n${canonicalizeARVJsonV1(unsigned)}`;
}

export function sha256ARVVerifierReleasePolicyV1(policy: ARVVerifierReleaseAuthorizationPolicyV1): string {
  const normalized = {
    signing_payload: canonicalARVVerifierReleasePolicySigningPayloadV1(policy),
    root_authorizations: [...policy.root_authorizations].sort((left, right) => left.key_id.localeCompare(right.key_id))
  };
  return sha256(`ARV-VERIFIER-RELEASE-POLICY-OBJECT-v1\n${canonicalizeARVJsonV1(normalized)}`);
}

export function sha256ARVVerifierReleaseManifestV1(manifest: ARVVerifierReleaseManifestV1): string {
  const normalized = {
    signing_payload: canonicalARVVerifierReleaseManifestSigningPayloadV1(manifest),
    signatures: [...manifest.signatures].sort((left, right) => left.key_id.localeCompare(right.key_id))
  };
  return sha256(`ARV-VERIFIER-RELEASE-MANIFEST-OBJECT-v1\n${canonicalizeARVJsonV1(normalized)}`);
}

export function sha256ARVVerifierReleasePinV1(pin: ARVVerifierReleasePinV1): string {
  return sha256(`ARV-VERIFIER-RELEASE-PIN-v1\n${canonicalizeARVJsonV1(pin)}`);
}

function keyActiveAt(key: { status: string; valid_from: string; valid_until: string | null }, evaluatedAt: string): boolean {
  return key.status === 'ACTIVE' && Date.parse(evaluatedAt) >= Date.parse(key.valid_from) &&
    (key.valid_until === null || Date.parse(evaluatedAt) < Date.parse(key.valid_until));
}

function verifyDetached(payload: string, signature: ARVVerifierReleaseSignatureV1, publicKeyBase64: string): boolean {
  const publicKey = base64Bytes(publicKeyBase64, nacl.sign.publicKeyLength, '$public_key');
  const signatureBytes = base64Bytes(signature.signature_base64, nacl.sign.signatureLength, '$signature');
  return nacl.sign.detached.verify(Buffer.from(payload, 'utf8'), signatureBytes, publicKey);
}

function verifyRootAuthorizations(
  policy: ARVVerifierReleaseAuthorizationPolicyV1,
  root: ARVTrustRootV1,
  evaluatedAt: string
): number {
  const payload = canonicalARVVerifierReleasePolicySigningPayloadV1(policy);
  const valid = new Set<string>();
  for (const signature of policy.root_authorizations) {
    const key = root.keys.find((candidate) => candidate.key_id === signature.key_id);
    if (!key || !key.roles.includes('ROOT') || !keyActiveAt(key, evaluatedAt)) continue;
    if (verifyDetached(payload, signature, key.public_key_base64)) valid.add(key.key_id);
  }
  return valid.size;
}

function verifyReleaseSignatures(
  manifest: ARVVerifierReleaseManifestV1,
  policy: ARVVerifierReleaseAuthorizationPolicyV1,
  evaluatedAt: string
): number {
  const payload = canonicalARVVerifierReleaseManifestSigningPayloadV1(manifest);
  const valid = new Set<string>();
  for (const signature of manifest.signatures) {
    const key = policy.release_keys.find((candidate) => candidate.key_id === signature.key_id);
    if (!key || !keyActiveAt(key, evaluatedAt)) continue;
    if (verifyDetached(payload, signature, key.public_key_base64)) valid.add(key.key_id);
  }
  return valid.size;
}

function verifyBuildAttestations(
  attestations: ARVVerifierBuildAttestationV1[],
  manifest: ARVVerifierReleaseManifestV1,
  manifestHash: string,
  policy: ARVVerifierReleaseAuthorizationPolicyV1,
  evaluatedAt: string
): { valid: number; bindingMismatch: boolean; invalidSignature: boolean } {
  const valid = new Set<string>();
  let bindingMismatch = false;
  let invalidSignature = false;
  for (const attestation of attestations) {
    const bound = attestation.manifest_id === manifest.manifest_id &&
      attestation.manifest_hash === manifestHash &&
      attestation.verifier_id === manifest.verifier_id &&
      attestation.release_sequence === manifest.release_sequence &&
      attestation.source_commit === manifest.source_commit &&
      attestation.build_recipe_digest === manifest.build_recipe_digest &&
      attestation.toolchain_digest === manifest.toolchain_digest &&
      attestation.artifact_set_digest === manifest.artifact_set_digest;
    if (!bound) {
      bindingMismatch = true;
      continue;
    }
    const key = policy.builder_keys.find((candidate) => candidate.key_id === attestation.builder_key_id);
    if (!key || !keyActiveAt(key, evaluatedAt)) {
      invalidSignature = true;
      continue;
    }
    if (!verifyDetached(canonicalARVVerifierBuildAttestationSigningPayloadV1(attestation), attestation.signature, key.public_key_base64)) {
      invalidSignature = true;
      continue;
    }
    valid.add(key.key_id);
  }
  return { valid: valid.size, bindingMismatch, invalidSignature };
}

function result(
  accepted: boolean,
  state: ARVVerifierReleaseStateV1,
  operation: ARVVerifierReleaseOperationV1,
  codes: ARVVerifierReleaseCodeV1[],
  trustedStateHash: string | null,
  currentPinHash: string | null,
  commitPreconditionHash: string | null,
  manifestHash: string | null,
  nextPin: ARVVerifierReleasePinV1 | null,
  validBuilders: number
): ARVVerifierReleaseVerificationV1 {
  return {
    schema: 'arv.verifier-release-verification',
    schema_version: 1,
    accepted,
    state,
    operation,
    trusted_state_hash: trustedStateHash,
    current_pin_hash: currentPinHash,
    commit_precondition_hash: commitPreconditionHash,
    manifest_hash: manifestHash,
    next_pin_hash: nextPin ? sha256ARVVerifierReleasePinV1(nextPin) : null,
    next_pin: nextPin,
    valid_builder_attestations: validBuilders,
    codes: Array.from(new Set(codes)).sort(),
    authority_basis: 'PINNED_VERIFIER_TRUST_STATE',
    release_authority: 'ROOT_AUTHORIZED_RELEASE_POLICY',
    build_authority: 'INDEPENDENT_ATTESTATION_ONLY',
    storage_authority: 'NONE',
    transport_authority: 'NONE',
    material_truth: 'NOT_EVALUATED'
  };
}

export function verifyARVVerifierReleaseV1(options: VerifyARVVerifierReleaseOptionsV1): ARVVerifierReleaseVerificationV1 {
  let trustedState: ARVVerifierTrustStateV1;
  let trustedStateHash: string | null = null;
  let root: ARVTrustRootV1;
  let policy: ARVVerifierReleaseAuthorizationPolicyV1;
  let manifest: ARVVerifierReleaseManifestV1;
  let manifestHash: string | null = null;
  let currentPin: ARVVerifierReleasePinV1 | null = null;
  let currentPinHash: string | null = null;
  try {
    assertNoARVPrivateKeyMaterialV1(options);
  } catch {
    return result(false, 'PRIVATE_KEY_MATERIAL_FORBIDDEN', 'NONE', ['PRIVATE_KEY_MATERIAL_FORBIDDEN'], null, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  timestamp(options.evaluated_at, '$options.evaluated_at');
  timestamp(options.installed_at, '$options.installed_at');
  if (typeof options.pin_id !== 'string' || !pinIdPattern.test(options.pin_id)) {
    return result(false, 'CURRENT_PIN_INVALID', 'NONE', ['CURRENT_RELEASE_PIN_SCHEMA_INVALID'], null, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  try {
    trustedState = assertARVVerifierTrustStateV1(options.trusted_verifier_state);
    trustedStateHash = sha256ARVVerifierTrustStateV1(trustedState);
  } catch {
    return result(false, 'TRUST_STATE_INVALID', 'NONE', ['TRUST_STATE_SCHEMA_INVALID'], null, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  if (options.expected_trusted_state_hash === null) {
    return result(false, 'TRUST_STATE_HASH_MISMATCH', 'NONE', ['TRUST_STATE_PIN_REQUIRED'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  if (options.expected_trusted_state_hash !== trustedStateHash) {
    return result(false, 'TRUST_STATE_HASH_MISMATCH', 'NONE', ['TRUST_STATE_PIN_MISMATCH'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  try {
    root = assertARVTrustRootV1(options.trust_root);
  } catch {
    return result(false, 'ROOT_MISMATCH', 'NONE', ['TRUST_ROOT_SCHEMA_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  const rootHash = sha256ARVTrustRootV1(root);
  if (rootHash !== trustedState.root_hash) {
    return result(false, 'ROOT_MISMATCH', 'NONE', ['TRUST_ROOT_HASH_MISMATCH'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  if (root.root_id !== trustedState.root_id || root.root_version !== trustedState.root_version || root.epoch !== trustedState.root_epoch) {
    return result(false, 'ROOT_MISMATCH', 'NONE', ['TRUST_ROOT_VERSION_MISMATCH'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  try {
    policy = assertARVVerifierReleaseAuthorizationPolicyV1(options.release_policy);
  } catch {
    return result(false, 'POLICY_INVALID', 'NONE', ['RELEASE_POLICY_SCHEMA_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  if (policy.root_id !== root.root_id || policy.root_version !== root.root_version || policy.root_epoch !== root.epoch || policy.root_hash !== rootHash) {
    return result(false, 'POLICY_UNAUTHORIZED', 'NONE', ['RELEASE_POLICY_ROOT_MISMATCH'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  try {
    assertTimeWindow(policy.valid_from, policy.expires_at, options.evaluated_at, '$release_policy');
  } catch {
    return result(false, 'POLICY_UNAUTHORIZED', 'NONE', ['RELEASE_POLICY_TIME_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  const rootSignatures = verifyRootAuthorizations(policy, root, options.evaluated_at);
  if (rootSignatures < root.threshold) {
    return result(false, 'POLICY_UNAUTHORIZED', 'NONE', ['RELEASE_POLICY_THRESHOLD_NOT_MET'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  try {
    manifest = assertARVVerifierReleaseManifestV1(options.release_manifest);
    manifestHash = sha256ARVVerifierReleaseManifestV1(manifest);
  } catch {
    return result(false, 'MANIFEST_INVALID', 'NONE', ['RELEASE_MANIFEST_SCHEMA_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, null, null, 0);
  }
  const policyHash = sha256ARVVerifierReleasePolicyV1(policy);
  if (manifest.policy_id !== policy.policy_id || manifest.policy_version !== policy.policy_version || manifest.policy_hash !== policyHash ||
      manifest.root_id !== root.root_id || manifest.root_version !== root.root_version || manifest.root_epoch !== root.epoch || manifest.root_hash !== rootHash) {
    return result(false, 'MANIFEST_UNAUTHORIZED', 'NONE', ['RELEASE_MANIFEST_POLICY_MISMATCH'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, 0);
  }
  try {
    assertTimeWindow(manifest.valid_from, manifest.expires_at, options.evaluated_at, '$release_manifest');
  } catch {
    return result(false, 'MANIFEST_UNAUTHORIZED', 'NONE', ['RELEASE_MANIFEST_TIME_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, 0);
  }
  const releaseSignatures = verifyReleaseSignatures(manifest, policy, options.evaluated_at);
  if (releaseSignatures < policy.release_threshold) {
    return result(false, 'MANIFEST_UNAUTHORIZED', 'NONE', ['RELEASE_MANIFEST_THRESHOLD_NOT_MET'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, 0);
  }
  if (!Array.isArray(options.build_attestations)) {
    return result(false, 'BUILD_ATTESTATION_INVALID', 'NONE', ['BUILD_ATTESTATION_SCHEMA_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, 0);
  }
  let attestations: ARVVerifierBuildAttestationV1[];
  try {
    attestations = options.build_attestations.map((item) => assertARVVerifierBuildAttestationV1(item));
  } catch {
    return result(false, 'BUILD_ATTESTATION_INVALID', 'NONE', ['BUILD_ATTESTATION_SCHEMA_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, 0);
  }
  const builders = verifyBuildAttestations(attestations, manifest, manifestHash, policy, options.evaluated_at);
  if (builders.valid < policy.builder_threshold) {
    const codes: ARVVerifierReleaseCodeV1[] = ['BUILD_ATTESTATION_THRESHOLD_NOT_MET'];
    if (builders.bindingMismatch) codes.push('BUILD_ATTESTATION_BINDING_MISMATCH');
    if (builders.invalidSignature) codes.push('BUILD_ATTESTATION_SIGNATURE_INVALID');
    return result(false, 'BUILD_QUORUM_NOT_MET', 'NONE', codes, trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, builders.valid);
  }
  if (options.current_release_pin === null) {
    if (options.expected_current_release_pin_hash !== null) {
      return result(false, 'CURRENT_PIN_INVALID', 'NONE', ['CURRENT_RELEASE_PIN_REQUIRED'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, builders.valid);
    }
    if (options.bootstrap_release_hash === null) {
      return result(false, 'BOOTSTRAP_PIN_REQUIRED', 'NONE', ['BOOTSTRAP_RELEASE_HASH_REQUIRED'], trustedStateHash, null, null, manifestHash, null, builders.valid);
    }
    if (options.bootstrap_release_hash !== manifestHash) {
      return result(false, 'BOOTSTRAP_PIN_MISMATCH', 'NONE', ['BOOTSTRAP_RELEASE_HASH_MISMATCH'], trustedStateHash, null, null, manifestHash, null, builders.valid);
    }
    const nextPin: ARVVerifierReleasePinV1 = {
      schema: ARV_VERIFIER_RELEASE_PIN_SCHEMA,
      schema_version: 1,
      pin_id: options.pin_id,
      verifier_id: manifest.verifier_id,
      generation: 1,
      release_sequence: manifest.release_sequence,
      release_version: manifest.release_version,
      manifest_id: manifest.manifest_id,
      manifest_hash: manifestHash,
      policy_id: policy.policy_id,
      policy_version: policy.policy_version,
      policy_hash: policyHash,
      trusted_state_hash: trustedStateHash,
      installed_at: options.installed_at,
      previous_pin_hash: null
    };
    return result(true, 'BOOTSTRAP_ACCEPTED', 'BOOTSTRAP', [], trustedStateHash, null, null, manifestHash, nextPin, builders.valid);
  }
  try {
    currentPin = assertARVVerifierReleasePinV1(options.current_release_pin);
    currentPinHash = sha256ARVVerifierReleasePinV1(currentPin);
  } catch {
    return result(false, 'CURRENT_PIN_INVALID', 'NONE', ['CURRENT_RELEASE_PIN_SCHEMA_INVALID'], trustedStateHash, null, options.expected_current_release_pin_hash, manifestHash, null, builders.valid);
  }
  if (options.expected_current_release_pin_hash === null) {
    return result(false, 'CURRENT_PIN_HASH_REQUIRED', 'NONE', ['CURRENT_RELEASE_PIN_HASH_REQUIRED'], trustedStateHash, currentPinHash, null, manifestHash, null, builders.valid);
  }
  if (options.expected_current_release_pin_hash !== currentPinHash) {
    return result(false, 'CURRENT_PIN_HASH_MISMATCH', 'NONE', ['CURRENT_RELEASE_PIN_HASH_MISMATCH'], trustedStateHash, currentPinHash, options.expected_current_release_pin_hash, manifestHash, null, builders.valid);
  }
  if (currentPin.verifier_id !== manifest.verifier_id) {
    return result(false, 'CURRENT_PIN_INVALID', 'NONE', ['VERIFIER_ID_MISMATCH'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (manifest.release_sequence < currentPin.release_sequence) {
    return result(false, 'RELEASE_ROLLBACK', 'NONE', ['RELEASE_SEQUENCE_ROLLBACK'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (manifest.release_sequence === currentPin.release_sequence) {
    if (manifestHash !== currentPin.manifest_hash) {
      return result(false, 'RELEASE_EQUIVOCATION', 'NONE', ['RELEASE_HASH_EQUIVOCATION'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
    }
    return result(true, 'REPLAY_ACCEPTED', 'REPLAY', [], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (manifest.release_sequence !== currentPin.release_sequence + 1) {
    return result(false, 'RELEASE_GAP', 'NONE', ['RELEASE_SEQUENCE_GAP'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (manifest.previous_release_hash !== currentPin.manifest_hash) {
    return result(false, 'RELEASE_PREDECESSOR_MISMATCH', 'NONE', ['RELEASE_PREDECESSOR_HASH_MISMATCH'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (policy.policy_version < currentPin.policy_version) {
    return result(false, 'POLICY_ROLLBACK', 'NONE', ['RELEASE_POLICY_VERSION_ROLLBACK'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (policy.policy_version > currentPin.policy_version + 1) {
    return result(false, 'POLICY_GAP', 'NONE', ['RELEASE_POLICY_VERSION_GAP'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  if (policy.policy_version === currentPin.policy_version && policyHash !== currentPin.policy_hash) {
    return result(false, 'POLICY_EQUIVOCATION', 'NONE', ['RELEASE_POLICY_HASH_EQUIVOCATION'], trustedStateHash, currentPinHash, currentPinHash, manifestHash, null, builders.valid);
  }
  const nextPin: ARVVerifierReleasePinV1 = {
    schema: ARV_VERIFIER_RELEASE_PIN_SCHEMA,
    schema_version: 1,
    pin_id: currentPin.pin_id,
    verifier_id: manifest.verifier_id,
    generation: currentPin.generation + 1,
    release_sequence: manifest.release_sequence,
    release_version: manifest.release_version,
    manifest_id: manifest.manifest_id,
    manifest_hash: manifestHash,
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    policy_hash: policyHash,
    trusted_state_hash: trustedStateHash,
    installed_at: options.installed_at,
    previous_pin_hash: currentPinHash
  };
  return result(true, 'UPDATE_ACCEPTED', 'UPDATE', [], trustedStateHash, currentPinHash, currentPinHash, manifestHash, nextPin, builders.valid);
}
