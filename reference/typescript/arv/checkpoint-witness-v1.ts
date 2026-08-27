import crypto from 'crypto';
import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';
import {
  ARVTrustRootSignatureV1,
  ARVTrustRootV1,
  assertARVTrustRootV1,
  assertNoARVPrivateKeyMaterialV1,
  sha256ARVTrustRootV1
} from './trust-root-lifecycle-v1';
import {
  ARVTrustRegistryCheckpointV1,
  VerifyARVTrustRegistryCheckpointOptionsV1,
  assertARVTrustRegistryCheckpointV1,
  sha256ARVTrustRegistryCheckpointV1,
  verifyARVTrustRegistryCheckpointV1
} from './trust-registry-checkpoint-v1';

export const ARV_CHECKPOINT_WITNESS_POLICY_SCHEMA = 'arv.checkpoint-witness-policy' as const;
export const ARV_CHECKPOINT_WITNESS_OBSERVATION_SCHEMA = 'arv.checkpoint-witness-observation' as const;
export const ARV_CHECKPOINT_WITNESS_BUNDLE_SCHEMA = 'arv.checkpoint-witness-bundle' as const;
export const ARV_CHECKPOINT_WITNESS_SCHEMA_VERSION = 1 as const;
export const ARV_CHECKPOINT_WITNESS_KEY_STATUSES = ['ACTIVE', 'REVOKED'] as const;
export const ARV_CHECKPOINT_WITNESS_STATES = [
  'WITNESS_QUORUM_VALID',
  'UNDERLYING_CHECKPOINT_INVALID',
  'WITNESS_POLICY_INVALID',
  'WITNESS_POLICY_UNTRUSTED',
  'WITNESS_QUORUM_INSUFFICIENT',
  'WITNESS_SIGNATURE_INVALID',
  'WITNESS_STALE',
  'WITNESS_ROLLBACK',
  'WITNESS_GAP',
  'SPLIT_VIEW_DETECTED',
  'WITNESS_EQUIVOCATION',
  'WITNESS_INVALID'
] as const;
export const ARV_CHECKPOINT_WITNESS_CODES = [
  'UNDERLYING_CHECKPOINT_REJECTED',
  'WITNESS_POLICY_SCHEMA_INVALID',
  'WITNESS_POLICY_ROOT_BINDING_MISMATCH',
  'WITNESS_POLICY_NOT_ACTIVE',
  'WITNESS_POLICY_EXPIRED',
  'WITNESS_POLICY_ROOT_THRESHOLD_NOT_MET',
  'WITNESS_POLICY_SIGNATURE_INVALID',
  'WITNESS_BUNDLE_SCHEMA_INVALID',
  'WITNESS_OBSERVATION_SCHEMA_INVALID',
  'WITNESS_NOT_AUTHORIZED',
  'WITNESS_NOT_ACTIVE',
  'WITNESS_OBSERVATION_TIME_INVALID',
  'WITNESS_OBSERVATION_STALE',
  'WITNESS_SIGNATURE_INVALID',
  'WITNESS_THRESHOLD_NOT_MET',
  'WITNESS_CHECKPOINT_BINDING_MISMATCH',
  'WITNESS_SPLIT_VIEW_DETECTED',
  'WITNESS_EQUIVOCATION_DETECTED',
  'WITNESS_SEQUENCE_ROLLBACK',
  'WITNESS_SEQUENCE_GAP',
  'WITNESS_PREDECESSOR_MISMATCH',
  'TRUSTED_WITNESS_CHECKPOINT_INVALID',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVCheckpointWitnessKeyStatusV1 = typeof ARV_CHECKPOINT_WITNESS_KEY_STATUSES[number];
export type ARVCheckpointWitnessStateV1 = typeof ARV_CHECKPOINT_WITNESS_STATES[number];
export type ARVCheckpointWitnessCodeV1 = typeof ARV_CHECKPOINT_WITNESS_CODES[number];

export interface ARVCheckpointWitnessKeyV1 {
  witness_key_id: string;
  algorithm: 'Ed25519';
  public_key_base64: string;
  status: ARVCheckpointWitnessKeyStatusV1;
  valid_from: string;
  valid_until: string | null;
}

export interface ARVCheckpointWitnessPolicyV1 {
  schema: typeof ARV_CHECKPOINT_WITNESS_POLICY_SCHEMA;
  schema_version: typeof ARV_CHECKPOINT_WITNESS_SCHEMA_VERSION;
  policy_id: string;
  policy_version: number;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  threshold: number;
  max_observation_age_seconds: number;
  witnesses: ARVCheckpointWitnessKeyV1[];
  signatures: ARVTrustRootSignatureV1[];
}

export interface ARVCheckpointWitnessSignatureV1 {
  algorithm: 'Ed25519';
  signature_base64: string;
}

export interface ARVCheckpointWitnessObservationV1 {
  schema: typeof ARV_CHECKPOINT_WITNESS_OBSERVATION_SCHEMA;
  schema_version: typeof ARV_CHECKPOINT_WITNESS_SCHEMA_VERSION;
  observation_id: string;
  witness_policy_id: string;
  witness_policy_version: number;
  witness_key_id: string;
  checkpoint_id: string;
  checkpoint_hash: string;
  sequence: number;
  registry_id: string;
  registry_version: number;
  registry_digest: string;
  previous_checkpoint_hash: string | null;
  observed_at: string;
  signature: ARVCheckpointWitnessSignatureV1;
}

export interface ARVCheckpointWitnessBundleV1 {
  schema: typeof ARV_CHECKPOINT_WITNESS_BUNDLE_SCHEMA;
  schema_version: typeof ARV_CHECKPOINT_WITNESS_SCHEMA_VERSION;
  bundle_id: string;
  witness_policy_id: string;
  witness_policy_version: number;
  checkpoint_id: string;
  checkpoint_hash: string;
  sequence: number;
  observations: ARVCheckpointWitnessObservationV1[];
}

export interface ARVTrustedWitnessCheckpointV1 {
  checkpoint_id: string;
  checkpoint_hash: string;
  sequence: number;
  witness_policy_id: string;
  witness_policy_version: number;
  observed_at: string;
}

export interface ARVCheckpointWitnessVerificationV1 {
  schema: 'arv.checkpoint-witness-verification';
  schema_version: 1;
  accepted: boolean;
  state: ARVCheckpointWitnessStateV1;
  checkpoint_hash: string | null;
  trusted_witness_checkpoint: ARVTrustedWitnessCheckpointV1 | null;
  witness_count: number;
  codes: ARVCheckpointWitnessCodeV1[];
  authority_basis: 'PINNED_TRUST_ROOT';
  witness_authority: 'DETECTION_ONLY';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

export interface VerifyARVCheckpointWitnessOptionsV1 extends VerifyARVTrustRegistryCheckpointOptionsV1 {
  witness_policy: unknown;
  witness_bundle: unknown;
  trusted_witness_checkpoint: unknown | null;
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const keyIdPattern = /^[a-f0-9]{24}$/;
const policyIdPattern = /^ARV-WITNESS-POLICY-[A-Z0-9-]+$/;
const observationIdPattern = /^ARV-WITNESS-OBSERVATION-[A-Z0-9-]+$/;
const bundleIdPattern = /^ARV-WITNESS-BUNDLE-[A-Z0-9-]+$/;
const checkpointIdPattern = /^ARV-TRUST-CHECKPOINT-[A-Z0-9-]+$/;
const registryIdPattern = /^ARV-TRUST-REGISTRY-[A-Z0-9-]+$/;
const rootIdPattern = /^ARV-ROOT-[A-Z0-9-]+$/;

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

function sha256(value: Uint8Array | string): string {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertSha256(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !sha256Pattern.test(value)) {
    throw new Error(`${location} must be a lowercase SHA-256 digest`);
  }
}

function decodeSignature(value: unknown, location: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${location} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64(value);
  } catch {
    throw new Error(`${location} is invalid`);
  }
  if (bytes.length !== nacl.sign.signatureLength) throw new Error(`${location} has an invalid length`);
  return bytes;
}

function assertRootSignature(value: unknown, index: number): ARVTrustRootSignatureV1 {
  const location = `$.signatures[${index}]`;
  const signature = object(value, location);
  exactKeys(signature, ['algorithm', 'key_id', 'signature_base64'], location);
  if (signature.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  if (typeof signature.key_id !== 'string' || !keyIdPattern.test(signature.key_id)) {
    throw new Error(`${location}.key_id is invalid`);
  }
  decodeSignature(signature.signature_base64, `${location}.signature_base64`);
  return signature as unknown as ARVTrustRootSignatureV1;
}

function assertWitnessKey(value: unknown, index: number): ARVCheckpointWitnessKeyV1 {
  const location = `$.witnesses[${index}]`;
  const key = object(value, location);
  exactKeys(key, ['witness_key_id', 'algorithm', 'public_key_base64', 'status', 'valid_from', 'valid_until'], location);
  if (typeof key.witness_key_id !== 'string' || !keyIdPattern.test(key.witness_key_id)) {
    throw new Error(`${location}.witness_key_id is invalid`);
  }
  if (key.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  if (!ARV_CHECKPOINT_WITNESS_KEY_STATUSES.includes(key.status as ARVCheckpointWitnessKeyStatusV1)) {
    throw new Error(`${location}.status is invalid`);
  }
  if (typeof key.public_key_base64 !== 'string') throw new Error(`${location}.public_key_base64 is invalid`);
  let publicKey: Uint8Array;
  try {
    publicKey = decodeBase64(key.public_key_base64);
  } catch {
    throw new Error(`${location}.public_key_base64 is invalid`);
  }
  if (publicKey.length !== nacl.sign.publicKeyLength) throw new Error(`${location}.public_key_base64 has an invalid length`);
  timestamp(key.valid_from, `${location}.valid_from`);
  if (key.valid_until !== null) {
    timestamp(key.valid_until, `${location}.valid_until`);
    if (Date.parse(key.valid_until) <= Date.parse(key.valid_from)) throw new Error(`${location}.valid_until is invalid`);
  }
  return key as unknown as ARVCheckpointWitnessKeyV1;
}

export function assertARVCheckpointWitnessPolicyV1(value: unknown): ARVCheckpointWitnessPolicyV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const policy = object(value, '$');
  exactKeys(policy, [
    'schema', 'schema_version', 'policy_id', 'policy_version', 'root_id', 'root_version', 'root_epoch',
    'root_hash', 'issued_at', 'valid_from', 'expires_at', 'threshold', 'max_observation_age_seconds',
    'witnesses', 'signatures'
  ], '$');
  if (policy.schema !== ARV_CHECKPOINT_WITNESS_POLICY_SCHEMA || policy.schema_version !== 1) {
    throw new Error('checkpoint witness policy schema is invalid');
  }
  if (typeof policy.policy_id !== 'string' || !policyIdPattern.test(policy.policy_id)) throw new Error('$.policy_id is invalid');
  positiveInteger(policy.policy_version, '$.policy_version');
  if (typeof policy.root_id !== 'string' || !rootIdPattern.test(policy.root_id)) throw new Error('$.root_id is invalid');
  positiveInteger(policy.root_version, '$.root_version');
  positiveInteger(policy.root_epoch, '$.root_epoch');
  assertSha256(policy.root_hash, '$.root_hash');
  timestamp(policy.issued_at, '$.issued_at');
  timestamp(policy.valid_from, '$.valid_from');
  timestamp(policy.expires_at, '$.expires_at');
  if (Date.parse(policy.valid_from) < Date.parse(policy.issued_at)) throw new Error('$.valid_from precedes issued_at');
  if (Date.parse(policy.expires_at) <= Date.parse(policy.valid_from)) throw new Error('$.expires_at is invalid');
  positiveInteger(policy.threshold, '$.threshold');
  positiveInteger(policy.max_observation_age_seconds, '$.max_observation_age_seconds');
  if (!Array.isArray(policy.witnesses) || policy.witnesses.length === 0) throw new Error('$.witnesses is invalid');
  const witnesses = policy.witnesses.map((entry, index) => assertWitnessKey(entry, index));
  if (new Set(witnesses.map((entry) => entry.witness_key_id)).size !== witnesses.length) {
    throw new Error('$.witnesses contains duplicate key identifiers');
  }
  if (Number(policy.threshold) > witnesses.filter((entry) => entry.status === 'ACTIVE').length) {
    throw new Error('$.threshold exceeds active witnesses');
  }
  if (!Array.isArray(policy.signatures) || policy.signatures.length === 0) throw new Error('$.signatures is invalid');
  const signatures = policy.signatures.map((entry, index) => assertRootSignature(entry, index));
  return { ...policy, witnesses, signatures } as unknown as ARVCheckpointWitnessPolicyV1;
}

function assertWitnessSignature(value: unknown, location: string): ARVCheckpointWitnessSignatureV1 {
  const signature = object(value, location);
  exactKeys(signature, ['algorithm', 'signature_base64'], location);
  if (signature.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  decodeSignature(signature.signature_base64, `${location}.signature_base64`);
  return signature as unknown as ARVCheckpointWitnessSignatureV1;
}

export function assertARVCheckpointWitnessObservationV1(value: unknown): ARVCheckpointWitnessObservationV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const observation = object(value, '$observation');
  exactKeys(observation, [
    'schema', 'schema_version', 'observation_id', 'witness_policy_id', 'witness_policy_version',
    'witness_key_id', 'checkpoint_id', 'checkpoint_hash', 'sequence', 'registry_id', 'registry_version',
    'registry_digest', 'previous_checkpoint_hash', 'observed_at', 'signature'
  ], '$observation');
  if (observation.schema !== ARV_CHECKPOINT_WITNESS_OBSERVATION_SCHEMA || observation.schema_version !== 1) {
    throw new Error('checkpoint witness observation schema is invalid');
  }
  if (typeof observation.observation_id !== 'string' || !observationIdPattern.test(observation.observation_id)) {
    throw new Error('$observation.observation_id is invalid');
  }
  if (typeof observation.witness_policy_id !== 'string' || !policyIdPattern.test(observation.witness_policy_id)) {
    throw new Error('$observation.witness_policy_id is invalid');
  }
  positiveInteger(observation.witness_policy_version, '$observation.witness_policy_version');
  if (typeof observation.witness_key_id !== 'string' || !keyIdPattern.test(observation.witness_key_id)) {
    throw new Error('$observation.witness_key_id is invalid');
  }
  if (typeof observation.checkpoint_id !== 'string' || !checkpointIdPattern.test(observation.checkpoint_id)) {
    throw new Error('$observation.checkpoint_id is invalid');
  }
  assertSha256(observation.checkpoint_hash, '$observation.checkpoint_hash');
  positiveInteger(observation.sequence, '$observation.sequence');
  if (typeof observation.registry_id !== 'string' || !registryIdPattern.test(observation.registry_id)) {
    throw new Error('$observation.registry_id is invalid');
  }
  positiveInteger(observation.registry_version, '$observation.registry_version');
  assertSha256(observation.registry_digest, '$observation.registry_digest');
  if (observation.sequence === 1 && observation.previous_checkpoint_hash !== null) {
    throw new Error('initial witness observation cannot have a predecessor');
  }
  if (observation.sequence > 1) assertSha256(observation.previous_checkpoint_hash, '$observation.previous_checkpoint_hash');
  timestamp(observation.observed_at, '$observation.observed_at');
  const signature = assertWitnessSignature(observation.signature, '$observation.signature');
  return { ...observation, signature } as unknown as ARVCheckpointWitnessObservationV1;
}

export function assertARVCheckpointWitnessBundleV1(value: unknown): ARVCheckpointWitnessBundleV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const bundle = object(value, '$bundle');
  exactKeys(bundle, [
    'schema', 'schema_version', 'bundle_id', 'witness_policy_id', 'witness_policy_version',
    'checkpoint_id', 'checkpoint_hash', 'sequence', 'observations'
  ], '$bundle');
  if (bundle.schema !== ARV_CHECKPOINT_WITNESS_BUNDLE_SCHEMA || bundle.schema_version !== 1) {
    throw new Error('checkpoint witness bundle schema is invalid');
  }
  if (typeof bundle.bundle_id !== 'string' || !bundleIdPattern.test(bundle.bundle_id)) throw new Error('$bundle.bundle_id is invalid');
  if (typeof bundle.witness_policy_id !== 'string' || !policyIdPattern.test(bundle.witness_policy_id)) {
    throw new Error('$bundle.witness_policy_id is invalid');
  }
  positiveInteger(bundle.witness_policy_version, '$bundle.witness_policy_version');
  if (typeof bundle.checkpoint_id !== 'string' || !checkpointIdPattern.test(bundle.checkpoint_id)) {
    throw new Error('$bundle.checkpoint_id is invalid');
  }
  assertSha256(bundle.checkpoint_hash, '$bundle.checkpoint_hash');
  positiveInteger(bundle.sequence, '$bundle.sequence');
  if (!Array.isArray(bundle.observations) || bundle.observations.length === 0) throw new Error('$bundle.observations is invalid');
  const observations = bundle.observations.map((entry) => assertARVCheckpointWitnessObservationV1(entry));
  return { ...bundle, observations } as unknown as ARVCheckpointWitnessBundleV1;
}

export function assertARVTrustedWitnessCheckpointV1(value: unknown): ARVTrustedWitnessCheckpointV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const trusted = object(value, '$trusted_witness_checkpoint');
  exactKeys(trusted, [
    'checkpoint_id', 'checkpoint_hash', 'sequence', 'witness_policy_id', 'witness_policy_version', 'observed_at'
  ], '$trusted_witness_checkpoint');
  if (typeof trusted.checkpoint_id !== 'string' || !checkpointIdPattern.test(trusted.checkpoint_id)) {
    throw new Error('$trusted_witness_checkpoint.checkpoint_id is invalid');
  }
  assertSha256(trusted.checkpoint_hash, '$trusted_witness_checkpoint.checkpoint_hash');
  positiveInteger(trusted.sequence, '$trusted_witness_checkpoint.sequence');
  if (typeof trusted.witness_policy_id !== 'string' || !policyIdPattern.test(trusted.witness_policy_id)) {
    throw new Error('$trusted_witness_checkpoint.witness_policy_id is invalid');
  }
  positiveInteger(trusted.witness_policy_version, '$trusted_witness_checkpoint.witness_policy_version');
  timestamp(trusted.observed_at, '$trusted_witness_checkpoint.observed_at');
  return trusted as unknown as ARVTrustedWitnessCheckpointV1;
}

function unsignedPolicy(policy: ARVCheckpointWitnessPolicyV1) {
  return {
    schema: policy.schema,
    schema_version: policy.schema_version,
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    root_id: policy.root_id,
    root_version: policy.root_version,
    root_epoch: policy.root_epoch,
    root_hash: policy.root_hash,
    issued_at: policy.issued_at,
    valid_from: policy.valid_from,
    expires_at: policy.expires_at,
    threshold: policy.threshold,
    max_observation_age_seconds: policy.max_observation_age_seconds,
    witnesses: [...policy.witnesses].sort((left, right) => left.witness_key_id.localeCompare(right.witness_key_id))
  };
}

export function canonicalARVCheckpointWitnessPolicySigningPayloadV1(policy: ARVCheckpointWitnessPolicyV1): string {
  return `ARV-CHECKPOINT-WITNESS-POLICY-v1\n${canonicalizeARVJsonV1(unsignedPolicy(policy))}`;
}

function unsignedObservation(observation: ARVCheckpointWitnessObservationV1) {
  return {
    schema: observation.schema,
    schema_version: observation.schema_version,
    observation_id: observation.observation_id,
    witness_policy_id: observation.witness_policy_id,
    witness_policy_version: observation.witness_policy_version,
    witness_key_id: observation.witness_key_id,
    checkpoint_id: observation.checkpoint_id,
    checkpoint_hash: observation.checkpoint_hash,
    sequence: observation.sequence,
    registry_id: observation.registry_id,
    registry_version: observation.registry_version,
    registry_digest: observation.registry_digest,
    previous_checkpoint_hash: observation.previous_checkpoint_hash,
    observed_at: observation.observed_at
  };
}

export function canonicalARVCheckpointWitnessObservationSigningPayloadV1(
  observation: ARVCheckpointWitnessObservationV1
): string {
  return `ARV-CHECKPOINT-WITNESS-OBSERVATION-v1\n${canonicalizeARVJsonV1(unsignedObservation(observation))}`;
}

function rootKeyUsableAt(root: ARVTrustRootV1, keyId: string, at: string) {
  const key = root.keys.find((candidate) => candidate.key_id === keyId);
  if (!key || key.status !== 'ACTIVE' || !key.roles.includes('ROOT')) return null;
  const time = Date.parse(at);
  if (time < Date.parse(key.valid_from)) return null;
  if (key.valid_until !== null && time >= Date.parse(key.valid_until)) return null;
  return key;
}

function verifyPolicyRootThreshold(root: ARVTrustRootV1, policy: ARVCheckpointWitnessPolicyV1) {
  const payload = Buffer.from(canonicalARVCheckpointWitnessPolicySigningPayloadV1(policy), 'utf8');
  const accepted = new Set<string>();
  let invalid = false;
  for (const signature of policy.signatures) {
    if (accepted.has(signature.key_id)) continue;
    const key = rootKeyUsableAt(root, signature.key_id, policy.issued_at);
    if (!key) {
      invalid = true;
      continue;
    }
    let signatureBytes: Uint8Array;
    let publicKey: Uint8Array;
    try {
      signatureBytes = decodeBase64(signature.signature_base64);
      publicKey = decodeBase64(key.public_key_base64);
    } catch {
      invalid = true;
      continue;
    }
    if (!nacl.sign.detached.verify(payload, signatureBytes, publicKey)) {
      invalid = true;
      continue;
    }
    accepted.add(signature.key_id);
  }
  return { count: accepted.size, invalid };
}

function result(
  state: ARVCheckpointWitnessStateV1,
  codes: ARVCheckpointWitnessCodeV1[],
  checkpointHash: string | null,
  trusted: ARVTrustedWitnessCheckpointV1 | null,
  witnessCount: number
): ARVCheckpointWitnessVerificationV1 {
  const accepted = state === 'WITNESS_QUORUM_VALID';
  return {
    schema: 'arv.checkpoint-witness-verification',
    schema_version: 1,
    accepted,
    state,
    checkpoint_hash: checkpointHash,
    trusted_witness_checkpoint: accepted ? trusted : null,
    witness_count: witnessCount,
    codes: Array.from(new Set(codes)),
    authority_basis: 'PINNED_TRUST_ROOT',
    witness_authority: 'DETECTION_ONLY',
    transport_authority: 'NONE',
    material_truth: 'NOT_EVALUATED'
  };
}

function trustedProjection(
  checkpoint: ARVTrustRegistryCheckpointV1,
  checkpointHash: string,
  policy: ARVCheckpointWitnessPolicyV1,
  observedAt: string
): ARVTrustedWitnessCheckpointV1 {
  return {
    checkpoint_id: checkpoint.checkpoint_id,
    checkpoint_hash: checkpointHash,
    sequence: checkpoint.sequence,
    witness_policy_id: policy.policy_id,
    witness_policy_version: policy.policy_version,
    observed_at: observedAt
  };
}

export function verifyARVCheckpointWitnessV1(
  options: VerifyARVCheckpointWitnessOptionsV1
): ARVCheckpointWitnessVerificationV1 {
  const underlying = verifyARVTrustRegistryCheckpointV1(options);
  if (!underlying.accepted || underlying.checkpoint_hash === null) {
    return result('UNDERLYING_CHECKPOINT_INVALID', ['UNDERLYING_CHECKPOINT_REJECTED'], underlying.checkpoint_hash, null, 0);
  }

  let root: ARVTrustRootV1;
  let checkpoint: ARVTrustRegistryCheckpointV1;
  let policy: ARVCheckpointWitnessPolicyV1;
  let bundle: ARVCheckpointWitnessBundleV1;
  let trusted: ARVTrustedWitnessCheckpointV1 | null = null;
  try {
    root = assertARVTrustRootV1(options.trust_root);
    checkpoint = assertARVTrustRegistryCheckpointV1(options.checkpoint);
    policy = assertARVCheckpointWitnessPolicyV1(options.witness_policy);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return result(
      'WITNESS_POLICY_INVALID',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'WITNESS_POLICY_SCHEMA_INVALID'],
      underlying.checkpoint_hash,
      null,
      0
    );
  }
  try {
    bundle = assertARVCheckpointWitnessBundleV1(options.witness_bundle);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return result(
      'WITNESS_INVALID',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'WITNESS_BUNDLE_SCHEMA_INVALID'],
      underlying.checkpoint_hash,
      null,
      0
    );
  }
  if (options.trusted_witness_checkpoint !== null) {
    try {
      trusted = assertARVTrustedWitnessCheckpointV1(options.trusted_witness_checkpoint);
    } catch (error) {
      const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
      return result(
        'WITNESS_INVALID',
        [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'TRUSTED_WITNESS_CHECKPOINT_INVALID'],
        underlying.checkpoint_hash,
        null,
        0
      );
    }
  }

  const rootHash = sha256ARVTrustRootV1(root);
  if (
    policy.root_id !== root.root_id || policy.root_version !== root.root_version ||
    policy.root_epoch !== root.epoch || policy.root_hash !== rootHash ||
    Date.parse(policy.issued_at) < Date.parse(root.valid_from) ||
    Date.parse(policy.expires_at) > Date.parse(root.expires_at)
  ) {
    return result('WITNESS_POLICY_UNTRUSTED', ['WITNESS_POLICY_ROOT_BINDING_MISMATCH'], underlying.checkpoint_hash, null, 0);
  }
  if (Date.parse(options.evaluated_at) < Date.parse(policy.valid_from)) {
    return result('WITNESS_POLICY_UNTRUSTED', ['WITNESS_POLICY_NOT_ACTIVE'], underlying.checkpoint_hash, null, 0);
  }
  if (Date.parse(options.evaluated_at) >= Date.parse(policy.expires_at)) {
    return result('WITNESS_POLICY_UNTRUSTED', ['WITNESS_POLICY_EXPIRED'], underlying.checkpoint_hash, null, 0);
  }
  const policyThreshold = verifyPolicyRootThreshold(root, policy);
  if (policyThreshold.count < root.threshold) {
    return result('WITNESS_POLICY_UNTRUSTED', ['WITNESS_POLICY_ROOT_THRESHOLD_NOT_MET'], underlying.checkpoint_hash, null, 0);
  }
  if (policyThreshold.invalid) {
    return result('WITNESS_POLICY_UNTRUSTED', ['WITNESS_POLICY_SIGNATURE_INVALID'], underlying.checkpoint_hash, null, 0);
  }

  if (
    bundle.witness_policy_id !== policy.policy_id || bundle.witness_policy_version !== policy.policy_version ||
    bundle.checkpoint_id !== checkpoint.checkpoint_id || bundle.checkpoint_hash !== underlying.checkpoint_hash ||
    bundle.sequence !== checkpoint.sequence
  ) {
    return result('WITNESS_INVALID', ['WITNESS_CHECKPOINT_BINDING_MISMATCH'], underlying.checkpoint_hash, null, 0);
  }

  if (trusted !== null) {
    if (checkpoint.sequence < trusted.sequence) {
      return result('WITNESS_ROLLBACK', ['WITNESS_SEQUENCE_ROLLBACK'], underlying.checkpoint_hash, null, 0);
    }
    if (checkpoint.sequence === trusted.sequence && underlying.checkpoint_hash !== trusted.checkpoint_hash) {
      return result('SPLIT_VIEW_DETECTED', ['WITNESS_SPLIT_VIEW_DETECTED'], underlying.checkpoint_hash, null, 0);
    }
    if (checkpoint.sequence > trusted.sequence + 1) {
      return result('WITNESS_GAP', ['WITNESS_SEQUENCE_GAP'], underlying.checkpoint_hash, null, 0);
    }
    if (checkpoint.sequence === trusted.sequence + 1 && checkpoint.previous_checkpoint_hash !== trusted.checkpoint_hash) {
      return result('SPLIT_VIEW_DETECTED', ['WITNESS_PREDECESSOR_MISMATCH'], underlying.checkpoint_hash, null, 0);
    }
  }

  const acceptedWitnesses = new Set<string>();
  const witnessedViews = new Map<string, { sequence: number; checkpointHash: string }>();
  let latestObservedAt = checkpoint.issued_at;
  for (const observation of bundle.observations) {
    if (observation.witness_policy_id !== policy.policy_id || observation.witness_policy_version !== policy.policy_version) {
      return result('WITNESS_INVALID', ['WITNESS_CHECKPOINT_BINDING_MISMATCH'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    const witness = policy.witnesses.find((candidate) => candidate.witness_key_id === observation.witness_key_id);
    if (!witness) return result('WITNESS_INVALID', ['WITNESS_NOT_AUTHORIZED'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    const observedTime = Date.parse(observation.observed_at);
    if (
      witness.status !== 'ACTIVE' || observedTime < Date.parse(witness.valid_from) ||
      (witness.valid_until !== null && observedTime >= Date.parse(witness.valid_until))
    ) {
      return result('WITNESS_INVALID', ['WITNESS_NOT_ACTIVE'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    if (
      observedTime < Date.parse(checkpoint.issued_at) || observedTime > Date.parse(options.evaluated_at) ||
      observedTime < Date.parse(policy.valid_from) || observedTime >= Date.parse(policy.expires_at)
    ) {
      return result('WITNESS_INVALID', ['WITNESS_OBSERVATION_TIME_INVALID'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    if (Date.parse(options.evaluated_at) - observedTime > policy.max_observation_age_seconds * 1000) {
      return result('WITNESS_STALE', ['WITNESS_OBSERVATION_STALE'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    let publicKey: Uint8Array;
    let signature: Uint8Array;
    try {
      publicKey = decodeBase64(witness.public_key_base64);
      signature = decodeBase64(observation.signature.signature_base64);
    } catch {
      return result('WITNESS_SIGNATURE_INVALID', ['WITNESS_SIGNATURE_INVALID'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    const payload = Buffer.from(canonicalARVCheckpointWitnessObservationSigningPayloadV1(observation), 'utf8');
    if (!nacl.sign.detached.verify(payload, signature, publicKey)) {
      return result('WITNESS_SIGNATURE_INVALID', ['WITNESS_SIGNATURE_INVALID'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    const priorView = witnessedViews.get(observation.witness_key_id);
    if (priorView && (priorView.sequence !== observation.sequence || priorView.checkpointHash !== observation.checkpoint_hash)) {
      return result('WITNESS_EQUIVOCATION', ['WITNESS_EQUIVOCATION_DETECTED'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    witnessedViews.set(observation.witness_key_id, {
      sequence: observation.sequence,
      checkpointHash: observation.checkpoint_hash
    });
    if (
      observation.checkpoint_id !== checkpoint.checkpoint_id || observation.checkpoint_hash !== underlying.checkpoint_hash ||
      observation.sequence !== checkpoint.sequence || observation.registry_id !== checkpoint.registry_id ||
      observation.registry_version !== checkpoint.registry_version || observation.registry_digest !== checkpoint.registry_digest ||
      observation.previous_checkpoint_hash !== checkpoint.previous_checkpoint_hash
    ) {
      return result('SPLIT_VIEW_DETECTED', ['WITNESS_SPLIT_VIEW_DETECTED'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
    }
    acceptedWitnesses.add(observation.witness_key_id);
    if (observedTime > Date.parse(latestObservedAt)) latestObservedAt = observation.observed_at;
  }

  if (acceptedWitnesses.size < policy.threshold) {
    return result('WITNESS_QUORUM_INSUFFICIENT', ['WITNESS_THRESHOLD_NOT_MET'], underlying.checkpoint_hash, null, acceptedWitnesses.size);
  }
  return result(
    'WITNESS_QUORUM_VALID',
    [],
    underlying.checkpoint_hash,
    trustedProjection(checkpoint, underlying.checkpoint_hash, policy, latestObservedAt),
    acceptedWitnesses.size
  );
}
