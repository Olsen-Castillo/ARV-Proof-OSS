import crypto from 'crypto';
import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';

export const ARV_TRUST_ROOT_SCHEMA = 'arv.trust-root' as const;
export const ARV_TRUST_ROOT_TRANSITION_SCHEMA = 'arv.trust-root-transition' as const;
export const ARV_TRUST_ROOT_SCHEMA_VERSION = 1 as const;
export const ARV_TRUST_ROOT_ROLES = ['ROOT', 'RECOVERY'] as const;
export const ARV_TRUST_ROOT_KEY_STATUSES = ['ACTIVE', 'REVOKED', 'RETIRED'] as const;
export const ARV_TRUST_ROOT_TRANSITION_TYPES = ['ROTATION', 'RECOVERY'] as const;
export const ARV_TRUST_ROOT_STATES = [
  'ROOT_VALID',
  'ROOT_EXPIRED',
  'ROOT_ROLLBACK',
  'ROOT_EQUIVOCATION',
  'INSUFFICIENT_THRESHOLD',
  'UNTRUSTED_SUCCESSOR',
  'COMPROMISE_RECOVERY_REQUIRED',
  'RECOVERY_VALID',
  'ROOT_INVALID'
] as const;
export const ARV_TRUST_ROOT_CODES = [
  'ROOT_SCHEMA_INVALID',
  'TRANSITION_SCHEMA_INVALID',
  'CHECKPOINT_INVALID',
  'ROOT_EXPIRED_AT_EVALUATION',
  'ROOT_VERSION_ROLLBACK',
  'ROOT_EPOCH_ROLLBACK',
  'ROOT_EQUIVOCATION_DETECTED',
  'ROOT_CHAIN_GAP',
  'ROOT_CHAIN_MISMATCH',
  'TRANSITION_HASH_MISMATCH',
  'TRANSITION_TIME_INVALID',
  'CURRENT_THRESHOLD_NOT_MET',
  'RECOVERY_THRESHOLD_NOT_MET',
  'SUCCESSOR_THRESHOLD_NOT_MET',
  'COMPROMISE_EFFECTIVE_FROM_REQUIRED',
  'SIGNATURE_INVALID',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVTrustRootRoleV1 = typeof ARV_TRUST_ROOT_ROLES[number];
export type ARVTrustRootKeyStatusV1 = typeof ARV_TRUST_ROOT_KEY_STATUSES[number];
export type ARVTrustRootTransitionTypeV1 = typeof ARV_TRUST_ROOT_TRANSITION_TYPES[number];
export type ARVTrustRootStateV1 = typeof ARV_TRUST_ROOT_STATES[number];
export type ARVTrustRootCodeV1 = typeof ARV_TRUST_ROOT_CODES[number];

export interface ARVTrustRootKeyV1 {
  key_id: string;
  algorithm: 'Ed25519';
  public_key_base64: string;
  roles: ARVTrustRootRoleV1[];
  status: ARVTrustRootKeyStatusV1;
  valid_from: string;
  valid_until: string | null;
}

export interface ARVTrustRootV1 {
  schema: typeof ARV_TRUST_ROOT_SCHEMA;
  schema_version: typeof ARV_TRUST_ROOT_SCHEMA_VERSION;
  root_id: string;
  root_version: number;
  epoch: number;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  threshold: number;
  recovery_threshold: number;
  previous_root_hash: string | null;
  policy_digest: string;
  keys: ARVTrustRootKeyV1[];
}

export interface ARVTrustRootSignatureV1 {
  algorithm: 'Ed25519';
  key_id: string;
  signature_base64: string;
}

export interface ARVTrustRootTransitionV1 {
  schema: typeof ARV_TRUST_ROOT_TRANSITION_SCHEMA;
  schema_version: typeof ARV_TRUST_ROOT_SCHEMA_VERSION;
  transition_id: string;
  transition_type: ARVTrustRootTransitionTypeV1;
  from_root_id: string;
  from_version: number;
  from_root_hash: string;
  to_root_id: string;
  to_version: number;
  to_root_hash: string;
  effective_at: string;
  compromise_effective_from: string | null;
  reason_code: string;
  current_authorizations: ARVTrustRootSignatureV1[];
  successor_authorizations: ARVTrustRootSignatureV1[];
}

export interface ARVTrustRootCheckpointV1 {
  root_id: string;
  root_version: number;
  epoch: number;
  root_hash: string;
}

export interface ARVTrustRootVerificationV1 {
  schema: 'arv.trust-root-verification';
  schema_version: 1;
  accepted: boolean;
  state: ARVTrustRootStateV1;
  current_root_hash: string | null;
  successor_root_hash: string | null;
  trusted_root_version: number | null;
  codes: ARVTrustRootCodeV1[];
  material_truth: 'NOT_EVALUATED';
}

export interface VerifyARVTrustRootTransitionOptionsV1 {
  current_root: unknown;
  successor_root: unknown;
  transition: unknown;
  checkpoint: unknown;
  evaluated_at: string;
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const keyIdPattern = /^[a-f0-9]{24}$/;
const rootIdPattern = /^ARV-ROOT-[A-Z0-9-]+$/;
const transitionIdPattern = /^ARV-ROOT-TRANSITION-[A-Z0-9-]+$/;
const reasonCodePattern = /^[A-Z][A-Z0-9_]{2,63}$/;
const forbiddenKeyPattern = /(?:private|secret|seed|mnemonic)/i;

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
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${location} fields are invalid`);
  }
}

function timestamp(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !timestampPattern.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${location} must be a UTC ISO-8601 timestamp`);
  }
}

function positiveInteger(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || Number(value) < 1) {
    throw new Error(`${location} must be a positive integer`);
  }
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

function walkForPrivateMaterial(value: unknown, location: string): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkForPrivateMaterial(item, `${location}[${index}]`));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (forbiddenKeyPattern.test(key)) {
      throw new Error(`PRIVATE_KEY_MATERIAL_FORBIDDEN:${location}.${key}`);
    }
    walkForPrivateMaterial(item, `${location}.${key}`);
  }
}

export function assertNoARVPrivateKeyMaterialV1(value: unknown): void {
  walkForPrivateMaterial(value, '$');
}

export function sha256ARVTrustRootV1(root: ARVTrustRootV1): string {
  return crypto.createHash('sha256').update(canonicalizeARVJsonV1(root), 'utf8').digest('hex');
}

export function fingerprintARVTrustRootPublicKeyV1(publicKey: Uint8Array): string {
  return crypto.createHash('sha256').update(Buffer.from(publicKey)).digest('hex').slice(0, 24);
}

function assertKey(value: unknown, index: number): ARVTrustRootKeyV1 {
  const location = `$.keys[${index}]`;
  const key = object(value, location);
  exactKeys(
    key,
    ['key_id', 'algorithm', 'public_key_base64', 'roles', 'status', 'valid_from', 'valid_until'],
    location
  );
  if (typeof key.key_id !== 'string' || !keyIdPattern.test(key.key_id)) {
    throw new Error(`${location}.key_id is invalid`);
  }
  if (key.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  const publicKey = base64Bytes(key.public_key_base64, nacl.sign.publicKeyLength, `${location}.public_key_base64`);
  if (fingerprintARVTrustRootPublicKeyV1(publicKey) !== key.key_id) {
    throw new Error(`${location}.key_id does not match public key`);
  }
  if (!Array.isArray(key.roles) || key.roles.length === 0) throw new Error(`${location}.roles is invalid`);
  for (const role of key.roles) {
    if (!ARV_TRUST_ROOT_ROLES.includes(role as ARVTrustRootRoleV1)) {
      throw new Error(`${location}.roles contains an unsupported role`);
    }
  }
  if (new Set(key.roles).size !== key.roles.length) throw new Error(`${location}.roles contains duplicates`);
  if (!ARV_TRUST_ROOT_KEY_STATUSES.includes(key.status as ARVTrustRootKeyStatusV1)) {
    throw new Error(`${location}.status is invalid`);
  }
  timestamp(key.valid_from, `${location}.valid_from`);
  if (key.valid_until !== null) {
    timestamp(key.valid_until, `${location}.valid_until`);
    if (Date.parse(key.valid_until) <= Date.parse(key.valid_from)) {
      throw new Error(`${location}.valid_until must be after valid_from`);
    }
  }
  return key as unknown as ARVTrustRootKeyV1;
}

export function assertARVTrustRootV1(value: unknown): ARVTrustRootV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const root = object(value, '$');
  exactKeys(
    root,
    [
      'schema', 'schema_version', 'root_id', 'root_version', 'epoch', 'issued_at', 'valid_from',
      'expires_at', 'threshold', 'recovery_threshold', 'previous_root_hash', 'policy_digest', 'keys'
    ],
    '$'
  );
  if (root.schema !== ARV_TRUST_ROOT_SCHEMA || root.schema_version !== ARV_TRUST_ROOT_SCHEMA_VERSION) {
    throw new Error('trust root schema is invalid');
  }
  if (typeof root.root_id !== 'string' || !rootIdPattern.test(root.root_id)) throw new Error('$.root_id is invalid');
  positiveInteger(root.root_version, '$.root_version');
  positiveInteger(root.epoch, '$.epoch');
  timestamp(root.issued_at, '$.issued_at');
  timestamp(root.valid_from, '$.valid_from');
  timestamp(root.expires_at, '$.expires_at');
  if (Date.parse(root.valid_from) < Date.parse(root.issued_at)) throw new Error('$.valid_from precedes issued_at');
  if (Date.parse(root.expires_at) <= Date.parse(root.valid_from)) throw new Error('$.expires_at must be after valid_from');
  positiveInteger(root.threshold, '$.threshold');
  positiveInteger(root.recovery_threshold, '$.recovery_threshold');
  if (root.root_version === 1 && root.previous_root_hash !== null) throw new Error('initial root cannot have predecessor');
  if (root.root_version > 1 && (typeof root.previous_root_hash !== 'string' || !sha256Pattern.test(root.previous_root_hash))) {
    throw new Error('successor root must bind its predecessor hash');
  }
  if (typeof root.policy_digest !== 'string' || !sha256Pattern.test(root.policy_digest)) {
    throw new Error('$.policy_digest is invalid');
  }
  if (!Array.isArray(root.keys) || root.keys.length === 0) throw new Error('$.keys is invalid');
  const keys = root.keys.map((entry, index) => assertKey(entry, index));
  if (new Set(keys.map((key) => key.key_id)).size !== keys.length) throw new Error('$.keys contains duplicate key IDs');
  const activeRootKeys = keys.filter((key) => key.status === 'ACTIVE' && key.roles.includes('ROOT')).length;
  const activeRecoveryKeys = keys.filter((key) => key.status === 'ACTIVE' && key.roles.includes('RECOVERY')).length;
  if (root.threshold > activeRootKeys) throw new Error('$.threshold exceeds active ROOT keys');
  if (root.recovery_threshold > activeRecoveryKeys) throw new Error('$.recovery_threshold exceeds active RECOVERY keys');
  return { ...root, keys } as unknown as ARVTrustRootV1;
}

function assertSignature(value: unknown, location: string): ARVTrustRootSignatureV1 {
  const signature = object(value, location);
  exactKeys(signature, ['algorithm', 'key_id', 'signature_base64'], location);
  if (signature.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  if (typeof signature.key_id !== 'string' || !keyIdPattern.test(signature.key_id)) {
    throw new Error(`${location}.key_id is invalid`);
  }
  base64Bytes(signature.signature_base64, nacl.sign.signatureLength, `${location}.signature_base64`);
  return signature as unknown as ARVTrustRootSignatureV1;
}

export function assertARVTrustRootTransitionV1(value: unknown): ARVTrustRootTransitionV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const transition = object(value, '$');
  exactKeys(
    transition,
    [
      'schema', 'schema_version', 'transition_id', 'transition_type', 'from_root_id', 'from_version',
      'from_root_hash', 'to_root_id', 'to_version', 'to_root_hash', 'effective_at',
      'compromise_effective_from', 'reason_code', 'current_authorizations', 'successor_authorizations'
    ],
    '$'
  );
  if (transition.schema !== ARV_TRUST_ROOT_TRANSITION_SCHEMA || transition.schema_version !== 1) {
    throw new Error('trust root transition schema is invalid');
  }
  if (typeof transition.transition_id !== 'string' || !transitionIdPattern.test(transition.transition_id)) {
    throw new Error('$.transition_id is invalid');
  }
  if (!ARV_TRUST_ROOT_TRANSITION_TYPES.includes(transition.transition_type as ARVTrustRootTransitionTypeV1)) {
    throw new Error('$.transition_type is invalid');
  }
  for (const field of ['from_root_id', 'to_root_id'] as const) {
    if (typeof transition[field] !== 'string' || !rootIdPattern.test(transition[field] as string)) {
      throw new Error(`$.${field} is invalid`);
    }
  }
  positiveInteger(transition.from_version, '$.from_version');
  positiveInteger(transition.to_version, '$.to_version');
  for (const field of ['from_root_hash', 'to_root_hash'] as const) {
    if (typeof transition[field] !== 'string' || !sha256Pattern.test(transition[field] as string)) {
      throw new Error(`$.${field} is invalid`);
    }
  }
  timestamp(transition.effective_at, '$.effective_at');
  if (transition.compromise_effective_from !== null) {
    timestamp(transition.compromise_effective_from, '$.compromise_effective_from');
  }
  if (typeof transition.reason_code !== 'string' || !reasonCodePattern.test(transition.reason_code)) {
    throw new Error('$.reason_code is invalid');
  }
  if (!Array.isArray(transition.current_authorizations)) throw new Error('$.current_authorizations is invalid');
  if (!Array.isArray(transition.successor_authorizations)) throw new Error('$.successor_authorizations is invalid');
  const current = transition.current_authorizations.map((entry, index) =>
    assertSignature(entry, `$.current_authorizations[${index}]`)
  );
  const successor = transition.successor_authorizations.map((entry, index) =>
    assertSignature(entry, `$.successor_authorizations[${index}]`)
  );
  return {
    ...transition,
    current_authorizations: current,
    successor_authorizations: successor
  } as unknown as ARVTrustRootTransitionV1;
}

export function assertARVTrustRootCheckpointV1(value: unknown): ARVTrustRootCheckpointV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const checkpoint = object(value, '$checkpoint');
  exactKeys(checkpoint, ['root_id', 'root_version', 'epoch', 'root_hash'], '$checkpoint');
  if (typeof checkpoint.root_id !== 'string' || !rootIdPattern.test(checkpoint.root_id)) {
    throw new Error('$checkpoint.root_id is invalid');
  }
  positiveInteger(checkpoint.root_version, '$checkpoint.root_version');
  positiveInteger(checkpoint.epoch, '$checkpoint.epoch');
  if (typeof checkpoint.root_hash !== 'string' || !sha256Pattern.test(checkpoint.root_hash)) {
    throw new Error('$checkpoint.root_hash is invalid');
  }
  return checkpoint as unknown as ARVTrustRootCheckpointV1;
}

export function canonicalARVTrustRootTransitionSigningPayloadV1(
  transition: ARVTrustRootTransitionV1
): string {
  const unsigned = {
    schema: transition.schema,
    schema_version: transition.schema_version,
    transition_id: transition.transition_id,
    transition_type: transition.transition_type,
    from_root_id: transition.from_root_id,
    from_version: transition.from_version,
    from_root_hash: transition.from_root_hash,
    to_root_id: transition.to_root_id,
    to_version: transition.to_version,
    to_root_hash: transition.to_root_hash,
    effective_at: transition.effective_at,
    compromise_effective_from: transition.compromise_effective_from,
    reason_code: transition.reason_code
  };
  return `ARV-TRUST-ROOT-TRANSITION-v1\n${canonicalizeARVJsonV1(unsigned)}`;
}

function verification(
  state: ARVTrustRootStateV1,
  codes: ARVTrustRootCodeV1[],
  currentHash: string | null,
  successorHash: string | null,
  version: number | null
): ARVTrustRootVerificationV1 {
  const accepted = state === 'ROOT_VALID' || state === 'RECOVERY_VALID';
  return {
    schema: 'arv.trust-root-verification',
    schema_version: 1,
    accepted,
    state,
    current_root_hash: currentHash,
    successor_root_hash: successorHash,
    trusted_root_version: accepted ? version : null,
    codes: Array.from(new Set(codes)),
    material_truth: 'NOT_EVALUATED'
  };
}

function keyUsableAt(key: ARVTrustRootKeyV1, role: ARVTrustRootRoleV1, at: string): boolean {
  if (key.status !== 'ACTIVE' || !key.roles.includes(role)) return false;
  const time = Date.parse(at);
  if (time < Date.parse(key.valid_from)) return false;
  if (key.valid_until !== null && time >= Date.parse(key.valid_until)) return false;
  return true;
}

function countValidAuthorizations(
  root: ARVTrustRootV1,
  role: ARVTrustRootRoleV1,
  authorizations: ARVTrustRootSignatureV1[],
  payload: string,
  effectiveAt: string
): { count: number; invalid: boolean } {
  const accepted = new Set<string>();
  let invalid = false;
  for (const authorization of authorizations) {
    if (accepted.has(authorization.key_id)) continue;
    const key = root.keys.find((candidate) => candidate.key_id === authorization.key_id);
    if (!key || !keyUsableAt(key, role, effectiveAt)) {
      invalid = true;
      continue;
    }
    const publicKey = decodeBase64(key.public_key_base64);
    const signature = decodeBase64(authorization.signature_base64);
    if (!nacl.sign.detached.verify(Buffer.from(payload, 'utf8'), signature, publicKey)) {
      invalid = true;
      continue;
    }
    accepted.add(authorization.key_id);
  }
  return { count: accepted.size, invalid };
}

export function verifyARVTrustRootTransitionV1(
  options: VerifyARVTrustRootTransitionOptionsV1
): ARVTrustRootVerificationV1 {
  let current: ARVTrustRootV1;
  let successor: ARVTrustRootV1;
  let transition: ARVTrustRootTransitionV1;
  let checkpoint: ARVTrustRootCheckpointV1;
  try {
    timestamp(options.evaluated_at, '$.evaluated_at');
    current = assertARVTrustRootV1(options.current_root);
    successor = assertARVTrustRootV1(options.successor_root);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return verification(
      'ROOT_INVALID',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'ROOT_SCHEMA_INVALID'],
      null,
      null,
      null
    );
  }
  const currentHash = sha256ARVTrustRootV1(current);
  const successorHash = sha256ARVTrustRootV1(successor);
  try {
    transition = assertARVTrustRootTransitionV1(options.transition);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return verification(
      'ROOT_INVALID',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'TRANSITION_SCHEMA_INVALID'],
      currentHash,
      successorHash,
      null
    );
  }
  try {
    checkpoint = assertARVTrustRootCheckpointV1(options.checkpoint);
  } catch {
    return verification('ROOT_INVALID', ['CHECKPOINT_INVALID'], currentHash, successorHash, null);
  }

  if (checkpoint.root_id !== current.root_id) {
    return verification('ROOT_INVALID', ['CHECKPOINT_INVALID'], currentHash, successorHash, null);
  }
  if (current.root_version < checkpoint.root_version) {
    return verification('ROOT_ROLLBACK', ['ROOT_VERSION_ROLLBACK'], currentHash, successorHash, null);
  }
  if (current.root_version > checkpoint.root_version || current.epoch > checkpoint.epoch) {
    return verification('UNTRUSTED_SUCCESSOR', ['ROOT_CHAIN_GAP'], currentHash, successorHash, null);
  }
  if (current.epoch < checkpoint.epoch) {
    return verification('ROOT_ROLLBACK', ['ROOT_EPOCH_ROLLBACK'], currentHash, successorHash, null);
  }
  if (checkpoint.root_hash !== currentHash) {
    return verification('ROOT_EQUIVOCATION', ['ROOT_EQUIVOCATION_DETECTED'], currentHash, successorHash, null);
  }
  if (Date.parse(options.evaluated_at) >= Date.parse(successor.expires_at)) {
    return verification('ROOT_EXPIRED', ['ROOT_EXPIRED_AT_EVALUATION'], currentHash, successorHash, null);
  }
  if (successor.root_version <= current.root_version || successor.epoch <= current.epoch) {
    return verification('ROOT_ROLLBACK', ['ROOT_VERSION_ROLLBACK'], currentHash, successorHash, null);
  }
  if (successor.root_version !== current.root_version + 1 || successor.epoch !== current.epoch + 1) {
    return verification('UNTRUSTED_SUCCESSOR', ['ROOT_CHAIN_GAP'], currentHash, successorHash, null);
  }
  if (
    successor.root_id !== current.root_id ||
    successor.previous_root_hash !== currentHash ||
    transition.from_root_id !== current.root_id ||
    transition.to_root_id !== successor.root_id ||
    transition.from_version !== current.root_version ||
    transition.to_version !== successor.root_version
  ) {
    return verification('UNTRUSTED_SUCCESSOR', ['ROOT_CHAIN_MISMATCH'], currentHash, successorHash, null);
  }
  if (transition.from_root_hash !== currentHash || transition.to_root_hash !== successorHash) {
    return verification('ROOT_EQUIVOCATION', ['TRANSITION_HASH_MISMATCH'], currentHash, successorHash, null);
  }
  const effectiveTime = Date.parse(transition.effective_at);
  if (
    effectiveTime < Date.parse(current.valid_from) ||
    effectiveTime >= Date.parse(current.expires_at) ||
    effectiveTime < Date.parse(successor.valid_from) ||
    Date.parse(options.evaluated_at) < effectiveTime
  ) {
    return verification('ROOT_INVALID', ['TRANSITION_TIME_INVALID'], currentHash, successorHash, null);
  }
  if (transition.transition_type === 'ROTATION' && transition.compromise_effective_from !== null) {
    return verification('ROOT_INVALID', ['TRANSITION_TIME_INVALID'], currentHash, successorHash, null);
  }
  if (transition.transition_type === 'RECOVERY') {
    if (transition.compromise_effective_from === null) {
      return verification(
        'COMPROMISE_RECOVERY_REQUIRED',
        ['COMPROMISE_EFFECTIVE_FROM_REQUIRED'],
        currentHash,
        successorHash,
        null
      );
    }
    if (Date.parse(transition.compromise_effective_from) > effectiveTime) {
      return verification('ROOT_INVALID', ['TRANSITION_TIME_INVALID'], currentHash, successorHash, null);
    }
  }

  const payload = canonicalARVTrustRootTransitionSigningPayloadV1(transition);
  const currentRole: ARVTrustRootRoleV1 = transition.transition_type === 'RECOVERY' ? 'RECOVERY' : 'ROOT';
  const currentThreshold = transition.transition_type === 'RECOVERY'
    ? current.recovery_threshold
    : current.threshold;
  const currentAuth = countValidAuthorizations(
    current,
    currentRole,
    transition.current_authorizations,
    payload,
    transition.effective_at
  );
  const successorAuth = countValidAuthorizations(
    successor,
    'ROOT',
    transition.successor_authorizations,
    payload,
    transition.effective_at
  );
  if (currentAuth.count < currentThreshold) {
    const code: ARVTrustRootCodeV1 = transition.transition_type === 'RECOVERY'
      ? 'RECOVERY_THRESHOLD_NOT_MET'
      : 'CURRENT_THRESHOLD_NOT_MET';
    return verification('INSUFFICIENT_THRESHOLD', [code], currentHash, successorHash, null);
  }
  if (successorAuth.count < successor.threshold) {
    return verification('INSUFFICIENT_THRESHOLD', ['SUCCESSOR_THRESHOLD_NOT_MET'], currentHash, successorHash, null);
  }
  if (currentAuth.invalid || successorAuth.invalid) {
    return verification('ROOT_INVALID', ['SIGNATURE_INVALID'], currentHash, successorHash, null);
  }
  return verification(
    transition.transition_type === 'RECOVERY' ? 'RECOVERY_VALID' : 'ROOT_VALID',
    [],
    currentHash,
    successorHash,
    successor.root_version
  );
}
