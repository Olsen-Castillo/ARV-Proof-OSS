import crypto from 'crypto';
import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';

export const ARV_TRUST_REGISTRY_SCHEMA = 'arv.trust-registry' as const;
export const ARV_TRUST_REGISTRY_SCHEMA_VERSION = 1 as const;
export const ARV_TRUST_PRODUCTS = [
  'ARV_SNAP',
  'ARV_PROOF_OSS',
  'PROOFOPS',
  'GENERIC'
] as const;
export const ARV_TRUST_ENVIRONMENTS = ['PRODUCTION', 'TEST'] as const;
export const ARV_TRUST_ROLES = ['ISSUER', 'VERIFIER'] as const;
export const ARV_AUTHORIZATION_STATUSES = ['ACTIVE', 'SUSPENDED', 'REVOKED'] as const;
export const ARV_TRUST_REGISTRY_CODES = [
  'REGISTRY_SCHEMA_INVALID',
  'TRUST_ANCHOR_INVALID',
  'TRUST_ANCHOR_MISMATCH',
  'REGISTRY_SIGNATURE_INVALID',
  'CHECKPOINT_UNAVAILABLE',
  'CHECKPOINT_INVALID',
  'REGISTRY_ROLLBACK_DETECTED',
  'REGISTRY_EQUIVOCATION_DETECTED',
  'REGISTRY_CHAIN_MISMATCH',
  'REGISTRY_CHAIN_GAP'
] as const;

export type ARVTrustProduct = typeof ARV_TRUST_PRODUCTS[number];
export type ARVTrustEnvironment = typeof ARV_TRUST_ENVIRONMENTS[number];
export type ARVTrustRole = typeof ARV_TRUST_ROLES[number];
export type ARVAuthorizationStatus = typeof ARV_AUTHORIZATION_STATUSES[number];
export type ARVTrustRegistryCode = typeof ARV_TRUST_REGISTRY_CODES[number];

export interface ARVIssuerAuthorizationV1 {
  authorization_id: string;
  issuer_id: string;
  authority: string;
  systems: string[];
  roles: ARVTrustRole[];
  products: ARVTrustProduct[];
  environment: ARVTrustEnvironment;
  key_fingerprint: string;
  valid_from: string;
  valid_until: string | null;
  status: ARVAuthorizationStatus;
  status_effective_at: string | null;
  compromise_effective_from: string | null;
}

export interface TrustRegistryV1 {
  schema: typeof ARV_TRUST_REGISTRY_SCHEMA;
  schema_version: typeof ARV_TRUST_REGISTRY_SCHEMA_VERSION;
  registry_id: string;
  sequence: number;
  issued_at: string;
  previous_registry_hash: string | null;
  authorizations: ARVIssuerAuthorizationV1[];
  signature: {
    algorithm: 'Ed25519';
    key_fingerprint: string;
    value: string;
  };
}

export type UnsignedTrustRegistryV1 = Omit<TrustRegistryV1, 'signature'>;

export interface TrustAnchorV1 {
  schema: 'arv.trust-anchor';
  schema_version: 1;
  registry_id: string;
  algorithm: 'Ed25519';
  key_fingerprint: string;
  public_key_base64: string;
}

export interface TrustRegistryCheckpointV1 {
  registry_id: string;
  sequence: number;
  registry_hash: string;
}

export interface TrustRegistryVerificationV1 {
  trusted: boolean;
  registry_id: string | null;
  sequence: number | null;
  registry_hash: string | null;
  codes: ARVTrustRegistryCode[];
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const keyFingerprintPattern = /^[a-f0-9]{24}$/;
const registryIdPattern = /^ARV-TRUST-[A-Z0-9-]+$/;
const authorizationIdPattern = /^ARV-AUTH-[A-Z0-9-]+$/;
const issuerIdPattern = /^ARV-ISSUER-[A-Z0-9-]+$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function object(value: unknown, location: string): Record<string, unknown> {
  if (!isObject(value)) throw new Error(`${location} must be an object`);
  return value;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  location: string
): void {
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${location} fields are invalid`);
  }
}

function nonEmpty(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${location} must be a non-empty string`);
  }
}

function timestamp(value: unknown, location: string): asserts value is string {
  nonEmpty(value, location);
  if (!timestampPattern.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${location} must be a UTC ISO-8601 timestamp`);
  }
}

function nullableTimestamp(value: unknown, location: string): void {
  if (value !== null) timestamp(value, location);
}

function uniqueStringArray<T extends readonly string[]>(
  value: unknown,
  allowed: T | null,
  location: string
): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${location} must be a non-empty array`);
  }
  for (const item of value) {
    nonEmpty(item, location);
    if (allowed && !allowed.includes(item as T[number])) {
      throw new Error(`${location} contains an unsupported value`);
    }
  }
  if (new Set(value).size !== value.length) throw new Error(`${location} contains duplicates`);
  return value as string[];
}

function assertAuthorization(value: unknown, index: number): ARVIssuerAuthorizationV1 {
  const location = `$.authorizations[${index}]`;
  const entry = object(value, location);
  exactKeys(
    entry,
    [
      'authorization_id',
      'issuer_id',
      'authority',
      'systems',
      'roles',
      'products',
      'environment',
      'key_fingerprint',
      'valid_from',
      'valid_until',
      'status',
      'status_effective_at',
      'compromise_effective_from'
    ],
    location
  );
  if (typeof entry.authorization_id !== 'string' || !authorizationIdPattern.test(entry.authorization_id)) {
    throw new Error(`${location}.authorization_id is invalid`);
  }
  if (typeof entry.issuer_id !== 'string' || !issuerIdPattern.test(entry.issuer_id)) {
    throw new Error(`${location}.issuer_id is invalid`);
  }
  nonEmpty(entry.authority, `${location}.authority`);
  uniqueStringArray(entry.systems, null, `${location}.systems`);
  uniqueStringArray(entry.roles, ARV_TRUST_ROLES, `${location}.roles`);
  uniqueStringArray(entry.products, ARV_TRUST_PRODUCTS, `${location}.products`);
  if (!ARV_TRUST_ENVIRONMENTS.includes(entry.environment as ARVTrustEnvironment)) {
    throw new Error(`${location}.environment is invalid`);
  }
  if (typeof entry.key_fingerprint !== 'string' || !keyFingerprintPattern.test(entry.key_fingerprint)) {
    throw new Error(`${location}.key_fingerprint is invalid`);
  }
  timestamp(entry.valid_from, `${location}.valid_from`);
  nullableTimestamp(entry.valid_until, `${location}.valid_until`);
  if (entry.valid_until !== null && Date.parse(entry.valid_until as string) <= Date.parse(entry.valid_from)) {
    throw new Error(`${location}.valid_until must be after valid_from`);
  }
  if (!ARV_AUTHORIZATION_STATUSES.includes(entry.status as ARVAuthorizationStatus)) {
    throw new Error(`${location}.status is invalid`);
  }
  nullableTimestamp(entry.status_effective_at, `${location}.status_effective_at`);
  nullableTimestamp(entry.compromise_effective_from, `${location}.compromise_effective_from`);
  if (entry.status === 'ACTIVE' && entry.status_effective_at !== null) {
    throw new Error(`${location}.status_effective_at must be null for ACTIVE`);
  }
  if (entry.status !== 'ACTIVE' && entry.status_effective_at === null) {
    throw new Error(`${location}.status_effective_at is required`);
  }
  if (
    entry.status_effective_at !== null &&
    Date.parse(entry.status_effective_at as string) < Date.parse(entry.valid_from)
  ) {
    throw new Error(`${location}.status_effective_at precedes valid_from`);
  }
  if (entry.compromise_effective_from !== null && entry.status !== 'REVOKED') {
    throw new Error(`${location}.compromise_effective_from requires REVOKED`);
  }
  if (
    entry.compromise_effective_from !== null &&
    entry.status_effective_at !== null &&
    Date.parse(entry.compromise_effective_from as string) > Date.parse(entry.status_effective_at as string)
  ) {
    throw new Error(`${location}.compromise_effective_from exceeds revocation time`);
  }
  return value as ARVIssuerAuthorizationV1;
}

export function assertTrustRegistryV1(input: unknown): TrustRegistryV1 {
  const registry = object(input, '$');
  exactKeys(
    registry,
    [
      'schema',
      'schema_version',
      'registry_id',
      'sequence',
      'issued_at',
      'previous_registry_hash',
      'authorizations',
      'signature'
    ],
    '$'
  );
  if (registry.schema !== ARV_TRUST_REGISTRY_SCHEMA) throw new Error('$.schema is invalid');
  if (registry.schema_version !== ARV_TRUST_REGISTRY_SCHEMA_VERSION) {
    throw new Error('$.schema_version is invalid');
  }
  if (typeof registry.registry_id !== 'string' || !registryIdPattern.test(registry.registry_id)) {
    throw new Error('$.registry_id is invalid');
  }
  if (!Number.isSafeInteger(registry.sequence) || (registry.sequence as number) < 1) {
    throw new Error('$.sequence is invalid');
  }
  timestamp(registry.issued_at, '$.issued_at');
  if (registry.previous_registry_hash !== null && (
    typeof registry.previous_registry_hash !== 'string' ||
    !sha256Pattern.test(registry.previous_registry_hash)
  )) {
    throw new Error('$.previous_registry_hash is invalid');
  }
  if (registry.sequence === 1 && registry.previous_registry_hash !== null) {
    throw new Error('sequence 1 must not have a previous hash');
  }
  if ((registry.sequence as number) > 1 && registry.previous_registry_hash === null) {
    throw new Error('sequence greater than 1 requires a previous hash');
  }
  if (!Array.isArray(registry.authorizations)) throw new Error('$.authorizations must be an array');
  const authorizations = registry.authorizations.map(assertAuthorization);
  const authorizationIds = authorizations.map((entry) => entry.authorization_id);
  const fingerprints = authorizations.map((entry) => entry.key_fingerprint);
  if (new Set(authorizationIds).size !== authorizationIds.length) {
    throw new Error('authorization ids must be unique');
  }
  if (new Set(fingerprints).size !== fingerprints.length) {
    throw new Error('key fingerprints must be unique');
  }
  const signature = object(registry.signature, '$.signature');
  exactKeys(signature, ['algorithm', 'key_fingerprint', 'value'], '$.signature');
  if (signature.algorithm !== 'Ed25519') throw new Error('$.signature.algorithm is invalid');
  if (typeof signature.key_fingerprint !== 'string' || !sha256Pattern.test(signature.key_fingerprint)) {
    throw new Error('$.signature.key_fingerprint is invalid');
  }
  nonEmpty(signature.value, '$.signature.value');
  return input as TrustRegistryV1;
}

export function assertTrustAnchorV1(input: unknown): TrustAnchorV1 {
  const anchor = object(input, '$anchor');
  exactKeys(
    anchor,
    ['schema', 'schema_version', 'registry_id', 'algorithm', 'key_fingerprint', 'public_key_base64'],
    '$anchor'
  );
  if (anchor.schema !== 'arv.trust-anchor' || anchor.schema_version !== 1) {
    throw new Error('trust anchor schema is invalid');
  }
  if (typeof anchor.registry_id !== 'string' || !registryIdPattern.test(anchor.registry_id)) {
    throw new Error('trust anchor registry_id is invalid');
  }
  if (anchor.algorithm !== 'Ed25519') throw new Error('trust anchor algorithm is invalid');
  if (typeof anchor.key_fingerprint !== 'string' || !sha256Pattern.test(anchor.key_fingerprint)) {
    throw new Error('trust anchor fingerprint is invalid');
  }
  nonEmpty(anchor.public_key_base64, 'trust anchor public key');
  return input as TrustAnchorV1;
}

export function canonicalTrustRegistryPayloadV1(registry: UnsignedTrustRegistryV1): string {
  return canonicalizeARVJsonV1(registry);
}

export function trustRegistryHashV1(registry: TrustRegistryV1): string {
  const { signature: _signature, ...unsigned } = registry;
  return crypto.createHash('sha256').update(canonicalTrustRegistryPayloadV1(unsigned)).digest('hex');
}

function checkpointValid(value: TrustRegistryCheckpointV1): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    registryIdPattern.test(value.registry_id) &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence >= 1 &&
    sha256Pattern.test(value.registry_hash)
  );
}

export function verifyTrustRegistryV1(
  input: unknown,
  anchorInput: unknown,
  checkpoint?: TrustRegistryCheckpointV1 | null
): TrustRegistryVerificationV1 {
  const codes = new Set<ARVTrustRegistryCode>();
  let registry: TrustRegistryV1;
  let anchor: TrustAnchorV1;
  try {
    registry = assertTrustRegistryV1(input);
  } catch {
    return { trusted: false, registry_id: null, sequence: null, registry_hash: null, codes: ['REGISTRY_SCHEMA_INVALID'] };
  }
  const registryHash = trustRegistryHashV1(registry);
  try {
    anchor = assertTrustAnchorV1(anchorInput);
  } catch {
    return {
      trusted: false,
      registry_id: registry.registry_id,
      sequence: registry.sequence,
      registry_hash: registryHash,
      codes: ['TRUST_ANCHOR_INVALID']
    };
  }
  if (
    anchor.registry_id !== registry.registry_id ||
    anchor.key_fingerprint !== registry.signature.key_fingerprint
  ) {
    codes.add('TRUST_ANCHOR_MISMATCH');
  }
  let publicKey: Uint8Array | null = null;
  try {
    publicKey = decodeBase64(anchor.public_key_base64);
  } catch {
    codes.add('TRUST_ANCHOR_INVALID');
  }
  if (
    publicKey === null ||
    publicKey.length !== nacl.sign.publicKeyLength ||
    crypto.createHash('sha256').update(Buffer.from(publicKey)).digest('hex') !== anchor.key_fingerprint
  ) {
    codes.add('TRUST_ANCHOR_INVALID');
  }
  if (publicKey !== null && !codes.has('TRUST_ANCHOR_INVALID')) {
    let signature: Uint8Array | null = null;
    try {
      signature = decodeBase64(registry.signature.value);
    } catch {
      codes.add('REGISTRY_SIGNATURE_INVALID');
    }
    const { signature: _signature, ...unsigned } = registry;
    if (
      signature === null ||
      signature.length !== nacl.sign.signatureLength ||
      !nacl.sign.detached.verify(
        Buffer.from(canonicalTrustRegistryPayloadV1(unsigned), 'utf8'),
        signature,
        publicKey
      )
    ) {
      codes.add('REGISTRY_SIGNATURE_INVALID');
    }
  }
  if (checkpoint === undefined || checkpoint === null) {
    codes.add('CHECKPOINT_UNAVAILABLE');
  } else if (!checkpointValid(checkpoint) || checkpoint.registry_id !== registry.registry_id) {
    codes.add('CHECKPOINT_INVALID');
  } else if (registry.sequence < checkpoint.sequence) {
    codes.add('REGISTRY_ROLLBACK_DETECTED');
  } else if (registry.sequence === checkpoint.sequence && registryHash !== checkpoint.registry_hash) {
    codes.add('REGISTRY_EQUIVOCATION_DETECTED');
  } else if (registry.sequence === checkpoint.sequence + 1) {
    if (registry.previous_registry_hash !== checkpoint.registry_hash) {
      codes.add('REGISTRY_CHAIN_MISMATCH');
    }
  } else if (registry.sequence > checkpoint.sequence + 1) {
    codes.add('REGISTRY_CHAIN_GAP');
  }
  const ordered = ARV_TRUST_REGISTRY_CODES.filter((code) => codes.has(code));
  return {
    trusted: ordered.length === 0,
    registry_id: registry.registry_id,
    sequence: registry.sequence,
    registry_hash: registryHash,
    codes: ordered
  };
}
