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

export const ARV_TRUST_REGISTRY_CHECKPOINT_SCHEMA = 'arv.trust-registry-checkpoint' as const;
export const ARV_TRUST_DISTRIBUTION_MANIFEST_SCHEMA = 'arv.trust-distribution-manifest' as const;
export const ARV_TRUST_CHECKPOINT_SCHEMA_VERSION = 1 as const;
export const ARV_TRUST_CHECKPOINT_STATES = [
  'CHECKPOINT_VALID',
  'CHECKPOINT_NOT_YET_VALID',
  'CHECKPOINT_EXPIRED',
  'CHECKPOINT_ROLLBACK',
  'CHECKPOINT_EQUIVOCATION',
  'CHECKPOINT_GAP',
  'ROOT_UNTRUSTED',
  'MANIFEST_INVALID',
  'REGISTRY_DIGEST_MISMATCH',
  'INSUFFICIENT_THRESHOLD',
  'CHECKPOINT_INVALID'
] as const;
export const ARV_TRUST_CHECKPOINT_CODES = [
  'CHECKPOINT_SCHEMA_INVALID',
  'MANIFEST_SCHEMA_INVALID',
  'TRUSTED_CHECKPOINT_INVALID',
  'CHECKPOINT_NOT_ACTIVE',
  'CHECKPOINT_EXPIRED_AT_EVALUATION',
  'CHECKPOINT_SEQUENCE_ROLLBACK',
  'REGISTRY_VERSION_ROLLBACK',
  'ROOT_VERSION_ROLLBACK',
  'ROOT_EPOCH_ROLLBACK',
  'CHECKPOINT_EQUIVOCATION_DETECTED',
  'CHECKPOINT_CHAIN_GAP',
  'PREVIOUS_CHECKPOINT_HASH_MISMATCH',
  'ROOT_BINDING_MISMATCH',
  'MANIFEST_DIGEST_MISMATCH',
  'MANIFEST_TIME_INVALID',
  'MANIFEST_REGISTRY_MISMATCH',
  'REGISTRY_ARTIFACT_DIGEST_MISMATCH',
  'ROOT_THRESHOLD_NOT_MET',
  'SIGNATURE_INVALID',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVTrustCheckpointStateV1 = typeof ARV_TRUST_CHECKPOINT_STATES[number];
export type ARVTrustCheckpointCodeV1 = typeof ARV_TRUST_CHECKPOINT_CODES[number];

export interface ARVTrustDistributionManifestV1 {
  schema: typeof ARV_TRUST_DISTRIBUTION_MANIFEST_SCHEMA;
  schema_version: typeof ARV_TRUST_CHECKPOINT_SCHEMA_VERSION;
  manifest_id: string;
  registry_id: string;
  registry_version: number;
  registry_path: string;
  registry_media_type: 'application/json';
  registry_bytes: number;
  registry_digest: string;
  created_at: string;
}

export interface ARVTrustRegistryCheckpointV1 {
  schema: typeof ARV_TRUST_REGISTRY_CHECKPOINT_SCHEMA;
  schema_version: typeof ARV_TRUST_CHECKPOINT_SCHEMA_VERSION;
  checkpoint_id: string;
  sequence: number;
  registry_id: string;
  registry_version: number;
  registry_digest: string;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  previous_checkpoint_hash: string | null;
  manifest_digest: string;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  signatures: ARVTrustRootSignatureV1[];
}

export interface ARVTrustedRegistryCheckpointV1 {
  checkpoint_id: string;
  checkpoint_hash: string;
  sequence: number;
  registry_id: string;
  registry_version: number;
  registry_digest: string;
  root_id: string;
  root_version: number;
  root_epoch: number;
}

export interface ARVTrustRegistryCheckpointVerificationV1 {
  schema: 'arv.trust-registry-checkpoint-verification';
  schema_version: 1;
  accepted: boolean;
  state: ARVTrustCheckpointStateV1;
  checkpoint_hash: string | null;
  trusted_checkpoint: ARVTrustedRegistryCheckpointV1 | null;
  codes: ARVTrustCheckpointCodeV1[];
  authority_basis: 'PINNED_TRUST_ROOT';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

export interface VerifyARVTrustRegistryCheckpointOptionsV1 {
  trust_root: unknown;
  checkpoint: unknown;
  manifest: unknown;
  registry_bytes: Uint8Array | string;
  trusted_checkpoint: unknown | null;
  evaluated_at: string;
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const keyIdPattern = /^[a-f0-9]{24}$/;
const checkpointIdPattern = /^ARV-TRUST-CHECKPOINT-[A-Z0-9-]+$/;
const manifestIdPattern = /^ARV-TRUST-MANIFEST-[A-Z0-9-]+$/;
const registryIdPattern = /^ARV-TRUST-REGISTRY-[A-Z0-9-]+$/;
const rootIdPattern = /^ARV-ROOT-[A-Z0-9-]+$/;
const relativePathPattern = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/;

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

function sha256(value: Uint8Array | string): string {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertSha256(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !sha256Pattern.test(value)) {
    throw new Error(`${location} must be a lowercase SHA-256 digest`);
  }
}

function assertSignature(value: unknown, index: number): ARVTrustRootSignatureV1 {
  const location = `$.signatures[${index}]`;
  const signature = object(value, location);
  exactKeys(signature, ['algorithm', 'key_id', 'signature_base64'], location);
  if (signature.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  if (typeof signature.key_id !== 'string' || !keyIdPattern.test(signature.key_id)) {
    throw new Error(`${location}.key_id is invalid`);
  }
  if (typeof signature.signature_base64 !== 'string') throw new Error(`${location}.signature_base64 is invalid`);
  let decoded: Uint8Array;
  try {
    decoded = decodeBase64(signature.signature_base64);
  } catch {
    throw new Error(`${location}.signature_base64 is invalid`);
  }
  if (decoded.length !== nacl.sign.signatureLength) throw new Error(`${location}.signature_base64 has an invalid length`);
  return signature as unknown as ARVTrustRootSignatureV1;
}

export function assertARVTrustDistributionManifestV1(value: unknown): ARVTrustDistributionManifestV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const manifest = object(value, '$');
  exactKeys(
    manifest,
    [
      'schema', 'schema_version', 'manifest_id', 'registry_id', 'registry_version', 'registry_path',
      'registry_media_type', 'registry_bytes', 'registry_digest', 'created_at'
    ],
    '$'
  );
  if (manifest.schema !== ARV_TRUST_DISTRIBUTION_MANIFEST_SCHEMA || manifest.schema_version !== 1) {
    throw new Error('trust distribution manifest schema is invalid');
  }
  if (typeof manifest.manifest_id !== 'string' || !manifestIdPattern.test(manifest.manifest_id)) {
    throw new Error('$.manifest_id is invalid');
  }
  if (typeof manifest.registry_id !== 'string' || !registryIdPattern.test(manifest.registry_id)) {
    throw new Error('$.registry_id is invalid');
  }
  positiveInteger(manifest.registry_version, '$.registry_version');
  if (
    typeof manifest.registry_path !== 'string' ||
    !relativePathPattern.test(manifest.registry_path) ||
    manifest.registry_path.includes('\\')
  ) {
    throw new Error('$.registry_path is invalid');
  }
  if (manifest.registry_media_type !== 'application/json') throw new Error('$.registry_media_type is invalid');
  positiveInteger(manifest.registry_bytes, '$.registry_bytes');
  assertSha256(manifest.registry_digest, '$.registry_digest');
  timestamp(manifest.created_at, '$.created_at');
  return manifest as unknown as ARVTrustDistributionManifestV1;
}

export function assertARVTrustRegistryCheckpointV1(value: unknown): ARVTrustRegistryCheckpointV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const checkpoint = object(value, '$');
  exactKeys(
    checkpoint,
    [
      'schema', 'schema_version', 'checkpoint_id', 'sequence', 'registry_id', 'registry_version',
      'registry_digest', 'root_id', 'root_version', 'root_epoch', 'root_hash',
      'previous_checkpoint_hash', 'manifest_digest', 'issued_at', 'valid_from', 'expires_at', 'signatures'
    ],
    '$'
  );
  if (checkpoint.schema !== ARV_TRUST_REGISTRY_CHECKPOINT_SCHEMA || checkpoint.schema_version !== 1) {
    throw new Error('trust registry checkpoint schema is invalid');
  }
  if (typeof checkpoint.checkpoint_id !== 'string' || !checkpointIdPattern.test(checkpoint.checkpoint_id)) {
    throw new Error('$.checkpoint_id is invalid');
  }
  positiveInteger(checkpoint.sequence, '$.sequence');
  if (typeof checkpoint.registry_id !== 'string' || !registryIdPattern.test(checkpoint.registry_id)) {
    throw new Error('$.registry_id is invalid');
  }
  positiveInteger(checkpoint.registry_version, '$.registry_version');
  assertSha256(checkpoint.registry_digest, '$.registry_digest');
  if (typeof checkpoint.root_id !== 'string' || !rootIdPattern.test(checkpoint.root_id)) {
    throw new Error('$.root_id is invalid');
  }
  positiveInteger(checkpoint.root_version, '$.root_version');
  positiveInteger(checkpoint.root_epoch, '$.root_epoch');
  assertSha256(checkpoint.root_hash, '$.root_hash');
  if (checkpoint.sequence === 1 && checkpoint.previous_checkpoint_hash !== null) {
    throw new Error('initial checkpoint cannot have a predecessor');
  }
  if (checkpoint.sequence > 1) {
    assertSha256(checkpoint.previous_checkpoint_hash, '$.previous_checkpoint_hash');
  }
  assertSha256(checkpoint.manifest_digest, '$.manifest_digest');
  timestamp(checkpoint.issued_at, '$.issued_at');
  timestamp(checkpoint.valid_from, '$.valid_from');
  timestamp(checkpoint.expires_at, '$.expires_at');
  if (Date.parse(checkpoint.valid_from) < Date.parse(checkpoint.issued_at)) {
    throw new Error('$.valid_from precedes issued_at');
  }
  if (Date.parse(checkpoint.expires_at) <= Date.parse(checkpoint.valid_from)) {
    throw new Error('$.expires_at must be after valid_from');
  }
  if (!Array.isArray(checkpoint.signatures) || checkpoint.signatures.length === 0) {
    throw new Error('$.signatures is invalid');
  }
  const signatures = checkpoint.signatures.map((entry, index) => assertSignature(entry, index));
  return { ...checkpoint, signatures } as unknown as ARVTrustRegistryCheckpointV1;
}

export function assertARVTrustedRegistryCheckpointV1(value: unknown): ARVTrustedRegistryCheckpointV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const trusted = object(value, '$trusted_checkpoint');
  exactKeys(
    trusted,
    [
      'checkpoint_id', 'checkpoint_hash', 'sequence', 'registry_id', 'registry_version',
      'registry_digest', 'root_id', 'root_version', 'root_epoch'
    ],
    '$trusted_checkpoint'
  );
  if (typeof trusted.checkpoint_id !== 'string' || !checkpointIdPattern.test(trusted.checkpoint_id)) {
    throw new Error('$trusted_checkpoint.checkpoint_id is invalid');
  }
  assertSha256(trusted.checkpoint_hash, '$trusted_checkpoint.checkpoint_hash');
  positiveInteger(trusted.sequence, '$trusted_checkpoint.sequence');
  if (typeof trusted.registry_id !== 'string' || !registryIdPattern.test(trusted.registry_id)) {
    throw new Error('$trusted_checkpoint.registry_id is invalid');
  }
  positiveInteger(trusted.registry_version, '$trusted_checkpoint.registry_version');
  assertSha256(trusted.registry_digest, '$trusted_checkpoint.registry_digest');
  if (typeof trusted.root_id !== 'string' || !rootIdPattern.test(trusted.root_id)) {
    throw new Error('$trusted_checkpoint.root_id is invalid');
  }
  positiveInteger(trusted.root_version, '$trusted_checkpoint.root_version');
  positiveInteger(trusted.root_epoch, '$trusted_checkpoint.root_epoch');
  return trusted as unknown as ARVTrustedRegistryCheckpointV1;
}

export function sha256ARVTrustDistributionManifestV1(manifest: ARVTrustDistributionManifestV1): string {
  return sha256(canonicalizeARVJsonV1(manifest));
}

function unsignedCheckpoint(checkpoint: ARVTrustRegistryCheckpointV1) {
  return {
    schema: checkpoint.schema,
    schema_version: checkpoint.schema_version,
    checkpoint_id: checkpoint.checkpoint_id,
    sequence: checkpoint.sequence,
    registry_id: checkpoint.registry_id,
    registry_version: checkpoint.registry_version,
    registry_digest: checkpoint.registry_digest,
    root_id: checkpoint.root_id,
    root_version: checkpoint.root_version,
    root_epoch: checkpoint.root_epoch,
    root_hash: checkpoint.root_hash,
    previous_checkpoint_hash: checkpoint.previous_checkpoint_hash,
    manifest_digest: checkpoint.manifest_digest,
    issued_at: checkpoint.issued_at,
    valid_from: checkpoint.valid_from,
    expires_at: checkpoint.expires_at
  };
}

export function canonicalARVTrustRegistryCheckpointSigningPayloadV1(
  checkpoint: ARVTrustRegistryCheckpointV1
): string {
  return `ARV-TRUST-REGISTRY-CHECKPOINT-v1\n${canonicalizeARVJsonV1(unsignedCheckpoint(checkpoint))}`;
}

export function sha256ARVTrustRegistryCheckpointV1(checkpoint: ARVTrustRegistryCheckpointV1): string {
  return sha256(canonicalARVTrustRegistryCheckpointSigningPayloadV1(checkpoint));
}

function trustedProjection(
  checkpoint: ARVTrustRegistryCheckpointV1,
  checkpointHash: string
): ARVTrustedRegistryCheckpointV1 {
  return {
    checkpoint_id: checkpoint.checkpoint_id,
    checkpoint_hash: checkpointHash,
    sequence: checkpoint.sequence,
    registry_id: checkpoint.registry_id,
    registry_version: checkpoint.registry_version,
    registry_digest: checkpoint.registry_digest,
    root_id: checkpoint.root_id,
    root_version: checkpoint.root_version,
    root_epoch: checkpoint.root_epoch
  };
}

function result(
  state: ARVTrustCheckpointStateV1,
  codes: ARVTrustCheckpointCodeV1[],
  checkpointHash: string | null,
  trusted: ARVTrustedRegistryCheckpointV1 | null
): ARVTrustRegistryCheckpointVerificationV1 {
  const accepted = state === 'CHECKPOINT_VALID';
  return {
    schema: 'arv.trust-registry-checkpoint-verification',
    schema_version: 1,
    accepted,
    state,
    checkpoint_hash: checkpointHash,
    trusted_checkpoint: accepted ? trusted : null,
    codes: Array.from(new Set(codes)),
    authority_basis: 'PINNED_TRUST_ROOT',
    transport_authority: 'NONE',
    material_truth: 'NOT_EVALUATED'
  };
}

function keyUsableAt(root: ARVTrustRootV1, keyId: string, at: string) {
  const key = root.keys.find((candidate) => candidate.key_id === keyId);
  if (!key || key.status !== 'ACTIVE' || !key.roles.includes('ROOT')) return null;
  const time = Date.parse(at);
  if (time < Date.parse(key.valid_from)) return null;
  if (key.valid_until !== null && time >= Date.parse(key.valid_until)) return null;
  return key;
}

function verifyThreshold(
  root: ARVTrustRootV1,
  checkpoint: ARVTrustRegistryCheckpointV1,
  payload: string
): { count: number; invalid: boolean } {
  const accepted = new Set<string>();
  let invalid = false;
  for (const signature of checkpoint.signatures) {
    if (accepted.has(signature.key_id)) continue;
    const key = keyUsableAt(root, signature.key_id, checkpoint.issued_at);
    if (!key) {
      invalid = true;
      continue;
    }
    let publicKey: Uint8Array;
    let signatureBytes: Uint8Array;
    try {
      publicKey = decodeBase64(key.public_key_base64);
      signatureBytes = decodeBase64(signature.signature_base64);
    } catch {
      invalid = true;
      continue;
    }
    if (!nacl.sign.detached.verify(Buffer.from(payload, 'utf8'), signatureBytes, publicKey)) {
      invalid = true;
      continue;
    }
    accepted.add(signature.key_id);
  }
  return { count: accepted.size, invalid };
}

export function verifyARVTrustRegistryCheckpointV1(
  options: VerifyARVTrustRegistryCheckpointOptionsV1
): ARVTrustRegistryCheckpointVerificationV1 {
  let root: ARVTrustRootV1;
  let checkpoint: ARVTrustRegistryCheckpointV1;
  let manifest: ARVTrustDistributionManifestV1;
  let trusted: ARVTrustedRegistryCheckpointV1 | null = null;

  try {
    timestamp(options.evaluated_at, '$.evaluated_at');
    root = assertARVTrustRootV1(options.trust_root);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return result(
      'ROOT_UNTRUSTED',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'ROOT_BINDING_MISMATCH'],
      null,
      null
    );
  }

  try {
    checkpoint = assertARVTrustRegistryCheckpointV1(options.checkpoint);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return result(
      'CHECKPOINT_INVALID',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'CHECKPOINT_SCHEMA_INVALID'],
      null,
      null
    );
  }

  const checkpointHash = sha256ARVTrustRegistryCheckpointV1(checkpoint);

  try {
    manifest = assertARVTrustDistributionManifestV1(options.manifest);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return result(
      'MANIFEST_INVALID',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'MANIFEST_SCHEMA_INVALID'],
      checkpointHash,
      null
    );
  }

  if (options.trusted_checkpoint !== null) {
    try {
      trusted = assertARVTrustedRegistryCheckpointV1(options.trusted_checkpoint);
    } catch (error) {
      const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
      return result(
        'CHECKPOINT_INVALID',
        [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'TRUSTED_CHECKPOINT_INVALID'],
        checkpointHash,
        null
      );
    }
  }

  const rootHash = sha256ARVTrustRootV1(root);
  if (
    checkpoint.root_id !== root.root_id ||
    checkpoint.root_version !== root.root_version ||
    checkpoint.root_epoch !== root.epoch ||
    checkpoint.root_hash !== rootHash ||
    Date.parse(checkpoint.issued_at) < Date.parse(root.valid_from) ||
    Date.parse(checkpoint.issued_at) >= Date.parse(root.expires_at) ||
    Date.parse(checkpoint.expires_at) > Date.parse(root.expires_at)
  ) {
    return result('ROOT_UNTRUSTED', ['ROOT_BINDING_MISMATCH'], checkpointHash, null);
  }

  if (Date.parse(options.evaluated_at) < Date.parse(checkpoint.valid_from)) {
    return result('CHECKPOINT_NOT_YET_VALID', ['CHECKPOINT_NOT_ACTIVE'], checkpointHash, null);
  }
  if (Date.parse(options.evaluated_at) >= Date.parse(checkpoint.expires_at)) {
    return result('CHECKPOINT_EXPIRED', ['CHECKPOINT_EXPIRED_AT_EVALUATION'], checkpointHash, null);
  }

  if (sha256ARVTrustDistributionManifestV1(manifest) !== checkpoint.manifest_digest) {
    return result('MANIFEST_INVALID', ['MANIFEST_DIGEST_MISMATCH'], checkpointHash, null);
  }
  if (Date.parse(manifest.created_at) > Date.parse(checkpoint.issued_at)) {
    return result('MANIFEST_INVALID', ['MANIFEST_TIME_INVALID'], checkpointHash, null);
  }
  if (
    manifest.registry_id !== checkpoint.registry_id ||
    manifest.registry_version !== checkpoint.registry_version ||
    manifest.registry_digest !== checkpoint.registry_digest ||
    manifest.registry_bytes !== Buffer.from(options.registry_bytes).length
  ) {
    return result('MANIFEST_INVALID', ['MANIFEST_REGISTRY_MISMATCH'], checkpointHash, null);
  }
  if (sha256(options.registry_bytes) !== checkpoint.registry_digest) {
    return result('REGISTRY_DIGEST_MISMATCH', ['REGISTRY_ARTIFACT_DIGEST_MISMATCH'], checkpointHash, null);
  }

  const threshold = verifyThreshold(
    root,
    checkpoint,
    canonicalARVTrustRegistryCheckpointSigningPayloadV1(checkpoint)
  );
  if (threshold.count < root.threshold) {
    return result('INSUFFICIENT_THRESHOLD', ['ROOT_THRESHOLD_NOT_MET'], checkpointHash, null);
  }
  if (threshold.invalid) {
    return result('CHECKPOINT_INVALID', ['SIGNATURE_INVALID'], checkpointHash, null);
  }

  if (trusted === null) {
    if (checkpoint.sequence !== 1 || checkpoint.registry_version !== 1 || checkpoint.previous_checkpoint_hash !== null) {
      return result('CHECKPOINT_GAP', ['CHECKPOINT_CHAIN_GAP'], checkpointHash, null);
    }
  } else {
    if (checkpoint.registry_id !== trusted.registry_id || checkpoint.root_id !== trusted.root_id) {
      return result('ROOT_UNTRUSTED', ['ROOT_BINDING_MISMATCH'], checkpointHash, null);
    }
    if (checkpoint.sequence < trusted.sequence) {
      return result('CHECKPOINT_ROLLBACK', ['CHECKPOINT_SEQUENCE_ROLLBACK'], checkpointHash, null);
    }
    if (checkpoint.sequence === trusted.sequence) {
      if (checkpointHash !== trusted.checkpoint_hash) {
        return result('CHECKPOINT_EQUIVOCATION', ['CHECKPOINT_EQUIVOCATION_DETECTED'], checkpointHash, null);
      }
      return result('CHECKPOINT_VALID', [], checkpointHash, trustedProjection(checkpoint, checkpointHash));
    }
    if (checkpoint.sequence !== trusted.sequence + 1) {
      return result('CHECKPOINT_GAP', ['CHECKPOINT_CHAIN_GAP'], checkpointHash, null);
    }
    if (checkpoint.previous_checkpoint_hash !== trusted.checkpoint_hash) {
      return result('CHECKPOINT_EQUIVOCATION', ['PREVIOUS_CHECKPOINT_HASH_MISMATCH'], checkpointHash, null);
    }
    if (checkpoint.registry_version <= trusted.registry_version) {
      return result('CHECKPOINT_ROLLBACK', ['REGISTRY_VERSION_ROLLBACK'], checkpointHash, null);
    }
    if (checkpoint.registry_version !== trusted.registry_version + 1) {
      return result('CHECKPOINT_GAP', ['CHECKPOINT_CHAIN_GAP'], checkpointHash, null);
    }
    if (checkpoint.root_version < trusted.root_version) {
      return result('CHECKPOINT_ROLLBACK', ['ROOT_VERSION_ROLLBACK'], checkpointHash, null);
    }
    if (checkpoint.root_epoch < trusted.root_epoch) {
      return result('CHECKPOINT_ROLLBACK', ['ROOT_EPOCH_ROLLBACK'], checkpointHash, null);
    }
  }

  return result('CHECKPOINT_VALID', [], checkpointHash, trustedProjection(checkpoint, checkpointHash));
}
