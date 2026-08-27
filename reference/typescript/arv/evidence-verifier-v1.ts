import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import {
  EvidenceEnvelopeV1,
  assertEvidenceEnvelopeV1
} from './evidence-envelope-v1';
import {
  canonicalEvidenceQrPayloadV1,
  canonicalEvidenceSigningPayloadV1
} from './canonical-payload-v1';
import { validateEvidenceProfileBoundaryV1 } from './evidence-profiles-v1';
import {
  ARVLifecycleState,
  ARVVerificationCode,
  VerificationResultV1,
  assertVerificationResultV1,
  deriveARVOverallState
} from './verification-result-v1';

export interface VerifyEvidenceEnvelopeOptionsV1 {
  root_dir?: string;
  keyring_dir?: string;
  artifact_file_path?: string;
  lifecycle_state?: ARVLifecycleState;
  checkpoint_verified?: boolean | null;
}

interface PublicKeyDescriptorV1 {
  schema: 'arv.public-key';
  schema_version: 1;
  algorithm: 'Ed25519';
  fingerprint: string;
  public_key_base64: string;
  status: 'ACTIVE' | 'REVOKED' | 'RETIRED';
}

const CODE_ORDER: readonly ARVVerificationCode[] = [
  'SCHEMA_INVALID',
  'VERSION_UNSUPPORTED',
  'FIELD_UNKNOWN',
  'PROJECTION_DIGEST_MISMATCH',
  'NETWORK_MISMATCH',
  'KEY_UNKNOWN',
  'KEY_REVOKED',
  'KEYRING_UNAVAILABLE',
  'SIGNATURE_INVALID',
  'PROFILE_UNAVAILABLE',
  'CHECKPOINT_UNAVAILABLE',
  'PROOF_INVALID',
  'LIFECYCLE_STATE_UNKNOWN',
  'ARTIFACT_DIGEST_MISMATCH'
];

function sha256Hex(input: Buffer | string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function orderedCodes(codes: Set<ARVVerificationCode>): ARVVerificationCode[] {
  return CODE_ORDER.filter((code) => codes.has(code));
}

function isPublicKeyDescriptorV1(value: unknown): value is PublicKeyDescriptorV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const descriptor = value as Record<string, unknown>;
  const keys = Object.keys(descriptor).sort();
  const expected = [
    'schema',
    'schema_version',
    'algorithm',
    'fingerprint',
    'public_key_base64',
    'status'
  ].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expected)) return false;
  if (descriptor.schema !== 'arv.public-key') return false;
  if (descriptor.schema_version !== 1) return false;
  if (descriptor.algorithm !== 'Ed25519') return false;
  if (typeof descriptor.fingerprint !== 'string') return false;
  if (!/^[a-f0-9]{24}$/.test(descriptor.fingerprint)) return false;
  if (typeof descriptor.public_key_base64 !== 'string') return false;
  if (!['ACTIVE', 'REVOKED', 'RETIRED'].includes(String(descriptor.status))) return false;
  return true;
}

function verifyStructuralProofs(envelope: EvidenceEnvelopeV1): boolean {
  const expectedMerkleRoot = sha256Hex(
    `ARV-LEAF-v1:${envelope.artifact.digest.value}`
  );
  const expectedPrimarySeal = sha256Hex(
    `ARV-DUAL-SEAL-v1|${envelope.validation_id}|${envelope.artifact.digest.value}|${expectedMerkleRoot}`
  );
  const expectedSecondarySeal = sha256Hex(
    `ARV-DUAL-SEAL-v1-VERIFY|${expectedPrimarySeal}|${envelope.proof.verification_url}`
  );
  if (envelope.proof.merkle_root !== expectedMerkleRoot) return false;
  if (envelope.proof.dual_seal.mode !== 'ARV-DUAL-SEAL-v1') return false;
  if (envelope.proof.dual_seal.primary_seal_hash !== expectedPrimarySeal) return false;
  if (envelope.proof.dual_seal.secondary_seal_hash !== expectedSecondarySeal) return false;
  if (!envelope.proof.qr.signed) return false;
  if (envelope.proof.qr.signature !== envelope.proof.signature.value) return false;
  if (envelope.proof.qr.payload !== canonicalEvidenceQrPayloadV1(envelope)) return false;
  return true;
}

function loadPublicKey(
  envelope: EvidenceEnvelopeV1,
  keyringDir: string,
  codes: Set<ARVVerificationCode>
): { key: Uint8Array | null; trusted: boolean } {
  const fingerprint = envelope.proof.signature.public_key_fingerprint;
  if (!fs.existsSync(keyringDir)) {
    codes.add('KEYRING_UNAVAILABLE');
    return { key: null, trusted: false };
  }
  if (fingerprint === null || !/^[a-f0-9]{24}$/.test(fingerprint)) {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  const descriptorPath = path.join(keyringDir, `${fingerprint}.json`);
  if (!fs.existsSync(descriptorPath)) {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(descriptorPath, 'utf8'));
  } catch {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  if (!isPublicKeyDescriptorV1(parsed) || parsed.fingerprint !== fingerprint) {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  let publicKey: Uint8Array;
  try {
    publicKey = decodeBase64(parsed.public_key_base64);
  } catch {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  if (publicKey.length !== nacl.sign.publicKeyLength) {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  if (sha256Hex(Buffer.from(publicKey)).slice(0, 24) !== fingerprint) {
    codes.add('KEY_UNKNOWN');
    return { key: null, trusted: false };
  }
  if (parsed.status === 'REVOKED') {
    codes.add('KEY_REVOKED');
    return { key: publicKey, trusted: false };
  }
  return { key: publicKey, trusted: true };
}

function verifySignature(
  envelope: EvidenceEnvelopeV1,
  publicKey: Uint8Array
): boolean {
  const signatureValue = envelope.proof.signature.value;
  if (signatureValue === null) return false;
  let signature: Uint8Array;
  try {
    signature = decodeBase64(signatureValue);
  } catch {
    return false;
  }
  if (signature.length !== nacl.sign.signatureLength) return false;
  return nacl.sign.detached.verify(
    Buffer.from(canonicalEvidenceSigningPayloadV1(envelope), 'utf8'),
    signature,
    publicKey
  );
}

export function verifyEvidenceEnvelopeV1(
  input: unknown,
  options: VerifyEvidenceEnvelopeOptionsV1 = {}
): VerificationResultV1 {
  const codes = new Set<ARVVerificationCode>();
  let envelope: EvidenceEnvelopeV1;
  try {
    envelope = assertEvidenceEnvelopeV1(input);
  } catch {
    codes.add('SCHEMA_INVALID');
    return assertVerificationResultV1({
      schema: 'arv.verification-result',
      schema_version: 1,
      integrity: 'FAILED',
      lifecycle: 'UNKNOWN',
      artifact_match: 'NOT_CHECKED',
      overall: 'FAILED',
      codes: orderedCodes(codes)
    });
  }

  const rootDir = options.root_dir ?? process.cwd();
  const lifecycle = options.lifecycle_state ?? 'UNKNOWN';
  let integrity: VerificationResultV1['integrity'] = 'VERIFIED';
  let artifactMatch: VerificationResultV1['artifact_match'] = 'NOT_CHECKED';
  const profile = validateEvidenceProfileBoundaryV1(envelope.profile);
  if (!profile.supported || profile.missing_claims.length > 0) {
    codes.add('PROFILE_UNAVAILABLE');
    integrity = 'INDETERMINATE';
  }

  if (!verifyStructuralProofs(envelope)) {
    codes.add('PROOF_INVALID');
    integrity = 'FAILED';
  }

  const keyringDir = options.keyring_dir ?? path.join(rootDir, 'vault', 'sovereign', 'keyring');
  const key = loadPublicKey(envelope, keyringDir, codes);
  if (!key.trusted && integrity !== 'FAILED') integrity = 'INDETERMINATE';
  if (key.key && !verifySignature(envelope, key.key)) {
    codes.add('SIGNATURE_INVALID');
    integrity = 'FAILED';
  }

  if (options.checkpoint_verified === undefined || options.checkpoint_verified === null) {
    codes.add('CHECKPOINT_UNAVAILABLE');
  }
  if (options.checkpoint_verified === false) {
    codes.add('PROOF_INVALID');
    integrity = 'FAILED';
  }
  if (lifecycle === 'UNKNOWN') codes.add('LIFECYCLE_STATE_UNKNOWN');

  if (options.artifact_file_path) {
    if (!fs.existsSync(options.artifact_file_path)) {
      artifactMatch = 'NOT_CHECKED';
    }
    if (fs.existsSync(options.artifact_file_path)) {
      const digest = sha256Hex(fs.readFileSync(options.artifact_file_path));
      artifactMatch = digest === envelope.artifact.digest.value ? 'MATCH' : 'MISMATCH';
      if (artifactMatch === 'MISMATCH') codes.add('ARTIFACT_DIGEST_MISMATCH');
    }
  }

  const overall = deriveARVOverallState(integrity, lifecycle, artifactMatch);
  return assertVerificationResultV1({
    schema: 'arv.verification-result',
    schema_version: 1,
    integrity,
    lifecycle,
    artifact_match: artifactMatch,
    overall,
    codes: orderedCodes(codes)
  });
}
