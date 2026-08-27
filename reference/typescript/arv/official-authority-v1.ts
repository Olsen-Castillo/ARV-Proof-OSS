import { EvidenceEnvelopeV1, assertEvidenceEnvelopeV1 } from './evidence-envelope-v1';
import { verifyEvidenceEnvelopeV1 } from './evidence-verifier-v1';
import {
  ARVTrustEnvironment,
  ARVTrustProduct,
  TrustAnchorV1,
  TrustRegistryCheckpointV1,
  TrustRegistryV1,
  assertTrustRegistryV1,
  verifyTrustRegistryV1
} from './trust-registry-v1';

export const ARV_OFFICIAL_AUTHORITY_STATES = [
  'OFFICIAL',
  'UNOFFICIAL',
  'UNKNOWN',
  'SUSPENDED',
  'REVOKED',
  'EXPIRED',
  'OUT_OF_SCOPE'
] as const;

export const ARV_CURRENT_KEY_STATES = [
  'ACTIVE',
  'SUSPENDED',
  'REVOKED',
  'EXPIRED',
  'UNKNOWN'
] as const;

export const ARV_OFFICIAL_AUTHORITY_CODES = [
  'EVIDENCE_ENVELOPE_INVALID',
  'CRYPTOGRAPHIC_PROOF_NOT_VERIFIED',
  'REGISTRY_NOT_TRUSTED',
  'REGISTRY_ISSUED_AFTER_EVALUATION',
  'KEY_FINGERPRINT_MISSING',
  'AUTHORIZATION_NOT_FOUND',
  'ISSUER_ROLE_NOT_AUTHORIZED',
  'AUTHORITY_CLAIM_MISMATCH',
  'SYSTEM_OUT_OF_SCOPE',
  'PRODUCT_OUT_OF_SCOPE',
  'ENVIRONMENT_OUT_OF_SCOPE',
  'AUTHORIZATION_NOT_YET_VALID',
  'AUTHORIZATION_EXPIRED_AT_RECORDING',
  'AUTHORIZATION_SUSPENDED_AT_RECORDING',
  'AUTHORIZATION_REVOKED_AT_RECORDING',
  'KEY_COMPROMISED_AT_RECORDING',
  'CURRENT_KEY_SUSPENDED_AFTER_RECORDING',
  'CURRENT_KEY_REVOKED_AFTER_RECORDING',
  'CURRENT_KEY_EXPIRED_AFTER_RECORDING'
] as const;

export type ARVOfficialAuthorityState = typeof ARV_OFFICIAL_AUTHORITY_STATES[number];
export type ARVCurrentKeyState = typeof ARV_CURRENT_KEY_STATES[number];
export type ARVOfficialAuthorityCode = typeof ARV_OFFICIAL_AUTHORITY_CODES[number];

export interface OfficialAuthorityEvaluationOptionsV1 {
  product: ARVTrustProduct;
  environment: ARVTrustEnvironment;
  evaluated_at: string;
  root_dir?: string;
  evidence_checkpoint_verified?: boolean | null;
}

export interface OfficialAuthorityResultV1 {
  schema: 'arv.official-authority-result';
  schema_version: 1;
  status: ARVOfficialAuthorityState;
  authority_at_recording: boolean | null;
  current_key_status: ARVCurrentKeyState;
  authorization_id: string | null;
  issuer_id: string | null;
  key_fingerprint: string | null;
  product: ARVTrustProduct;
  environment: ARVTrustEnvironment;
  recorded_at: string | null;
  evaluated_at: string;
  cryptographic_integrity: 'VERIFIED' | 'FAILED' | 'INDETERMINATE';
  cryptographic_codes: string[];
  registry: {
    registry_id: string | null;
    sequence: number | null;
    registry_hash: string | null;
    trust_codes: string[];
  };
  codes: ARVOfficialAuthorityCode[];
  material_truth: 'NOT_EVALUATED';
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

function validTimestamp(value: string): boolean {
  return timestampPattern.test(value) && !Number.isNaN(Date.parse(value));
}

function orderedCodes(codes: Set<ARVOfficialAuthorityCode>): ARVOfficialAuthorityCode[] {
  return ARV_OFFICIAL_AUTHORITY_CODES.filter((code) => codes.has(code));
}

function currentKeyStatus(
  authorization: TrustRegistryV1['authorizations'][number],
  evaluatedAt: number
): ARVCurrentKeyState {
  if (evaluatedAt < Date.parse(authorization.valid_from)) return 'UNKNOWN';
  if (authorization.valid_until !== null && evaluatedAt >= Date.parse(authorization.valid_until)) {
    return 'EXPIRED';
  }
  if (
    authorization.compromise_effective_from !== null &&
    evaluatedAt >= Date.parse(authorization.compromise_effective_from)
  ) {
    return 'REVOKED';
  }
  if (
    authorization.status !== 'ACTIVE' &&
    authorization.status_effective_at !== null &&
    evaluatedAt >= Date.parse(authorization.status_effective_at)
  ) {
    return authorization.status;
  }
  return 'ACTIVE';
}

export function evaluateOfficialAuthorityV1(
  envelopeInput: unknown,
  registryInput: unknown,
  anchor: TrustAnchorV1,
  checkpoint: TrustRegistryCheckpointV1 | null,
  options: OfficialAuthorityEvaluationOptionsV1
): OfficialAuthorityResultV1 {
  if (!validTimestamp(options.evaluated_at)) {
    throw new Error('ARV_OFFICIAL_AUTHORITY_EVALUATED_AT_INVALID');
  }
  const codes = new Set<ARVOfficialAuthorityCode>();
  let envelope: EvidenceEnvelopeV1 | null = null;
  try {
    envelope = assertEvidenceEnvelopeV1(envelopeInput);
  } catch {
    codes.add('EVIDENCE_ENVELOPE_INVALID');
  }
  const proof = verifyEvidenceEnvelopeV1(envelopeInput, {
    root_dir: options.root_dir,
    checkpoint_verified: options.evidence_checkpoint_verified
  });
  const trust = verifyTrustRegistryV1(registryInput, anchor, checkpoint);
  let registry: TrustRegistryV1 | null = null;
  try {
    registry = assertTrustRegistryV1(registryInput);
  } catch {
    registry = null;
  }

  const base = {
    schema: 'arv.official-authority-result' as const,
    schema_version: 1 as const,
    authorization_id: null as string | null,
    issuer_id: null as string | null,
    key_fingerprint: envelope?.proof.signature.public_key_fingerprint ?? null,
    product: options.product,
    environment: options.environment,
    recorded_at: envelope?.registration.recorded_at ?? null,
    evaluated_at: options.evaluated_at,
    cryptographic_integrity: proof.integrity,
    cryptographic_codes: [...proof.codes],
    registry: {
      registry_id: trust.registry_id,
      sequence: trust.sequence,
      registry_hash: trust.registry_hash,
      trust_codes: [...trust.codes]
    },
    material_truth: 'NOT_EVALUATED' as const
  };

  function result(
    status: ARVOfficialAuthorityState,
    authorityAtRecording: boolean | null,
    currentStatus: ARVCurrentKeyState,
    authorizationId: string | null = null,
    issuerId: string | null = null
  ): OfficialAuthorityResultV1 {
    return {
      ...base,
      status,
      authority_at_recording: authorityAtRecording,
      current_key_status: currentStatus,
      authorization_id: authorizationId,
      issuer_id: issuerId,
      codes: orderedCodes(codes)
    };
  }

  if (envelope === null) return result('UNKNOWN', null, 'UNKNOWN');
  if (proof.integrity !== 'VERIFIED') {
    codes.add('CRYPTOGRAPHIC_PROOF_NOT_VERIFIED');
    return result('UNKNOWN', null, 'UNKNOWN');
  }
  if (!trust.trusted || registry === null) {
    codes.add('REGISTRY_NOT_TRUSTED');
    return result('UNKNOWN', null, 'UNKNOWN');
  }
  if (Date.parse(registry.issued_at) > Date.parse(options.evaluated_at)) {
    codes.add('REGISTRY_ISSUED_AFTER_EVALUATION');
    return result('UNKNOWN', null, 'UNKNOWN');
  }
  const fingerprint = envelope.proof.signature.public_key_fingerprint;
  if (fingerprint === null) {
    codes.add('KEY_FINGERPRINT_MISSING');
    return result('UNKNOWN', null, 'UNKNOWN');
  }
  const authorization = registry.authorizations.find(
    (candidate) => candidate.key_fingerprint === fingerprint
  );
  if (!authorization) {
    codes.add('AUTHORIZATION_NOT_FOUND');
    return result('UNOFFICIAL', false, 'UNKNOWN');
  }
  const evaluatedAt = Date.parse(options.evaluated_at);
  const currentStatus = currentKeyStatus(authorization, evaluatedAt);
  const authorizationId = authorization.authorization_id;
  const issuerId = authorization.issuer_id;
  if (!authorization.roles.includes('ISSUER')) {
    codes.add('ISSUER_ROLE_NOT_AUTHORIZED');
    return result('OUT_OF_SCOPE', false, currentStatus, authorizationId, issuerId);
  }
  if (authorization.authority !== envelope.registration.authority) {
    codes.add('AUTHORITY_CLAIM_MISMATCH');
    return result('UNOFFICIAL', false, currentStatus, authorizationId, issuerId);
  }
  if (!authorization.systems.includes(envelope.registration.system)) {
    codes.add('SYSTEM_OUT_OF_SCOPE');
    return result('OUT_OF_SCOPE', false, currentStatus, authorizationId, issuerId);
  }
  if (!authorization.products.includes(options.product)) {
    codes.add('PRODUCT_OUT_OF_SCOPE');
    return result('OUT_OF_SCOPE', false, currentStatus, authorizationId, issuerId);
  }
  if (authorization.environment !== options.environment) {
    codes.add('ENVIRONMENT_OUT_OF_SCOPE');
    return result('OUT_OF_SCOPE', false, currentStatus, authorizationId, issuerId);
  }
  const recordedAt = Date.parse(envelope.registration.recorded_at);
  if (recordedAt < Date.parse(authorization.valid_from)) {
    codes.add('AUTHORIZATION_NOT_YET_VALID');
    return result('UNOFFICIAL', false, currentStatus, authorizationId, issuerId);
  }
  if (authorization.valid_until !== null && recordedAt >= Date.parse(authorization.valid_until)) {
    codes.add('AUTHORIZATION_EXPIRED_AT_RECORDING');
    return result('EXPIRED', false, currentStatus, authorizationId, issuerId);
  }
  if (
    authorization.compromise_effective_from !== null &&
    recordedAt >= Date.parse(authorization.compromise_effective_from)
  ) {
    codes.add('KEY_COMPROMISED_AT_RECORDING');
    return result('REVOKED', false, currentStatus, authorizationId, issuerId);
  }
  if (
    authorization.status !== 'ACTIVE' &&
    authorization.status_effective_at !== null &&
    recordedAt >= Date.parse(authorization.status_effective_at)
  ) {
    if (authorization.status === 'SUSPENDED') {
      codes.add('AUTHORIZATION_SUSPENDED_AT_RECORDING');
      return result('SUSPENDED', false, currentStatus, authorizationId, issuerId);
    }
    codes.add('AUTHORIZATION_REVOKED_AT_RECORDING');
    return result('REVOKED', false, currentStatus, authorizationId, issuerId);
  }
  if (currentStatus === 'SUSPENDED') codes.add('CURRENT_KEY_SUSPENDED_AFTER_RECORDING');
  if (currentStatus === 'REVOKED') codes.add('CURRENT_KEY_REVOKED_AFTER_RECORDING');
  if (currentStatus === 'EXPIRED') codes.add('CURRENT_KEY_EXPIRED_AFTER_RECORDING');
  return result('OFFICIAL', true, currentStatus, authorizationId, issuerId);
}
