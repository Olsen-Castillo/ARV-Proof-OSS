export const ARV_VERIFICATION_RESULT_SCHEMA = 'arv.verification-result' as const;
export const ARV_VERIFICATION_RESULT_SCHEMA_VERSION = 1 as const;

export const ARV_INTEGRITY_STATES = [
  'VERIFIED',
  'FAILED',
  'INDETERMINATE'
] as const;

export const ARV_LIFECYCLE_STATES = [
  'ACTIVE',
  'SUPERSEDED',
  'REVOKED',
  'UNKNOWN'
] as const;

export const ARV_ARTIFACT_MATCH_STATES = [
  'MATCH',
  'MISMATCH',
  'NOT_CHECKED'
] as const;

export const ARV_OVERALL_STATES = [
  'VERIFIED_ACTIVE',
  'VERIFIED_HISTORICAL',
  'FAILED',
  'INDETERMINATE'
] as const;

export const ARV_VERIFICATION_CODES = [
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
] as const;

export type ARVIntegrityState = typeof ARV_INTEGRITY_STATES[number];
export type ARVLifecycleState = typeof ARV_LIFECYCLE_STATES[number];
export type ARVArtifactMatchState = typeof ARV_ARTIFACT_MATCH_STATES[number];
export type ARVOverallState = typeof ARV_OVERALL_STATES[number];
export type ARVVerificationCode = typeof ARV_VERIFICATION_CODES[number];

export interface VerificationResultV1 {
  schema: typeof ARV_VERIFICATION_RESULT_SCHEMA;
  schema_version: typeof ARV_VERIFICATION_RESULT_SCHEMA_VERSION;
  integrity: ARVIntegrityState;
  lifecycle: ARVLifecycleState;
  artifact_match: ARVArtifactMatchState;
  overall: ARVOverallState;
  codes: ARVVerificationCode[];
}

const RESULT_KEYS = [
  'schema',
  'schema_version',
  'integrity',
  'lifecycle',
  'artifact_match',
  'overall',
  'codes'
] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyResultKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value).sort();
  const expected = [...RESULT_KEYS].sort();
  return JSON.stringify(keys) === JSON.stringify(expected);
}

function includes<T extends readonly string[]>(values: T, value: unknown): value is T[number] {
  return typeof value === 'string' && values.includes(value as T[number]);
}

export function isVerificationResultV1(value: unknown): value is VerificationResultV1 {
  if (!isPlainObject(value) || !hasOnlyResultKeys(value)) return false;
  if (value.schema !== ARV_VERIFICATION_RESULT_SCHEMA) return false;
  if (value.schema_version !== ARV_VERIFICATION_RESULT_SCHEMA_VERSION) return false;
  if (!includes(ARV_INTEGRITY_STATES, value.integrity)) return false;
  if (!includes(ARV_LIFECYCLE_STATES, value.lifecycle)) return false;
  if (!includes(ARV_ARTIFACT_MATCH_STATES, value.artifact_match)) return false;
  if (!includes(ARV_OVERALL_STATES, value.overall)) return false;
  if (!Array.isArray(value.codes)) return false;
  if (!value.codes.every((code) => includes(ARV_VERIFICATION_CODES, code))) return false;
  if (new Set(value.codes).size !== value.codes.length) return false;

  const expectedOverall = deriveARVOverallState(
    value.integrity,
    value.lifecycle,
    value.artifact_match
  );
  if (value.overall !== expectedOverall) return false;

  return true;
}

export function deriveARVOverallState(
  integrity: ARVIntegrityState,
  lifecycle: ARVLifecycleState,
  artifactMatch: ARVArtifactMatchState
): ARVOverallState {
  if (artifactMatch === 'MISMATCH') return 'FAILED';
  if (integrity === 'FAILED') return 'FAILED';
  if (integrity === 'INDETERMINATE') return 'INDETERMINATE';
  if (lifecycle === 'ACTIVE') return 'VERIFIED_ACTIVE';
  if (lifecycle === 'SUPERSEDED' || lifecycle === 'REVOKED') return 'VERIFIED_HISTORICAL';
  return 'INDETERMINATE';
}

export function assertVerificationResultV1(value: unknown): VerificationResultV1 {
  if (!isVerificationResultV1(value)) {
    throw new Error('ARV_VERIFICATION_RESULT_V1_INVALID');
  }

  return value;
}
