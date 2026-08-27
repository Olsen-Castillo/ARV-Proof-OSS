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
import { ARVVerifierAttestationTransparencyVerificationV1 } from './verifier-attestation-transparency-v1';

export const ARV_VERIFIER_INCIDENT_POLICY_SCHEMA = 'arv.verifier-incident-adjudication-policy' as const;
export const ARV_VERIFIER_INCIDENT_CASE_SCHEMA = 'arv.verifier-incident-case' as const;
export const ARV_VERIFIER_INCIDENT_DECISION_SCHEMA = 'arv.verifier-incident-adjudication-decision' as const;
export const ARV_VERIFIER_QUARANTINE_STATE_SCHEMA = 'arv.verifier-quarantine-state' as const;
export const ARV_VERIFIER_INCIDENT_RECOVERY_AUTHORIZATION_SCHEMA = 'arv.verifier-incident-recovery-authorization' as const;
export const ARV_VERIFIER_INCIDENT_SCHEMA_VERSION = 1 as const;

export const ARV_VERIFIER_INCIDENT_TYPES = [
  'ATTESTATION_FAILURE', 'EVENT_CHAIN_FAILURE', 'GAP', 'RUNTIME_DRIFT',
  'ROLLBACK', 'SPLIT_VIEW', 'TRANSPARENCY_FAILURE', 'EQUIVOCATION'
] as const;
export const ARV_VERIFIER_INCIDENT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
export const ARV_VERIFIER_INCIDENT_OUTCOMES = [
  'DISMISS', 'QUARANTINE', 'RECOVER', 'RETAIN_QUARANTINE'
] as const;
export const ARV_VERIFIER_QUARANTINE_STATUSES = ['CLEAR', 'QUARANTINED'] as const;
export const ARV_VERIFIER_INCIDENT_OPERATIONS = ['NONE', 'DISMISS', 'QUARANTINE', 'RECOVER', 'REPLAY', 'RETAIN'] as const;
export const ARV_VERIFIER_INCIDENT_STATES = [
  'INCIDENT_DISMISSED', 'QUARANTINE_APPLIED', 'QUARANTINE_RETAINED', 'RECOVERY_AUTHORIZED', 'REPLAY_ACCEPTED',
  'POLICY_INVALID', 'ROOT_INVALID', 'ROOT_BINDING_INVALID', 'TRANSPARENCY_EVIDENCE_INVALID',
  'INCIDENT_INVALID', 'INCIDENT_BINDING_INVALID', 'DECISION_INVALID', 'DECISION_BINDING_INVALID',
  'ADJUDICATOR_QUORUM_NOT_MET', 'DISMISSAL_FORBIDDEN', 'CURRENT_STATE_REQUIRED', 'CURRENT_STATE_INVALID',
  'COMPARE_AND_SWAP_REQUIRED', 'COMPARE_AND_SWAP_MISMATCH', 'INCIDENT_ROLLBACK', 'INCIDENT_GAP',
  'INCIDENT_EQUIVOCATION', 'RECOVERY_AUTHORIZATION_REQUIRED', 'RECOVERY_AUTHORIZATION_INVALID',
  'ROOT_RECOVERY_QUORUM_NOT_MET', 'RECOVERY_ADJUDICATOR_QUORUM_NOT_MET', 'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVVerifierIncidentTypeV1 = typeof ARV_VERIFIER_INCIDENT_TYPES[number];
export type ARVVerifierIncidentSeverityV1 = typeof ARV_VERIFIER_INCIDENT_SEVERITIES[number];
export type ARVVerifierIncidentOutcomeV1 = typeof ARV_VERIFIER_INCIDENT_OUTCOMES[number];
export type ARVVerifierQuarantineStatusV1 = typeof ARV_VERIFIER_QUARANTINE_STATUSES[number];
export type ARVVerifierIncidentOperationV1 = typeof ARV_VERIFIER_INCIDENT_OPERATIONS[number];
export type ARVVerifierIncidentStateV1 = typeof ARV_VERIFIER_INCIDENT_STATES[number];

export interface ARVIncidentAdjudicatorV1 {
  adjudicator_id: string;
  key_id: string;
  algorithm: 'Ed25519';
  public_key_spki_base64: string;
  status: 'ACTIVE' | 'REVOKED';
  valid_from: string;
  expires_at: string;
}

export interface ARVVerifierIncidentAdjudicationPolicyV1 {
  schema: typeof ARV_VERIFIER_INCIDENT_POLICY_SCHEMA;
  schema_version: 1;
  policy_id: string;
  policy_version: number;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  adjudication_threshold: number;
  dismissal_threshold: number;
  recovery_threshold: number;
  max_decision_age_seconds: number;
  max_clock_skew_seconds: number;
  adjudicators: ARVIncidentAdjudicatorV1[];
  issued_at: string;
}

export interface ARVVerifierIncidentCaseV1 {
  schema: typeof ARV_VERIFIER_INCIDENT_CASE_SCHEMA;
  schema_version: 1;
  incident_id: string;
  verifier_id: string;
  instance_id: string;
  incident_sequence: number;
  incident_type: ARVVerifierIncidentTypeV1;
  severity: ARVVerifierIncidentSeverityV1;
  trigger_state: string;
  trigger_transparency_hash: string;
  trigger_checkpoint_hash: string | null;
  trigger_evidence_digest: string;
  opened_at: string;
  previous_incident_hash: string | null;
}

export interface ARVIncidentSignatureV1 {
  algorithm: 'Ed25519';
  key_id: string;
  signature_base64: string;
}

export interface ARVVerifierIncidentAdjudicationDecisionV1 {
  schema: typeof ARV_VERIFIER_INCIDENT_DECISION_SCHEMA;
  schema_version: 1;
  decision_id: string;
  incident_id: string;
  incident_hash: string;
  decision_sequence: number;
  outcome: ARVVerifierIncidentOutcomeV1;
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  reason_digest: string;
  issued_at: string;
  previous_decision_hash: string | null;
  authorizations: ARVIncidentSignatureV1[];
}

export interface ARVVerifierQuarantineStateV1 {
  schema: typeof ARV_VERIFIER_QUARANTINE_STATE_SCHEMA;
  schema_version: 1;
  state_id: string;
  verifier_id: string;
  instance_id: string;
  generation: number;
  status: ARVVerifierQuarantineStatusV1;
  incident_sequence: number;
  incident_hash: string;
  decision_hash: string;
  effective_at: string;
  previous_state_hash: string | null;
}

export interface ARVVerifierIncidentRecoveryAuthorizationV1 {
  schema: typeof ARV_VERIFIER_INCIDENT_RECOVERY_AUTHORIZATION_SCHEMA;
  schema_version: 1;
  authorization_id: string;
  incident_id: string;
  incident_hash: string;
  quarantine_state_hash: string;
  policy_hash: string;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  issued_at: string;
  expires_at: string;
  reason_digest: string;
  root_authorizations: ARVTrustRootSignatureV1[];
  adjudicator_authorizations: ARVIncidentSignatureV1[];
}

export interface VerifyARVVerifierIncidentAdjudicationOptionsV1 {
  incident_policy: unknown;
  trust_root: unknown;
  transparency_verification: unknown;
  incident_case: unknown;
  adjudication_decision: unknown;
  recovery_authorization: unknown | null;
  current_quarantine_state: unknown | null;
  expected_current_quarantine_state_hash: string | null;
  next_state_id: string;
  evaluated_at: string;
}

export interface ARVVerifierIncidentAdjudicationVerificationV1 {
  schema: 'arv.verifier-incident-adjudication-verification';
  schema_version: 1;
  accepted: boolean;
  frozen: boolean;
  quarantined: boolean;
  state: ARVVerifierIncidentStateV1;
  operation: ARVVerifierIncidentOperationV1;
  policy_hash: string | null;
  root_hash: string | null;
  transparency_verification_hash: string | null;
  incident_hash: string | null;
  decision_hash: string | null;
  current_quarantine_state_hash: string | null;
  commit_precondition_hash: string | null;
  next_quarantine_state_hash: string | null;
  next_quarantine_state: ARVVerifierQuarantineStateV1 | null;
  valid_adjudicator_signatures: number;
  valid_root_recovery_signatures: number;
  valid_recovery_adjudicator_signatures: number;
  codes: string[];
  incident_evidence_authority: 'VERIFIED_TRANSPARENCY_COMMITMENTS';
  adjudication_authority: 'ROOT_BOUND_INDEPENDENT_ADJUDICATOR_QUORUM';
  recovery_authority: 'ROOT_RECOVERY_AND_ADJUDICATOR_QUORUM';
  quarantine_authority: 'FAIL_CLOSED_STATE_MACHINE';
  log_operator_authority: 'NONE';
  monitor_authority: 'NONE';
  storage_authority: 'NONE';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const digestPattern = /^[a-f0-9]{64}$/;
const keyPattern = /^[a-f0-9]{24,128}$/;
const policyPattern = /^ARV-INCIDENT-ADJUDICATION-POLICY-[A-Z0-9-]+$/;
const incidentPattern = /^ARV-INCIDENT-[A-Z0-9-]+$/;
const decisionPattern = /^ARV-INCIDENT-DECISION-[A-Z0-9-]+$/;
const statePattern = /^ARV-QUARANTINE-STATE-[A-Z0-9-]+$/;
const recoveryPattern = /^ARV-INCIDENT-RECOVERY-[A-Z0-9-]+$/;
const verifierPattern = /^ARV-VERIFIER-[A-Z0-9-]+$/;
const instancePattern = /^ARV-VERIFIER-INSTANCE-[A-Z0-9-]+$/;
const rootPattern = /^ARV-ROOT-[A-Z0-9-]+$/;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function object(value: unknown, location: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${location} must be an object`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, fields: readonly string[], location: string): void {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) throw new Error(`${location} fields are invalid`);
}
function string(value: unknown, pattern: RegExp, location: string): asserts value is string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${location} is invalid`);
}
function digest(value: unknown, location: string): asserts value is string { string(value, digestPattern, location); }
function positive(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || Number(value) < 1) throw new Error(`${location} must be a positive integer`);
}
function timestamp(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !timestampPattern.test(value) || Number.isNaN(Date.parse(value))) throw new Error(`${location} must be a UTC timestamp`);
}
function nullableDigest(value: unknown, location: string): asserts value is string | null {
  if (value !== null) digest(value, location);
}
function sha256Domain(domain: string, value: unknown): string {
  return crypto.createHash('sha256').update(`${domain}\n${canonicalizeARVJsonV1(value)}`, 'utf8').digest('hex');
}
function parseSignature(value: unknown, location: string): ARVIncidentSignatureV1 {
  const input = object(value, location);
  exact(input, ['algorithm','key_id','signature_base64'], location);
  if (input.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  string(input.key_id, keyPattern, `${location}.key_id`);
  string(input.signature_base64, base64Pattern, `${location}.signature_base64`);
  const bytes = Buffer.from(input.signature_base64, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== input.signature_base64) throw new Error(`${location} signature encoding is invalid`);
  return input as unknown as ARVIncidentSignatureV1;
}
function parseRootSignature(value: unknown, location: string): ARVTrustRootSignatureV1 {
  const input = object(value, location);
  exact(input, ['algorithm','key_id','signature_base64'], location);
  if (input.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  string(input.key_id, /^[a-f0-9]{24}$/, `${location}.key_id`);
  string(input.signature_base64, base64Pattern, `${location}.signature_base64`);
  if (Buffer.from(input.signature_base64, 'base64').length !== 64) throw new Error(`${location} signature length is invalid`);
  return input as unknown as ARVTrustRootSignatureV1;
}

export function assertARVVerifierIncidentAdjudicationPolicyV1(value: unknown): ARVVerifierIncidentAdjudicationPolicyV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$incident_policy');
  exact(input, ['schema','schema_version','policy_id','policy_version','root_id','root_version','root_epoch','root_hash','adjudication_threshold','dismissal_threshold','recovery_threshold','max_decision_age_seconds','max_clock_skew_seconds','adjudicators','issued_at'], '$incident_policy');
  if (input.schema !== ARV_VERIFIER_INCIDENT_POLICY_SCHEMA || input.schema_version !== 1) throw new Error('$incident_policy schema is invalid');
  string(input.policy_id, policyPattern, '$incident_policy.policy_id'); positive(input.policy_version, '$incident_policy.policy_version');
  string(input.root_id, rootPattern, '$incident_policy.root_id'); positive(input.root_version, '$incident_policy.root_version'); positive(input.root_epoch, '$incident_policy.root_epoch'); digest(input.root_hash, '$incident_policy.root_hash');
  positive(input.adjudication_threshold, '$incident_policy.adjudication_threshold'); positive(input.dismissal_threshold, '$incident_policy.dismissal_threshold'); positive(input.recovery_threshold, '$incident_policy.recovery_threshold');
  positive(input.max_decision_age_seconds, '$incident_policy.max_decision_age_seconds'); positive(input.max_clock_skew_seconds, '$incident_policy.max_clock_skew_seconds'); timestamp(input.issued_at, '$incident_policy.issued_at');
  if (!Array.isArray(input.adjudicators) || input.adjudicators.length === 0) throw new Error('$incident_policy.adjudicators is invalid');
  const adjudicators = input.adjudicators.map((value, index) => {
    const item = object(value, `$incident_policy.adjudicators[${index}]`);
    exact(item, ['adjudicator_id','key_id','algorithm','public_key_spki_base64','status','valid_from','expires_at'], `$incident_policy.adjudicators[${index}]`);
    string(item.adjudicator_id, /^ARV-ADJUDICATOR-[A-Z0-9-]+$/, `$incident_policy.adjudicators[${index}].adjudicator_id`);
    string(item.key_id, keyPattern, `$incident_policy.adjudicators[${index}].key_id`);
    if (item.algorithm !== 'Ed25519' || !['ACTIVE','REVOKED'].includes(String(item.status))) throw new Error('$incident_policy adjudicator is invalid');
    string(item.public_key_spki_base64, base64Pattern, `$incident_policy.adjudicators[${index}].public_key_spki_base64`);
    timestamp(item.valid_from, `$incident_policy.adjudicators[${index}].valid_from`); timestamp(item.expires_at, `$incident_policy.adjudicators[${index}].expires_at`);
    return item as unknown as ARVIncidentAdjudicatorV1;
  });
  const ids = adjudicators.map((item) => item.adjudicator_id); const keys = adjudicators.map((item) => item.key_id);
  if (new Set(ids).size !== ids.length || new Set(keys).size !== keys.length || ids.some((item, index) => item !== [...ids].sort()[index])) throw new Error('$incident_policy adjudicators must be unique and sorted');
  for (const threshold of [input.adjudication_threshold,input.dismissal_threshold,input.recovery_threshold]) if (Number(threshold) > adjudicators.length) throw new Error('$incident_policy threshold exceeds adjudicator count');
  return { ...(input as unknown as ARVVerifierIncidentAdjudicationPolicyV1), adjudicators };
}

export function assertARVVerifierIncidentCaseV1(value: unknown): ARVVerifierIncidentCaseV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$incident_case');
  exact(input, ['schema','schema_version','incident_id','verifier_id','instance_id','incident_sequence','incident_type','severity','trigger_state','trigger_transparency_hash','trigger_checkpoint_hash','trigger_evidence_digest','opened_at','previous_incident_hash'], '$incident_case');
  if (input.schema !== ARV_VERIFIER_INCIDENT_CASE_SCHEMA || input.schema_version !== 1) throw new Error('$incident_case schema is invalid');
  string(input.incident_id, incidentPattern, '$incident_case.incident_id'); string(input.verifier_id, verifierPattern, '$incident_case.verifier_id'); string(input.instance_id, instancePattern, '$incident_case.instance_id');
  positive(input.incident_sequence, '$incident_case.incident_sequence');
  if (!ARV_VERIFIER_INCIDENT_TYPES.includes(input.incident_type as ARVVerifierIncidentTypeV1) || !ARV_VERIFIER_INCIDENT_SEVERITIES.includes(input.severity as ARVVerifierIncidentSeverityV1)) throw new Error('$incident_case classification is invalid');
  if (typeof input.trigger_state !== 'string' || input.trigger_state.length === 0) throw new Error('$incident_case.trigger_state is invalid');
  digest(input.trigger_transparency_hash, '$incident_case.trigger_transparency_hash'); nullableDigest(input.trigger_checkpoint_hash, '$incident_case.trigger_checkpoint_hash'); digest(input.trigger_evidence_digest, '$incident_case.trigger_evidence_digest');
  timestamp(input.opened_at, '$incident_case.opened_at'); nullableDigest(input.previous_incident_hash, '$incident_case.previous_incident_hash');
  if (Number(input.incident_sequence) === 1 && input.previous_incident_hash !== null) throw new Error('$incident_case genesis linkage is invalid');
  if (Number(input.incident_sequence) > 1 && input.previous_incident_hash === null) throw new Error('$incident_case previous hash is required');
  return input as unknown as ARVVerifierIncidentCaseV1;
}

export function assertARVVerifierIncidentAdjudicationDecisionV1(value: unknown): ARVVerifierIncidentAdjudicationDecisionV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$adjudication_decision');
  exact(input, ['schema','schema_version','decision_id','incident_id','incident_hash','decision_sequence','outcome','policy_id','policy_version','policy_hash','reason_digest','issued_at','previous_decision_hash','authorizations'], '$adjudication_decision');
  if (input.schema !== ARV_VERIFIER_INCIDENT_DECISION_SCHEMA || input.schema_version !== 1) throw new Error('$adjudication_decision schema is invalid');
  string(input.decision_id, decisionPattern, '$adjudication_decision.decision_id'); string(input.incident_id, incidentPattern, '$adjudication_decision.incident_id'); digest(input.incident_hash, '$adjudication_decision.incident_hash');
  positive(input.decision_sequence, '$adjudication_decision.decision_sequence');
  if (!ARV_VERIFIER_INCIDENT_OUTCOMES.includes(input.outcome as ARVVerifierIncidentOutcomeV1)) throw new Error('$adjudication_decision.outcome is invalid');
  string(input.policy_id, policyPattern, '$adjudication_decision.policy_id'); positive(input.policy_version, '$adjudication_decision.policy_version'); digest(input.policy_hash, '$adjudication_decision.policy_hash'); digest(input.reason_digest, '$adjudication_decision.reason_digest');
  timestamp(input.issued_at, '$adjudication_decision.issued_at'); nullableDigest(input.previous_decision_hash, '$adjudication_decision.previous_decision_hash');
  if (!Array.isArray(input.authorizations) || input.authorizations.length === 0) throw new Error('$adjudication_decision.authorizations is invalid');
  const authorizations = input.authorizations.map((item, index) => parseSignature(item, `$adjudication_decision.authorizations[${index}]`));
  const keys = authorizations.map((item) => item.key_id);
  if (new Set(keys).size !== keys.length || keys.some((item, index) => item !== [...keys].sort()[index])) throw new Error('$adjudication_decision authorizations must be unique and sorted');
  return { ...(input as unknown as ARVVerifierIncidentAdjudicationDecisionV1), authorizations };
}

export function assertARVVerifierQuarantineStateV1(value: unknown): ARVVerifierQuarantineStateV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$quarantine_state');
  exact(input, ['schema','schema_version','state_id','verifier_id','instance_id','generation','status','incident_sequence','incident_hash','decision_hash','effective_at','previous_state_hash'], '$quarantine_state');
  if (input.schema !== ARV_VERIFIER_QUARANTINE_STATE_SCHEMA || input.schema_version !== 1) throw new Error('$quarantine_state schema is invalid');
  string(input.state_id, statePattern, '$quarantine_state.state_id'); string(input.verifier_id, verifierPattern, '$quarantine_state.verifier_id'); string(input.instance_id, instancePattern, '$quarantine_state.instance_id');
  positive(input.generation, '$quarantine_state.generation'); if (!ARV_VERIFIER_QUARANTINE_STATUSES.includes(input.status as ARVVerifierQuarantineStatusV1)) throw new Error('$quarantine_state.status is invalid');
  positive(input.incident_sequence, '$quarantine_state.incident_sequence'); digest(input.incident_hash, '$quarantine_state.incident_hash'); digest(input.decision_hash, '$quarantine_state.decision_hash'); timestamp(input.effective_at, '$quarantine_state.effective_at'); nullableDigest(input.previous_state_hash, '$quarantine_state.previous_state_hash');
  if (Number(input.generation) === 1 && input.previous_state_hash !== null) throw new Error('$quarantine_state genesis linkage is invalid');
  if (Number(input.generation) > 1 && input.previous_state_hash === null) throw new Error('$quarantine_state previous hash is required');
  return input as unknown as ARVVerifierQuarantineStateV1;
}

export function assertARVVerifierIncidentRecoveryAuthorizationV1(value: unknown): ARVVerifierIncidentRecoveryAuthorizationV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$recovery_authorization');
  exact(input, ['schema','schema_version','authorization_id','incident_id','incident_hash','quarantine_state_hash','policy_hash','root_id','root_version','root_epoch','root_hash','issued_at','expires_at','reason_digest','root_authorizations','adjudicator_authorizations'], '$recovery_authorization');
  if (input.schema !== ARV_VERIFIER_INCIDENT_RECOVERY_AUTHORIZATION_SCHEMA || input.schema_version !== 1) throw new Error('$recovery_authorization schema is invalid');
  string(input.authorization_id, recoveryPattern, '$recovery_authorization.authorization_id'); string(input.incident_id, incidentPattern, '$recovery_authorization.incident_id');
  for (const field of ['incident_hash','quarantine_state_hash','policy_hash','root_hash','reason_digest'] as const) digest(input[field], `$recovery_authorization.${field}`);
  string(input.root_id, rootPattern, '$recovery_authorization.root_id'); positive(input.root_version, '$recovery_authorization.root_version'); positive(input.root_epoch, '$recovery_authorization.root_epoch'); timestamp(input.issued_at, '$recovery_authorization.issued_at'); timestamp(input.expires_at, '$recovery_authorization.expires_at');
  if (!Array.isArray(input.root_authorizations) || !Array.isArray(input.adjudicator_authorizations)) throw new Error('$recovery_authorization signatures are invalid');
  const rootAuthorizations = input.root_authorizations.map((item, index) => parseRootSignature(item, `$recovery_authorization.root_authorizations[${index}]`));
  const adjudicatorAuthorizations = input.adjudicator_authorizations.map((item, index) => parseSignature(item, `$recovery_authorization.adjudicator_authorizations[${index}]`));
  for (const signatures of [rootAuthorizations, adjudicatorAuthorizations]) {
    const keys = signatures.map((item) => item.key_id);
    if (new Set(keys).size !== keys.length || keys.some((item, index) => item !== [...keys].sort()[index])) throw new Error('$recovery_authorization signatures must be unique and sorted');
  }
  return { ...(input as unknown as ARVVerifierIncidentRecoveryAuthorizationV1), root_authorizations: rootAuthorizations, adjudicator_authorizations: adjudicatorAuthorizations };
}

export function assertARVVerifierAttestationTransparencyVerificationForIncidentV1(value: unknown): ARVVerifierAttestationTransparencyVerificationV1 {
  const input = object(value, '$transparency_verification');
  exact(input, ['schema','schema_version','accepted','frozen','state','operation','policy_hash','attestation_hash','security_event_chain_hash','entry_hash','leaf_hash','checkpoint_hash','current_checkpoint_hash','commit_precondition_hash','next_checkpoint_hash','valid_operator_signatures','valid_monitor_observations','codes','runtime_evidence_authority','transparency_authority','log_operator_authority','monitor_authority','storage_authority','transport_authority','material_truth'], '$transparency_verification');
  if (input.schema !== 'arv.verifier-attestation-transparency-verification' || input.schema_version !== 1 || typeof input.accepted !== 'boolean' || typeof input.frozen !== 'boolean') throw new Error('$transparency_verification schema is invalid');
  if (typeof input.state !== 'string' || typeof input.operation !== 'string' || !Array.isArray(input.codes)) throw new Error('$transparency_verification state is invalid');
  for (const field of ['policy_hash','attestation_hash','security_event_chain_hash','entry_hash','leaf_hash','checkpoint_hash','current_checkpoint_hash','commit_precondition_hash','next_checkpoint_hash'] as const) nullableDigest(input[field], `$transparency_verification.${field}`);
  if (!Number.isInteger(input.valid_operator_signatures) || !Number.isInteger(input.valid_monitor_observations)) throw new Error('$transparency_verification counts are invalid');
  if (input.runtime_evidence_authority !== 'VERIFIED_ATTESTATION_AND_EVENT_CHAIN' || input.transparency_authority !== 'APPEND_ONLY_COMMITMENT_PROOFS' || input.log_operator_authority !== 'COMMITMENT_PUBLICATION_ONLY' || input.monitor_authority !== 'INDEPENDENT_OBSERVATION_ONLY' || input.storage_authority !== 'NONE' || input.transport_authority !== 'NONE' || input.material_truth !== 'NOT_EVALUATED') throw new Error('$transparency_verification authority boundary is invalid');
  return input as unknown as ARVVerifierAttestationTransparencyVerificationV1;
}

export function sha256ARVVerifierIncidentAdjudicationPolicyV1(value: ARVVerifierIncidentAdjudicationPolicyV1): string { return sha256Domain('ARV-VERIFIER-INCIDENT-ADJUDICATION-POLICY-v1', assertARVVerifierIncidentAdjudicationPolicyV1(value)); }
export function sha256ARVVerifierIncidentCaseV1(value: ARVVerifierIncidentCaseV1): string { return sha256Domain('ARV-VERIFIER-INCIDENT-CASE-v1', assertARVVerifierIncidentCaseV1(value)); }
export function sha256ARVVerifierIncidentDecisionV1(value: ARVVerifierIncidentAdjudicationDecisionV1): string { return sha256Domain('ARV-VERIFIER-INCIDENT-DECISION-v1', assertARVVerifierIncidentAdjudicationDecisionV1(value)); }
export function sha256ARVVerifierQuarantineStateV1(value: ARVVerifierQuarantineStateV1): string { return sha256Domain('ARV-VERIFIER-QUARANTINE-STATE-v1', assertARVVerifierQuarantineStateV1(value)); }
export function sha256ARVVerifierTransparencyVerificationForIncidentV1(value: ARVVerifierAttestationTransparencyVerificationV1): string { return sha256Domain('ARV-VERIFIER-ATTESTATION-TRANSPARENCY-VERIFICATION-v1', value); }

export function canonicalARVVerifierIncidentDecisionSigningBytesV1(value: ARVVerifierIncidentAdjudicationDecisionV1): Buffer {
  const { authorizations: _authorizations, ...unsigned } = assertARVVerifierIncidentAdjudicationDecisionV1(value);
  return Buffer.from(`ARV-VERIFIER-INCIDENT-DECISION-v1\n${canonicalizeARVJsonV1(unsigned)}`, 'utf8');
}
export function canonicalARVVerifierIncidentRecoverySigningBytesV1(value: ARVVerifierIncidentRecoveryAuthorizationV1): Buffer {
  const { root_authorizations: _root, adjudicator_authorizations: _adjudicators, ...unsigned } = assertARVVerifierIncidentRecoveryAuthorizationV1(value);
  return Buffer.from(`ARV-VERIFIER-INCIDENT-RECOVERY-v1\n${canonicalizeARVJsonV1(unsigned)}`, 'utf8');
}
function activeAdjudicator(value: ARVIncidentAdjudicatorV1, at: number): boolean { return value.status === 'ACTIVE' && Date.parse(value.valid_from) <= at && at < Date.parse(value.expires_at); }
function verifySpki(publicKey: string, payload: Buffer, signature: string): boolean {
  try { return crypto.verify(null, payload, { key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' }, Buffer.from(signature, 'base64')); } catch { return false; }
}
function validAdjudicatorSignatures(policy: ARVVerifierIncidentAdjudicationPolicyV1, signatures: ARVIncidentSignatureV1[], payload: Buffer, at: number): number {
  const accepted = new Set<string>();
  for (const signature of signatures) {
    const signer = policy.adjudicators.find((candidate) => candidate.key_id === signature.key_id);
    if (signer && !accepted.has(signer.key_id) && activeAdjudicator(signer, at) && verifySpki(signer.public_key_spki_base64, payload, signature.signature_base64)) accepted.add(signer.key_id);
  }
  return accepted.size;
}
function validRootRecoverySignatures(root: ARVTrustRootV1, signatures: ARVTrustRootSignatureV1[], payload: Buffer, at: number): number {
  const accepted = new Set<string>();
  for (const signature of signatures) {
    const key = root.keys.find((candidate) => candidate.key_id === signature.key_id);
    if (!key || accepted.has(key.key_id) || key.status !== 'ACTIVE' || !key.roles.includes('RECOVERY')) continue;
    if (Date.parse(key.valid_from) > at || (key.valid_until !== null && at >= Date.parse(key.valid_until))) continue;
    try {
      if (nacl.sign.detached.verify(payload, decodeBase64(signature.signature_base64), decodeBase64(key.public_key_base64))) accepted.add(key.key_id);
    } catch { continue; }
  }
  return accepted.size;
}

function result(
  state: ARVVerifierIncidentStateV1,
  operation: ARVVerifierIncidentOperationV1,
  codes: string[],
  hashes: Partial<Pick<ARVVerifierIncidentAdjudicationVerificationV1,'policy_hash'|'root_hash'|'transparency_verification_hash'|'incident_hash'|'decision_hash'|'current_quarantine_state_hash'|'commit_precondition_hash'|'next_quarantine_state_hash'>>,
  next: ARVVerifierQuarantineStateV1 | null,
  adjudicators = 0,
  rootRecovery = 0,
  recoveryAdjudicators = 0
): ARVVerifierIncidentAdjudicationVerificationV1 {
  const accepted = ['INCIDENT_DISMISSED','QUARANTINE_APPLIED','QUARANTINE_RETAINED','RECOVERY_AUTHORIZED','REPLAY_ACCEPTED'].includes(state);
  const quarantined = next !== null ? next.status === 'QUARANTINED' : !accepted;
  return {
    schema: 'arv.verifier-incident-adjudication-verification', schema_version: 1,
    accepted, frozen: quarantined, quarantined, state, operation,
    policy_hash: hashes.policy_hash ?? null, root_hash: hashes.root_hash ?? null,
    transparency_verification_hash: hashes.transparency_verification_hash ?? null,
    incident_hash: hashes.incident_hash ?? null, decision_hash: hashes.decision_hash ?? null,
    current_quarantine_state_hash: hashes.current_quarantine_state_hash ?? null,
    commit_precondition_hash: hashes.commit_precondition_hash ?? null,
    next_quarantine_state_hash: accepted ? (hashes.next_quarantine_state_hash ?? null) : null,
    next_quarantine_state: accepted ? next : null,
    valid_adjudicator_signatures: adjudicators,
    valid_root_recovery_signatures: rootRecovery,
    valid_recovery_adjudicator_signatures: recoveryAdjudicators,
    codes,
    incident_evidence_authority: 'VERIFIED_TRANSPARENCY_COMMITMENTS',
    adjudication_authority: 'ROOT_BOUND_INDEPENDENT_ADJUDICATOR_QUORUM',
    recovery_authority: 'ROOT_RECOVERY_AND_ADJUDICATOR_QUORUM',
    quarantine_authority: 'FAIL_CLOSED_STATE_MACHINE',
    log_operator_authority: 'NONE', monitor_authority: 'NONE', storage_authority: 'NONE', transport_authority: 'NONE', material_truth: 'NOT_EVALUATED'
  };
}

const mandatoryQuarantine = new Set<ARVVerifierIncidentTypeV1>(['ROLLBACK','GAP','EQUIVOCATION','SPLIT_VIEW']);

export function verifyARVVerifierIncidentAdjudicationV1(options: VerifyARVVerifierIncidentAdjudicationOptionsV1): ARVVerifierIncidentAdjudicationVerificationV1 {
  const hashes: Parameters<typeof result>[3] = {};
  try { assertNoARVPrivateKeyMaterialV1(options); } catch { return result('PRIVATE_KEY_MATERIAL_FORBIDDEN','NONE',['PRIVATE_KEY_MATERIAL_FORBIDDEN'],hashes,null); }
  let policy: ARVVerifierIncidentAdjudicationPolicyV1; let root: ARVTrustRootV1;
  try { policy = assertARVVerifierIncidentAdjudicationPolicyV1(options.incident_policy); hashes.policy_hash = sha256ARVVerifierIncidentAdjudicationPolicyV1(policy); }
  catch { return result('POLICY_INVALID','NONE',['POLICY_INVALID'],hashes,null); }
  try { root = assertARVTrustRootV1(options.trust_root); hashes.root_hash = sha256ARVTrustRootV1(root); }
  catch { return result('ROOT_INVALID','NONE',['ROOT_INVALID'],hashes,null); }
  if (policy.root_id !== root.root_id || policy.root_version !== root.root_version || policy.root_epoch !== root.epoch || policy.root_hash !== hashes.root_hash) return result('ROOT_BINDING_INVALID','NONE',['POLICY_ROOT_BINDING_INVALID'],hashes,null);
  let transparency: ARVVerifierAttestationTransparencyVerificationV1;
  try { transparency = assertARVVerifierAttestationTransparencyVerificationForIncidentV1(options.transparency_verification); hashes.transparency_verification_hash = sha256ARVVerifierTransparencyVerificationForIncidentV1(transparency); }
  catch { return result('TRANSPARENCY_EVIDENCE_INVALID','NONE',['TRANSPARENCY_EVIDENCE_INVALID'],hashes,null); }
  let incident: ARVVerifierIncidentCaseV1;
  try { incident = assertARVVerifierIncidentCaseV1(options.incident_case); hashes.incident_hash = sha256ARVVerifierIncidentCaseV1(incident); }
  catch { return result('INCIDENT_INVALID','NONE',['INCIDENT_INVALID'],hashes,null); }
  if (incident.trigger_state !== transparency.state || incident.trigger_transparency_hash !== hashes.transparency_verification_hash || incident.trigger_checkpoint_hash !== transparency.checkpoint_hash) return result('INCIDENT_BINDING_INVALID','NONE',['INCIDENT_BINDING_INVALID'],hashes,null);
  let decision: ARVVerifierIncidentAdjudicationDecisionV1;
  try { decision = assertARVVerifierIncidentAdjudicationDecisionV1(options.adjudication_decision); hashes.decision_hash = sha256ARVVerifierIncidentDecisionV1(decision); }
  catch { return result('DECISION_INVALID','NONE',['DECISION_INVALID'],hashes,null); }
  if (decision.incident_id !== incident.incident_id || decision.incident_hash !== hashes.incident_hash || decision.decision_sequence !== incident.incident_sequence || decision.policy_id !== policy.policy_id || decision.policy_version !== policy.policy_version || decision.policy_hash !== hashes.policy_hash) return result('DECISION_BINDING_INVALID','NONE',['DECISION_BINDING_INVALID'],hashes,null);
  timestamp(options.evaluated_at, '$evaluated_at'); string(options.next_state_id, statePattern, '$next_state_id');
  const evaluatedAt = Date.parse(options.evaluated_at); const decisionAt = Date.parse(decision.issued_at);
  if (decisionAt > evaluatedAt + policy.max_clock_skew_seconds * 1000 || evaluatedAt - decisionAt > policy.max_decision_age_seconds * 1000) return result('DECISION_INVALID','NONE',['DECISION_STALE_OR_FUTURE'],hashes,null);
  const validDecisionSignatures = validAdjudicatorSignatures(policy, decision.authorizations, canonicalARVVerifierIncidentDecisionSigningBytesV1(decision), evaluatedAt);
  let decisionThreshold = policy.adjudication_threshold;
  if (decision.outcome === 'DISMISS') decisionThreshold = policy.dismissal_threshold;
  if (decision.outcome === 'RECOVER') decisionThreshold = policy.recovery_threshold;
  if (validDecisionSignatures < decisionThreshold) return result('ADJUDICATOR_QUORUM_NOT_MET','NONE',['ADJUDICATOR_QUORUM_NOT_MET'],hashes,null,validDecisionSignatures);
  if (mandatoryQuarantine.has(incident.incident_type) && decision.outcome === 'DISMISS') return result('DISMISSAL_FORBIDDEN','NONE',['MANDATORY_QUARANTINE_INCIDENT'],hashes,null,validDecisionSignatures);
  let current: ARVVerifierQuarantineStateV1 | null = null;
  if (options.current_quarantine_state !== null) {
    try { current = assertARVVerifierQuarantineStateV1(options.current_quarantine_state); hashes.current_quarantine_state_hash = sha256ARVVerifierQuarantineStateV1(current); }
    catch { return result('CURRENT_STATE_INVALID','NONE',['CURRENT_QUARANTINE_STATE_INVALID'],hashes,null,validDecisionSignatures); }
    if (options.expected_current_quarantine_state_hash === null) return result('COMPARE_AND_SWAP_REQUIRED','NONE',['COMPARE_AND_SWAP_HASH_REQUIRED'],hashes,null,validDecisionSignatures);
    if (options.expected_current_quarantine_state_hash !== hashes.current_quarantine_state_hash) return result('COMPARE_AND_SWAP_MISMATCH','NONE',['COMPARE_AND_SWAP_HASH_MISMATCH'],hashes,null,validDecisionSignatures);
    hashes.commit_precondition_hash = hashes.current_quarantine_state_hash;
    if (current.verifier_id !== incident.verifier_id || current.instance_id !== incident.instance_id) return result('INCIDENT_BINDING_INVALID','NONE',['QUARANTINE_SUBJECT_MISMATCH'],hashes,null,validDecisionSignatures);
    if (incident.incident_sequence < current.incident_sequence) return result('INCIDENT_ROLLBACK','NONE',['INCIDENT_SEQUENCE_ROLLBACK'],hashes,null,validDecisionSignatures);
    if (incident.incident_sequence === current.incident_sequence) {
      if (hashes.incident_hash === current.incident_hash && hashes.decision_hash === current.decision_hash) { hashes.next_quarantine_state_hash = hashes.current_quarantine_state_hash; return result('REPLAY_ACCEPTED','REPLAY',['INCIDENT_REPLAY_ACCEPTED'],hashes,current,validDecisionSignatures); }
      return result('INCIDENT_EQUIVOCATION','NONE',['SAME_SEQUENCE_DIFFERENT_INCIDENT'],hashes,null,validDecisionSignatures);
    }
    if (incident.incident_sequence !== current.incident_sequence + 1 || incident.previous_incident_hash !== current.incident_hash || decision.previous_decision_hash !== current.decision_hash) return result('INCIDENT_GAP','NONE',['INCIDENT_CHAIN_GAP'],hashes,null,validDecisionSignatures);
  }
  if (current === null) {
    if (options.expected_current_quarantine_state_hash !== null || incident.incident_sequence !== 1 || decision.decision_sequence !== 1 || incident.previous_incident_hash !== null || decision.previous_decision_hash !== null) return result('CURRENT_STATE_INVALID','NONE',['INCIDENT_GENESIS_STATE_INVALID'],hashes,null,validDecisionSignatures);
    hashes.commit_precondition_hash = hashes.policy_hash;
  }
  let status: ARVVerifierQuarantineStatusV1 = 'QUARANTINED'; let state: ARVVerifierIncidentStateV1 = 'QUARANTINE_APPLIED'; let operation: ARVVerifierIncidentOperationV1 = 'QUARANTINE';
  if (decision.outcome === 'DISMISS') { status = 'CLEAR'; state = 'INCIDENT_DISMISSED'; operation = 'DISMISS'; }
  if (decision.outcome === 'RETAIN_QUARANTINE') { status = 'QUARANTINED'; state = 'QUARANTINE_RETAINED'; operation = 'RETAIN'; }
  let rootRecovery = 0; let recoveryAdjudicators = 0;
  if (decision.outcome === 'RECOVER') {
    if (current === null || current.status !== 'QUARANTINED' || options.recovery_authorization === null) return result('RECOVERY_AUTHORIZATION_REQUIRED','NONE',['ACTIVE_QUARANTINE_AND_RECOVERY_AUTHORIZATION_REQUIRED'],hashes,null,validDecisionSignatures);
    let recovery: ARVVerifierIncidentRecoveryAuthorizationV1;
    try { recovery = assertARVVerifierIncidentRecoveryAuthorizationV1(options.recovery_authorization); }
    catch { return result('RECOVERY_AUTHORIZATION_INVALID','NONE',['RECOVERY_AUTHORIZATION_INVALID'],hashes,null,validDecisionSignatures); }
    if (recovery.incident_id !== incident.incident_id || recovery.incident_hash !== hashes.incident_hash || recovery.quarantine_state_hash !== hashes.current_quarantine_state_hash || recovery.policy_hash !== hashes.policy_hash || recovery.root_id !== root.root_id || recovery.root_version !== root.root_version || recovery.root_epoch !== root.epoch || recovery.root_hash !== hashes.root_hash || Date.parse(recovery.issued_at) > evaluatedAt + policy.max_clock_skew_seconds * 1000 || evaluatedAt >= Date.parse(recovery.expires_at)) return result('RECOVERY_AUTHORIZATION_INVALID','NONE',['RECOVERY_BINDING_OR_TIME_INVALID'],hashes,null,validDecisionSignatures);
    const recoveryBytes = canonicalARVVerifierIncidentRecoverySigningBytesV1(recovery);
    rootRecovery = validRootRecoverySignatures(root, recovery.root_authorizations, recoveryBytes, evaluatedAt);
    recoveryAdjudicators = validAdjudicatorSignatures(policy, recovery.adjudicator_authorizations, recoveryBytes, evaluatedAt);
    if (rootRecovery < root.recovery_threshold) return result('ROOT_RECOVERY_QUORUM_NOT_MET','NONE',['ROOT_RECOVERY_QUORUM_NOT_MET'],hashes,null,validDecisionSignatures,rootRecovery,recoveryAdjudicators);
    if (recoveryAdjudicators < policy.recovery_threshold) return result('RECOVERY_ADJUDICATOR_QUORUM_NOT_MET','NONE',['RECOVERY_ADJUDICATOR_QUORUM_NOT_MET'],hashes,null,validDecisionSignatures,rootRecovery,recoveryAdjudicators);
    status = 'CLEAR'; state = 'RECOVERY_AUTHORIZED'; operation = 'RECOVER';
  }
  const next: ARVVerifierQuarantineStateV1 = {
    schema: ARV_VERIFIER_QUARANTINE_STATE_SCHEMA, schema_version: 1,
    state_id: options.next_state_id, verifier_id: incident.verifier_id, instance_id: incident.instance_id,
    generation: current === null ? 1 : current.generation + 1, status,
    incident_sequence: incident.incident_sequence, incident_hash: hashes.incident_hash,
    decision_hash: hashes.decision_hash, effective_at: decision.issued_at,
    previous_state_hash: current === null ? null : hashes.current_quarantine_state_hash
  };
  hashes.next_quarantine_state_hash = sha256ARVVerifierQuarantineStateV1(next);
  return result(state,operation,[state],hashes,next,validDecisionSignatures,rootRecovery,recoveryAdjudicators);
}
