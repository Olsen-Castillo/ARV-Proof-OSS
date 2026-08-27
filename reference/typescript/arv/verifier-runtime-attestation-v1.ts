import crypto from 'crypto';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';
import { assertNoARVPrivateKeyMaterialV1 } from './trust-root-lifecycle-v1';
import {
  ARVVerifierActivationPinV1,
  ARVVerifierRuntimeMeasurementV1,
  ARVVerifierRuntimeVerificationV1,
  VerifyARVVerifierRuntimeOptionsV1,
  assertARVVerifierActivationPinV1,
  assertARVVerifierRuntimeMeasurementV1,
  sha256ARVVerifierActivationPinV1,
  sha256ARVVerifierRuntimeMeasurementV1,
  verifyARVVerifierRuntimeIntegrityV1
} from './verifier-runtime-integrity-v1';

export const ARV_VERIFIER_RUNTIME_ATTESTATION_POLICY_SCHEMA = 'arv.verifier-runtime-attestation-policy' as const;
export const ARV_VERIFIER_RUNTIME_ATTESTATION_SCHEMA = 'arv.verifier-runtime-attestation' as const;
export const ARV_VERIFIER_SECURITY_EVENT_SCHEMA = 'arv.verifier-security-event' as const;
export const ARV_VERIFIER_SECURITY_EVENT_CHAIN_SCHEMA = 'arv.verifier-security-event-chain' as const;
export const ARV_VERIFIER_RUNTIME_ATTESTATION_PIN_SCHEMA = 'arv.verifier-runtime-attestation-pin' as const;
export const ARV_VERIFIER_RUNTIME_ATTESTATION_SCHEMA_VERSION = 1 as const;

export const ARV_VERIFIER_SECURITY_EVENT_TYPES = [
  'BOOT', 'DRIFT_DETECTED', 'INCIDENT_REPORTED', 'QUARANTINE_ENTERED', 'QUARANTINE_RELEASED',
  'RUNTIME_CHECK', 'SHUTDOWN', 'UPDATE_ACTIVATED'
] as const;
export const ARV_VERIFIER_SECURITY_EVENT_SEVERITIES = ['CRITICAL', 'HIGH', 'INFO', 'LOW', 'MEDIUM'] as const;
export const ARV_VERIFIER_RUNTIME_ATTESTATION_STATES = [
  'BOOTSTRAP_ACCEPTED', 'UPDATE_ACCEPTED', 'REPLAY_ACCEPTED', 'RUNTIME_REJECTED',
  'POLICY_INVALID', 'POLICY_PIN_REQUIRED', 'POLICY_PIN_MISMATCH', 'ATTESTATION_INVALID',
  'ATTESTATION_BINDING_INVALID', 'CHALLENGE_MISMATCH', 'ATTESTATION_TIME_INVALID',
  'SIGNATURE_QUORUM_NOT_MET', 'EVENT_CHAIN_INVALID', 'EVENT_CHAIN_ROLLBACK', 'EVENT_CHAIN_GAP',
  'EVENT_CHAIN_EQUIVOCATION', 'CURRENT_PIN_REQUIRED', 'CURRENT_PIN_INVALID',
  'CURRENT_PIN_HASH_REQUIRED', 'CURRENT_PIN_HASH_MISMATCH', 'ATTESTATION_ROLLBACK',
  'ATTESTATION_GAP', 'ATTESTATION_EQUIVOCATION', 'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;
export const ARV_VERIFIER_RUNTIME_ATTESTATION_OPERATIONS = ['NONE', 'BOOTSTRAP', 'UPDATE', 'REPLAY'] as const;

export type ARVVerifierSecurityEventTypeV1 = typeof ARV_VERIFIER_SECURITY_EVENT_TYPES[number];
export type ARVVerifierSecurityEventSeverityV1 = typeof ARV_VERIFIER_SECURITY_EVENT_SEVERITIES[number];
export type ARVVerifierRuntimeAttestationStateV1 = typeof ARV_VERIFIER_RUNTIME_ATTESTATION_STATES[number];
export type ARVVerifierRuntimeAttestationOperationV1 = typeof ARV_VERIFIER_RUNTIME_ATTESTATION_OPERATIONS[number];

export interface ARVVerifierRuntimeAttestorV1 {
  attestor_id: string;
  key_id: string;
  algorithm: 'Ed25519';
  public_key_spki_base64: string;
  status: 'ACTIVE' | 'REVOKED';
  valid_from: string;
  expires_at: string;
}

export interface ARVVerifierRuntimeAttestationPolicyV1 {
  schema: typeof ARV_VERIFIER_RUNTIME_ATTESTATION_POLICY_SCHEMA;
  schema_version: 1;
  policy_id: string;
  verifier_id: string;
  policy_version: number;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  attestation_threshold: number;
  max_attestation_age_seconds: number;
  max_clock_skew_seconds: number;
  allowed_event_types: ARVVerifierSecurityEventTypeV1[];
  attestors: ARVVerifierRuntimeAttestorV1[];
  issued_at: string;
}

export interface ARVVerifierAttestationSignatureV1 {
  algorithm: 'Ed25519';
  key_id: string;
  signature_base64: string;
}

export interface ARVVerifierRuntimeAttestationV1 {
  schema: typeof ARV_VERIFIER_RUNTIME_ATTESTATION_SCHEMA;
  schema_version: 1;
  attestation_id: string;
  verifier_id: string;
  instance_id: string;
  attestation_sequence: number;
  activation_sequence: number;
  release_manifest_hash: string;
  activation_pin_hash: string;
  runtime_measurement_hash: string;
  security_event_chain_hash: string;
  challenge_nonce: string;
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  issued_at: string;
  expires_at: string;
  previous_attestation_hash: string | null;
  signatures: ARVVerifierAttestationSignatureV1[];
}

export interface ARVVerifierSecurityEventV1 {
  schema: typeof ARV_VERIFIER_SECURITY_EVENT_SCHEMA;
  schema_version: 1;
  event_id: string;
  verifier_id: string;
  instance_id: string;
  event_sequence: number;
  event_type: ARVVerifierSecurityEventTypeV1;
  severity: ARVVerifierSecurityEventSeverityV1;
  activation_pin_hash: string;
  runtime_measurement_hash: string;
  details_digest: string;
  observed_at: string;
  previous_event_hash: string | null;
}

export interface ARVVerifierSecurityEventChainV1 {
  schema: typeof ARV_VERIFIER_SECURITY_EVENT_CHAIN_SCHEMA;
  schema_version: 1;
  chain_id: string;
  verifier_id: string;
  instance_id: string;
  first_event_sequence: number;
  last_event_sequence: number;
  previous_chain_hash: string | null;
  events: ARVVerifierSecurityEventV1[];
  closed_at: string;
}

export interface ARVVerifierRuntimeAttestationPinV1 {
  schema: typeof ARV_VERIFIER_RUNTIME_ATTESTATION_PIN_SCHEMA;
  schema_version: 1;
  pin_id: string;
  verifier_id: string;
  instance_id: string;
  generation: number;
  attestation_sequence: number;
  attestation_hash: string;
  security_event_chain_hash: string;
  last_event_sequence: number;
  last_event_hash: string;
  activation_pin_hash: string;
  runtime_measurement_hash: string;
  issued_at: string;
  previous_pin_hash: string | null;
}

export interface VerifyARVVerifierRuntimeAttestationOptionsV1 {
  runtime_verification_options: VerifyARVVerifierRuntimeOptionsV1;
  attestation_policy: unknown;
  runtime_attestation: unknown;
  security_event_chain: unknown;
  current_attestation_pin: unknown | null;
  expected_current_attestation_pin_hash: string | null;
  bootstrap_policy_hash: string | null;
  expected_challenge_nonce: string;
  attestation_pin_id: string;
  evaluated_at: string;
}

export interface ARVVerifierRuntimeAttestationVerificationV1 {
  schema: 'arv.verifier-runtime-attestation-verification';
  schema_version: 1;
  accepted: boolean;
  quarantined: boolean;
  state: ARVVerifierRuntimeAttestationStateV1;
  operation: ARVVerifierRuntimeAttestationOperationV1;
  runtime_verification_state: ARVVerifierRuntimeVerificationV1['state'] | null;
  policy_hash: string | null;
  activation_pin_hash: string | null;
  runtime_measurement_hash: string | null;
  security_event_chain_hash: string | null;
  attestation_hash: string | null;
  current_attestation_pin_hash: string | null;
  commit_precondition_hash: string | null;
  next_attestation_pin_hash: string | null;
  next_attestation_pin: ARVVerifierRuntimeAttestationPinV1 | null;
  valid_attestation_signatures: number;
  codes: string[];
  runtime_integrity_authority: 'VERIFIED_RUNTIME';
  attestation_authority: 'ROOT_AUTHORIZED_RUNTIME_ATTESTOR_QUORUM';
  security_event_authority: 'HASH_CHAINED_OBSERVATION_ONLY';
  operating_system_authority: 'NONE';
  collector_authority: 'NONE';
  storage_authority: 'NONE';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

const digestPattern = /^[a-f0-9]{64}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const verifierPattern = /^ARV-VERIFIER-[A-Z0-9-]+$/;
const instancePattern = /^ARV-VERIFIER-INSTANCE-[A-Z0-9-]+$/;
const policyPattern = /^ARV-VERIFIER-RUNTIME-ATTESTATION-POLICY-[A-Z0-9-]+$/;
const attestationPattern = /^ARV-VERIFIER-RUNTIME-ATTESTATION-[A-Z0-9-]+$/;
const eventPattern = /^ARV-VERIFIER-SECURITY-EVENT-[A-Z0-9-]+$/;
const chainPattern = /^ARV-VERIFIER-SECURITY-EVENT-CHAIN-[A-Z0-9-]+$/;
const pinPattern = /^ARV-VERIFIER-RUNTIME-ATTESTATION-PIN-[A-Z0-9-]+$/;
const rootPattern = /^ARV-ROOT-[A-Z0-9-]+$/;
const attestorPattern = /^ARV-RUNTIME-ATTESTOR-[A-Z0-9-]+$/;
const keyPattern = /^[a-f0-9]{24,128}$/;
const noncePattern = /^[a-f0-9]{32,128}$/;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function object(value: unknown, location: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${location} must be an object`);
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, keys: string[], location: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${location} contains unexpected or missing fields`);
}

function string(value: unknown, pattern: RegExp, location: string): asserts value is string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${location} is invalid`);
}

function digest(value: unknown, location: string): asserts value is string { string(value, digestPattern, location); }

function timestamp(value: unknown, location: string): asserts value is string {
  string(value, timestampPattern, location);
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${location} must be a valid UTC timestamp`);
}

function positive(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 1) throw new Error(`${location} must be a positive integer`);
}

function sha256Domain(domain: string, value: unknown): string {
  return crypto.createHash('sha256').update(`${domain}\n${canonicalizeARVJsonV1(value)}`, 'utf8').digest('hex');
}

export function assertARVVerifierRuntimeAttestationPolicyV1(value: unknown): ARVVerifierRuntimeAttestationPolicyV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$attestation_policy');
  exact(input, ['schema','schema_version','policy_id','verifier_id','policy_version','root_id','root_version','root_epoch','root_hash','attestation_threshold','max_attestation_age_seconds','max_clock_skew_seconds','allowed_event_types','attestors','issued_at'], '$attestation_policy');
  if (input.schema !== ARV_VERIFIER_RUNTIME_ATTESTATION_POLICY_SCHEMA || input.schema_version !== 1) throw new Error('$attestation_policy schema is invalid');
  string(input.policy_id, policyPattern, '$attestation_policy.policy_id');
  string(input.verifier_id, verifierPattern, '$attestation_policy.verifier_id');
  string(input.root_id, rootPattern, '$attestation_policy.root_id');
  positive(input.policy_version, '$attestation_policy.policy_version'); positive(input.root_version, '$attestation_policy.root_version'); positive(input.root_epoch, '$attestation_policy.root_epoch');
  digest(input.root_hash, '$attestation_policy.root_hash'); positive(input.attestation_threshold, '$attestation_policy.attestation_threshold');
  positive(input.max_attestation_age_seconds, '$attestation_policy.max_attestation_age_seconds'); positive(input.max_clock_skew_seconds, '$attestation_policy.max_clock_skew_seconds');
  if (!Array.isArray(input.allowed_event_types) || input.allowed_event_types.length === 0) throw new Error('$attestation_policy.allowed_event_types is invalid');
  const eventTypes = input.allowed_event_types as string[];
  eventTypes.forEach((item) => { if (!ARV_VERIFIER_SECURITY_EVENT_TYPES.includes(item as ARVVerifierSecurityEventTypeV1)) throw new Error('$attestation_policy event type is invalid'); });
  if (new Set(eventTypes).size !== eventTypes.length || eventTypes.some((item, index) => item !== [...eventTypes].sort()[index])) throw new Error('$attestation_policy event types must be unique and sorted');
  if (!Array.isArray(input.attestors) || input.attestors.length === 0) throw new Error('$attestation_policy.attestors is invalid');
  const attestors = input.attestors.map((item, index) => {
    const attestor = object(item, `$attestation_policy.attestors[${index}]`);
    exact(attestor, ['attestor_id','key_id','algorithm','public_key_spki_base64','status','valid_from','expires_at'], `$attestation_policy.attestors[${index}]`);
    string(attestor.attestor_id, attestorPattern, `$attestation_policy.attestors[${index}].attestor_id`); string(attestor.key_id, keyPattern, `$attestation_policy.attestors[${index}].key_id`);
    if (attestor.algorithm !== 'Ed25519' || !['ACTIVE','REVOKED'].includes(attestor.status as string)) throw new Error('$attestation_policy attestor is invalid');
    string(attestor.public_key_spki_base64, base64Pattern, `$attestation_policy.attestors[${index}].public_key_spki_base64`);
    const keyBytes = Buffer.from(attestor.public_key_spki_base64 as string, 'base64');
    if (keyBytes.length < 40 || keyBytes.length > 128) throw new Error('$attestation_policy public key is invalid');
    timestamp(attestor.valid_from, `$attestation_policy.attestors[${index}].valid_from`); timestamp(attestor.expires_at, `$attestation_policy.attestors[${index}].expires_at`);
    if (Date.parse(attestor.valid_from as string) >= Date.parse(attestor.expires_at as string)) throw new Error('$attestation_policy attestor interval is invalid');
    return attestor as unknown as ARVVerifierRuntimeAttestorV1;
  });
  const keyIds = attestors.map((item) => item.key_id);
  if (new Set(keyIds).size !== keyIds.length || keyIds.some((item, index) => item !== [...keyIds].sort()[index])) throw new Error('$attestation_policy attestors must be unique and sorted by key_id');
  if ((input.attestation_threshold as number) > attestors.filter((item) => item.status === 'ACTIVE').length) throw new Error('$attestation_policy threshold is unsatisfiable');
  timestamp(input.issued_at, '$attestation_policy.issued_at');
  return { ...input, allowed_event_types: eventTypes, attestors } as unknown as ARVVerifierRuntimeAttestationPolicyV1;
}

function assertSignatures(value: unknown): ARVVerifierAttestationSignatureV1[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error('$runtime_attestation.signatures is invalid');
  const signatures = value.map((item, index) => {
    const signature = object(item, `$runtime_attestation.signatures[${index}]`);
    exact(signature, ['algorithm','key_id','signature_base64'], `$runtime_attestation.signatures[${index}]`);
    if (signature.algorithm !== 'Ed25519') throw new Error('$runtime_attestation signature algorithm is invalid');
    string(signature.key_id, keyPattern, `$runtime_attestation.signatures[${index}].key_id`); string(signature.signature_base64, base64Pattern, `$runtime_attestation.signatures[${index}].signature_base64`);
    if (Buffer.from(signature.signature_base64 as string, 'base64').length !== 64) throw new Error('$runtime_attestation signature length is invalid');
    return signature as unknown as ARVVerifierAttestationSignatureV1;
  });
  const keys = signatures.map((item) => item.key_id);
  if (new Set(keys).size !== keys.length || keys.some((item, index) => item !== [...keys].sort()[index])) throw new Error('$runtime_attestation signatures must be unique and sorted');
  return signatures;
}

export function assertARVVerifierRuntimeAttestationV1(value: unknown): ARVVerifierRuntimeAttestationV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$runtime_attestation');
  exact(input, ['schema','schema_version','attestation_id','verifier_id','instance_id','attestation_sequence','activation_sequence','release_manifest_hash','activation_pin_hash','runtime_measurement_hash','security_event_chain_hash','challenge_nonce','policy_id','policy_version','policy_hash','root_id','root_version','root_epoch','root_hash','issued_at','expires_at','previous_attestation_hash','signatures'], '$runtime_attestation');
  if (input.schema !== ARV_VERIFIER_RUNTIME_ATTESTATION_SCHEMA || input.schema_version !== 1) throw new Error('$runtime_attestation schema is invalid');
  string(input.attestation_id, attestationPattern, '$runtime_attestation.attestation_id'); string(input.verifier_id, verifierPattern, '$runtime_attestation.verifier_id'); string(input.instance_id, instancePattern, '$runtime_attestation.instance_id');
  positive(input.attestation_sequence, '$runtime_attestation.attestation_sequence'); positive(input.activation_sequence, '$runtime_attestation.activation_sequence');
  ['release_manifest_hash','activation_pin_hash','runtime_measurement_hash','security_event_chain_hash','policy_hash','root_hash'].forEach((field) => digest(input[field], `$runtime_attestation.${field}`));
  string(input.challenge_nonce, noncePattern, '$runtime_attestation.challenge_nonce'); string(input.policy_id, policyPattern, '$runtime_attestation.policy_id'); positive(input.policy_version, '$runtime_attestation.policy_version');
  string(input.root_id, rootPattern, '$runtime_attestation.root_id'); positive(input.root_version, '$runtime_attestation.root_version'); positive(input.root_epoch, '$runtime_attestation.root_epoch');
  timestamp(input.issued_at, '$runtime_attestation.issued_at'); timestamp(input.expires_at, '$runtime_attestation.expires_at');
  if (Date.parse(input.issued_at as string) >= Date.parse(input.expires_at as string)) throw new Error('$runtime_attestation interval is invalid');
  if (input.previous_attestation_hash !== null) digest(input.previous_attestation_hash, '$runtime_attestation.previous_attestation_hash');
  const signatures = assertSignatures(input.signatures);
  return { ...input, signatures } as unknown as ARVVerifierRuntimeAttestationV1;
}

export function assertARVVerifierSecurityEventV1(value: unknown, location = '$security_event'): ARVVerifierSecurityEventV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, location);
  exact(input, ['schema','schema_version','event_id','verifier_id','instance_id','event_sequence','event_type','severity','activation_pin_hash','runtime_measurement_hash','details_digest','observed_at','previous_event_hash'], location);
  if (input.schema !== ARV_VERIFIER_SECURITY_EVENT_SCHEMA || input.schema_version !== 1) throw new Error(`${location} schema is invalid`);
  string(input.event_id, eventPattern, `${location}.event_id`); string(input.verifier_id, verifierPattern, `${location}.verifier_id`); string(input.instance_id, instancePattern, `${location}.instance_id`); positive(input.event_sequence, `${location}.event_sequence`);
  if (!ARV_VERIFIER_SECURITY_EVENT_TYPES.includes(input.event_type as ARVVerifierSecurityEventTypeV1)) throw new Error(`${location}.event_type is invalid`);
  if (!ARV_VERIFIER_SECURITY_EVENT_SEVERITIES.includes(input.severity as ARVVerifierSecurityEventSeverityV1)) throw new Error(`${location}.severity is invalid`);
  digest(input.activation_pin_hash, `${location}.activation_pin_hash`); digest(input.runtime_measurement_hash, `${location}.runtime_measurement_hash`); digest(input.details_digest, `${location}.details_digest`); timestamp(input.observed_at, `${location}.observed_at`);
  if (input.previous_event_hash !== null) digest(input.previous_event_hash, `${location}.previous_event_hash`);
  return input as unknown as ARVVerifierSecurityEventV1;
}

export function assertARVVerifierSecurityEventChainV1(value: unknown): ARVVerifierSecurityEventChainV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$security_event_chain');
  exact(input, ['schema','schema_version','chain_id','verifier_id','instance_id','first_event_sequence','last_event_sequence','previous_chain_hash','events','closed_at'], '$security_event_chain');
  if (input.schema !== ARV_VERIFIER_SECURITY_EVENT_CHAIN_SCHEMA || input.schema_version !== 1) throw new Error('$security_event_chain schema is invalid');
  string(input.chain_id, chainPattern, '$security_event_chain.chain_id'); string(input.verifier_id, verifierPattern, '$security_event_chain.verifier_id'); string(input.instance_id, instancePattern, '$security_event_chain.instance_id');
  positive(input.first_event_sequence, '$security_event_chain.first_event_sequence'); positive(input.last_event_sequence, '$security_event_chain.last_event_sequence');
  if (input.previous_chain_hash !== null) digest(input.previous_chain_hash, '$security_event_chain.previous_chain_hash');
  if (!Array.isArray(input.events) || input.events.length === 0) throw new Error('$security_event_chain.events is invalid');
  const events = input.events.map((item, index) => assertARVVerifierSecurityEventV1(item, `$security_event_chain.events[${index}]`));
  if (events[0].event_sequence !== input.first_event_sequence || events[events.length - 1].event_sequence !== input.last_event_sequence) throw new Error('$security_event_chain bounds are invalid');
  timestamp(input.closed_at, '$security_event_chain.closed_at');
  return { ...input, events } as unknown as ARVVerifierSecurityEventChainV1;
}

export function assertARVVerifierRuntimeAttestationPinV1(value: unknown): ARVVerifierRuntimeAttestationPinV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$attestation_pin');
  exact(input, ['schema','schema_version','pin_id','verifier_id','instance_id','generation','attestation_sequence','attestation_hash','security_event_chain_hash','last_event_sequence','last_event_hash','activation_pin_hash','runtime_measurement_hash','issued_at','previous_pin_hash'], '$attestation_pin');
  if (input.schema !== ARV_VERIFIER_RUNTIME_ATTESTATION_PIN_SCHEMA || input.schema_version !== 1) throw new Error('$attestation_pin schema is invalid');
  string(input.pin_id, pinPattern, '$attestation_pin.pin_id'); string(input.verifier_id, verifierPattern, '$attestation_pin.verifier_id'); string(input.instance_id, instancePattern, '$attestation_pin.instance_id');
  positive(input.generation, '$attestation_pin.generation'); positive(input.attestation_sequence, '$attestation_pin.attestation_sequence'); positive(input.last_event_sequence, '$attestation_pin.last_event_sequence');
  ['attestation_hash','security_event_chain_hash','last_event_hash','activation_pin_hash','runtime_measurement_hash'].forEach((field) => digest(input[field], `$attestation_pin.${field}`)); timestamp(input.issued_at, '$attestation_pin.issued_at');
  if (input.previous_pin_hash !== null) digest(input.previous_pin_hash, '$attestation_pin.previous_pin_hash');
  if (input.generation === 1 && input.previous_pin_hash !== null) throw new Error('$attestation_pin bootstrap predecessor must be null');
  if ((input.generation as number) > 1 && input.previous_pin_hash === null) throw new Error('$attestation_pin predecessor is required');
  return input as unknown as ARVVerifierRuntimeAttestationPinV1;
}

export function sha256ARVVerifierRuntimeAttestationPolicyV1(value: ARVVerifierRuntimeAttestationPolicyV1): string { return sha256Domain('ARV-VERIFIER-RUNTIME-ATTESTATION-POLICY-v1', value); }
export function sha256ARVVerifierRuntimeAttestationV1(value: ARVVerifierRuntimeAttestationV1): string { return sha256Domain('ARV-VERIFIER-RUNTIME-ATTESTATION-v1', value); }
export function sha256ARVVerifierSecurityEventV1(value: ARVVerifierSecurityEventV1): string { return sha256Domain('ARV-VERIFIER-SECURITY-EVENT-v1', value); }
export function sha256ARVVerifierSecurityEventChainV1(value: ARVVerifierSecurityEventChainV1): string { return sha256Domain('ARV-VERIFIER-SECURITY-EVENT-CHAIN-v1', value); }
export function sha256ARVVerifierRuntimeAttestationPinV1(value: ARVVerifierRuntimeAttestationPinV1): string { return sha256Domain('ARV-VERIFIER-RUNTIME-ATTESTATION-PIN-v1', value); }

export function canonicalARVVerifierRuntimeAttestationSigningBytesV1(value: ARVVerifierRuntimeAttestationV1): Buffer {
  return Buffer.from(`ARV-VERIFIER-RUNTIME-ATTESTATION-SIGNATURE-v1\n${canonicalizeARVJsonV1({ ...value, signatures: [] })}`, 'utf8');
}

function result(state: ARVVerifierRuntimeAttestationStateV1, operation: ARVVerifierRuntimeAttestationOperationV1, codes: string[], runtime: ARVVerifierRuntimeVerificationV1 | null, hashes: { policy?: string | null; activation?: string | null; measurement?: string | null; chain?: string | null; attestation?: string | null; current?: string | null; precondition?: string | null }, nextPin: ARVVerifierRuntimeAttestationPinV1 | null, validSignatures = 0): ARVVerifierRuntimeAttestationVerificationV1 {
  const accepted = ['BOOTSTRAP_ACCEPTED','UPDATE_ACCEPTED','REPLAY_ACCEPTED'].includes(state);
  return {
    schema: 'arv.verifier-runtime-attestation-verification', schema_version: 1, accepted, quarantined: !accepted,
    state, operation, runtime_verification_state: runtime ? runtime.state : null,
    policy_hash: hashes.policy ?? null, activation_pin_hash: hashes.activation ?? null,
    runtime_measurement_hash: hashes.measurement ?? null, security_event_chain_hash: hashes.chain ?? null,
    attestation_hash: hashes.attestation ?? null, current_attestation_pin_hash: hashes.current ?? null,
    commit_precondition_hash: hashes.precondition ?? null,
    next_attestation_pin_hash: nextPin ? sha256ARVVerifierRuntimeAttestationPinV1(nextPin) : null,
    next_attestation_pin: nextPin, valid_attestation_signatures: validSignatures,
    codes: Array.from(new Set(codes)).sort(), runtime_integrity_authority: 'VERIFIED_RUNTIME',
    attestation_authority: 'ROOT_AUTHORIZED_RUNTIME_ATTESTOR_QUORUM', security_event_authority: 'HASH_CHAINED_OBSERVATION_ONLY',
    operating_system_authority: 'NONE', collector_authority: 'NONE', storage_authority: 'NONE', transport_authority: 'NONE', material_truth: 'NOT_EVALUATED'
  };
}

function activePin(runtime: ARVVerifierRuntimeVerificationV1, options: VerifyARVVerifierRuntimeOptionsV1): ARVVerifierActivationPinV1 | null {
  if (runtime.next_activation_pin) return runtime.next_activation_pin;
  if (runtime.operation !== 'REPLAY' || options.current_activation_pin === null) return null;
  try { return assertARVVerifierActivationPinV1(options.current_activation_pin); } catch { return null; }
}

function validSignatureCount(attestation: ARVVerifierRuntimeAttestationV1, policy: ARVVerifierRuntimeAttestationPolicyV1, evaluatedAt: number): number {
  const bytes = canonicalARVVerifierRuntimeAttestationSigningBytesV1(attestation);
  let count = 0;
  for (const signature of attestation.signatures) {
    const attestor = policy.attestors.find((item) => item.key_id === signature.key_id);
    if (!attestor || attestor.status !== 'ACTIVE' || evaluatedAt < Date.parse(attestor.valid_from) || evaluatedAt > Date.parse(attestor.expires_at)) continue;
    try {
      const key = crypto.createPublicKey({ key: Buffer.from(attestor.public_key_spki_base64, 'base64'), format: 'der', type: 'spki' });
      if (crypto.verify(null, bytes, key, Buffer.from(signature.signature_base64, 'base64'))) count += 1;
    } catch { /* malformed or unsupported public key */ }
  }
  return count;
}

export function verifyARVVerifierRuntimeAttestationV1(options: VerifyARVVerifierRuntimeAttestationOptionsV1): ARVVerifierRuntimeAttestationVerificationV1 {
  try { assertNoARVPrivateKeyMaterialV1(options); } catch { return result('PRIVATE_KEY_MATERIAL_FORBIDDEN','NONE',['PRIVATE_KEY_MATERIAL_FORBIDDEN'],null,{},null); }
  try { timestamp(options.evaluated_at, '$options.evaluated_at'); string(options.expected_challenge_nonce, noncePattern, '$options.expected_challenge_nonce'); string(options.attestation_pin_id, pinPattern, '$options.attestation_pin_id'); } catch { return result('ATTESTATION_INVALID','NONE',['OPTIONS_INVALID'],null,{},null); }
  const runtime = verifyARVVerifierRuntimeIntegrityV1(options.runtime_verification_options);
  if (!runtime.accepted || runtime.quarantined) return result('RUNTIME_REJECTED','NONE',['RUNTIME_NOT_ACCEPTED'],runtime,{},null);
  let measurement: ARVVerifierRuntimeMeasurementV1;
  let activationPin: ARVVerifierActivationPinV1;
  try {
    measurement = assertARVVerifierRuntimeMeasurementV1(options.runtime_verification_options.runtime_measurement);
    const resolved = activePin(runtime, options.runtime_verification_options);
    if (!resolved) throw new Error('activation pin unavailable');
    activationPin = resolved;
  } catch { return result('RUNTIME_REJECTED','NONE',['RUNTIME_BINDING_INVALID'],runtime,{},null); }
  const activationHash = sha256ARVVerifierActivationPinV1(activationPin);
  const measurementHash = sha256ARVVerifierRuntimeMeasurementV1(measurement);

  let policy: ARVVerifierRuntimeAttestationPolicyV1;
  try { policy = assertARVVerifierRuntimeAttestationPolicyV1(options.attestation_policy); } catch { return result('POLICY_INVALID','NONE',['ATTESTATION_POLICY_SCHEMA_INVALID'],runtime,{ activation: activationHash, measurement: measurementHash },null); }
  const policyHash = sha256ARVVerifierRuntimeAttestationPolicyV1(policy);
  let attestation: ARVVerifierRuntimeAttestationV1;
  let chain: ARVVerifierSecurityEventChainV1;
  try { attestation = assertARVVerifierRuntimeAttestationV1(options.runtime_attestation); chain = assertARVVerifierSecurityEventChainV1(options.security_event_chain); } catch { return result('ATTESTATION_INVALID','NONE',['ATTESTATION_OR_EVENT_SCHEMA_INVALID'],runtime,{ policy: policyHash, activation: activationHash, measurement: measurementHash },null); }
  const chainHash = sha256ARVVerifierSecurityEventChainV1(chain);
  const attestationHash = sha256ARVVerifierRuntimeAttestationV1(attestation);
  const baseHashes = { policy: policyHash, activation: activationHash, measurement: measurementHash, chain: chainHash, attestation: attestationHash };

  if (options.current_attestation_pin === null) {
    if (options.bootstrap_policy_hash === null) return result('POLICY_PIN_REQUIRED','NONE',['BOOTSTRAP_POLICY_HASH_REQUIRED'],runtime,baseHashes,null);
    if (options.bootstrap_policy_hash !== policyHash) return result('POLICY_PIN_MISMATCH','NONE',['BOOTSTRAP_POLICY_HASH_MISMATCH'],runtime,baseHashes,null);
  }
  if (attestation.challenge_nonce !== options.expected_challenge_nonce) return result('CHALLENGE_MISMATCH','NONE',['CHALLENGE_NONCE_MISMATCH'],runtime,baseHashes,null);
  if (policy.verifier_id !== measurement.verifier_id || attestation.verifier_id !== measurement.verifier_id || chain.verifier_id !== measurement.verifier_id || attestation.instance_id !== measurement.instance_id || chain.instance_id !== measurement.instance_id || attestation.activation_sequence !== activationPin.activation_sequence || attestation.release_manifest_hash !== activationPin.release_manifest_hash || attestation.activation_pin_hash !== activationHash || attestation.runtime_measurement_hash !== measurementHash || attestation.security_event_chain_hash !== chainHash || attestation.policy_id !== policy.policy_id || attestation.policy_version !== policy.policy_version || attestation.policy_hash !== policyHash || attestation.root_id !== policy.root_id || attestation.root_version !== policy.root_version || attestation.root_epoch !== policy.root_epoch || attestation.root_hash !== policy.root_hash) {
    return result('ATTESTATION_BINDING_INVALID','NONE',['RUNTIME_ATTESTATION_BINDING_MISMATCH'],runtime,baseHashes,null);
  }
  const evaluatedAt = Date.parse(options.evaluated_at); const issuedAt = Date.parse(attestation.issued_at); const expiresAt = Date.parse(attestation.expires_at); const skew = policy.max_clock_skew_seconds * 1000;
  if (issuedAt > evaluatedAt + skew || expiresAt < evaluatedAt - skew || evaluatedAt - issuedAt > policy.max_attestation_age_seconds * 1000 + skew || Date.parse(chain.closed_at) > issuedAt + skew) return result('ATTESTATION_TIME_INVALID','NONE',['ATTESTATION_FRESHNESS_INVALID'],runtime,baseHashes,null);
  const validSignatures = validSignatureCount(attestation, policy, evaluatedAt);
  if (validSignatures < policy.attestation_threshold) return result('SIGNATURE_QUORUM_NOT_MET','NONE',['ATTESTATION_SIGNATURE_THRESHOLD_NOT_MET'],runtime,baseHashes,null,validSignatures);

  const events = chain.events;
  if (events.some((event) => event.verifier_id !== measurement.verifier_id || event.instance_id !== measurement.instance_id || event.activation_pin_hash !== activationHash || event.runtime_measurement_hash !== measurementHash || !policy.allowed_event_types.includes(event.event_type))) return result('EVENT_CHAIN_INVALID','NONE',['SECURITY_EVENT_BINDING_INVALID'],runtime,baseHashes,null,validSignatures);
  for (let index = 0; index < events.length; index += 1) {
    if (events[index].event_sequence !== chain.first_event_sequence + index) return result('EVENT_CHAIN_GAP','NONE',['SECURITY_EVENT_SEQUENCE_GAP'],runtime,baseHashes,null,validSignatures);
    if (index > 0 && events[index].previous_event_hash !== sha256ARVVerifierSecurityEventV1(events[index - 1])) return result('EVENT_CHAIN_EQUIVOCATION','NONE',['SECURITY_EVENT_HASH_CHAIN_INVALID'],runtime,baseHashes,null,validSignatures);
  }
  const lastEventHash = sha256ARVVerifierSecurityEventV1(events[events.length - 1]);

  let currentPin: ARVVerifierRuntimeAttestationPinV1 | null = null;
  let currentPinHash: string | null = null;
  if (options.current_attestation_pin !== null) {
    try { currentPin = assertARVVerifierRuntimeAttestationPinV1(options.current_attestation_pin); currentPinHash = sha256ARVVerifierRuntimeAttestationPinV1(currentPin); } catch { return result('CURRENT_PIN_INVALID','NONE',['CURRENT_ATTESTATION_PIN_INVALID'],runtime,baseHashes,null,validSignatures); }
    if (options.expected_current_attestation_pin_hash === null) return result('CURRENT_PIN_HASH_REQUIRED','NONE',['CURRENT_ATTESTATION_PIN_HASH_REQUIRED'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
    if (options.expected_current_attestation_pin_hash !== currentPinHash) return result('CURRENT_PIN_HASH_MISMATCH','NONE',['CURRENT_ATTESTATION_PIN_HASH_MISMATCH'],runtime,{...baseHashes,current:currentPinHash,precondition:options.expected_current_attestation_pin_hash},null,validSignatures);
    if (currentPin.verifier_id !== attestation.verifier_id || currentPin.instance_id !== attestation.instance_id) return result('CURRENT_PIN_INVALID','NONE',['CURRENT_ATTESTATION_PIN_IDENTITY_MISMATCH'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
    if (attestation.attestation_sequence < currentPin.attestation_sequence) return result('ATTESTATION_ROLLBACK','NONE',['ATTESTATION_SEQUENCE_ROLLBACK'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
    if (attestation.attestation_sequence === currentPin.attestation_sequence) {
      if (attestationHash !== currentPin.attestation_hash || chainHash !== currentPin.security_event_chain_hash) return result('ATTESTATION_EQUIVOCATION','NONE',['ATTESTATION_HASH_EQUIVOCATION'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
      return result('REPLAY_ACCEPTED','REPLAY',[],runtime,{...baseHashes,current:currentPinHash,precondition:currentPinHash},null,validSignatures);
    }
    if (attestation.attestation_sequence !== currentPin.attestation_sequence + 1) return result('ATTESTATION_GAP','NONE',['ATTESTATION_SEQUENCE_GAP'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
    if (attestation.previous_attestation_hash !== currentPin.attestation_hash || chain.previous_chain_hash !== currentPin.security_event_chain_hash) return result('EVENT_CHAIN_EQUIVOCATION','NONE',['ATTESTATION_OR_CHAIN_PREDECESSOR_MISMATCH'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
    if (chain.first_event_sequence !== currentPin.last_event_sequence + 1) return result(chain.first_event_sequence <= currentPin.last_event_sequence ? 'EVENT_CHAIN_ROLLBACK' : 'EVENT_CHAIN_GAP','NONE',[chain.first_event_sequence <= currentPin.last_event_sequence ? 'SECURITY_EVENT_SEQUENCE_ROLLBACK' : 'SECURITY_EVENT_SEQUENCE_GAP'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
    if (events[0].previous_event_hash !== currentPin.last_event_hash) return result('EVENT_CHAIN_EQUIVOCATION','NONE',['SECURITY_EVENT_PREDECESSOR_MISMATCH'],runtime,{...baseHashes,current:currentPinHash},null,validSignatures);
  } else {
    if (options.expected_current_attestation_pin_hash !== null) return result('CURRENT_PIN_REQUIRED','NONE',['CURRENT_ATTESTATION_PIN_REQUIRED'],runtime,{...baseHashes,precondition:options.expected_current_attestation_pin_hash},null,validSignatures);
    if (attestation.attestation_sequence !== 1 || attestation.previous_attestation_hash !== null || chain.first_event_sequence !== 1 || chain.previous_chain_hash !== null || events[0].previous_event_hash !== null) return result('ATTESTATION_GAP','NONE',['BOOTSTRAP_CONTINUITY_INVALID'],runtime,baseHashes,null,validSignatures);
  }

  const nextPin: ARVVerifierRuntimeAttestationPinV1 = {
    schema: ARV_VERIFIER_RUNTIME_ATTESTATION_PIN_SCHEMA, schema_version: 1, pin_id: options.attestation_pin_id,
    verifier_id: attestation.verifier_id, instance_id: attestation.instance_id, generation: currentPin ? currentPin.generation + 1 : 1,
    attestation_sequence: attestation.attestation_sequence, attestation_hash: attestationHash, security_event_chain_hash: chainHash,
    last_event_sequence: chain.last_event_sequence, last_event_hash: lastEventHash, activation_pin_hash: activationHash,
    runtime_measurement_hash: measurementHash, issued_at: attestation.issued_at, previous_pin_hash: currentPinHash
  };
  return result(currentPin ? 'UPDATE_ACCEPTED' : 'BOOTSTRAP_ACCEPTED', currentPin ? 'UPDATE' : 'BOOTSTRAP', [], runtime, {...baseHashes,current:currentPinHash,precondition:currentPinHash}, nextPin, validSignatures);
}
