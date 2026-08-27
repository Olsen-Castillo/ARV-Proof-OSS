import crypto from 'crypto';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';
import {
  ARVTrustRootV1,
  assertARVTrustRootV1,
  assertNoARVPrivateKeyMaterialV1,
  sha256ARVTrustRootV1,
  verifyARVTrustRootTransitionV1
} from './trust-root-lifecycle-v1';
import {
  ARVTrustRegistryCheckpointV1,
  ARVTrustedRegistryCheckpointV1,
  assertARVTrustRegistryCheckpointV1,
  sha256ARVTrustRegistryCheckpointV1
} from './trust-registry-checkpoint-v1';
import {
  ARVCheckpointWitnessPolicyV1,
  ARVCheckpointWitnessVerificationV1,
  ARVTrustedWitnessCheckpointV1,
  VerifyARVCheckpointWitnessOptionsV1,
  assertARVCheckpointWitnessPolicyV1,
  canonicalARVCheckpointWitnessPolicySigningPayloadV1,
  verifyARVCheckpointWitnessV1
} from './checkpoint-witness-v1';

export const ARV_VERIFIER_TRUST_STATE_SCHEMA = 'arv.verifier-trust-state' as const;
export const ARV_VERIFIER_BOOTSTRAP_PINS_SCHEMA = 'arv.verifier-bootstrap-pins' as const;
export const ARV_VERIFIER_TRUST_STATE_ENVELOPE_SCHEMA = 'arv.verifier-trust-state-envelope' as const;
export const ARV_VERIFIER_TRUST_STATE_SCHEMA_VERSION = 1 as const;
export const ARV_VERIFIER_TRUST_STATE_OPERATIONS = ['NONE', 'BOOTSTRAP', 'ADVANCE', 'REPLAY', 'RECOVERY'] as const;
export const ARV_VERIFIER_TRUST_STATE_STATES = [
  'BOOTSTRAP_ACCEPTED',
  'ADVANCE_ACCEPTED',
  'REPLAY_ACCEPTED',
  'RECOVERY_ACCEPTED',
  'UNDERLYING_WITNESS_REJECTED',
  'STATE_INVALID',
  'STATE_HASH_MISMATCH',
  'BOOTSTRAP_REQUIRED',
  'BOOTSTRAP_PIN_MISMATCH',
  'BOOTSTRAP_REUSE_FORBIDDEN',
  'STATE_ROLLBACK',
  'STATE_GAP',
  'STATE_EQUIVOCATION',
  'POLICY_ROLLBACK',
  'POLICY_GAP',
  'POLICY_EQUIVOCATION',
  'ROOT_TRANSITION_REQUIRED',
  'ROOT_RECOVERY_INVALID',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;
export const ARV_VERIFIER_TRUST_STATE_CODES = [
  'WITNESS_VERIFICATION_REJECTED',
  'CURRENT_STATE_SCHEMA_INVALID',
  'CURRENT_STATE_HASH_REQUIRED',
  'CURRENT_STATE_HASH_MISMATCH',
  'BOOTSTRAP_PINS_REQUIRED',
  'BOOTSTRAP_PINS_SCHEMA_INVALID',
  'BOOTSTRAP_ROOT_PIN_MISMATCH',
  'BOOTSTRAP_POLICY_PIN_MISMATCH',
  'BOOTSTRAP_CHECKPOINT_PIN_MISMATCH',
  'BOOTSTRAP_REGISTRY_PIN_MISMATCH',
  'BOOTSTRAP_REUSE_FORBIDDEN',
  'VERIFIER_ID_MISMATCH',
  'STATE_SEQUENCE_ROLLBACK',
  'STATE_SEQUENCE_GAP',
  'STATE_CHECKPOINT_EQUIVOCATION',
  'STATE_PREDECESSOR_MISMATCH',
  'POLICY_VERSION_ROLLBACK',
  'POLICY_VERSION_GAP',
  'POLICY_HASH_EQUIVOCATION',
  'ROOT_TRANSITION_REQUIRED',
  'RECOVERY_AUTHORIZATION_REQUIRED',
  'RECOVERY_AUTHORIZATION_INVALID',
  'RECOVERY_CURRENT_ROOT_MISMATCH',
  'RECOVERY_SUCCESSOR_ROOT_MISMATCH',
  'RECOVERY_CHAIN_RESET_REQUIRED',
  'STATE_ENVELOPE_INVALID',
  'STATE_ENVELOPE_HASH_MISMATCH',
  'EXTERNAL_STATE_PIN_REQUIRED',
  'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export type ARVVerifierTrustStateOperationV1 = typeof ARV_VERIFIER_TRUST_STATE_OPERATIONS[number];
export type ARVVerifierTrustStateStateV1 = typeof ARV_VERIFIER_TRUST_STATE_STATES[number];
export type ARVVerifierTrustStateCodeV1 = typeof ARV_VERIFIER_TRUST_STATE_CODES[number];

export interface ARVVerifierTrustStateV1 {
  schema: typeof ARV_VERIFIER_TRUST_STATE_SCHEMA;
  schema_version: typeof ARV_VERIFIER_TRUST_STATE_SCHEMA_VERSION;
  state_id: string;
  verifier_id: string;
  generation: number;
  recovery_count: number;
  bootstrap_mode: 'EXPLICIT_PIN';
  status: 'ACTIVE';
  last_operation: 'BOOTSTRAP' | 'ADVANCE' | 'RECOVERY';
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  witness_policy_id: string;
  witness_policy_version: number;
  witness_policy_hash: string;
  checkpoint_id: string;
  checkpoint_hash: string;
  checkpoint_sequence: number;
  registry_id: string;
  registry_version: number;
  registry_digest: string;
  observed_at: string;
  created_at: string;
  updated_at: string;
  previous_state_hash: string | null;
}

export interface ARVVerifierBootstrapPinsV1 {
  schema: typeof ARV_VERIFIER_BOOTSTRAP_PINS_SCHEMA;
  schema_version: typeof ARV_VERIFIER_TRUST_STATE_SCHEMA_VERSION;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  witness_policy_id: string;
  witness_policy_version: number;
  witness_policy_hash: string;
  checkpoint_id: string;
  checkpoint_hash: string;
  checkpoint_sequence: number;
  registry_id: string;
  registry_version: number;
  registry_digest: string;
}

export interface ARVVerifierTrustStateEnvelopeV1 {
  schema: typeof ARV_VERIFIER_TRUST_STATE_ENVELOPE_SCHEMA;
  schema_version: typeof ARV_VERIFIER_TRUST_STATE_SCHEMA_VERSION;
  state: ARVVerifierTrustStateV1;
  state_hash: string;
  exported_at: string;
}

export interface ARVVerifierTrustStateRecoveryAuthorizationV1 {
  current_root: unknown;
  transition: unknown;
  root_checkpoint: unknown;
}

export interface EvaluateARVVerifierTrustStateOptionsV1
  extends Omit<VerifyARVCheckpointWitnessOptionsV1, 'trusted_checkpoint' | 'trusted_witness_checkpoint'> {
  state_id: string;
  verifier_id: string;
  current_state: unknown | null;
  expected_current_state_hash: string | null;
  bootstrap_pins: unknown | null;
  recovery_authorization: ARVVerifierTrustStateRecoveryAuthorizationV1 | null;
  updated_at: string;
}

export interface ARVVerifierTrustStateVerificationV1 {
  schema: 'arv.verifier-trust-state-verification';
  schema_version: 1;
  accepted: boolean;
  state: ARVVerifierTrustStateStateV1;
  operation: ARVVerifierTrustStateOperationV1;
  current_state_hash: string | null;
  commit_precondition_hash: string | null;
  next_state_hash: string | null;
  next_state: ARVVerifierTrustStateV1 | null;
  witness_state: string | null;
  codes: ARVVerifierTrustStateCodeV1[];
  authority_basis: 'PINNED_TRUST_ROOT';
  local_state_authority: 'CONTINUITY_ONLY';
  storage_authority: 'NONE';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const stateIdPattern = /^ARV-VERIFIER-STATE-[A-Z0-9-]+$/;
const verifierIdPattern = /^ARV-VERIFIER-[A-Z0-9-]+$/;
const rootIdPattern = /^ARV-ROOT-[A-Z0-9-]+$/;
const policyIdPattern = /^ARV-WITNESS-POLICY-[A-Z0-9-]+$/;
const checkpointIdPattern = /^ARV-TRUST-CHECKPOINT-[A-Z0-9-]+$/;
const registryIdPattern = /^ARV-TRUST-REGISTRY-[A-Z0-9-]+$/;

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

function nonNegativeInteger(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || Number(value) < 0) throw new Error(`${location} must be a non-negative integer`);
}

function assertSha256(value: unknown, location: string): asserts value is string {
  if (typeof value !== 'string' || !sha256Pattern.test(value)) throw new Error(`${location} must be a lowercase SHA-256 digest`);
}

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function sha256ARVCheckpointWitnessPolicyForStateV1(policy: ARVCheckpointWitnessPolicyV1): string {
  const normalized = {
    signing_payload: canonicalARVCheckpointWitnessPolicySigningPayloadV1(policy),
    signatures: [...policy.signatures].sort((left, right) => left.key_id.localeCompare(right.key_id))
  };
  return sha256(`ARV-CHECKPOINT-WITNESS-POLICY-STATE-v1\n${canonicalizeARVJsonV1(normalized)}`);
}

export function assertARVVerifierTrustStateV1(value: unknown): ARVVerifierTrustStateV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const state = object(value, '$state');
  exactKeys(state, [
    'schema', 'schema_version', 'state_id', 'verifier_id', 'generation', 'recovery_count',
    'bootstrap_mode', 'status', 'last_operation', 'root_id', 'root_version', 'root_epoch', 'root_hash',
    'witness_policy_id', 'witness_policy_version', 'witness_policy_hash', 'checkpoint_id',
    'checkpoint_hash', 'checkpoint_sequence', 'registry_id', 'registry_version', 'registry_digest',
    'observed_at', 'created_at', 'updated_at', 'previous_state_hash'
  ], '$state');
  if (state.schema !== ARV_VERIFIER_TRUST_STATE_SCHEMA || state.schema_version !== 1) throw new Error('$state schema is invalid');
  if (typeof state.state_id !== 'string' || !stateIdPattern.test(state.state_id)) throw new Error('$state.state_id is invalid');
  if (typeof state.verifier_id !== 'string' || !verifierIdPattern.test(state.verifier_id)) throw new Error('$state.verifier_id is invalid');
  positiveInteger(state.generation, '$state.generation');
  nonNegativeInteger(state.recovery_count, '$state.recovery_count');
  if (state.bootstrap_mode !== 'EXPLICIT_PIN' || state.status !== 'ACTIVE') throw new Error('$state trust mode is invalid');
  if (!['BOOTSTRAP', 'ADVANCE', 'RECOVERY'].includes(String(state.last_operation))) throw new Error('$state.last_operation is invalid');
  if (typeof state.root_id !== 'string' || !rootIdPattern.test(state.root_id)) throw new Error('$state.root_id is invalid');
  positiveInteger(state.root_version, '$state.root_version');
  positiveInteger(state.root_epoch, '$state.root_epoch');
  assertSha256(state.root_hash, '$state.root_hash');
  if (typeof state.witness_policy_id !== 'string' || !policyIdPattern.test(state.witness_policy_id)) throw new Error('$state.witness_policy_id is invalid');
  positiveInteger(state.witness_policy_version, '$state.witness_policy_version');
  assertSha256(state.witness_policy_hash, '$state.witness_policy_hash');
  if (typeof state.checkpoint_id !== 'string' || !checkpointIdPattern.test(state.checkpoint_id)) throw new Error('$state.checkpoint_id is invalid');
  assertSha256(state.checkpoint_hash, '$state.checkpoint_hash');
  positiveInteger(state.checkpoint_sequence, '$state.checkpoint_sequence');
  if (typeof state.registry_id !== 'string' || !registryIdPattern.test(state.registry_id)) throw new Error('$state.registry_id is invalid');
  positiveInteger(state.registry_version, '$state.registry_version');
  assertSha256(state.registry_digest, '$state.registry_digest');
  timestamp(state.observed_at, '$state.observed_at');
  timestamp(state.created_at, '$state.created_at');
  timestamp(state.updated_at, '$state.updated_at');
  if (Date.parse(String(state.created_at)) > Date.parse(String(state.updated_at))) throw new Error('$state timestamps are invalid');
  if (Number(state.generation) === 1 && state.previous_state_hash !== null) throw new Error('$state initial predecessor is invalid');
  if (Number(state.generation) > 1) assertSha256(state.previous_state_hash, '$state.previous_state_hash');
  return state as unknown as ARVVerifierTrustStateV1;
}

export function assertARVVerifierBootstrapPinsV1(value: unknown): ARVVerifierBootstrapPinsV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const pins = object(value, '$bootstrap_pins');
  exactKeys(pins, [
    'schema', 'schema_version', 'root_id', 'root_version', 'root_epoch', 'root_hash',
    'witness_policy_id', 'witness_policy_version', 'witness_policy_hash', 'checkpoint_id',
    'checkpoint_hash', 'checkpoint_sequence', 'registry_id', 'registry_version', 'registry_digest'
  ], '$bootstrap_pins');
  if (pins.schema !== ARV_VERIFIER_BOOTSTRAP_PINS_SCHEMA || pins.schema_version !== 1) throw new Error('$bootstrap_pins schema is invalid');
  if (typeof pins.root_id !== 'string' || !rootIdPattern.test(pins.root_id)) throw new Error('$bootstrap_pins.root_id is invalid');
  positiveInteger(pins.root_version, '$bootstrap_pins.root_version');
  positiveInteger(pins.root_epoch, '$bootstrap_pins.root_epoch');
  assertSha256(pins.root_hash, '$bootstrap_pins.root_hash');
  if (typeof pins.witness_policy_id !== 'string' || !policyIdPattern.test(pins.witness_policy_id)) throw new Error('$bootstrap_pins.witness_policy_id is invalid');
  positiveInteger(pins.witness_policy_version, '$bootstrap_pins.witness_policy_version');
  assertSha256(pins.witness_policy_hash, '$bootstrap_pins.witness_policy_hash');
  if (typeof pins.checkpoint_id !== 'string' || !checkpointIdPattern.test(pins.checkpoint_id)) throw new Error('$bootstrap_pins.checkpoint_id is invalid');
  assertSha256(pins.checkpoint_hash, '$bootstrap_pins.checkpoint_hash');
  positiveInteger(pins.checkpoint_sequence, '$bootstrap_pins.checkpoint_sequence');
  if (typeof pins.registry_id !== 'string' || !registryIdPattern.test(pins.registry_id)) throw new Error('$bootstrap_pins.registry_id is invalid');
  positiveInteger(pins.registry_version, '$bootstrap_pins.registry_version');
  assertSha256(pins.registry_digest, '$bootstrap_pins.registry_digest');
  return pins as unknown as ARVVerifierBootstrapPinsV1;
}

export function canonicalARVVerifierTrustStateV1(state: ARVVerifierTrustStateV1): string {
  return `ARV-VERIFIER-TRUST-STATE-v1\n${canonicalizeARVJsonV1(state)}`;
}

export function sha256ARVVerifierTrustStateV1(state: ARVVerifierTrustStateV1): string {
  return sha256(canonicalARVVerifierTrustStateV1(state));
}

export function exportARVVerifierTrustStateV1(
  stateValue: unknown,
  exportedAt: string
): ARVVerifierTrustStateEnvelopeV1 {
  const state = assertARVVerifierTrustStateV1(stateValue);
  timestamp(exportedAt, '$exported_at');
  if (Date.parse(exportedAt) < Date.parse(state.updated_at)) throw new Error('$exported_at precedes state update');
  return {
    schema: ARV_VERIFIER_TRUST_STATE_ENVELOPE_SCHEMA,
    schema_version: 1,
    state,
    state_hash: sha256ARVVerifierTrustStateV1(state),
    exported_at: exportedAt
  };
}

export function serializeARVVerifierTrustStateEnvelopeV1(envelopeValue: unknown): string {
  const envelope = assertARVVerifierTrustStateEnvelopeV1(envelopeValue);
  return `${canonicalizeARVJsonV1(envelope)}\n`;
}

export function assertARVVerifierTrustStateEnvelopeV1(value: unknown): ARVVerifierTrustStateEnvelopeV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const envelope = object(value, '$envelope');
  exactKeys(envelope, ['schema', 'schema_version', 'state', 'state_hash', 'exported_at'], '$envelope');
  if (envelope.schema !== ARV_VERIFIER_TRUST_STATE_ENVELOPE_SCHEMA || envelope.schema_version !== 1) {
    throw new Error('$envelope schema is invalid');
  }
  const state = assertARVVerifierTrustStateV1(envelope.state);
  assertSha256(envelope.state_hash, '$envelope.state_hash');
  timestamp(envelope.exported_at, '$envelope.exported_at');
  if (envelope.state_hash !== sha256ARVVerifierTrustStateV1(state)) throw new Error('STATE_ENVELOPE_HASH_MISMATCH');
  if (Date.parse(String(envelope.exported_at)) < Date.parse(state.updated_at)) throw new Error('$envelope.exported_at is invalid');
  return { ...envelope, state } as unknown as ARVVerifierTrustStateEnvelopeV1;
}

export function importARVVerifierTrustStateV1(
  serialized: string,
  expectedStateHash: string
): ARVVerifierTrustStateV1 {
  assertSha256(expectedStateHash, '$expected_state_hash');
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error('STATE_ENVELOPE_INVALID');
  }
  const envelope = assertARVVerifierTrustStateEnvelopeV1(parsed);
  if (envelope.state_hash !== expectedStateHash) throw new Error('EXTERNAL_STATE_PIN_REQUIRED');
  return envelope.state;
}

function verification(
  state: ARVVerifierTrustStateStateV1,
  operation: ARVVerifierTrustStateOperationV1,
  codes: ARVVerifierTrustStateCodeV1[],
  currentHash: string | null,
  nextState: ARVVerifierTrustStateV1 | null,
  witness: ARVCheckpointWitnessVerificationV1 | null
): ARVVerifierTrustStateVerificationV1 {
  const accepted = ['BOOTSTRAP_ACCEPTED', 'ADVANCE_ACCEPTED', 'REPLAY_ACCEPTED', 'RECOVERY_ACCEPTED'].includes(state);
  return {
    schema: 'arv.verifier-trust-state-verification',
    schema_version: 1,
    accepted,
    state,
    operation,
    current_state_hash: currentHash,
    commit_precondition_hash: accepted ? currentHash : null,
    next_state_hash: accepted && nextState !== null ? sha256ARVVerifierTrustStateV1(nextState) : null,
    next_state: accepted ? nextState : null,
    witness_state: witness?.state ?? null,
    codes: Array.from(new Set(codes)),
    authority_basis: 'PINNED_TRUST_ROOT',
    local_state_authority: 'CONTINUITY_ONLY',
    storage_authority: 'NONE',
    transport_authority: 'NONE',
    material_truth: 'NOT_EVALUATED'
  };
}

function trustedCheckpoint(state: ARVVerifierTrustStateV1): ARVTrustedRegistryCheckpointV1 {
  return {
    checkpoint_id: state.checkpoint_id,
    checkpoint_hash: state.checkpoint_hash,
    sequence: state.checkpoint_sequence,
    registry_id: state.registry_id,
    registry_version: state.registry_version,
    registry_digest: state.registry_digest,
    root_id: state.root_id,
    root_version: state.root_version,
    root_epoch: state.root_epoch
  };
}

function trustedWitnessCheckpoint(state: ARVVerifierTrustStateV1): ARVTrustedWitnessCheckpointV1 {
  return {
    checkpoint_id: state.checkpoint_id,
    checkpoint_hash: state.checkpoint_hash,
    sequence: state.checkpoint_sequence,
    witness_policy_id: state.witness_policy_id,
    witness_policy_version: state.witness_policy_version,
    observed_at: state.observed_at
  };
}

function newState(
  options: EvaluateARVVerifierTrustStateOptionsV1,
  root: ARVTrustRootV1,
  policy: ARVCheckpointWitnessPolicyV1,
  checkpoint: ARVTrustRegistryCheckpointV1,
  witness: ARVCheckpointWitnessVerificationV1,
  previous: ARVVerifierTrustStateV1 | null,
  operation: 'BOOTSTRAP' | 'ADVANCE' | 'RECOVERY'
): ARVVerifierTrustStateV1 {
  if (witness.checkpoint_hash === null || witness.trusted_witness_checkpoint === null) {
    throw new Error('accepted witness projection is incomplete');
  }
  return {
    schema: ARV_VERIFIER_TRUST_STATE_SCHEMA,
    schema_version: 1,
    state_id: options.state_id,
    verifier_id: options.verifier_id,
    generation: previous === null ? 1 : previous.generation + 1,
    recovery_count: previous === null ? 0 : previous.recovery_count + (operation === 'RECOVERY' ? 1 : 0),
    bootstrap_mode: 'EXPLICIT_PIN',
    status: 'ACTIVE',
    last_operation: operation,
    root_id: root.root_id,
    root_version: root.root_version,
    root_epoch: root.epoch,
    root_hash: sha256ARVTrustRootV1(root),
    witness_policy_id: policy.policy_id,
    witness_policy_version: policy.policy_version,
    witness_policy_hash: sha256ARVCheckpointWitnessPolicyForStateV1(policy),
    checkpoint_id: checkpoint.checkpoint_id,
    checkpoint_hash: witness.checkpoint_hash,
    checkpoint_sequence: checkpoint.sequence,
    registry_id: checkpoint.registry_id,
    registry_version: checkpoint.registry_version,
    registry_digest: checkpoint.registry_digest,
    observed_at: witness.trusted_witness_checkpoint.observed_at,
    created_at: previous?.created_at ?? options.updated_at,
    updated_at: options.updated_at,
    previous_state_hash: previous === null ? null : sha256ARVVerifierTrustStateV1(previous)
  };
}

function pinMismatch(
  pins: ARVVerifierBootstrapPinsV1,
  root: ARVTrustRootV1,
  policy: ARVCheckpointWitnessPolicyV1,
  checkpoint: ARVTrustRegistryCheckpointV1,
  checkpointHash: string
): ARVVerifierTrustStateCodeV1 | null {
  if (
    pins.root_id !== root.root_id || pins.root_version !== root.root_version || pins.root_epoch !== root.epoch ||
    pins.root_hash !== sha256ARVTrustRootV1(root)
  ) return 'BOOTSTRAP_ROOT_PIN_MISMATCH';
  if (
    pins.witness_policy_id !== policy.policy_id || pins.witness_policy_version !== policy.policy_version ||
    pins.witness_policy_hash !== sha256ARVCheckpointWitnessPolicyForStateV1(policy)
  ) return 'BOOTSTRAP_POLICY_PIN_MISMATCH';
  if (
    pins.checkpoint_id !== checkpoint.checkpoint_id || pins.checkpoint_hash !== checkpointHash ||
    pins.checkpoint_sequence !== checkpoint.sequence
  ) return 'BOOTSTRAP_CHECKPOINT_PIN_MISMATCH';
  if (
    pins.registry_id !== checkpoint.registry_id || pins.registry_version !== checkpoint.registry_version ||
    pins.registry_digest !== checkpoint.registry_digest
  ) return 'BOOTSTRAP_REGISTRY_PIN_MISMATCH';
  return null;
}

function verifyWitness(
  options: EvaluateARVVerifierTrustStateOptionsV1,
  trusted: ARVVerifierTrustStateV1 | null
): ARVCheckpointWitnessVerificationV1 {
  return verifyARVCheckpointWitnessV1({
    ...options,
    trusted_checkpoint: trusted === null ? null : trustedCheckpoint(trusted),
    trusted_witness_checkpoint: trusted === null ? null : trustedWitnessCheckpoint(trusted)
  });
}

export function evaluateARVVerifierTrustStateV1(
  options: EvaluateARVVerifierTrustStateOptionsV1
): ARVVerifierTrustStateVerificationV1 {
  let root: ARVTrustRootV1;
  let policy: ARVCheckpointWitnessPolicyV1;
  let checkpoint: ARVTrustRegistryCheckpointV1;
  let current: ARVVerifierTrustStateV1 | null = null;
  try {
    assertNoARVPrivateKeyMaterialV1(options);
    if (!stateIdPattern.test(options.state_id) || !verifierIdPattern.test(options.verifier_id)) throw new Error('verifier identifiers are invalid');
    timestamp(options.updated_at, '$updated_at');
    timestamp(options.evaluated_at, '$evaluated_at');
    if (Date.parse(options.updated_at) < Date.parse(options.evaluated_at)) throw new Error('$updated_at precedes evaluation');
    root = assertARVTrustRootV1(options.trust_root);
    policy = assertARVCheckpointWitnessPolicyV1(options.witness_policy);
    checkpoint = assertARVTrustRegistryCheckpointV1(options.checkpoint);
    if (options.current_state !== null) current = assertARVVerifierTrustStateV1(options.current_state);
  } catch (error) {
    const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    return verification(
      privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'STATE_INVALID',
      'NONE',
      [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'CURRENT_STATE_SCHEMA_INVALID'],
      null,
      null,
      null
    );
  }

  if (current === null) {
    if (options.expected_current_state_hash !== null) {
      return verification('STATE_HASH_MISMATCH', 'NONE', ['CURRENT_STATE_HASH_MISMATCH'], null, null, null);
    }
    if (options.bootstrap_pins === null) {
      return verification('BOOTSTRAP_REQUIRED', 'NONE', ['BOOTSTRAP_PINS_REQUIRED'], null, null, null);
    }
    if (options.recovery_authorization !== null) {
      return verification('STATE_INVALID', 'NONE', ['BOOTSTRAP_REUSE_FORBIDDEN'], null, null, null);
    }
    let pins: ARVVerifierBootstrapPinsV1;
    try {
      pins = assertARVVerifierBootstrapPinsV1(options.bootstrap_pins);
    } catch (error) {
      const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
      return verification(
        privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'STATE_INVALID',
        'NONE',
        [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'BOOTSTRAP_PINS_SCHEMA_INVALID'],
        null,
        null,
        null
      );
    }
    const witness = verifyWitness(options, null);
    if (!witness.accepted || witness.checkpoint_hash === null) {
      return verification('UNDERLYING_WITNESS_REJECTED', 'NONE', ['WITNESS_VERIFICATION_REJECTED'], null, null, witness);
    }
    const mismatch = pinMismatch(pins, root, policy, checkpoint, witness.checkpoint_hash);
    if (mismatch !== null) return verification('BOOTSTRAP_PIN_MISMATCH', 'NONE', [mismatch], null, null, witness);
    const next = newState(options, root, policy, checkpoint, witness, null, 'BOOTSTRAP');
    return verification('BOOTSTRAP_ACCEPTED', 'BOOTSTRAP', [], null, next, witness);
  }

  const currentHash = sha256ARVVerifierTrustStateV1(current);
  if (options.expected_current_state_hash === null) {
    return verification('STATE_HASH_MISMATCH', 'NONE', ['CURRENT_STATE_HASH_REQUIRED'], currentHash, null, null);
  }
  if (options.expected_current_state_hash !== currentHash) {
    return verification('STATE_HASH_MISMATCH', 'NONE', ['CURRENT_STATE_HASH_MISMATCH'], currentHash, null, null);
  }
  if (current.state_id !== options.state_id || current.verifier_id !== options.verifier_id) {
    return verification('STATE_INVALID', 'NONE', ['VERIFIER_ID_MISMATCH'], currentHash, null, null);
  }
  if (options.bootstrap_pins !== null) {
    return verification('BOOTSTRAP_REUSE_FORBIDDEN', 'NONE', ['BOOTSTRAP_REUSE_FORBIDDEN'], currentHash, null, null);
  }

  const rootHash = sha256ARVTrustRootV1(root);
  const policyHash = sha256ARVCheckpointWitnessPolicyForStateV1(policy);
  if (rootHash !== current.root_hash) {
    if (options.recovery_authorization === null) {
      return verification('ROOT_TRANSITION_REQUIRED', 'NONE', ['RECOVERY_AUTHORIZATION_REQUIRED'], currentHash, null, null);
    }
    let recoveryCurrentRoot: ARVTrustRootV1;
    try {
      recoveryCurrentRoot = assertARVTrustRootV1(options.recovery_authorization.current_root);
    } catch (error) {
      const privateMaterial = error instanceof Error && error.message.includes('PRIVATE_KEY_MATERIAL_FORBIDDEN');
      return verification(
        privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'ROOT_RECOVERY_INVALID',
        'NONE',
        [privateMaterial ? 'PRIVATE_KEY_MATERIAL_FORBIDDEN' : 'RECOVERY_AUTHORIZATION_INVALID'],
        currentHash,
        null,
        null
      );
    }
    if (sha256ARVTrustRootV1(recoveryCurrentRoot) !== current.root_hash) {
      return verification('ROOT_RECOVERY_INVALID', 'NONE', ['RECOVERY_CURRENT_ROOT_MISMATCH'], currentHash, null, null);
    }
    const rootTransition = verifyARVTrustRootTransitionV1({
      current_root: recoveryCurrentRoot,
      successor_root: root,
      transition: options.recovery_authorization.transition,
      checkpoint: options.recovery_authorization.root_checkpoint,
      evaluated_at: options.evaluated_at
    });
    if (!rootTransition.accepted || rootTransition.successor_root_hash !== rootHash) {
      return verification('ROOT_RECOVERY_INVALID', 'NONE', ['RECOVERY_AUTHORIZATION_INVALID'], currentHash, null, null);
    }
    const witness = verifyWitness(options, null);
    if (!witness.accepted) {
      return verification('UNDERLYING_WITNESS_REJECTED', 'NONE', ['WITNESS_VERIFICATION_REJECTED'], currentHash, null, witness);
    }
    if (checkpoint.sequence !== 1 || checkpoint.registry_version !== 1 || checkpoint.previous_checkpoint_hash !== null) {
      return verification('ROOT_RECOVERY_INVALID', 'NONE', ['RECOVERY_CHAIN_RESET_REQUIRED'], currentHash, null, witness);
    }
    const next = newState(options, root, policy, checkpoint, witness, current, 'RECOVERY');
    return verification('RECOVERY_ACCEPTED', 'RECOVERY', [], currentHash, next, witness);
  }

  if (options.recovery_authorization !== null) {
    return verification('ROOT_RECOVERY_INVALID', 'NONE', ['RECOVERY_SUCCESSOR_ROOT_MISMATCH'], currentHash, null, null);
  }
  if (root.root_id !== current.root_id || root.root_version !== current.root_version || root.epoch !== current.root_epoch) {
    return verification('STATE_EQUIVOCATION', 'NONE', ['RECOVERY_SUCCESSOR_ROOT_MISMATCH'], currentHash, null, null);
  }
  if (policy.policy_id !== current.witness_policy_id || policy.policy_version < current.witness_policy_version) {
    return verification('POLICY_ROLLBACK', 'NONE', ['POLICY_VERSION_ROLLBACK'], currentHash, null, null);
  }
  if (policy.policy_version === current.witness_policy_version && policyHash !== current.witness_policy_hash) {
    return verification('POLICY_EQUIVOCATION', 'NONE', ['POLICY_HASH_EQUIVOCATION'], currentHash, null, null);
  }
  if (policy.policy_version > current.witness_policy_version + 1) {
    return verification('POLICY_GAP', 'NONE', ['POLICY_VERSION_GAP'], currentHash, null, null);
  }

  const candidateCheckpointHash = sha256ARVTrustRegistryCheckpointV1(checkpoint);
  if (checkpoint.sequence < current.checkpoint_sequence) {
    return verification('STATE_ROLLBACK', 'NONE', ['STATE_SEQUENCE_ROLLBACK'], currentHash, null, null);
  }
  if (checkpoint.sequence > current.checkpoint_sequence + 1) {
    return verification('STATE_GAP', 'NONE', ['STATE_SEQUENCE_GAP'], currentHash, null, null);
  }
  if (checkpoint.sequence === current.checkpoint_sequence && candidateCheckpointHash !== current.checkpoint_hash) {
    return verification('STATE_EQUIVOCATION', 'NONE', ['STATE_CHECKPOINT_EQUIVOCATION'], currentHash, null, null);
  }
  if (
    checkpoint.sequence === current.checkpoint_sequence + 1 &&
    checkpoint.previous_checkpoint_hash !== current.checkpoint_hash
  ) {
    return verification('STATE_EQUIVOCATION', 'NONE', ['STATE_PREDECESSOR_MISMATCH'], currentHash, null, null);
  }

  const witness = verifyWitness(options, current);
  if (!witness.accepted || witness.checkpoint_hash === null) {
    return verification('UNDERLYING_WITNESS_REJECTED', 'NONE', ['WITNESS_VERIFICATION_REJECTED'], currentHash, null, witness);
  }
  if (checkpoint.sequence < current.checkpoint_sequence) {
    return verification('STATE_ROLLBACK', 'NONE', ['STATE_SEQUENCE_ROLLBACK'], currentHash, null, witness);
  }
  if (checkpoint.sequence === current.checkpoint_sequence) {
    if (witness.checkpoint_hash !== current.checkpoint_hash) {
      return verification('STATE_EQUIVOCATION', 'NONE', ['STATE_CHECKPOINT_EQUIVOCATION'], currentHash, null, witness);
    }
    if (
      checkpoint.registry_id !== current.registry_id || checkpoint.registry_version !== current.registry_version ||
      checkpoint.registry_digest !== current.registry_digest || policyHash !== current.witness_policy_hash
    ) {
      return verification('STATE_EQUIVOCATION', 'NONE', ['STATE_CHECKPOINT_EQUIVOCATION'], currentHash, null, witness);
    }
    return verification('REPLAY_ACCEPTED', 'REPLAY', [], currentHash, current, witness);
  }
  if (checkpoint.sequence !== current.checkpoint_sequence + 1) {
    return verification('STATE_GAP', 'NONE', ['STATE_SEQUENCE_GAP'], currentHash, null, witness);
  }
  if (checkpoint.previous_checkpoint_hash !== current.checkpoint_hash) {
    return verification('STATE_EQUIVOCATION', 'NONE', ['STATE_PREDECESSOR_MISMATCH'], currentHash, null, witness);
  }
  const next = newState(options, root, policy, checkpoint, witness, current, 'ADVANCE');
  return verification('ADVANCE_ACCEPTED', 'ADVANCE', [], currentHash, next, witness);
}
