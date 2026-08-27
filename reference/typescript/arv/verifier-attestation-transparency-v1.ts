import crypto from 'crypto';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';
import { assertNoARVPrivateKeyMaterialV1 } from './trust-root-lifecycle-v1';
import {
  ARVVerifierRuntimeAttestationV1,
  ARVVerifierSecurityEventChainV1,
  assertARVVerifierRuntimeAttestationV1,
  assertARVVerifierSecurityEventChainV1,
  sha256ARVVerifierRuntimeAttestationV1,
  sha256ARVVerifierSecurityEventChainV1
} from './verifier-runtime-attestation-v1';

export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_POLICY_SCHEMA = 'arv.verifier-attestation-transparency-policy' as const;
export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_ENTRY_SCHEMA = 'arv.verifier-attestation-transparency-entry' as const;
export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_CHECKPOINT_SCHEMA = 'arv.verifier-attestation-transparency-checkpoint' as const;
export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_RECEIPT_SCHEMA = 'arv.verifier-attestation-transparency-receipt' as const;
export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_MONITOR_OBSERVATION_SCHEMA = 'arv.verifier-attestation-transparency-monitor-observation' as const;
export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_SCHEMA_VERSION = 1 as const;

export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_STATES = [
  'BOOTSTRAP_ACCEPTED', 'UPDATE_ACCEPTED', 'REPLAY_ACCEPTED',
  'POLICY_INVALID', 'POLICY_PIN_REQUIRED', 'POLICY_PIN_MISMATCH',
  'ENTRY_INVALID', 'ENTRY_BINDING_INVALID', 'EVIDENCE_COMMITMENT_INVALID',
  'CHECKPOINT_INVALID', 'CHECKPOINT_BINDING_INVALID', 'CHECKPOINT_TIME_INVALID',
  'LOG_OPERATOR_QUORUM_NOT_MET', 'RECEIPT_INVALID', 'RECEIPT_BINDING_INVALID',
  'INCLUSION_PROOF_INVALID', 'MONITOR_OBSERVATION_INVALID', 'MONITOR_QUORUM_NOT_MET',
  'MONITOR_SPLIT_VIEW', 'CURRENT_CHECKPOINT_REQUIRED', 'CURRENT_CHECKPOINT_INVALID',
  'CURRENT_CHECKPOINT_HASH_REQUIRED', 'CURRENT_CHECKPOINT_HASH_MISMATCH',
  'CHECKPOINT_ROLLBACK', 'CHECKPOINT_GAP', 'CHECKPOINT_EQUIVOCATION',
  'CONSISTENCY_PROOF_INVALID', 'PRIVATE_KEY_MATERIAL_FORBIDDEN'
] as const;

export const ARV_VERIFIER_ATTESTATION_TRANSPARENCY_OPERATIONS = ['NONE', 'BOOTSTRAP', 'UPDATE', 'REPLAY'] as const;

export type ARVVerifierAttestationTransparencyStateV1 = typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_STATES[number];
export type ARVVerifierAttestationTransparencyOperationV1 = typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_OPERATIONS[number];

export interface ARVTransparencyPublicSignerV1 {
  signer_id: string;
  key_id: string;
  algorithm: 'Ed25519';
  public_key_spki_base64: string;
  status: 'ACTIVE' | 'REVOKED';
  valid_from: string;
  expires_at: string;
}

export interface ARVVerifierAttestationTransparencyPolicyV1 {
  schema: typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_POLICY_SCHEMA;
  schema_version: 1;
  policy_id: string;
  log_id: string;
  policy_version: number;
  root_id: string;
  root_version: number;
  root_epoch: number;
  root_hash: string;
  operator_threshold: number;
  monitor_threshold: number;
  max_checkpoint_age_seconds: number;
  max_clock_skew_seconds: number;
  operators: ARVTransparencyPublicSignerV1[];
  monitors: ARVTransparencyPublicSignerV1[];
  issued_at: string;
}

export interface ARVVerifierAttestationTransparencyEntryV1 {
  schema: typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_ENTRY_SCHEMA;
  schema_version: 1;
  entry_id: string;
  log_id: string;
  leaf_index: number;
  verifier_id: string;
  instance_id: string;
  attestation_sequence: number;
  attestation_hash: string;
  security_event_chain_hash: string;
  disclosure_digest: string;
  evidence_commitment: string;
  submitted_at: string;
}

export interface ARVTransparencySignatureV1 {
  algorithm: 'Ed25519';
  key_id: string;
  signature_base64: string;
}

export interface ARVVerifierAttestationTransparencyCheckpointV1 {
  schema: typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_CHECKPOINT_SCHEMA;
  schema_version: 1;
  checkpoint_id: string;
  log_id: string;
  checkpoint_sequence: number;
  tree_size: number;
  root_hash: string;
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  issued_at: string;
  previous_checkpoint_hash: string | null;
  signatures: ARVTransparencySignatureV1[];
}

export interface ARVVerifierAttestationTransparencyReceiptV1 {
  schema: typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_RECEIPT_SCHEMA;
  schema_version: 1;
  receipt_id: string;
  log_id: string;
  entry_hash: string;
  leaf_hash: string;
  leaf_index: number;
  tree_size: number;
  checkpoint_hash: string;
  prior_tree_size: number;
  prior_checkpoint_hash: string | null;
  inclusion_path: string[];
  consistency_path: string[];
}

export interface ARVVerifierAttestationTransparencyMonitorObservationV1 {
  schema: typeof ARV_VERIFIER_ATTESTATION_TRANSPARENCY_MONITOR_OBSERVATION_SCHEMA;
  schema_version: 1;
  observation_id: string;
  monitor_id: string;
  key_id: string;
  log_id: string;
  checkpoint_sequence: number;
  tree_size: number;
  root_hash: string;
  checkpoint_hash: string;
  observed_at: string;
  signature_base64: string;
}

export interface VerifyARVVerifierAttestationTransparencyOptionsV1 {
  transparency_policy: unknown;
  runtime_attestation: unknown;
  security_event_chain: unknown;
  transparency_entry: unknown;
  transparency_checkpoint: unknown;
  transparency_receipt: unknown;
  monitor_observations: unknown;
  current_checkpoint: unknown | null;
  expected_current_checkpoint_hash: string | null;
  bootstrap_policy_hash: string | null;
  evaluated_at: string;
}

export interface ARVVerifierAttestationTransparencyVerificationV1 {
  schema: 'arv.verifier-attestation-transparency-verification';
  schema_version: 1;
  accepted: boolean;
  frozen: boolean;
  state: ARVVerifierAttestationTransparencyStateV1;
  operation: ARVVerifierAttestationTransparencyOperationV1;
  policy_hash: string | null;
  attestation_hash: string | null;
  security_event_chain_hash: string | null;
  entry_hash: string | null;
  leaf_hash: string | null;
  checkpoint_hash: string | null;
  current_checkpoint_hash: string | null;
  commit_precondition_hash: string | null;
  next_checkpoint_hash: string | null;
  valid_operator_signatures: number;
  valid_monitor_observations: number;
  codes: string[];
  runtime_evidence_authority: 'VERIFIED_ATTESTATION_AND_EVENT_CHAIN';
  transparency_authority: 'APPEND_ONLY_COMMITMENT_PROOFS';
  log_operator_authority: 'COMMITMENT_PUBLICATION_ONLY';
  monitor_authority: 'INDEPENDENT_OBSERVATION_ONLY';
  storage_authority: 'NONE';
  transport_authority: 'NONE';
  material_truth: 'NOT_EVALUATED';
}

const digestPattern = /^[a-f0-9]{64}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const policyPattern = /^ARV-ATTESTATION-TRANSPARENCY-POLICY-[A-Z0-9-]+$/;
const logPattern = /^ARV-ATTESTATION-TRANSPARENCY-LOG-[A-Z0-9-]+$/;
const entryPattern = /^ARV-ATTESTATION-TRANSPARENCY-ENTRY-[A-Z0-9-]+$/;
const checkpointPattern = /^ARV-ATTESTATION-TRANSPARENCY-CHECKPOINT-[A-Z0-9-]+$/;
const receiptPattern = /^ARV-ATTESTATION-TRANSPARENCY-RECEIPT-[A-Z0-9-]+$/;
const observationPattern = /^ARV-ATTESTATION-TRANSPARENCY-OBSERVATION-[A-Z0-9-]+$/;
const operatorPattern = /^ARV-TRANSPARENCY-LOG-OPERATOR-[A-Z0-9-]+$/;
const monitorPattern = /^ARV-TRANSPARENCY-MONITOR-[A-Z0-9-]+$/;
const verifierPattern = /^ARV-VERIFIER-[A-Z0-9-]+$/;
const instancePattern = /^ARV-VERIFIER-INSTANCE-[A-Z0-9-]+$/;
const rootPattern = /^ARV-ROOT-[A-Z0-9-]+$/;
const keyPattern = /^[a-f0-9]{24,128}$/;
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

function nonNegative(value: unknown, location: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 0) throw new Error(`${location} must be a non-negative integer`);
}

function sha256Domain(domain: string, value: unknown): string {
  return crypto.createHash('sha256').update(`${domain}\n${canonicalizeARVJsonV1(value)}`, 'utf8').digest('hex');
}

function parsePublicSigner(value: unknown, location: string, idPattern: RegExp): ARVTransparencyPublicSignerV1 {
  const signer = object(value, location);
  exact(signer, ['signer_id','key_id','algorithm','public_key_spki_base64','status','valid_from','expires_at'], location);
  string(signer.signer_id, idPattern, `${location}.signer_id`);
  string(signer.key_id, keyPattern, `${location}.key_id`);
  if (signer.algorithm !== 'Ed25519' || !['ACTIVE','REVOKED'].includes(signer.status as string)) throw new Error(`${location} signer is invalid`);
  string(signer.public_key_spki_base64, base64Pattern, `${location}.public_key_spki_base64`);
  const keyBytes = Buffer.from(signer.public_key_spki_base64 as string, 'base64');
  if (keyBytes.length === 0 || keyBytes.toString('base64') !== signer.public_key_spki_base64) throw new Error(`${location} public key encoding is invalid`);
  timestamp(signer.valid_from, `${location}.valid_from`);
  timestamp(signer.expires_at, `${location}.expires_at`);
  if (Date.parse(signer.valid_from as string) >= Date.parse(signer.expires_at as string)) throw new Error(`${location} validity is invalid`);
  return signer as unknown as ARVTransparencyPublicSignerV1;
}

function uniqueSortedSigners(signers: ARVTransparencyPublicSignerV1[], location: string): void {
  const ids = signers.map((item) => item.signer_id);
  const keys = signers.map((item) => item.key_id);
  if (new Set(ids).size !== ids.length || new Set(keys).size !== keys.length) throw new Error(`${location} signers must be unique`);
  if (ids.some((item, index) => item !== [...ids].sort()[index])) throw new Error(`${location} signers must be sorted`);
}

export function assertARVVerifierAttestationTransparencyPolicyV1(value: unknown): ARVVerifierAttestationTransparencyPolicyV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$transparency_policy');
  exact(input, ['schema','schema_version','policy_id','log_id','policy_version','root_id','root_version','root_epoch','root_hash','operator_threshold','monitor_threshold','max_checkpoint_age_seconds','max_clock_skew_seconds','operators','monitors','issued_at'], '$transparency_policy');
  if (input.schema !== ARV_VERIFIER_ATTESTATION_TRANSPARENCY_POLICY_SCHEMA || input.schema_version !== 1) throw new Error('$transparency_policy schema is invalid');
  string(input.policy_id, policyPattern, '$transparency_policy.policy_id');
  string(input.log_id, logPattern, '$transparency_policy.log_id');
  positive(input.policy_version, '$transparency_policy.policy_version');
  string(input.root_id, rootPattern, '$transparency_policy.root_id');
  positive(input.root_version, '$transparency_policy.root_version');
  positive(input.root_epoch, '$transparency_policy.root_epoch');
  digest(input.root_hash, '$transparency_policy.root_hash');
  positive(input.operator_threshold, '$transparency_policy.operator_threshold');
  positive(input.monitor_threshold, '$transparency_policy.monitor_threshold');
  positive(input.max_checkpoint_age_seconds, '$transparency_policy.max_checkpoint_age_seconds');
  positive(input.max_clock_skew_seconds, '$transparency_policy.max_clock_skew_seconds');
  timestamp(input.issued_at, '$transparency_policy.issued_at');
  if (!Array.isArray(input.operators) || input.operators.length === 0) throw new Error('$transparency_policy.operators is invalid');
  if (!Array.isArray(input.monitors) || input.monitors.length === 0) throw new Error('$transparency_policy.monitors is invalid');
  const operators = input.operators.map((item, index) => parsePublicSigner(item, `$transparency_policy.operators[${index}]`, operatorPattern));
  const monitors = input.monitors.map((item, index) => parsePublicSigner(item, `$transparency_policy.monitors[${index}]`, monitorPattern));
  uniqueSortedSigners(operators, '$transparency_policy.operators');
  uniqueSortedSigners(monitors, '$transparency_policy.monitors');
  if ((input.operator_threshold as number) > operators.length || (input.monitor_threshold as number) > monitors.length) throw new Error('$transparency_policy threshold exceeds signer count');
  return { ...(input as unknown as ARVVerifierAttestationTransparencyPolicyV1), operators, monitors };
}

export function assertARVVerifierAttestationTransparencyEntryV1(value: unknown): ARVVerifierAttestationTransparencyEntryV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$transparency_entry');
  exact(input, ['schema','schema_version','entry_id','log_id','leaf_index','verifier_id','instance_id','attestation_sequence','attestation_hash','security_event_chain_hash','disclosure_digest','evidence_commitment','submitted_at'], '$transparency_entry');
  if (input.schema !== ARV_VERIFIER_ATTESTATION_TRANSPARENCY_ENTRY_SCHEMA || input.schema_version !== 1) throw new Error('$transparency_entry schema is invalid');
  string(input.entry_id, entryPattern, '$transparency_entry.entry_id');
  string(input.log_id, logPattern, '$transparency_entry.log_id');
  nonNegative(input.leaf_index, '$transparency_entry.leaf_index');
  string(input.verifier_id, verifierPattern, '$transparency_entry.verifier_id');
  string(input.instance_id, instancePattern, '$transparency_entry.instance_id');
  positive(input.attestation_sequence, '$transparency_entry.attestation_sequence');
  digest(input.attestation_hash, '$transparency_entry.attestation_hash');
  digest(input.security_event_chain_hash, '$transparency_entry.security_event_chain_hash');
  digest(input.disclosure_digest, '$transparency_entry.disclosure_digest');
  digest(input.evidence_commitment, '$transparency_entry.evidence_commitment');
  timestamp(input.submitted_at, '$transparency_entry.submitted_at');
  return input as unknown as ARVVerifierAttestationTransparencyEntryV1;
}

function parseSignature(value: unknown, location: string): ARVTransparencySignatureV1 {
  const signature = object(value, location);
  exact(signature, ['algorithm','key_id','signature_base64'], location);
  if (signature.algorithm !== 'Ed25519') throw new Error(`${location}.algorithm is invalid`);
  string(signature.key_id, keyPattern, `${location}.key_id`);
  string(signature.signature_base64, base64Pattern, `${location}.signature_base64`);
  const bytes = Buffer.from(signature.signature_base64 as string, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== signature.signature_base64) throw new Error(`${location} signature encoding is invalid`);
  return signature as unknown as ARVTransparencySignatureV1;
}

export function assertARVVerifierAttestationTransparencyCheckpointV1(value: unknown): ARVVerifierAttestationTransparencyCheckpointV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$transparency_checkpoint');
  exact(input, ['schema','schema_version','checkpoint_id','log_id','checkpoint_sequence','tree_size','root_hash','policy_id','policy_version','policy_hash','issued_at','previous_checkpoint_hash','signatures'], '$transparency_checkpoint');
  if (input.schema !== ARV_VERIFIER_ATTESTATION_TRANSPARENCY_CHECKPOINT_SCHEMA || input.schema_version !== 1) throw new Error('$transparency_checkpoint schema is invalid');
  string(input.checkpoint_id, checkpointPattern, '$transparency_checkpoint.checkpoint_id');
  string(input.log_id, logPattern, '$transparency_checkpoint.log_id');
  positive(input.checkpoint_sequence, '$transparency_checkpoint.checkpoint_sequence');
  positive(input.tree_size, '$transparency_checkpoint.tree_size');
  digest(input.root_hash, '$transparency_checkpoint.root_hash');
  string(input.policy_id, policyPattern, '$transparency_checkpoint.policy_id');
  positive(input.policy_version, '$transparency_checkpoint.policy_version');
  digest(input.policy_hash, '$transparency_checkpoint.policy_hash');
  timestamp(input.issued_at, '$transparency_checkpoint.issued_at');
  if (input.previous_checkpoint_hash !== null) digest(input.previous_checkpoint_hash, '$transparency_checkpoint.previous_checkpoint_hash');
  if (!Array.isArray(input.signatures) || input.signatures.length === 0) throw new Error('$transparency_checkpoint.signatures is invalid');
  const signatures = input.signatures.map((item, index) => parseSignature(item, `$transparency_checkpoint.signatures[${index}]`));
  const keys = signatures.map((item) => item.key_id);
  if (new Set(keys).size !== keys.length || keys.some((item, index) => item !== [...keys].sort()[index])) throw new Error('$transparency_checkpoint signatures must be unique and sorted');
  return { ...(input as unknown as ARVVerifierAttestationTransparencyCheckpointV1), signatures };
}

function digestArray(value: unknown, location: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${location} must be an array`);
  value.forEach((item, index) => digest(item, `${location}[${index}]`));
  return value as string[];
}

export function assertARVVerifierAttestationTransparencyReceiptV1(value: unknown): ARVVerifierAttestationTransparencyReceiptV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$transparency_receipt');
  exact(input, ['schema','schema_version','receipt_id','log_id','entry_hash','leaf_hash','leaf_index','tree_size','checkpoint_hash','prior_tree_size','prior_checkpoint_hash','inclusion_path','consistency_path'], '$transparency_receipt');
  if (input.schema !== ARV_VERIFIER_ATTESTATION_TRANSPARENCY_RECEIPT_SCHEMA || input.schema_version !== 1) throw new Error('$transparency_receipt schema is invalid');
  string(input.receipt_id, receiptPattern, '$transparency_receipt.receipt_id');
  string(input.log_id, logPattern, '$transparency_receipt.log_id');
  digest(input.entry_hash, '$transparency_receipt.entry_hash');
  digest(input.leaf_hash, '$transparency_receipt.leaf_hash');
  nonNegative(input.leaf_index, '$transparency_receipt.leaf_index');
  positive(input.tree_size, '$transparency_receipt.tree_size');
  digest(input.checkpoint_hash, '$transparency_receipt.checkpoint_hash');
  nonNegative(input.prior_tree_size, '$transparency_receipt.prior_tree_size');
  if (input.prior_checkpoint_hash !== null) digest(input.prior_checkpoint_hash, '$transparency_receipt.prior_checkpoint_hash');
  const inclusionPath = digestArray(input.inclusion_path, '$transparency_receipt.inclusion_path');
  const consistencyPath = digestArray(input.consistency_path, '$transparency_receipt.consistency_path');
  if ((input.leaf_index as number) >= (input.tree_size as number)) throw new Error('$transparency_receipt tree coordinates are invalid');
  return { ...(input as unknown as ARVVerifierAttestationTransparencyReceiptV1), inclusion_path: inclusionPath, consistency_path: consistencyPath };
}

export function assertARVVerifierAttestationTransparencyMonitorObservationV1(value: unknown): ARVVerifierAttestationTransparencyMonitorObservationV1 {
  assertNoARVPrivateKeyMaterialV1(value);
  const input = object(value, '$monitor_observation');
  exact(input, ['schema','schema_version','observation_id','monitor_id','key_id','log_id','checkpoint_sequence','tree_size','root_hash','checkpoint_hash','observed_at','signature_base64'], '$monitor_observation');
  if (input.schema !== ARV_VERIFIER_ATTESTATION_TRANSPARENCY_MONITOR_OBSERVATION_SCHEMA || input.schema_version !== 1) throw new Error('$monitor_observation schema is invalid');
  string(input.observation_id, observationPattern, '$monitor_observation.observation_id');
  string(input.monitor_id, monitorPattern, '$monitor_observation.monitor_id');
  string(input.key_id, keyPattern, '$monitor_observation.key_id');
  string(input.log_id, logPattern, '$monitor_observation.log_id');
  positive(input.checkpoint_sequence, '$monitor_observation.checkpoint_sequence');
  positive(input.tree_size, '$monitor_observation.tree_size');
  digest(input.root_hash, '$monitor_observation.root_hash');
  digest(input.checkpoint_hash, '$monitor_observation.checkpoint_hash');
  timestamp(input.observed_at, '$monitor_observation.observed_at');
  string(input.signature_base64, base64Pattern, '$monitor_observation.signature_base64');
  const bytes = Buffer.from(input.signature_base64 as string, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== input.signature_base64) throw new Error('$monitor_observation signature encoding is invalid');
  return input as unknown as ARVVerifierAttestationTransparencyMonitorObservationV1;
}

export function sha256ARVVerifierAttestationTransparencyPolicyV1(value: ARVVerifierAttestationTransparencyPolicyV1): string {
  return sha256Domain('ARV-VERIFIER-ATTESTATION-TRANSPARENCY-POLICY-V1', assertARVVerifierAttestationTransparencyPolicyV1(value));
}

export function sha256ARVVerifierAttestationTransparencyEntryV1(value: ARVVerifierAttestationTransparencyEntryV1): string {
  return sha256Domain('ARV-VERIFIER-ATTESTATION-TRANSPARENCY-ENTRY-V1', assertARVVerifierAttestationTransparencyEntryV1(value));
}

export function evidenceCommitmentARVVerifierAttestationTransparencyV1(attestationHash: string, eventChainHash: string, disclosureDigest: string): string {
  digest(attestationHash, '$attestation_hash'); digest(eventChainHash, '$event_chain_hash'); digest(disclosureDigest, '$disclosure_digest');
  return sha256Domain('ARV-TRANSPARENCY-EVIDENCE-COMMITMENT-V1', {
    attestation_hash: attestationHash,
    security_event_chain_hash: eventChainHash,
    disclosure_digest: disclosureDigest
  });
}

export function canonicalARVVerifierAttestationTransparencyCheckpointSigningBytesV1(value: ARVVerifierAttestationTransparencyCheckpointV1): Buffer {
  const checkpoint = assertARVVerifierAttestationTransparencyCheckpointV1(value);
  const { signatures: _signatures, ...unsigned } = checkpoint;
  return Buffer.from(`ARV-VERIFIER-ATTESTATION-TRANSPARENCY-CHECKPOINT-SIGNATURE-V1\n${canonicalizeARVJsonV1(unsigned)}`, 'utf8');
}

export function sha256ARVVerifierAttestationTransparencyCheckpointV1(value: ARVVerifierAttestationTransparencyCheckpointV1): string {
  const checkpoint = assertARVVerifierAttestationTransparencyCheckpointV1(value);
  const { signatures: _signatures, ...unsigned } = checkpoint;
  return sha256Domain('ARV-VERIFIER-ATTESTATION-TRANSPARENCY-CHECKPOINT-V1', unsigned);
}

export function canonicalARVVerifierAttestationTransparencyMonitorObservationSigningBytesV1(value: ARVVerifierAttestationTransparencyMonitorObservationV1): Buffer {
  const observation = assertARVVerifierAttestationTransparencyMonitorObservationV1(value);
  const { signature_base64: _signature, ...unsigned } = observation;
  return Buffer.from(`ARV-VERIFIER-ATTESTATION-TRANSPARENCY-MONITOR-OBSERVATION-SIGNATURE-V1\n${canonicalizeARVJsonV1(unsigned)}`, 'utf8');
}

export function sha256ARVTransparencyLeafV1(entryHash: string): string {
  digest(entryHash, '$entry_hash');
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(entryHash, 'hex')])).digest('hex');
}

export function sha256ARVTransparencyNodeV1(left: string, right: string): string {
  digest(left, '$left'); digest(right, '$right');
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')])).digest('hex');
}

function largestPowerOfTwoLessThan(value: number): number {
  let result = 1;
  while ((result << 1) < value) result <<= 1;
  return result;
}

export function merkleRootARVTransparencyV1(entryHashes: string[]): string {
  if (!Array.isArray(entryHashes) || entryHashes.length === 0) throw new Error('$entry_hashes must be a non-empty array');
  entryHashes.forEach((item, index) => digest(item, `$entry_hashes[${index}]`));
  const tree = (items: string[]): string => {
    if (items.length === 1) return sha256ARVTransparencyLeafV1(items[0]);
    const split = largestPowerOfTwoLessThan(items.length);
    return sha256ARVTransparencyNodeV1(tree(items.slice(0, split)), tree(items.slice(split)));
  };
  return tree(entryHashes);
}

export function verifyARVTransparencyInclusionProofV1(leafHash: string, leafIndex: number, treeSize: number, proof: string[], expectedRoot: string): boolean {
  try {
    digest(leafHash, '$leaf_hash'); digest(expectedRoot, '$expected_root');
    nonNegative(leafIndex, '$leaf_index'); positive(treeSize, '$tree_size');
    if (leafIndex >= treeSize || !Array.isArray(proof)) return false;
    proof.forEach((item, index) => digest(item, `$proof[${index}]`));
    let fn = leafIndex;
    let sn = treeSize - 1;
    let root = leafHash;
    for (const sibling of proof) {
      if ((fn & 1) === 1 || fn === sn) {
        root = sha256ARVTransparencyNodeV1(sibling, root);
        while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
      } else {
        root = sha256ARVTransparencyNodeV1(root, sibling);
      }
      fn >>= 1; sn >>= 1;
    }
    return sn === 0 && root === expectedRoot;
  } catch { return false; }
}

export function verifyARVTransparencyConsistencyProofV1(oldSize: number, newSize: number, oldRoot: string, newRoot: string, proof: string[]): boolean {
  try {
    nonNegative(oldSize, '$old_size'); positive(newSize, '$new_size');
    digest(oldRoot, '$old_root'); digest(newRoot, '$new_root');
    if (oldSize > newSize || !Array.isArray(proof)) return false;
    proof.forEach((item, index) => digest(item, `$proof[${index}]`));
    if (oldSize === 0) return proof.length === 0;
    if (oldSize === newSize) return proof.length === 0 && oldRoot === newRoot;
    let fn = oldSize - 1;
    let sn = newSize - 1;
    while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
    let index = 0;
    let firstRoot: string;
    let secondRoot: string;
    if (fn === 0) {
      firstRoot = oldRoot; secondRoot = oldRoot;
    } else {
      if (proof.length === 0) return false;
      firstRoot = proof[0]; secondRoot = proof[0]; index = 1;
    }
    for (; index < proof.length; index += 1) {
      const node = proof[index];
      if ((fn & 1) === 1 || fn === sn) {
        firstRoot = sha256ARVTransparencyNodeV1(node, firstRoot);
        secondRoot = sha256ARVTransparencyNodeV1(node, secondRoot);
        while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
      } else {
        secondRoot = sha256ARVTransparencyNodeV1(secondRoot, node);
      }
      fn >>= 1; sn >>= 1;
    }
    return sn === 0 && firstRoot === oldRoot && secondRoot === newRoot;
  } catch { return false; }
}

function activeSigner(signer: ARVTransparencyPublicSignerV1, evaluatedAt: number): boolean {
  return signer.status === 'ACTIVE' && Date.parse(signer.valid_from) <= evaluatedAt && evaluatedAt < Date.parse(signer.expires_at);
}

function verifySignature(publicKeyBase64: string, bytes: Buffer, signatureBase64: string): boolean {
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(publicKeyBase64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, bytes, publicKey, Buffer.from(signatureBase64, 'base64'));
  } catch { return false; }
}

function verificationResult(
  state: ARVVerifierAttestationTransparencyStateV1,
  operation: ARVVerifierAttestationTransparencyOperationV1,
  codes: string[],
  hashes: Partial<Pick<ARVVerifierAttestationTransparencyVerificationV1, 'policy_hash'|'attestation_hash'|'security_event_chain_hash'|'entry_hash'|'leaf_hash'|'checkpoint_hash'|'current_checkpoint_hash'|'commit_precondition_hash'|'next_checkpoint_hash'>>,
  validOperatorSignatures = 0,
  validMonitorObservations = 0
): ARVVerifierAttestationTransparencyVerificationV1 {
  const accepted = ['BOOTSTRAP_ACCEPTED','UPDATE_ACCEPTED','REPLAY_ACCEPTED'].includes(state);
  return {
    schema: 'arv.verifier-attestation-transparency-verification', schema_version: 1,
    accepted, frozen: !accepted, state, operation,
    policy_hash: hashes.policy_hash ?? null,
    attestation_hash: hashes.attestation_hash ?? null,
    security_event_chain_hash: hashes.security_event_chain_hash ?? null,
    entry_hash: hashes.entry_hash ?? null,
    leaf_hash: hashes.leaf_hash ?? null,
    checkpoint_hash: hashes.checkpoint_hash ?? null,
    current_checkpoint_hash: hashes.current_checkpoint_hash ?? null,
    commit_precondition_hash: hashes.commit_precondition_hash ?? null,
    next_checkpoint_hash: accepted ? (hashes.next_checkpoint_hash ?? null) : null,
    valid_operator_signatures: validOperatorSignatures,
    valid_monitor_observations: validMonitorObservations,
    codes,
    runtime_evidence_authority: 'VERIFIED_ATTESTATION_AND_EVENT_CHAIN',
    transparency_authority: 'APPEND_ONLY_COMMITMENT_PROOFS',
    log_operator_authority: 'COMMITMENT_PUBLICATION_ONLY',
    monitor_authority: 'INDEPENDENT_OBSERVATION_ONLY',
    storage_authority: 'NONE', transport_authority: 'NONE', material_truth: 'NOT_EVALUATED'
  };
}

export function verifyARVVerifierAttestationTransparencyV1(options: VerifyARVVerifierAttestationTransparencyOptionsV1): ARVVerifierAttestationTransparencyVerificationV1 {
  const hashes: Parameters<typeof verificationResult>[3] = {};
  try { assertNoARVPrivateKeyMaterialV1(options); } catch { return verificationResult('PRIVATE_KEY_MATERIAL_FORBIDDEN','NONE',['PRIVATE_KEY_MATERIAL_FORBIDDEN'],hashes); }
  let policy: ARVVerifierAttestationTransparencyPolicyV1;
  try { policy = assertARVVerifierAttestationTransparencyPolicyV1(options.transparency_policy); hashes.policy_hash = sha256ARVVerifierAttestationTransparencyPolicyV1(policy); }
  catch { return verificationResult('POLICY_INVALID','NONE',['POLICY_INVALID'],hashes); }
  let attestation: ARVVerifierRuntimeAttestationV1;
  let chain: ARVVerifierSecurityEventChainV1;
  try {
    attestation = assertARVVerifierRuntimeAttestationV1(options.runtime_attestation);
    chain = assertARVVerifierSecurityEventChainV1(options.security_event_chain);
    hashes.attestation_hash = sha256ARVVerifierRuntimeAttestationV1(attestation);
    hashes.security_event_chain_hash = sha256ARVVerifierSecurityEventChainV1(chain);
  } catch { return verificationResult('ENTRY_BINDING_INVALID','NONE',['ATTESTATION_EVIDENCE_INVALID'],hashes); }
  let entry: ARVVerifierAttestationTransparencyEntryV1;
  try { entry = assertARVVerifierAttestationTransparencyEntryV1(options.transparency_entry); hashes.entry_hash = sha256ARVVerifierAttestationTransparencyEntryV1(entry); hashes.leaf_hash = sha256ARVTransparencyLeafV1(hashes.entry_hash); }
  catch { return verificationResult('ENTRY_INVALID','NONE',['ENTRY_INVALID'],hashes); }
  if (entry.log_id !== policy.log_id || entry.verifier_id !== attestation.verifier_id || entry.instance_id !== attestation.instance_id || entry.attestation_sequence !== attestation.attestation_sequence || entry.attestation_hash !== hashes.attestation_hash || entry.security_event_chain_hash !== hashes.security_event_chain_hash || chain.verifier_id !== attestation.verifier_id || chain.instance_id !== attestation.instance_id) {
    return verificationResult('ENTRY_BINDING_INVALID','NONE',['ATTESTATION_EVIDENCE_BINDING_INVALID'],hashes);
  }
  const commitment = evidenceCommitmentARVVerifierAttestationTransparencyV1(hashes.attestation_hash, hashes.security_event_chain_hash, entry.disclosure_digest);
  if (entry.evidence_commitment !== commitment) return verificationResult('EVIDENCE_COMMITMENT_INVALID','NONE',['EVIDENCE_COMMITMENT_INVALID'],hashes);
  let checkpoint: ARVVerifierAttestationTransparencyCheckpointV1;
  try { checkpoint = assertARVVerifierAttestationTransparencyCheckpointV1(options.transparency_checkpoint); hashes.checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(checkpoint); }
  catch { return verificationResult('CHECKPOINT_INVALID','NONE',['CHECKPOINT_INVALID'],hashes); }
  if (checkpoint.log_id !== policy.log_id || checkpoint.policy_id !== policy.policy_id || checkpoint.policy_version !== policy.policy_version || checkpoint.policy_hash !== hashes.policy_hash) return verificationResult('CHECKPOINT_BINDING_INVALID','NONE',['CHECKPOINT_POLICY_BINDING_INVALID'],hashes);
  let receipt: ARVVerifierAttestationTransparencyReceiptV1;
  try { receipt = assertARVVerifierAttestationTransparencyReceiptV1(options.transparency_receipt); }
  catch { return verificationResult('RECEIPT_INVALID','NONE',['RECEIPT_INVALID'],hashes); }
  if (receipt.log_id !== policy.log_id || receipt.entry_hash !== hashes.entry_hash || receipt.leaf_hash !== hashes.leaf_hash || receipt.leaf_index !== entry.leaf_index || receipt.tree_size !== checkpoint.tree_size || receipt.checkpoint_hash !== hashes.checkpoint_hash) return verificationResult('RECEIPT_BINDING_INVALID','NONE',['RECEIPT_BINDING_INVALID'],hashes);
  if (!verifyARVTransparencyInclusionProofV1(hashes.leaf_hash, receipt.leaf_index, receipt.tree_size, receipt.inclusion_path, checkpoint.root_hash)) return verificationResult('INCLUSION_PROOF_INVALID','NONE',['ENTRY_NOT_INCLUDED'],hashes);
  timestamp(options.evaluated_at, '$evaluated_at');
  const evaluatedAt = Date.parse(options.evaluated_at);
  const checkpointIssuedAt = Date.parse(checkpoint.issued_at);
  if (checkpointIssuedAt > evaluatedAt + policy.max_clock_skew_seconds * 1000 || evaluatedAt - checkpointIssuedAt > policy.max_checkpoint_age_seconds * 1000) return verificationResult('CHECKPOINT_TIME_INVALID','NONE',['CHECKPOINT_STALE_OR_FUTURE'],hashes);
  const checkpointBytes = canonicalARVVerifierAttestationTransparencyCheckpointSigningBytesV1(checkpoint);
  let validOperators = 0;
  for (const signature of checkpoint.signatures) {
    const signer = policy.operators.find((candidate) => candidate.key_id === signature.key_id);
    if (signer && activeSigner(signer, evaluatedAt) && verifySignature(signer.public_key_spki_base64, checkpointBytes, signature.signature_base64)) validOperators += 1;
  }
  if (validOperators < policy.operator_threshold) return verificationResult('LOG_OPERATOR_QUORUM_NOT_MET','NONE',['LOG_OPERATOR_QUORUM_NOT_MET'],hashes,validOperators);
  if (!Array.isArray(options.monitor_observations)) return verificationResult('MONITOR_OBSERVATION_INVALID','NONE',['MONITOR_OBSERVATIONS_INVALID'],hashes,validOperators);
  const observations: ARVVerifierAttestationTransparencyMonitorObservationV1[] = [];
  try { options.monitor_observations.forEach((item) => observations.push(assertARVVerifierAttestationTransparencyMonitorObservationV1(item))); }
  catch { return verificationResult('MONITOR_OBSERVATION_INVALID','NONE',['MONITOR_OBSERVATION_INVALID'],hashes,validOperators); }
  const validByMonitor = new Map<string, ARVVerifierAttestationTransparencyMonitorObservationV1[]>();
  for (const observation of observations) {
    const monitor = policy.monitors.find((candidate) => candidate.signer_id === observation.monitor_id && candidate.key_id === observation.key_id);
    if (!monitor || !activeSigner(monitor, evaluatedAt)) continue;
    if (Date.parse(observation.observed_at) > evaluatedAt + policy.max_clock_skew_seconds * 1000) continue;
    if (!verifySignature(monitor.public_key_spki_base64, canonicalARVVerifierAttestationTransparencyMonitorObservationSigningBytesV1(observation), observation.signature_base64)) continue;
    const group = validByMonitor.get(observation.monitor_id) ?? [];
    group.push(observation); validByMonitor.set(observation.monitor_id, group);
  }
  let splitView = false;
  let validMonitors = 0;
  for (const group of Array.from(validByMonitor.values())) {
    const views = new Set(group.map((item) => `${item.log_id}|${item.checkpoint_sequence}|${item.tree_size}|${item.root_hash}|${item.checkpoint_hash}`));
    if (views.size > 1) splitView = true;
    const matching = group.some((item) => item.log_id === checkpoint.log_id && item.checkpoint_sequence === checkpoint.checkpoint_sequence && item.tree_size === checkpoint.tree_size && item.root_hash === checkpoint.root_hash && item.checkpoint_hash === hashes.checkpoint_hash);
    const conflicting = group.some((item) => item.log_id === checkpoint.log_id && item.checkpoint_sequence === checkpoint.checkpoint_sequence && (item.tree_size !== checkpoint.tree_size || item.root_hash !== checkpoint.root_hash || item.checkpoint_hash !== hashes.checkpoint_hash));
    if (conflicting) splitView = true;
    if (matching) validMonitors += 1;
  }
  if (splitView) return verificationResult('MONITOR_SPLIT_VIEW','NONE',['SPLIT_VIEW_DETECTED'],hashes,validOperators,validMonitors);
  if (validMonitors < policy.monitor_threshold) return verificationResult('MONITOR_QUORUM_NOT_MET','NONE',['MONITOR_QUORUM_NOT_MET'],hashes,validOperators,validMonitors);
  if (options.current_checkpoint === null) {
    if (options.expected_current_checkpoint_hash !== null || receipt.prior_tree_size !== 0 || receipt.prior_checkpoint_hash !== null || receipt.consistency_path.length !== 0 || checkpoint.previous_checkpoint_hash !== null) return verificationResult('CURRENT_CHECKPOINT_INVALID','NONE',['BOOTSTRAP_STATE_INVALID'],hashes,validOperators,validMonitors);
    if (options.bootstrap_policy_hash === null) return verificationResult('POLICY_PIN_REQUIRED','NONE',['BOOTSTRAP_POLICY_PIN_REQUIRED'],hashes,validOperators,validMonitors);
    if (options.bootstrap_policy_hash !== hashes.policy_hash) return verificationResult('POLICY_PIN_MISMATCH','NONE',['BOOTSTRAP_POLICY_PIN_MISMATCH'],hashes,validOperators,validMonitors);
    hashes.commit_precondition_hash = hashes.policy_hash;
    hashes.next_checkpoint_hash = hashes.checkpoint_hash;
    return verificationResult('BOOTSTRAP_ACCEPTED','BOOTSTRAP',['TRANSPARENCY_BOOTSTRAP_ACCEPTED'],hashes,validOperators,validMonitors);
  }
  let current: ARVVerifierAttestationTransparencyCheckpointV1;
  try { current = assertARVVerifierAttestationTransparencyCheckpointV1(options.current_checkpoint); hashes.current_checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(current); }
  catch { return verificationResult('CURRENT_CHECKPOINT_INVALID','NONE',['CURRENT_CHECKPOINT_INVALID'],hashes,validOperators,validMonitors); }
  if (options.expected_current_checkpoint_hash === null) return verificationResult('CURRENT_CHECKPOINT_HASH_REQUIRED','NONE',['COMPARE_AND_SWAP_HASH_REQUIRED'],hashes,validOperators,validMonitors);
  if (options.expected_current_checkpoint_hash !== hashes.current_checkpoint_hash) return verificationResult('CURRENT_CHECKPOINT_HASH_MISMATCH','NONE',['COMPARE_AND_SWAP_HASH_MISMATCH'],hashes,validOperators,validMonitors);
  hashes.commit_precondition_hash = hashes.current_checkpoint_hash;
  if (current.log_id !== checkpoint.log_id || receipt.prior_tree_size !== current.tree_size || receipt.prior_checkpoint_hash !== hashes.current_checkpoint_hash || checkpoint.previous_checkpoint_hash !== hashes.current_checkpoint_hash) return verificationResult('CHECKPOINT_GAP','NONE',['CHECKPOINT_LINKAGE_GAP'],hashes,validOperators,validMonitors);
  if (checkpoint.checkpoint_sequence < current.checkpoint_sequence || checkpoint.tree_size < current.tree_size) return verificationResult('CHECKPOINT_ROLLBACK','NONE',['CHECKPOINT_ROLLBACK'],hashes,validOperators,validMonitors);
  if (checkpoint.checkpoint_sequence === current.checkpoint_sequence || checkpoint.tree_size === current.tree_size) {
    if (hashes.checkpoint_hash === hashes.current_checkpoint_hash && checkpoint.root_hash === current.root_hash && receipt.consistency_path.length === 0) {
      hashes.next_checkpoint_hash = hashes.current_checkpoint_hash;
      return verificationResult('REPLAY_ACCEPTED','REPLAY',['CHECKPOINT_REPLAY_ACCEPTED'],hashes,validOperators,validMonitors);
    }
    return verificationResult('CHECKPOINT_EQUIVOCATION','NONE',['SAME_POSITION_DIFFERENT_CHECKPOINT'],hashes,validOperators,validMonitors);
  }
  if (checkpoint.checkpoint_sequence !== current.checkpoint_sequence + 1) return verificationResult('CHECKPOINT_GAP','NONE',['CHECKPOINT_SEQUENCE_GAP'],hashes,validOperators,validMonitors);
  if (!verifyARVTransparencyConsistencyProofV1(current.tree_size, checkpoint.tree_size, current.root_hash, checkpoint.root_hash, receipt.consistency_path)) return verificationResult('CONSISTENCY_PROOF_INVALID','NONE',['APPEND_ONLY_CONSISTENCY_NOT_PROVEN'],hashes,validOperators,validMonitors);
  hashes.next_checkpoint_hash = hashes.checkpoint_hash;
  return verificationResult('UPDATE_ACCEPTED','UPDATE',['TRANSPARENCY_UPDATE_ACCEPTED'],hashes,validOperators,validMonitors);
}
