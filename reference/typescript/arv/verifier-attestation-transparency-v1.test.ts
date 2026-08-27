import crypto from 'crypto';
import {
  ARVVerifierRuntimeAttestationV1,
  ARVVerifierSecurityEventChainV1,
  ARVVerifierSecurityEventV1,
  sha256ARVVerifierRuntimeAttestationV1,
  sha256ARVVerifierSecurityEventChainV1
} from './verifier-runtime-attestation-v1';
import {
  ARVTransparencyPublicSignerV1,
  ARVVerifierAttestationTransparencyCheckpointV1,
  ARVVerifierAttestationTransparencyEntryV1,
  ARVVerifierAttestationTransparencyMonitorObservationV1,
  ARVVerifierAttestationTransparencyPolicyV1,
  ARVVerifierAttestationTransparencyReceiptV1,
  VerifyARVVerifierAttestationTransparencyOptionsV1,
  assertARVVerifierAttestationTransparencyCheckpointV1,
  assertARVVerifierAttestationTransparencyEntryV1,
  assertARVVerifierAttestationTransparencyMonitorObservationV1,
  assertARVVerifierAttestationTransparencyPolicyV1,
  assertARVVerifierAttestationTransparencyReceiptV1,
  canonicalARVVerifierAttestationTransparencyCheckpointSigningBytesV1,
  canonicalARVVerifierAttestationTransparencyMonitorObservationSigningBytesV1,
  evidenceCommitmentARVVerifierAttestationTransparencyV1,
  merkleRootARVTransparencyV1,
  sha256ARVTransparencyLeafV1,
  sha256ARVTransparencyNodeV1,
  sha256ARVVerifierAttestationTransparencyCheckpointV1,
  sha256ARVVerifierAttestationTransparencyEntryV1,
  sha256ARVVerifierAttestationTransparencyPolicyV1,
  verifyARVTransparencyConsistencyProofV1,
  verifyARVTransparencyInclusionProofV1,
  verifyARVVerifierAttestationTransparencyV1
} from './verifier-attestation-transparency-v1';

const digest = (value: string) => value.repeat(64).slice(0, 64);
const emptySignature = Buffer.alloc(64).toString('base64');

interface Fixture {
  policy: ARVVerifierAttestationTransparencyPolicyV1;
  attestation: ARVVerifierRuntimeAttestationV1;
  chain: ARVVerifierSecurityEventChainV1;
  entry: ARVVerifierAttestationTransparencyEntryV1;
  checkpoint: ARVVerifierAttestationTransparencyCheckpointV1;
  receipt: ARVVerifierAttestationTransparencyReceiptV1;
  observations: ARVVerifierAttestationTransparencyMonitorObservationV1[];
  options: VerifyARVVerifierAttestationTransparencyOptionsV1;
  operatorPrivateKeys: crypto.KeyObject[];
  monitorPrivateKeys: crypto.KeyObject[];
}

function makeSigner(id: string, keyId: string, privateKeys: crypto.KeyObject[]): ARVTransparencyPublicSignerV1 {
  const pair = crypto.generateKeyPairSync('ed25519');
  privateKeys.push(pair.privateKey);
  return {
    signer_id: id,
    key_id: keyId,
    algorithm: 'Ed25519',
    public_key_spki_base64: (pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64'),
    status: 'ACTIVE',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2028-01-01T00:00:00Z'
  };
}

function signCheckpoint(checkpoint: ARVVerifierAttestationTransparencyCheckpointV1, policy: ARVVerifierAttestationTransparencyPolicyV1, keys: crypto.KeyObject[]): void {
  checkpoint.signatures = policy.operators.map((operator, index) => ({
    algorithm: 'Ed25519',
    key_id: operator.key_id,
    signature_base64: crypto.sign(null, canonicalARVVerifierAttestationTransparencyCheckpointSigningBytesV1({ ...checkpoint, signatures: [{ algorithm: 'Ed25519', key_id: operator.key_id, signature_base64: emptySignature }] }), keys[index]).toString('base64')
  }));
}

function signObservation(observation: ARVVerifierAttestationTransparencyMonitorObservationV1, key: crypto.KeyObject): void {
  observation.signature_base64 = crypto.sign(null, canonicalARVVerifierAttestationTransparencyMonitorObservationSigningBytesV1({ ...observation, signature_base64: emptySignature }), key).toString('base64');
}

function largestPower(value: number): number {
  let result = 1;
  while ((result << 1) < value) result <<= 1;
  return result;
}

function root(entryHashes: string[]): string {
  if (entryHashes.length === 1) return sha256ARVTransparencyLeafV1(entryHashes[0]);
  const split = largestPower(entryHashes.length);
  return sha256ARVTransparencyNodeV1(root(entryHashes.slice(0, split)), root(entryHashes.slice(split)));
}

function inclusionPath(index: number, entryHashes: string[]): string[] {
  if (entryHashes.length === 1) return [];
  const split = largestPower(entryHashes.length);
  if (index < split) return [...inclusionPath(index, entryHashes.slice(0, split)), root(entryHashes.slice(split))];
  return [...inclusionPath(index - split, entryHashes.slice(split)), root(entryHashes.slice(0, split))];
}

function consistencySubproof(oldSize: number, entryHashes: string[], complete: boolean): string[] {
  if (oldSize === entryHashes.length) return complete ? [] : [root(entryHashes)];
  const split = largestPower(entryHashes.length);
  if (oldSize <= split) return [...consistencySubproof(oldSize, entryHashes.slice(0, split), complete), root(entryHashes.slice(split))];
  return [...consistencySubproof(oldSize - split, entryHashes.slice(split), false), root(entryHashes.slice(0, split))];
}

function consistencyPath(oldSize: number, entryHashes: string[]): string[] {
  return consistencySubproof(oldSize, entryHashes, true);
}

function fixture(): Fixture {
  const operatorPrivateKeys: crypto.KeyObject[] = [];
  const monitorPrivateKeys: crypto.KeyObject[] = [];
  const operators = [
    makeSigner('ARV-TRANSPARENCY-LOG-OPERATOR-1', '111111111111111111111111', operatorPrivateKeys),
    makeSigner('ARV-TRANSPARENCY-LOG-OPERATOR-2', '222222222222222222222222', operatorPrivateKeys)
  ];
  const monitors = [
    makeSigner('ARV-TRANSPARENCY-MONITOR-1', '333333333333333333333333', monitorPrivateKeys),
    makeSigner('ARV-TRANSPARENCY-MONITOR-2', '444444444444444444444444', monitorPrivateKeys)
  ];
  const policy: ARVVerifierAttestationTransparencyPolicyV1 = {
    schema: 'arv.verifier-attestation-transparency-policy', schema_version: 1,
    policy_id: 'ARV-ATTESTATION-TRANSPARENCY-POLICY-PROD',
    log_id: 'ARV-ATTESTATION-TRANSPARENCY-LOG-PROD', policy_version: 1,
    root_id: 'ARV-ROOT-PROD', root_version: 1, root_epoch: 1, root_hash: digest('a'),
    operator_threshold: 2, monitor_threshold: 2, max_checkpoint_age_seconds: 3600, max_clock_skew_seconds: 30,
    operators, monitors, issued_at: '2026-01-01T00:00:00Z'
  };
  const event: ARVVerifierSecurityEventV1 = {
    schema: 'arv.verifier-security-event', schema_version: 1,
    event_id: 'ARV-VERIFIER-SECURITY-EVENT-NODE-1', verifier_id: 'ARV-VERIFIER-PROD',
    instance_id: 'ARV-VERIFIER-INSTANCE-NODE-1', event_sequence: 1, event_type: 'BOOT', severity: 'INFO',
    activation_pin_hash: digest('b'), runtime_measurement_hash: digest('c'), details_digest: digest('d'),
    observed_at: '2026-02-01T00:00:30Z', previous_event_hash: null
  };
  const chain: ARVVerifierSecurityEventChainV1 = {
    schema: 'arv.verifier-security-event-chain', schema_version: 1,
    chain_id: 'ARV-VERIFIER-SECURITY-EVENT-CHAIN-NODE-1', verifier_id: event.verifier_id,
    instance_id: event.instance_id, first_event_sequence: 1, last_event_sequence: 1,
    previous_chain_hash: null, events: [event], closed_at: '2026-02-01T00:00:40Z'
  };
  const attestation: ARVVerifierRuntimeAttestationV1 = {
    schema: 'arv.verifier-runtime-attestation', schema_version: 1,
    attestation_id: 'ARV-VERIFIER-RUNTIME-ATTESTATION-NODE-1', verifier_id: event.verifier_id,
    instance_id: event.instance_id, attestation_sequence: 1, activation_sequence: 1,
    release_manifest_hash: digest('e'), activation_pin_hash: event.activation_pin_hash,
    runtime_measurement_hash: event.runtime_measurement_hash,
    security_event_chain_hash: sha256ARVVerifierSecurityEventChainV1(chain), challenge_nonce: 'ab'.repeat(32),
    policy_id: 'ARV-VERIFIER-RUNTIME-ATTESTATION-POLICY-PROD', policy_version: 1, policy_hash: digest('f'),
    root_id: policy.root_id, root_version: policy.root_version, root_epoch: policy.root_epoch, root_hash: policy.root_hash,
    issued_at: '2026-02-01T00:00:50Z', expires_at: '2026-02-01T00:05:50Z', previous_attestation_hash: null,
    signatures: [{ algorithm: 'Ed25519', key_id: '555555555555555555555555', signature_base64: emptySignature }]
  };
  const attestationHash = sha256ARVVerifierRuntimeAttestationV1(attestation);
  const chainHash = sha256ARVVerifierSecurityEventChainV1(chain);
  const disclosureDigest = digest('6');
  const entry: ARVVerifierAttestationTransparencyEntryV1 = {
    schema: 'arv.verifier-attestation-transparency-entry', schema_version: 1,
    entry_id: 'ARV-ATTESTATION-TRANSPARENCY-ENTRY-1', log_id: policy.log_id, leaf_index: 0,
    verifier_id: attestation.verifier_id, instance_id: attestation.instance_id,
    attestation_sequence: attestation.attestation_sequence, attestation_hash: attestationHash,
    security_event_chain_hash: chainHash, disclosure_digest: disclosureDigest,
    evidence_commitment: evidenceCommitmentARVVerifierAttestationTransparencyV1(attestationHash, chainHash, disclosureDigest),
    submitted_at: '2026-02-01T00:01:00Z'
  };
  const entryHash = sha256ARVVerifierAttestationTransparencyEntryV1(entry);
  const leafHash = sha256ARVTransparencyLeafV1(entryHash);
  const policyHash = sha256ARVVerifierAttestationTransparencyPolicyV1(policy);
  const checkpoint: ARVVerifierAttestationTransparencyCheckpointV1 = {
    schema: 'arv.verifier-attestation-transparency-checkpoint', schema_version: 1,
    checkpoint_id: 'ARV-ATTESTATION-TRANSPARENCY-CHECKPOINT-1', log_id: policy.log_id,
    checkpoint_sequence: 1, tree_size: 1, root_hash: leafHash,
    policy_id: policy.policy_id, policy_version: policy.policy_version, policy_hash: policyHash,
    issued_at: '2026-02-01T00:01:10Z', previous_checkpoint_hash: null, signatures: []
  };
  signCheckpoint(checkpoint, policy, operatorPrivateKeys);
  const checkpointHash = sha256ARVVerifierAttestationTransparencyCheckpointV1(checkpoint);
  const receipt: ARVVerifierAttestationTransparencyReceiptV1 = {
    schema: 'arv.verifier-attestation-transparency-receipt', schema_version: 1,
    receipt_id: 'ARV-ATTESTATION-TRANSPARENCY-RECEIPT-1', log_id: policy.log_id,
    entry_hash: entryHash, leaf_hash: leafHash, leaf_index: 0, tree_size: 1,
    checkpoint_hash: checkpointHash, prior_tree_size: 0, prior_checkpoint_hash: null,
    inclusion_path: [], consistency_path: []
  };
  const observations = monitors.map((monitor, index) => {
    const observation: ARVVerifierAttestationTransparencyMonitorObservationV1 = {
      schema: 'arv.verifier-attestation-transparency-monitor-observation', schema_version: 1,
      observation_id: `ARV-ATTESTATION-TRANSPARENCY-OBSERVATION-${index + 1}`,
      monitor_id: monitor.signer_id, key_id: monitor.key_id, log_id: checkpoint.log_id,
      checkpoint_sequence: checkpoint.checkpoint_sequence, tree_size: checkpoint.tree_size,
      root_hash: checkpoint.root_hash, checkpoint_hash: checkpointHash,
      observed_at: '2026-02-01T00:01:20Z', signature_base64: emptySignature
    };
    signObservation(observation, monitorPrivateKeys[index]);
    return observation;
  });
  const options: VerifyARVVerifierAttestationTransparencyOptionsV1 = {
    transparency_policy: policy, runtime_attestation: attestation, security_event_chain: chain,
    transparency_entry: entry, transparency_checkpoint: checkpoint, transparency_receipt: receipt,
    monitor_observations: observations, current_checkpoint: null, expected_current_checkpoint_hash: null,
    bootstrap_policy_hash: policyHash, evaluated_at: '2026-02-01T00:01:30Z'
  };
  return { policy, attestation, chain, entry, checkpoint, receipt, observations, options, operatorPrivateKeys, monitorPrivateKeys };
}

function updateFixture(value: Fixture): void {
  const current = structuredClone(value.checkpoint);
  const firstHash = sha256ARVVerifierAttestationTransparencyEntryV1(value.entry);
  const hashes = [firstHash, digest('7'), digest('8')];
  value.checkpoint.checkpoint_id = 'ARV-ATTESTATION-TRANSPARENCY-CHECKPOINT-2';
  value.checkpoint.checkpoint_sequence = 2;
  value.checkpoint.tree_size = hashes.length;
  value.checkpoint.root_hash = merkleRootARVTransparencyV1(hashes);
  value.checkpoint.previous_checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(current);
  value.checkpoint.issued_at = '2026-02-01T00:02:00Z';
  signCheckpoint(value.checkpoint, value.policy, value.operatorPrivateKeys);
  const checkpointHash = sha256ARVVerifierAttestationTransparencyCheckpointV1(value.checkpoint);
  value.receipt.tree_size = hashes.length;
  value.receipt.checkpoint_hash = checkpointHash;
  value.receipt.prior_tree_size = current.tree_size;
  value.receipt.prior_checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(current);
  value.receipt.inclusion_path = inclusionPath(0, hashes);
  value.receipt.consistency_path = consistencyPath(current.tree_size, hashes);
  value.observations.forEach((observation, index) => {
    observation.observation_id = `ARV-ATTESTATION-TRANSPARENCY-OBSERVATION-UPDATE-${index + 1}`;
    observation.checkpoint_sequence = value.checkpoint.checkpoint_sequence;
    observation.tree_size = value.checkpoint.tree_size;
    observation.root_hash = value.checkpoint.root_hash;
    observation.checkpoint_hash = checkpointHash;
    observation.observed_at = '2026-02-01T00:02:10Z';
    signObservation(observation, value.monitorPrivateKeys[index]);
  });
  value.options.current_checkpoint = current;
  value.options.expected_current_checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(current);
  value.options.bootstrap_policy_hash = null;
  value.options.evaluated_at = '2026-02-01T00:02:20Z';
}

describe('ARV Public transparency receipts and independent monitoring', () => {
  test('strict assertions and deterministic hashes accept canonical values', () => {
    const value = fixture();
    expect(assertARVVerifierAttestationTransparencyPolicyV1(value.policy)).toEqual(value.policy);
    expect(assertARVVerifierAttestationTransparencyEntryV1(value.entry)).toEqual(value.entry);
    expect(assertARVVerifierAttestationTransparencyCheckpointV1(value.checkpoint)).toEqual(value.checkpoint);
    expect(assertARVVerifierAttestationTransparencyReceiptV1(value.receipt)).toEqual(value.receipt);
    expect(assertARVVerifierAttestationTransparencyMonitorObservationV1(value.observations[0])).toEqual(value.observations[0]);
    expect(sha256ARVVerifierAttestationTransparencyPolicyV1(value.policy)).toMatch(/^[a-f0-9]{64}$/);
  });

  test('rejects unexpected fields and private key material', () => {
    const value = fixture();
    expect(() => assertARVVerifierAttestationTransparencyEntryV1({ ...value.entry, raw_telemetry: {} })).toThrow();
    expect(() => assertARVVerifierAttestationTransparencyPolicyV1({ ...value.policy, private_key: 'forbidden' })).toThrow();
  });

  test('verifies deterministic Merkle inclusion and consistency proofs', () => {
    const hashes = [digest('1'), digest('2'), digest('3'), digest('4'), digest('5')];
    const rootHash = root(hashes);
    const leafHash = sha256ARVTransparencyLeafV1(hashes[3]);
    expect(verifyARVTransparencyInclusionProofV1(leafHash, 3, hashes.length, inclusionPath(3, hashes), rootHash)).toBe(true);
    const oldRoot = root(hashes.slice(0, 3));
    expect(verifyARVTransparencyConsistencyProofV1(3, 5, oldRoot, rootHash, consistencyPath(3, hashes))).toBe(true);
    expect(verifyARVTransparencyConsistencyProofV1(3, 5, oldRoot, rootHash, [digest('f')])).toBe(false);
  });

  test('accepts explicitly pinned bootstrap with operator and monitor quorums', () => {
    const value = fixture();
    const result = verifyARVVerifierAttestationTransparencyV1(value.options);
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('BOOTSTRAP_ACCEPTED');
    expect(result.valid_operator_signatures).toBe(2);
    expect(result.valid_monitor_observations).toBe(2);
    expect(result.next_checkpoint_hash).toBe(sha256ARVVerifierAttestationTransparencyCheckpointV1(value.checkpoint));
  });

  test('accepts append-only update with inclusion and consistency proofs', () => {
    const value = fixture();
    updateFixture(value);
    const result = verifyARVVerifierAttestationTransparencyV1(value.options);
    expect(result.accepted).toBe(true);
    expect(result.operation).toBe('UPDATE');
    expect(result.state).toBe('UPDATE_ACCEPTED');
  });

  test('fails closed when evidence commitment or inclusion proof is invalid', () => {
    const value = fixture();
    value.entry.evidence_commitment = digest('f');
    expect(verifyARVVerifierAttestationTransparencyV1(value.options).state).toBe('EVIDENCE_COMMITMENT_INVALID');
    const second = fixture();
    second.receipt.leaf_hash = digest('f');
    expect(verifyARVVerifierAttestationTransparencyV1(second.options).state).toBe('RECEIPT_BINDING_INVALID');
  });

  test('requires threshold signatures from authorized log operators', () => {
    const value = fixture();
    value.checkpoint.signatures = value.checkpoint.signatures.slice(0, 1);
    value.receipt.checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(value.checkpoint);
    value.observations.forEach((observation, index) => {
      observation.checkpoint_hash = value.receipt.checkpoint_hash;
      signObservation(observation, value.monitorPrivateKeys[index]);
    });
    expect(verifyARVVerifierAttestationTransparencyV1(value.options).state).toBe('LOG_OPERATOR_QUORUM_NOT_MET');
  });

  test('requires independent monitor quorum', () => {
    const value = fixture();
    value.options.monitor_observations = value.observations.slice(0, 1);
    expect(verifyARVVerifierAttestationTransparencyV1(value.options).state).toBe('MONITOR_QUORUM_NOT_MET');
  });

  test('detects a validly signed monitor split view', () => {
    const value = fixture();
    const conflict = structuredClone(value.observations[0]);
    conflict.observation_id = 'ARV-ATTESTATION-TRANSPARENCY-OBSERVATION-CONFLICT';
    conflict.root_hash = digest('f');
    conflict.checkpoint_hash = digest('e');
    signObservation(conflict, value.monitorPrivateKeys[0]);
    value.options.monitor_observations = [...value.observations, conflict];
    expect(verifyARVVerifierAttestationTransparencyV1(value.options).state).toBe('MONITOR_SPLIT_VIEW');
  });

  test('rejects compare-and-swap mismatch, rollback and checkpoint gaps', () => {
    const mismatch = fixture(); updateFixture(mismatch);
    mismatch.options.expected_current_checkpoint_hash = digest('f');
    expect(verifyARVVerifierAttestationTransparencyV1(mismatch.options).state).toBe('CURRENT_CHECKPOINT_HASH_MISMATCH');

    const rollback = fixture(); updateFixture(rollback);
    const rollbackCurrent = structuredClone(rollback.checkpoint);
    const rollbackCurrentHash = sha256ARVVerifierAttestationTransparencyCheckpointV1(rollbackCurrent);
    rollback.options.current_checkpoint = rollbackCurrent;
    rollback.options.expected_current_checkpoint_hash = rollbackCurrentHash;
    rollback.checkpoint.checkpoint_sequence = 1;
    rollback.checkpoint.tree_size = 1;
    rollback.checkpoint.root_hash = sha256ARVTransparencyLeafV1(sha256ARVVerifierAttestationTransparencyEntryV1(rollback.entry));
    rollback.checkpoint.previous_checkpoint_hash = rollbackCurrentHash;
    signCheckpoint(rollback.checkpoint, rollback.policy, rollback.operatorPrivateKeys);
    rollback.receipt.tree_size = 1;
    rollback.receipt.checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(rollback.checkpoint);
    rollback.receipt.prior_tree_size = rollbackCurrent.tree_size;
    rollback.receipt.prior_checkpoint_hash = rollbackCurrentHash;
    rollback.receipt.inclusion_path = [];
    rollback.observations.forEach((observation, index) => {
      observation.checkpoint_sequence = 1; observation.tree_size = 1; observation.root_hash = rollback.checkpoint.root_hash;
      observation.checkpoint_hash = rollback.receipt.checkpoint_hash; signObservation(observation, rollback.monitorPrivateKeys[index]);
    });
    expect(verifyARVVerifierAttestationTransparencyV1(rollback.options).state).toBe('CHECKPOINT_ROLLBACK');

    const gap = fixture(); updateFixture(gap);
    gap.checkpoint.checkpoint_sequence = 3;
    signCheckpoint(gap.checkpoint, gap.policy, gap.operatorPrivateKeys);
    gap.receipt.checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(gap.checkpoint);
    gap.observations.forEach((observation, index) => {
      observation.checkpoint_sequence = 3; observation.checkpoint_hash = gap.receipt.checkpoint_hash;
      signObservation(observation, gap.monitorPrivateKeys[index]);
    });
    expect(verifyARVVerifierAttestationTransparencyV1(gap.options).state).toBe('CHECKPOINT_GAP');
  });

  test('rejects invalid consistency proof and same-position equivocation', () => {
    const invalid = fixture(); updateFixture(invalid);
    invalid.receipt.consistency_path = [digest('f')];
    expect(verifyARVVerifierAttestationTransparencyV1(invalid.options).state).toBe('CONSISTENCY_PROOF_INVALID');

    const equivocation = fixture(); updateFixture(equivocation);
    const current = equivocation.options.current_checkpoint as ARVVerifierAttestationTransparencyCheckpointV1;
    const currentHash = sha256ARVVerifierAttestationTransparencyCheckpointV1(current);
    equivocation.checkpoint.checkpoint_sequence = current.checkpoint_sequence;
    equivocation.checkpoint.tree_size = current.tree_size;
    equivocation.checkpoint.root_hash = current.root_hash;
    equivocation.checkpoint.previous_checkpoint_hash = currentHash;
    signCheckpoint(equivocation.checkpoint, equivocation.policy, equivocation.operatorPrivateKeys);
    equivocation.receipt.tree_size = current.tree_size;
    equivocation.receipt.checkpoint_hash = sha256ARVVerifierAttestationTransparencyCheckpointV1(equivocation.checkpoint);
    equivocation.receipt.prior_tree_size = current.tree_size;
    equivocation.receipt.prior_checkpoint_hash = currentHash;
    equivocation.receipt.inclusion_path = [];
    equivocation.receipt.consistency_path = [];
    equivocation.observations.forEach((observation, index) => {
      observation.checkpoint_sequence = current.checkpoint_sequence; observation.tree_size = current.tree_size;
      observation.root_hash = equivocation.checkpoint.root_hash; observation.checkpoint_hash = equivocation.receipt.checkpoint_hash;
      signObservation(observation, equivocation.monitorPrivateKeys[index]);
    });
    expect(verifyARVVerifierAttestationTransparencyV1(equivocation.options).state).toBe('CHECKPOINT_EQUIVOCATION');
  });

  test('keeps operators, monitors, storage and transport outside authority', () => {
    const result = verifyARVVerifierAttestationTransparencyV1(fixture().options);
    expect(result.log_operator_authority).toBe('COMMITMENT_PUBLICATION_ONLY');
    expect(result.monitor_authority).toBe('INDEPENDENT_OBSERVATION_ONLY');
    expect(result.storage_authority).toBe('NONE');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });
});
