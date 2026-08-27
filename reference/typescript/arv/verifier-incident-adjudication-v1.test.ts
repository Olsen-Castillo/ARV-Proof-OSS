import crypto from 'crypto';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import {
  ARV_VERIFIER_INCIDENT_CASE_SCHEMA,
  ARV_VERIFIER_INCIDENT_DECISION_SCHEMA,
  ARV_VERIFIER_INCIDENT_POLICY_SCHEMA,
  ARV_VERIFIER_INCIDENT_RECOVERY_AUTHORIZATION_SCHEMA,
  ARVVerifierIncidentAdjudicationDecisionV1,
  ARVVerifierIncidentAdjudicationPolicyV1,
  ARVVerifierIncidentCaseV1,
  ARVVerifierIncidentRecoveryAuthorizationV1,
  ARVVerifierQuarantineStateV1,
  canonicalARVVerifierIncidentDecisionSigningBytesV1,
  canonicalARVVerifierIncidentRecoverySigningBytesV1,
  sha256ARVVerifierIncidentAdjudicationPolicyV1,
  sha256ARVVerifierIncidentCaseV1,
  sha256ARVVerifierQuarantineStateV1,
  sha256ARVVerifierTransparencyVerificationForIncidentV1,
  verifyARVVerifierIncidentAdjudicationV1
} from './verifier-incident-adjudication-v1';
import {
  ARVTrustRootV1,
  fingerprintARVTrustRootPublicKeyV1,
  sha256ARVTrustRootV1
} from './trust-root-lifecycle-v1';
import { ARVVerifierAttestationTransparencyVerificationV1 } from './verifier-attestation-transparency-v1';

const d = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const placeholder = Buffer.alloc(64).toString('base64');

function material() {
  const adjudicators = ['A','B','C'].map((name) => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    return {
      name,
      key_id: d(`adjudicator-${name}`).slice(0,24),
      publicDer,
      privateKey: pair.privateKey
    };
  });
  const recoveryKeys = [nacl.sign.keyPair(), nacl.sign.keyPair()];
  const root: ARVTrustRootV1 = {
    schema: 'arv.trust-root', schema_version: 1, root_id: 'ARV-ROOT-TEST', root_version: 1, epoch: 1,
    issued_at: '2026-01-01T00:00:00Z', valid_from: '2026-01-01T00:00:00Z', expires_at: '2030-01-01T00:00:00Z',
    threshold: 2, recovery_threshold: 2, previous_root_hash: null, policy_digest: d('root-policy'),
    keys: recoveryKeys.map((pair) => ({
      key_id: fingerprintARVTrustRootPublicKeyV1(pair.publicKey), algorithm: 'Ed25519' as const,
      public_key_base64: encodeBase64(pair.publicKey), roles: ['ROOT','RECOVERY'] as ('ROOT'|'RECOVERY')[],
      status: 'ACTIVE' as const, valid_from: '2026-01-01T00:00:00Z', valid_until: '2030-01-01T00:00:00Z'
    }))
  };
  const policy: ARVVerifierIncidentAdjudicationPolicyV1 = {
    schema: ARV_VERIFIER_INCIDENT_POLICY_SCHEMA, schema_version: 1,
    policy_id: 'ARV-INCIDENT-ADJUDICATION-POLICY-TEST', policy_version: 1,
    root_id: root.root_id, root_version: root.root_version, root_epoch: root.epoch, root_hash: sha256ARVTrustRootV1(root),
    adjudication_threshold: 2, dismissal_threshold: 3, recovery_threshold: 2,
    max_decision_age_seconds: 3600, max_clock_skew_seconds: 60,
    adjudicators: adjudicators.map((item) => ({
      adjudicator_id: `ARV-ADJUDICATOR-${item.name}`, key_id: item.key_id, algorithm: 'Ed25519',
      public_key_spki_base64: item.publicDer.toString('base64'), status: 'ACTIVE',
      valid_from: '2026-01-01T00:00:00Z', expires_at: '2030-01-01T00:00:00Z'
    })), issued_at: '2026-01-01T00:00:00Z'
  };
  const transparency: ARVVerifierAttestationTransparencyVerificationV1 = {
    schema: 'arv.verifier-attestation-transparency-verification', schema_version: 1,
    accepted: false, frozen: true, state: 'MONITOR_SPLIT_VIEW', operation: 'NONE',
    policy_hash: d('transparency-policy'), attestation_hash: d('attestation'), security_event_chain_hash: d('event-chain'),
    entry_hash: d('entry'), leaf_hash: d('leaf'), checkpoint_hash: d('checkpoint'), current_checkpoint_hash: d('current-checkpoint'),
    commit_precondition_hash: d('precondition'), next_checkpoint_hash: null,
    valid_operator_signatures: 2, valid_monitor_observations: 2, codes: ['SPLIT_VIEW_DETECTED'],
    runtime_evidence_authority: 'VERIFIED_ATTESTATION_AND_EVENT_CHAIN', transparency_authority: 'APPEND_ONLY_COMMITMENT_PROOFS',
    log_operator_authority: 'COMMITMENT_PUBLICATION_ONLY', monitor_authority: 'INDEPENDENT_OBSERVATION_ONLY',
    storage_authority: 'NONE', transport_authority: 'NONE', material_truth: 'NOT_EVALUATED'
  };
  const incident: ARVVerifierIncidentCaseV1 = {
    schema: ARV_VERIFIER_INCIDENT_CASE_SCHEMA, schema_version: 1, incident_id: 'ARV-INCIDENT-TEST-1',
    verifier_id: 'ARV-VERIFIER-TEST', instance_id: 'ARV-VERIFIER-INSTANCE-TEST', incident_sequence: 1,
    incident_type: 'SPLIT_VIEW', severity: 'CRITICAL', trigger_state: transparency.state,
    trigger_transparency_hash: sha256ARVVerifierTransparencyVerificationForIncidentV1(transparency),
    trigger_checkpoint_hash: transparency.checkpoint_hash, trigger_evidence_digest: d('incident-evidence'),
    opened_at: '2026-06-01T00:00:00Z', previous_incident_hash: null
  };
  const unsignedDecision: ARVVerifierIncidentAdjudicationDecisionV1 = {
    schema: ARV_VERIFIER_INCIDENT_DECISION_SCHEMA, schema_version: 1, decision_id: 'ARV-INCIDENT-DECISION-TEST-1',
    incident_id: incident.incident_id, incident_hash: sha256ARVVerifierIncidentCaseV1(incident), decision_sequence: 1,
    outcome: 'QUARANTINE', policy_id: policy.policy_id, policy_version: policy.policy_version,
    policy_hash: sha256ARVVerifierIncidentAdjudicationPolicyV1(policy), reason_digest: d('reason'),
    issued_at: '2026-06-01T00:01:00Z', previous_decision_hash: null,
    authorizations: [{ algorithm: 'Ed25519', key_id: adjudicators[0].key_id, signature_base64: placeholder }]
  };
  const decisionBytes = canonicalARVVerifierIncidentDecisionSigningBytesV1(unsignedDecision);
  const decision: ARVVerifierIncidentAdjudicationDecisionV1 = {
    ...unsignedDecision,
    authorizations: adjudicators.slice(0,2).map((item) => ({
      algorithm: 'Ed25519' as const, key_id: item.key_id,
      signature_base64: crypto.sign(null, decisionBytes, item.privateKey).toString('base64')
    })).sort((a,b) => a.key_id.localeCompare(b.key_id))
  };
  return { adjudicators, recoveryKeys, root, policy, transparency, incident, decision };
}

function options(overrides: Record<string, unknown> = {}) {
  const value = material();
  return {
    value,
    options: {
      incident_policy: value.policy, trust_root: value.root, transparency_verification: value.transparency,
      incident_case: value.incident, adjudication_decision: value.decision, recovery_authorization: null,
      current_quarantine_state: null, expected_current_quarantine_state_hash: null,
      next_state_id: 'ARV-QUARANTINE-STATE-TEST-1', evaluated_at: '2026-06-01T00:02:00Z', ...overrides
    }
  };
}

describe('ARV Public incident adjudication, quarantine and recovery', () => {
  test('applies mandatory fail-closed quarantine with independent adjudicator quorum', () => {
    const fixture = options();
    const result = verifyARVVerifierIncidentAdjudicationV1(fixture.options);
    expect(result.accepted).toBe(true);
    expect(result.state).toBe('QUARANTINE_APPLIED');
    expect(result.quarantined).toBe(true);
    expect(result.valid_adjudicator_signatures).toBe(2);
    expect(result.incident_evidence_authority).toBe('VERIFIED_TRANSPARENCY_COMMITMENTS');
  });

  test('rejects unexpected fields and private key material', () => {
    const fixture = options({ private_key: 'forbidden' });
    const result = verifyARVVerifierIncidentAdjudicationV1(fixture.options);
    expect(result.state).toBe('PRIVATE_KEY_MATERIAL_FORBIDDEN');
    expect(result.accepted).toBe(false);
    expect(result.quarantined).toBe(true);
  });

  test('requires independent adjudicator threshold signatures', () => {
    const fixture = options();
    fixture.value.decision.authorizations = fixture.value.decision.authorizations.slice(0,1);
    const result = verifyARVVerifierIncidentAdjudicationV1(fixture.options);
    expect(result.state).toBe('ADJUDICATOR_QUORUM_NOT_MET');
    expect(result.frozen).toBe(true);
  });

  test('forbids dismissal of rollback, gap, equivocation and split-view incidents', () => {
    const fixture = options();
    const unsigned = { ...fixture.value.decision, outcome: 'DISMISS' as const, authorizations: [{ algorithm: 'Ed25519' as const, key_id: fixture.value.adjudicators[0].key_id, signature_base64: placeholder }] };
    const bytes = canonicalARVVerifierIncidentDecisionSigningBytesV1(unsigned);
    fixture.value.decision = {
      ...unsigned,
      authorizations: fixture.value.adjudicators.map((item) => ({ algorithm: 'Ed25519' as const, key_id: item.key_id, signature_base64: crypto.sign(null, bytes, item.privateKey).toString('base64') })).sort((a,b) => a.key_id.localeCompare(b.key_id))
    };
    const result = verifyARVVerifierIncidentAdjudicationV1({ ...fixture.options, adjudication_decision: fixture.value.decision });
    expect(result.state).toBe('DISMISSAL_FORBIDDEN');
    expect(result.quarantined).toBe(true);
  });

  test('enforces atomic compare-and-swap continuity and replay safety', () => {
    const fixture = options();
    const first = verifyARVVerifierIncidentAdjudicationV1(fixture.options);
    expect(first.next_quarantine_state).not.toBeNull();
    const replay = verifyARVVerifierIncidentAdjudicationV1({
      ...fixture.options,
      current_quarantine_state: first.next_quarantine_state,
      expected_current_quarantine_state_hash: first.next_quarantine_state_hash,
      next_state_id: 'ARV-QUARANTINE-STATE-TEST-2'
    });
    expect(replay.state).toBe('REPLAY_ACCEPTED');
    const mismatch = verifyARVVerifierIncidentAdjudicationV1({
      ...fixture.options,
      current_quarantine_state: first.next_quarantine_state,
      expected_current_quarantine_state_hash: d('wrong'),
      next_state_id: 'ARV-QUARANTINE-STATE-TEST-2'
    });
    expect(mismatch.state).toBe('COMPARE_AND_SWAP_MISMATCH');
  });

  test('requires Public root recovery and independent recovery quorums', () => {
    const fixture = options();
    const first = verifyARVVerifierIncidentAdjudicationV1(fixture.options);
    const current = first.next_quarantine_state as ARVVerifierQuarantineStateV1;
    const incident: ARVVerifierIncidentCaseV1 = {
      ...fixture.value.incident, incident_id: 'ARV-INCIDENT-TEST-2', incident_sequence: 2,
      incident_type: 'RUNTIME_DRIFT', trigger_evidence_digest: d('reverified-evidence'),
      previous_incident_hash: current.incident_hash
    };
    const unsignedDecision: ARVVerifierIncidentAdjudicationDecisionV1 = {
      ...fixture.value.decision, decision_id: 'ARV-INCIDENT-DECISION-TEST-2', incident_id: incident.incident_id,
      incident_hash: sha256ARVVerifierIncidentCaseV1(incident), decision_sequence: 2, outcome: 'RECOVER',
      issued_at: '2026-06-01T00:03:00Z', previous_decision_hash: current.decision_hash,
      authorizations: [{ algorithm: 'Ed25519', key_id: fixture.value.adjudicators[0].key_id, signature_base64: placeholder }]
    };
    const decisionBytes = canonicalARVVerifierIncidentDecisionSigningBytesV1(unsignedDecision);
    const decision: ARVVerifierIncidentAdjudicationDecisionV1 = {
      ...unsignedDecision,
      authorizations: fixture.value.adjudicators.slice(0,2).map((item) => ({ algorithm: 'Ed25519' as const, key_id: item.key_id, signature_base64: crypto.sign(null, decisionBytes, item.privateKey).toString('base64') })).sort((a,b) => a.key_id.localeCompare(b.key_id))
    };
    const unsignedRecovery: ARVVerifierIncidentRecoveryAuthorizationV1 = {
      schema: ARV_VERIFIER_INCIDENT_RECOVERY_AUTHORIZATION_SCHEMA, schema_version: 1,
      authorization_id: 'ARV-INCIDENT-RECOVERY-TEST-2', incident_id: incident.incident_id,
      incident_hash: sha256ARVVerifierIncidentCaseV1(incident), quarantine_state_hash: sha256ARVVerifierQuarantineStateV1(current),
      policy_hash: sha256ARVVerifierIncidentAdjudicationPolicyV1(fixture.value.policy), root_id: fixture.value.root.root_id,
      root_version: fixture.value.root.root_version, root_epoch: fixture.value.root.epoch, root_hash: sha256ARVTrustRootV1(fixture.value.root),
      issued_at: '2026-06-01T00:03:00Z', expires_at: '2026-06-01T01:03:00Z', reason_digest: d('recovery-reason'),
      root_authorizations: [{ algorithm: 'Ed25519', key_id: fixture.value.root.keys[0].key_id, signature_base64: placeholder }],
      adjudicator_authorizations: [{ algorithm: 'Ed25519', key_id: fixture.value.adjudicators[0].key_id, signature_base64: placeholder }]
    };
    const recoveryBytes = canonicalARVVerifierIncidentRecoverySigningBytesV1(unsignedRecovery);
    const recovery: ARVVerifierIncidentRecoveryAuthorizationV1 = {
      ...unsignedRecovery,
      root_authorizations: fixture.value.recoveryKeys.map((pair, index) => ({ algorithm: 'Ed25519' as const, key_id: fixture.value.root.keys[index].key_id, signature_base64: encodeBase64(nacl.sign.detached(recoveryBytes, pair.secretKey)) })).sort((a,b) => a.key_id.localeCompare(b.key_id)),
      adjudicator_authorizations: fixture.value.adjudicators.slice(0,2).map((item) => ({ algorithm: 'Ed25519' as const, key_id: item.key_id, signature_base64: crypto.sign(null, recoveryBytes, item.privateKey).toString('base64') })).sort((a,b) => a.key_id.localeCompare(b.key_id))
    };
    const result = verifyARVVerifierIncidentAdjudicationV1({
      ...fixture.options, incident_case: incident, adjudication_decision: decision, recovery_authorization: recovery,
      current_quarantine_state: current, expected_current_quarantine_state_hash: sha256ARVVerifierQuarantineStateV1(current),
      next_state_id: 'ARV-QUARANTINE-STATE-TEST-2', evaluated_at: '2026-06-01T00:04:00Z'
    });
    expect(result.state).toBe('RECOVERY_AUTHORIZED');
    expect(result.quarantined).toBe(false);
    expect(result.valid_root_recovery_signatures).toBe(2);
    expect(result.valid_recovery_adjudicator_signatures).toBe(2);
    expect(result.recovery_authority).toBe('ROOT_RECOVERY_AND_ADJUDICATOR_QUORUM');
  });

  test('keeps log operator, monitor, storage and transport outside authority', () => {
    const result = verifyARVVerifierIncidentAdjudicationV1(options().options);
    expect(result.log_operator_authority).toBe('NONE');
    expect(result.monitor_authority).toBe('NONE');
    expect(result.storage_authority).toBe('NONE');
    expect(result.transport_authority).toBe('NONE');
    expect(result.material_truth).toBe('NOT_EVALUATED');
  });
});
