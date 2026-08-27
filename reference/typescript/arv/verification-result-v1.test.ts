import {
  ARV_ARTIFACT_MATCH_STATES,
  ARV_INTEGRITY_STATES,
  ARV_LIFECYCLE_STATES,
  ARV_OVERALL_STATES,
  ARVArtifactMatchState,
  ARVIntegrityState,
  ARVLifecycleState,
  VerificationResultV1,
  assertVerificationResultV1,
  deriveARVOverallState,
  isVerificationResultV1
} from './verification-result-v1';

function result(
  integrity: ARVIntegrityState,
  lifecycle: ARVLifecycleState,
  artifactMatch: ARVArtifactMatchState
): VerificationResultV1 {
  return {
    schema: 'arv.verification-result',
    schema_version: 1,
    integrity,
    lifecycle,
    artifact_match: artifactMatch,
    overall: deriveARVOverallState(integrity, lifecycle, artifactMatch),
    codes: []
  };
}

describe('ARV public verification result contract', () => {
  test('accepts all deterministic state combinations', () => {
    let count = 0;
    for (const integrity of ARV_INTEGRITY_STATES) {
      for (const lifecycle of ARV_LIFECYCLE_STATES) {
        for (const artifactMatch of ARV_ARTIFACT_MATCH_STATES) {
          const value = result(integrity, lifecycle, artifactMatch);
          expect(isVerificationResultV1(value)).toBe(true);
          expect(assertVerificationResultV1(value)).toBe(value);
          count += 1;
        }
      }
    }
    expect(count).toBe(36);
  });

  test('rejects incorrect overall states', () => {
    for (const integrity of ARV_INTEGRITY_STATES) {
      for (const lifecycle of ARV_LIFECYCLE_STATES) {
        for (const artifactMatch of ARV_ARTIFACT_MATCH_STATES) {
          const value = result(integrity, lifecycle, artifactMatch);
          const wrong = ARV_OVERALL_STATES.find(
            (candidate) => candidate !== value.overall
          );
          expect(isVerificationResultV1({ ...value, overall: wrong })).toBe(false);
        }
      }
    }
  });

  test('fails closed on unknown fields, duplicate codes and invalid versions', () => {
    const valid = result('VERIFIED', 'ACTIVE', 'MATCH');
    expect(isVerificationResultV1({ ...valid, unknown_field: true })).toBe(false);
    expect(isVerificationResultV1({
      ...valid,
      codes: ['SIGNATURE_INVALID', 'SIGNATURE_INVALID']
    })).toBe(false);
    expect(() => assertVerificationResultV1({ ...valid, schema_version: 2 })).toThrow(
      'ARV_VERIFICATION_RESULT_V1_INVALID'
    );
  });
});
