import { EvidenceEnvelopeV1, assertEvidenceEnvelopeV1 } from './evidence-envelope-v1';
import { validateEvidenceProfileBoundaryV1 } from './evidence-profiles-v1';

const digest = 'a'.repeat(64);
const merkleRoot = 'b'.repeat(64);

function envelope(
  validationId = 'ARV-SM-2026-11111111-1111-4111-8111-111111111111'
): EvidenceEnvelopeV1 {
  return {
    schema: 'arv.evidence-envelope',
    schema_version: 1,
    validation_id: validationId,
    profile: {
      id: 'arv.profile.generic-document.v1',
      version: 1,
      claims: {}
    },
    artifact: {
      kind: 'DOCUMENT',
      digest: { algorithm: 'SHA-256', value: digest },
      byte_length: 42,
      media_type: 'application/pdf'
    },
    assertion: {
      type: 'SELF_MANAGED_RECORD',
      asserted_by: { type: 'SYSTEM', identifier: 'public-test' },
      participants: [],
      attributes: {}
    },
    registration: {
      recorded_at: '2026-08-21T12:01:00Z',
      authority: 'SELF_MANAGED',
      system: 'ARV Proof OSS',
      canon: 'ARV Proof Protocol v1',
      epoch_id: 'ARV-SM-EPOCH-20260821',
      ledger_position: null
    },
    proof: {
      merkle_root: merkleRoot,
      signature: {
        algorithm: 'Ed25519',
        value: null,
        public_key_fingerprint: null
      },
      dual_seal: {
        mode: 'ARV-DUAL-SEAL-v1',
        primary_seal_hash: null,
        secondary_seal_hash: null
      },
      qr: {
        payload: 'ARV_QR_PENDING',
        signed: false,
        signature: null,
        image_path: `/vault/portable/qr/${validationId}.png`
      },
      verification_url: `urn:arv:verify:${validationId}`
    }
  };
}

describe('ARV public evidence envelope V1', () => {
  test('accepts the self-managed namespace', () => {
    const value = envelope();
    expect(assertEvidenceEnvelopeV1(value)).toBe(value);
  });

  test('preserves legacy managed namespace compatibility', () => {
    const value = envelope('ARV-2026-000003');
    expect(assertEvidenceEnvelopeV1(value)).toBe(value);
  });

  test('rejects malformed self-managed identifiers', () => {
    expect(() => assertEvidenceEnvelopeV1(envelope('ARV-SM-2026-not-a-uuid'))).toThrow();
  });

  test('rejects unknown core fields while profile claims remain extensible', () => {
    const value = envelope();
    value.profile.claims.reference = 'PUBLIC-001';
    expect(assertEvidenceEnvelopeV1(value)).toBe(value);
    expect(() => assertEvidenceEnvelopeV1({ ...value, university: 'forbidden' })).toThrow('unknown');
  });

  test('supports the generic profile with empty claims', () => {
    expect(validateEvidenceProfileBoundaryV1(envelope().profile)).toEqual({
      supported: true,
      profile_id: 'arv.profile.generic-document.v1',
      missing_claims: []
    });
  });

  test('keeps future profiles out of the core verifier profile boundary', () => {
    const value = envelope();
    value.profile.id = 'arv.profile.future-domain.v1';
    expect(assertEvidenceEnvelopeV1(value)).toBe(value);
    expect(validateEvidenceProfileBoundaryV1(value.profile).supported).toBe(false);
  });
});
