import { EvidenceEnvelopeV1, assertEvidenceEnvelopeV1 } from './evidence-envelope-v1';

export interface MinimalPublicProjectionV1 {
  schema: 'arv.public-projection';
  schema_version: 1;
  disclosure_mode: 'MINIMAL';
  namespace: 'SELF_MANAGED' | 'LEGACY_MANAGED';
  officiality: 'NOT_EVALUATED';
  validation_id: string;
  profile_id: string;
  artifact: {
    kind: string;
    media_type: string;
    byte_length: number;
    digest_algorithm: string;
    digest: string;
  };
  registration: {
    recorded_at: string;
    authority_claim: string;
    system: string;
    canon: string;
    ledger_position: number | null;
  };
  proof: {
    merkle_root: string;
    dual_seal_mode: string;
    signature_algorithm: string;
    public_key_fingerprint: string | null;
    verification_uri: string;
  };
  omitted: {
    artifact_name: true;
    claims: true;
    attributes: true;
    participants: true;
    subject: true;
    asserted_by: true;
    jurisdiction: true;
    occurred_at: true;
    raw_signature: true;
    qr_payload: true;
  };
}

export function projectEvidenceEnvelopeMinimalV1(
  input: unknown
): MinimalPublicProjectionV1 {
  const envelope: EvidenceEnvelopeV1 = 
    assertEvidenceEnvelopeV1(input);

  const namespace = 
    envelope.validation_id.startsWith(
      'ARV-SM-'
    )
      ? 'SELF_MANAGED'
      : 'LEGACY_MANAGED';

  return {
    schema: 'arv.public-projection',
    schema_version: 1,
    disclosure_mode: 'MINIMAL',
    namespace,
    officiality: 'NOT_EVALUATED',
    validation_id: envelope.validation_id,
    profile_id: envelope.profile.id,
    artifact: {
      kind: envelope.artifact.kind,
      media_type: envelope.artifact.media_type,
      byte_length: envelope.artifact.byte_length,
      digest_algorithm: envelope.artifact.digest.algorithm,
      digest: envelope.artifact.digest.value
    },
    registration: {
      recorded_at: envelope.registration.recorded_at,
      authority_claim: envelope.registration.authority,
      system: envelope.registration.system,
      canon: envelope.registration.canon,
      ledger_position: envelope.registration.ledger_position
    },
    proof: {
      merkle_root: envelope.proof.merkle_root,
      dual_seal_mode: envelope.proof.dual_seal.mode,
      signature_algorithm: envelope.proof.signature.algorithm,
      public_key_fingerprint: 
        envelope.proof.signature.public_key_fingerprint,
      verification_uri: envelope.proof.verification_url
    },
    omitted: {
      artifact_name: true,
      claims: true,
      attributes: true,
      participants: true,
      subject: true,
      asserted_by: true,
      jurisdiction: true,
      occurred_at: true,
      raw_signature: true,
      qr_payload: true
    }
  };
}
