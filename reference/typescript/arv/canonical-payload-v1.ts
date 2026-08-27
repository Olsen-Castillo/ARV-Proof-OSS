import type { EvidenceEnvelopeV1 } from './evidence-envelope-v1';

export function canonicalizeARVJsonV1(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const primitive = JSON.stringify(value);
    if (primitive === undefined) throw new Error('CANONICAL_JSON_UNDEFINED_VALUE');
    return primitive;
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalizeARVJsonV1(entry)).join(',')}]`;
  }
  const object = value as Record<string, unknown>;
  const entries = Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeARVJsonV1(object[key])}`);
  return `{${entries.join(',')}}`;
}

export function canonicalEvidenceSigningPayloadV1(
  envelope: EvidenceEnvelopeV1
): string {
  return canonicalizeARVJsonV1({
    schema: 'arv.evidence-signing-payload',
    schema_version: 1,
    validation_id: envelope.validation_id,
    profile: envelope.profile,
    artifact: envelope.artifact,
    assertion: envelope.assertion,
    registration: envelope.registration,
    proof: {
      merkle_root: envelope.proof.merkle_root,
      primary_seal_hash: envelope.proof.dual_seal.primary_seal_hash,
      secondary_seal_hash: envelope.proof.dual_seal.secondary_seal_hash,
      verification_url: envelope.proof.verification_url
    }
  });
}

export function canonicalEvidenceQrPayloadV1(
  envelope: EvidenceEnvelopeV1
): string {
  return canonicalizeARVJsonV1({
    digest: envelope.artifact.digest.value,
    id: envelope.validation_id,
    merkle_root: envelope.proof.merkle_root,
    signature: envelope.proof.signature.value,
    verify: envelope.proof.verification_url
  });
}
