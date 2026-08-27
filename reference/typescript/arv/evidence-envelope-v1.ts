export const ARV_ARTIFACT_KINDS = [
  'DOCUMENT',
  'IMAGE',
  'VIDEO',
  'AUDIO',
  'DATASET',
  'SOFTWARE',
  'ARCHIVE',
  'BINARY',
  'OTHER'
] as const;

export const ARV_ENTITY_TYPES = [
  'PERSON',
  'ORGANIZATION',
  'SYSTEM',
  'UNKNOWN'
] as const;

export type ARVArtifactKind = typeof ARV_ARTIFACT_KINDS[number];
export type ARVEntityType = typeof ARV_ENTITY_TYPES[number];
export type ARVJsonValue =
  | null
  | boolean
  | number
  | string
  | ARVJsonValue[]
  | { [key: string]: ARVJsonValue };

export interface EvidenceEntityV1 {
  type: ARVEntityType;
  name?: string;
  identifier?: string;
}

export interface EvidenceProfileV1 {
  id: string;
  version: number;
  claims: Record<string, ARVJsonValue>;
}

export interface EvidenceEnvelopeV1 {
  schema: 'arv.evidence-envelope';
  schema_version: 1;
  validation_id: string;
  profile: EvidenceProfileV1;
  artifact: {
    kind: ARVArtifactKind;
    digest: {
      algorithm: 'SHA-256';
      value: string;
    };
    byte_length: number;
    media_type: string;
    name?: string;
  };
  assertion: {
    type: string;
    asserted_by: EvidenceEntityV1;
    subject?: EvidenceEntityV1;
    participants: Array<{
      role: string;
      entity: EvidenceEntityV1;
    }>;
    occurred_at?: string;
    jurisdiction?: string;
    attributes: Record<string, ARVJsonValue>;
  };
  registration: {
    recorded_at: string;
    authority: string;
    system: string;
    canon: string;
    epoch_id: string;
    ledger_position: number | null;
  };
  proof: {
    merkle_root: string;
    signature: {
      algorithm: 'Ed25519';
      value: string | null;
      public_key_fingerprint: string | null;
    };
    dual_seal: {
      mode: string;
      primary_seal_hash: string | null;
      secondary_seal_hash: string | null;
    };
    qr: {
      payload: string;
      signed: boolean;
      signature: string | null;
      image_path: string;
    };
    verification_url: string;
  };
}

const validationIdPattern = /^(?:ARV-\d{4}-\d{6}|ARV-SM-\d{4}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const profileIdPattern = /^arv\.profile\.[a-z0-9.-]+\.v[1-9]\d*$/;
const tokenPattern = /^[A-Z][A-Z0-9_]*$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertObject(value: unknown, path: string): Record<string, unknown> {
  if (!isObject(value)) throw new Error(`${path} must be an object`);
  return value;
}

function assertExactKeys(
  object: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  path: string
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) throw new Error(`${path}.${key} is unknown`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(object, key)) {
      throw new Error(`${path}.${key} is required`);
    }
  }
}

function assertNonEmptyString(value: unknown, path: string): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${path} must be a non-empty string`);
  }
}

function assertNullableString(value: unknown, path: string): void {
  if (value !== null && typeof value !== 'string') {
    throw new Error(`${path} must be a string or null`);
  }
}

function assertTimestamp(value: unknown, path: string): asserts value is string {
  assertNonEmptyString(value, path);
  if (!timestampPattern.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${path} must be a UTC ISO-8601 timestamp`);
  }
}

function assertUri(value: unknown, path: string): asserts value is string {
  assertNonEmptyString(value, path);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${path} must be an absolute URI`);
  }
  if (parsed.protocol.length === 0) throw new Error(`${path} must be an absolute URI`);
}

function assertJsonValue(value: unknown, path: string): asserts value is ARVJsonValue {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertJsonValue(entry, `${path}[${index}]`));
    return;
  }
  if (isObject(value)) {
    for (const [key, entry] of Object.entries(value)) {
      assertJsonValue(entry, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`${path} must be a JSON value`);
}

function assertEntity(value: unknown, path: string): asserts value is EvidenceEntityV1 {
  const entity = assertObject(value, path);
  assertExactKeys(entity, ['type'], ['name', 'identifier'], path);
  if (!ARV_ENTITY_TYPES.includes(entity.type as ARVEntityType)) {
    throw new Error(`${path}.type is unsupported`);
  }
  if (entity.name !== undefined) assertNonEmptyString(entity.name, `${path}.name`);
  if (entity.identifier !== undefined) {
    assertNonEmptyString(entity.identifier, `${path}.identifier`);
  }
  if (entity.name === undefined && entity.identifier === undefined && entity.type !== 'UNKNOWN') {
    throw new Error(`${path} requires name or identifier`);
  }
}

export function assertEvidenceEnvelopeV1(input: unknown): EvidenceEnvelopeV1 {
  const envelope = assertObject(input, '$');
  assertExactKeys(
    envelope,
    [
      'schema',
      'schema_version',
      'validation_id',
      'profile',
      'artifact',
      'assertion',
      'registration',
      'proof'
    ],
    [],
    '$'
  );

  if (envelope.schema !== 'arv.evidence-envelope') throw new Error('$.schema is invalid');
  if (envelope.schema_version !== 1) throw new Error('$.schema_version is unsupported');
  if (typeof envelope.validation_id !== 'string' || !validationIdPattern.test(envelope.validation_id)) {
    throw new Error('$.validation_id is invalid');
  }

  const profile = assertObject(envelope.profile, '$.profile');
  assertExactKeys(profile, ['id', 'version', 'claims'], [], '$.profile');
  if (typeof profile.id !== 'string' || !profileIdPattern.test(profile.id)) {
    throw new Error('$.profile.id is invalid');
  }
  if (!Number.isInteger(profile.version) || (profile.version as number) < 1) {
    throw new Error('$.profile.version is invalid');
  }
  const claims = assertObject(profile.claims, '$.profile.claims');
  for (const [key, value] of Object.entries(claims)) {
    assertJsonValue(value, `$.profile.claims.${key}`);
  }

  const artifact = assertObject(envelope.artifact, '$.artifact');
  assertExactKeys(artifact, ['kind', 'digest', 'byte_length', 'media_type'], ['name'], '$.artifact');
  if (!ARV_ARTIFACT_KINDS.includes(artifact.kind as ARVArtifactKind)) {
    throw new Error('$.artifact.kind is unsupported');
  }
  const digest = assertObject(artifact.digest, '$.artifact.digest');
  assertExactKeys(digest, ['algorithm', 'value'], [], '$.artifact.digest');
  if (digest.algorithm !== 'SHA-256') throw new Error('$.artifact.digest.algorithm is invalid');
  if (typeof digest.value !== 'string' || !sha256Pattern.test(digest.value)) {
    throw new Error('$.artifact.digest.value is invalid');
  }
  if (!Number.isSafeInteger(artifact.byte_length) || (artifact.byte_length as number) < 0) {
    throw new Error('$.artifact.byte_length is invalid');
  }
  assertNonEmptyString(artifact.media_type, '$.artifact.media_type');
  if (artifact.name !== undefined) assertNonEmptyString(artifact.name, '$.artifact.name');

  const assertion = assertObject(envelope.assertion, '$.assertion');
  assertExactKeys(
    assertion,
    ['type', 'asserted_by', 'participants', 'attributes'],
    ['subject', 'occurred_at', 'jurisdiction'],
    '$.assertion'
  );
  if (typeof assertion.type !== 'string' || !tokenPattern.test(assertion.type)) {
    throw new Error('$.assertion.type is invalid');
  }
  assertEntity(assertion.asserted_by, '$.assertion.asserted_by');
  if (assertion.subject !== undefined) assertEntity(assertion.subject, '$.assertion.subject');
  if (!Array.isArray(assertion.participants)) {
    throw new Error('$.assertion.participants must be an array');
  }
  assertion.participants.forEach((entry, index) => {
    const participant = assertObject(entry, `$.assertion.participants[${index}]`);
    assertExactKeys(participant, ['role', 'entity'], [], `$.assertion.participants[${index}]`);
    if (typeof participant.role !== 'string' || !tokenPattern.test(participant.role)) {
      throw new Error(`$.assertion.participants[${index}].role is invalid`);
    }
    assertEntity(participant.entity, `$.assertion.participants[${index}].entity`);
  });
  if (assertion.occurred_at !== undefined) {
    assertTimestamp(assertion.occurred_at, '$.assertion.occurred_at');
  }
  if (assertion.jurisdiction !== undefined) {
    assertNonEmptyString(assertion.jurisdiction, '$.assertion.jurisdiction');
  }
  const attributes = assertObject(assertion.attributes, '$.assertion.attributes');
  for (const [key, value] of Object.entries(attributes)) {
    assertJsonValue(value, `$.assertion.attributes.${key}`);
  }

  const registration = assertObject(envelope.registration, '$.registration');
  assertExactKeys(
    registration,
    ['recorded_at', 'authority', 'system', 'canon', 'epoch_id', 'ledger_position'],
    [],
    '$.registration'
  );
  assertTimestamp(registration.recorded_at, '$.registration.recorded_at');
  assertNonEmptyString(registration.authority, '$.registration.authority');
  assertNonEmptyString(registration.system, '$.registration.system');
  assertNonEmptyString(registration.canon, '$.registration.canon');
  assertNonEmptyString(registration.epoch_id, '$.registration.epoch_id');
  if (
    registration.ledger_position !== null &&
    (!Number.isSafeInteger(registration.ledger_position) || (registration.ledger_position as number) < 1)
  ) {
    throw new Error('$.registration.ledger_position is invalid');
  }

  const proof = assertObject(envelope.proof, '$.proof');
  assertExactKeys(
    proof,
    ['merkle_root', 'signature', 'dual_seal', 'qr', 'verification_url'],
    [],
    '$.proof'
  );
  if (typeof proof.merkle_root !== 'string' || !sha256Pattern.test(proof.merkle_root)) {
    throw new Error('$.proof.merkle_root is invalid');
  }
  const signature = assertObject(proof.signature, '$.proof.signature');
  assertExactKeys(signature, ['algorithm', 'value', 'public_key_fingerprint'], [], '$.proof.signature');
  if (signature.algorithm !== 'Ed25519') throw new Error('$.proof.signature.algorithm is invalid');
  assertNullableString(signature.value, '$.proof.signature.value');
  assertNullableString(signature.public_key_fingerprint, '$.proof.signature.public_key_fingerprint');

  const dualSeal = assertObject(proof.dual_seal, '$.proof.dual_seal');
  assertExactKeys(
    dualSeal,
    ['mode', 'primary_seal_hash', 'secondary_seal_hash'],
    [],
    '$.proof.dual_seal'
  );
  assertNonEmptyString(dualSeal.mode, '$.proof.dual_seal.mode');
  assertNullableString(dualSeal.primary_seal_hash, '$.proof.dual_seal.primary_seal_hash');
  assertNullableString(dualSeal.secondary_seal_hash, '$.proof.dual_seal.secondary_seal_hash');

  const qr = assertObject(proof.qr, '$.proof.qr');
  assertExactKeys(qr, ['payload', 'signed', 'signature', 'image_path'], [], '$.proof.qr');
  assertNonEmptyString(qr.payload, '$.proof.qr.payload');
  if (typeof qr.signed !== 'boolean') throw new Error('$.proof.qr.signed is invalid');
  assertNullableString(qr.signature, '$.proof.qr.signature');
  assertNonEmptyString(qr.image_path, '$.proof.qr.image_path');
  if (!qr.image_path.startsWith('/') || qr.image_path.includes('..')) {
    throw new Error('$.proof.qr.image_path is unsafe');
  }
  assertUri(proof.verification_url, '$.proof.verification_url');

  return input as EvidenceEnvelopeV1;
}
