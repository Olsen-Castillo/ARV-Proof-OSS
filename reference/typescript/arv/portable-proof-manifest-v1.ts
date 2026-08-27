import crypto from 'crypto';
import fs from 'fs';
import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64 } from 'tweetnacl-util';
import { EvidenceEnvelopeV1, assertEvidenceEnvelopeV1 } from './evidence-envelope-v1';
import { canonicalizeARVJsonV1 } from './canonical-payload-v1';

export interface PortableProofDigestV1 {
  algorithm: 'SHA-256';
  value: string;
}

export interface PortableProofCanonicalDigestV1
  extends PortableProofDigestV1 {
  canonicalization: 'ARV-JSON-v1';
}

export interface PortableProofManifestUnsignedV1 {
  schema: 'arv.portable-proof-manifest';
  schema_version: 1;
  validation_id: string;
  profile_id: string;
  envelope_digest: PortableProofCanonicalDigestV1;
  artifact_digest: PortableProofDigestV1 | null;
  recorded_at: string;
  signer: {
    algorithm: 'Ed25519';
    public_key_fingerprint: string;
  };
  verification_uri: string;
}

export interface PortableProofManifestV1
  extends PortableProofManifestUnsignedV1 {
  signature: {
    algorithm: 'Ed25519';
    value: string;
  };
}

export interface CreatePortableProofManifestOptionsV1 {
  include_artifact_digest?: boolean;
}

export const PORTABLE_PROOF_MANIFEST_CODES = [
  'KEY_INVALID',
  'KEY_FINGERPRINT_MISMATCH',
  'SIGNATURE_INVALID',
  'ENVELOPE_DIGEST_MISMATCH',
  'ARTIFACT_UNAVAILABLE',
  'ARTIFACT_DIGEST_UNDISCLOSED',
  'ARTIFACT_DIGEST_MISMATCH'
] as const;

export type PortableProofManifestCodeV1 =
  typeof PORTABLE_PROOF_MANIFEST_CODES[number];

export interface PortableProofManifestVerificationV1 {
  state: 'VERIFIED' | 'FAILED' | 'INDETERMINATE';
  signature_valid: boolean;
  envelope_match: boolean | null;
  artifact_match: boolean | null;
  officiality: 'NOT_EVALUATED';
  envelope_integrity: 'NOT_EVALUATED';
  material_truth: 'NOT_EVALUATED';
  codes: PortableProofManifestCodeV1[];
}

const digestPattern = /^[a-f0-9]{64}$/;
const fingerprintPattern = /^[a-f0-9]{24}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const validationIdPattern = /^(?:ARV-\d{4}-\d{6}|ARV-SM-\d{4}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const uriPattern = /^[a-z][a-z0-9+.-]*:/i;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function sha256Hex(input: Buffer | string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function object(
  value: unknown,
  location: string
): Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new Error(location + ' must be an object');
  }

  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  location: string
): void {
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();

  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(location + ' fields are invalid');
  }
}

function assertDigest(
  value: unknown,
  canonical: boolean,
  location: string
): void {
  const digest = object(value, location);

  const required = canonical
    ? ['algorithm', 'canonicalization', 'value']
    : ['algorithm', 'value'];

  exactKeys(digest, required, location);

  if (digest.algorithm !== 'SHA-256') {
    throw new Error(location + '.algorithm is invalid');
  }

  if (
    typeof digest.value !== 'string' ||
    !digestPattern.test(digest.value)
  ) {
    throw new Error(location + '.value is invalid');
  }

  if (
    canonical &&
    digest.canonicalization !== 'ARV-JSON-v1'
  ) {
    throw new Error(location + '.canonicalization is invalid');
  }
}

export function assertPortableProofManifestV1(
  input: unknown
): PortableProofManifestV1 {
  const manifest = object(input, '$');

  exactKeys(
    manifest,
    [
      'schema',
      'schema_version',
      'validation_id',
      'profile_id',
      'envelope_digest',
      'artifact_digest',
      'recorded_at',
      'signer',
      'verification_uri',
      'signature'
    ],
    '$'
  );

  if (manifest.schema !== 'arv.portable-proof-manifest') {
    throw new Error('$.schema is invalid');
  }

  if (manifest.schema_version !== 1) {
    throw new Error('$.schema_version is invalid');
  }

  if (
    typeof manifest.validation_id !== 'string' ||
    !validationIdPattern.test(manifest.validation_id)
  ) {
    throw new Error('$.validation_id is invalid');
  }

  if (
    typeof manifest.profile_id !== 'string' ||
    manifest.profile_id.trim().length === 0
  ) {
    throw new Error('$.profile_id is invalid');
  }

  assertDigest(
    manifest.envelope_digest,
    true,
    '$.envelope_digest'
  );

  if (manifest.artifact_digest !== null) {
    assertDigest(
      manifest.artifact_digest,
      false,
      '$.artifact_digest'
    );
  }

  if (
    typeof manifest.recorded_at !== 'string' ||
    !timestampPattern.test(manifest.recorded_at) ||
    Number.isNaN(Date.parse(manifest.recorded_at))
  ) {
    throw new Error('$.recorded_at is invalid');
  }

  const signer = object(manifest.signer, '$.signer');

  exactKeys(
    signer,
    ['algorithm', 'public_key_fingerprint'],
    '$.signer'
  );

  if (signer.algorithm !== 'Ed25519') {
    throw new Error('$.signer.algorithm is invalid');
  }

  if (
    typeof signer.public_key_fingerprint !== 'string' ||
    !fingerprintPattern.test(signer.public_key_fingerprint)
  ) {
    throw new Error('$.signer.public_key_fingerprint is invalid');
  }

  if (
    typeof manifest.verification_uri !== 'string' ||
    !uriPattern.test(manifest.verification_uri)
  ) {
    throw new Error('$.verification_uri is invalid');
  }

  const signature = object(manifest.signature, '$.signature');

  exactKeys(
    signature,
    ['algorithm', 'value'],
    '$.signature'
  );

  if (signature.algorithm !== 'Ed25519') {
    throw new Error('$.signature.algorithm is invalid');
  }

  if (
    typeof signature.value !== 'string' ||
    signature.value.length === 0 ||
    !base64Pattern.test(signature.value)
  ) {
    throw new Error('$.signature.value is invalid');
  }

  return input as PortableProofManifestV1;
}

export function portableEnvelopeDigestV1(
  envelopeInput: unknown
): string {
  const envelope = assertEvidenceEnvelopeV1(
    envelopeInput
  );

  return sha256Hex(
    canonicalizeARVJsonV1(envelope)
  );
}

export function canonicalPortableProofManifestSigningPayloadV1(
  value: PortableProofManifestUnsignedV1
): string {
  return canonicalizeARVJsonV1({
    schema: 'arv.portable-proof-manifest-signing-payload',
    schema_version: 1,
    manifest: value
  });
}

function unsignedManifest(
  manifest: PortableProofManifestV1
): PortableProofManifestUnsignedV1 {
  return {
    schema: manifest.schema,
    schema_version: manifest.schema_version,
    validation_id: manifest.validation_id,
    profile_id: manifest.profile_id,
    envelope_digest: manifest.envelope_digest,
    artifact_digest: manifest.artifact_digest,
    recorded_at: manifest.recorded_at,
    signer: manifest.signer,
    verification_uri: manifest.verification_uri
  };
}

export function createPortableProofManifestV1(
  envelopeInput: unknown,
  signingSecretKeyBase64: string,
  options: CreatePortableProofManifestOptionsV1 = {}
): PortableProofManifestV1 {
  const envelope = assertEvidenceEnvelopeV1(
    envelopeInput
  );

  if (!base64Pattern.test(signingSecretKeyBase64)) {
    throw new Error('PORTABLE_SIGNING_KEY_INVALID');
  }

  const secretKey = decodeBase64(
    signingSecretKeyBase64
  );

  if (secretKey.length !== nacl.sign.secretKeyLength) {
    throw new Error('PORTABLE_SIGNING_KEY_INVALID');
  }

  const pair = nacl.sign.keyPair.fromSecretKey(
    secretKey
  );

  const fingerprint = sha256Hex(
    Buffer.from(pair.publicKey)
  ).slice(0, 24);

  if (
    envelope.proof.signature.public_key_fingerprint !==
    fingerprint
  ) {
    throw new Error(
      'PORTABLE_SIGNER_FINGERPRINT_MISMATCH'
    );
  }

  const includeArtifactDigest =
    options.include_artifact_digest ?? true;

  const unsigned: PortableProofManifestUnsignedV1 = {
    schema: 'arv.portable-proof-manifest',
    schema_version: 1,
    validation_id: envelope.validation_id,
    profile_id: envelope.profile.id,
    envelope_digest: {
      algorithm: 'SHA-256',
      canonicalization: 'ARV-JSON-v1',
      value: portableEnvelopeDigestV1(envelope)
    },
    artifact_digest: includeArtifactDigest
      ? {
          algorithm: 'SHA-256',
          value: envelope.artifact.digest.value
        }
      : null,
    recorded_at: envelope.registration.recorded_at,
    signer: {
      algorithm: 'Ed25519',
      public_key_fingerprint: fingerprint
    },
    verification_uri: envelope.proof.verification_url
  };

  const payload =
    canonicalPortableProofManifestSigningPayloadV1(
      unsigned
    );

  const signatureValue = encodeBase64(
    nacl.sign.detached(
      Buffer.from(payload, 'utf8'),
      secretKey
    )
  );

  return assertPortableProofManifestV1({
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      value: signatureValue
    }
  });
}

export function verifyPortableProofManifestV1(
  manifestInput: unknown,
  publicKeyBase64: string,
  options: {
    full_envelope?: EvidenceEnvelopeV1;
    artifact_file_path?: string;
  } = {}
): PortableProofManifestVerificationV1 {
  const manifest = assertPortableProofManifestV1(
    manifestInput
  );

  const codes: PortableProofManifestCodeV1[] = [];
  let signatureValid = false;
  let envelopeMatch: boolean | null = null;
  let artifactMatch: boolean | null = null;

  if (
    typeof publicKeyBase64 !== 'string' ||
    !base64Pattern.test(publicKeyBase64)
  ) {
    codes.push('KEY_INVALID');
  }

  let publicKey: Uint8Array | null = null;

  if (codes.length === 0) {
    publicKey = decodeBase64(publicKeyBase64);

    if (publicKey.length !== nacl.sign.publicKeyLength) {
      codes.push('KEY_INVALID');
      publicKey = null;
    }
  }

  if (publicKey !== null) {
    const fingerprint = sha256Hex(
      Buffer.from(publicKey)
    ).slice(0, 24);

    if (
      fingerprint !==
      manifest.signer.public_key_fingerprint
    ) {
      codes.push('KEY_FINGERPRINT_MISMATCH');
    }
  }

  if (
    publicKey !== null &&
    codes.length === 0
  ) {
    const signature = decodeBase64(
      manifest.signature.value
    );

    if (signature.length !== nacl.sign.signatureLength) {
      codes.push('SIGNATURE_INVALID');
    }

    if (signature.length === nacl.sign.signatureLength) {
      signatureValid = nacl.sign.detached.verify(
        Buffer.from(
          canonicalPortableProofManifestSigningPayloadV1(
            unsignedManifest(manifest)
          ),
          'utf8'
        ),
        signature,
        publicKey
      );

      if (!signatureValid) {
        codes.push('SIGNATURE_INVALID');
      }
    }
  }

  if (options.full_envelope !== undefined) {
    const fullEnvelope = assertEvidenceEnvelopeV1(
      options.full_envelope
    );

    envelopeMatch = (
      portableEnvelopeDigestV1(fullEnvelope) ===
      manifest.envelope_digest.value
    );

    if (!envelopeMatch) {
      codes.push('ENVELOPE_DIGEST_MISMATCH');
    }
  }

  if (options.artifact_file_path !== undefined) {
    if (manifest.artifact_digest === null) {
      codes.push('ARTIFACT_DIGEST_UNDISCLOSED');
    }

    if (
      manifest.artifact_digest !== null &&
      !fs.existsSync(options.artifact_file_path)
    ) {
      codes.push('ARTIFACT_UNAVAILABLE');
    }

    if (
      manifest.artifact_digest !== null &&
      fs.existsSync(options.artifact_file_path)
    ) {
      artifactMatch = (
        sha256Hex(
          fs.readFileSync(
            options.artifact_file_path
          )
        ) === manifest.artifact_digest.value
      );

      if (!artifactMatch) {
        codes.push('ARTIFACT_DIGEST_MISMATCH');
      }
    }
  }

  const failed = (
    !signatureValid ||
    envelopeMatch === false ||
    artifactMatch === false
  );

  const incomplete = (
    codes.includes('ARTIFACT_UNAVAILABLE') ||
    codes.includes('ARTIFACT_DIGEST_UNDISCLOSED')
  );

  let state: 'VERIFIED' | 'FAILED' | 'INDETERMINATE' =
    'VERIFIED';

  if (failed) {
    state = 'FAILED';
  }

  if (!failed && incomplete) {
    state = 'INDETERMINATE';
  }

  return {
    state,
    signature_valid: signatureValid,
    envelope_match: envelopeMatch,
    artifact_match: artifactMatch,
    officiality: 'NOT_EVALUATED',
    envelope_integrity: 'NOT_EVALUATED',
    material_truth: 'NOT_EVALUATED',
    codes
  };
}
