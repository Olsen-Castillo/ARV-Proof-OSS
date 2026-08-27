import crypto from 'crypto';
import fs from 'fs';
import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64 } from 'tweetnacl-util';
import { EvidenceEnvelopeV1, assertEvidenceEnvelopeV1 } from './evidence-envelope-v1';
import { canonicalEvidenceQrPayloadV1, canonicalEvidenceSigningPayloadV1 } from './canonical-payload-v1';
import { storeSovereignEnvelopeV1, storeSovereignPublicKeyV1 } from './sovereign-vault-v1';

export interface SelfManagedEmissionInputV1 {
  source_file_path: string;
  artifact: {
    kind: EvidenceEnvelopeV1['artifact']['kind'];
    media_type: string;
  };
  signing_secret_key_base64: string;
}

export interface SelfManagedEmissionOptionsV1 {
  root_dir?: string;
  now?: () => Date;
  uuid?: () => string;
}

export interface SelfManagedEmissionResultV1 {
  envelope: EvidenceEnvelopeV1;
  envelope_path: string;
  public_key_path: string;
  issuance_class: 'SELF_MANAGED';
  official_status: 'NOT_EVALUATED';
  qr_image_generated: false;
}

function sha256Hex(input: Buffer | string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function signingMaterial(
  secretKeyBase64: string
): {
  secret_key: Uint8Array;
  public_key_base64: string;
  public_key_fingerprint: string;
} {
  let secretKey: Uint8Array;

  try {
    secretKey = decodeBase64(secretKeyBase64);
  } catch {
    throw new Error('INVALID_ED25519_SECRET_KEY_BASE64');
  }

  if (secretKey.length !== nacl.sign.secretKeyLength) {
    throw new Error('INVALID_ED25519_SECRET_KEY_LENGTH');
  }

  const pair = nacl.sign.keyPair.fromSecretKey(secretKey);

  return {
    secret_key: secretKey,
    public_key_base64: encodeBase64(pair.publicKey),
    public_key_fingerprint: sha256Hex(
      Buffer.from(pair.publicKey)
    ).slice(0, 24)
  };
}

function selfManagedValidationId(
  timestamp: string,
  uuidFactory: () => string
): string {
  const year = timestamp.slice(0, 4);
  const uuid = uuidFactory().toLowerCase();

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)) {
    throw new Error('SELF_MANAGED_UUID_V4_REQUIRED');
  }

  return `ARV-SM-${year}-${uuid}`;
}

export function emitSelfManagedEvidenceV1(
  input: SelfManagedEmissionInputV1,
  options: SelfManagedEmissionOptionsV1 = {}
): SelfManagedEmissionResultV1 {
  const rootDir = options.root_dir ?? process.cwd();
  const now = options.now ?? (() => new Date());
  const uuidFactory = options.uuid ?? (() => crypto.randomUUID());

  if (!fs.existsSync(input.source_file_path)) {
    throw new Error(
      `SOURCE_FILE_NOT_FOUND:${input.source_file_path}`
    );
  }

  if (!fs.statSync(input.source_file_path).isFile()) {
    throw new Error(
      `SOURCE_PATH_NOT_FILE:${input.source_file_path}`
    );
  }

  if (input.artifact.media_type.trim().length === 0) {
    throw new Error('SELF_MANAGED_MEDIA_TYPE_REQUIRED');
  }

  const timestamp = now().toISOString();

  const validationId = selfManagedValidationId(
    timestamp,
    uuidFactory
  );

  const bytes = fs.readFileSync(input.source_file_path);
  const artifactDigest = sha256Hex(bytes);

  const merkleRoot = sha256Hex(
    `ARV-LEAF-v1:${artifactDigest}`
  );

  const verificationUri = 
    `urn:arv:verify:${validationId}`;

  const primarySealHash = sha256Hex(
    `ARV-DUAL-SEAL-v1|${validationId}|${artifactDigest}|${merkleRoot}`
  );

  const secondarySealHash = sha256Hex(
    `ARV-DUAL-SEAL-v1-VERIFY|${primarySealHash}|${verificationUri}`
  );

  const signing = signingMaterial(
    input.signing_secret_key_base64
  );

  const unsignedEnvelope = assertEvidenceEnvelopeV1({
    schema: 'arv.evidence-envelope',
    schema_version: 1,
    validation_id: validationId,
    profile: {
      id: 'arv.profile.generic-document.v1',
      version: 1,
      claims: {}
    },
    artifact: {
      kind: input.artifact.kind,
      digest: {
        algorithm: 'SHA-256',
        value: artifactDigest
      },
      byte_length: bytes.length,
      media_type: input.artifact.media_type
    },
    assertion: {
      type: 'SELF_MANAGED_RECORD',
      asserted_by: {
        type: 'SYSTEM',
        identifier: 'self-managed'
      },
      participants: [],
      attributes: {}
    },
    registration: {
      recorded_at: timestamp,
      authority: 'SELF_MANAGED',
      system: 'ARV Proof OSS',
      canon: 'ARV Proof Protocol v1',
      epoch_id: 
        `ARV-SM-EPOCH-${timestamp.slice(0, 10).replace(/-/g, '')}`,
      ledger_position: null
    },
    proof: {
      merkle_root: merkleRoot,
      signature: {
        algorithm: 'Ed25519',
        value: null,
        public_key_fingerprint: 
          signing.public_key_fingerprint
      },
      dual_seal: {
        mode: 'ARV-DUAL-SEAL-v1',
        primary_seal_hash: primarySealHash,
        secondary_seal_hash: secondarySealHash
      },
      qr: {
        payload: 'ARV_QR_PENDING',
        signed: false,
        signature: null,
        image_path: 
          `/vault/portable/qr/${validationId}.png`
      },
      verification_url: verificationUri
    }
  });

  const signingPayload = 
    canonicalEvidenceSigningPayloadV1(
      unsignedEnvelope
    );

  const signatureValue = encodeBase64(
    nacl.sign.detached(
      Buffer.from(signingPayload, 'utf8'),
      signing.secret_key
    )
  );

  const signedEnvelope = assertEvidenceEnvelopeV1({
    ...unsignedEnvelope,
    proof: {
      ...unsignedEnvelope.proof,
      signature: {
        algorithm: 'Ed25519',
        value: signatureValue,
        public_key_fingerprint: 
          signing.public_key_fingerprint
      },
      qr: {
        payload: 'ARV_QR_PENDING',
        signed: true,
        signature: signatureValue,
        image_path: 
          `/vault/portable/qr/${validationId}.png`
      }
    }
  });

  signedEnvelope.proof.qr.payload = 
    canonicalEvidenceQrPayloadV1(
      signedEnvelope
    );

  const envelope = assertEvidenceEnvelopeV1(
    signedEnvelope
  );

  const publicKeyPath = storeSovereignPublicKeyV1(
    rootDir,
    {
      schema: 'arv.public-key',
      schema_version: 1,
      algorithm: 'Ed25519',
      fingerprint: signing.public_key_fingerprint,
      public_key_base64: signing.public_key_base64,
      status: 'ACTIVE'
    }
  );

  const envelopePath = storeSovereignEnvelopeV1(
    rootDir,
    envelope
  );

  return {
    envelope,
    envelope_path: envelopePath,
    public_key_path: publicKeyPath,
    issuance_class: 'SELF_MANAGED',
    official_status: 'NOT_EVALUATED',
    qr_image_generated: false
  };
}
