import fs from 'fs';
import path from 'path';
import { EvidenceEnvelopeV1, assertEvidenceEnvelopeV1 } from './evidence-envelope-v1';

export interface SovereignVaultPathsV1 {
  root: string;
  envelopes: string;
  keyring: string;
  receipts: string;
  exports: string;
}

export interface SovereignPublicKeyDescriptorV1 {
  schema: 'arv.public-key';
  schema_version: 1;
  algorithm: 'Ed25519';
  fingerprint: string;
  public_key_base64: string;
  status: 'ACTIVE' | 'REVOKED' | 'RETIRED';
}

export function resolveSovereignVaultPathsV1(
  rootDir: string
): SovereignVaultPathsV1 {
  const root = path.resolve(rootDir, 'vault', 'sovereign');

  return {
    root,
    envelopes: path.join(root, 'envelopes'),
    keyring: path.join(root, 'keyring'),
    receipts: path.join(root, 'receipts'),
    exports: path.join(root, 'exports')
  };
}

export function initializeSovereignVaultV1(
  rootDir: string
): SovereignVaultPathsV1 {
  const paths = resolveSovereignVaultPathsV1(rootDir);

  const directories = [
    paths.root,
    paths.envelopes,
    paths.keyring,
    paths.receipts,
    paths.exports
  ];

  for (const directory of directories) {
    fs.mkdirSync(directory, { recursive: true });
  }

  return paths;
}

function assertSafeValidationIdV1(
  validationId: string
): string {
  if (!/^(?:ARV-\d{4}-\d{6}|ARV-SM-\d{4}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(validationId)) {
    throw new Error('SOVEREIGN_VAULT_INVALID_VALIDATION_ID');
  }

  return validationId;
}

function assertSafeFingerprintV1(
  fingerprint: string
): string {
  if (!/^[a-f0-9]{24}$/.test(fingerprint)) {
    throw new Error('SOVEREIGN_VAULT_INVALID_KEY_FINGERPRINT');
  }

  return fingerprint;
}

export function storeSovereignEnvelopeV1(
  rootDir: string,
  input: unknown
): string {
  const envelope = assertEvidenceEnvelopeV1(input);
  const validationId = assertSafeValidationIdV1(
    envelope.validation_id
  );

  const paths = initializeSovereignVaultV1(rootDir);

  const target = path.join(
    paths.envelopes,
    `${validationId}.json`
  );

  const serialized = `${JSON.stringify(
    envelope,
    null,
    2
  )}\n`;

  fs.writeFileSync(
    target,
    serialized,
    { encoding: 'utf8', flag: 'wx' }
  );

  return target;
}

export function readSovereignEnvelopeV1(
  rootDir: string,
  validationIdInput: string
): EvidenceEnvelopeV1 | null {
  const validationId = assertSafeValidationIdV1(
    validationIdInput
  );

  const paths = resolveSovereignVaultPathsV1(rootDir);

  const target = path.join(
    paths.envelopes,
    `${validationId}.json`
  );

  if (!fs.existsSync(target)) return null;

  const parsed = JSON.parse(
    fs.readFileSync(target, 'utf8')
  );

  return assertEvidenceEnvelopeV1(parsed);
}

export function storeSovereignPublicKeyV1(
  rootDir: string,
  descriptor: SovereignPublicKeyDescriptorV1
): string {
  if (descriptor.schema !== 'arv.public-key') {
    throw new Error('SOVEREIGN_VAULT_INVALID_KEY_SCHEMA');
  }

  if (descriptor.schema_version !== 1) {
    throw new Error('SOVEREIGN_VAULT_INVALID_KEY_VERSION');
  }

  if (descriptor.algorithm !== 'Ed25519') {
    throw new Error('SOVEREIGN_VAULT_INVALID_KEY_ALGORITHM');
  }

  if (![
    'ACTIVE',
    'REVOKED',
    'RETIRED'
  ].includes(descriptor.status)) {
    throw new Error('SOVEREIGN_VAULT_INVALID_KEY_STATUS');
  }

  const fingerprint = assertSafeFingerprintV1(
    descriptor.fingerprint
  );

  const paths = initializeSovereignVaultV1(rootDir);

  const target = path.join(
    paths.keyring,
    `${fingerprint}.json`
  );

  const serialized = `${JSON.stringify(
    descriptor,
    null,
    2
  )}\n`;

  if (fs.existsSync(target)) {
    const existing = fs.readFileSync(target, 'utf8');

    if (existing !== serialized) {
      throw new Error('SOVEREIGN_VAULT_PUBLIC_KEY_COLLISION');
    }

    return target;
  }

  fs.writeFileSync(
    target,
    serialized,
    { encoding: 'utf8', flag: 'wx' }
  );

  return target;
}

export function readSovereignPublicKeyV1(
  rootDir: string,
  fingerprintInput: string
): SovereignPublicKeyDescriptorV1 | null {
  const fingerprint = assertSafeFingerprintV1(
    fingerprintInput
  );

  const paths = resolveSovereignVaultPathsV1(rootDir);

  const target = path.join(
    paths.keyring,
    `${fingerprint}.json`
  );

  if (!fs.existsSync(target)) return null;

  const parsed = JSON.parse(
    fs.readFileSync(target, 'utf8')
  ) as SovereignPublicKeyDescriptorV1;

  return parsed;
}
