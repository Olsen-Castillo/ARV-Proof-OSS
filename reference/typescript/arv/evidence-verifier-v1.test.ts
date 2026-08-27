import fs from 'fs';
import os from 'os';
import path from 'path';
import { encodeBase64 } from 'tweetnacl-util';
import { emitSelfManagedFixtureV1 } from './public-test-fixture-v1';
import { verifyEvidenceEnvelopeV1 } from './evidence-verifier-v1';

const temporaryRoots: string[] = [];

function temporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'arv-public-verifier-'));
  temporaryRoots.push(root);
  return root;
}

function emitted(root: string) {
  const fixture = emitSelfManagedFixtureV1(root);
  return {
    request: {
      source_file_path: fixture.source_file_path
    },
    result: fixture.result
  };
}
afterEach(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root) fs.rmSync(root, { recursive: true, force: true });
  }
});

describe('ARV Public keyring, signature and artifact verification', () => {
  test('verifies integrity while preserving unknown lifecycle and unchecked artifact', async () => {
    const root = temporaryRoot();
    const { result } = await emitted(root);
    const verified = verifyEvidenceEnvelopeV1(result.envelope, { root_dir: root });

    expect(verified).toEqual({
      schema: 'arv.verification-result',
      schema_version: 1,
      integrity: 'VERIFIED',
      lifecycle: 'UNKNOWN',
      artifact_match: 'NOT_CHECKED',
      overall: 'INDETERMINATE',
      codes: ['CHECKPOINT_UNAVAILABLE', 'LIFECYCLE_STATE_UNKNOWN']
    });
  });

  test('reports a matching supplied artifact independently from lifecycle', async () => {
    const root = temporaryRoot();
    const { request, result } = await emitted(root);
    const verified = verifyEvidenceEnvelopeV1(result.envelope, {
      root_dir: root,
      artifact_file_path: request.source_file_path
    });

    expect(verified.integrity).toBe('VERIFIED');
    expect(verified.artifact_match).toBe('MATCH');
    expect(verified.overall).toBe('INDETERMINATE');
  });

  test('fails when supplied artifact bytes differ', async () => {
    const root = temporaryRoot();
    const { request, result } = await emitted(root);
    fs.writeFileSync(request.source_file_path, 'tampered bytes', 'utf8');
    const verified = verifyEvidenceEnvelopeV1(result.envelope, {
      root_dir: root,
      artifact_file_path: request.source_file_path
    });

    expect(verified.artifact_match).toBe('MISMATCH');
    expect(verified.overall).toBe('FAILED');
    expect(verified.codes).toContain('ARTIFACT_DIGEST_MISMATCH');
  });

  test('fails when the Ed25519 signature is altered', async () => {
    const root = temporaryRoot();
    const { result } = await emitted(root);
    result.envelope.proof.signature.value = encodeBase64(new Uint8Array(64).fill(3));
    result.envelope.proof.qr.signature = result.envelope.proof.signature.value;
    const verified = verifyEvidenceEnvelopeV1(result.envelope, { root_dir: root });

    expect(verified.integrity).toBe('FAILED');
    expect(verified.overall).toBe('FAILED');
    expect(verified.codes).toEqual([
      'SIGNATURE_INVALID',
      'CHECKPOINT_UNAVAILABLE',
      'PROOF_INVALID',
      'LIFECYCLE_STATE_UNKNOWN'
    ]);
  });

  test('fails closed when the trusted keyring directory is absent', async () => {
    const root = temporaryRoot();
    const { result } = await emitted(root);
    const isolatedRoot = temporaryRoot();
    const verified = verifyEvidenceEnvelopeV1(result.envelope, {
      root_dir: isolatedRoot
    });

    expect(verified.integrity).toBe('INDETERMINATE');
    expect(verified.codes).toContain('KEYRING_UNAVAILABLE');
  });

  test('distinguishes an unknown key from an unavailable keyring', async () => {
    const root = temporaryRoot();
    const { result } = await emitted(root);
    const isolatedRoot = temporaryRoot();
    fs.mkdirSync(path.join(isolatedRoot, 'vault', 'sovereign', 'keyring'), {
      recursive: true
    });
    const verified = verifyEvidenceEnvelopeV1(result.envelope, {
      root_dir: isolatedRoot
    });

    expect(verified.codes).toContain('KEY_UNKNOWN');
    expect(verified.codes).not.toContain('KEYRING_UNAVAILABLE');
  });

  test('does not trust a revoked signing key', async () => {
    const root = temporaryRoot();
    const { result } = await emitted(root);
    const descriptor = JSON.parse(fs.readFileSync(result.public_key_path, 'utf8'));
    descriptor.status = 'REVOKED';
    fs.writeFileSync(result.public_key_path, `${JSON.stringify(descriptor, null, 2)}\n`, 'utf8');
    const verified = verifyEvidenceEnvelopeV1(result.envelope, { root_dir: root });

    expect(verified.integrity).toBe('INDETERMINATE');
    expect(verified.codes).toContain('KEY_REVOKED');
  });

  test('fails closed on an invalid evidence envelope schema', () => {
    const verified = verifyEvidenceEnvelopeV1({ schema: 'unknown' });

    expect(verified.integrity).toBe('FAILED');
    expect(verified.overall).toBe('FAILED');
    expect(verified.codes).toEqual(['SCHEMA_INVALID']);
  });

  test('fails when an explicitly supplied checkpoint does not verify', async () => {
    const root = temporaryRoot();
    const { result } = await emitted(root);
    const verified = verifyEvidenceEnvelopeV1(result.envelope, {
      root_dir: root,
      checkpoint_verified: false
    });

    expect(verified.integrity).toBe('FAILED');
    expect(verified.codes).toContain('PROOF_INVALID');
  });

  test('reaches VERIFIED_ACTIVE only with key, proof, checkpoint, lifecycle and bytes', async () => {
    const root = temporaryRoot();
    const { request, result } = await emitted(root);
    const verified = verifyEvidenceEnvelopeV1(result.envelope, {
      root_dir: root,
      artifact_file_path: request.source_file_path,
      checkpoint_verified: true,
      lifecycle_state: 'ACTIVE'
    });

    expect(verified).toEqual({
      schema: 'arv.verification-result',
      schema_version: 1,
      integrity: 'VERIFIED',
      lifecycle: 'ACTIVE',
      artifact_match: 'MATCH',
      overall: 'VERIFIED_ACTIVE',
      codes: []
    });
  });
});
