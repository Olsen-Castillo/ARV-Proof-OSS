import fs from 'fs';
import os from 'os';
import path from 'path';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { emitSelfManagedFixtureV1 } from './public-test-fixture-v1';
import {
  createPortableProofManifestV1,
  portableEnvelopeDigestV1,
  verifyPortableProofManifestV1
} from './portable-proof-manifest-v1';

const roots: string[] = [];

function root(): string {
  const value = fs.mkdtempSync(
    path.join(os.tmpdir(), 'arv-portable-proof-')
  );
  roots.push(value);
  return value;
}

function pair(
  fill = 11
): nacl.SignKeyPair {
  return nacl.sign.keyPair.fromSeed(
    new Uint8Array(32).fill(fill)
  );
}

function secret(
  fill = 11
): string {
  return encodeBase64(
    pair(fill).secretKey
  );
}

afterEach(() => {
  while (roots.length > 0) {
    const value = roots.pop();

    if (value) {
      fs.rmSync(
        value,
        { recursive: true, force: true }
      );
    }
  }
});

describe('ARV Portable Proof Manifest V1', () => {
  test('keeps the protocol schema minimal and synchronized', () => {
    const schemaPath = path.join(
      __dirname,
      '..',
      '..',
      '..',
      'protocol',
      'schemas',
      'v1',
      'portable-proof-manifest.schema.json'
    );

    const schema = JSON.parse(
      fs.readFileSync(schemaPath, 'utf8')
    );

    expect(schema.properties.schema.const).toBe('arv.portable-proof-manifest');
    expect(schema.properties.schema_version.const).toBe(1);
    expect(schema.additionalProperties).toBe(false);

    const serialized = JSON.stringify(schema);

    for (const forbidden of [
      'claims',
      'participants',
      'asserted_by',
      'subject',
      'attributes',
      'jurisdiction',
      'occurred_at',
      'qr_payload'
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  test('creates a signed whole-envelope commitment', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const manifest = createPortableProofManifestV1(
      fixture.result.envelope,
      secret()
    );

    expect(manifest.schema).toBe('arv.portable-proof-manifest');
    expect(manifest.validation_id).toBe(
      fixture.result.envelope.validation_id
    );
    expect(manifest.envelope_digest).toEqual({
      algorithm: 'SHA-256',
      canonicalization: 'ARV-JSON-v1',
      value: portableEnvelopeDigestV1(
        fixture.result.envelope
      )
    });
    expect(manifest.artifact_digest).toEqual(
      fixture.result.envelope.artifact.digest
    );
    expect(manifest.signature.algorithm).toBe('Ed25519');
    expect(manifest.signature.value.length).toBeGreaterThan(0);
  });

  test('verifies the portable manifest signature independently', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const manifest = createPortableProofManifestV1(
      fixture.result.envelope,
      secret()
    );

    const verified = verifyPortableProofManifestV1(
      manifest,
      encodeBase64(pair().publicKey)
    );

    expect(verified.state).toBe('VERIFIED');
    expect(verified.signature_valid).toBe(true);
    expect(verified.envelope_match).toBeNull();
    expect(verified.artifact_match).toBeNull();
    expect(verified.officiality).toBe('NOT_EVALUATED');
    expect(verified.envelope_integrity).toBe('NOT_EVALUATED');
    expect(verified.material_truth).toBe('NOT_EVALUATED');
    expect(verified.codes).toEqual([]);
  });

  test('matches a later full envelope and artifact disclosure', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const manifest = createPortableProofManifestV1(
      fixture.result.envelope,
      secret()
    );

    const verified = verifyPortableProofManifestV1(
      manifest,
      encodeBase64(pair().publicKey),
      {
        full_envelope: fixture.result.envelope,
        artifact_file_path: fixture.source_file_path
      }
    );

    expect(verified.state).toBe('VERIFIED');
    expect(verified.signature_valid).toBe(true);
    expect(verified.envelope_match).toBe(true);
    expect(verified.artifact_match).toBe(true);
    expect(verified.codes).toEqual([]);
  });

  test('fails when a signed manifest field is altered', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const manifest = createPortableProofManifestV1(
      fixture.result.envelope,
      secret()
    );

    const altered = JSON.parse(
      JSON.stringify(manifest)
    );

    altered.recorded_at = '2026-08-22T00:00:00Z';

    const verified = verifyPortableProofManifestV1(
      altered,
      encodeBase64(pair().publicKey)
    );

    expect(verified.state).toBe('FAILED');
    expect(verified.signature_valid).toBe(false);
    expect(verified.codes).toContain('SIGNATURE_INVALID');
  });

  test('detects a different full envelope', () => {
    const runtime = root();

    const first = emitSelfManagedFixtureV1(
      runtime,
      {
        uuid: '11111111-1111-4111-8111-111111111111'
      }
    );

    const second = emitSelfManagedFixtureV1(
      runtime,
      {
        uuid: '22222222-2222-4222-8222-222222222222',
        content: 'different envelope content'
      }
    );

    const manifest = createPortableProofManifestV1(
      first.result.envelope,
      secret()
    );

    const verified = verifyPortableProofManifestV1(
      manifest,
      encodeBase64(pair().publicKey),
      {
        full_envelope: second.result.envelope
      }
    );

    expect(verified.state).toBe('FAILED');
    expect(verified.envelope_match).toBe(false);
    expect(verified.codes).toContain('ENVELOPE_DIGEST_MISMATCH');
  });

  test('detects artifact byte mismatch', () => {
    const runtime = root();
    const fixture = emitSelfManagedFixtureV1(runtime);
    const manifest = createPortableProofManifestV1(
      fixture.result.envelope,
      secret()
    );

    const alteredArtifact = path.join(
      runtime,
      'tampered.bin'
    );

    fs.writeFileSync(
      alteredArtifact,
      'tampered artifact bytes',
      'utf8'
    );

    const verified = verifyPortableProofManifestV1(
      manifest,
      encodeBase64(pair().publicKey),
      {
        artifact_file_path: alteredArtifact
      }
    );

    expect(verified.state).toBe('FAILED');
    expect(verified.artifact_match).toBe(false);
    expect(verified.codes).toContain('ARTIFACT_DIGEST_MISMATCH');
  });

  test('allows artifact digest nondisclosure without weakening manifest signature', () => {
    const fixture = emitSelfManagedFixtureV1(root());

    const manifest = createPortableProofManifestV1(
      fixture.result.envelope,
      secret(),
      {
        include_artifact_digest: false
      }
    );

    expect(manifest.artifact_digest).toBeNull();

    const signatureOnly = verifyPortableProofManifestV1(
      manifest,
      encodeBase64(pair().publicKey)
    );

    expect(signatureOnly.state).toBe('VERIFIED');
    expect(signatureOnly.signature_valid).toBe(true);

    const artifactRequested = verifyPortableProofManifestV1(
      manifest,
      encodeBase64(pair().publicKey),
      {
        artifact_file_path: fixture.source_file_path
      }
    );

    expect(artifactRequested.state).toBe('INDETERMINATE');
    expect(artifactRequested.artifact_match).toBeNull();
    expect(artifactRequested.codes).toContain(
      'ARTIFACT_DIGEST_UNDISCLOSED'
    );
  });

  test('omits sensitive envelope fields while committing to the whole envelope', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const envelope = JSON.parse(
      JSON.stringify(fixture.result.envelope)
    );

    envelope.profile.claims.secret = 'CLAIM_SECRET_PORTABLE';
    envelope.artifact.name = 'SECRET_FILE_PORTABLE.pdf';
    envelope.assertion.asserted_by = {
      type: 'PERSON',
      name: 'ASSERTED_SECRET_PORTABLE'
    };
    envelope.assertion.subject = {
      type: 'PERSON',
      name: 'SUBJECT_SECRET_PORTABLE'
    };
    envelope.assertion.participants = [
      {
        role: 'WITNESS',
        entity: {
          type: 'PERSON',
          name: 'PARTICIPANT_SECRET_PORTABLE'
        }
      }
    ];
    envelope.assertion.jurisdiction = 'JURISDICTION_SECRET_PORTABLE';
    envelope.assertion.attributes = {
      note: 'ATTRIBUTE_SECRET_PORTABLE'
    };

    const manifest = createPortableProofManifestV1(
      envelope,
      secret()
    );

    const serialized = JSON.stringify(manifest);

    for (const marker of [
      'CLAIM_SECRET_PORTABLE',
      'SECRET_FILE_PORTABLE.pdf',
      'ASSERTED_SECRET_PORTABLE',
      'SUBJECT_SECRET_PORTABLE',
      'PARTICIPANT_SECRET_PORTABLE',
      'JURISDICTION_SECRET_PORTABLE',
      'ATTRIBUTE_SECRET_PORTABLE'
    ]) {
      expect(serialized).not.toContain(marker);
    }

    expect(serialized).not.toContain(
      envelope.proof.signature.value
    );

    expect(serialized).not.toContain(
      envelope.proof.qr.payload
    );

    expect(manifest.envelope_digest.value).toBe(
      portableEnvelopeDigestV1(envelope)
    );
  });

  test('rejects a portable signer that does not match the envelope signer fingerprint', () => {
    const fixture = emitSelfManagedFixtureV1(root());

    expect(() => createPortableProofManifestV1(
      fixture.result.envelope,
      secret(12)
    )).toThrow(
      'PORTABLE_SIGNER_FINGERPRINT_MISMATCH'
    );
  });
});
