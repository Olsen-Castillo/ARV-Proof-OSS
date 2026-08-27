import fs from 'fs';
import os from 'os';
import path from 'path';
import { emitSelfManagedFixtureV1 } from './public-test-fixture-v1';
import { projectEvidenceEnvelopeMinimalV1 } from './public-projection-v1';

const roots: string[] = [];

function root(): string {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), 'arv-public-projection-'));
  roots.push(value);
  return value;
}

afterEach(() => {
  while (roots.length > 0) {
    const value = roots.pop();
    if (value) fs.rmSync(value, { recursive: true, force: true });
  }
});

describe('ARV minimal public projection', () => {
  test('does not disclose sensitive assertion material or raw proof values', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const envelope = JSON.parse(JSON.stringify(fixture.result.envelope));

    envelope.profile.claims.secret = 'CLAIM_SECRET_PUBLIC';
    envelope.artifact.name = 'SECRET_FILE_PUBLIC.pdf';
    envelope.assertion.asserted_by = { type: 'PERSON', name: 'ASSERTED_SECRET_PUBLIC' };
    envelope.assertion.subject = { type: 'PERSON', name: 'SUBJECT_SECRET_PUBLIC' };
    envelope.assertion.participants = [
      { role: 'WITNESS', entity: { type: 'PERSON', name: 'PARTICIPANT_SECRET_PUBLIC' } }
    ];
    envelope.assertion.jurisdiction = 'JURISDICTION_SECRET_PUBLIC';
    envelope.assertion.attributes = { note: 'ATTRIBUTE_SECRET_PUBLIC' };

    const projection = projectEvidenceEnvelopeMinimalV1(envelope);
    const serialized = JSON.stringify(projection);

    for (const marker of [
      'CLAIM_SECRET_PUBLIC',
      'SECRET_FILE_PUBLIC.pdf',
      'ASSERTED_SECRET_PUBLIC',
      'SUBJECT_SECRET_PUBLIC',
      'PARTICIPANT_SECRET_PUBLIC',
      'JURISDICTION_SECRET_PUBLIC',
      'ATTRIBUTE_SECRET_PUBLIC'
    ]) {
      expect(serialized).not.toContain(marker);
    }

    expect(serialized).not.toContain(fixture.result.envelope.proof.signature.value);
    expect(serialized).not.toContain(fixture.result.envelope.proof.qr.payload);
    expect(projection.disclosure_mode).toBe('MINIMAL');
    expect(projection.namespace).toBe('SELF_MANAGED');
  });

  test('classifies a backward-compatible legacy identifier without conferring officiality', () => {
    const fixture = emitSelfManagedFixtureV1(root());
    const envelope = JSON.parse(JSON.stringify(fixture.result.envelope));
    envelope.validation_id = 'ARV-2026-000001';
    envelope.proof.verification_url = 'urn:arv:verify:ARV-2026-000001';
    const projection = projectEvidenceEnvelopeMinimalV1(envelope);
    expect(projection.namespace).toBe('LEGACY_MANAGED');
    expect(projection.officiality).toBe('NOT_EVALUATED');
  });
});
