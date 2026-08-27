import fs from 'fs';
import os from 'os';
import path from 'path';
import { emitSelfManagedFixtureV1 } from './public-test-fixture-v1';

const roots: string[] = [];

function root(): string {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), 'arv-public-emitter-'));
  roots.push(value);
  return value;
}

afterEach(() => {
  while (roots.length > 0) {
    const value = roots.pop();
    if (value) fs.rmSync(value, { recursive: true, force: true });
  }
});

describe('ARV public self-managed emitter', () => {
  test('emits an ARV-SM proof with privacy-minimal defaults', () => {
    const runtime = root();
    const fixture = emitSelfManagedFixtureV1(runtime);
    const envelope = fixture.result.envelope;

    expect(envelope.validation_id).toMatch(/^ARV-SM-2026-/);
    expect(envelope.registration.authority).toBe('SELF_MANAGED');
    expect(envelope.registration.system).toBe('ARV Proof OSS');
    expect(envelope.registration.ledger_position).toBeNull();
    expect(envelope.profile.claims).toEqual({});
    expect(envelope.assertion.attributes).toEqual({});
    expect(envelope.assertion.participants).toEqual([]);
    expect('subject' in envelope.assertion).toBe(false);
    expect('jurisdiction' in envelope.assertion).toBe(false);
    expect('occurred_at' in envelope.assertion).toBe(false);
    expect('name' in envelope.artifact).toBe(false);
    expect(fixture.result.official_status).toBe('NOT_EVALUATED');
  });

  test('reuses one sovereign public-key descriptor across multiple emissions', () => {
    const runtime = root();
    const first = emitSelfManagedFixtureV1(runtime, {
      uuid: '11111111-1111-4111-8111-111111111111'
    });
    const second = emitSelfManagedFixtureV1(runtime, {
      uuid: '22222222-2222-4222-8222-222222222222',
      content: 'second public test evidence bytes'
    });

    expect(first.result.envelope.validation_id).not.toBe(
      second.result.envelope.validation_id
    );
    expect(first.result.envelope.proof.signature.public_key_fingerprint).toBe(
      second.result.envelope.proof.signature.public_key_fingerprint
    );

    const keyring = path.join(runtime, 'vault', 'sovereign', 'keyring');
    const envelopes = path.join(runtime, 'vault', 'sovereign', 'envelopes');
    expect(fs.readdirSync(keyring).filter((name) => name.endsWith('.json'))).toHaveLength(1);
    expect(fs.readdirSync(envelopes).filter((name) => name.endsWith('.json'))).toHaveLength(2);
  });
});
