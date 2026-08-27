import fs from 'fs';
import path from 'path';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { emitSelfManagedEvidenceV1, SelfManagedEmissionResultV1 } from './self-managed-emitter-v1';

export interface PublicFixtureOptionsV1 {
  recorded_at?: string;
  uuid?: string;
  key_fill?: number;
  content?: string;
}

export interface PublicFixtureEmissionV1 {
  source_file_path: string;
  result: SelfManagedEmissionResultV1;
}

export function emitSelfManagedFixtureV1(
  rootDir: string,
  options: PublicFixtureOptionsV1 = {}
): PublicFixtureEmissionV1 {
  const recordedAt = options.recorded_at ?? '2026-08-21T16:00:00Z';
  const uuid = options.uuid ?? '11111111-1111-4111-8111-111111111111';
  const keyFill = options.key_fill ?? 11;
  const content = options.content ?? 'public test evidence bytes';

  const source = path.join(rootDir, 'incoming', uuid + '.bin');
  fs.mkdirSync(path.dirname(source), { recursive: true });
  fs.writeFileSync(source, content, 'utf8');

  const pair = nacl.sign.keyPair.fromSeed(
    new Uint8Array(32).fill(keyFill)
  );

  const result = emitSelfManagedEvidenceV1(
    {
      source_file_path: source,
      artifact: {
        kind: 'BINARY',
        media_type: 'application/octet-stream'
      },
      signing_secret_key_base64: encodeBase64(pair.secretKey)
    },
    {
      root_dir: rootDir,
      now: () => new Date(recordedAt),
      uuid: () => uuid
    }
  );

  return {
    source_file_path: source,
    result
  };
}
