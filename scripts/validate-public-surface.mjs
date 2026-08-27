import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = process.cwd();

const arvDir = path.join(root, 'reference', 'typescript', 'arv');
const schemaDir = path.join(root, 'protocol', 'schemas', 'v1');

function walk(directory) {
  const files = [];

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      if (entry.name === '.git') continue;
      files.push(...walk(full));
    }

    if (entry.isFile()) {
      files.push(full);
    }
  }

  return files;
}

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

const requiredFiles = [
  'LICENSE',
  'LICENSES/AGPL-3.0-only.txt',
  'LICENSES/Apache-2.0.txt',
  'LICENSES/SCOPE.md',
  'README.md',
  'CONTRIBUTING.md',
  'SECURITY.md',
  'NOTICE.md',
  'TRADEMARKS.md',
  'BRAND.md',
  'FORK_POLICY.md',
  'portal/README.md',
  'portal/index.html',
  'portal/styles.css',
  'portal/app.js',
  'reference/typescript/arv/self-managed-emitter-v1.ts',
  'reference/typescript/arv/portable-proof-manifest-v1.ts',
  'protocol/schemas/v1/portable-proof-manifest.schema.json',
  'vault/sovereign/README.md',
  'vault/portable/README.md'
];

for (const relative of requiredFiles) {
  if (!fs.existsSync(path.join(root, relative))) {
    fail('REQUIRED_FILE_MISSING:' + relative);
  }
}

const portalCodeFiles = [
  'portal/index.html',
  'portal/styles.css',
  'portal/app.js'
];

const portalCode = portalCodeFiles
  .map((relative) => fs.readFileSync(path.join(root, relative), 'utf8'))
  .join('\n');

const forbiddenPortalNetwork = [
  ['FETCH', /\bfetch\s*\(/i],
  ['XHR', /\bXMLHttpRequest\b/i],
  ['WEBSOCKET', /\bWebSocket\b/i],
  ['SEND_BEACON', /\bsendBeacon\b/i],
  ['REMOTE_HTTP', /https?:\/\//i]
];

for (const [name, pattern] of forbiddenPortalNetwork) {
  if (pattern.test(portalCode)) {
    fail('PORTAL_NETWORK_SURFACE_FORBIDDEN:' + name);
  }
}

const tsFiles = fs.readdirSync(arvDir)
  .filter((name) => name.endsWith('.ts'));

const testFiles = tsFiles
  .filter((name) => name.endsWith('.test.ts'));

if (tsFiles.length !== 38) {
  fail('UNEXPECTED_TYPESCRIPT_FILE_COUNT:' + tsFiles.length);
}

if (testFiles.length !== 17) {
  fail('UNEXPECTED_TEST_FILE_COUNT:' + testFiles.length);
}

const schemaFiles = fs.readdirSync(schemaDir)
  .filter((name) => name.endsWith('.json'));

if (schemaFiles.length !== 51) {
  fail('UNEXPECTED_SCHEMA_FILE_COUNT:' + schemaFiles.length);
}

const rawIdPrefix =
  'https://raw.githubusercontent.com/' +
  'Olsen-Castillo/ARV-Proof-OSS/main/' +
  'protocol/schemas/v1/';

const allowedHttpsSchemaHosts = new Set([
  'arv.example',
  'schemas.arv.example'
]);

function validSchemaId(value) {
  if (typeof value !== 'string') return false;

  if (value.startsWith('urn:arv:schema:')) {
    return true;
  }

  if (value.startsWith(rawIdPrefix)) {
    return true;
  }

  let parsed = null;

  try {
    parsed = new URL(value);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:') {
    return false;
  }

  return allowedHttpsSchemaHosts.has(parsed.hostname);
}

for (const name of schemaFiles) {
  const full = path.join(schemaDir, name);
  const text = fs.readFileSync(full, 'utf8');
  let parsed = null;

  try {
    parsed = JSON.parse(text);
  } catch {
    fail('SCHEMA_JSON_INVALID:' + name);
  }

  if (!parsed || typeof parsed.$id !== 'string') {
    fail('SCHEMA_ID_MISSING:' + name);
  }

  if (
    parsed &&
    typeof parsed.$id === 'string' &&
    !validSchemaId(parsed.$id)
  ) {
    fail('SCHEMA_ID_NOT_ALLOWED:' + name);
  }
}

const textExtensions = new Set([
  '.ts', '.tsx', '.js', '.mjs', '.cjs',
  '.json', '.md', '.yml', '.yaml', '.txt', '.go'
]);

const forbidden = [
  ['INTERNAL_MILESTONE_NAMESPACE', /\bTECH(?:8[1-9]|9[0-2])(?:_[A-Z0-9_]+)?\b/i],
  ['LEGACY_DOMAIN', /arvseal\\.com/i],
  ['LEGACY_AUTHORITY', /Reality Validation Authority/i],
  ['LEGACY_SYSTEM', /A System by Intelligence Olsen/i],
  ['LEGACY_FORGED', /FORGED-LRO/i],
  ['PRIVATE_CLIENT_FIXTURE', /CLIENT-001/i],
  ['PAYMENT_PROVIDER', /checkout\\.session|stripe/i],
  ['HISTORICAL_EMITTER_IMPORT', /evidence-emitter-v1/i],
  ['HOSTED_KEYRING_PATH', /public[\\\\/]vault[\\\\/]keyring/i]
];

const selfPath = path.resolve(
  fileURLToPath(import.meta.url)
);

for (const file of walk(root)) {
  if (path.resolve(file) === selfPath) continue;

  const relative = path
    .relative(root, file)
    .split(path.sep)
    .join('/');
  if (relative === 'package-lock.json') continue;

  const extension = path.extname(file).toLowerCase();

  if (!textExtensions.has(extension)) continue;

  const text = fs.readFileSync(file, 'utf8');

  for (const [name, pattern] of forbidden) {
    if (pattern.test(text)) {
      fail('FORBIDDEN_PUBLIC_SURFACE:' + name + ':' + relative);
    }
  }
}

const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, 'package.json'), 'utf8')
);

if (packageJson.name !== 'arv-proof-oss') {
  fail('PACKAGE_NAME_INVALID');
}

if (packageJson.version !== '0.2.1') {
  fail('PACKAGE_VERSION_INVALID');
}

if (packageJson.private !== true) {
  fail('PACKAGE_MUST_REMAIN_PRIVATE_FROM_NPM');
}

const runtimeDependencies = Object.keys(
  packageJson.dependencies ?? {}
).sort();

if (
  JSON.stringify(runtimeDependencies) !==
  JSON.stringify(['tweetnacl', 'tweetnacl-util'])
) {
  fail('RUNTIME_DEPENDENCY_BOUNDARY_INVALID');
}

for (const forbiddenDependency of [
  'next',
  'react',
  'react-dom',
  'jspdf',
  'pdf-lib',
  'qrcode',
  '@stablelib/base64'
]) {
  if (
    packageJson.dependencies?.[forbiddenDependency] ||
    packageJson.devDependencies?.[forbiddenDependency]
  ) {
    fail('PORTAL_DEPENDENCY_FORBIDDEN:' + forbiddenDependency);
  }
}

if (!process.exitCode) {
  console.log('PUBLIC_SURFACE_VALIDATION_PASS');
}

