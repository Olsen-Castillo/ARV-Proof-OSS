# Contributing to ARV Proof OSS

Contributions that improve correctness, interoperability, security, portability, documentation, or test coverage are welcome.

## Development checks

Before submitting a change, run:

```bash
npm ci
npm run validate:public
npm run typecheck
npm test
go test ./reference/go/...
go vet ./reference/go/...
```

## Keep changes narrow

A pull request should explain:

- what changed;
- why the change is needed;
- compatibility consequences;
- whether canonical bytes, identifiers, signatures, or protocol semantics change;
- security and privacy consequences;
- tests performed.

## Protocol compatibility

Changes to canonicalization, signing payloads, domain separators, schema identifiers, validation identifiers, trust semantics, or signed fields can break interoperability even when the source change appears small.

Treat cryptographic byte changes as protocol changes and document them explicitly.

## Evidence boundaries

Do not describe cryptographic validity as proof of material truth.

Do not describe a self-managed or independently generated proof as official ARV solely because it uses compatible code, identifiers, schemas, or signatures.

## Security and private data

Never commit production private keys, access tokens, credentials, confidential evidence, private customer data, or secret operational infrastructure.

Potential vulnerabilities should follow `SECURITY.md`.

## License scope

Contributions to reference implementation and tooling are accepted under the repository AGPL-3.0-only scope unless a file states otherwise.

Protocol and schema contributions under `protocol/` are accepted under Apache-2.0.

By contributing, you represent that you have the right to submit the contribution under the applicable repository license.

