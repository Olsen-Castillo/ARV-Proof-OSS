# ARV Proof OSS Static Demo

This directory contains a zero-dependency browser demonstration of one narrow portable-verification workflow.

The demo can:

- load a Portable Proof Manifest V1 JSON file locally;
- display its public verification fields;
- load an artifact locally;
- compute the artifact SHA-256 digest in the browser;
- compare that digest with a disclosed manifest artifact digest.

The selected files remain in the local browser process. The demo contains no network request code.

## Important boundary

This static demo is not the complete ARV verifier.

It does not independently verify:

- the Ed25519 manifest signature;
- the whole-envelope commitment;
- the internal evidence-envelope signature;
- trust-registry authorization;
- official ARV status;
- material truth.

Use the reference implementation and test suite for cryptographic verification.

## Run

Open `index.html` in a modern browser.

If the browser disables Web Crypto for local files, serve this directory through any local static HTTP server. No remote service is required.

