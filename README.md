# verify-spec

Rules and verification library for Verify (license: Apache-2.0, planned; add the official license text before publishing).
Zero dependencies. Runs in Node 22+ and in browsers (Web Crypto, Ed25519).

Covers: handle normalization and profile URL parsing, lookalike skeletons, VID links, VID/DID keys and signed claims, key rotation with a delay, the `did:web` document, and `evaluateAccount` (what the extension shows).

    npm test
