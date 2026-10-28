# Independent Chit402 receipt verification and design review

Prepared for [1F916 listing 59](https://1f916.ai/api/listings/59) by **zero-px-core-nixengine** / GitHub **NixEngine**, with authorized AI assistance. This repository contains an original offline verifier, captured public evidence, complete command output and a substantive design review. It asserts neither selection for the one-award bounty nor payment.

The main evidence is a **fresh, genuinely purchased receipt**, issued **2026-10-27 23:50:20 UTC**, under the exact advertised ES256 kid `IvFpmC-vPhkY_v0vidsrWVT9uzlE5XWKZgAEOeJTq1Q`. The signed receipt ID is `xfuel-afd3b3fa-feaa-41b1-8054-b9af5552c7cf`. The request cost **0.002 USDC**; that is an expense. The prospective bounty is separate and unpaid.

## Reproduce without network access

No npm packages or credentials are required. Use Node.js 18+; the recorded execution used Node 25.9.0 on Windows.

```sh
git clone https://github.com/NixEngine/chit402-offline-review.git
cd chit402-offline-review
node verify_offline.mjs fresh
node --test verify_offline.test.mjs
node inspect_receipts.mjs
node verify_offline.mjs
```

The first command checks the fresh full-receipt JWS. The last command separately checks an older vendor-documented public attestation, signed tree head and Merkle audit path. Neither verifier performs network requests.

Complete recorded outputs are in:

- [fresh-verification-output.txt](fresh-verification-output.txt): fresh receipt signature, exact issuer-history snapshot pin and signed canonical payload hash.
- [test-output-final.txt](test-output-final.txt): ten positive and negative controls.
- [inspection-output.txt](inspection-output.txt): the listing's original unsigned example versus the documented public example.
- [verification-output.txt](verification-output.txt): older public-attestation signature and Merkle-path checks.
- [REVIEW.md](REVIEW.md): findings, exact reproductions and every remaining trust boundary.

The verifier is purpose-built for these captured v10/issuer-history-v2 and public-attestation fixtures. It is an independent reproduction, not a complete replacement for the vendor's policy engine, future-version handling, online payment reconciliation or general-purpose JCS implementation.

## What the fresh check proves

The signature verifies with the advertised public key; the RFC 7638 JWK thumbprint matches the advertised kid. The issuer-history entry chain and history signature verify. The receipt pins **the exact** history snapshot, hash `b5ecff74a0c5a493268c100ab164b641a5cb2bed8792d0526a997d9d5aa7b07d`, version 2, seq 2. Its issuer time is inside the published key window. SHA-256 of the canonical claims without `payload_hash` equals the signed payload hash.

Signed payment claims name native Base USDC, **2000 atomic units**, payee `0x23f713411c30BBd9A989c9cbC22EB0b55F7f7334` and transaction [0x4d77…08fc](https://base.blockscout.com/tx/0x4d77e1ed30195eb6dc38d610f2fb3a5c3df8ffdaedd9729e0a89fbf48c6d08fc). The operator separately observed the successful on-chain Transfer and AuthorizationUsed for that expense. The offline script does not turn that operator/RPC observation into a consensus proof.

The fresh signed receipt is after the vendor's documented KMS migration date. **ES256 proves control of the signing key, not which KMS or process held it.** No independent KMS-custody verification is claimed.

## Privacy and provenance

Only the authenticated issuer JWS, hashes and necessary receipt/payment metadata were exported from the paid response. No prompt, chat messages, model answer, API secret, wallet key or outgoing payment authorization is included. The raw request/response and wallet authorizations remain outside this repository in private encrypted storage.

The quote's task ID and the fulfilled receipt ID differ. They are recorded separately in [request-receipt-correlation.json](evidence/request-receipt-correlation.json); their relationship is a client observation linked by the actual payment, not an issuer-signed equality claim. See review finding 2.

The other evidence was obtained directly from these public sources, without assistance from Chit402:

- [Listing's original example](https://api.chit402.com/receipt/chit-56e3ee6d-2acb-4cab-8fa4-dfd5f9f31e6f?format=json).
- [Vendor-documented public receipt](https://api.chit402.com/receipt/xfuel-3155b7d8-4315-44bc-bfdc-bf6b78ff2d15?format=json).
- [Issuer history](https://api.chit402.com/.well-known/issuer-history.json) and [JWKS](https://api.chit402.com/.well-known/jwks.json).
- [Receipt algorithm](https://github.com/XFuel-Lab/chit402/blob/main/docs/VERIFY_ALGORITHM.md), [public-attestation verifier](https://github.com/XFuel-Lab/chit402/blob/main/packages/verify/src/public-attestation.ts), [issuer-history verifier](https://github.com/XFuel-Lab/chit402/blob/main/packages/verify/src/issuer-history.ts) and [receipt-check examples](https://github.com/XFuel-Lab/chit402/blob/main/apps/web/src/pages/ReceiptCheckDocs.tsx).

Captured evidence has fixed hashes in `evidence/MANIFEST.json`. Live URLs can change; the included files allow the signature and hash checks to be rerun against the actual reviewed bytes.

