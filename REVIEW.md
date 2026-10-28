# Receipt and verifier review

This is a design-improvement review with reproducible observations. No vulnerability, exploitation, fraud, KMS compromise or entitlement to payment is claimed.

## 1. The listing's example no longer supplies a receipt attestation to a stranger

Reproduction, using only the bundled public snapshots:

```sh
node inspect_receipts.mjs
```

For the listing's example `xfuel-56e3ee6d-2acb-4cab-8fa4-dfd5f9f31e6f`, the recorded output reports `unsignedShell:true`, `hasFullReceiptJws:false`, `hasPublicAttestation:false` and `signedTreeHead:true`. The original HTTP request was:

```sh
curl --fail --silent --show-error 'https://api.chit402.com/receipt/chit-56e3ee6d-2acb-4cab-8fa4-dfd5f9f31e6f?format=json'
```

A signed tree head authenticates a root; it does not authenticate this shell's displayed amount and payee. The vendor's current algorithm explicitly describes this privacy behavior, so this is not a signature bypass.

Expected for a stranger following this particular assignment: the linked example supplies enough public signed evidence to perform its signature step without contacting the issuer. Observed: it supplies a shell and an inclusion proof, but no receipt/public-field attestation. We independently found the newer public example in the vendor's own documentation, then obtained a fresh owner receipt through a real bounded paid call.

Recommendation: maintain a stable, explicitly public verification fixture linked directly from the work specification. Publish its evidence kind, kid, issuance time, expected capability-specific verdict and snapshot digest. A privacy-preserving shell should remain a shell, with a machine-readable route to an opted-in attestation when one exists. Do not solve this by marking the shell as signed.

## 2. Quote and fulfilled-receipt identities need an explicit correlation contract

Exact observed pair:

- Quote task ID: `xfuel-71387e12-0f2e-49cc-ac99-c595c9af64c0`.
- Paid response body, response task header and verified issuer JWS: `xfuel-afd3b3fa-feaa-41b1-8054-b9af5552c7cf`.
- The signed payment reference is the actual transaction `base:0x4d77e1ed30195eb6dc38d610f2fb3a5c3df8ffdaedd9729e0a89fbf48c6d08fc`, for 2000 atomic units.

The correlation snapshot records the request digest and transport metadata without revealing the request or model answer. Reproduce the signed half:

```sh
node verify_offline.mjs fresh
```

Its output deliberately prints both IDs. The initial exporter stopped when it assumed they were equal; it was corrected to require agreement between the response body, response header and signed receipt, with the quote ID retained separately.

This is **not** proof of a substitution attack: the two identifiers may intentionally address different lifecycle objects. It is a concrete auditability and client-integration issue when their relationship is not explicit. In this signed receipt, `fulfillment.intent.resource` and `fulfillment.intent.intent_id` are null; the client request digest is not asserted here as an issuer-signed quote mapping.

Recommendation: document the lifecycle distinction and return a stable mapping field. Where cryptographic quote-to-fulfillment correlation is a product promise, include the quote identifier and canonical request/quote digest in the signed fulfillment claims. Preserve an explicit distinction between quote ID, execution ID, receipt ID and payment transaction. Do not silently relabel one as another.

## 3. KMS provenance and signature validity are different facts

The advertised kid matches the JWKS thumbprint and validates both captured receipt contexts. The public issuer history starts that key's window on 4 September; the receipt-check documentation says production signing moved to cloud KMS on 20 October without changing the kid. The older public attestation was issued on 19 October. The newly purchased receipt is issued on 27 October.

```sh
node inspect_receipts.mjs
node verify_offline.mjs fresh
```

These commands reproduce the dates and valid signatures. They cannot distinguish a signature made by KMS from one made by another holder of the same private key. The fresh timestamp resolves the old example's temporal limitation; it does not prove the operator's custody statement.

Recommendation: expose custody provenance as separately classified evidence, with its stated effective date and source. Keep a field such as `kmsCustodyIndependentlyVerified:false` separate from `issuerSignature:true`. A custody migration without rekeying should not be presented as a cryptographically observable key rotation. If stronger provenance is needed, define and independently witness that evidence rather than inferring it from ES256.

## 4. Preserve fail-closed policy while making offline evidence replay practical

The reviewed vendor public-attestation parser separates receipt/public/history/head contexts, enforces exact claim allowlists and canonical payloads, and rejects an attestation used as another object type. Its issuer-history code pins a trusted key, checks chain entries and rejects status/window regressions. These are useful boundaries and should be retained.

The current verifier README says its full verdict needs online log/anchor/payment checks; a local signed file alone remains partial when those cannot be checked. That is the correct distinction, rather than an offline claim that consensus or inference correctness was established.

Recommendation: add an evidence-capsule interface that records exact downloaded history, log paths, heads, RPC observations, fetch times and verifier version, then replays those checks offline with a verdict that still labels RPC/issuer trust. This repository demonstrates a small independent capsule: the fresh receipt signature, exact history pin and payload hash are separate from the older public receipt's Merkle proof. It never combines those two receipts into one full-success verdict.

## Remaining trust, explicitly enumerated

1. The binding of the advertised kid to Chit402 came from the assignment and the issuer's HTTPS material, not an independently audited legal identity.
2. HTTPS, the local operating system and Node's cryptographic implementation are trusted for download/execution. The offline cryptographic checks do not need the issuer to remain online.
3. Issuer-history hash chains and signatures prove consistency of the captured document. They do not alone prove globally unique history or absence of an issuer-signed fork; an external witness/gossip system would be separate evidence.
4. `iat`, key-window declarations, custody claims and signed receipt facts are statements authenticated by the issuer. The signature does not independently prove the truth of every statement.
5. KMS custody is operator-attested. No AWS account policy, key-residency attestation or independent hardware evidence was available or inferred.
6. The fresh receipt's output is a hash commitment. We neither disclose nor verify semantic correctness of the model answer, and we do not claim evidence of a particular private reasoning process.
7. The offline run does not validate Base/Solana consensus, fresh anchor finality, or the real-world quality of work. The operator's separate transaction observation is identified as such.
8. The claim/payment/request/receipt identifier mapping is recorded according to its actual evidence source. A client-side correlation record is not an issuer signature over that mapping.
9. The small independent verifier covers these fixtures and the stated checks. It does not claim full vendor-version compatibility, all malformed-input cases, or a general audit of the gateway.

## Negative controls and results

The ten controls cover the real fresh receipt, the older public receipt, a modified JWS payment claim, an unsigned displayed-amount change, a modified Merkle sibling, an unsigned shell, a changed history chain, a wrong exact history snapshot, and cross-context substitution. Complete output is retained in `test-output-final.txt`. All ten passed; those are local reproducibility checks, not a maintainer's acceptance or bounty award.

No paid request was replayed to produce this review, no additional authorization was signed by this reviewer, and no comments/posts/votes/tags were purchased. The task's one-USDC award remains the funder's decision under its published terms.

