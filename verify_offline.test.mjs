import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {loadEvidence,verifyPublicReceipt,verifyFreshReceipt} from './verify_offline.mjs';
const clone=()=>structuredClone(loadEvidence());
test('captured live public receipt verifies offline',()=>{const e=clone();const r=verifyPublicReceipt(e.receipt,e.history,e.jwks);assert.equal(r.verdict,'OFFLINE_PUBLIC_ATTESTATION_VERIFIED');assert.equal(r.networkRequests,0);});
test('changing signed JWS payload fails its signature',()=>{const e=clone(),parts=e.receipt.public_attestation.jws.split('.');const payload=Buffer.from(parts[1],'base64url').toString().replace('"settled_amount":"2000"','"settled_amount":"2001"');parts[1]=Buffer.from(payload).toString('base64url');e.receipt.public_attestation.jws=parts.join('.');assert.throws(()=>verifyPublicReceipt(e.receipt,e.history,e.jwks),/JWS_SIGNATURE_INVALID/);});
test('changing unsigned display is detected despite unchanged valid signature',()=>{const e=clone();e.receipt.amount_settled='2001';assert.throws(()=>verifyPublicReceipt(e.receipt,e.history,e.jwks),/UNSIGNED_DISPLAY_MISMATCH/);});
test('altered Merkle sibling cannot retain the signed root',()=>{const e=clone();e.receipt.inclusion.proof[0].hash='0'.repeat(64);assert.throws(()=>verifyPublicReceipt(e.receipt,e.history,e.jwks),/MERKLE_ROOT_MISMATCH/);});
test('unsigned original-style shell alone is rejected',()=>{const e=clone();delete e.receipt.public_attestation;assert.throws(()=>verifyPublicReceipt(e.receipt,e.history,e.jwks),/MISSING_PUBLIC_ATTESTATION/);});
test('changing history data fails the hash chain',()=>{const e=clone();e.history.entries[0].status='retired';assert.throws(()=>verifyPublicReceipt(e.receipt,e.history,e.jwks),/HISTORY_HASH_CHAIN_INVALID/);});
const fresh=()=>JSON.parse(fs.readFileSync(new URL('./evidence/fresh-receipt-attestation.json',import.meta.url),'utf8'));
test('fresh paid receipt verifies signature, exact history pin and payload hash offline',()=>{const e=clone(),r=verifyFreshReceipt(fresh(),e.history,e.jwks);assert.equal(r.verdict,'OFFLINE_FRESH_RECEIPT_SIGNATURE_AND_HASHES_VERIFIED');assert.equal(r.issuedUtc,'2026-10-27T23:50:20.000Z');assert.equal(r.networkRequests,0);assert.equal(r.kmsCustodyIndependentlyVerified,false);});
test('fresh receipt signature rejects a changed payment claim',()=>{const e=clone(),a=fresh(),p=a.issuer_signature.jws.split('.');const c=JSON.parse(Buffer.from(p[1],'base64url').toString());c.payment.settled_amount='2001';p[1]=Buffer.from(JSON.stringify(c)).toString('base64url');a.issuer_signature.jws=p.join('.');assert.throws(()=>verifyFreshReceipt(a,e.history,e.jwks),/JWS_SIGNATURE_INVALID/);});
test('a different issuer-history snapshot cannot satisfy the exact signed pin',()=>{const e=clone();e.history.seq+=1;assert.throws(()=>verifyFreshReceipt(fresh(),e.history,e.jwks),/EXACT_HISTORY_SNAPSHOT_PIN_MISMATCH/);});
test('public-attestation context cannot substitute for full-receipt context',()=>{const e=clone(),a=fresh();a.issuer_signature.jws=e.receipt.public_attestation.jws;assert.throws(()=>verifyFreshReceipt(a,e.history,e.jwks),/JWS_HEADER_MISMATCH/);});

