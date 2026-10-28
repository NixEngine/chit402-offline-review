// Inspect only public receipt capabilities; no network and no private receipt.
import fs from 'node:fs';
const original=JSON.parse(fs.readFileSync(new URL('./evidence/original-task-example.json',import.meta.url),'utf8'));
const alternate=JSON.parse(fs.readFileSync(new URL('./evidence/public-receipt.json',import.meta.url),'utf8'));
for(const [label,r] of [['listing_example',original],['documented_public_example',alternate]]){
 let c=null;if(r.public_attestation?.jws){const p=Buffer.from(r.public_attestation.jws.split('.')[1],'base64url').toString();c=JSON.parse(p.slice('chit402.public_receipt.v1\n'.length));}
 console.log(JSON.stringify({label,receiptId:r.receipt_id,schema:r.schema,unsignedShell:r.unsigned,hasFullReceiptJws:!!r.issuer_signature?.jws,hasPublicAttestation:!!r.public_attestation?.jws,signedTreeHead:!!r.inclusion?.signed_head?.signature,issuedAt:r.issued_at,attestedAt:c?.attested_at??null,attestationPrecedesDocumentedKmsMigration:c?Date.parse(c.attested_at)<Date.parse('2026-10-20T00:00:00Z'):null}));
}

