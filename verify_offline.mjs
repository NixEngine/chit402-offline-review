// Independent public-attestation verifier: Node built-ins only, no network.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
const HERE=path.dirname(fileURLToPath(import.meta.url));
export const EXPECTED_KID='IvFpmC-vPhkY_v0vidsrWVT9uzlE5XWKZgAEOeJTq1Q';
const sha=b=>createHash('sha256').update(b).digest('hex');
function requireCheck(ok,code){if(!ok)throw Error(code);}
function canonical(value){
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value!==null&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 requireCheck(typeof value!=='number'||Number.isFinite(value),'NON_FINITE_JSON');
 return JSON.stringify(value);
}
function signedPayload(jws,jwk,typ,prefix=''){
 requireCheck(typeof jws==='string','MISSING_PUBLIC_ATTESTATION');
 const parts=jws.split('.');requireCheck(parts.length===3,'INVALID_JWS');
 const header=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'));
 requireCheck(header.alg==='ES256'&&header.kid===EXPECTED_KID&&header.typ===typ,'JWS_HEADER_MISMATCH');
 const signature=Buffer.from(parts[2],'base64url');requireCheck(signature.length===64,'INVALID_ES256_SIGNATURE_LENGTH');
 requireCheck(verifySignature('sha256',Buffer.from(parts[0]+'.'+parts[1]),{key:createPublicKey({key:jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},signature),'JWS_SIGNATURE_INVALID');
 const raw=Buffer.from(parts[1],'base64url').toString('utf8');
 requireCheck(raw.startsWith(prefix),'SIGNED_DOMAIN_MISMATCH');
 return JSON.parse(raw.slice(prefix.length));
}
function treeRoot(leaf,index,size,proof){
 requireCheck(/^[0-9a-f]{64}$/.test(leaf)&&Number.isSafeInteger(index)&&Number.isSafeInteger(size)&&index>=0&&index<size,'MERKLE_INPUT_INVALID');
 let current=Buffer.from(leaf,'hex'),i=index,width=size,step=0;
 while(width>1){
  const side=i%2===1?'left':i+1<width?'right':null;
  if(side){
   const sibling=proof[step++];requireCheck(sibling?.position===side&&/^[0-9a-f]{64}$/.test(sibling.hash),'MERKLE_PROOF_SHAPE_INVALID');
   const other=Buffer.from(sibling.hash,'hex');
   current=Buffer.from(sha(Buffer.concat([Buffer.from([1]),...(side==='left'?[other,current]:[current,other])])),'hex');
  }
  i=Math.floor(i/2);width=Math.ceil(width/2);
 }
 requireCheck(step===proof.length,'MERKLE_PROOF_EXTRA_NODES');return current.toString('hex');
}
export function verifyPublicReceipt(receipt,history,jwks){
 const keys=jwks.keys.filter(k=>k.kid===EXPECTED_KID);requireCheck(keys.length===1,'EXPECTED_KEY_NOT_UNIQUE');
 const jwk=keys[0];requireCheck(jwk.kty==='EC'&&jwk.crv==='P-256','KEY_TYPE_MISMATCH');
 const thumb=createHash('sha256').update(canonical({crv:jwk.crv,kty:jwk.kty,x:jwk.x,y:jwk.y})).digest('base64url');
 requireCheck(thumb===EXPECTED_KID,'ADVERTISED_KID_THUMBPRINT_MISMATCH');
 let previous=null;
 for(const entry of history.entries){
  const {entry_hash,...body}=entry;requireCheck(body.prev_hash===previous&&sha(canonical(body))===entry_hash,'HISTORY_HASH_CHAIN_INVALID');previous=entry_hash;
 }
 requireCheck(previous===history.head_hash,'HISTORY_HEAD_MISMATCH');
 const hc=signedPayload(history.issuer_signature.jws,jwk,'chit402-issuer-history+jwt');
 requireCheck(hc.head_hash===history.head_hash&&hc.entry_count===history.entries.length&&hc.version===history.version&&hc.seq===history.seq,'SIGNED_HISTORY_MISMATCH');
 const entry=history.entries.find(x=>x.kid===EXPECTED_KID);requireCheck(entry&&canonical(entry.jwk)===canonical(jwk),'HISTORY_KEY_MISMATCH');
 const claims=signedPayload(receipt.public_attestation?.jws,jwk,'chit402-public-receipt+jwt','chit402.public_receipt.v1\n');
 const issued=Date.parse(claims.issued_at),attested=Date.parse(claims.attested_at),before=Date.parse(entry.not_before);
 requireCheck(Number.isFinite(issued)&&Number.isFinite(attested)&&Number.isFinite(before)&&issued>=before&&attested>=issued,'ISSUER_TIME_WINDOW_INVALID');
 requireCheck(!entry.not_after||attested<=Date.parse(entry.not_after),'KEY_EXPIRED_AT_ATTESTATION');
 requireCheck(!entry.revoked_at||attested<Date.parse(entry.revoked_at),'KEY_REVOKED_AT_ATTESTATION');
 requireCheck(claims.iss==='chit402'&&claims.task_id===receipt.task_id&&receipt.receipt_id===claims.task_id&&claims.issued_at===receipt.issued_at,'RECEIPT_IDENTITY_MISMATCH');
 const p=claims.payment;
 requireCheck(p.rail==='usdc'&&p.asset.toLowerCase()===receipt.asset.toLowerCase()&&p.payee.toLowerCase()===receipt.pay_to.toLowerCase()&&p.gross_amount===receipt.amount_gross&&p.settled_amount===receipt.amount_settled&&p.ref==='base:'+receipt.payment_tx&&receipt.chain==='base','UNSIGNED_DISPLAY_MISMATCH');
 const inclusion=receipt.inclusion,head=signedPayload(inclusion.signed_head.signature,jwk,'chit402-tree-head+jwt');
 requireCheck(head.root===inclusion.signed_head.root&&head.tree_size===inclusion.signed_head.tree_size&&claims.log.leaf_hash===inclusion.leaf_hash&&claims.log.epoch===head.epoch,'SIGNED_LOG_BINDING_MISMATCH');
 const root=treeRoot(claims.log.leaf_hash,claims.log.leaf_index,head.tree_size,inclusion.proof);requireCheck(root===head.root,'MERKLE_ROOT_MISMATCH');
 return {verdict:'OFFLINE_PUBLIC_ATTESTATION_VERIFIED',receiptId:claims.task_id,kid:EXPECTED_KID,signatureAlgorithm:'ES256',issuerHistoryHashChain:true,issuerHistorySignature:true,historyVersion:history.version,historySeq:history.seq,publicAttestationSignature:true,publicDisplayMatchesSignedClaims:true,treeHeadSignature:true,merkleAuditPath:true,leafIndex:claims.log.leaf_index,treeSize:head.tree_size,root:head.root,amountAtomic:p.settled_amount,token:p.asset,chain:'base',paymentTx:p.ref.slice(5),issuedAt:claims.issued_at,attestedAt:claims.attested_at,networkRequests:0,unverified:['Issuer identity and KMS custody are not proved by ES256','No independent log consistency proof or globally witnessed checkpoint','No Base/Solana consensus or payment receipt checked offline','No private full-receipt claims, payer, prompt, or model output verified']};
}
export function verifyFreshReceipt(artifact,history,jwks){
 const key=jwks.keys.find(k=>k.kid===EXPECTED_KID);requireCheck(key,'EXPECTED_KEY_MISSING');
 const thumb=createHash('sha256').update(canonical({crv:key.crv,kty:key.kty,x:key.x,y:key.y})).digest('base64url');requireCheck(thumb===EXPECTED_KID,'KID_THUMBPRINT_MISMATCH');
 const claims=signedPayload(artifact.issuer_signature?.jws,key,'chit402-receipt+jwt');
 requireCheck(claims.payload_version===10&&claims.task_id===artifact.receiptId,'FRESH_RECEIPT_IDENTITY_MISMATCH');
 const pin=claims.issuer_history;
 requireCheck(pin&&pin.version===history.version&&pin.seq===history.seq&&pin.hash===sha(canonical(history)),'EXACT_HISTORY_SNAPSHOT_PIN_MISMATCH');
 let previous=null;for(const entry of history.entries){const {entry_hash,...body}=entry;requireCheck(body.prev_hash===previous&&sha(canonical(body))===entry_hash,'HISTORY_HASH_CHAIN_INVALID');previous=entry_hash;}
 requireCheck(previous===history.head_hash,'HISTORY_HEAD_MISMATCH');
 const hc=signedPayload(history.issuer_signature.jws,key,'chit402-issuer-history+jwt');requireCheck(hc.head_hash===history.head_hash&&hc.entry_count===history.entries.length&&hc.version===history.version&&hc.seq===history.seq,'SIGNED_HISTORY_MISMATCH');
 const entries=history.entries.filter(e=>e.kid===EXPECTED_KID);requireCheck(entries.length===1,'CAPTURED_KEY_HISTORY_AMBIGUOUS');const entry=entries[0];
 requireCheck(Number.isSafeInteger(claims.iat)&&claims.iat*1000>=Date.parse(entry.not_before)&&(!entry.not_after||claims.iat*1000<Date.parse(entry.not_after))&&(!entry.revoked_at||claims.iat*1000<Date.parse(entry.revoked_at)),'KEY_WINDOW_INVALID');
 const {payload_hash,...preimage}=claims;requireCheck(payload_hash===sha(canonical(preimage)),'SIGNED_CANONICAL_PAYLOAD_HASH_MISMATCH');
 const payment=claims.payment;requireCheck(payment?.rail==='usdc'&&payment.asset.toLowerCase()==='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'&&payment.payee.toLowerCase()==='0x23f713411c30bbd9a989c9cbc22eb0b55f7f7334'&&payment.gross_amount==='2000'&&payment.settled_amount==='2000'&&payment.ref==='base:0x4d77e1ed30195eb6dc38d610f2fb3a5c3df8ffdaedd9729e0a89fbf48c6d08fc','FRESH_PAYMENT_CLAIMS_MISMATCH');
 requireCheck(/^0x[0-9a-f]{64}$/i.test(claims.output?.hash??''),'OUTPUT_COMMITMENT_INVALID');
 return {verdict:'OFFLINE_FRESH_RECEIPT_SIGNATURE_AND_HASHES_VERIFIED',receiptId:claims.task_id,quoteTaskId:artifact.quoteTaskId,issuer:claims.iss,kid:EXPECTED_KID,signatureAlgorithm:'ES256',payloadVersion:claims.payload_version,issuedUtc:new Date(claims.iat*1000).toISOString(),issuerSignature:true,issuerHistorySignature:true,issuerHistoryHashChain:true,exactHistorySnapshotPin:true,historyHash:pin.hash,signedCanonicalPayloadHash:true,payloadHash:payload_hash,keyWindow:true,claimIdPresent:claims.claim_id!==null&&claims.claim_id!==undefined,amountAtomic:payment.settled_amount,payee:payment.payee,asset:payment.asset,paymentRef:payment.ref,outputCommitment:claims.output.hash,signedTreeHeadHash:claims.tree_head_hash,networkRequests:0,kmsCustodyIndependentlyVerified:false,unverified:['AWS KMS custody is an operator statement, not proven by ES256','Inference correctness and raw model output are not disclosed or verified','This offline run does not perform Base consensus, transfer-log, or fresh log-anchor verification','Quote task ID and fulfilled receipt ID are distinct observed identifiers; no equality assumed']};
}
export function loadEvidence(){
 const read=n=>JSON.parse(fs.readFileSync(path.join(HERE,'evidence',n),'utf8'));
 return {receipt:read('public-receipt.json'),history:read('issuer-history.json'),jwks:read('jwks.json')};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const e=loadEvidence();const result=process.argv[2]==='fresh'?verifyFreshReceipt(JSON.parse(fs.readFileSync(path.join(HERE,'evidence/fresh-receipt-attestation.json'),'utf8')),e.history,e.jwks):verifyPublicReceipt(e.receipt,e.history,e.jwks);console.log(JSON.stringify(result,null,2));}
 catch(e){console.error(JSON.stringify({verdict:'REJECTED',reason:/^[A-Z_]+$/.test(e.message)?e.message:'INVALID_INPUT'}));process.exitCode=1;}
}

