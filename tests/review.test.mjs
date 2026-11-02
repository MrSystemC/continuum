import test from 'node:test';
import assert from 'node:assert/strict';
import {createCapsule,verifyCapsule,parseCapsuleJSON,bytesToBase64} from '../dist/engine.js';
const enc = new TextEncoder();
const b64 = s => bytesToBase64(enc.encode(s));
const options = () => ({title:'Review fixture',description:'Independent review',owner:'Unverified test owner',license:'Test only',files:[{name:'data.json',dataBase64:b64('{"n":7}'),mime:'application/json'}],checks:[{type:'json',file:'data.json',path:'n',expected:7}]});

test('review: unsafe JSON integers cannot satisfy rounded equality', async () => {
  const o=options();o.files[0].dataBase64=b64('{"n":9007199254740993}');o.checks[0].expected=9007199254740992;
  await assert.rejects(createCapsule(o));
});
test('review: duplicate keys encoded through Unicode escape rejected', () => {
  assert.throws(()=>parseCapsuleJSON('{"a":1,"\\u0061":2}'), /Duplicate/);
});
test('review: removing or adding embedded files invalidates capsule', async () => {
  let c=await createCapsule(options());c.files=[];assert.equal((await verifyCapsule(c)).valid,false);
  c=await createCapsule(options());c.files.push({name:'extra.txt',dataBase64:b64('extra')});assert.equal((await verifyCapsule(c)).valid,false);
});
test('review: claimed file size mismatch invalidates capsule', async () => {
  const c=await createCapsule(options());c.manifest.files[0].size++;
  const r=await verifyCapsule(c);assert.equal(r.valid,false);assert.equal(r.filesValid,false);assert.equal(r.signatureValid,false);
});
test('review: malformed pin is rejected, no implicit trust', async () => {
  const c=await createCapsule(options());let r=await verifyCapsule(c);assert.equal(r.valid,true);assert.equal(r.trustedKeyMatch,null);
  r=await verifyCapsule(c,{expectedFingerprint:'not-a-fingerprint'});assert.equal(r.valid,false);assert.ok(r.errors.length);
});
test('review: JSON path cannot inherit array properties', async () => {
  const o=options();o.files[0].dataBase64=b64('{"n":[]}');o.checks[0].path='n.toString';o.checks[0].expected='x';
  await assert.rejects(createCapsule(o));
});
test('review: control characters and invalid calendar creation dates rejected', async () => {
  let c=await createCapsule(options());c.manifest.createdAt='2026-02-31T00:00:00.000Z';assert.equal((await verifyCapsule(c)).valid,false);
  const o=options();o.files[0].name='x\u0000.json';await assert.rejects(createCapsule(o));
});

test('review: signature interoperates with independent node crypto verifier', async () => {
  const {createPublicKey,verify}=await import('node:crypto');
  const {canonicalize,base64ToBytes}=await import('../dist/engine.js');
  const c=await createCapsule(options());
  const key=createPublicKey({key:c.publicKey,format:'jwk'});
  const data=Buffer.from('continuum/manifest-signature/v1\u0000'+canonicalize(c.manifest));
  assert.equal(verify('sha256',data,{key,dsaEncoding:'ieee-p1363'},base64ToBytes(c.signature.value)),true);
  assert.equal(verify('sha256',Buffer.from('wrong-domain\u0000'+canonicalize(c.manifest)),{key,dsaEncoding:'ieee-p1363'},base64ToBytes(c.signature.value)),false);
});
