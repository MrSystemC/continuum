import test from 'node:test';
import assert from 'node:assert/strict';
import {createDecipheriv,pbkdf2Sync} from 'node:crypto';
import {encryptCapsule,decryptCapsule,toBase64,fromBase64} from '../dist/crypto.js';
const password='independent-review-password';

test('crypto review: encryption interoperates with independent node AES-GCM decryption',async()=>{
  const object={hello:'Проверка',nested:[1,true,null]};const e=await encryptCapsule(object,password);
  const key=pbkdf2Sync(Buffer.from(password,'utf8'),Buffer.from(e.salt,'base64'),210000,32,'sha256');
  const encrypted=Buffer.from(e.ciphertext,'base64');const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64'));
  decipher.setAAD(Buffer.from('continuum/encrypted-1'));decipher.setAuthTag(encrypted.subarray(-16));
  const plaintext=Buffer.concat([decipher.update(encrypted.subarray(0,-16)),decipher.final()]);
  assert.deepEqual(JSON.parse(plaintext.toString('utf8')),object);
});
test('crypto review: malformed salt/IV lengths and empty ciphertext fail',async()=>{
  const e=await encryptCapsule({test:true},password);
  for(const patch of [{salt:toBase64(new Uint8Array(15))},{iv:toBase64(new Uint8Array(13))},{ciphertext:''}])await assert.rejects(decryptCapsule({...e,...patch},password));
});
test('crypto review: metadata, additional fields, and salt tamper fail',async()=>{
  const e=await encryptCapsule({test:true},password);
  for(const patch of [{format:'continuum/encrypted-2'},{cipher:'AES-CBC'},{kdf:'none'},{iterations:210001},{extra:true},{salt:toBase64(new Uint8Array(16))}])await assert.rejects(decryptCapsule({...e,...patch},password));
});
test('crypto review: excessive password length is rejected',async()=>{
  await assert.rejects(encryptCapsule({},'x'.repeat(1025)));
});
test('crypto review: base64 helper rejects alternate/ambiguous encodings',()=>{
  for(const value of ['AB==','AA==\n','AA','____','a===','????'])assert.throws(()=>fromBase64(value));
  assert.deepEqual(fromBase64(toBase64(new Uint8Array([0,1,254,255]))),new Uint8Array([0,1,254,255]));
});
