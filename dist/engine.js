/** Continuum capsule engine v1. No network or persistent key storage. */
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder('utf-8', {fatal: true});
export const LIMITS = Object.freeze({files:32, checks:64, binaryBytes:5*1024*1024, jsonBytes:8*1024*1024, depth:32});
const DOMAIN = 'continuum/manifest-signature/v1\u0000';
const HEX = /^[a-f0-9]{64}$/;
const own = (o,k) => Object.prototype.hasOwnProperty.call(o,k);
const object = o => !!o && typeof o==='object' && !Array.isArray(o) && [Object.prototype,null].includes(Object.getPrototypeOf(o));
function fail(message) { throw new Error(message); }
function keys(o, allowed, name) {
  if (!object(o) || Object.keys(o).length!==allowed.length || Object.keys(o).some(k=>!allowed.includes(k))) fail(`Invalid ${name} fields`);
}
function text(s,max,name,{empty=false}={}) {
  if (typeof s!=='string' || s.length>max || (!empty&&!s.trim()) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(s)) fail(`Invalid ${name}`);
  // Lone surrogates produce ambiguous UTF-8 replacement characters in signing.
  for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);if(c>=0xD800&&c<=0xDBFF){const d=s.charCodeAt(++i);if(!(d>=0xDC00&&d<=0xDFFF))fail(`Invalid Unicode in ${name}`);}else if(c>=0xDC00&&c<=0xDFFF)fail(`Invalid Unicode in ${name}`);}
  return s;
}
function filename(s) {
  text(s,160,'file name');
  if(s.split('/').some(p=>/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(p)) || s!==s.normalize('NFC') || /[\\<>:"|?*\u0000-\u001f\u007f]/u.test(s) || s.startsWith('/') || s.endsWith('/') || s.split('/').some(p=>!p||p==='.'||p==='..'||p!==p.trim()||p.endsWith('.')))fail('Unsafe file name');
  return s;
}
function mime(s) { if(typeof s!=='string'||s.length>100||! /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/.test(s))fail('Invalid MIME type');return s; }
/** Internal deterministic serialization, NOT a claim of RFC 8785 compliance. */
export function canonicalize(value) {
  let nodes=0;
  function visit(v,d){
    if(d>LIMITS.depth||++nodes>50000)fail('JSON structure limit exceeded');
    if(v===null||typeof v==='boolean')return JSON.stringify(v);
    if(typeof v==='string'){text(v,LIMITS.jsonBytes,'JSON string',{empty:true});return JSON.stringify(v);}
    if(typeof v==='number'){if(!Number.isFinite(v))fail('Non-finite JSON number');if(Number.isInteger(v)&&!Number.isSafeInteger(v))fail('Unsafe JSON integer');return JSON.stringify(v);}
    if(Array.isArray(v)){const items=[];for(let j=0;j<v.length;j++){if(!own(v,j))fail('Sparse JSON array');items.push(visit(v[j],d+1));}return '['+items.join(',')+']';}
    if(object(v))return '{'+Object.keys(v).sort().map(k=>{text(k,1024,'JSON key',{empty:true});return JSON.stringify(k)+':'+visit(v[k],d+1);}).join(',')+'}';
    fail('Unsupported JSON value');
  }
  return visit(value,0);
}
export function bytesToBase64(bytes) {
  if(!(bytes instanceof Uint8Array))fail('Expected Uint8Array');
  let s=''; for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));
  return btoa(s);
}
export function base64ToBytes(s) {
  if(typeof s!=='string'||s.length>Math.ceil(LIMITS.binaryBytes/3)*4||s.length%4!==0|| /[^A-Za-z0-9+/=]/.test(s))fail('Invalid or oversized base64');
  const padding=s.indexOf('=');if(padding!==-1&&((padding!==s.length-1&&padding!==s.length-2)||!/^={1,2}$/.test(s.slice(padding))))fail('Invalid base64 padding');
  let decoded; try{decoded=atob(s);}catch{fail('Invalid base64');}
  const bytes=Uint8Array.from(decoded,c=>c.charCodeAt(0));
  if(bytesToBase64(bytes)!==s)fail('Non-canonical base64');
  return bytes;
}
export async function sha256(value) {
  const bytes=typeof value==='string'?ENCODER.encode(value):value;
  if(!(bytes instanceof Uint8Array)&&!(bytes instanceof ArrayBuffer))fail('Expected text or bytes');
  const digest=await crypto.subtle.digest('SHA-256',bytes);
  return Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,'0')).join('');
}
function publicJWK(jwk){
  keys(jwk,['kty','crv','x','y'],'public key');
  if(jwk.kty!=='EC'||jwk.crv!=='P-256'||! /^[A-Za-z0-9_-]{43}$/.test(jwk.x)||! /^[A-Za-z0-9_-]{43}$/.test(jwk.y))fail('Invalid public key');
  return jwk;
}
export async function fingerprint(jwk){publicJWK(jwk);return sha256(canonicalize(jwk));}
/** Strict JSON parser: rejects duplicate keys, nonfinite numbers, excessive depth. */
export function parseCapsuleJSON(input){
  if(typeof input!=='string'||ENCODER.encode(input).length>LIMITS.jsonBytes)fail('JSON exceeds 8 MiB limit');
  let i=0,nodes=0;
  const ws=()=>{while(i<input.length&&/[\t\r\n ]/.test(input[i]))i++;};
  function str(){const start=i++;let escaped=false;while(i<input.length){const c=input[i++];if(escaped){escaped=false;continue;}if(c==='\\'){escaped=true;continue;}if(c==='"'){let s;try{s=JSON.parse(input.slice(start,i));}catch{fail('Invalid JSON string');}text(s,LIMITS.jsonBytes,'JSON string',{empty:true});return s;}if(c.charCodeAt(0)<32)fail('Invalid JSON string');}fail('Unterminated JSON string');}
  function val(depth){
    if(depth>LIMITS.depth||++nodes>50000)fail('JSON structure limit exceeded');ws();const c=input[i];
    if(c==='"')return str();
    if(c==='{'){i++;const o=Object.create(null);ws();if(input[i]==='}'){i++;return o;}while(true){ws();if(input[i]!=='"')fail('Invalid JSON object');const k=str();if(own(o,k))fail('Duplicate JSON key');ws();if(input[i++]!==':')fail('Invalid JSON object');o[k]=val(depth+1);ws();const s=input[i++];if(s==='}')return o;if(s!==',')fail('Invalid JSON object');}}
    if(c==='['){i++;const a=[];ws();if(input[i]===']'){i++;return a;}while(true){a.push(val(depth+1));ws();const s=input[i++];if(s===']')return a;if(s!==',')fail('Invalid JSON array');}}
    for(const [token,value] of [['true',true],['false',false],['null',null]])if(input.slice(i,i+token.length)===token){i+=token.length;return value;}
    const m=/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(input.slice(i));if(m){i+=m[0].length;const v=Number(m[0]);if(!Number.isFinite(v))fail('Non-finite JSON number');if(Number.isInteger(v)&&!Number.isSafeInteger(v))fail('Unsafe JSON integer');return v;}
    fail('Invalid JSON value');
  }
  const result=val(0);ws();if(i!==input.length)fail('Trailing JSON data');return result;
}
function validateCheck(c, names){
  if(!object(c)||!['file','json','csv'].includes(c.type))fail('Invalid check type');
  filename(c.file);if(!names.has(c.file))fail('Check references missing file');
  if(c.type==='file')keys(c,['type','file'],'file check');
  if(c.type==='json'){
    keys(c,['type','file','path','expected'],'JSON check');
    if(typeof c.path!=='string'||c.path.length>240||! /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/.test(c.path)||c.path.split('.').some(p=>['__proto__','prototype','constructor'].includes(p)))fail('Invalid JSON path');
    if(ENCODER.encode(canonicalize(c.expected)).length>16384)fail('Expected JSON value too large');
  }
  if(c.type==='csv'){
    keys(c,['type','file','columns'],'CSV check');
    if(!Array.isArray(c.columns)||!c.columns.length||c.columns.length>64||new Set(c.columns).size!==c.columns.length)fail('Invalid CSV columns');
    c.columns.forEach(s=>text(s,120,'CSV column'));
  }
}
function parseCSV(data){
  let rows=[], row=[], field='', quoted=false, afterQuote=false;
  const pushField=()=>{row.push(field);field='';afterQuote=false;};
  const pushRow=()=>{pushField();rows.push(row);row=[];if(rows.length>100000)fail('Too many CSV rows');};
  for(let i=0;i<data.length;i++){
    const c=data[i];
    if(quoted){if(c==='"'){if(data[i+1]==='"'){field+='"';i++;}else{quoted=false;afterQuote=true;}}else field+=c;continue;}
    if(afterQuote&&c!==','&&c!=='\r'&&c!=='\n')fail('Unexpected character after CSV quote');
    if(c==='"'){if(field.length||afterQuote)fail('Invalid CSV quote');quoted=true;}
    else if(c===',')pushField();
    else if(c==='\n')pushRow();
    else if(c==='\r'){if(data[i+1]==='\n')i++;pushRow();}
    else field+=c;
  }
  if(quoted)fail('Unclosed CSV quote');
  if(field.length||row.length||afterQuote)pushRow();
  if(!rows.length||rows[0].some(x=>!x)||new Set(rows[0]).size!==rows[0].length)fail('Invalid CSV header');
  if(rows.some(r=>r.length!==rows[0].length))fail('Inconsistent CSV row width');
  return rows;
}
function runCheck(c, files){
  const result={type:c.type,file:c.file,passed:false,detail:''};
  try{
    const bytes=files.get(c.file);if(!bytes)fail('File missing');
    if(c.type==='file'){result.passed=true;result.detail='File present';}
    if(c.type==='json'){
      let value=parseCapsuleJSON(DECODER.decode(bytes));
      for(const p of c.path.split('.')){if((!object(value)&&!Array.isArray(value))||!own(value,p))fail('JSON path not found');value=value[p];}
      if(canonicalize(value)!==canonicalize(c.expected))fail('JSON value differs');
      result.passed=true;result.detail='JSON value matches';
    }
    if(c.type==='csv'){
      const rows=parseCSV(DECODER.decode(bytes).replace(/^\uFEFF/,''));
      if(c.columns.some(x=>!rows[0].includes(x)))fail('Required CSV column missing');
      result.passed=true;result.detail=`CSV columns present; ${rows.length-1} data rows`;
    }
  }catch(e){result.detail=e.message||'Check failed';}
  return result;
}
function validateEnvelope(capsule){
  keys(capsule,['format','manifest','files','publicKey','signature'],'capsule');
  if(capsule.format!=='continuum/capsule-1')fail('Unsupported capsule format');
  const m=capsule.manifest;
  keys(m,['format','title','description','owner','license','createdAt','files','checks'],'manifest');
  if(m.format!=='continuum/manifest-1')fail('Unsupported manifest format');
  text(m.title,160,'title');text(m.description,4000,'description',{empty:true});text(m.owner,200,'owner');text(m.license,2000,'license');
  if(typeof m.createdAt!=='string'||! /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(m.createdAt)||!Number.isFinite(Date.parse(m.createdAt))||new Date(m.createdAt).toISOString()!==m.createdAt)fail('Invalid creation date');
  if(!Array.isArray(m.files)||!m.files.length||m.files.length>LIMITS.files||!Array.isArray(capsule.files)||capsule.files.length!==m.files.length)fail('Invalid file count');
  const names=new Set(), decoded=new Map();let total=0;
  for(let i=0;i<m.files.length;i++){
    const meta=m.files[i], file=capsule.files[i];keys(meta,['name','size','mime','sha256'],'file metadata');keys(file,['name','dataBase64'],'embedded file');
    filename(meta.name);filename(file.name);if(names.has(meta.name.toLowerCase())||file.name!==meta.name)fail('Duplicate or mismatched file name');names.add(meta.name.toLowerCase());
    if(!Number.isSafeInteger(meta.size)||meta.size<0||meta.size>LIMITS.binaryBytes||typeof meta.sha256!=='string'||!HEX.test(meta.sha256))fail('Invalid file metadata');
    mime(meta.mime);const bytes=base64ToBytes(file.dataBase64);total+=bytes.length;if(total>LIMITS.binaryBytes)fail('Files exceed 5 MiB limit');decoded.set(meta.name,bytes);
  }
  if(!Array.isArray(m.checks)||!m.checks.length||m.checks.length>LIMITS.checks)fail('Invalid check count');
  m.checks.forEach(c=>validateCheck(c,new Set(m.files.map(f=>f.name))));publicJWK(capsule.publicKey);
  keys(capsule.signature,['algorithm','value'],'signature');if(capsule.signature.algorithm!=='ECDSA-P256-SHA256'||base64ToBytes(capsule.signature.value).length!==64)fail('Invalid signature');
  // Limit metadata as well as raw file bytes for both direct API and parsed input.
  if(ENCODER.encode(canonicalize(capsule)).length>LIMITS.jsonBytes)fail('Capsule exceeds 8 MiB limit');
  return decoded;
}
export async function createCapsule(options){
  if(!object(options)||Object.keys(options).some(k=>!['files','title','description','owner','license','checks'].includes(k)))fail('Invalid creation options');
  const {files,title,description='',owner,license,checks=[]}=options;
  if(!Array.isArray(files)||!files.length||files.length>LIMITS.files)fail('Supply 1–32 files');
  const names=new Set(), decoded=new Map(), meta=[], embedded=[];let total=0;
  for(const file of files){
    if(!object(file)||Object.keys(file).some(k=>!['name','dataBase64','mime'].includes(k)))fail('Invalid input file');
    const name=filename(file.name);if(names.has(name.toLowerCase()))fail('Duplicate file name');names.add(name.toLowerCase());
    const data=base64ToBytes(file.dataBase64);total+=data.length;if(total>LIMITS.binaryBytes)fail('Files exceed 5 MiB limit');decoded.set(name,data);
    meta.push({name,size:data.length,mime:mime(file.mime||'application/octet-stream'),sha256:await sha256(data)});embedded.push({name,dataBase64:file.dataBase64});
  }
  text(title,160,'title');text(description,4000,'description',{empty:true});text(owner,200,'owner');text(license,2000,'license');
  if(!Array.isArray(checks)||!checks.length||checks.length>LIMITS.checks)fail('Invalid check count');
  const checkCopies=checks.map(c=>{validateCheck(c,new Set(files.map(f=>f.name)));return parseCapsuleJSON(canonicalize(c));});
  for(const c of checkCopies){const r=runCheck(c,decoded);if(!r.passed)fail(`Check failed for ${c.file}: ${r.detail}`);}
  const manifest={format:'continuum/manifest-1',title,description,owner,license,createdAt:new Date().toISOString(),files:meta,checks:checkCopies};
  const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const jwk=await crypto.subtle.exportKey('jwk',key.publicKey);
  const publicKey={kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y};
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.privateKey,ENCODER.encode(DOMAIN+canonicalize(manifest)));
  const capsule={format:'continuum/capsule-1',manifest,files:embedded,publicKey,signature:{algorithm:'ECDSA-P256-SHA256',value:bytesToBase64(new Uint8Array(sig))}};
  validateEnvelope(capsule);
  return capsule;
}
export async function verifyCapsule(capsule,{expectedFingerprint}={}){
  const report={valid:false,signatureValid:false,filesValid:false,checksValid:false,trustedKeyMatch:null,fingerprint:null,capsuleId:null,checks:[],errors:[]};
  try{
    if(expectedFingerprint!==undefined&&expectedFingerprint!==''&&(typeof expectedFingerprint!=='string'||!HEX.test(expectedFingerprint.toLowerCase())))fail('Expected fingerprint must be 64 hexadecimal characters');
    const files=validateEnvelope(capsule);
    report.fingerprint=await fingerprint(capsule.publicKey);report.capsuleId=await sha256(canonicalize(capsule.manifest));
    if(expectedFingerprint)report.trustedKeyMatch=report.fingerprint===expectedFingerprint.toLowerCase();
    try{const key=await crypto.subtle.importKey('jwk',capsule.publicKey,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);report.signatureValid=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64ToBytes(capsule.signature.value),ENCODER.encode(DOMAIN+canonicalize(capsule.manifest)));}catch{report.signatureValid=false;}
    if(!report.signatureValid)report.errors.push('Signature verification failed');
    report.filesValid=true;
    for(const meta of capsule.manifest.files){const b=files.get(meta.name);if(meta.size!==b.length||meta.sha256!==await sha256(b)){report.filesValid=false;report.errors.push(`File integrity failed: ${meta.name}`);}}
    report.checks=capsule.manifest.checks.map(c=>runCheck(c,files));report.checksValid=report.checks.every(r=>r.passed);
    if(!report.checksValid)report.errors.push('One or more recovery checks failed');
    if(report.trustedKeyMatch===false)report.errors.push('Pinned public key fingerprint does not match');
    report.valid=report.signatureValid&&report.filesValid&&report.checksValid&&report.trustedKeyMatch!==false;
  }catch(e){report.errors.push(e.message||'Invalid capsule');}
  return report;
}
