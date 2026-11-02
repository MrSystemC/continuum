#!/usr/bin/env node
import {readFile,stat} from 'node:fs/promises';import {readFileSync} from 'node:fs';
import {parseCapsuleJSON,verifyCapsule} from '../dist/engine.js';import {isEncrypted,decryptCapsule} from '../dist/crypto.js';
const args=process.argv.slice(2);let file,pin,stdinPassword=false;
for(let i=0;i<args.length;i++){if(args[i]==='--fingerprint')pin=args[++i];else if(args[i]==='--password-stdin')stdinPassword=true;else if(!file&&!args[i].startsWith('--'))file=args[i];else{console.error('Unknown argument');process.exit(2)}}
if(!file){console.error('Usage: node scripts/verify.mjs capsule.json [--fingerprint SHA256] [--password-stdin]');process.exit(2)}
try{if((await stat(file)).size>12*1024*1024)throw Error('File exceeds 12 MiB');const raw=await readFile(file,'utf8');const outer=JSON.parse(raw);let capsule;if(isEncrypted(outer)){if(!stdinPassword)throw Error('Encrypted capsule requires --password-stdin (password on stdin, no command-line secret)');const password=readFileSync(0,'utf8').replace(/\r?\n$/,'');capsule=parseCapsuleJSON(await decryptCapsule(outer,password))}else capsule=parseCapsuleJSON(raw);const report=await verifyCapsule(capsule,pin?{expectedFingerprint:pin}:{});console.log(JSON.stringify(report,null,2));process.exitCode=report.valid?0:1}catch(e){console.error(e.message);process.exitCode=2}
