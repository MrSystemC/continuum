# Continuum engine v1

`dist/engine.js` is a dependency-free browser ES module. It uses WebCrypto and requires a secure browser context (HTTPS or localhost), or Node 20+ for automated verification. It does not call a network, write to browser storage, execute packaged code, or extract files onto a filesystem.

## API

```js
import {
  createCapsule, verifyCapsule, parseCapsuleJSON,
  canonicalize, sha256, fingerprint,
  bytesToBase64, base64ToBytes, LIMITS
} from './engine.js';

const capsule = await createCapsule({
  title: 'Operational handover',
  description: 'A small self-declared package',
  owner: 'Name asserted by the package creator',
  license: 'Self-declared transfer/reuse terms',
  files: [{
    name: 'settings.json',
    mime: 'application/json', // optional; defaults to application/octet-stream
    dataBase64: bytesToBase64(new TextEncoder().encode('{"mode":"ready"}'))
  }],
  checks: [
    {type: 'file', file: 'settings.json'},
    {type: 'json', file: 'settings.json', path: 'mode', expected: 'ready'}
  ]
});
const report = await verifyCapsule(parseCapsuleJSON(JSON.stringify(capsule)));
// Optionally pin the public key fingerprint received through an independent channel:
const pinnedReport = await verifyCapsule(capsule, {expectedFingerprint: report.fingerprint});
```

`createCapsule()` rejects invalid input or any failing declared check. It generates a fresh, ephemeral ECDSA P-256 key pair for every capsule. The private key is not extractable or exported. The exported capsule contains the public JWK and signature only. This implementation cannot use a persistent organizational signing identity or sign follow-up events under the same key.

`verifyCapsule()` returns a report and does not throw for malformed capsule data:

```js
{
  valid,              // signature + file integrity + declared checks + optional pin
  signatureValid,
  filesValid,
  checksValid,
  trustedKeyMatch,    // null when no expected fingerprint is provided
  fingerprint,       // SHA-256 of internal canonical public JWK
  capsuleId,         // SHA-256 of internal canonical manifest
  checks: [{type, file, passed, detail}],
  errors: []
}
```

A true `valid` result without an independent key pin means that the capsule is internally consistent under its included key. It does not establish trust in a person or organization. A matching pin shows correspondence with the independently supplied key; it does not prove identity, ownership, authenticity of source facts, legal rights, time of creation, or operational fitness. A creator can supply fabricated files and claims, or create a different capsule under a different key.

## Declared checks

- `{type:'file', file:'name'}` checks that the embedded file is present. Byte hashes and sizes are separately checked for every file during verification.
- `{type:'json', file:'name', path:'service.state', expected:'ready'}` parses UTF-8 JSON and compares the selected value through internal canonical serialization. Dot segments may contain ASCII letters, digits, `_`, `-`; arrays can use numeric index segments. Prototype paths are rejected and lookups use own properties only.
- `{type:'csv', file:'name', columns:['id','name']}` parses a UTF-8 comma-separated file (optional UTF-8 BOM), validates quoting and row widths, and checks that required header columns exist. Quoted commas, escaped double quotes, quoted newlines, CRLF/LF, and terminal newlines are supported. Empty or duplicate headers are rejected. The number of data rows is reported, but a minimum row count is not asserted.

These are bounded static data assertions. They do not start a service, execute an application, validate backups against an external system, or prove a successful real-world restoration.

## Format and signing

```js
{
  format: 'continuum/capsule-1',
  manifest: {
    format: 'continuum/manifest-1',
    title, description, owner, license, createdAt,
    files: [{name, size, mime, sha256}],
    checks: [/* declared checks */]
  },
  files: [{name, dataBase64}],
  publicKey: {kty:'EC', crv:'P-256', x, y},
  signature: {algorithm:'ECDSA-P256-SHA256', value:'base64'}
}
```

The signature covers UTF-8 bytes of:

```
'continuum/manifest-signature/v1\u0000' + canonicalize(manifest)
```

ECDSA signatures use the WebCrypto 64-byte IEEE-P1363 encoding (`r || s`), with SHA-256. Each embedded file is bound to the signed manifest by SHA-256 of its exact decoded bytes and by byte count. `createdAt` is merely a self-reported UTC timestamp; there is no trusted timestamp service, transparency log, revocation registry, chain of custody, or external witness.

`canonicalize()` sorts object keys using JavaScript's default string sort, preserves array ordering, serializes finite JavaScript numbers with `JSON.stringify`, and rejects unsupported values and sparse arrays. It is the internal v1 format, not a claim of RFC 8785 conformance. A verifier in another language must reproduce these exact serialization rules and domain bytes. JSON integer values outside JavaScript's safe integer range are rejected to avoid rounding two different integers to one value. Finite decimal values otherwise use JavaScript IEEE-754 semantics; use decimal strings for exact quantities and large integer identifiers.

`parseCapsuleJSON()` is a strict bounded parser. It rejects duplicate object keys (including keys encoded with Unicode escapes), invalid/lone Unicode surrogate characters, nonfinite numbers, unsafe integers, and excessive nesting. It produces null-prototype objects. Use it for untrusted JSON instead of plain `JSON.parse` if duplicate-key rejection is needed.

## Limits and safety properties

- 1–32 embedded files; at most 5 MiB of decoded binary data in aggregate.
- 1–64 declared checks.
- At most 8 MiB of UTF-8 JSON; nesting at most 32 levels; canonicalization/parsing at most 50,000 nodes.
- File names: at most 160 UTF-16 code units, NFC Unicode, relative nonempty segments; rejects absolute paths, traversal, backslashes, Windows-reserved device basenames, forbidden filename punctuation, whitespace-bound segments, and case-insensitive duplicate names. Files are never automatically extracted.
- Schema rejects missing or extra capsule/manifest fields and unknown signature algorithms.
- Base64 must use canonical standard alphabet and padding, without whitespace or URL-safe substitutions.
- JSON expectations are at most 16 KiB; CSV at most 100,000 parsed rows.
- Included files and metadata in the base format are plaintext. Encryption, when used by the application, is an outer layer and not implemented by this module.

## Verification

From the project root:

```bash
node --test tests/*.test.mjs
```

Engine tests cover the positive round-trip and rejection of data/manifest/key tampering, pin mismatches, malformed schemas, duplicate JSON keys, unsafe JSON integers, untrusted JSON paths, malformed CSV, canonical base64, path and count limits, and the aggregate 5 MiB boundary. The independent review tests also verify the signature with Node's separate `node:crypto` ECDSA implementation. Successful tests validate these implemented mechanisms; they are not an independent security audit or a guarantee of suitability for regulated or high-risk use.
