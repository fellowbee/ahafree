// Minimal JWE (ECDH-ES + A256GCM, compact serialization) using only
// node:crypto — no external dependency.
//
// Why this exists: the `jose` npm package is ESM-only (its dist is pure
// `import`/`export`, package `"type": "module"`, no CJS build). Calling
// `require('jose')` from this CommonJS service only works on Node versions
// that support require() of ESM (22.12+). On older Node runtimes — which is
// what Vercel's lambda can run — the require throws ERR_REQUIRE_ESM at
// import time, so every invocation fails with FUNCTION_INVOCATION_FAILED
// before any request is handled. This file removes that whole class of
// failure: it works in plain CommonJS on every Node 18+ runtime.
//
// Profile (matches Aha's server exactly, verified live):
//  - alg ECDH-ES (direct key agreement, no key wrapping), enc A256GCM.
//  - Protected header: {alg, enc, kid, epk} where epk is a fresh ephemeral
//    P-256 public key generated per call (the server requires epk).
//  - CEK via Concat KDF (RFC 7518 §4.6.2): SHA-256 over
//    counter || Z || len(enc)||enc || len(apu)||apu || len(apv)||apv || keyLenBits.
//    apu/apv are empty; enc is "A256GCM"; key length is 256 bits.
//  - AES-256-GCM with a random 96-bit IV; AAD is the ASCII of the
//    base64url-encoded protected header; 128-bit auth tag.
//  - Compact form: protected . "" (empty encrypted key) . iv . ciphertext . tag.
const crypto = require('node:crypto');

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

function unb64u(s) {
  return Buffer.from(s, 'base64url');
}

function uint32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

function concatKdf(z, enc, keyLenBits) {
  const algId = Buffer.from(enc, 'utf8');
  const otherInfo = Buffer.concat([
    uint32be(algId.length), algId,
    uint32be(0), // apu: empty
    uint32be(0), // apv: empty
    uint32be(keyLenBits), // SuppPubInfo: key length in bits
  ]);
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1, 0);
  return crypto.createHash('sha256')
    .update(Buffer.concat([counter, z, otherInfo]))
    .digest();
}

// A P-256 JWK (x, y) as a 65-byte uncompressed EC point: 0x04 || x || y.
function pubPointFromJwk(jwk) {
  return Buffer.concat([Buffer.from([0x04]), unb64u(jwk.x), unb64u(jwk.y)]);
}

function encryptJWE(payloadObj, recipientPublicJwk) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const ephPub = ecdh.getPublicKey(); // 65-byte uncompressed point
  const protectedHeader = {
    alg: 'ECDH-ES',
    enc: 'A256GCM',
    kid: recipientPublicJwk.kid,
    epk: {
      kty: 'EC',
      crv: 'P-256',
      x: b64u(ephPub.subarray(1, 33)),
      y: b64u(ephPub.subarray(33, 65)),
    },
  };
  const protectedB64 = b64u(Buffer.from(JSON.stringify(protectedHeader), 'utf8'));
  const z = ecdh.computeSecret(pubPointFromJwk(recipientPublicJwk));
  const cek = concatKdf(z, 'A256GCM', 256);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
  cipher.setAAD(Buffer.from(protectedB64, 'ascii'));
  const plaintext = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [protectedB64, '', b64u(iv), b64u(ciphertext), b64u(tag)].join('.');
}

function decryptJWE(compactJwe, privateJwk) {
  const parts = compactJwe.split('.');
  if (parts.length !== 5) throw new Error('Invalid compact JWE');
  const [protectedB64, , ivB64, ciphertextB64, tagB64] = parts;
  const header = JSON.parse(unb64u(protectedB64).toString('utf8'));
  if (header.alg !== 'ECDH-ES' || header.enc !== 'A256GCM') {
    throw new Error(`Unsupported JWE alg/enc: ${header.alg}/${header.enc}`);
  }
  if (!header.epk || !header.epk.x || !header.epk.y) throw new Error('JWE epk missing');
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(unb64u(privateJwk.d));
  const z = ecdh.computeSecret(pubPointFromJwk(header.epk));
  const cek = concatKdf(z, 'A256GCM', 256);
  const decipher = crypto.createDecipheriv('aes-256-gcm', cek, unb64u(ivB64));
  decipher.setAAD(Buffer.from(protectedB64, 'ascii'));
  decipher.setAuthTag(unb64u(tagB64));
  const plaintext = Buffer.concat([decipher.update(unb64u(ciphertextB64)), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

module.exports = { encryptJWE, decryptJWE };
