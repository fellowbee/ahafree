// Aha (aha.video) session + stream service.
//
// How it works (recovered from Aha's own web bundle, verified live):
//  - The web app is a *device* first: it registers the browser as a device
//    (POST /user/v2/registerDevice/) and gets back a clientKey JWT (valid
//    ~180 days), a deviceId and the server's ECDH public key
//    (kid "server-jwe-key-v1"). No user login / OTP is needed for that step.
//  - Every stream call is a JWE: the JSON payload {code, fields, ts, jti}
//    is encrypted to the server public key (ECDH-ES + A256GCM, fresh
//    ephemeral key per call) and POSTed with Content-Type: application/jose.
//    The response is a JWE encrypted to *this* device's public key
//    (kid "client-web-enc-v1") and is decrypted with the device private key.
//  - Payload rules learned from the server's own errors:
//      ts  = unix seconds (milliseconds are rejected),
//      jti = random UUID without dashes (fresh per call, anti-replay).
//  - The clientKey is the "temp access token". This service keeps it alive
//    by re-registering the same device (same serialNo) before it expires.
//
// Boundaries: this uses only your own device session. It does not bypass
// Aha's paywall, strip DRM, or share anything. Guest content works with
// the device session alone; subscriber-only content needs a user login
// (OTP) attached to the device, which is not implemented yet.
//
// State: the device identity (serialNo, clientKey, deviceId, server public
// key, client private key) lives in device.json next to this file. It is
// created on first registration, never logged, never committed, and never
// included in the zip. Delete it to start a brand-new device identity.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { encryptJWE, decryptJWE } = require('./jwe');

const PORT = Number(process.env.PORT || 3000);
const API = process.env.AHA_BASE_URL || 'https://api.aha.video';
const TENANT_ID = '0461396a-f05d-46e8-b2a7-95906f1cfbbb';
const CLIENT_SECRET = 'Web-ee9220449c93';
const CONTENT_LANGUAGE = process.env.AHA_CONTENT_LANGUAGE || 'tamil';
const STATE_FILE = process.env.AHA_STATE_FILE
  || (process.env.VERCEL ? path.join('/tmp', 'device.json') : path.join(__dirname, 'device.json'));
// On Vercel the only writable directory is /tmp, and it is per-instance and
// ephemeral: after a cold start the saved state is gone, so the service
// registers a fresh device (fast, ~1s, fully functional). For a stable
// device identity across cold starts, run it on a machine with a
// persistent disk instead.
// Re-register this far before the clientKey expires.
const REFRESH_BEFORE_MS = Number(process.env.AHA_REFRESH_BEFORE_MS || 7 * 24 * 60 * 60 * 1000);
const FIELDS = 'generalInfo,videlapsedTimeeos,contents,images,subtitles,serviceIds,restrictedCountries,videos,createdCast,relatedCast,previews,publishingHouse,thumbnailSeekPreview,skipConfig,nextContentDetails';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';

let state = null; // { serialNo, deviceId, clientKey, expiresAt, serverPublicKey, clientPrivateKey }
let registering = null;

function loadState() {
  try {
    state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    state = null;
  }
}

function saveState() {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8');
}

function baseHeaders(extra = {}) {
  return {
    'x-myplex-platform': 'web',
    'x-myplex-tenant-id': TENANT_ID,
    'User-Agent': UA,
    ...extra,
  };
}

// Register (or re-register) this service as an Aha web device.
// Returns the stored state. Reuses the same serialNo so the device
// identity stays stable across refreshes.
async function registerDevice(force = false) {
  if (registering) return registering;
  registering = (async () => {
    try {
      const serialNo = state?.serialNo || crypto.randomUUID();
      let keypair = null;
      let clientPublicKey;
      if (state?.clientPrivateKey) {
        // Derive the public JWK from the stored private key.
        const privKeyObj = crypto.createPrivateKey({ key: state.clientPrivateKey, format: 'jwk' });
        const pub = crypto.createPublicKey(privKeyObj).export({ format: 'jwk' });
        clientPublicKey = { crv: pub.crv, kid: 'client-web-enc-v1', kty: pub.kty, use: 'enc', x: pub.x, y: pub.y };
      } else {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const pubJwk = publicKey.export({ format: 'jwk' });
        const privJwk = privateKey.export({ format: 'jwk' });
        clientPublicKey = { crv: pubJwk.crv, kid: 'client-web-enc-v1', kty: pubJwk.kty, use: 'enc', x: pubJwk.x, y: pubJwk.y };
        keypair = { privJwk };
      }

      const params = new URLSearchParams({
        serialNo,
        clientSecret: CLIENT_SECRET,
        profile: 'work',
        make: 'web',
        model: 'Chrome',
        os: 'web',
        osVersion: '157.0.0.0',
        resolution: '1920x1080',
        clientPublicKey: JSON.stringify(clientPublicKey),
      });
      const res = await fetch(`${API}/user/v2/registerDevice/`, {
        method: 'POST',
        headers: { ...baseHeaders(), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      });
      const data = await res.json();
      // First registration: code 201. Re-registering the same device:
      // code 200 "Device already registered" — still returns a fresh clientKey.
      if (res.status !== 200 || !data.clientKey) {
        throw Object.assign(new Error(data.message || 'device registration failed'), { status: res.status, data });
      }
      state = {
        serialNo,
        deviceId: data.deviceId,
        clientKey: data.clientKey,
        expiresAt: data.expiresAt,
        serverPublicKey: data.serverPublicKey,
        clientPrivateKey: keypair ? keypair.privJwk : state.clientPrivateKey,
      };
      saveState();
      console.log('Aha device registered. deviceId:', state.deviceId, '| clientKey expires:', state.expiresAt);
      return state;
    } finally {
      registering = null;
    }
  })();
  return registering;
}

function sessionIsFresh() {
  if (!state?.clientKey || !state?.expiresAt) return false;
  return new Date(state.expiresAt).getTime() - Date.now() > REFRESH_BEFORE_MS;
}

async function ensureSession() {
  if (sessionIsFresh()) return state;
  return registerDevice();
}

async function encryptStreamPayload(payload) {
  return encryptJWE(payload, state.serverPublicKey);
}

async function decryptResponse(jwe) {
  return decryptJWE(jwe, state.clientPrivateKey);
}

// Error responses never echo raw server data (it can contain a clientKey).
function safeError(e) {
  const d = e.data || {};
  return { code: d.code, status: d.status, message: d.message };
}
// Returns the decoded JSON the app itself sees.
async function getStream(code, profileType = 'master') {
  await ensureSession();
  const payload = {
    code,
    fields: FIELDS,
    ts: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID().replace(/-/g, ''),
  };
  const doCall = async () => {
    const jwe = await encryptStreamPayload(payload);
    const res = await fetch(`${API}/content/v2/stream/?profileType=${encodeURIComponent(profileType)}`, {
      method: 'POST',
      headers: {
        ...baseHeaders(),
        'Content-Type': 'application/jose',
        clientkey: state.clientKey,
        contentlanguage: CONTENT_LANGUAGE,
        origin: 'https://www.aha.video',
        referer: 'https://www.aha.video/',
      },
      body: jwe,
    });
    const raw = await res.text();
    if (raw.startsWith('eyJ')) return decryptResponse(raw);
    let parsed;
    try { parsed = JSON.parse(raw); } catch { parsed = { raw: raw.slice(0, 500) }; }
    if (res.status >= 400) {
      const err = new Error(parsed.message || `stream API HTTP ${res.status}`);
      err.status = res.status; err.data = parsed;
      throw err;
    }
    return parsed;
  };
  try {
    return await doCall();
  } catch (e) {
    // Session rejected -> re-register once and retry.
    const code = e.data?.code;
    if (e.status === 401 || code === 401 || e.data?.status === 'ERR_INVALID_SESSION_ID') {
      console.log('Aha session rejected, re-registering device…');
      await registerDevice(true);
      return doCall();
    }
    throw e;
  }
}

const app = express();
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'aha-service',
    hasSession: !!state?.clientKey,
    deviceId: state?.deviceId || null,
    clientKeyExpiresAt: state?.expiresAt || null,
    sessionFresh: sessionIsFresh(),
  });
});

// Current valid clientKey for your own portal to call Aha APIs with.
// Only expose this on a machine you trust; it is your device session.
app.get('/api/token', async (req, res) => {
  try {
    const s = await ensureSession();
    res.json({ clientKey: s.clientKey, deviceId: s.deviceId, expiresAt: s.expiresAt });
  } catch (e) {
    res.status(e.status || 502).json({ error: e.message, ...safeError(e) });
  }
});

// Force a (re-)registration of this device.
app.post('/api/register', async (req, res) => {
  try {
    const s = await registerDevice(true);
    res.json({ ok: true, deviceId: s.deviceId, expiresAt: s.expiresAt });
  } catch (e) {
    res.status(e.status || 502).json({ error: e.message, ...safeError(e) });
  }
});

// Decoded stream response for a content code/slug, e.g. ?code=rich-kid
app.get('/api/stream', async (req, res) => {
  const code = (req.query.code || '').trim();
  if (!code) return res.status(400).json({ error: 'Pass ?code=<content code or slug>, e.g. ?code=rich-kid' });
  try {
    const data = await getStream(code, (req.query.profileType || 'master').trim());
    res.json(data);
  } catch (e) {
    res.status(e.status || 502).json({ error: e.message, ...safeError(e) });
  }
});

app.use((req, res) => res.status(404).json({ error: 'unknown route', routes: ['GET /health', 'GET /api/token', 'POST /api/register', 'GET /api/stream?code='] }));

loadState();

// Export the app for serverless (Vercel) — api/index.js requires this file.
// Only start a listener when run directly (node server.js).
module.exports = app;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`aha-service listening on http://localhost:${PORT}`);
    if (state?.clientKey) {
      console.log('Loaded saved device session. deviceId:', state.deviceId, '| expires:', state.expiresAt);
    } else {
      console.log('No saved device session yet. First /api/token or /api/stream call will register this device.');
    }
  });
}
