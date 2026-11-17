# aha-service

Keeps an Aha (aha.video) device session alive and decodes the stream API —
for your own account, on your own machine.

## What it does

Aha's web app is a *device* first. It registers the browser as a device and
gets a `clientKey` JWT (the "temp access token", valid ~180 days), a
`deviceId`, and the server's ECDH public key. Every stream call is a JWE:
the JSON payload is encrypted to the server key and the response is a JWE
decrypted with the device private key. This service does exactly that, and
re-registers the same device before the key expires, so the session stays
alive without you re-logging in.

Verified live 2026-11-17: device registration returns 201 SUCCESS, and
`GET /api/stream?code=rich-kid` returns the decoded stream response
(`code 200 SUCCESS`, videos with Widevine/Fairplay FHD/HD/SD links +
license URLs, DRM enabled).

## Run

```bash
npm install
npm start
# listening on http://localhost:3000
```

First call registers this machine as a new Aha web device and saves the
identity to `device.json` (created automatically, never committed, never
zipped — delete it to start a brand-new device).

## Deploy on Vercel

Vercel does not run a long-lived `node server.js` — that is why a plain
deploy fails with "a function needed by this page temporarily failed".
This repo is wired for serverless: `api/index.js` exports the Express app
and `vercel.json` routes every path to it.

```bash
vercel deploy
# or: push to GitHub and import the repo in the Vercel dashboard
```

Then open `https://<your-project>.vercel.app/health` — it should return
`{"ok":true,...}`. No environment variables are required.

One Vercel quirk: the only writable directory is `/tmp`, and it is
ephemeral, so after a cold start the saved device state is gone and the
service registers a fresh device on the next call (takes ~1s, works the
same). If you want one stable device identity that never re-registers,
run it on a machine with a persistent disk instead.

## Endpoints

| Route | What it does |
|---|---|
| `GET /health` | Service + session status, key expiry |
| `GET /api/token` | Current valid `clientKey` + `deviceId` + `expiresAt`, for your own portal to call Aha APIs with. Only expose on a machine you trust. |
| `POST /api/register` | Force a re-registration of this device |
| `GET /api/stream?code=rich-kid` | Decoded stream response for a content code/slug (`profileType` defaults to `master`) |

Examples:

```bash
curl localhost:3000/health
curl "localhost:3000/api/stream?code=rich-kid" | head -c 2000
```

## How the session stays alive

- The `clientKey` lasts ~180 days (`expiresAt` from registration).
- Before every call the service checks the expiry; if under 7 days are
  left (or the key is gone/expired) it re-registers the *same* device
  (same `serialNo`, same keypair) and carries on.
- If Aha rejects a call with 401 / `ERR_INVALID_SESSION_ID`, the service
  re-registers once and retries that call.

## Notes and limits

- Guest content works with the device session alone. Subscriber-only
  content needs a user login (mobile OTP) attached to the device — not
  implemented yet. The endpoints for it are mapped (`/user/v3/mobile/signIn`
  to send the OTP, `/user/v7/mobile/jwe/signIn/` to verify, also JWE).
- Stream links are DRM-protected (Widevine/Fairplay). This service returns
  what Aha returns; it does not strip DRM or bypass the paywall.
- The JWE payload must include `ts` (unix **seconds**, not ms) and a fresh
  `jti` (UUID without dashes) per call, or Aha rejects it.
