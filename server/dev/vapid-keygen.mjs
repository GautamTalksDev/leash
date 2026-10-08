// Prints a fresh VAPID private key (ES256 JWK) for phone alerts. Pipe it straight into the Worker secret:
//   node dev/vapid-keygen.mjs | npx wrangler secret put VAPID_PRIVATE_JWK
// Keep no copy: if it is ever lost, generate a new one; devices just turn alerts on again.
const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
process.stdout.write(JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey)));
