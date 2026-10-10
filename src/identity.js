// SPDX-License-Identifier: Apache-2.0
import { enc, b64uEncode, b64uDecode, canonical, sha256b64u } from './encoding.js';
import { normalizeHandle, isValidHandle, profileUrl } from './normalize.js';

const subtle = globalThis.crypto.subtle;

// A key rotation takes effect only after this delay, so the real owner can notice and react (D24).
export const ROTATION_DELAY_MS = 48 * 3600 * 1000;

export async function generateKeyPair() {
  const kp = await subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return {
    pub: b64uEncode(new Uint8Array(await subtle.exportKey('raw', kp.publicKey))),
    priv: b64uEncode(new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey))),
  };
}

export async function signBody(priv, body) {
  const key = await subtle.importKey('pkcs8', b64uDecode(priv), 'Ed25519', false, ['sign']);
  const sig = await subtle.sign('Ed25519', key, enc.encode(canonical(body)));
  return b64uEncode(new Uint8Array(sig));
}

export async function verifyBody(pub, body, sig) {
  try {
    const key = await subtle.importKey('raw', b64uDecode(pub), 'Ed25519', false, ['verify']);
    return await subtle.verify('Ed25519', key, b64uDecode(sig), enc.encode(canonical(body)));
  } catch {
    return false;
  }
}

// VID = hash of the inception entry, so it is bound to the first key.
export async function vidFromBody(body) {
  return (await sha256b64u(canonical(body))).slice(0, 22);
}

export async function createVp({ priv, pub, now = new Date() }) {
  const body = { type: 'create', pub, created: now.toISOString() };
  const entry = { body, sig: await signBody(priv, body) };
  return { vid: await vidFromBody(body), entry };
}

export async function makeRotation({ priv, vid, prevEntry, newPub, now = new Date(), delayMs = ROTATION_DELAY_MS }) {
  const body = {
    type: 'rotate',
    vid,
    prev: await sha256b64u(canonical(prevEntry.body)),
    pub: newPub,
    created: now.toISOString(),
    effectiveAt: new Date(now.getTime() + delayMs).toISOString(),
  };
  return { body, sig: await signBody(priv, body) };
}

// Public key in force at time t (log must already be verified).
export function keyAt(log, t) {
  let pub = log[0].body.pub;
  for (const e of log.slice(1)) {
    if (e.body.type === 'rotate' && new Date(e.body.effectiveAt) <= t) pub = e.body.pub;
  }
  return pub;
}

export async function verifyLog(log, vid) {
  if (!Array.isArray(log) || log.length === 0) return { ok: false, error: 'empty log' };
  const first = log[0];
  if (first?.body?.type !== 'create') return { ok: false, error: 'first entry must be create' };
  if ((await vidFromBody(first.body)) !== vid) return { ok: false, error: 'vid does not match inception' };
  if (!(await verifyBody(first.body.pub, first.body, first.sig))) return { ok: false, error: 'bad inception signature' };
  for (let i = 1; i < log.length; i++) {
    const e = log[i];
    const b = e?.body;
    if (b?.type !== 'rotate' || b.vid !== vid) return { ok: false, error: `entry ${i} invalid` };
    if (b.prev !== (await sha256b64u(canonical(log[i - 1].body)))) return { ok: false, error: `entry ${i} breaks chain` };
    if (!(new Date(b.effectiveAt) >= new Date(b.created))) return { ok: false, error: `entry ${i} bad dates` };
    const signer = keyAt(log.slice(0, i), new Date(b.created));
    if (!(await verifyBody(signer, b, e.sig))) return { ok: false, error: `entry ${i} bad signature` };
  }
  return { ok: true };
}

export async function makeClaim({ priv, vid, platform, handle, now = new Date() }) {
  const body = { type: 'claim', vid, platform, handle: normalizeHandle(platform, handle), created: now.toISOString() };
  return { body, sig: await signBody(priv, body) };
}

// KNOWN LIMIT: `created` is self-declared. A stolen old key could backdate claims to before a
// rotation. The server must enforce a timestamp window at ingest; see open question Q24.
export async function verifyClaim(log, claim) {
  const b = claim?.body;
  if (b?.type !== 'claim' || !isValidHandle(b.platform, b.handle)) return false;
  if (b.handle !== normalizeHandle(b.platform, b.handle)) return false;
  return verifyBody(keyAt(log, new Date(b.created)), b, claim.sig);
}

// vp = { vid, log, claims } as served by the registry. Returns only claims that check out.
export async function verifyVp(vp) {
  const r = await verifyLog(vp?.log, vp?.vid);
  if (!r.ok) return { ok: false, error: r.error };
  const claims = [];
  for (const c of vp.claims ?? []) {
    if (c.body?.vid === vp.vid && (await verifyClaim(vp.log, c))) claims.push(c);
  }
  return { ok: true, vid: vp.vid, claims };
}

export function didFor(host, vid) {
  return `did:web:${host.replace(':', '%3A')}:v:${vid}`;
}

export function didDocument({ host, vid, log, claims = [], now = new Date() }) {
  const id = didFor(host, vid);
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id,
    verificationMethod: [{
      id: `${id}#key-1`,
      type: 'JsonWebKey2020',
      controller: id,
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: keyAt(log, now) },
    }],
    authentication: [`${id}#key-1`],
    assertionMethod: [`${id}#key-1`],
    alsoKnownAs: claims.map((c) => profileUrl(c.body.platform, c.body.handle)),
  };
}
