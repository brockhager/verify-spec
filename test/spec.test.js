// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import * as V from '../src/index.js';

test('parseProfileUrl', () => {
  assert.deepEqual(V.parseProfileUrl('https://x.com/Some_User?s=20'), { platform: 'x', handle: 'some_user' });
  assert.deepEqual(V.parseProfileUrl('https://twitter.com/abc'), { platform: 'x', handle: 'abc' });
  assert.deepEqual(V.parseProfileUrl('https://www.linkedin.com/in/jane-doe-123/'), { platform: 'linkedin', handle: 'jane-doe-123' });
  assert.deepEqual(V.parseProfileUrl('https://github.com/octo-cat/repo'), { platform: 'github', handle: 'octo-cat' });
  assert.equal(V.parseProfileUrl('https://x.com/home'), null);
  assert.equal(V.parseProfileUrl('https://example.com/user'), null);
  assert.equal(V.parseProfileUrl('not a url'), null);
  assert.equal(V.parseProfileUrl('https://notx.com/user'), null);
});

test('skeleton and lookalike', () => {
  assert.equal(V.skeleton('Brock_Hager'), V.skeleton('brock.hager'));
  assert.equal(V.skeleton('rnike'), V.skeleton('mike'));
  assert.equal(V.skeleton('аpple'), V.skeleton('apple')); // Cyrillic a
  assert.equal(V.skeleton('creat0r'), V.skeleton('creator'));
  const reg = [V.makeRegistryEntry('instagram', 'realcreator', 'VID1', '2026-01-01T00:00:00Z')];
  assert.equal(V.checkLookalike('instagram', 'RealCreator', reg).kind, 'exact');
  assert.equal(V.checkLookalike('instagram', 'real_creator', reg).kind, 'lookalike');
  assert.equal(V.checkLookalike('instagram', 'realcreater', reg).kind, 'near');
  assert.equal(V.checkLookalike('instagram', 'someoneelse', reg), null);
  assert.equal(V.checkLookalike('x', 'realcreator', reg), null);
});

test('vid links', () => {
  const vid = 'A'.repeat(22);
  assert.deepEqual(V.extractVidLinks(`my real accounts: ${V.buildVidLink('verify.example', vid)} thanks`), [{ host: 'verify.example', vid }]);
  assert.equal(V.extractVidLinks(`verify.example/v/${vid}x`).length, 0);
  assert.equal(V.extractVidLinks(`http://localhost:8787/v/${vid}`).length, 1);
  assert.equal(V.extractVidLinks(`evil.example/v/${vid}`, { hosts: ['verify.example'] }).length, 0);
});

test('identity: create, claim, tamper', async () => {
  const k = await V.generateKeyPair();
  const { vid, entry } = await V.createVp({ priv: k.priv, pub: k.pub });
  assert.equal(vid.length, 22);
  assert.ok((await V.verifyLog([entry], vid)).ok);
  assert.ok(!(await V.verifyLog([entry], 'B'.repeat(22))).ok);
  const bad = structuredClone(entry); bad.body.pub = (await V.generateKeyPair()).pub;
  assert.ok(!(await V.verifyLog([bad], vid)).ok);

  const claim = await V.makeClaim({ priv: k.priv, vid, platform: 'github', handle: '@Octo-Cat' });
  assert.equal(claim.body.handle, 'octo-cat');
  const vp = { vid, log: [entry], claims: [claim] };
  const r = await V.verifyVp(vp);
  assert.ok(r.ok); assert.equal(r.claims.length, 1);
  const forged = structuredClone(claim); forged.body.handle = 'someone-else';
  assert.equal((await V.verifyVp({ vid, log: [entry], claims: [forged] })).claims.length, 0);
  const other = await V.generateKeyPair();
  const wrong = await V.makeClaim({ priv: other.priv, vid, platform: 'github', handle: 'x1' });
  assert.equal((await V.verifyVp({ vid, log: [entry], claims: [wrong] })).claims.length, 0);
});

test('identity: rotation delay and chain', async () => {
  const t0 = new Date('2026-01-01T00:00:00Z');
  const k1 = await V.generateKeyPair();
  const k2 = await V.generateKeyPair();
  const { vid, entry } = await V.createVp({ priv: k1.priv, pub: k1.pub, now: t0 });
  const rot = await V.makeRotation({ priv: k1.priv, vid, prevEntry: entry, newPub: k2.pub, now: t0 });
  const log = [entry, rot];
  assert.ok((await V.verifyLog(log, vid)).ok);
  assert.equal(V.keyAt(log, new Date(t0.getTime() + 3600e3)), k1.pub);       // before delay: old key
  assert.equal(V.keyAt(log, new Date(t0.getTime() + 49 * 3600e3)), k2.pub);  // after delay: new key

  const early = await V.makeClaim({ priv: k2.priv, vid, platform: 'x', handle: 'abc', now: new Date(t0.getTime() + 3600e3) });
  const later = await V.makeClaim({ priv: k2.priv, vid, platform: 'x', handle: 'abc', now: new Date(t0.getTime() + 72 * 3600e3) });
  const oldAfter = await V.makeClaim({ priv: k1.priv, vid, platform: 'x', handle: 'abc', now: new Date(t0.getTime() + 72 * 3600e3) });
  assert.equal(await V.verifyClaim(log, early), false);
  assert.equal(await V.verifyClaim(log, later), true);
  assert.equal(await V.verifyClaim(log, oldAfter), false);

  // rotation signed by a stranger is rejected
  const k3 = await V.generateKeyPair();
  const evil = await V.makeRotation({ priv: k3.priv, vid, prevEntry: entry, newPub: k3.pub, now: t0 });
  assert.ok(!(await V.verifyLog([entry, evil], vid)).ok);
});

test('did document', async () => {
  const k = await V.generateKeyPair();
  const { vid, entry } = await V.createVp({ priv: k.priv, pub: k.pub });
  const claim = await V.makeClaim({ priv: k.priv, vid, platform: 'x', handle: 'abc' });
  const doc = V.didDocument({ host: 'localhost:8787', vid, log: [entry], claims: [claim] });
  assert.equal(doc.id, `did:web:localhost%3A8787:v:${vid}`);
  assert.deepEqual(doc.alsoKnownAs, ['https://x.com/abc']);
  assert.equal(doc.verificationMethod[0].publicKeyJwk.x, k.pub);
});

test('evaluateAccount states', async () => {
  const k = await V.generateKeyPair();
  const now = new Date('2026-06-01T00:00:00Z');
  const { vid, entry } = await V.createVp({ priv: k.priv, pub: k.pub, now: new Date('2026-01-01T00:00:00Z') });
  const claim = await V.makeClaim({ priv: k.priv, vid, platform: 'instagram', handle: 'realcreator', now: new Date('2026-01-02T00:00:00Z') });
  const vp = await V.verifyVp({ vid, log: [entry], claims: [claim] });
  const registry = [V.makeRegistryEntry('instagram', 'realcreator', vid, claim.body.created)];
  const base = { platform: 'instagram', vps: { [vid]: vp }, registry, now };

  assert.equal(V.evaluateAccount({ ...base, handle: 'realcreator', pageVids: [vid] }).state, 'verified');
  assert.equal(V.evaluateAccount({ ...base, handle: 'realcreator', pageVids: [] }).state, 'unconfirmed');
  const copied = V.evaluateAccount({ ...base, handle: 'fake_creator_99', pageVids: [vid] });
  assert.deepEqual([copied.state, copied.reason], ['impersonation', 'copied-link']);
  const look = V.evaluateAccount({ ...base, handle: 'real.creator', pageVids: [] });
  assert.deepEqual([look.state, look.reason], ['impersonation', 'lookalike']);
  assert.equal(V.evaluateAccount({ ...base, handle: 'nobody', pageVids: [] }).state, 'unknown');
  assert.equal(V.evaluateAccount({ ...base, handle: 'nobody', pageVids: ['Z'.repeat(22)] }).state, 'unverifiable');
  // recently verified is flagged
  const recent = V.evaluateAccount({ ...base, handle: 'realcreator', pageVids: [vid], now: new Date('2026-01-10T00:00:00Z') });
  assert.equal(recent.recentlyChanged, true);
});
