// SPDX-License-Identifier: Apache-2.0
import { normalizeHandle } from './normalize.js';
import { skeleton, levenshtein } from './skeleton.js';

// registry entry: { p: platform, h: normalized handle, s: skeleton, v: vid, t: claim created }
export function makeRegistryEntry(platform, handle, vid, created) {
  const h = normalizeHandle(platform, handle);
  return { p: platform, h, s: skeleton(h), v: vid, t: created };
}

// Returns the strongest match or null: exact > lookalike > near.
export function checkLookalike(platform, handle, registry) {
  const h = normalizeHandle(platform, handle);
  const s = skeleton(h);
  let best = null;
  for (const e of registry) {
    if (e.p !== platform) continue;
    let kind = null;
    if (e.h === h) kind = 'exact';
    else if (e.s === s) kind = 'lookalike';
    else if (s.length >= 6 && e.s.length >= 6 && levenshtein(s, e.s) <= 1) kind = 'near';
    if (!kind) continue;
    const rank = { exact: 3, lookalike: 2, near: 1 };
    if (!best || rank[kind] > rank[best.kind]) best = { kind, vid: e.v, handle: e.h };
  }
  return best;
}
