// SPDX-License-Identifier: Apache-2.0
import { normalizeHandle } from './normalize.js';
import { checkLookalike } from './lookalike.js';

// Decides what the extension shows for one profile page. Pure function: no network.
//  pageVids: VIDs whose links were found on the page
//  vps:      map vid -> result of verifyVp() ({ok, claims})
//  registry: downloaded public list of entries
// States: verified | impersonation | unconfirmed | unverifiable | unknown
export function evaluateAccount({ platform, handle, pageVids = [], vps = {}, registry = [], now = new Date(), recentDays = 30 }) {
  const h = normalizeHandle(platform, handle);
  let copiedFrom = null;
  let unresolved = false;

  for (const vid of pageVids) {
    const vp = vps[vid];
    if (!vp?.ok) { unresolved = true; continue; }
    const c = vp.claims.find((c) => c.body.platform === platform && c.body.handle === h);
    if (c) {
      const ageDays = (now - new Date(c.body.created)) / 864e5;
      return { state: 'verified', vid, since: c.body.created, recentlyChanged: ageDays < recentDays };
    }
    copiedFrom = copiedFrom ?? vid;
  }
  // Page links to a real profile that does not list this account: link was copied.
  if (copiedFrom) return { state: 'impersonation', reason: 'copied-link', vid: copiedFrom };

  const lk = checkLookalike(platform, h, registry);
  if (lk?.kind === 'exact') return { state: 'unconfirmed', vid: lk.vid };
  if (lk) return { state: 'impersonation', reason: lk.kind, vid: lk.vid, handle: lk.handle };
  if (unresolved) return { state: 'unverifiable' };
  return { state: 'unknown' };
}
