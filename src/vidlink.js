// SPDX-License-Identifier: Apache-2.0
// The VID link a user places in their profile: https://<host>/v/<vid>
export function buildVidLink(host, vid) {
  const scheme = /^localhost(:\d+)?$/.test(host) ? 'http' : 'https';
  return `${scheme}://${host}/v/${vid}`;
}

// Finds VID links in text or URLs. If `hosts` is given, only those hosts count.
export function extractVidLinks(text, { hosts } = {}) {
  const re = /(?:https?:\/\/)?((?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?::\d+)?)\/v\/([A-Za-z0-9_-]{22})(?![A-Za-z0-9_-])/gi;
  const out = [];
  for (const m of String(text).matchAll(re)) {
    const host = m[1].toLowerCase();
    if (hosts && !hosts.map((h) => h.toLowerCase()).includes(host)) continue;
    out.push({ host, vid: m[2] });
  }
  return out;
}
