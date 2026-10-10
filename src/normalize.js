// SPDX-License-Identifier: Apache-2.0
// Platform rules are a starting point and incomplete (reserved paths especially).
export const PLATFORMS = {
  x: {
    name: 'X',
    hosts: ['x.com', 'twitter.com'],
    pattern: /^[a-z0-9_]{1,15}$/,
    url: (h) => `https://x.com/${h}`,
    reserved: ['home', 'i', 'explore', 'search', 'settings', 'notifications', 'messages', 'compose', 'hashtag', 'login', 'signup', 'tos', 'privacy'],
  },
  github: {
    name: 'GitHub',
    hosts: ['github.com'],
    pattern: /^[a-z0-9](?:[a-z0-9-]{0,38})$/,
    url: (h) => `https://github.com/${h}`,
    reserved: ['orgs', 'settings', 'topics', 'marketplace', 'features', 'pricing', 'login', 'join', 'about', 'explore', 'notifications', 'pulls', 'issues', 'sponsors', 'collections', 'trending', 'search'],
  },
  instagram: {
    name: 'Instagram',
    hosts: ['instagram.com'],
    pattern: /^[a-z0-9._]{1,30}$/,
    url: (h) => `https://www.instagram.com/${h}`,
    reserved: ['p', 'reel', 'reels', 'explore', 'accounts', 'stories', 'direct', 'tv', 'about', 'legal'],
  },
  facebook: {
    name: 'Facebook',
    hosts: ['facebook.com'],
    pattern: /^[a-z0-9.]{1,50}$/,
    url: (h) => `https://www.facebook.com/${h}`,
    reserved: ['profile.php', 'groups', 'pages', 'watch', 'marketplace', 'events', 'login', 'help', 'policies', 'privacy', 'gaming', 'reel', 'stories', 'friends', 'messages'],
  },
  linkedin: {
    name: 'LinkedIn',
    hosts: ['linkedin.com'],
    pathPrefix: 'in',
    pattern: /^[a-z0-9%_-]{3,100}$/,
    url: (h) => `https://www.linkedin.com/in/${h}`,
    reserved: [],
  },
};

export function hostMatches(host, hosts) {
  host = host.toLowerCase();
  return hosts.some((h) => host === h || host.endsWith('.' + h));
}

export function normalizeHandle(platform, handle) {
  if (!PLATFORMS[platform]) throw new Error(`unknown platform: ${platform}`);
  let h = String(handle).trim().normalize('NFKC');
  if (h.startsWith('@')) h = h.slice(1);
  return h.toLowerCase();
}

export function isValidHandle(platform, handle) {
  const p = PLATFORMS[platform];
  if (!p) return false;
  const h = normalizeHandle(platform, handle);
  return p.pattern.test(h) && !p.reserved.includes(h);
}

export function profileUrl(platform, handle) {
  return PLATFORMS[platform].url(normalizeHandle(platform, handle));
}

// Returns {platform, handle} for a profile URL, or null.
export function parseProfileUrl(url) {
  let u;
  try { u = new URL(url); } catch { return null; }
  if (!['http:', 'https:'].includes(u.protocol)) return null;
  for (const [platform, p] of Object.entries(PLATFORMS)) {
    if (!hostMatches(u.hostname, p.hosts)) continue;
    const parts = u.pathname.split('/').filter(Boolean);
    let seg;
    if (p.pathPrefix) {
      if (parts[0] !== p.pathPrefix || !parts[1]) return null;
      seg = parts[1];
    } else {
      seg = parts[0];
    }
    if (!seg) return null;
    const handle = normalizeHandle(platform, seg);
    if (!isValidHandle(platform, handle)) return null;
    return { platform, handle };
  }
  return null;
}
