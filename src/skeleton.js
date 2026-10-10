// SPDX-License-Identifier: Apache-2.0
// Lookalike "skeleton": handles that look alike reduce to the same string.
// Deliberately aggressive: a match means "possible impersonation", never "fake".
const LETTER_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
  'х': 'x', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g',
  'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'ι': 'i',
};
const GLYPH_MAP = {
  '1': 'l', 'i': 'l', '|': 'l', '0': 'o', '3': 'e', '5': 's', '$': 's',
  '4': 'a', '@': 'a', '7': 't', '8': 'b', '9': 'g',
};

export function skeleton(handle) {
  let s = String(handle).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase();
  s = [...s].map((c) => LETTER_MAP[c] ?? c).map((c) => GLYPH_MAP[c] ?? c).join('');
  s = s.replace(/[._\-\s]/g, '');
  return s.replace(/rn/g, 'm').replace(/vv/g, 'w');
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}
