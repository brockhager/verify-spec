// SPDX-License-Identifier: Apache-2.0
import { sha256hex } from './encoding.js';
import { normalizeHandle } from './normalize.js';

// Hash of a platform handle, for lookups that should not reveal the handle (private entries).
export async function handleHash(platform, handle) {
  return sha256hex(`${platform}:${normalizeHandle(platform, handle)}`);
}
export const hashPrefix = (hash, n = 4) => hash.slice(0, n);
