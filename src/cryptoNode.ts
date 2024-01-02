// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// See utils.ts for details.
// The file will throw on node.js 14 and earlier.
// @ts-ignore
import * as nc from 'node:crypto';
const crypto =
  nc && typeof nc === 'object' && 'webcrypto' in nc ? (nc.webcrypto as any) : undefined;

export function randomBytes(bytesLength = 32): Uint8Array {
  if (crypto && typeof crypto.getRandomValues === 'function') {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  throw new Error('crypto.getRandomValues must be defined');
}

export function getWebcryptoSubtle() {
  if (crypto && typeof crypto.subtle === 'object' && crypto.subtle != null) return crypto.subtle;
  throw new Error('crypto.subtle must be defined');
}
