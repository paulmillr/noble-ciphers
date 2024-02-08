// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// See utils.ts for details.
declare const globalThis: Record<string, any> | undefined;
const cr = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;

export function randomBytes(bytesLength = 32): Uint8Array {
  if (cr && typeof cr.getRandomValues === 'function')
    return cr.getRandomValues(new Uint8Array(bytesLength));
  throw new Error('crypto.getRandomValues must be defined');
}

export function getWebcryptoSubtle() {
  if (cr && typeof cr.subtle === 'object' && cr.subtle != null) return cr.subtle;
  throw new Error('crypto.subtle must be defined');
}
