// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.js on#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
import { crypto } from '@noble/ciphers/webcrypto/crypto';
import { Cipher, concatBytes } from '../utils.js';
import { number } from '../_assert.js';

/**
 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
 */
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

type RemoveNonceInner<T extends any[], Ret> = ((...args: T) => Ret) extends (
  arg0: any,
  arg1: any,
  ...rest: infer R
) => any
  ? (key: Uint8Array, ...args: R) => Ret
  : never;

type RemoveNonce<T extends (...args: any) => any> = RemoveNonceInner<Parameters<T>, ReturnType<T>>;
type CipherWithNonce = ((key: Uint8Array, nonce: Uint8Array, ...args: any[]) => Cipher) & {
  nonceLength: number;
};

// Uses CSPRG for nonce, nonce injected in ciphertext
export function managedNonce<T extends CipherWithNonce>(fn: T): RemoveNonce<T> {
  number(fn.nonceLength);
  return ((key: Uint8Array, ...args: any[]): any => ({
    encrypt: (plaintext: Uint8Array, ...argsEnc: any[]) => {
      const { nonceLength } = fn;
      const nonce = randomBytes(nonceLength);
      const ciphertext = (fn(key, nonce, ...args).encrypt as any)(plaintext, ...argsEnc);
      const out = concatBytes(nonce, ciphertext);
      ciphertext.fill(0);
      return out;
    },
    decrypt: (ciphertext: Uint8Array, ...argsDec: any[]) => {
      const { nonceLength } = fn;
      const nonce = ciphertext.subarray(0, nonceLength);
      const data = ciphertext.subarray(nonceLength);
      return (fn(key, nonce, ...args).decrypt as any)(data, ...argsDec);
    },
  })) as RemoveNonce<T>;
}

// // Type tests
// import { siv, gcm, ctr, ecb, cbc } from '../aes.js';
// import { xsalsa20poly1305 } from '../salsa.js';
// import { chacha20poly1305, xchacha20poly1305 } from '../chacha.js';

// const wsiv = managedNonce(siv);
// const wgcm = managedNonce(gcm);
// const wctr = managedNonce(ctr);
// const wcbc = managedNonce(cbc);
// const wsalsapoly = managedNonce(xsalsa20poly1305);
// const wchacha = managedNonce(chacha20poly1305);
// const wxchacha = managedNonce(xchacha20poly1305);

// // should fail
// const wcbc2 = managedNonce(managedNonce(cbc));
// const wecb = managedNonce(ecb);
