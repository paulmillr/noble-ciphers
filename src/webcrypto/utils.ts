// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.js on#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
import { crypto } from '@noble/ciphers/webcrypto/crypto';

/**
 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
 */
export function randomBytes(bytesLength = 32): Uint8Array {
  if (crypto && typeof crypto.getRandomValues === 'function') {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  throw new Error('crypto.getRandomValues must be defined');
}

function getWebcryptoSubtle() {
  if (crypto && typeof crypto.subtle === 'object' && crypto.subtle != null) return crypto.subtle;
  throw new Error('crypto.subtle must be defined');
}

// Overridable
const BLOCK_LEN = 16;
const IV_BUF = new Uint8Array(BLOCK_LEN);
export const cryptoSubtleUtils = {
  async aesEncrypt(key: Uint8Array, keyParams: any, cryptParams: any, plaintext: Uint8Array) {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
    const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
    return new Uint8Array(ciphertext);
  },
  async aesDecrypt(key: Uint8Array, keyParams: any, cryptParams: any, ciphertext: Uint8Array) {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
    const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
    return new Uint8Array(plaintext);
  },
  async aesEncryptBlock(msg: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    if (key.length !== 16 && key.length !== 32) throw new Error('invalid key length');
    const keyParams = { name: 'AES-CBC', length: key.length * 8 };
    const cryptParams = { name: 'aes-cbc', iv: IV_BUF, counter: IV_BUF, length: 64 };
    const ciphertext = await cryptoSubtleUtils.aesEncrypt(key, keyParams, cryptParams, msg);
    return ciphertext.subarray(0, 16);
  },
};
