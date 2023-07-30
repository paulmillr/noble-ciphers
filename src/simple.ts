import { xchacha20poly1305 } from './chacha.js';
import { xsalsa20poly1305 } from './salsa.js';
import { concatBytes, ensureBytes, utf8ToBytes } from './utils.js';
import { aes_256_gcm } from './webcrypto/aes.js';
import { randomBytes } from './webcrypto/utils.js';

export { utf8ToBytes };

/**
 * Alias to xsalsa20poly1305, for compatibility with libsodium / nacl
 */
export function secretbox(key: Uint8Array, nonce: Uint8Array) {
  ensureBytes(key);
  ensureBytes(nonce);
  const xs = xsalsa20poly1305(key, nonce);
  return { seal: xs.encrypt, open: xs.decrypt };
}

export function randomKey(): Uint8Array {
  return randomBytes(32);
}
/**
 * Encrypt plaintext under key with random nonce, using xchacha20poly1305.
 * User never touches nonce: it is prepended to ciphertext.
 */
export function encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  ensureBytes(key);
  const nonce = randomBytes(24);
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);
  return concatBytes(nonce, ciphertext);
}

/**
 * Decrypt plaintext under key with random nonce, using xchacha20poly1305.
 * User never touches nonce: it is prepended to ciphertext.
 */
export function decrypt(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const nonceLength = 24;
  ensureBytes(ciphertext);
  if (ciphertext.length <= nonceLength) throw new Error('invalid ciphertext length');
  const nonce = ciphertext.subarray(0, nonceLength);
  const ciphertextWithoutNonce = ciphertext.subarray(nonceLength);
  return xchacha20poly1305(key, nonce).decrypt(ciphertextWithoutNonce);
}

export async function aes_encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonceLength = 12;
  ensureBytes(key);
  const nonce = randomBytes(nonceLength);
  const ciphertext = await aes_256_gcm(key, nonce).encrypt(plaintext);
  return concatBytes(nonce, ciphertext);
}

export async function aes_decrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const nonceLength = 12;
  ensureBytes(ciphertext);
  if (ciphertext.length <= nonceLength) throw new Error('invalid ciphertext length');
  const nonce = ciphertext.subarray(0, nonceLength);
  const ciphertextWithoutNonce = ciphertext.subarray(nonceLength);
  return aes_256_gcm(key, nonce).decrypt(ciphertextWithoutNonce);
}
