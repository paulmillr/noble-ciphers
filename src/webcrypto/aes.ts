import { getWebcryptoSubtle } from './utils.js';
import { ensureBytes, AsyncCipher } from '../utils.js';

// Overridable
export const utils = {
  async encrypt(key: Uint8Array, keyParams: any, cryptParams: any, plaintext: Uint8Array) {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
    const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
    return new Uint8Array(ciphertext);
  },
  async decrypt(key: Uint8Array, keyParams: any, cryptParams: any, ciphertext: Uint8Array) {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
    const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
    return new Uint8Array(plaintext);
  },
};

const enum BlockMode {
  CBC = 'AES-CBC',
  CTR = 'AES-CTR',
  GCM = 'AES-GCM',
}

function getCryptParams(
  algo: BlockMode,
  nonce: Uint8Array,
  AAD?: Uint8Array
): AesCbcParams | AesCtrParams | AesGcmParams {
  if (algo === BlockMode.CBC) return { name: BlockMode.CBC, iv: nonce };
  if (algo === BlockMode.CTR) return { name: BlockMode.CTR, counter: nonce, length: 64 };
  if (algo === BlockMode.GCM) return { name: BlockMode.GCM, iv: nonce, additionalData: AAD };
  throw new Error('unknown aes block mode');
}

function generate(algo: BlockMode) {
  return (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): AsyncCipher => {
    ensureBytes(key);
    ensureBytes(nonce);
    // const keyLength = key.length;
    const keyParams = { name: algo, length: key.length * 8 };
    const cryptParams = getCryptParams(algo, nonce, AAD);
    return {
      // keyLength,
      encrypt(plaintext: Uint8Array) {
        ensureBytes(plaintext);
        return utils.encrypt(key, keyParams, cryptParams, plaintext);
      },
      decrypt(ciphertext: Uint8Array) {
        ensureBytes(ciphertext);
        return utils.decrypt(key, keyParams, cryptParams, ciphertext);
      },
    };
  };
}

export const cbc = generate(BlockMode.CBC);
export const ctr = generate(BlockMode.CTR);
export const gcm = generate(BlockMode.GCM);
