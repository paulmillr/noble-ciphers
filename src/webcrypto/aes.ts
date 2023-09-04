import { ensureBytes } from '../utils.js';
import { cryptoSubtleUtils } from './utils.js';

/**
 * AAD is only effective on AES-256-GCM or AES-128-GCM. Otherwise it'll be ignored
 */
export type Cipher = (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
) => {
  keyLength: number;
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
};

enum AesBlockMode {
  CBC = 'AES-CBC',
  CTR = 'AES-CTR',
  GCM = 'AES-GCM',
}

type BitLength = 128 | 256;

function getCryptParams(
  algo: AesBlockMode,
  nonce: Uint8Array,
  AAD?: Uint8Array
): AesCbcParams | AesCtrParams | AesGcmParams {
  if (algo === AesBlockMode.CBC) return { name: AesBlockMode.CBC, iv: nonce };
  if (algo === AesBlockMode.CTR) return { name: AesBlockMode.CTR, counter: nonce, length: 64 };
  if (algo === AesBlockMode.GCM) return { name: AesBlockMode.GCM, iv: nonce, additionalData: AAD };
  throw new Error('unknown aes cipher');
}

function generate(algo: AesBlockMode, length: BitLength): Cipher {
  const keyLength = length / 8;
  const keyParams = { name: algo, length };

  return (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => {
    ensureBytes(key, keyLength);
    const cryptParams = getCryptParams(algo, nonce, AAD);
    return {
      keyLength,
      encrypt(plaintext: Uint8Array) {
        ensureBytes(plaintext);
        return cryptoSubtleUtils.aesEncrypt(key, keyParams, cryptParams, plaintext);
      },
      decrypt(ciphertext: Uint8Array) {
        ensureBytes(ciphertext);
        return cryptoSubtleUtils.aesDecrypt(key, keyParams, cryptParams, ciphertext);
      },
    };
  };
}

export const aes_128_ctr = generate(AesBlockMode.CTR, 128);
export const aes_256_ctr = generate(AesBlockMode.CTR, 256);

export const aes_128_cbc = generate(AesBlockMode.CBC, 128);
export const aes_256_cbc = generate(AesBlockMode.CBC, 256);

export const aes_128_gcm = generate(AesBlockMode.GCM, 128);
export const aes_256_gcm = generate(AesBlockMode.GCM, 256);
