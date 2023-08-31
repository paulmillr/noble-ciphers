import { ensureBytes } from '../utils.js';
import { getWebcryptoSubtle } from './utils.js';

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

type Algo = 'AES-CTR' | 'AES-GCM' | 'AES-CBC';
type BitLength = 128 | 256;

function getCryptParams(
  algo: Algo,
  nonce: Uint8Array,
  AAD?: Uint8Array
): AesCbcParams | AesCtrParams | AesGcmParams {
  const params = { name: algo };
  if (algo === 'AES-CTR') {
    return { ...params, counter: nonce, length: 64 } as AesCtrParams;
  } else if (algo === 'AES-GCM') {
    return { ...params, iv: nonce, additionalData: AAD } as AesGcmParams;
  } else if (algo === 'AES-CBC') {
    return { ...params, iv: nonce } as AesCbcParams;
  } else {
    throw new Error('unknown aes cipher');
  }
}

function generate(algo: Algo, length: BitLength): Cipher {
  const keyLength = length / 8;
  const keyParams = { name: algo, length };

  return (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => {
    ensureBytes(key, keyLength);
    const cryptParams = getCryptParams(algo, nonce, AAD);

    return {
      keyLength,

      async encrypt(plaintext: Uint8Array) {
        ensureBytes(plaintext);
        const cr = getWebcryptoSubtle();
        const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
        const cipher = await cr.encrypt(cryptParams, iKey, plaintext);
        return new Uint8Array(cipher);
      },

      async decrypt(ciphertext: Uint8Array) {
        ensureBytes(ciphertext);
        const cr = getWebcryptoSubtle();
        const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
        const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
        return new Uint8Array(plaintext);
      },
    };
  };
}

export const aes_128_ctr = generate('AES-CTR', 128);
export const aes_256_ctr = generate('AES-CTR', 256);

export const aes_128_cbc = generate('AES-CBC', 128);
export const aes_256_cbc = generate('AES-CBC', 256);

export const aes_128_gcm = generate('AES-GCM', 128);
export const aes_256_gcm = generate('AES-GCM', 256);
