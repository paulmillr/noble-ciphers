import { ensureBytes } from '../utils.js';
import { getWebcryptoSubtle } from './utils.js';

function generate(algo: string, length: number) {
  const keyLength = length / 8;
  const keyParams = { name: algo, length };
  const cryptParams: Record<string, any> = { name: algo };
  // const params: Record<string, any> = ({ e: algo, i: { name: algo, length } });

  return (key: Uint8Array, nonce: Uint8Array) => {
    ensureBytes(key, keyLength);
    if (algo === 'AES-CTR') {
      cryptParams.counter = nonce;
      cryptParams.length = 64;
    } else {
      cryptParams.iv = nonce;
    }

    return {
      keyLength,

      async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
        ensureBytes(plaintext);
        const cr = getWebcryptoSubtle();
        const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
        const cipher = await cr.encrypt(cryptParams, iKey, plaintext);
        return new Uint8Array(cipher);
      },

      async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
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
