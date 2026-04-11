/**
 * WebCrypto-based AES gcm/ctr/cbc, `managedNonce` and `randomBytes`.
 * We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
 * @module
 */
import { abytes, anumber, type AsyncCipher, type TArg, type TRet } from './utils.ts';

function getWebcryptoSubtle(): any {
  const cr = typeof globalThis !== 'undefined' && (globalThis as any).crypto;
  if (cr && typeof cr.subtle === 'object' && cr.subtle != null) return cr.subtle;
  throw new Error('crypto.subtle must be defined');
}

type WebcryptoUtils = {
  encrypt(
    key: TArg<Uint8Array>,
    keyParams: unknown,
    cryptParams: unknown,
    plaintext: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>>;
  decrypt(
    key: TArg<Uint8Array>,
    keyParams: unknown,
    cryptParams: unknown,
    ciphertext: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>>;
};
/**
 * Internal webcrypto utils. Can be overridden if crypto.subtle is not present,
 * for example in React Native.
 * Raw keys are re-imported on every call; this wrapper intentionally does not
 * cache `CryptoKey` objects between operations.
 */
export const utils: TRet<WebcryptoUtils> = {
  async encrypt(
    key: TArg<Uint8Array>,
    keyParams: any,
    cryptParams: any,
    plaintext: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>> {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
    const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
    return new Uint8Array(ciphertext) as TRet<Uint8Array>;
  },
  async decrypt(
    key: TArg<Uint8Array>,
    keyParams: any,
    cryptParams: any,
    ciphertext: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>> {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
    const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
    return new Uint8Array(plaintext) as TRet<Uint8Array>;
  },
};

const mode = {
  CBC: 'AES-CBC',
  CTR: 'AES-CTR',
  GCM: 'AES-GCM',
} as const;
type BlockMode = (typeof mode)[keyof typeof mode];

function getCryptParams(algo: BlockMode, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>) {
  if (algo === mode.CBC) return { name: mode.CBC, iv: nonce };
  // WebCrypto allows 1..128 counter bits; use the full block to match sync ctr() / Node CTR wrap.
  if (algo === mode.CTR) return { name: mode.CTR, counter: nonce, length: 128 };
  if (algo === mode.GCM) {
    // Rely on the backend default tag length (128 bits) instead of setting it explicitly.
    if (AAD) return { name: mode.GCM, iv: nonce, additionalData: AAD };
    else return { name: mode.GCM, iv: nonce };
  }

  throw new Error('unknown aes block mode');
}

function generate(
  algo: BlockMode,
  nonceLength: number
): TRet<
  ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>) => AsyncCipher) & {
    blockSize: number;
    nonceLength: number;
  }
> {
  anumber(nonceLength);
  const res = (
    key: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    AAD?: TArg<Uint8Array>
  ): TRet<AsyncCipher> => {
    abytes(key);
    abytes(nonce);
    // Reject falsy non-byte AAD locally; otherwise false/0/''/null silently become "no AAD".
    if (AAD !== undefined) abytes(AAD, undefined, 'AAD');
    // Exact nonce-length enforcement and WebCrypto-specific AAD normalization are
    // delegated to the backend; locally we only require byte-array inputs here.
    // Keep caller key/nonce/AAD by reference; mutating them after
    // construction changes later operations.
    const keyParams = { name: algo, length: key.length * 8 };
    const cryptParams = getCryptParams(algo, nonce, AAD);
    let consumed = false;
    return {
      // keyLength,
      encrypt(plaintext: TArg<Uint8Array>): Promise<TRet<Uint8Array>> {
        abytes(plaintext);
        if (consumed) throw new Error('Cannot encrypt() twice with same key / nonce');
        consumed = true;
        return utils.encrypt(key, keyParams, cryptParams, plaintext);
      },
      decrypt(ciphertext: TArg<Uint8Array>): Promise<TRet<Uint8Array>> {
        abytes(ciphertext);
        return utils.decrypt(key, keyParams, cryptParams, ciphertext);
      },
    } as TRet<AsyncCipher>;
  };
  res.nonceLength = nonceLength;
  res.blockSize = 16; // always for AES
  return res as TRet<
    ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>) => AsyncCipher) & {
      blockSize: number;
      nonceLength: number;
    }
  >;
}

/**
 * AES-CBC implemented with WebCrypto.
 * Uses WebCrypto's built-in PKCS padding behavior; exact IV-length checks are
 * delegated to the backend instead of local `abytes(..., 16)` validation.
 * @param key - AES key bytes.
 * @param iv - 16-byte initialization vector.
 * @returns Async cipher instance.
 * @example
 * Encrypts a block with the browser or Node WebCrypto backend.
 *
 * ```ts
 * import { cbc } from '@noble/ciphers/webcrypto.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const iv = randomBytes(16);
 * const cipher = cbc(key, iv);
 * await cipher.encrypt(new Uint8Array(16));
 * ```
 */
export const cbc: TRet<
  ((key: TArg<Uint8Array>, iv: TArg<Uint8Array>) => AsyncCipher) & {
    blockSize: number;
    nonceLength: number;
  }
> = /* @__PURE__ */ (() => generate(mode.CBC, 16))();
/**
 * AES-CTR implemented with WebCrypto.
 * Uses WebCrypto's full 128-bit counter-length setting so the whole
 * 16-byte counter block is incremented, matching sync `aes.ts:ctr`.
 * @param key - AES key bytes.
 * @param nonce - 16-byte counter block incremented as a full big-endian AES counter block.
 * @returns Async cipher instance.
 * @example
 * Encrypts a short payload with WebCrypto AES-CTR.
 *
 * ```ts
 * import { ctr } from '@noble/ciphers/webcrypto.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const nonce = randomBytes(16);
 * const cipher = ctr(key, nonce);
 * await cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const ctr: TRet<
  ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>) => AsyncCipher) & {
    blockSize: number;
    nonceLength: number;
  }
> = /* @__PURE__ */ (() => generate(mode.CTR, 16))();
/**
 * AES-GCM implemented with WebCrypto.
 * AAD type normalization and nonce-shape enforcement beyond raw bytes are left
 * to the backend WebCrypto implementation.
 * @param key - AES key bytes.
 * @param nonce - Nonce bytes.
 * @param AAD - Additional authenticated data.
 * @returns Async cipher instance.
 * @example
 * Encrypts and authenticates plaintext with WebCrypto AES-GCM.
 *
 * ```ts
 * import { gcm } from '@noble/ciphers/webcrypto.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const key = randomBytes(16);
 * const nonce = randomBytes(12);
 * const cipher = gcm(key, nonce);
 * await cipher.encrypt(new Uint8Array([1, 2, 3]));
 * ```
 */
export const gcm: TRet<
  ((key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, AAD?: TArg<Uint8Array>) => AsyncCipher) & {
    blockSize: number;
    nonceLength: number;
  }
> = /* @__PURE__ */ (() => generate(mode.GCM, 12))();

// // Type tests
// import { siv, gcm, ctr, ecb, cbc } from '../aes.ts';
// import { xsalsa20poly1305 } from '../salsa.ts';
// import { chacha20poly1305, xchacha20poly1305 } from '../chacha.ts';

// const wsiv = managedNonce(siv);
// const wgcm = managedNonce(gcm);
// const wctr = managedNonce(ctr);
// const wcbc = managedNonce(cbc);
// const wsalsapoly = managedNonce(xsalsa20poly1305);
// const wchacha = managedNonce(chacha20poly1305);
// const wxchacha = managedNonce(xchacha20poly1305);

// // should fail
// const wcbc2 = managedNonce(managedNonce(cbc));
// const wctr = managedNonce(ctr);
// import { gcm as gcmSync } from '../aes.ts';
// const x1 = managedNonce(gcmSync);
// // const x1: (key: Uint8Array, AAD?: Uint8Array | undefined) => Cipher
// const x2 = managedNonce(gcm);
// // const x2: (key: Uint8Array, AAD?: Uint8Array | undefined) => AsyncCipher
