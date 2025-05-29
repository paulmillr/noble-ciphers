/**
 * WebCrypto-based AES gcm/ctr/cbc, `managedNonce` and `randomBytes`.
 * We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
 * @module
 */
import { abytes, anumber, type AsyncCipher, type Cipher, concatBytes } from './utils.ts';

function getWebcryptoSubtle(): any {
  const cr = typeof globalThis !== 'undefined' && (globalThis as any).crypto;
  if (cr && typeof cr.subtle === 'object' && cr.subtle != null) return cr.subtle;
  throw new Error('crypto.subtle must be defined');
}

/**
 * Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`.
 * We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
 */
export function randomBytes(bytesLength = 32): Uint8Array {
  const cr = typeof globalThis != null && (globalThis as any).crypto;
  if (!cr || typeof cr.getRandomValues !== 'function')
    throw new Error('crypto.getRandomValues must be defined');
  return cr.getRandomValues(new Uint8Array(bytesLength));
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

/**
 * Uses CSPRG for nonce, nonce injected in ciphertext.
 * For `encrypt`, a `nonceBytes`-length buffer is fetched from CSPRNG and
 * prepended to encrypted ciphertext. For `decrypt`, first `nonceBytes` of ciphertext
 * are treated as nonce.
 *
 * NOTE: Under the same key, using random nonces (e.g. `managedNonce`) with AES-GCM and ChaCha
 * should be limited to `2**23` (8M) messages to get a collision chance of `2**-50`. Stretching to  * `2**32` (4B) messages, chance would become `2**-33` - still negligible, but creeping up.
 * @example
 * const gcm = managedNonce(aes.gcm);
 * const ciphr = gcm(key).encrypt(data);
 * const plain = gcm(key).decrypt(ciph);
 */
export function managedNonce<T extends CipherWithNonce>(fn: T): RemoveNonce<T> {
  const { nonceLength } = fn;
  anumber(nonceLength);
  return ((key: Uint8Array, ...args: any[]): any => ({
    encrypt(plaintext: Uint8Array, ...argsEnc: any[]) {
      const nonce = randomBytes(nonceLength);
      const ciphertext = (fn(key, nonce, ...args).encrypt as any)(plaintext, ...argsEnc);
      const out = concatBytes(nonce, ciphertext);
      ciphertext.fill(0);
      return out;
    },
    decrypt(ciphertext: Uint8Array, ...argsDec: any[]) {
      const nonce = ciphertext.subarray(0, nonceLength);
      const data = ciphertext.subarray(nonceLength);
      return (fn(key, nonce, ...args).decrypt as any)(data, ...argsDec);
    },
  })) as RemoveNonce<T>;
}

/**
 * Internal webcrypto utils. Can be overridden of crypto.subtle is not present,
 * for example in React Native.
 */
export const utils: {
  encrypt: (key: Uint8Array, ...all: any[]) => Promise<Uint8Array>;
  decrypt: (key: Uint8Array, ...all: any[]) => Promise<Uint8Array>;
} = {
  async encrypt(
    key: Uint8Array,
    keyParams: any,
    cryptParams: any,
    plaintext: Uint8Array
  ): Promise<Uint8Array> {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
    const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
    return new Uint8Array(ciphertext);
  },
  async decrypt(
    key: Uint8Array,
    keyParams: any,
    cryptParams: any,
    ciphertext: Uint8Array
  ): Promise<Uint8Array> {
    const cr = getWebcryptoSubtle();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
    const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
    return new Uint8Array(plaintext);
  },
};

const mode = {
  CBC: 'AES-CBC',
  CTR: 'AES-CTR',
  GCM: 'AES-GCM',
} as const;
type BlockMode = (typeof mode)[keyof typeof mode];

function getCryptParams(algo: BlockMode, nonce: Uint8Array, AAD?: Uint8Array) {
  if (algo === mode.CBC) return { name: mode.CBC, iv: nonce };
  if (algo === mode.CTR) return { name: mode.CTR, counter: nonce, length: 64 };
  if (algo === mode.GCM) {
    if (AAD) return { name: mode.GCM, iv: nonce, additionalData: AAD };
    else return { name: mode.GCM, iv: nonce };
  }

  throw new Error('unknown aes block mode');
}

function generate(algo: BlockMode) {
  return (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): AsyncCipher => {
    abytes(key);
    abytes(nonce);
    const keyParams = { name: algo, length: key.length * 8 };
    const cryptParams = getCryptParams(algo, nonce, AAD);
    let consumed = false;
    return {
      // keyLength,
      encrypt(plaintext: Uint8Array) {
        abytes(plaintext);
        if (consumed) throw new Error('Cannot encrypt() twice with same key / nonce');
        consumed = true;
        return utils.encrypt(key, keyParams, cryptParams, plaintext);
      },
      decrypt(ciphertext: Uint8Array) {
        abytes(ciphertext);
        return utils.decrypt(key, keyParams, cryptParams, ciphertext);
      },
    };
  };
}

/** AES-CBC, native webcrypto version */
export const cbc: (key: Uint8Array, iv: Uint8Array) => AsyncCipher = /* @__PURE__ */ (() =>
  generate(mode.CBC))();
/** AES-CTR, native webcrypto version */
export const ctr: (key: Uint8Array, nonce: Uint8Array) => AsyncCipher = /* @__PURE__ */ (() =>
  generate(mode.CTR))();
/** AES-GCM, native webcrypto version */
export const gcm: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => AsyncCipher =
  /* @__PURE__ */ (() => generate(mode.GCM))();

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
