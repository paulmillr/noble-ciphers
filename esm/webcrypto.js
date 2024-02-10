// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.js on#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
import { randomBytes, getWebcryptoSubtle } from '@noble/ciphers/crypto';
import { concatBytes } from './utils.js';
import { number } from './_assert.js';
import { bytes as abytes } from './_assert.js';
/**
 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
 */
export { randomBytes, getWebcryptoSubtle };
// Uses CSPRG for nonce, nonce injected in ciphertext
export function managedNonce(fn) {
    number(fn.nonceLength);
    return ((key, ...args) => ({
        encrypt: (plaintext, ...argsEnc) => {
            const { nonceLength } = fn;
            const nonce = randomBytes(nonceLength);
            const ciphertext = fn(key, nonce, ...args).encrypt(plaintext, ...argsEnc);
            const out = concatBytes(nonce, ciphertext);
            ciphertext.fill(0);
            return out;
        },
        decrypt: (ciphertext, ...argsDec) => {
            const { nonceLength } = fn;
            const nonce = ciphertext.subarray(0, nonceLength);
            const data = ciphertext.subarray(nonceLength);
            return fn(key, nonce, ...args).decrypt(data, ...argsDec);
        },
    }));
}
// Overridable
export const utils = {
    async encrypt(key, keyParams, cryptParams, plaintext) {
        const cr = getWebcryptoSubtle();
        const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
        const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
        return new Uint8Array(ciphertext);
    },
    async decrypt(key, keyParams, cryptParams, ciphertext) {
        const cr = getWebcryptoSubtle();
        const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
        const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
        return new Uint8Array(plaintext);
    },
};
function getCryptParams(algo, nonce, AAD) {
    if (algo === "AES-CBC" /* BlockMode.CBC */)
        return { name: "AES-CBC" /* BlockMode.CBC */, iv: nonce };
    if (algo === "AES-CTR" /* BlockMode.CTR */)
        return { name: "AES-CTR" /* BlockMode.CTR */, counter: nonce, length: 64 };
    if (algo === "AES-GCM" /* BlockMode.GCM */)
        return { name: "AES-GCM" /* BlockMode.GCM */, iv: nonce, additionalData: AAD };
    throw new Error('unknown aes block mode');
}
function generate(algo) {
    return (key, nonce, AAD) => {
        abytes(key);
        abytes(nonce);
        // const keyLength = key.length;
        const keyParams = { name: algo, length: key.length * 8 };
        const cryptParams = getCryptParams(algo, nonce, AAD);
        return {
            // keyLength,
            encrypt(plaintext) {
                abytes(plaintext);
                return utils.encrypt(key, keyParams, cryptParams, plaintext);
            },
            decrypt(ciphertext) {
                abytes(ciphertext);
                return utils.decrypt(key, keyParams, cryptParams, ciphertext);
            },
        };
    };
}
export const cbc = generate("AES-CBC" /* BlockMode.CBC */);
export const ctr = generate("AES-CTR" /* BlockMode.CTR */);
export const gcm = generate("AES-GCM" /* BlockMode.GCM */);
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
//# sourceMappingURL=webcrypto.js.map