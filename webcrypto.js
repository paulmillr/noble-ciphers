"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.gcm = exports.ctr = exports.cbc = exports.utils = exports.managedNonce = exports.getWebcryptoSubtle = exports.randomBytes = void 0;
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.js on#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
const crypto_1 = require("@noble/ciphers/crypto");
Object.defineProperty(exports, "randomBytes", { enumerable: true, get: function () { return crypto_1.randomBytes; } });
Object.defineProperty(exports, "getWebcryptoSubtle", { enumerable: true, get: function () { return crypto_1.getWebcryptoSubtle; } });
const utils_js_1 = require("./utils.js");
const _assert_js_1 = require("./_assert.js");
const _assert_js_2 = require("./_assert.js");
// Uses CSPRG for nonce, nonce injected in ciphertext
function managedNonce(fn) {
    (0, _assert_js_1.number)(fn.nonceLength);
    return ((key, ...args) => ({
        encrypt: (plaintext, ...argsEnc) => {
            const { nonceLength } = fn;
            const nonce = (0, crypto_1.randomBytes)(nonceLength);
            const ciphertext = fn(key, nonce, ...args).encrypt(plaintext, ...argsEnc);
            const out = (0, utils_js_1.concatBytes)(nonce, ciphertext);
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
exports.managedNonce = managedNonce;
// Overridable
exports.utils = {
    async encrypt(key, keyParams, cryptParams, plaintext) {
        const cr = (0, crypto_1.getWebcryptoSubtle)();
        const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
        const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
        return new Uint8Array(ciphertext);
    },
    async decrypt(key, keyParams, cryptParams, ciphertext) {
        const cr = (0, crypto_1.getWebcryptoSubtle)();
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
        (0, _assert_js_2.bytes)(key);
        (0, _assert_js_2.bytes)(nonce);
        // const keyLength = key.length;
        const keyParams = { name: algo, length: key.length * 8 };
        const cryptParams = getCryptParams(algo, nonce, AAD);
        return {
            // keyLength,
            encrypt(plaintext) {
                (0, _assert_js_2.bytes)(plaintext);
                return exports.utils.encrypt(key, keyParams, cryptParams, plaintext);
            },
            decrypt(ciphertext) {
                (0, _assert_js_2.bytes)(ciphertext);
                return exports.utils.decrypt(key, keyParams, cryptParams, ciphertext);
            },
        };
    };
}
exports.cbc = generate("AES-CBC" /* BlockMode.CBC */);
exports.ctr = generate("AES-CTR" /* BlockMode.CTR */);
exports.gcm = generate("AES-GCM" /* BlockMode.GCM */);
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