"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getWebcryptoSubtle = exports.randomBytes = void 0;
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// See utils.ts for details.
// The file will throw on node.js 14 and earlier.
// @ts-ignore
const nc = require("node:crypto");
const cr = nc && typeof nc === 'object' && 'webcrypto' in nc ? nc.webcrypto : undefined;
function randomBytes(bytesLength = 32) {
    if (cr && typeof cr.getRandomValues === 'function')
        return cr.getRandomValues(new Uint8Array(bytesLength));
    throw new Error('crypto.getRandomValues must be defined');
}
exports.randomBytes = randomBytes;
function getWebcryptoSubtle() {
    if (cr && typeof cr.subtle === 'object' && cr.subtle != null)
        return cr.subtle;
    throw new Error('crypto.subtle must be defined');
}
exports.getWebcryptoSubtle = getWebcryptoSubtle;
//# sourceMappingURL=cryptoNode.js.map