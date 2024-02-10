"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getWebcryptoSubtle = exports.randomBytes = void 0;
const cr = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
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
//# sourceMappingURL=crypto.js.map