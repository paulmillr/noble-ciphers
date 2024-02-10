const cr = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
export function randomBytes(bytesLength = 32) {
    if (cr && typeof cr.getRandomValues === 'function')
        return cr.getRandomValues(new Uint8Array(bytesLength));
    throw new Error('crypto.getRandomValues must be defined');
}
export function getWebcryptoSubtle() {
    if (cr && typeof cr.subtle === 'object' && cr.subtle != null)
        return cr.subtle;
    throw new Error('crypto.subtle must be defined');
}
//# sourceMappingURL=crypto.js.map