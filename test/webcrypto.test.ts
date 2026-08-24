import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { cbc, ctr, gcm } from '../src/aes.ts';
import { managedNonce, randomBytes } from '../src/utils.ts';
import * as web from '../src/webcrypto.ts';
const BT = { describe, it };

export function test(variant = 'noble', platform = { cbc, ctr, gcm, web }, { describe, it } = BT) {
  const { cbc, ctr, gcm, web } = platform;
  describe(`Webcrypto (${variant})`, () => {
    const ciphers = {
      cbc: { sync: cbc, async: web.cbc },
      ctr: { sync: ctr, async: web.ctr },
      gcm: { sync: gcm, async: web.gcm },
    };
    for (const name in ciphers) {
      const c = ciphers[name];
      it(name, async () => {
        // Basic sanity check
        const key = randomBytes(32);
        const iv = randomBytes(16);
        const msg = randomBytes(64);
        eql(c.sync(key, iv).encrypt(msg), await c.async(key, iv).encrypt(msg));
        const ct = c.sync(key, iv).encrypt(msg);
        eql(c.sync(key, iv).decrypt(ct), await c.async(key, iv).decrypt(ct));
        eql(c.sync.nonceLength, c.async.nonceLength);
        // Managed
        const managed = {
          sync: managedNonce(c.sync),
          async: managedNonce(c.async),
        };
        const enc = managed.sync(key).encrypt(msg);
        eql(await managed.async(key).decrypt(enc), msg);
        eql(managed.sync(key).decrypt(enc), msg);
        const encAsync = await managed.async(key).encrypt(msg);
        eql(await managed.async(key).decrypt(encAsync), msg);
        eql(managed.sync(key).decrypt(encAsync), msg);
        if (name === 'gcm') {
          // check for AAD support
          const AAD = randomBytes(128);
          const enc = managed.sync(key, AAD).encrypt(msg);
          eql(await managed.async(key, AAD).decrypt(enc), msg);
          eql(managed.sync(key, AAD).decrypt(enc), msg);
          const encAsync = await managed.async(key, AAD).encrypt(msg);
          eql(await managed.async(key, AAD).decrypt(encAsync), msg);
          eql(managed.sync(key, AAD).decrypt(encAsync), msg);
        }
      });
    }
    it('ctr matches sync ctr when low 64-bit counter wraps', async () => {
      const key = Uint8Array.from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
      ]);
      const nonce = Uint8Array.from([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff,
      ]);
      const msg = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
      eql(await web.ctr(key, nonce).encrypt(msg), ctr(key, nonce).encrypt(msg));
    });
    it('enforces encrypt-once and rejects tampered GCM ciphertext', async () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const msg = randomBytes(33);
      const c = web.gcm(key, nonce);
      const ct = await c.encrypt(msg);
      // Same instance cannot encrypt twice, matching sync wrapCipher semantics.
      throws(() => c.encrypt(msg), /encrypt/);
      // Tag corruption must reject; the untouched ciphertext must still decrypt.
      const bad = ct.slice();
      bad[bad.length - 1] ^= 1;
      await rejects(() => web.gcm(key, nonce).decrypt(bad));
      eql(await web.gcm(key, nonce).decrypt(ct), msg);
    });
    it('gcm rejects falsy non-byte AAD', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      for (const bad of [false, 0, '', null])
        throws(() => web.gcm(key, nonce, bad as any), TypeError);
    });
    it('advertise AAD support explicitly', () => {
      eql(
        { cbc: (web.cbc as any).withAAD, ctr: (web.ctr as any).withAAD, gcm: web.gcm.withAAD },
        { cbc: undefined, ctr: undefined, gcm: true }
      );
    });
    it('reject AAD for no-AAD ciphers', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(16);
      const aad = randomBytes(16);
      throws(() => (web.cbc as any)(key, nonce, aad));
      throws(() => (web.ctr as any)(key, nonce, aad));
    });
    it('snapshots key and crypt params, but not payload, before awaiting key import', async () => {
      const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
      const calls: any[] = [];
      let resumeImport!: () => void;
      let importGate = new Promise<void>((resolve) => (resumeImport = resolve));
      const record = (params, key, data) => {
        const savedParams = { ...params };
        for (const name of ['iv', 'counter', 'additionalData'])
          if (savedParams[name] !== undefined)
            savedParams[name] = Uint8Array.from(savedParams[name]);
        calls.push({ params: savedParams, key, data: Uint8Array.from(data) });
      };
      const subtle = {
        async importKey(_format, key, _params, _extractable, usages) {
          const snapshot = Uint8Array.from(key);
          await importGate;
          return { key: snapshot, usage: usages[0] };
        },
        async encrypt(params, key, data) {
          record(params, key, data);
          return Uint8Array.from(data).buffer;
        },
        async decrypt(params, key, data) {
          record(params, key, data);
          return Uint8Array.from(data).buffer;
        },
      };
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle } });
      try {
        const key = Uint8Array.of(1, 2, 3, 4);
        const nonce = Uint8Array.of(5, 6, 7, 8);
        const aad = Uint8Array.of(9, 10);
        const plaintext = Uint8Array.of(11, 12, 13);
        const expected = {
          key: key.slice(),
          nonce: nonce.slice(),
          aad: aad.slice(),
        };
        const encrypted = web.gcm(key, nonce, aad).encrypt(plaintext);
        key.fill(0);
        nonce.fill(0);
        aad.fill(0);
        plaintext.fill(21);
        const expectedPlaintext = plaintext.slice();
        resumeImport();
        eql(await encrypted, expectedPlaintext);
        eql(calls[0].key, { key: expected.key, usage: 'encrypt' });
        eql(calls[0].params.iv, expected.nonce);
        eql(calls[0].params.additionalData, expected.aad);
        eql(calls[0].data, expectedPlaintext);

        importGate = new Promise<void>((resolve) => (resumeImport = resolve));
        const ciphertext = Uint8Array.of(14, 15, 16);
        const decryptNonce = Uint8Array.of(17, 18, 19, 20);
        const expectedNonce = decryptNonce.slice();
        const decrypted = web.ctr(expected.key, decryptNonce).decrypt(ciphertext);
        decryptNonce.fill(0);
        ciphertext.fill(22);
        const expectedCiphertext = ciphertext.slice();
        resumeImport();
        eql(await decrypted, expectedCiphertext);
        eql(calls[1].params.counter, expectedNonce);
        eql(calls[1].data, expectedCiphertext);
      } finally {
        if (originalCrypto) Object.defineProperty(globalThis, 'crypto', originalCrypto);
        else delete (globalThis as any).crypto;
      }
    });
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
it.runWhen(import.meta.url);
