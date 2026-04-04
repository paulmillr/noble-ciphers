import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { cbc, ctr, gcm } from '../src/aes.ts';
import { pathToFileURL } from 'node:url';
import { managedNonce, randomBytes } from '../src/utils.ts';
import * as web from '../src/webcrypto.ts';
const BT = { describe, should };

export function test(variant = 'noble', platform = { cbc, ctr, gcm, web }, { describe, should } = BT) {
const { cbc, ctr, gcm, web } = platform;
describe(`Webcrypto (${variant})`, () => {
  const ciphers = {
    cbc: { sync: cbc, async: web.cbc },
    ctr: { sync: ctr, async: web.ctr },
    gcm: { sync: gcm, async: web.gcm },
  };
  for (const name in ciphers) {
    const c = ciphers[name];
    should(name, async () => {
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
  should('ctr matches sync ctr when low 64-bit counter wraps', async () => {
    const key = Uint8Array.from([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    const nonce = Uint8Array.from([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
    const msg = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
    eql(await web.ctr(key, nonce).encrypt(msg), ctr(key, nonce).encrypt(msg));
  });
  should('gcm rejects falsy non-byte AAD', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    for (const bad of [false, 0, '', null]) throws(() => web.gcm(key, nonce, bad as any), TypeError);
  });
});
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
should.runWhen(import.meta.url);
