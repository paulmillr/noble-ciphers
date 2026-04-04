import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { cmac } from '../src/aes.ts';
import { poly1305 } from '../src/_poly1305.ts';
import { ghash, polyval } from '../src/_polyval.ts';
import { pathToFileURL } from 'node:url';
import { concatBytes } from '../src/utils.ts';

const BT = { describe, should };

export function test(
  variant = 'noble',
  platform = { poly1305, ghash, polyval, cmac },
  { describe, should } = BT
) {
const { poly1305, ghash, polyval, cmac } = platform;

describe(`MAC (${variant})`, () => {
  const macs = [
    { name: 'poly1305', mac: poly1305, key: new Uint8Array(32).fill(1) },
    { name: 'ghash', mac: ghash, key: new Uint8Array(16).fill(2) },
    { name: 'polyval', mac: polyval, key: new Uint8Array(16).fill(3) },
    { name: 'cmac', mac: cmac, key: new Uint8Array(16).fill(4) },
  ];
  const a = new Uint8Array(16).fill(5);
  const b = new Uint8Array(16).fill(6);
  const mk = (len: number, off: number) => Uint8Array.from({ length: len }, (_, i) => off + i);
  const pad = (msg: Uint8Array) =>
    !msg.length || msg.length === 16 ? msg : concatBytes(msg, new Uint8Array(16 - msg.length));

  for (const { name, mac, key } of macs) {
    should(`${name}: incremental contract`, () => {
      // Use full 16-byte chunks so the shared expectation is valid for GHASH / POLYVAL too:
      // their `update()` semantics zero-pad each update boundary independently for short segments.
      const inc = mac.create(key);
      const single = mac.create(key);
      eql(inc.blockLen, 16);
      eql(inc.outputLen, 16);
      inc.update(a).update(b);
      single.update(concatBytes(a, b));
      const out = new Uint8Array(16);
      eql(inc.digestInto(out), undefined);
      eql(out, single.digest());
      eql(out, mac(concatBytes(a, b), key));
      throws(() => inc.update(new Uint8Array([7])), /digest/);
      single.destroy();
      inc.destroy();
      throws(() => inc.digest(), /destroyed/);
    });
    should(`${name}: digestInto allows oversized output and preserves tail`, () => {
      const msg = concatBytes(a, b);
      const tag = mac(msg, key);
      const out = new Uint8Array(32).fill(0xa5);
      const expect = new Uint8Array(32).fill(0xa5);
      expect.set(tag, 0);
      const h = mac.create(key);
      h.update(msg);
      eql(h.digestInto(out), undefined);
      eql(out, expect);
      h.destroy();
    });

    should(`${name}: rejects update after destroy`, () => {
      const h = mac.create(key);
      h.destroy();
      throws(() => h.update(new Uint8Array([1])), /destroyed/);
      throws(() => h.digest(), /destroyed/);
    });
  }

  for (const { name, mac, key } of macs.filter((i) => i.name === 'poly1305' || i.name === 'cmac')) {
    should(`${name}: split updates match raw concat for lengths 0..16`, () => {
      for (let alen = 0; alen <= 16; alen++) {
        for (let blen = 0; blen <= 16; blen++) {
          const a = mk(alen, 1);
          const b = mk(blen, 33);
          const inc = mac.create(key);
          inc.update(a).update(b);
          eql(inc.digest(), mac(concatBytes(a, b), key));
        }
      }
    });
  }

  for (const { name, mac, key } of macs.filter((i) => i.name === 'ghash' || i.name === 'polyval')) {
    should(`${name}: split updates match padded-segment model for lengths 0..16`, () => {
      for (let alen = 0; alen <= 16; alen++) {
        for (let blen = 0; blen <= 16; blen++) {
          const a = mk(alen, 1);
          const b = mk(blen, 33);
          const inc = mac.create(key);
          inc.update(a).update(b);
          eql(inc.digest(), mac(concatBytes(pad(a), pad(b)), key));
        }
      }
    });
  }
});
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
should.runWhen(import.meta.url);
