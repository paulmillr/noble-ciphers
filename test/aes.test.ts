import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { __TESTS, aeskw, aeskwp, cbc, cfb, ctr, ecb, gcm, gcmsiv, unsafe } from '../src/aes.ts';
import { bytesToHex, concatBytes, hexToBytes } from '../src/utils.ts';
import * as web from '../src/webcrypto.ts';
import { cbc_small, ctr_small, gcm_small } from './misc/micro-aes.ts';
import { json } from './utils.ts';

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-C
const NIST_VECTORS = json('./vectors/nist_800_38a.json');
const VECTORS = json('./vectors/siv.json');
const aes_gcm_test = json('./vectors/wycheproof/aes_gcm_test.json');
const aes_gcm_siv_test = json('./vectors/wycheproof/aes_gcm_siv_test.json');
const aes_cbc_test = json('./vectors/wycheproof/aes_cbc_pkcs5_test.json');
const aes_kw_test = json('./vectors/wycheproof/aes_wrap_test.json');
const aes_kwp_test = json('./vectors/wycheproof/aes_kwp_test.json');
const hex = { decode: hexToBytes, encode: bytesToHex };

const isDeno = 'deno' in process.versions;
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
const BT = { describe, it };

export function test(
  variant = 'noble',
  platform = { __TESTS, unsafe, aeskw, aeskwp, cbc, cfb, ctr, ecb, gcm, gcmsiv, web },
  { describe, it } = BT
) {
  const { __TESTS, unsafe, aeskw, aeskwp, cbc, cfb, ctr, ecb, gcm, gcmsiv, web } = platform;
  const CIPHERS = { ecb, cbc, ctr, siv: gcmsiv, gcm };
  describe(`AES (${variant})`, () => {
    if (__TESTS?.incBytes)
      it('incBytes accepts the largest safe bitwise carry and rejects the next one', () => {
        const out = new Uint8Array(16);
        __TESTS.incBytes(out, false, 0xffffff00);
        eql(out, hex.decode('000000000000000000000000ffffff00'));
        const before = out.slice();
        throws(() => __TESTS.incBytes(out, false, 0xffffff01), /incBytes: wrong carry/);
        eql(out, before);
        throws(() => __TESTS.incBytes(out, false, -1), /incBytes: wrong carry/);
        eql(out, before);
      });
    if (unsafe?.ctrCounter)
      it('unsafe ctrCounter leaves partial-block continuation to the caller', () => {
        const key = hex.decode('2b7e151628aed2a6abf7158809cf4f3c');
        const nonce = hex.decode('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
        const initial = bytesToHex(nonce);
        const xk = unsafe.expandKeyLE(key);
        const expected = unsafe.ctrCounter(xk, hex.decode(initial), new Uint8Array(17)).subarray(1);
        unsafe.ctrCounter(xk, nonce, new Uint8Array([0]));
        const afterPartial = bytesToHex(nonce);
        const resumed = unsafe.ctrCounter(xk, nonce, new Uint8Array(17)).subarray(1);
        eql(
          {
            afterPartial,
            resumed: bytesToHex(resumed),
          },
          {
            afterPartial: initial,
            resumed: bytesToHex(expected),
          }
        );
      });
    if (unsafe?.ctr32)
      it('unsafe ctr32 leaves partial-block continuation to the caller', () => {
        const key = hex.decode('2b7e151628aed2a6abf7158809cf4f3c');
        const nonce = hex.decode('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
        const xk = unsafe.expandKeyLE(key);
        const initial = bytesToHex(nonce);
        const expected = unsafe
          .ctr32(xk, false, hex.decode(initial), new Uint8Array(17))
          .subarray(1);
        unsafe.ctr32(xk, false, nonce, new Uint8Array([0]));
        const afterPartial = bytesToHex(nonce);
        const resumed = unsafe.ctr32(xk, false, nonce, new Uint8Array(17)).subarray(1);
        const zeroNonce = new Uint8Array(16);
        const zeroXk = unsafe.expandKeyLE(new Uint8Array(16));
        const expectedLE = unsafe
          .ctr32(zeroXk, true, new Uint8Array(16), new Uint8Array(17))
          .subarray(1);
        unsafe.ctr32(zeroXk, true, zeroNonce, new Uint8Array([0]));
        const afterPartialLE = bytesToHex(zeroNonce);
        const resumedLE = unsafe.ctr32(zeroXk, true, zeroNonce, new Uint8Array(17)).subarray(1);
        eql(
          {
            afterPartial,
            resumed: bytesToHex(resumed),
            afterPartialLE,
            resumedLE: bytesToHex(resumedLE),
          },
          {
            afterPartial: initial,
            resumed: bytesToHex(expected),
            afterPartialLE: bytesToHex(new Uint8Array(16)),
            resumedLE: bytesToHex(expectedLE),
          }
        );
      });
    it('rejects invalid keys before allocation and wipes plaintext copies', () => {
      const Native = Uint8Array;
      const key = new Native(16);
      const invalidKey = new Native(15);
      const iv = new Native(16);
      const data = new Native(1024);
      const off = new Native(1025).subarray(1);
      const plaintext = new Native(17).subarray(1);
      plaintext.fill(0x42);
      const padded = new Native(20).subarray(1);
      padded.fill(0x24);
      const ecbOut = new Native(32);
      const cbcOut = new Native(32);
      const allocs: Uint8Array[] = [];
      const Tracked = new Proxy(Native, {
        construct(target, args, next) {
          const out = Reflect.construct(target, args, next);
          if (typeof args[0] === 'number') allocs.push(out);
          return out;
        },
      });
      // Invalid keys are known before message-sized work, and alignment copies contain
      // plaintext, so retain the allocations to verify both rejection order and zeroization.
      (globalThis as any).Uint8Array = Tracked;
      try {
        const rejectsBeforeAlloc = (fn: () => unknown) => {
          allocs.length = 0;
          throws(fn, /aes key/);
          return allocs.map((buf) => buf.length);
        };
        const rejectsDetached = (create: (key: Uint8Array) => () => unknown) => {
          const key = new Native(16);
          const run = create(key);
          const buffer = key.buffer as ArrayBuffer;
          structuredClone(buffer, { transfer: [buffer] });
          return rejectsBeforeAlloc(run);
        };
        const rejectsResized = (create: (key: Uint8Array) => () => unknown) => {
          const buffer = new (ArrayBuffer as any)(16, { maxByteLength: 32 });
          if (!buffer.resizable) return [];
          const key = new Native(buffer);
          const run = create(key);
          buffer.resize(15);
          return rejectsBeforeAlloc(run);
        };
        const wipedCopies = (fn: () => Uint8Array) => {
          allocs.length = 0;
          const out = fn();
          return allocs.filter((buf) => buf.length === plaintext.length && buf !== out);
        };
        const wipedScratch = (fn: () => Uint8Array) => {
          allocs.length = 0;
          fn();
          return allocs.slice();
        };
        const got = {
          invalid: {
            ecbEncrypt: rejectsBeforeAlloc(() =>
              ecb(invalidKey, { disablePadding: true }).encrypt(off)
            ),
            ecbDecrypt: rejectsBeforeAlloc(() =>
              ecb(invalidKey, { disablePadding: true }).decrypt(data)
            ),
            cbcDecrypt: rejectsBeforeAlloc(() =>
              cbc(invalidKey, iv, { disablePadding: true }).decrypt(data)
            ),
            cbcEncrypt: rejectsBeforeAlloc(() =>
              cbc(invalidKey, iv, { disablePadding: true }).encrypt(off)
            ),
          },
          detached: {
            ecbEncrypt: rejectsDetached((key) => {
              const cipher = ecb(key, { disablePadding: true });
              return () => cipher.encrypt(off);
            }),
            ecbDecrypt: rejectsDetached((key) => {
              const cipher = ecb(key, { disablePadding: true });
              return () => cipher.decrypt(data);
            }),
            cbcEncrypt: rejectsDetached((key) => {
              const cipher = cbc(key, iv, { disablePadding: true });
              return () => cipher.encrypt(off);
            }),
            cbcDecrypt: rejectsDetached((key) => {
              const cipher = cbc(key, iv, { disablePadding: true });
              return () => cipher.decrypt(data);
            }),
          },
          resized: {
            ecbEncrypt: rejectsResized((key) => {
              const cipher = ecb(key, { disablePadding: true });
              return () => cipher.encrypt(off);
            }),
            ecbDecrypt: rejectsResized((key) => {
              const cipher = ecb(key, { disablePadding: true });
              return () => cipher.decrypt(data);
            }),
            cbcEncrypt: rejectsResized((key) => {
              const cipher = cbc(key, iv, { disablePadding: true });
              return () => cipher.encrypt(off);
            }),
            cbcDecrypt: rejectsResized((key) => {
              const cipher = cbc(key, iv, { disablePadding: true });
              return () => cipher.decrypt(data);
            }),
          },
          wiped: {
            ecbEncrypt: wipedCopies(() => ecb(key, { disablePadding: true }).encrypt(plaintext)),
            cbcEncrypt: wipedCopies(() =>
              cbc(key, iv, { disablePadding: true }).encrypt(plaintext)
            ),
            ecbPadded: wipedScratch(() => ecb(key).encrypt(padded, ecbOut)),
            cbcPadded: wipedScratch(() => cbc(key, iv).encrypt(padded, cbcOut)),
          },
        };
        const zero = new Native(plaintext.length);
        eql(got, {
          invalid: { ecbEncrypt: [], ecbDecrypt: [], cbcDecrypt: [], cbcEncrypt: [] },
          detached: { ecbEncrypt: [], ecbDecrypt: [], cbcEncrypt: [], cbcDecrypt: [] },
          resized: { ecbEncrypt: [], ecbDecrypt: [], cbcEncrypt: [], cbcDecrypt: [] },
          wiped: {
            ecbEncrypt: [zero],
            cbcEncrypt: [zero],
            ecbPadded: [new Native(padded.length), new Native(16)],
            cbcPadded: [new Native(padded.length), new Native(16)],
          },
        });
      } finally {
        (globalThis as any).Uint8Array = Native;
      }
    });
    it('CTR', () => {
      const nodeAES = (name) => ({
        encrypt: (buf, opts) =>
          Uint8Array.from(createCipheriv(name, opts.key, opts.nonce).update(buf)),
        decrypt: (buf, opts) =>
          Uint8Array.from(createDecipheriv(name, opts.key, opts.nonce).update(buf)),
      });
      // MDN says counter should be 64 bit
      // https://developer.mozilla.org/en-US/docs/Web/API/AesCtrParams
      // and links NIST SP800-38A which actually says in B.1 that standard increment function
      // uses all bits, so 128 bit counter. Which is the same as in OpenSSL.
      const key = new Uint8Array(32).fill(32);
      const msg = new Uint8Array(64).fill(64);
      const nonces = [
        new Uint8Array(16).fill(1),
        // 64 bit
        concatBytes(new Uint8Array(8), new Uint8Array(8).fill(255)),
        concatBytes(new Uint8Array(8).fill(255), new Uint8Array(8)),
        // 32 bit
        concatBytes(new Uint8Array(12), new Uint8Array(4).fill(255)),
        concatBytes(new Uint8Array(4).fill(255), new Uint8Array(12)),
        new Uint8Array(16).fill(255), // this wraps in 128 bit
      ];
      // So, current behaviour seems reasonable.
      // We don't have variable counter length at web version for now, but it works.
      if (isDeno) return; // deno fails
      for (const nonce of nonces) {
        const nodeVal = nodeAES('aes-256-ctr').encrypt(msg, { key, nonce });
        const c = ctr(key, nonce);
        eql(c.encrypt(msg), nodeVal);
        eql(c.decrypt(nodeVal), msg);
      }
    });
    it('CTR 128-bit counter wraparound (fixed vectors)', () => {
      // Environment-independent versions of the node.js cross-checks above
      // (those are skipped on deno). Expected values produced by OpenSSL via
      // node:crypto createCipheriv('aes-*-ctr'), which uses the full 128-bit
      // wrapping counter from NIST SP 800-38A B.1.
      const key = new Uint8Array(32).fill(7);
      const vectors = [
        {
          name: 'wrap ff..ff -> 00..00 across 3 full blocks',
          key,
          nonce: hex.decode('ffffffffffffffffffffffffffffffff'),
          msg: new Uint8Array(48).fill(0x42),
          ct: hex.decode(
            'b8f77a429211f0a04cd60b7b47218d73480facc5a52ea2963e2c5e9d852f62e1' +
              '1c99133b14a375bc56d58c82eb374e3b'
          ),
        },
        {
          name: 'wrap right before a final partial block (41 bytes)',
          key,
          nonce: hex.decode('fffffffffffffffffffffffffffffffe'),
          msg: new Uint8Array(41).fill(0x24),
          ct: hex.decode(
            '504dbe0025938b7f52a9329ec58d9e36de911c24f47796c62ab06d1d2147eb15' +
              '2e69caa3c348c4f058'
          ),
        },
        {
          name: 'carry propagation stops mid-counter (low 9 bytes are ff)',
          key: hex.decode('2b7e151628aed2a6abf7158809cf4f3c'),
          nonce: hex.decode('00000000000000ffffffffffffffffff'),
          msg: new Uint8Array(32).fill(0x11),
          ct: hex.decode('cbdd8059efaaeef253c4914426fb044ee755477cf13e438bb46c8b7175bd1ba7'),
        },
      ];
      for (const t of vectors) {
        eql(ctr(t.key, t.nonce).encrypt(t.msg), t.ct, t.name);
        eql(ctr(t.key, t.nonce).decrypt(t.ct), t.msg, t.name + ' (decrypt)');
      }
    });
    it('CFB final short segment matches byte-stream vector', () => {
      const key = hex.decode('000102030405060708090a0b0c0d0e0f');
      const iv = hex.decode('101112131415161718191a1b1c1d1e1f');
      // A 15-byte input has only a byte tail; BE output normalization must not rewrite it.
      const msg = hex.decode('a0a1a2a3a4a5a6a7a8a9aaabacadae');
      const ct = hex.decode('a75f4dd74570a5c938a744ba22393c');
      eql(
        {
          encrypted: bytesToHex(cfb(key, iv).encrypt(msg)),
          decrypted: bytesToHex(cfb(key, iv).decrypt(ct)),
        },
        {
          encrypted: bytesToHex(ct),
          decrypted: bytesToHex(msg),
        }
      );
    });
    it('CBC reports invalid PKCS padding as bad decrypt', () => {
      const key = new Uint8Array(16);
      const iv = new Uint8Array(16);
      const ct = cbc(key, iv).encrypt(hex.decode('68656c6c6f'));
      ct[ct.length - 1] ^= 1;
      throws(() => cbc(key, iv).decrypt(ct), /bad decrypt/);
    });
    describe('NIST 800-38a', () => {
      for (const t of NIST_VECTORS) {
        it(`${t.name}`, () => {
          let c;
          const cipher = CIPHERS[t.cipher];
          if (t.iv) c = cipher(hex.decode(t.key), hex.decode(t.iv || ''), { disablePadding: true });
          else c = cipher(hex.decode(t.key), { disablePadding: true });
          const ciphertext = concatBytes(...t.blocks.map((i) => hex.decode(i.ciphertext)));
          const plaintext = concatBytes(...t.blocks.map((i) => hex.decode(i.plaintext)));
          eql(c.decrypt(ciphertext), plaintext);
          eql(c.encrypt(plaintext), ciphertext);
        });
        if (t.name === 'ctr' && typeof web !== 'undefined') {
          it(`${t.name}: web`, async () => {
            let c;
            const cipher = web.ctr;
            if (t.iv)
              c = cipher(hex.decode(t.key), hex.decode(t.iv || ''), { disablePadding: true });
            else c = cipher(hex.decode(t.key), { disablePadding: true });
            const ciphertext = concatBytes(...t.blocks.map((i) => hex.decode(i.ciphertext)));
            const plaintext = concatBytes(...t.blocks.map((i) => hex.decode(i.plaintext)));
            eql(await c.decrypt(ciphertext), plaintext);
            eql(await c.encrypt(plaintext), ciphertext);
          });
        }
      }
    });
    describe('GCM-SIV', () => {
      it('vectors', () => {
        for (const flavor of ['aes128', 'aes256', 'counterWrap']) {
          for (let i = 0; i < VECTORS[flavor].length; i++) {
            const v = VECTORS[flavor][i];
            const label = `${flavor}(${i})`;
            let a = gcmsiv(hex.decode(v.key), hex.decode(v.nonce), hex.decode(v.AAD));
            eql(a.encrypt(hex.decode(v.plaintext)), hex.decode(v.result), `${label}.encrypt`);
            a = gcmsiv(hex.decode(v.key), hex.decode(v.nonce), hex.decode(v.AAD));
            eql(a.decrypt(hex.decode(v.result)), hex.decode(v.plaintext), `${label}.decrypt`);
          }
        }
      });
      it(`throws on lengths`, () => {
        gcmsiv(new Uint8Array(32), new Uint8Array(12), new Uint8Array(12));
        throws(() => gcmsiv(new Uint8Array(32), new Uint8Array(11), new Uint8Array(12))); // nonce
        throws(() => gcmsiv(new Uint8Array(33), new Uint8Array(12), new Uint8Array(12))); // key
      });
      it('AES-192 local extension roundtrips and authenticates', () => {
        // RFC 8452 only defines 16/32-byte keys; 24-byte AES-192 keys are a
        // documented local extension, so pin its roundtrip + tag rejection.
        const key = new Uint8Array(24).map((_, i) => i);
        const nonce = new Uint8Array(12).fill(3);
        const aad = new Uint8Array(5).fill(4);
        const msg = new Uint8Array(33).map((_, i) => 255 - i);
        const ct = gcmsiv(key, nonce, aad).encrypt(msg);
        eql(gcmsiv(key, nonce, aad).decrypt(ct), msg);
        const bad = ct.slice();
        bad[bad.length - 1] ^= 1;
        throws(() => gcmsiv(key, nonce, aad).decrypt(bad), /invalid polyval tag/);
      });
    });

    describe('Wycheproof', () => {
      it('vectors', async () => {
        const cases = [
          { name: 'GCM-SIV', groups: aes_gcm_siv_test.testGroups, cipher: 'siv' },
          { name: 'GCM', groups: aes_gcm_test.testGroups, cipher: 'gcm', webcipher: web.gcm },
          { name: 'CBC', groups: aes_cbc_test.testGroups, cipher: 'cbc', webcipher: web.cbc }, // PCKS5 is enabled by default
        ];
        for (const c of cases) {
          for (const g of c.groups) {
            const name = `Wycheproof/${c.name}/${g.ivSize}/${g.keySize}/${g.tagSize}/${g.type}`;
            for (let i = 0; i < g.tests.length; i++) {
              const t = g.tests[i];
              const label = `${name}: ${i}`;
              try {
                const ct = concatBytes(hex.decode(t.ct), hex.decode(t.tag || ''));
                const msg = hex.decode(t.msg);
                const cipher = CIPHERS[c.cipher];
                const key = hex.decode(t.key);
                const iv = hex.decode(t.iv);
                const aad = hex.decode(t.aad || '');
                // CBC vectors share the AEAD-shaped Wycheproof schema, but CBC has no AAD slot.
                const init = (fn) => (c.cipher === 'cbc' ? fn(key, iv) : fn(key, iv, aad));
                if (t.result === 'valid') {
                  if (t.flags.includes('SmallIv')) continue; // skip test, we don't support iv < 8b
                  const a = init(cipher);
                  const ct = concatBytes(hex.decode(t.ct), hex.decode(t.tag || ''));
                  eql(a.decrypt(ct), msg, `${label}: decrypt`);
                  eql(a.encrypt(msg), ct, `${label}: encrypt`);
                  // Webcrypto has different limits
                  if (c.webcipher && t.iv.length !== 16 && t.iv.length % 16 === 0) {
                    const wc = init(c.webcipher);
                    if (isDeno) continue;
                    eql(await wc.decrypt(ct), msg, `${label}: web decrypt`);
                    eql(await wc.encrypt(msg), ct, `${label}: web encrypt`);
                  }
                } else {
                  throws(() => init(cipher).decrypt(ct), `${label}: decrypt invalid`);
                }
              } catch (error) {
                if (error instanceof Error) error.message = `${label}: ${error.message}`;
                throw error;
              }
            }
          }
        }
      });
    });
    describe('micro-aes reference', () => {
      // Deterministic bytes so failures are reproducible.
      const buf = (len, seed = 0) =>
        Uint8Array.from({ length: len }, (_, i) => (i * 7 + seed) & 0xff);
      const LENS = [0, 1, 15, 16, 17, 32, 47, 64];
      it('ctr_small matches ctr', () => {
        for (const keyLen of [16, 24, 32]) {
          const key = buf(keyLen, 1);
          const nonce = buf(16, 2);
          for (const len of LENS) {
            const data = buf(len, 3);
            const exp = ctr(key, nonce).encrypt(data);
            eql(ctr_small(key, nonce).encrypt(data), exp, `encrypt ${keyLen}/${len}`);
            eql(ctr_small(key, nonce).decrypt(exp), data, `decrypt ${keyLen}/${len}`);
          }
        }
      });
      it('cbc_small matches cbc', () => {
        for (const keyLen of [16, 24, 32]) {
          const key = buf(keyLen, 1);
          const iv = buf(16, 2);
          for (const len of LENS) {
            const data = buf(len, 3);
            const exp = cbc(key, iv).encrypt(data);
            eql(cbc_small(key, iv).encrypt(data), exp, `encrypt ${keyLen}/${len}`);
            eql(cbc_small(key, iv).decrypt(exp), data, `decrypt ${keyLen}/${len}`);
          }
        }
      });
      it('gcm_small matches gcm', () => {
        for (const keyLen of [16, 24, 32]) {
          const key = buf(keyLen, 1);
          // Non-12-byte nonces exercise the GHASH-based J0 derivation.
          for (const nonceLen of [12, 8, 16]) {
            const nonce = buf(nonceLen, 2);
            for (const aad of [undefined, buf(13, 4)]) {
              for (const len of LENS) {
                const data = buf(len, 3);
                const label = `${keyLen}/${nonceLen}/${aad ? 'aad' : 'no-aad'}/${len}`;
                const exp = gcm(key, nonce, aad).encrypt(data);
                eql(gcm_small(key, nonce, aad).encrypt(data), exp, `encrypt ${label}`);
                eql(gcm_small(key, nonce, aad).decrypt(exp), data, `decrypt ${label}`);
              }
            }
          }
        }
        const key = buf(32, 1);
        const nonce = buf(12, 2);
        const corrupt = gcm_small(key, nonce).encrypt(buf(10, 3));
        corrupt[corrupt.length - 1] ^= 1;
        throws(() => gcm_small(key, nonce).decrypt(corrupt), /invalid tag/);
      });
    });
    describe('AESKW', () => {
      it('RFC3394', () => {
        // https://www.rfc-editor.org/rfc/rfc3394#section-4.1
        const vectors = [
          // 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
          {
            KEK: hex.decode('000102030405060708090A0B0C0D0E0F'),
            KeyData: hex.decode('00112233445566778899AABBCCDDEEFF'),
            Ciphertext: hex.decode('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'),
          },
          // 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
          {
            KEK: hex.decode('000102030405060708090A0B0C0D0E0F1011121314151617'),
            KeyData: hex.decode('00112233445566778899AABBCCDDEEFF'),
            Ciphertext: hex.decode('96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D'),
          },
          // 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
          {
            KEK: hex.decode('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
            KeyData: hex.decode('00112233445566778899AABBCCDDEEFF'),
            Ciphertext: hex.decode('64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7'),
          },
          // 4.4 Wrap 192 bits of Key Data with a 192-bit KEK
          {
            KEK: hex.decode('000102030405060708090A0B0C0D0E0F1011121314151617'),
            KeyData: hex.decode('00112233445566778899AABBCCDDEEFF0001020304050607'),
            Ciphertext: hex.decode(
              '031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2'
            ),
          },
          // 4.5 Wrap 192 bits of Key Data with a 256-bit KEK
          {
            KEK: hex.decode('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
            KeyData: hex.decode('00112233445566778899AABBCCDDEEFF0001020304050607'),
            Ciphertext: hex.decode(
              'A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1'
            ),
          },
          // 4.6 Wrap 256 bits of Key Data with a 256-bit KEK
          {
            KEK: hex.decode('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
            KeyData: hex.decode('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F'),
            Ciphertext: hex.decode(
              '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'
            ),
          },
        ];
        for (const t of vectors) {
          const kw = aeskw(t.KEK);
          eql(kw.encrypt(t.KeyData), t.Ciphertext);
          eql(kw.decrypt(t.Ciphertext), t.KeyData);
        }
      });
      it('Wycheproof', () => {
        for (const group of aes_kw_test.testGroups) {
          for (const t of group.tests) {
            const kw = aeskw(hex.decode(t.key));
            // 8-byte keys considered 'acceptable' by Wychenproof, but seems like bug.
            if (t.flags.includes('ShortKey')) continue;
            if (t.result === 'valid' || t.result === 'acceptable') {
              eql(hex.encode(kw.encrypt(hex.decode(t.msg))), t.ct);
              eql(hex.encode(kw.decrypt(hex.decode(t.ct))), t.msg);
            } else {
              throws(() => kw.decrypt(hex.decode(t.ct)));
              throws(() => eql(kw.encrypt(hex.decode(t.msg)), hex.decode(t.ct)));
            }
          }
        }
      });
      it('throws on 8 byte keys', () => {
        throws(() => aeskw(new Uint8Array(8)).encrypt(new Uint8Array(8)));
      });
      it('KWP', () => {
        // https://www.rfc-editor.org/rfc/rfc5649
        const vectors = [
          {
            KEK: hex.decode('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8'),
            Key: hex.decode('c37b7e6492584340bed12207808941155068f738'),
            Wrap: hex.decode('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a'),
          },
          {
            KEK: hex.decode('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8'),
            Key: hex.decode('466f7250617369'),
            Wrap: hex.decode('afbeb0f07dfbf5419200f2ccb50bb24f'),
          },
        ];
        for (const t of vectors) {
          const kwp = aeskwp(t.KEK);
          eql(kwp.encrypt(t.Key), t.Wrap);
          eql(kwp.decrypt(t.Wrap), t.Key);
        }
      });
      it('AESKWP: Wycheproof', () => {
        for (const group of aes_kwp_test.testGroups) {
          for (const t of group.tests) {
            const kwp = aeskwp(hex.decode(t.key));
            if (t.result === 'valid' || t.result === 'acceptable') {
              eql(hex.encode(kwp.encrypt(hex.decode(t.msg))), t.ct);
              eql(hex.encode(kwp.decrypt(hex.decode(t.ct))), t.msg);
            } else {
              throws(() => kwp.decrypt(hex.decode(t.ct)), 'decrypt');
              throws(() => eql(kwp.encrypt(hex.decode(t.msg)), hex.decode(t.ct)));
            }
          }
        }
      });
    });
  });
}
if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
it.runWhen(import.meta.url);
