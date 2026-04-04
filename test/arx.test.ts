import { describe, should } from '@paulmillr/jsbt/test.js';
import { base64 } from '@scure/base';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { poly1305 } from '../src/_poly1305.ts';
import {
  __TESTS,
  chacha8,
  chacha12,
  chacha20,
  chacha20orig,
  chacha20poly1305,
  hchacha,
  xchacha20,
  xchacha20poly1305,
} from '../src/chacha.ts';
import { pathToFileURL } from 'node:url';
import { hsalsa, salsa20, secretbox, xsalsa20, xsalsa20poly1305 } from '../src/salsa.ts';
import * as utils from '../src/utils.ts';
import { json } from './utils.ts';

const stable_chacha_poly = json('./vectors/stablelib_chacha20poly1305.json');
const stable_xchacha_poly = json('./vectors/stablelib_xchacha20poly1305.json');
const stable_poly1305 = json('./vectors/stablelib_poly1305.json');
// Wycheproof
const wycheproof_chacha20_poly1305 = json('./vectors/wycheproof/chacha20_poly1305_test.json');
const wycheproof_xchacha20_poly1305 = json('./vectors/wycheproof/xchacha20_poly1305_test.json');
// getKey for hsalsa/hchacha
const sigma16 = new TextEncoder().encode('expand 16-byte k');
const sigma32 = new TextEncoder().encode('expand 32-byte k');
const sigma16_32 = utils.u32(sigma16);
const sigma32_32 = utils.u32(sigma32);
const { u32 } = utils;
const hex = { decode: utils.hexToBytes, encode: utils.bytesToHex };

const getKey = (key) => {
  if (key.length === 32) return { key, sigma: sigma32_32 };
  const k = new Uint8Array(32);
  k.set(key);
  k.set(key, 16);
  return { key, sigma: sigma16_32 };
};
const BT = { describe, should };

export function test(
  variant = 'noble',
  platform = {
    poly1305,
    chacha8,
    chacha12,
    chacha20,
    chacha20orig,
    chacha20poly1305,
    hchacha,
    xchacha20,
    xchacha20poly1305,
    hsalsa,
    salsa20,
    secretbox,
    xsalsa20,
    xsalsa20poly1305,
  },
  { describe, should } = BT
) {
const {
  poly1305,
  chacha8,
  chacha12,
  chacha20,
  chacha20orig,
  chacha20poly1305,
  hchacha,
  xchacha20,
  xchacha20poly1305,
  hsalsa,
  salsa20,
  secretbox,
  xsalsa20,
  xsalsa20poly1305,
} = platform;
describe(`Salsa20 (${variant})`, () => {
  should('basic', () => {
    const stable_salsa = json('./vectors/stablelib_salsa20.json');
    for (const v of stable_salsa) {
      {
        const dst = salsa20(hex.decode(v.key), hex.decode(v.nonce), new Uint8Array(v.length));
        const res = new Uint8Array(64);
        let i = 0;
        while (i < dst.length) for (let j = 0; j < 64; j++) res[j] ^= dst[i++];
        eql(hex.encode(res), v.digest);
      }
    }
  });
  if (hsalsa) {
    should('hsalsa', () => {
      const src = hex.decode('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0');
      const good = 'c6cb53882782b5b86df1ab2ed9b810ec8a88c0a7f29211e693f0019fe0728858';
      const dst = new Uint8Array(32);

      const { key, sigma } = getKey(
        hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
      );
      hsalsa(sigma, u32(key), u32(src), u32(dst));
      eql(hex.encode(dst), good);
    });
  }
  should('xsalsa20', () => {
    const key = hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const nonce = hex.decode('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8');
    const good =
      '300885cce813d8cdbe05f89706f9d5557041e4fadc3ebc5db89c6ca60f7' +
      '3ede4f91ff1f9521d3e9af058e037e7fd0601db9ccbd7a9f5ced151426f' +
      'de32fc544f4f95576e2614377049c258664845a93d5ff5dd479cfeb55c7' +
      '579b60d419b8a8c03da3494993577b4597dcb658be52ab7';
    const dst = new Uint8Array(good.length / 2);
    xsalsa20(key, nonce, dst, dst);
    eql(hex.encode(dst), good);
  });
});

describe(`chacha (${variant})`, () => {
  should('chacha8 basic round-trip', () => {
    const key = new Uint8Array(32).fill(1);
    const nonce = new Uint8Array(12).fill(2);
    const msg = Uint8Array.from({ length: 32 }, (_, i) => i);
    const enc = chacha8(key, nonce, msg);
    eql(chacha8(key, nonce, enc), msg);
  });
  should('basic', () => {
    const stable_chacha = json('./vectors/stablelib_chacha20.json');
    for (const v of stable_chacha) {
      const res = chacha20orig(
        hex.decode(v.key),
        hex.decode(v.nonce),
        new Uint8Array(v.stream.length / 2)
      );
      eql(hex.encode(res), v.stream);
    }
  });
  should('chachaCore_small matches chachaCore on the RFC 8439 block-function input', () => {
    const sigma = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    const key = new Uint32Array([
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
      0x1f1e1d1c,
    ]);
    const nonce = new Uint32Array([0x09000000, 0x4a000000, 0x00000000]);
    const small = new Uint32Array(16);
    const fast = new Uint32Array(16);
    __TESTS.chachaCore_small(sigma, key, nonce, small, 1, 20);
    __TESTS.chachaCore(sigma, key, nonce, fast, 1, 20);
    eql(small, fast);
  });
  should('short key', () => {
    const res = chacha20orig(
      new Uint8Array(16).fill(1),
      new Uint8Array(8).fill(2),
      new Uint8Array(10).fill(10)
    );
    eql(hex.encode(res), '4ad24b21cba95a002754');
  });
  should('small nonce', () => {
    throws(() =>
      chacha20orig(
        new Uint8Array(16).fill(1),
        new Uint8Array(6).fill(2),
        new Uint8Array(10).fill(10)
      )
    );
  });

  if (hchacha) {
    // test taken from draft-arciszewski-xchacha-03 section 2.2.1
    // see https://tools.ietf.org/html/draft-arciszewski-xchacha-03#section-2.2.1
    should('hchacha', () => {
      const { key, sigma } = getKey(
        hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
      );
      const nonce = hex.decode('000000090000004a0000000031415927');
      const good = '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc';
      const subkey = new Uint8Array(32);
      hchacha(sigma, u32(key), u32(nonce.subarray(0, 16)), u32(subkey));
      eql(hex.encode(subkey), good);
    });
  }

  // test taken from XChaCha20 TV1 in libsodium (line 93 in libsodium/test/default/xchacha20.c)
  should('xchacha20/0', () => {
    const key = hex.decode('79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4');
    const nonce = hex.decode('b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419');
    const good = 'c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c';
    eql(hex.encode(xchacha20(key, nonce, new Uint8Array(good.length / 2))), good);
  });

  // test taken from draft-arciszewski-xchacha-03 section A.3.2
  // see https://tools.ietf.org/html/draft-arciszewski-xchacha-03#appendix-A.3.2
  should('xchacha20/1', () => {
    const key = hex.decode('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const plaintext = hex.decode(
      '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973' +
        '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420' +
        '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e' +
        '2049742069732061626f7574207468652073697a65206f662061204765726d61' +
        '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061' +
        '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c' +
        '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173' +
        '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163' +
        '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963' +
        '2066616d696c792043616e696461652e'
    );
    const nonce = hex.decode('404142434445464748494a4b4c4d4e4f5051525354555658');
    const ciphertext =
      '4559abba4e48c16102e8bb2c05e6947f' +
      '50a786de162f9b0b7e592a9b53d0d4e9' +
      '8d8d6410d540a1a6375b26d80dace4fa' +
      'b52384c731acbf16a5923c0c48d3575d' +
      '4d0d2c673b666faa731061277701093a' +
      '6bf7a158a8864292a41c48e3a9b4c0da' +
      'ece0f8d98d0d7e05b37a307bbb663331' +
      '64ec9e1b24ea0d6c3ffddcec4f68e744' +
      '3056193a03c810e11344ca06d8ed8a2b' +
      'fb1e8d48cfa6bc0eb4e2464b74814240' +
      '7c9f431aee769960e15ba8b96890466e' +
      'f2457599852385c661f752ce20f9da0c' +
      '09ab6b19df74e76a95967446f8d0fd41' +
      '5e7bee2a12a114c20eb5292ae7a349ae' +
      '577820d5520a1f3fb62a17ce6a7e68fa' +
      '7c79111d8860920bc048ef43fe84486c' +
      'cb87c25f0ae045f0cce1e7989a9aa220' +
      'a28bdd4827e751a24a6d5c62d790a663' +
      '93b93111c1a55dd7421a10184974c7c5';
    eql(hex.encode(xchacha20(key, nonce, plaintext)), ciphertext);
  });
  should('output length', () => {
    for (const fn of [chacha8, chacha12, chacha20, chacha20orig, xchacha20, xsalsa20, salsa20]) {
      // thows on output < data
      throws(() =>
        fn(new Uint8Array(32), new Uint8Array(16), new Uint8Array(10), new Uint8Array(9))
      );
    }
  });
  should('raw stream ciphers reject oversized output buffers', () => {
    const data = new Uint8Array(4);
    const cases = [
      { fn: chacha8, key: new Uint8Array(32), nonce: new Uint8Array(12) },
      { fn: chacha12, key: new Uint8Array(32), nonce: new Uint8Array(12) },
      { fn: chacha20, key: new Uint8Array(32), nonce: new Uint8Array(12) },
      { fn: chacha20orig, key: new Uint8Array(32), nonce: new Uint8Array(8) },
      { fn: xchacha20, key: new Uint8Array(32), nonce: new Uint8Array(24) },
      { fn: salsa20, key: new Uint8Array(32), nonce: new Uint8Array(8) },
      { fn: xsalsa20, key: new Uint8Array(32), nonce: new Uint8Array(24) },
    ];
    for (const { fn, key, nonce } of cases) {
      throws(() => fn(key, nonce, data, new Uint8Array(8)), /"output" expected Uint8Array of length 4/);
    }
  });
});

describe(`counter oracles (${variant})`, () => {
  const seq = (start: number, len: number) => Uint8Array.from({ length: len }, (_, i) => start + i);
  const pat = (len: number) => Uint8Array.from({ length: len }, (_, i) => 0x30 + (i % 32));
  const counter = (name: string, fn: () => Uint8Array, exp: string) =>
    should(name, () => throws(() => eql(fn(), hex.decode(exp)), /arx: counter overflow/));

  // Pin the exact boundary bytes from the local production oracles so explicit-counter behavior
  // stays visible in review: noble currently rejects `0xffffffff` on every shared ARX surface.
  // AEAD/default paths are intentionally omitted here: they don't accept a public counter, and
  // even a 32-bit boundary would take about 2^32 * 64 bytes = 256 GiB to hit through normal use.
  counter(
    'chacha20: RFC/IETF last valid 32-bit counter block',
    () => chacha20(seq(0, 32), seq(0xa0, 12), pat(64), undefined, 0xffffffff),
    'af60ebc8a7cc0777591b15f06fd4877b7873967879542b17f7dffc072dc4933103a0ba277db1935b2d6794b51b9f6dd86e289f4a3ae2903e7fc81030b6f29916'
  );
  counter(
    'chacha20: RFC/IETF stream crosses 0xffffffff -> 0x100000000',
    () => chacha20(seq(0, 32), seq(0xa0, 12), pat(128), undefined, 0xfffffffe),
    '1d248024960d8b8a80d367a10cca865c190cd21346304cbe0adb6c01d01ca3eb0b1a213566648be45cb026cc319325c7e5484edc8492075a366745e8d9810959af60ebc8a7cc0777591b15f06fd4877b7873967879542b17f7dffc072dc4933103a0ba277db1935b2d6794b51b9f6dd86e289f4a3ae2903e7fc81030b6f29916'
  );
  counter(
    'chacha20: OpenSSL/Node 16-byte-IV low word 0xffffffff',
    () => chacha20(seq(0, 32), seq(0xa0, 12), new Uint8Array(64), undefined, 0xffffffff),
    'f664a96a4e604407db9f6c8a9f828c197bcbcc5effc416807451249a6efe4f6d9b9ba5fe0e5cad96023b16d2b7dffd2b6a95b7cb3fa76bf82148471c0fa3c5a0'
  );
  counter(
    'chacha20: OpenSSL/Node 16-byte-IV carries into word 1',
    () => chacha20(seq(0, 32), seq(0xa0, 12), new Uint8Array(128), undefined, 0xfffffffe),
    '02ee48cc38408bdfc666d8b2e2847783942d00e039d28aafcba27f8b002c71145a7f02874679b626d1f78a02aaae5d8369af4b8efa6f297f41b6923a77c06d35f664a96a4e604407db9f6c8a9f828c197bcbcc5effc416807451249a6efe4f6d9b9ba5fe0e5cad96023b16d2b7dffd2b6a95b7cb3fa76bf82148471c0fa3c5a0'
  );
  counter(
    'chacha20orig: libsodium raw stream carries into the high 32 bits',
    () => chacha20orig(seq(0x00, 32), seq(0xa0, 8), new Uint8Array(192), undefined, 0xffffffff),
    'aa07a6552d0b049adaacee7d2487a4bde0b35396ee1003f75310c36691ac2a8abd997a5e63b9e7954f21323435e6eeffc36bd58b8695944fac3eb03fad55a13b8902e65d02ea2c1db273c4f6542aef8a8eeeccca7bbed8564375ed48ff3146002c94541c193de0f59f3ede7795dbfd2c8051cb271836ca71247e41a34a0c5f51901b8cf636e3fd52f36e599354a2e64311e5f387fdec0ec17058ef95d07910c1ee03735043dc71c06382add9ee6edfaf1df4f22a633efa6012ebc6d9bff49538'
  );
  counter(
    'salsa20: libsodium raw stream carries into the high 32 bits',
    () => salsa20(seq(0x20, 32), seq(0xb0, 8), new Uint8Array(192), undefined, 0xffffffff),
    '9e3a95ac113554cde3781eb81f197cf58650ac236882a4cbd3d704a31348672e75feb24a776aff7a94f4032f4959138f098d86e066aa3332e8657d6f06edfd82e6336ab673497dcd63746f26fbbab4c4cdd2f163f93356d3e777bb336f2de70dbda89bba9692b665046249f3d2be661850c1f8f0510c767d76212a04cc1a6e28fe980632e101aa2c8819153fa8a79f5e682786fbed2379d72c358f7264e6fd14291e5c37ef4ac0e4083d8f4828622e2005059452accb30f22c4fb3eff0266a84'
  );
  counter(
    'xsalsa20: libsodium raw stream carries into the high 32 bits',
    () => xsalsa20(seq(0x40, 32), seq(0xc0, 24), new Uint8Array(192), undefined, 0xffffffff),
    'c5beb52c8b882ec68b23592da0bfcbe61adb6e4308ace5ff41b24bef88ede43b811e7c974d8e23882745347d73c166a48c5f80a47fb247ff5cf5ec1af1e3796ce268f80c3dd0a9494ccb88b0c2a3caefe10e5dfee661668a2582e131f8e9e14fc41abf09952395cbf5e3c42f464c92eb8930bbe9290681e99a209ee31b83f29abb98b17d25d2ab3bd84120fb9f3a5a0c0efd3597e1185f77c36956cb74cd0a6db9cf6eaa722a63e29bbddd50cf0cc6803116592420ad7c76c0b639a231b18a3f'
  );
  counter(
    'xchacha20: libsodium raw stream carries into the high 32 bits',
    () => xchacha20(seq(0x60, 32), seq(0xe0, 24), new Uint8Array(192), undefined, 0xffffffff),
    '43e4f6775de266a18b592f8abf6769228c3a290cd4f77986dea167e9a1dfbe817f4d853d11cfc7d354978ae9e6331f2921b9f7594530452816c73eb506fdf553456e8d1e8e2c2792609d3f528a3828c3f69f84266f600a33332df080f74eb77a66508a77bcafb86aaf056eb3bfa906dc57c532de371663416132445d4cd1eceaa25c065bc99d18cdcd7762518cb4db315ddc0509787cf4ee09fbce6232f38b825484ad3cd2d4be1f2f366f3b7a337ade154783f60fb9e1b64eaff95712bbb4cf'
  );
});

describe(`poly1305 (${variant})`, () => {
  should('basic', () => {
    for (const v of stable_poly1305) {
      eql(hex.encode(poly1305(hex.decode(v.data), hex.decode(v.key).subarray(0, 32))), v.mac);
    }
  });

  should('multiple updates', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < key.length; i++) key[i] = i;
    const data = new Uint8Array(4 + 64 + 169);
    for (let i = 0; i < data.length; i++) data[i] = i;
    const d1 = data.subarray(0, 4);
    const d2 = data.subarray(4, 4 + 64);
    const d3 = data.subarray(4 + 64);
    eql([d1, d2, d3].map(hex.encode).join(''), hex.encode(data));
    const r1 = poly1305.create(key).update(data).digest();
    const r2 = poly1305.create(key).update(d1).update(d2).update(d3).digest();
    eql(hex.encode(r1), hex.encode(r2));
  });

  const t = (name, testVectors, cipher) => {
    describe(name, () => {
      for (let i = 0; i < testVectors.length; i++) {
        const v = testVectors[i];
        should(`${i}`, () => {
          const aad = v.aad ? hex.decode(v.aad) : undefined;
          const c = cipher(hex.decode(v.key), hex.decode(v.nonce), aad);
          const msg = hex.decode(v.msg);
          const exp = hex.decode(v.result);

          // console.log('V', v);
          eql(hex.encode(c.encrypt(msg)), v.result, 'encrypt');
          const plaintext = c.decrypt(exp);
          eql(hex.encode(plaintext), v.msg, 'decrypt');
          const corrupt = exp.slice();
          corrupt[corrupt.length - 1] = 0;
          throws(() => c.decrypt(corrupt));
        });
      }
    });
  };
  t('Chacha20Poly1305', stable_chacha_poly, chacha20poly1305);
  t('Xchacha20Poly1305', stable_xchacha_poly, xchacha20poly1305);
});

should(`tweetnacl secretbox compat (${variant})`, () => {
  const tweetnacl_secretbox = json('./vectors/tweetnacl_secretbox.json');
  for (let i = 0; i < tweetnacl_secretbox.length; i++) {
    const v = tweetnacl_secretbox[i];
    const [key, nonce, msg, exp] = v.map(base64.decode);
    const c = xsalsa20poly1305(key, nonce);
    eql(hex.encode(c.encrypt(msg)), hex.encode(exp), i);
    eql(hex.encode(c.decrypt(exp)), hex.encode(msg), i);
    // Secret box
    eql(secretbox(key, nonce).seal(msg), exp);
    eql(secretbox(key, nonce).open(exp), msg);
  }
});

describe(`handle byte offsets correctly (${variant})`, () => {
  const VECTORS = {
    chacha20poly1305: { stream: chacha20poly1305, nonceLen: 12, keyLen: 32 },
    xchacha20poly1305: { stream: xchacha20poly1305, nonceLen: 24, keyLen: 32 },
    xsalsa20poly1305: { stream: xsalsa20poly1305, nonceLen: 24, keyLen: 32 },
  };
  for (const name in VECTORS) {
    const v = VECTORS[name];
    should(name, () => {
      const sample = new Uint8Array(60).fill(1);
      const data = new Uint8Array(sample.buffer, 1);
      const key = new Uint8Array(v.keyLen).fill(2);
      const nonce = new Uint8Array(v.nonceLen).fill(3);
      const stream_c = v.stream(key, nonce);
      const encrypted_c = stream_c.encrypt(data);
      const decrypted_c = stream_c.decrypt(encrypted_c);
      eql(decrypted_c, data);
      // Key + nonce with offset
      const keyOffset = new Uint8Array(v.keyLen + 1).fill(2).subarray(1);
      const nonceOffset = new Uint8Array(v.nonceLen + 1).fill(3).subarray(1);
      const stream_c2 = v.stream(key, nonce);
      const streamOffset = v.stream(keyOffset, nonceOffset);
      const encryptedOffset = stream_c2.encrypt(data);
      eql(encryptedOffset, encrypted_c);
      const decryptedOffset = streamOffset.decrypt(encryptedOffset);
      eql(decryptedOffset, data);
    });
  }
});

describe(`Wycheproof (${variant})`, () => {
  const t = (name, vectors, cipher) => {
    should(name, () => {
      for (const group of vectors.testGroups) {
        for (const t of group.tests) {
          const ct = t.ct + t.tag;
          const aad = t.aad ? hex.decode(t.aad) : undefined;
          if (t.result !== 'invalid') {
            const c = cipher(hex.decode(t.key), hex.decode(t.iv), aad);
            const enc = c.encrypt(hex.decode(t.msg));
            eql(hex.encode(enc), ct);
            const dec = c.decrypt(hex.decode(ct));
            eql(hex.encode(dec), t.msg);
          } else {
            throws(() => {
              const c = cipher(hex.decode(t.key), hex.decode(t.iv), aad);
              const enc = c.encrypt(hex.decode(t.msg));
              eql(hex.encode(enc), ct);
              const dec = c.decrypt(hex.decode(ct));
              eql(hex.encode(dec), t.msg);
            });
          }
        }
      }
    });
  };
  t('wycheproof_chacha20_poly1305', wycheproof_chacha20_poly1305, chacha20poly1305);
  t('wycheproof_xchacha20_poly1305', wycheproof_xchacha20_poly1305, xchacha20poly1305);
});

}
if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
should.runWhen(import.meta.url);
