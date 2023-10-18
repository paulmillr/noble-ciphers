const { deepStrictEqual, throws } = require('assert');
const { should, describe } = require('micro-should');
const { hex, base64 } = require('@scure/base');
const { salsa20, hsalsa, xsalsa20, xsalsa20poly1305 } = require('../salsa.js');
const {
  chacha20orig,
  hchacha,
  xchacha20,
  chacha20poly1305,
  xchacha20poly1305,
} = require('../chacha.js');
const { poly1305 } = require('../_poly1305.js');
const slow = require('../_micro.js');
const tweetnacl_secretbox = require('./vectors/tweetnacl_secretbox.json');
// Stablelib tests
const stable_salsa = require('./vectors/stablelib_salsa20.json');
const stable_chacha = require('./vectors/stablelib_chacha20.json');

const stable_chacha_poly = require('./vectors/stablelib_chacha20poly1305.json');
const stable_xchacha_poly = require('./vectors/stablelib_xchacha20poly1305.json');
const stable_poly1305 = require('./vectors/stablelib_poly1305.json');
// Wycheproof
const wycheproof_chacha20_poly1305 = require('./wycheproof/chacha20_poly1305_test.json');
const wycheproof_xchacha20_poly1305 = require('./wycheproof/xchacha20_poly1305_test.json');
// getKey for hsalsa/hchacha
const utils = require('../utils.js');
const sigma16 = utils.utf8ToBytes('expand 16-byte k');
const sigma32 = utils.utf8ToBytes('expand 32-byte k');
const sigma16_32 = utils.u32(sigma16);
const sigma32_32 = utils.u32(sigma32);

const getKey = (key) => {
  if (key.length === 32) return { key, sigma: sigma32_32 };
  const k = new Uint8Array(32);
  k.set(key);
  k.set(key, 16);
  return { key, sigma: sigma16_32 };
};

describe('Salsa20', () => {
  should('basic', () => {
    for (const v of stable_salsa) {
      {
        const dst = salsa20(hex.decode(v.key), hex.decode(v.nonce), new Uint8Array(v.length));
        const res = new Uint8Array(64);
        let i = 0;
        while (i < dst.length) for (let j = 0; j < 64; j++) res[j] ^= dst[i++];
        deepStrictEqual(hex.encode(res), v.digest);
      }
      {
        const dst = slow.salsa20(hex.decode(v.key), hex.decode(v.nonce), new Uint8Array(v.length));
        const res = new Uint8Array(64);
        let i = 0;
        while (i < dst.length) for (let j = 0; j < 64; j++) res[j] ^= dst[i++];
        deepStrictEqual(hex.encode(res), v.digest);
      }
    }
  });
  should('hsalsa', () => {
    const src = hex.decode('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0');
    const good = 'c6cb53882782b5b86df1ab2ed9b810ec8a88c0a7f29211e693f0019fe0728858';
    const dst = new Uint8Array(32);
    const { key, sigma } = getKey(
      hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    );
    deepStrictEqual(hex.encode(hsalsa(sigma, key, src, dst)), good);
    deepStrictEqual(hex.encode(slow.hsalsa(sigma, key, src, dst)), good);
  });
  should('xsalsa20', () => {
    const key = hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const nonce = hex.decode('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8');
    const good =
      '300885cce813d8cdbe05f89706f9d5557041e4fadc3ebc5db89c6ca60f7' +
      '3ede4f91ff1f9521d3e9af058e037e7fd0601db9ccbd7a9f5ced151426f' +
      'de32fc544f4f95576e2614377049c258664845a93d5ff5dd479cfeb55c7' +
      '579b60d419b8a8c03da3494993577b4597dcb658be52ab7';
    const dst = new Uint8Array(good.length / 2);
    deepStrictEqual(hex.encode(xsalsa20(key, nonce, dst)), good);
    const dst2 = new Uint8Array(good.length / 2);
    deepStrictEqual(hex.encode(slow.xsalsa20(key, nonce, dst2)), good);
  });
});

describe('chacha', () => {
  should('basic', () => {
    for (const v of stable_chacha) {
      const res = chacha20orig(
        hex.decode(v.key),
        hex.decode(v.nonce),
        new Uint8Array(v.stream.length / 2)
      );
      deepStrictEqual(hex.encode(res), v.stream);
      const res2 = slow.chacha20orig(
        hex.decode(v.key),
        hex.decode(v.nonce),
        new Uint8Array(v.stream.length / 2)
      );
      deepStrictEqual(hex.encode(res2), v.stream);
    }
  });

  // test taken from draft-arciszewski-xchacha-03 section 2.2.1
  // see https://tools.ietf.org/html/draft-arciszewski-xchacha-03#section-2.2.1
  should('hchacha', () => {
    const { key, sigma } = getKey(
      hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    );
    const nonce = hex.decode('000000090000004a0000000031415927');
    const good = '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc';
    const subkey = hchacha(sigma, key, nonce.subarray(0, 16), new Uint8Array(32));
    deepStrictEqual(hex.encode(subkey), good);
    const subkeySlow = slow.hchacha(sigma, key, nonce.subarray(0, 16), new Uint8Array(32));
    deepStrictEqual(hex.encode(subkeySlow), good);
  });

  // test taken from XChaCha20 TV1 in libsodium (line 93 in libsodium/test/default/xchacha20.c)
  should('xchacha20/0', () => {
    const key = hex.decode('79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4');
    const nonce = hex.decode('b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419');
    const good = 'c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c';
    deepStrictEqual(hex.encode(xchacha20(key, nonce, new Uint8Array(good.length / 2))), good);
    deepStrictEqual(hex.encode(slow.xchacha20(key, nonce, new Uint8Array(good.length / 2))), good);
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
    deepStrictEqual(hex.encode(xchacha20(key, nonce, plaintext)), ciphertext);
    deepStrictEqual(hex.encode(slow.xchacha20(key, nonce, plaintext)), ciphertext);
  });
});

describe('poly1305', () => {
  should('basic', () => {
    for (const v of stable_poly1305) {
      deepStrictEqual(
        hex.encode(poly1305(hex.decode(v.data), hex.decode(v.key).subarray(0, 32))),
        v.mac
      );
      deepStrictEqual(
        hex.encode(slow.poly1305(hex.decode(v.data), hex.decode(v.key).subarray(0, 32))),
        v.mac,
        'slow'
      );
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
    deepStrictEqual([d1, d2, d3].map(hex.encode).join(''), hex.encode(data));
    const r1 = poly1305.create(key).update(data).digest();
    const r2 = poly1305.create(key).update(d1).update(d2).update(d3).digest();
    deepStrictEqual(hex.encode(r1), hex.encode(r2));
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
          deepStrictEqual(hex.encode(c.encrypt(msg)), v.result, 'encrypt');
          const plaintext = c.decrypt(exp);
          deepStrictEqual(hex.encode(plaintext), v.msg, 'decrypt');
          const corrupt = exp.slice();
          corrupt[corrupt.length - 1] = 0;
          throws(() => c.decrypt(corrupt));
        });
      }
    });
  };
  t('Chacha20Poly1305', stable_chacha_poly, chacha20poly1305);
  t('Xchacha20Poly1305', stable_xchacha_poly, xchacha20poly1305);
  t('Chacha20Poly1305', stable_chacha_poly, slow.chacha20poly1305);
  t('Xchacha20Poly1305', stable_xchacha_poly, slow.xchacha20poly1305);
});

should('tweetnacl secretbox compat', () => {
  for (let i = 0; i < tweetnacl_secretbox.length; i++) {
    const v = tweetnacl_secretbox[i];
    const [key, nonce, msg, exp] = v.map(base64.decode);
    const c = xsalsa20poly1305(key, nonce);
    deepStrictEqual(hex.encode(c.encrypt(msg)), hex.encode(exp), i);
    deepStrictEqual(hex.encode(c.decrypt(exp)), hex.encode(msg), i);
    const cSlow = slow.xsalsa20poly1305(key, nonce);
    deepStrictEqual(hex.encode(cSlow.encrypt(msg)), hex.encode(exp), i);
    deepStrictEqual(hex.encode(cSlow.decrypt(exp)), hex.encode(msg), i);
  }
});

describe('handle byte offsets correctly', () => {
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
      deepStrictEqual(decrypted_c, data);
      // Key + nonce with offset
      const keyOffset = new Uint8Array(v.keyLen + 1).fill(2).subarray(1);
      const nonceOffset = new Uint8Array(v.nonceLen + 1).fill(3).subarray(1);
      const streamOffset = v.stream(keyOffset, nonceOffset);
      const encryptedOffset = stream_c.encrypt(data);
      deepStrictEqual(encryptedOffset, encrypted_c);
      const decryptedOffset = streamOffset.decrypt(encryptedOffset);
      deepStrictEqual(decryptedOffset, data);
    });
  }
});

describe('Wycheproof', () => {
  const t = (name, vectors, cipher) => {
    should(name, () => {
      for (const group of vectors.testGroups) {
        for (const t of group.tests) {
          const ct = t.ct + t.tag;
          const aad = t.aad ? hex.decode(t.aad) : undefined;
          if (t.result !== 'invalid') {
            const c = cipher(hex.decode(t.key), hex.decode(t.iv), aad);
            const enc = c.encrypt(hex.decode(t.msg));
            deepStrictEqual(hex.encode(enc), ct);
            const dec = c.decrypt(hex.decode(ct));
            deepStrictEqual(hex.encode(dec), t.msg);
          } else {
            throws(() => {
              const c = cipher(hex.decode(t.key), hex.decode(t.iv), aad);
              const enc = c.encrypt(hex.decode(t.msg));
              deepStrictEqual(hex.encode(enc), ct);
              const dec = c.decrypt(hex.decode(ct));
              deepStrictEqual(hex.encode(dec), t.msg);
            });
          }
        }
      }
    });
  };
  t('wycheproof_chacha20_poly1305', wycheproof_chacha20_poly1305, chacha20poly1305);
  t('wycheproof_xchacha20_poly1305', wycheproof_xchacha20_poly1305, xchacha20poly1305);
  t('wycheproof_chacha20_poly1305', wycheproof_chacha20_poly1305, slow.chacha20poly1305);
  t('wycheproof_xchacha20_poly1305', wycheproof_xchacha20_poly1305, slow.xchacha20poly1305);
});

if (require.main === module) should.run();
