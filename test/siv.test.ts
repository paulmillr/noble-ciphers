import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { aessiv as siv, unsafe } from '../src/aes.ts';
import { bytesToHex, hexToBytes } from '../src/utils.ts';
import { json } from './utils.ts';

// Test vectors from [RFC 5297](https://datatracker.ietf.org/doc/html/rfc5297.html#appendix-A)
describe('S2V', () => {
  describe('RFC 5297 test vectors', () => {
    should('Example A.1', () => {
      const key = hexToBytes('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0');
      const ad = hexToBytes('101112131415161718191a1b1c1d1e1f2021222324252627');
      const plaintext = hexToBytes('112233445566778899aabbccddee');
      const result = unsafe.s2v(key, [ad, plaintext]);
      const expected = '85632d07c6e8f37f950acd320a2ecc93';
      deepStrictEqual(bytesToHex(result), expected);
    });

    should('Example A.2', () => {
      const key = hexToBytes('7f7e7d7c7b7a79787776757473727170');
      const ad1 = hexToBytes(
        '00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100'
      );
      const ad2 = hexToBytes('102030405060708090a0');
      const nonce = hexToBytes('09f911029d74e35bd84156c5635688c0');
      const plaintext = hexToBytes(
        '7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553'
      );
      const result = unsafe.s2v(key, [ad1, ad2, nonce, plaintext]);
      const expected = '7bdb6e3b432667eb06f4d14bff2fbd0f';
      deepStrictEqual(bytesToHex(result), expected);
    });
  });

  describe('Key validation', () => {
    should('accept 128-bit keys', () => {
      const key128 = hexToBytes('0102030405060708090a0b0c0d0e0f10');
      const input = hexToBytes('404142434445464748494a4b4c4d4e4f');
      const result = unsafe.s2v(key128, [input]);
      deepStrictEqual(result.length, 16);
    });

    should('accept 192-bit keys', () => {
      const key192 = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718');
      const input = hexToBytes('404142434445464748494a4b4c4d4e4f');
      const result = unsafe.s2v(key192, [input]);
      deepStrictEqual(result.length, 16);
    });

    should('accept 256-bit keys', () => {
      const key256 = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
      const input = hexToBytes('404142434445464748494a4b4c4d4e4f');
      const result = unsafe.s2v(key256, [input]);
      deepStrictEqual(result.length, 16);
    });

    should('reject invalid key lengths', () => {
      throws(() => unsafe.s2v(new Uint8Array(15), [new Uint8Array(16)]));
      throws(() => unsafe.s2v(new Uint8Array(17), [new Uint8Array(16)]));
      throws(() => unsafe.s2v(new Uint8Array(25), [new Uint8Array(16)]));
    });
  });
});

describe('AES-SIV', () => {
  describe('RFC 5297 test vectors', () => {
    should('Example A.1', () => {
      const key = hexToBytes('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      const ad = hexToBytes('101112131415161718191a1b1c1d1e1f2021222324252627');
      const plaintext = hexToBytes('112233445566778899aabbccddee');
      const result = siv(key, ad).encrypt(plaintext);
      const expected = '85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c';
      deepStrictEqual(bytesToHex(result), expected);
    });

    should('Example A.2', () => {
      const key = hexToBytes('7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f');
      const ad1 = hexToBytes(
        '00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100'
      );
      const ad2 = hexToBytes('102030405060708090a0');
      const nonce = hexToBytes('09f911029d74e35bd84156c5635688c0');
      const plaintext = hexToBytes(
        '7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553'
      );
      const result = siv(key, ad1, ad2, nonce).encrypt(plaintext);
      const expected =
        '7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d';
      deepStrictEqual(bytesToHex(result), expected);
    });
  });

  describe('Parameter validation', () => {
    should('reject wrong key types', () => {
      const key = 'not bytes';
      const aadArray = [new Uint8Array(16)];
      throws(() => siv(key, ...aadArray));
    });

    should('reject invalid key lengths', () => {
      throws(() => siv(new Uint8Array(15), new Uint8Array(16)));
      throws(() => siv(new Uint8Array(17), new Uint8Array(16)));
      throws(() => siv(new Uint8Array(25), new Uint8Array(16)));
    });

    should('reject too many AADs', () => {
      const key = hexToBytes('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      const aadArray = new Array(127).fill(hexToBytes('00010203'));
      throws(() => siv(key, ...aadArray));
    });

    should('reject wrong aad types', () => {
      const key = hexToBytes('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      const aadArray = ['not bytes'];
      throws(() => siv(key, ...aadArray));
    });
  });

  describe('Wycheproof', () => {
    const aes_siv_test = json('./vectors/wycheproof/aes_siv_cmac_test.json');
    for (const group of aes_siv_test.testGroups) {
      describe(`Key size: ${group.keySize}`, () => {
        for (const t of group.tests) {
          should(`TCID ${t.tcId} - ${t.comment}`, () => {
            const aessiv = siv(hexToBytes(t.key), hexToBytes(t.aad));
            if (t.result === 'valid' || t.result === 'acceptable') {
              deepStrictEqual(bytesToHex(aessiv.encrypt(hexToBytes(t.msg))), t.ct);
              deepStrictEqual(bytesToHex(aessiv.decrypt(hexToBytes(t.ct))), t.msg);
            } else {
              throws(() => aessiv.decrypt(hexToBytes(t.ct)), 'decrypt');
              throws(() => deepStrictEqual(aessiv.encrypt(hexToBytes(t.msg)), hexToBytes(t.ct)));
            }
          });
        }
      });
    }
  });
});

should.runWhen(import.meta.url);
