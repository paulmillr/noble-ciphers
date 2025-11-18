import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { hexToBytes, bytesToHex, equalBytes } from '../src/utils.ts';
import { cmac } from '../src/aes.ts';

describe('AES-CMAC', () => {
  // Test vectors from https://www.rfc-editor.org/rfc/rfc4493.html#section-4
  const RFC4493_KEY = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
  const rfcTestVectors = [
    {
      name: 'Test Case 1: Empty message',
      message: hexToBytes(''),
      expected: 'bb1d6929e95937287fa37d129b756746',
    },
    {
      name: 'Test Case 2: 16-byte message',
      message: hexToBytes('6bc1bee22e409f96e93d7e117393172a'),
      expected: '070a16b46b4d4144f79bdd9dd04a287c',
    },
    {
      name: 'Test Case 3: 40-byte message',
      message: hexToBytes(
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'
      ),
      expected: 'dfa66747de9ae63030ca32611497c827',
    },
    {
      name: 'Test Case 4: 64-byte message',
      message: hexToBytes(
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'
      ),
      expected: '51f0bebf7e3b9d92fc49741779363cfe',
    },
  ];

  // Test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
  const nistTestVectors = [
    {
      name: 'AES-128 Example 1',
      key: hexToBytes('2B7E151628AED2A6ABF7158809CF4F3C'),
      message: hexToBytes(''),
      expected: 'BB1D6929E95937287FA37D129B756746'.toLowerCase(),
    },
    {
      name: 'AES-128 Example 2',
      key: hexToBytes('2B7E151628AED2A6ABF7158809CF4F3C'),
      message: hexToBytes('6BC1BEE22E409F96E93D7E117393172A'),
      expected: '070A16B46B4D4144F79BDD9DD04A287C'.toLowerCase(),
    },
    {
      name: 'AES-128 Example 3',
      key: hexToBytes('2B7E151628AED2A6ABF7158809CF4F3C'),
      message: hexToBytes('6BC1BEE22E409F96E93D7E117393172AAE2D8A57'),
      expected: '7D85449EA6EA19C823A7BF78837DFADE'.toLowerCase(),
    },
    {
      name: 'AES-128 Example 4',
      key: hexToBytes('2B7E151628AED2A6ABF7158809CF4F3C'),
      message: hexToBytes(
        '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'
      ),
      expected: '51F0BEBF7E3B9D92FC49741779363CFE'.toLowerCase(),
    },
    // CMAC-AES192
    {
      name: 'AES-192 Example 1',
      key: hexToBytes('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'),
      message: hexToBytes(''),
      expected: 'D17DDF46ADAACDE531CAC483DE7A9367'.toLowerCase(),
    },
    {
      name: 'AES-192 Example 2',
      key: hexToBytes('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'),
      message: hexToBytes('6BC1BEE22E409F96E93D7E117393172A'),
      expected: '9E99A7BF31E710900662F65E617C5184'.toLowerCase(),
    },
    {
      name: 'AES-192 Example 3',
      key: hexToBytes('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'),
      message: hexToBytes('6BC1BEE22E409F96E93D7E117393172AAE2D8A57'),
      expected: '3D75C194ED96070444A9FA7EC740ECF8'.toLowerCase(),
    },
    {
      name: 'AES-192 Example 4',
      key: hexToBytes('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'),
      message: hexToBytes(
        '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'
      ),
      expected: 'A1D5DF0EED790F794D77589659F39A11'.toLowerCase(),
    },
    // CMAC-AES256
    {
      name: 'AES-256 Example 1',
      key: hexToBytes('603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'),
      message: hexToBytes(''),
      expected: '028962F61B7BF89EFC6B551F4667D983'.toLowerCase(),
    },
    {
      name: 'AES-256 Example 2',
      key: hexToBytes('603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'),
      message: hexToBytes('6BC1BEE22E409F96E93D7E117393172A'),
      expected: '28A7023F452E8F82BD4BF28D8C37C35C'.toLowerCase(),
    },
    {
      name: 'AES-256 Example 3',
      key: hexToBytes('603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'),
      message: hexToBytes('6BC1BEE22E409F96E93D7E117393172AAE2D8A57'),
      expected: '156727DC0878944A023C1FE03BAD6D93'.toLowerCase(),
    },
    {
      name: 'AES-256 Example 4',
      key: hexToBytes('603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'),
      message: hexToBytes(
        '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710'
      ),
      expected: 'E1992190549F6ED5696A2C056C315410'.toLowerCase(),
    },
  ];

  describe('RFC 4493 test vectors', () => {
    for (const vector of rfcTestVectors) {
      should(vector.name, () => {
        const result = cmac.tag(RFC4493_KEY, vector.message);
        deepStrictEqual(bytesToHex(result), vector.expected);
      });
    }
  });

  describe('Subkey generation', () => {
    should('generate correct subkeys', () => {
      // Test vectors for subkey generation (derived from RFC 4493)
      const subkeys = cmac.generateSubkeys(RFC4493_KEY);

      // Expected values computed according to RFC 4493 algorithm
      const expectedK1 = 'fbeed618357133667c85e08f7236a8de';
      const expectedK2 = 'f7ddac306ae266ccf90bc11ee46d513b';

      deepStrictEqual(bytesToHex(subkeys.k1), expectedK1);
      deepStrictEqual(bytesToHex(subkeys.k2), expectedK2);
    });
  });

  describe('NIST test vectors', () => {
    for (const vector of nistTestVectors) {
      should(vector.name, () => {
        const result = cmac.tag(vector.key, vector.message);
        deepStrictEqual(bytesToHex(result), vector.expected);
      });
    }
  });

  describe('Streaming interface', () => {
    should('work with update/digest pattern', () => {
      const mac = cmac.create(RFC4493_KEY);
      mac.update(hexToBytes('6bc1bee22e409f96e93d7e117393172a'));
      const result = mac.digest();
      deepStrictEqual(bytesToHex(result), '070a16b46b4d4144f79bdd9dd04a287c');
      mac.destroy();
    });

    should('work with multiple updates', () => {
      const mac = cmac.create(RFC4493_KEY);
      const message = hexToBytes(
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'
      );

      // Split message and update in parts
      mac.update(message.subarray(0, 16));
      mac.update(message.subarray(16, 32));
      mac.update(message.subarray(32));

      const result = mac.digest();
      deepStrictEqual(bytesToHex(result), 'dfa66747de9ae63030ca32611497c827');
      mac.destroy();
    });

    should('work with single byte updates', () => {
      const mac = cmac.create(RFC4493_KEY);
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');

      for (const byte of message) {
        mac.update(new Uint8Array([byte]));
      }

      const result = mac.digest();
      deepStrictEqual(bytesToHex(result), '070a16b46b4d4144f79bdd9dd04a287c');
      mac.destroy();
    });
  });

  describe('Verification', () => {
    should('verify correct tags', () => {
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');
      const tag = hexToBytes('070a16b46b4d4144f79bdd9dd04a287c');
      deepStrictEqual(cmac.verify(RFC4493_KEY, message, tag), true);
    });

    should('reject incorrect tags', () => {
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');
      const wrongTag = hexToBytes('070a16b46b4d4144f79bdd9dd04a287d'); // Last byte changed
      deepStrictEqual(cmac.verify(RFC4493_KEY, message, wrongTag), false);
    });
  });

  describe('Different key sizes', () => {
    should('work with 192-bit keys', () => {
      const key192 = hexToBytes('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');
      const result = cmac.tag(key192, message);
      deepStrictEqual(result.length, 16); // Should always produce 16-byte tag
    });

    should('work with 256-bit keys', () => {
      const key256 = hexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');
      const result = cmac.tag(key256, message);
      deepStrictEqual(result.length, 16); // Should always produce 16-byte tag
    });
  });

  describe('Error handling', () => {
    should('reject invalid key lengths', () => {
      throws(() => cmac.tag(new Uint8Array(15), new Uint8Array(16)));
      throws(() => cmac.tag(new Uint8Array(17), new Uint8Array(16)));
      throws(() => cmac.tag(new Uint8Array(25), new Uint8Array(16)));
    });

    should('reject invalid tag lengths in verify', () => {
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');
      throws(() => cmac.verify(RFC4493_KEY, message, new Uint8Array(15)));
      throws(() => cmac.verify(RFC4493_KEY, message, new Uint8Array(17)));
    });

    should('prevent use after destroy', () => {
      const mac = cmac.create(RFC4493_KEY);
      mac.destroy();
      throws(() => mac.update(new Uint8Array(16)));
      throws(() => mac.digest());
    });

    should('handle multiple destroy calls', () => {
      const mac = cmac.create(RFC4493_KEY);
      mac.destroy();
      mac.destroy(); // Should not throw
    });
  });

  describe('Security properties', () => {
    should('produce different tags for different keys', () => {
      const key1 = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
      const key2 = hexToBytes('2b7e151628aed2a6abf7158809cf4f3d'); // Last byte different
      const message = hexToBytes('6bc1bee22e409f96e93d7e117393172a');

      const tag1 = cmac.tag(key1, message);
      const tag2 = cmac.tag(key2, message);

      deepStrictEqual(tag1.length, tag2.length);
      deepStrictEqual(equalBytes(tag1, tag2), false);
    });

    should('produce different tags for different messages', () => {
      const message1 = hexToBytes('6bc1bee22e409f96e93d7e117393172a');
      const message2 = hexToBytes('6bc1bee22e409f96e93d7e117393172b'); // Last byte different

      const tag1 = cmac.tag(RFC4493_KEY, message1);
      const tag2 = cmac.tag(RFC4493_KEY, message2);

      deepStrictEqual(tag1.length, tag2.length);
      deepStrictEqual(equalBytes(tag1, tag2), false);
    });
  });
});
