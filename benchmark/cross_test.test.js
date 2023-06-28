import { deepStrictEqual, throws } from 'assert';
import { should, describe } from 'micro-should';
import { CIPHERS } from './index.js';

describe('Big', () => {
  should('secretbox', () => {
    const big4g = new Uint8Array(2 ** 32 - 32).fill(7);
    const libs = CIPHERS.xsalsa20_poly1305;
    const nacl4 = libs.tweetnacl.encrypt(big4g, libs.opts);
    const noble4 = libs.noble.encrypt(big4g, libs.opts);
    deepStrictEqual(noble4, nacl4, 'noble encrypt');
    deepStrictEqual(libs.noble.decrypt(noble4, libs.opts), big4g, 'noble decrypt');
  });
});

// ESM is broken.
import url from 'url';

if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
