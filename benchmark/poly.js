import { deepStrictEqual } from 'assert';
import { compare, utils as butils } from 'micro-bmark';
import { poly1305 } from '@noble/ciphers/_poly1305';
import * as micro from '@noble/ciphers/_micro';
import { oneTimeAuth as stablePoly1305 } from '@stablelib/poly1305';
import { default as tweetnacl } from 'tweetnacl'; // secretbox = xsalsa20-poly1305.

const ONLY_NOBLE = process.argv[2] === 'noble';
const buf = (n) => new Uint8Array(n).fill(n);
const HASHES = {
  poly1305: {
    opts: { key: buf(32) },
    stable: (buf, opts) => stablePoly1305(opts.key, buf),
    // function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
    tweetnacl: (buf, opts) => {
      // Such awesome API!
      const res = new Uint8Array(16);
      tweetnacl.lowlevel.crypto_onetimeauth(res, 0, buf, 0, buf.length, opts.key);
      return res;
    },
    noble: (buf, opts) => poly1305(buf, opts.key),
    micro: (buf, opts) => micro.poly1305(buf, opts.key),
  },
};

// buffer title, sample count, data
const buffers = {
  '32B': [2000000, buf(32)],
  '64B': [1000000, buf(64)],
  '1KB': [66667, buf(1024)],
  '8KB': [8333, buf(1024 * 8)],
  '1MB': [524, buf(1024 * 1024)],
};

async function validate() {
  // Verify that things we bench actually work
  const bufs = [...Object.entries(buffers).map((i) => i[1][1])];
  // Verify different buffer sizes
  for (let i = 0; i < 2048; i++) bufs.push(buf(i));
  // Verify different subarrays positions
  const b2 = buf(2048);
  //for (let i = 0; i < 2048; i++) bufs.push(b2.subarray(i));
  for (const buf of bufs) {
    const b = buf.slice();
    // hashes
    for (let [k, libs] of Object.entries(HASHES)) {
      let value;
      for (const [lib, fn] of Object.entries(libs)) {
        if (lib === 'opts') continue;
        if (value === undefined) value = fn(buf, libs.opts);
        else {
          const cur = fn(buf, libs.opts);
          deepStrictEqual(value, cur, `hash verify (${lib})`);
        }
        deepStrictEqual(buf, b, `hash mutates buffer (${lib})`);
      }
    }
  }
  console.log('VALIDATED');
}

export const main = async () => {
  await validate();
  // Benchmark against other libraries
  for (let [k, libs] of Object.entries(HASHES)) {
    for (const [size, [samples, buf]] of Object.entries(buffers)) {
      await compare(
        `${k} (${size})`,
        samples,
        Object.fromEntries(
          Object.entries(libs)
            .filter(([lib, _]) => lib !== 'opts')
            .map(([lib, fn]) => [lib, () => fn(buf, libs.opts)])
        )
      );
    }
  }
  // Log current RAM
  butils.logMem();
};

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
