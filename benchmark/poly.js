import { compare, utils as butils } from 'micro-bmark';
import { poly1305 } from '@noble/ciphers/_poly1305';
import * as micro from '@noble/ciphers/_micro';
import { oneTimeAuth as stablePoly1305 } from '@stablelib/poly1305';
import { default as tweetnacl } from 'tweetnacl'; // secretbox = xsalsa20-poly1305.
import { validateHashes, buf } from './_utils.js';

const buffers = [
  { size: '32B', samples: 2_000_000, data: buf(32) },
  { size: '64B', samples: 1_000_000, data: buf(64) },
  { size: '1KB', samples: 66667, data: buf(1024) },
  { size: '8KB', samples: 8333, data: buf(1024 * 8) },
  { size: '1MB', samples: 524, data: buf(1024 * 1024) },
];

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

export async function main() {
  await validateHashes(buffers, HASHES);
  // Benchmark against other libraries
  for (let [k, libs] of Object.entries(HASHES)) {
    for (const { size, samples, data: buf } of buffers) {
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
}

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
