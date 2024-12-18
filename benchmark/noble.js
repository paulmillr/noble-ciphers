import { mark } from 'micro-bmark';
import { buf } from './_utils.js';
import { concatBytes } from '@noble/ciphers/utils';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { xchacha20poly1305, chacha20poly1305 } from '@noble/ciphers/chacha';
import { salsa20, xsalsa20 } from '@noble/ciphers/salsa';
import { chacha20, xchacha20, chacha8, chacha12 } from '@noble/ciphers/chacha';
import { ecb, ctr, cbc, gcm, siv } from '@noble/ciphers/aes';

const buffers = [
  // { size: '16B', samples: 1_500_000, data: buf(16) }, // common block size
  { size: '32B', samples: 1_500_000, data: buf(32) },
  { size: '64B', samples: 1_000_000, data: buf(64) },
  // { size: '1KB', samples: 50_000, data: buf(1024) },
  // { size: '8KB', samples: 10_000, data: buf(1024 * 8) },
  { size: '1MB', samples: 100, data: buf(1024 * 1024) },
];

async function main() {
  const key = buf(32);
  const nonce = buf(12);
  const nonce8 = buf(8);
  const nonce16 = buf(16);
  const nonce24 = buf(24);
  for (let i = 0; i < 100000; i++) xsalsa20poly1305(key, nonce24).encrypt(buf(64)); // warm-up
  for (const { size, samples: i, data: buf } of buffers) {
    console.log(size);
    await mark('xsalsa20poly1305', i, () => xsalsa20poly1305(key, nonce24).encrypt(buf));
    await mark('chacha20poly1305', i, () => chacha20poly1305(key, nonce).encrypt(buf));
    await mark('xchacha20poly1305', i, () => xchacha20poly1305(key, nonce24).encrypt(buf));
    await mark('aes-256-gcm', i, () => gcm(key, nonce).encrypt(buf));
    await mark('aes-256-gcm-siv', i, () => siv(key, nonce).encrypt(buf));

    console.log('# Unauthenticated encryption');
    await mark('salsa20', i, () => salsa20(key, nonce8, buf));
    await mark('xsalsa20', i, () => xsalsa20(key, nonce24, buf));
    await mark('chacha20', i, () => chacha20(key, nonce, buf));
    await mark('xchacha20', i, () => xchacha20(key, nonce24, buf));
    await mark('chacha8', i, () => chacha8(key, nonce, buf));
    await mark('chacha12', i, () => chacha12(key, nonce, buf));
    await mark('aes-256-ecb', i, () => ecb(key).encrypt(buf));
    await mark('aes-256-cbc', i, () => cbc(key, nonce16).encrypt(buf));
    await mark('aes-256-ctr', i, () => ctr(key, nonce16).encrypt(buf));
    console.log();
  }
}
main();
