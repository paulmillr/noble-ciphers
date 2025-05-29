import mark from 'micro-bmark';
import { cbc, ctr, ecb, gcm, gcmsiv } from '../../src/aes.ts';
import {
  chacha12,
  chacha20,
  chacha20poly1305,
  chacha8,
  xchacha20,
  xchacha20poly1305,
} from '../../src/chacha.ts';
import { salsa20, xsalsa20, xsalsa20poly1305 } from '../../src/salsa.ts';
import * as aesw from '../../src/webcrypto.ts';
import { buf } from './_utils.ts';

const buffers = [
  // { size: '16B', data: buf(16) }, // common block size
  // { size: '32B', data: buf(32) },
  { size: '64B', data: buf(64) },
  // { size: '1KB', data: buf(1024) },
  // { size: '8KB', data: buf(1024 * 8) },
  { size: '1MB', data: buf(1024 * 1024) },
];

async function main() {
  const key = buf(32);
  const nonce = buf(12);
  const nonce8 = buf(8);
  const nonce16 = buf(16);
  const nonce24 = buf(24);
  // Do we need this at all?
  for (let i = 0; i < 100_000; i++) xsalsa20poly1305(key, nonce24).encrypt(buf(64)); // warm-up
  for (const { size, data: buf } of buffers) {
    console.log(size);
    await mark('xsalsa20poly1305', () => xsalsa20poly1305(key, nonce24).encrypt(buf));
    await mark('chacha20poly1305', () => chacha20poly1305(key, nonce).encrypt(buf));
    await mark('xchacha20poly1305', () => xchacha20poly1305(key, nonce24).encrypt(buf));
    await mark('aes-256-gcm', () => gcm(key, nonce).encrypt(buf));
    await mark('aes-256-gcm-siv', () => gcmsiv(key, nonce).encrypt(buf));

    console.log('# Unauthenticated encryption');
    await mark('salsa20', () => salsa20(key, nonce8, buf));
    await mark('xsalsa20', () => xsalsa20(key, nonce24, buf));
    await mark('chacha20', () => chacha20(key, nonce, buf));
    await mark('xchacha20', () => xchacha20(key, nonce24, buf));
    await mark('chacha8', () => chacha8(key, nonce, buf));
    await mark('chacha12', () => chacha12(key, nonce, buf));
    await mark('aes-ecb-256', () => ecb(key).encrypt(buf));
    await mark('aes-cbc-256', () => cbc(key, nonce16).encrypt(buf));
    await mark('aes-ctr-256', () => ctr(key, nonce16).encrypt(buf));

    if (size === '1MB') {
      console.log('# Wrapper over built-in webcrypto');
      await mark('webcrypto ctr-256', 5000, () => aesw.ctr(key, nonce16).encrypt(buf));
      await mark('webcrypto cbc-256', 1000, () => aesw.cbc(key, nonce16).encrypt(buf));
      await mark('webcrypto gcm-256', 5000, () => aesw.gcm(key, nonce).encrypt(buf));
    }
    console.log();
  }
}
main();
