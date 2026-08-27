import bench, { section, subsection, warmup } from '@paulmillr/jsbt/benchmark.js';
import { aessiv, cbc, ctr, ecb, gcm, gcmsiv } from '../src/aes.ts';
import {
  chacha12,
  chacha20,
  chacha20poly1305,
  chacha8,
  rngChacha8,
  xchacha20,
  xchacha20poly1305
} from '../src/chacha.ts';
import { salsa20, xsalsa20, xsalsa20poly1305 } from '../src/salsa.ts';
import * as aesw from '../src/webcrypto.ts';
import { buf } from './_utils.ts';

const buffers = [
  { size: '64B', data: buf(64) },
  { size: '1MB', data: buf(1024 * 1024) },
];

async function main() {
  const key = buf(32);
  const key64 = buf(64);
  const nonce = buf(12);
  const nonce8 = buf(8);
  const nonce16 = buf(16);
  const nonce24 = buf(24);

  const warm = buf(64);
  await warmup(() => xsalsa20poly1305(key, nonce24).encrypt(warm));
  for (const { size, data: buf } of buffers) {
    section(size, { bytes: buf, mode: buf.byteLength === 64 ? 'time' : 'normal' });
    await bench('xsalsa20poly1305', () => xsalsa20poly1305(key, nonce24).encrypt(buf));
    await bench('chacha20poly1305', () => chacha20poly1305(key, nonce).encrypt(buf));
    await bench('xchacha20poly1305', () => xchacha20poly1305(key, nonce24).encrypt(buf));
    await bench('aes-gcm-256', () => gcm(key, nonce).encrypt(buf));
    await bench('aes-gcm-siv-256', () => gcmsiv(key, nonce).encrypt(buf));
    await bench('aes-siv-256', () => aessiv(key, nonce, nonce16, nonce24).encrypt(buf));

    subsection('Unauthenticated encryption');
    await bench('chacha20', () => chacha20(key, nonce, buf));
    await bench('aes-cbc-256', () => cbc(key, nonce16).encrypt(buf));
    await bench('aes-ctr-256', () => ctr(key, nonce16).encrypt(buf));

    subsection('Random number generator');
    const rng8 = rngChacha8();
    const len = buf.length;
    await bench('rngChacha8', () => rng8.randomBytes(len));
    if (size === '1MB') {
      subsection('Wrapper over built-in webcrypto');
      await bench('webcrypto ctr-256', () => aesw.ctr(key, nonce16).encrypt(buf));
      await bench('webcrypto cbc-256', () => aesw.cbc(key, nonce16).encrypt(buf));
      await bench('webcrypto gcm-256', () => aesw.gcm(key, nonce).encrypt(buf));
    }
  }
}
main();
