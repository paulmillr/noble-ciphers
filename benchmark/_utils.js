import { deepStrictEqual } from 'assert';
import { compare } from 'micro-bmark';

// type Buffers = ({size: string, samples: number, data: Uint8Array})[];
export async function crossValidate(buffers, ciphers) {
  // Verify that things we bench actually work
  const bufs = buffers.map((buf) => buf.data);
  // const bufs = Object.entries(buffers).map((entry) => entry[1][1])
  // const bufs = [...Object.entries(buffers).map((i) => i[1][1])];
  // Verify different buffer sizes
  for (let i = 0; i < 2048; i++) bufs.push(buf(i));
  // Verify different subarrays positions
  // const b2 = buf(2048);
  // for (let i = 0; i < 2048; i++) bufs.push(b2.subarray(i));
  for (const buf of bufs) {
    const b = buf.slice();
    // ciphers
    for (let [k, libs] of Object.entries(ciphers)) {
      // Skip some buffers for block ciphers without padding
      if (libs.opts.blockSize && b.length % libs.opts.blockSize) continue;
      let encrypted;
      for (const [lib, fn] of Object.entries(libs)) {
        if (lib === 'opts') continue;
        if (encrypted === undefined) {
          encrypted = await fn.encrypt(buf, libs.opts);
        } else {
          const cur = await fn.encrypt(buf, libs.opts);
          deepStrictEqual(encrypted, cur, `encrypt verify (${lib})`);
        }
        deepStrictEqual(buf, b, `encrypt mutates buffer (${lib})`);
        const res = await fn.decrypt(encrypted, libs.opts);
        deepStrictEqual(res, buf, `decrypt verify (${lib})`);
      }
    }
  }
  console.log('Libraries cross-validated against each other correctly');
}

export async function validateHashes(buffers, HASHES) {
  // Verify that things we bench actually work
  // const bufs = [...Object.entries(buffers).map((i) => i[1][1])];
  const bufs = buffers.map((buf) => buf.data);
  // Verify different buffer sizes
  for (let i = 0; i < 2048; i++) bufs.push(buf(i));
  // Verify different subarrays positions
  // const b2 = buf(2048);
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
  console.log('Libraries cross-validated against each other correctly');
}

export const onlyNoble = process.argv[2] === 'noble';
export function buf(n) {
  return new Uint8Array(n).fill(n);
}
export async function benchmarkOnlyNoble(buffers, ciphers) {
  const nobleImpls = [];
  // chacha20_poly1305: {
  //   opts: { key: buf(32), nonce: buf(12) },
  //   noble: {
  for (const [algoName, implementations] of Object.entries(ciphers)) {
    const { opts } = implementations;
    let implementation = implementations.noble;
    if (implementation) {
      nobleImpls.push({ algoName, implementation, opts });
    }
  }
  for (const { size, samples, data: buf } of buffers) {
    await compare(
      `encrypt (${size})`,
      samples,
      Object.fromEntries(
        nobleImpls.map((impl) => [impl.algoName, () => impl.implementation.encrypt(buf, impl.opts)])
      )
    );
  }
}

export async function benchmarkAllLibraries(buffers, ciphers) {
  for (let [algoName, libraries] of Object.entries(ciphers)) {
    console.log(`==== ${algoName} ====`);
    const { opts } = libraries;
    for (const { size, samples, data: buf } of buffers) {
      const libs = Object.entries(libraries).filter(([lib, _]) => lib !== 'opts');
      const firstLibrary = libs[0][1];
      const encrypted = await firstLibrary.encrypt(buf, opts);
      const encrypts = libs.map(([lib, fn]) => [lib, () => fn.encrypt(buf, opts)]);
      const decrypts = libs.map(([lib, fn]) => [lib, () => fn.decrypt(encrypted, opts)]);
      await compare(`${algoName} (encrypt, ${size})`, samples, Object.fromEntries(encrypts));
      await compare(`${algoName} (decrypt, ${size})`, samples, Object.fromEntries(decrypts));
    }
  }
}
