import { deepStrictEqual } from 'node:assert';

export const onlyNoble = process.argv[2] === 'noble';
export function buf(n) {
  return new Uint8Array(n).fill(n % 251);
}

// type Buffers = ({size: string, samples: number, data: Uint8Array})[];
export async function crossValidate(title, buffers, ciphers) {
  // Verify that things we bench actually work
  const bufs = Object.values(buffers);
  const bufMap = new Map(Object.entries(buffers).map(([k, v]) => [v, k]));
  // const bufs = Object.entries(buffers).map((entry) => entry[1][1])
  // const bufs = [...Object.entries(buffers).map((i) => i[1][1])];
  // Verify different buffer sizes
  for (let i = 0; i < 2048; i++) bufs.push(buf(i));
  // Verify different subarrays positions
  // const b2 = buf(2048);
  // for (let i = 0; i < 2048; i++) bufs.push(b2.subarray(i));

  // Return encrypted values for buffers for decrypt test
  const res = {};
  for (const buf of bufs) {
    const b = buf.slice();
    // ciphers
    let encrypted;
    const opts = ciphers.options;
    // Skip some buffers for block ciphers without padding
    if (opts.blockSize && b.length % opts.blockSize) continue;
    for (let [lib, fn] of Object.entries(ciphers)) {
      if (lib === 'options') continue;
      if (encrypted === undefined) {
        encrypted = await fn.encrypt(buf, opts);
      } else {
        const cur = await fn.encrypt(buf, opts);
        deepStrictEqual(encrypted, cur, `${title}: encrypt verify (${lib})`);
      }
      deepStrictEqual(buf, b, `${title}: encrypt mutates buffer (${lib})`);
      const res = await fn.decrypt(encrypted, opts);
      deepStrictEqual(res, buf, `${title}: decrypt verify (${lib})`);
    }
    const bufName = bufMap.get(buf);
    if (bufName) res[bufName] = encrypted;
  }
  return res;
}
