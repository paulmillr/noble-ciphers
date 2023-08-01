/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */

// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

const u8a = (a: any): a is Uint8Array => a instanceof Uint8Array;
// Cast array to different type
export const u8 = (arr: TypedArray) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
export const u16 = (arr: TypedArray) =>
  new Uint16Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 2));
export const u32 = (arr: TypedArray) =>
  new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));

// Cast array to view
export const createView = (arr: TypedArray) =>
  new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

// big-endian hardware is rare. Just in case someone still decides to run ciphers:
// early-throw an error because we don't support BE yet.
export const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE) throw new Error('Non little-endian hardware is not supported');

const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
export function bytesToHex(bytes: Uint8Array): string {
  if (!u8a(bytes)) throw new Error('Uint8Array expected');
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}

/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  const len = hex.length;
  if (len % 2) throw new Error('padded hex string expected, got unpadded hex of length ' + len);
  const array = new Uint8Array(len / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// There is no setImmediate in browser and setTimeout is slow.
// call of async fn will return Promise, which will be fullfiled only on
// next scheduler queue processing step and this is exactly what we need.
export const nextTick = async () => {};

// Returns control to thread each 'tick' ms to avoid blocking
export async function asyncLoop(iters: number, tick: number, cb: (i: number) => void) {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick) continue;
    await nextTick();
    ts += diff;
  }
}

// Global symbols in both browsers and Node.js since v11
// See https://github.com/microsoft/TypeScript/issues/31535
declare const TextEncoder: any;
declare const TextDecoder: any;

/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export type Input = Uint8Array | string;
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
export function toBytes(data: Input): Uint8Array {
  if (typeof data === 'string') data = utf8ToBytes(data);
  if (!u8a(data)) throw new Error(`expected Uint8Array, got ${typeof data}`);
  return data;
}

/**
 * Copies several Uint8Arrays into one.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const r = new Uint8Array(arrays.reduce((sum, a) => sum + a.length, 0));
  let pad = 0; // walk through each item, ensure they have proper type
  arrays.forEach((a) => {
    if (!u8a(a)) throw new Error('Uint8Array expected');
    r.set(a, pad);
    pad += a.length;
  });
  return r;
}

// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj: any) =>
  Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;

type EmptyObj = {};
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts?: T2
): T1 & T2 {
  if (opts !== undefined && (typeof opts !== 'object' || !isPlainObject(opts)))
    throw new Error('options must be object or undefined');
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

export function ensureBytes(b: any, len?: number) {
  if (!(b instanceof Uint8Array)) throw new Error('Uint8Array expected');
  if (typeof len === 'number')
    if (b.length !== len) throw new Error(`Uint8Array length ${len} expected`);
}

// Constant-time equality
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Should not happen
  if (a.length !== b.length) throw new Error('equalBytes: Different size of Uint8Arrays');
  let isSame = true;
  for (let i = 0; i < a.length; i++) isSame &&= a[i] === b[i]; // Lets hope JIT won't optimize away.
  return isSame;
}

// For runtime check if class implements interface
export abstract class Hash<T extends Hash<T>> {
  abstract blockLen: number; // Bytes per block
  abstract outputLen: number; // Bytes in output
  abstract update(buf: Input): this;
  // Writes digest into buf
  abstract digestInto(buf: Uint8Array): void;
  abstract digest(): Uint8Array;
  /**
   * Resets internal state. Makes Hash instance unusable.
   * Reset is impossible for keyed hashes if key is consumed into state. If digest is not consumed
   * by user, they will need to manually call `destroy()` when zeroing is necessary.
   */
  abstract destroy(): void;
}

// This will allow to re-use with composable things like packed & base encoders
// Also, we probably can make tags composable
export type Cipher = {
  tagLength?: number;
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
};

export type AsyncCipher = {
  tagLength?: number;
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
};

export type CipherWithOutput = Cipher & {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};

// Polyfill for Safari 14
export function setBigUint64(
  view: DataView,
  byteOffset: number,
  value: bigint,
  isLE: boolean
): void {
  if (typeof view.setBigUint64 === 'function') return view.setBigUint64(byteOffset, value, isLE);
  const _32n = BigInt(32);
  const _u32_max = BigInt(0xffffffff);
  const wh = Number((value >> _32n) & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
