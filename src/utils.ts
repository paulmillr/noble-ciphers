/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */
import { abytes, isBytes } from './_assert.js';
// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

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

// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
export function bytesToHex(bytes: Uint8Array): string {
  abytes(bytes);
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}

// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const;
function asciiToBase16(ch: number): number | undefined {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
  return;
}

/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) throw new Error('hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array;
}

export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  return BigInt(hex === '' ? '0' : '0x' + hex); // Big Endian
}

// BE: Big Endian, LE: Little Endian
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  return hexToBytes(n.toString(16).padStart(len * 2, '0'));
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
  if (typeof str !== 'string') throw new Error('string expected');
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}

/**
 * @example bytesToUtf8(new Uint8Array([97, 98, 99])) // 'abc'
 */
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
  else if (isBytes(data)) data = copyBytes(data);
  else throw new Error('Uint8Array expected, got ' + typeof data);
  return data;
}

/**
 * Checks if two U8A use same underlying buffer and overlaps (will corrupt and break if input and output same)
 */
export function overlapBytes(a: Uint8Array, b: Uint8Array): boolean {
  return (
    a.buffer === b.buffer && // probably will fail with some obscure proxies, but this is best we can do
    a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
    b.byteOffset < a.byteOffset + a.byteLength // b starts before a end
  );
}

/**
 * If input and output overlap and input starts before output, we will overwrite end of input before
 * we start processing it, so this is not supported for most ciphers (except chacha/salse, which designed with this)
 */
export function complexOverlapBytes(input: Uint8Array, output: Uint8Array) {
  // This is very cursed. It works somehow, but I'm completely unsure,
  // reasoning about overlapping aligned windows is very hard.
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error('complex overlap of input and output is not supported');
}

/**
 * Copies several Uint8Arrays into one.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

type EmptyObj = {};
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts: T2
): T1 & T2 {
  if (opts == null || typeof opts !== 'object') throw new Error('options must be defined');
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

// Compares 2 u8a-s in kinda constant time
export function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
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
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
};

export type AsyncCipher = {
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
};

export type CipherWithOutput = Cipher & {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};

// Params is outside return type, so it is accessible before calling constructor
// If function support multiple nonceLength's, we return best one
export type CipherParams = {
  blockSize: number;
  nonceLength?: number;
  tagLength?: number;
  varSizeNonce?: boolean;
};
export type CipherCons<T extends any[]> = (key: Uint8Array, ...args: T) => Cipher;
/**
 * @__NO_SIDE_EFFECTS__
 */
export const wrapCipher = <C extends CipherCons<any>, P extends CipherParams>(
  params: P,
  constructor: C
): C & P => {
  function wrappedCipher(key: Uint8Array, ...args: any[]): CipherWithOutput {
    // Validate key
    abytes(key);

    // Validate nonce if nonceLength is present
    if (params.nonceLength !== undefined) {
      const nonce = args[0];
      if (!nonce) throw new Error('nonce / iv required');
      if (params.varSizeNonce) abytes(nonce);
      else abytes(nonce, params.nonceLength);
    }

    // Validate AAD if tagLength present
    const tagl = params.tagLength;
    if (tagl && args[1] !== undefined) {
      abytes(args[1]);
    }

    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength: number, output?: Uint8Array) => {
      if (output !== undefined) {
        if (fnLength !== 2) throw new Error('cipher output not supported');
        abytes(output);
      }
    };
    // Create wrapped cipher with validation and single-use encryption
    let called = false;
    const wrCipher = {
      encrypt(data: Uint8Array, output?: Uint8Array) {
        if (called) throw new Error('cannot encrypt() twice with same key + nonce');
        called = true;
        abytes(data);
        checkOutput(cipher.encrypt.length, output);
        return (cipher as CipherWithOutput).encrypt(data, output);
      },
      decrypt(data: Uint8Array, output?: Uint8Array) {
        abytes(data);
        if (tagl && data.length < tagl)
          throw new Error('invalid ciphertext length: smaller than tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return (cipher as CipherWithOutput).decrypt(data, output);
      },
    };

    return wrCipher;
  }

  Object.assign(wrappedCipher, params);
  return wrappedCipher as C & P;
};

export type XorStream = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output?: Uint8Array,
  counter?: number
) => Uint8Array;

export function getOutput(expectedLength: number, out?: Uint8Array, onlyAligned = true) {
  if (out === undefined) return new Uint8Array(expectedLength);
  if (out.length !== expectedLength)
    throw new Error('invalid output length, expected ' + expectedLength + ', got: ' + out.length);
  if (onlyAligned && !isAligned32(out)) throw new Error('invalid output, must be aligned');
  return out;
}

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

export function u64Lengths(ciphertext: Uint8Array, AAD?: Uint8Array) {
  const num = new Uint8Array(16);
  const view = createView(num);
  setBigUint64(view, 0, BigInt(AAD ? AAD.length : 0), true);
  setBigUint64(view, 8, BigInt(ciphertext.length), true);
  return num;
}

// Is byte array aligned to 4 byte offset (u32)?
export function isAligned32(bytes: Uint8Array) {
  return bytes.byteOffset % 4 === 0;
}

// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
export function copyBytes(bytes: Uint8Array) {
  return Uint8Array.from(bytes);
}

export function clean(...arrays: TypedArray[]) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
