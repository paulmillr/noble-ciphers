/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */

/**
 * Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
 * @param a - Value to inspect.
 * @returns `true` when the value is a Uint8Array view.
 * @example
 * Guards a value before treating it as raw key material.
 *
 * ```ts
 * isBytes(new Uint8Array());
 * ```
 */
export function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}

/**
 * Asserts something is boolean.
 * @param b - Value to validate.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Validates a boolean option before branching on it.
 *
 * ```ts
 * abool(true);
 * ```
 */
export function abool(b: boolean): void {
  if (typeof b !== 'boolean') throw new TypeError(`boolean expected, not ${b}`);
}

/**
 * Asserts something is a positive integer.
 * @param n - Value to validate.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validates a non-negative length or counter.
 *
 * ```ts
 * anumber(1);
 * ```
 */
export function anumber(n: number): void {
  if (typeof n !== 'number') throw new TypeError('number expected, got ' + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError('positive integer expected, got ' + n);
}

/**
 * Asserts something is Uint8Array.
 * @param value - Value to validate.
 * @param length - Expected byte length.
 * @param title - Optional label used in error messages.
 * @returns The validated byte array.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument lengths. {@link RangeError}
 * @example
 * Validates a fixed-length nonce or key buffer.
 *
 * ```ts
 * abytes(new Uint8Array([1, 2]), 2);
 * ```
 */
export function abytes(value: Uint8Array, length?: number, title: string = ''): Uint8Array {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : '';
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + 'expected Uint8Array' + ofLen + ', got ' + got;
    if (!bytes) throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}

/**
 * Asserts a hash instance has not been destroyed or finished.
 * @param instance - Hash-like instance to validate.
 * @param checkFinished - Whether to reject finished instances.
 * @throws If the hash instance has already been destroyed or finalized. {@link Error}
 * @example
 * Guards against calling `update()` or `digest()` on a finished hash.
 *
 * ```ts
 * aexists({ destroyed: false, finished: false });
 * ```
 */
export function aexists(instance: any, checkFinished = true): void {
  if (instance.destroyed) throw new Error('Hash instance has been destroyed');
  if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}

/**
 * Asserts output is a properly-sized byte array.
 * @param out - Output buffer to validate.
 * @param instance - Hash-like instance providing `outputLen`.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong output buffer lengths. {@link RangeError}
 * @example
 * Verifies that a caller-provided output buffer is large enough.
 *
 * ```ts
 * aoutput(new Uint8Array(16), { outputLen: 16 });
 * ```
 */
export function aoutput(out: any, instance: any): void {
  abytes(out, undefined, 'output');
  const min = instance.outputLen;
  if (out.length < min) {
    throw new RangeError('digestInto() expects output buffer of length at least ' + min);
  }
}

/** One-shot hash helper with `.create()`. */
export type IHash = {
  (data: string | Uint8Array): Uint8Array;
  /** Input block size in bytes. */
  blockLen: number;
  /** Digest size in bytes. */
  outputLen: number;
  /** Creates a fresh incremental hash instance of the same algorithm. */
  create: any;
};

/** Generic type encompassing 8/16/32-bit typed arrays, but not 64-bit. */
// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

/**
 * Casts a typed-array view to Uint8Array.
 * @param arr - Typed-array view to reinterpret.
 * @returns Uint8Array view over the same bytes.
 * @example
 * Views 32-bit words as raw bytes without copying.
 *
 * ```ts
 * u8(new Uint32Array([1]));
 * ```
 */
export function u8(arr: TypedArray): Uint8Array {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}

/**
 * Casts a typed-array view to Uint32Array.
 * @param arr - Typed-array view to reinterpret.
 * @returns Uint32Array view over the same bytes.
 * @example
 * Views a byte buffer as 32-bit words for block processing.
 *
 * ```ts
 * u32(new Uint8Array(4));
 * ```
 */
export function u32(arr: TypedArray): Uint32Array {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}

/**
 * Zeroizes typed arrays in place.
 * Warning: JS provides no guarantees.
 * @param arrays - Arrays to wipe.
 * @example
 * Wipes a temporary key buffer after use.
 *
 * ```ts
 * const bytes = new Uint8Array([1]);
 * clean(bytes);
 * ```
 */
export function clean(...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}

/**
 * Creates a DataView for byte-level manipulation.
 * @param arr - Typed-array view to wrap.
 * @returns DataView over the same bytes.
 * @example
 * Creates an endian-aware view for length encoding.
 *
 * ```ts
 * createView(new Uint8Array(4));
 * ```
 */
export function createView(arr: TypedArray): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

/**
 * Whether the current platform is little-endian.
 * Most are; some IBM systems are not.
 */
export const isLE: boolean = /* @__PURE__ */ (() =>
  new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();

// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin: boolean = /* @__PURE__ */ (() =>
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();

// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);

/**
 * Convert byte array to hex string. Uses built-in function, when available.
 * @param bytes - Bytes to encode.
 * @returns Lowercase hexadecimal string.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Formats ciphertext bytes for logs or test vectors.
 *
 * ```ts
 * bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])); // 'cafe0123'
 * ```
 */
export function bytesToHex(bytes: Uint8Array): string {
  abytes(bytes);
  // @ts-ignore
  if (hasHexBuiltin) return bytes.toHex();
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
 * Convert hex string to byte array. Uses built-in function, when available.
 * @param hex - Hexadecimal string to decode.
 * @returns Decoded bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On malformed hexadecimal input. {@link RangeError}
 * @example
 * Parses a hex test vector into bytes.
 *
 * ```ts
 * hexToBytes('cafe0123'); // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 * ```
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
  if (hasHexBuiltin) {
    try {
      return (Uint8Array as any).fromHex(hex);
    } catch (error) {
      if (error instanceof SyntaxError) throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) throw new RangeError('hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError(
        'hex string expected, got non-hex character "' + char + '" at index ' + hi
      );
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array;
}

// Used in micro
/**
 * Converts a big-endian hex string into bigint.
 * @param hex - Hexadecimal string without `0x`.
 * @returns Parsed bigint value.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Parses a big-endian field element or counter from hex.
 *
 * ```ts
 * hexToNumber('ff');
 * ```
 */
export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
  return BigInt(hex === '' ? '0' : '0x' + hex); // Big Endian
}

// Used in ff1
// BE: Big Endian, LE: Little Endian
/**
 * Converts big-endian bytes into bigint.
 * @param bytes - Big-endian bytes.
 * @returns Parsed bigint value.
 * @throws On invalid byte input passed to the internal hex conversion. {@link TypeError}
 * @example
 * Reads a big-endian integer from serialized bytes.
 *
 * ```ts
 * bytesToNumberBE(new Uint8Array([1, 0]));
 * ```
 */
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

// Used in micro, ff1
/**
 * Converts a number into big-endian bytes of fixed length.
 * @param n - Number to encode.
 * @param len - Output length in bytes.
 * @returns Big-endian bytes padded to `len`.
 * @throws On wrong argument types. {@link TypeError}
 * @throws If the requested output length cannot represent the encoded value. {@link RangeError}
 * @example
 * Encodes a counter as fixed-width big-endian bytes.
 *
 * ```ts
 * numberToBytesBE(1, 2);
 * ```
 */
export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}

// Global symbols, but ts doesn't see them: https://github.com/microsoft/TypeScript/issues/31535
declare const TextEncoder: any;
declare const TextDecoder: any;

/**
 * Converts string to bytes using UTF8 encoding.
 * @param str - String to encode.
 * @returns UTF-8 bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Encodes application text before encryption or MACing.
 *
 * ```ts
 * utf8ToBytes('abc'); // new Uint8Array([97, 98, 99])
 * ```
 */
export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new TypeError('string expected');
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}

/**
 * Converts bytes to string using UTF8 encoding.
 * @param bytes - UTF-8 bytes.
 * @returns Decoded string.
 * @example
 * Decodes UTF-8 plaintext back into a string.
 *
 * ```ts
 * bytesToUtf8(new Uint8Array([97, 98, 99])); // 'abc'
 * ```
 */
export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Checks if two U8A use same underlying buffer and overlaps.
 * This is invalid and can corrupt data.
 * @param a - First byte view.
 * @param b - Second byte view.
 * @returns `true` when the views overlap in memory.
 * @example
 * Detects whether two slices alias the same backing buffer.
 *
 * ```ts
 * overlapBytes(new Uint8Array(4), new Uint8Array(4));
 * ```
 */
export function overlapBytes(a: Uint8Array, b: Uint8Array): boolean {
  return (
    a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
    a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
    b.byteOffset < a.byteOffset + a.byteLength // b starts before a end
  );
}

/**
 * If input and output overlap and input starts before output, we will overwrite end of input before
 * we start processing it, so this is not supported for most ciphers (except chacha/salse, which designed with this)
 * @param input - Input bytes.
 * @param output - Output bytes.
 * @throws If the output view would overwrite unread input bytes. {@link Error}
 * @example
 * Rejects an in-place layout that would overwrite unread input bytes.
 *
 * ```ts
 * complexOverlapBytes(new Uint8Array(4), new Uint8Array(4));
 * ```
 */
export function complexOverlapBytes(input: Uint8Array, output: Uint8Array): void {
  // This is very cursed. It works somehow, but I'm completely unsure,
  // reasoning about overlapping aligned windows is very hard.
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error('complex overlap of input and output is not supported');
}

/**
 * Copies several Uint8Arrays into one.
 * @param arrays - Byte arrays to concatenate.
 * @returns Combined byte array.
 * @throws On wrong argument types inside the byte-array list. {@link TypeError}
 * @example
 * Builds a `nonce || ciphertext` style buffer.
 *
 * ```ts
 * concatBytes(new Uint8Array([1]), new Uint8Array([2]));
 * ```
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

// Used in ARX only
type EmptyObj = {};
/**
 * Merges user options into defaults.
 * @param defaults - Default option values.
 * @param opts - User-provided overrides.
 * @returns Combined options object.
 * @throws If options are missing or not an object. {@link Error}
 * @example
 * Applies user overrides to the default cipher options.
 *
 * ```ts
 * checkOpts({ rounds: 20 }, { rounds: 8 });
 * ```
 */
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts: T2
): T1 & T2 {
  if (opts == null || typeof opts !== 'object') throw new Error('options must be defined');
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

/**
 * Compares two byte arrays in kinda constant time.
 * @param a - First byte array.
 * @param b - Second byte array.
 * @returns `true` when the arrays contain the same bytes.
 * @example
 * Compares an expected authentication tag with the received one.
 *
 * ```ts
 * equalBytes(new Uint8Array([1]), new Uint8Array([1]));
 * ```
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// TODO: remove
/** Incremental hash interface used internally. */
export interface IHash2 {
  /** Bytes processed per compression block. */
  blockLen: number;
  /** Bytes produced by the final digest. */
  outputLen: number;
  /**
   * Absorbs one more chunk into the hash state.
   * @param buf - Data chunk to hash.
   * @returns The same hash instance for chaining.
   */
  update(buf: string | Uint8Array): this;
  /**
   * Writes the final digest into a caller-provided buffer.
   * @param buf - Destination buffer for the digest bytes.
   */
  digestInto(buf: Uint8Array): void;
  /**
   * Finalizes the hash and returns a fresh digest buffer.
   * @returns Digest bytes.
   */
  digest(): Uint8Array;
  /**
   * Resets internal state. Makes Hash instance unusable.
   * Reset is impossible for keyed hashes if key is consumed into state. If digest is not consumed
   * by user, they will need to manually call `destroy()` when zeroing is necessary.
   */
  destroy(): void;
}

// This will allow to re-use with composable things like packed & base encoders
// Also, we probably can make tags composable

/** Sync cipher: takes byte array and returns byte array. */
export type Cipher = {
  /**
   * Encrypts plaintext bytes.
   * @param plaintext - Data to encrypt.
   * @returns Ciphertext bytes.
   */
  encrypt(plaintext: Uint8Array): Uint8Array;
  /**
   * Decrypts ciphertext bytes.
   * @param ciphertext - Data to decrypt.
   * @returns Plaintext bytes.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array;
};

/** Async cipher e.g. from built-in WebCrypto. */
export type AsyncCipher = {
  /**
   * Encrypts plaintext bytes.
   * @param plaintext - Data to encrypt.
   * @returns Promise resolving to ciphertext bytes.
   */
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  /**
   * Decrypts ciphertext bytes.
   * @param ciphertext - Data to decrypt.
   * @returns Promise resolving to plaintext bytes.
   */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
};

/** Cipher with `output` argument which can optimize by doing 1 less allocation. */
export type CipherWithOutput = Cipher & {
  /**
   * Encrypts plaintext bytes into an optional caller-provided buffer.
   * @param plaintext - Data to encrypt.
   * @param output - Optional destination buffer.
   * @returns Ciphertext bytes.
   */
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  /**
   * Decrypts ciphertext bytes into an optional caller-provided buffer.
   * @param ciphertext - Data to decrypt.
   * @param output - Optional destination buffer.
   * @returns Plaintext bytes.
   */
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};

/**
 * Params are outside of return type, so it is accessible before calling constructor.
 * If function support multiple nonceLength's, we return the best one.
 */
export type CipherParams = {
  /** Cipher block size in bytes. */
  blockSize: number;
  /** Nonce length in bytes when the cipher uses a fixed nonce size. */
  nonceLength?: number;
  /** Authentication-tag length in bytes for AEAD modes. */
  tagLength?: number;
  /** Whether nonce length is variable at runtime. */
  varSizeNonce?: boolean;
};
/**
 * ARX AEAD cipher, like salsa or chacha.
 * @param key - Secret key bytes.
 * @param nonce - Nonce bytes.
 * @param AAD - Optional associated data.
 * @returns Cipher instance with caller-managed output buffers.
 */
export type ARXCipher = ((
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
) => CipherWithOutput) & {
  blockSize: number;
  nonceLength: number;
  tagLength: number;
};
/**
 * Cipher constructor signature.
 * @param key - Secret key bytes.
 * @param args - Additional constructor arguments, such as nonce or IV.
 * @returns Cipher instance.
 */
export type CipherCons<T extends any[]> = (key: Uint8Array, ...args: T) => Cipher;
/**
 * Wraps a cipher: validates args, ensures encrypt() can only be called once.
 * Used internally by the exported cipher constructors.
 * @__NO_SIDE_EFFECTS__
 * @param params - Static cipher metadata. See {@link CipherParams}.
 * @param constructor - Cipher constructor.
 * @returns Wrapped constructor with validation.
 */
export const wrapCipher = <C extends CipherCons<any>, P extends CipherParams>(
  params: P,
  constructor: C
): C & P => {
  function wrappedCipher(key: Uint8Array, ...args: any[]): CipherWithOutput {
    // Validate key
    abytes(key, undefined, 'key');

    // Big-Endian hardware is rare. Just in case someone still decides to run ciphers:
    if (!isLE) throw new Error('Non little-endian hardware is not yet supported');

    // Validate nonce if nonceLength is present
    if (params.nonceLength !== undefined) {
      const nonce = args[0];
      abytes(nonce, params.varSizeNonce ? undefined : params.nonceLength, 'nonce');
    }

    // Validate AAD if tagLength present
    const tagl = params.tagLength;
    if (tagl && args[1] !== undefined) abytes(args[1], undefined, 'AAD');

    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength: number, output?: Uint8Array) => {
      if (output !== undefined) {
        if (fnLength !== 2) throw new Error('cipher output not supported');
        abytes(output, undefined, 'output');
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
          throw new Error('"ciphertext" expected length bigger than tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return (cipher as CipherWithOutput).decrypt(data, output);
      },
    };

    return wrCipher;
  }

  Object.assign(wrappedCipher, params);
  return wrappedCipher as C & P;
};

/**
 * Represents a Salsa or ChaCha xor stream.
 * @param key - Secret key bytes.
 * @param nonce - Nonce bytes.
 * @param data - Input bytes to xor with the keystream.
 * @param output - Optional destination buffer.
 * @param counter - Optional starting block counter.
 * @returns Output bytes.
 */
export type XorStream = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output?: Uint8Array,
  counter?: number
) => Uint8Array;

/**
 * By default, returns u8a of length.
 * When out is available, it checks it for validity and uses it.
 * @param expectedLength - Required output length.
 * @param out - Optional destination buffer.
 * @param onlyAligned - Whether `out` must be 4-byte aligned.
 * @returns Output buffer ready for writing.
 * @throws If the provided output buffer has the wrong size or alignment. {@link Error}
 * @example
 * Reuses a caller-provided output buffer when lengths match.
 *
 * ```ts
 * getOutput(16, new Uint8Array(16));
 * ```
 */
export function getOutput(
  expectedLength: number,
  out?: Uint8Array,
  onlyAligned = true
): Uint8Array {
  if (out === undefined) return new Uint8Array(expectedLength);
  if (out.length !== expectedLength)
    throw new Error(
      '"output" expected Uint8Array of length ' + expectedLength + ', got: ' + out.length
    );
  if (onlyAligned && !isAligned32(out)) throw new Error('invalid output, must be aligned');
  return out;
}

/**
 * Encodes data and AAD bit lengths into a 16-byte buffer.
 * @param dataLength - Data length in bits.
 * @param aadLength - AAD length in bits.
 * @param isLE - Whether to encode lengths as little-endian.
 * @returns 16-byte length block.
 * @throws On wrong argument types passed to the endian validator. {@link TypeError}
 * @example
 * Builds the length block appended by GCM and Poly1305.
 *
 * ```ts
 * u64Lengths(16, 8, true);
 * ```
 */
export function u64Lengths(dataLength: number, aadLength: number, isLE: boolean): Uint8Array {
  abool(isLE);
  const num = new Uint8Array(16);
  const view = createView(num);
  view.setBigUint64(0, BigInt(aadLength), isLE);
  view.setBigUint64(8, BigInt(dataLength), isLE);
  return num;
}

/**
 * Checks whether a byte array is aligned to a 4-byte offset.
 * @param bytes - Byte array to inspect.
 * @returns `true` when the view is 4-byte aligned.
 * @example
 * Checks whether a buffer can be safely viewed as Uint32Array.
 *
 * ```ts
 * isAligned32(new Uint8Array(4));
 * ```
 */
export function isAligned32(bytes: Uint8Array): boolean {
  return bytes.byteOffset % 4 === 0;
}

/**
 * Copies bytes into a new Uint8Array.
 * @param bytes - Bytes to copy.
 * @returns Copied byte array.
 * @example
 * Copies input into an aligned Uint8Array before block processing.
 *
 * ```ts
 * copyBytes(new Uint8Array([1, 2]));
 * ```
 */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

/**
 * Cryptographically secure PRNG.
 * Uses internal OS-level `crypto.getRandomValues`.
 * @param bytesLength - Number of bytes to produce.
 * @returns Random byte array.
 * @throws If the runtime does not expose `crypto.getRandomValues`. {@link Error}
 * @example
 * Generates a fresh nonce or key.
 *
 * ```ts
 * randomBytes(16);
 * ```
 */
export function randomBytes(bytesLength = 32): Uint8Array {
  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : null;
  if (typeof cr?.getRandomValues !== 'function')
    throw new Error('crypto.getRandomValues must be defined');
  return cr.getRandomValues(new Uint8Array(bytesLength));
}

/**
 * The pseudorandom number generator doesn't wipe current state:
 * instead, it generates new one based on previous state + entropy.
 * Not reseed/rekey, since AES CTR DRBG does rekey on each randomBytes,
 * which is in fact `reseed`, since it changes counter too.
 */
export interface PRG {
  /**
   * Mixes fresh entropy into the current generator state.
   * @param seed - Entropy bytes to absorb.
   */
  addEntropy(seed: Uint8Array): void;
  /**
   * Produces a requested number of pseudorandom bytes.
   * @param length - Number of bytes to generate.
   * @returns Random byte array.
   */
  randomBytes(length: number): Uint8Array;
  /** Destroys the generator state. */
  clean(): void;
}

type RemoveNonceInner<T extends any[], Ret> = ((...args: T) => Ret) extends (
  arg0: any,
  arg1: any,
  ...rest: infer R
) => any
  ? (key: Uint8Array, ...args: R) => Ret
  : never;

/** Removes the nonce argument from a cipher constructor type. */
export type RemoveNonce<T extends (...args: any) => any> = RemoveNonceInner<
  Parameters<T>,
  ReturnType<T>
>;
/**
 * Cipher constructor that requires a nonce argument.
 * @param key - Secret key bytes.
 * @param nonce - Nonce bytes.
 * @param args - Additional cipher-specific arguments.
 * @returns Cipher instance.
 */
export type CipherWithNonce = ((
  key: Uint8Array,
  nonce: Uint8Array,
  ...args: any[]
) => Cipher | AsyncCipher) & {
  nonceLength: number;
};

/**
 * Uses CSPRNG for nonce, nonce injected in ciphertext.
 * For `encrypt`, a `nonceBytes`-length buffer is fetched from CSPRNG and
 * prepended to encrypted ciphertext. For `decrypt`, first `nonceBytes` of ciphertext
 * are treated as nonce.
 *
 * NOTE: Under the same key, using random nonces (e.g. `managedNonce`) with AES-GCM and ChaCha
 * should be limited to `2**23` (8M) messages to get a collision chance of `2**-50`. Stretching to  * `2**32` (4B) messages, chance would become `2**-33` - still negligible, but creeping up.
 * @param fn - Cipher constructor that expects a nonce.
 * @param randomBytes_ - Random-byte source used for nonce generation.
 * @returns Cipher constructor that prepends the nonce to ciphertext.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On invalid nonce lengths observed at wrapper construction or use. {@link RangeError}
 * @example
 * Prepends a fresh random nonce to every ciphertext.
 *
 * ```ts
 * import { gcm } from '@noble/ciphers/aes.js';
 * import { managedNonce, randomBytes } from '@noble/ciphers/utils.js';
 * const wrapped = managedNonce(gcm);
 * const key = randomBytes(16);
 * const ciphertext = wrapped(key).encrypt(new Uint8Array([1, 2, 3]));
 * wrapped(key).decrypt(ciphertext);
 * ```
 */
export function managedNonce<T extends CipherWithNonce>(
  fn: T,
  randomBytes_: typeof randomBytes = randomBytes
): RemoveNonce<T> {
  const { nonceLength } = fn;
  anumber(nonceLength);
  const addNonce = (nonce: Uint8Array, ciphertext: Uint8Array) => {
    const out = concatBytes(nonce, ciphertext);
    ciphertext.fill(0);
    return out;
  };
  // NOTE: we cannot support DST here, it would be mistake:
  // - we don't know how much dst length cipher requires
  // - nonce may unalign dst and break everything
  // - we create new u8a anyway (concatBytes)
  // - previously we passed all args to cipher, but that was mistake!
  return ((key: Uint8Array, ...args: any[]): any => ({
    encrypt(plaintext: Uint8Array) {
      abytes(plaintext);
      const nonce = randomBytes_(nonceLength);
      const encrypted = fn(key, nonce, ...args).encrypt(plaintext);
      // @ts-ignore
      if (encrypted instanceof Promise) return encrypted.then((ct) => addNonce(nonce, ct));
      return addNonce(nonce, encrypted);
    },
    decrypt(ciphertext: Uint8Array) {
      abytes(ciphertext);
      const nonce = ciphertext.subarray(0, nonceLength);
      const decrypted = ciphertext.subarray(nonceLength);
      return fn(key, nonce, ...args).decrypt(decrypted);
    },
  })) as RemoveNonce<T>;
}

/** `Uint8Array.of()` return type helper for TS 5.9. */
export type Uint8ArrayBuffer = ReturnType<typeof Uint8Array.of>;
