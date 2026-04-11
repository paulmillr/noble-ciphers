/**
 * Basic utils for ARX (add-rotate-xor) salsa and chacha ciphers.

RFC8439 requires multi-step cipher stream, where
authKey starts with counter: 0, actual msg with counter: 1.

For this, we need a way to re-use nonce / counter:

    const counter = new Uint8Array(4);
    chacha(..., counter, ...); // counter is now 1
    chacha(..., counter, ...); // counter is now 2

This is complicated:

- 32-bit counters are enough, no need for 64-bit: max ArrayBuffer size in JS is 4GB
- Original papers don't allow mutating counters
- Counter overflow is undefined [^1]
- Idea A: allow providing (nonce | counter) instead of just nonce, re-use it
- Caveat: Cannot be re-used through all cases:
- * chacha has (counter | nonce)
- * xchacha has (nonce16 | counter | nonce16)
- Idea B: separate nonce / counter and provide separate API for counter re-use
- Caveat: there are different counter sizes depending on an algorithm.
- salsa & chacha also differ in structures of key & sigma:
  salsa20:      s[0] | k(4) | s[1] | nonce(2) | cnt(2) | s[2] | k(4) | s[3]
  chacha:       s(4) | k(8) | cnt(1) | nonce(3)
  chacha20orig: s(4) | k(8) | cnt(2) | nonce(2)
- Idea C: helper method such as `setSalsaState(key, nonce, sigma, data)`
- Caveat: we can't re-use counter array

xchacha uses the subkey and remaining 8 byte nonce with ChaCha20 as normal
(prefixed by 4 NUL bytes, since RFC8439 specifies a 12-byte nonce).
Counter overflow is undefined; see {@link https://mailarchive.ietf.org/arch/msg/cfrg/gsOnTJzcbgG6OqD8Sc0GO5aR_tU/ | the CFRG thread}.
Current noble policy is strict non-wrap for the shared 32-bit counter path:
exported ARX ciphers reject initial `0xffffffff` and stop before any implicit
wrap back to zero.
See {@link https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.2 | the XChaCha appendix} for the extended-nonce construction.

 * @module
 */
import {
  type PRG,
  type TArg,
  type TRet,
  type XorStream,
  abool,
  abytes,
  anumber,
  checkOpts,
  clean,
  copyBytes,
  getOutput,
  isAligned32,
  isLE,
  randomBytes,
  swap32IfBE,
  u32,
} from './utils.ts';

// Replaces `TextEncoder` for ASCII literals, which is enough for sigma constants.
// Non-ASCII input would not match UTF-8 `TextEncoder` output.
const encodeStr = (str: string) => Uint8Array.from(str.split(''), (c) => c.charCodeAt(0));
// Raw `createCipher(...)` exports consume these native-endian `u32(...)` views directly.
// Public `wrapCipher(...)` APIs reject non-little-endian platforms before reaching this path.
// RFC 8439 §2.3 / RFC 7539 §2.3 only define the 256-bit-key constants; this 16-byte sigma is
// kept for legacy allowShortKeys Salsa/ChaCha variants.
const sigma16_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr('expand 16-byte k'))))();
// RFC 8439 §2.3 / RFC 7539 §2.3 define words 0-3 as
// `0x61707865 0x3320646e 0x79622d32 0x6b206574`, i.e. `expand 32-byte k`.
const sigma32_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr('expand 32-byte k'))))();

/**
 * Rotates a 32-bit word left.
 * @param a - Input word.
 * @param b - Rotation count in bits.
 * @returns Rotated 32-bit word.
 * @example
 * Moves the top byte of `0x12345678` into the low byte position.
 * ```ts
 * rotl(0x12345678, 8);
 * ```
 */
export function rotl(a: number, b: number): number {
  return (a << b) | (a >>> (32 - b));
}

/**
 * ARX core function operating on 32-bit words. Ciphers must use u32 for efficiency.
 * @param sigma - Sigma constants for the selected cipher layout.
 * @param key - Expanded key words.
 * @param nonce - Nonce and counter words prepared for the round function.
 * @param output - Output block written in place.
 * @param counter - Block counter value.
 * @param rounds - Optional round count override.
 */
export type CipherCoreFn = (
  sigma: TArg<Uint32Array>,
  key: TArg<Uint32Array>,
  nonce: TArg<Uint32Array>,
  output: TArg<Uint32Array>,
  counter: number,
  rounds?: number
) => void;

/**
 * Nonce-extension function used by XChaCha and XSalsa.
 * @param sigma - Sigma constants for the selected cipher layout.
 * @param key - Expanded key words.
 * @param input - Input nonce words used for subkey derivation.
 * @param output - Output buffer written with the derived nonce words.
 */
export type ExtendNonceFn = (
  sigma: TArg<Uint32Array>,
  key: TArg<Uint32Array>,
  input: TArg<Uint32Array>,
  output: TArg<Uint32Array>
) => void;

/** ARX cipher options.
 * * `allowShortKeys` for 16-byte keys
 * * `counterLength` in bytes
 * * `counterRight`: right: `nonce|counter`; left: `counter|nonce`
 * */
export type CipherOpts = {
  /** Whether 16-byte keys are accepted for legacy Salsa and ChaCha variants. */
  allowShortKeys?: boolean;
  /** Optional nonce-expansion hook used by extended-nonce variants. */
  extendNonceFn?: ExtendNonceFn;
  /** Counter length in bytes inside the nonce/counter layout. */
  counterLength?: number;
  /** Whether the layout is `nonce|counter` instead of `counter|nonce`. */
  counterRight?: boolean;
  /** Number of core rounds to execute. */
  rounds?: number;
};

// Salsa and Chacha block length is always 512-bit
const BLOCK_LEN = 64;
// RFC 8439 §2.2 / RFC 7539 §2.2: the ChaCha state has 16 32-bit words.
const BLOCK_LEN32 = 16;

// Counter policy for the shared public `counter` argument:
// - RFC/IETF ChaCha20 uses a 32-bit counter.
// - OpenSSL/Node `chacha20` instead treat the full 16-byte IV as a 128-bit
//   counter state and carry into the next word.
// - Raw `chacha20orig`, `salsa20`, `xsalsa20`, and `xchacha20` use 64-bit counters in libsodium
//   and libtomcrypt, while some libs (for example libtomcrypt's RFC/IETF path) reject the max
//   boundary instead of carrying.
// - AEAD wrappers diverge too: libsodium `xchacha20poly1305` uses the IETF payload counter from
//   block 1, while `secretstream_xchacha20poly1305` is a different protocol with rekey/reset.
// Noble intentionally throws instead of silently picking one wrap model for users. In the default
// path, even a 32-bit boundary would take 2^32 blocks * 64 bytes = 256 GiB, which is practically
// unreachable for normal JS callers; advanced users who pass `counter` explicitly can implement
// whatever wider carry / wrap policy they need on top.
const MAX_COUNTER = /* @__PURE__ */ (() => 2 ** 32 - 1)();
const U32_EMPTY = /* @__PURE__ */ Uint32Array.of();
function runCipher(
  core: TArg<CipherCoreFn>,
  sigma: TArg<Uint32Array>,
  key: TArg<Uint32Array>,
  nonce: TArg<Uint32Array>,
  data: TArg<Uint8Array>,
  output: TArg<Uint8Array>,
  counter: number,
  rounds: number
): void {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u32(block);
  // Make sure that buffers aligned to 4 bytes
  const isAligned = isLE && isAligned32(data) && isAligned32(output);
  const d32 = isAligned ? u32(data) : U32_EMPTY;
  const o32 = isAligned ? u32(output) : U32_EMPTY;
  // RFC 8439 §2.4.1 / RFC 7539 §2.4.1 allow XORing one keystream block at a time and
  // truncating the final partial block instead of materializing the whole keystream.
  if (!isLE) {
    for (let pos = 0; pos < len; counter++) {
      core(
        sigma as TRet<Uint32Array>,
        key as TRet<Uint32Array>,
        nonce as TRet<Uint32Array>,
        b32,
        counter,
        rounds
      );
      // RFC 8439 §2.4 / RFC 7539 §2.4 serialize keystream words in little-endian order.
      swap32IfBE(b32);
      if (counter >= MAX_COUNTER) throw new Error('arx: counter overflow');
      const take = Math.min(BLOCK_LEN, len - pos);
      for (let j = 0, posj; j < take; j++) {
        posj = pos + j;
        output[posj] = data[posj] ^ block[j];
      }
      pos += take;
    }
    return;
  }
  for (let pos = 0; pos < len; counter++) {
    core(
      sigma as TRet<Uint32Array>,
      key as TRet<Uint32Array>,
      nonce as TRet<Uint32Array>,
      b32,
      counter,
      rounds
    );
    // See MAX_COUNTER policy note above: never silently wrap the shared public counter.
    if (counter >= MAX_COUNTER) throw new Error('arx: counter overflow');
    const take = Math.min(BLOCK_LEN, len - pos);
    // aligned to 4 bytes
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0) throw new Error('arx: invalid block position');
      for (let j = 0, posj: number; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}

/**
 * Creates an ARX stream cipher from a 32-bit core permutation.
 * Used internally to build the exported Salsa and ChaCha stream ciphers.
 * @param core - Core function that fills one keystream block.
 * @param opts - Cipher layout and nonce-extension options. See {@link CipherOpts}.
 * @returns Stream cipher function over byte arrays.
 * @throws If the core callback, key size, counter, or output sizing is invalid. {@link Error}
 */
export function createCipher(core: TArg<CipherCoreFn>, opts: TArg<CipherOpts>): TRet<XorStream> {
  const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts(
    { allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 },
    opts
  );
  if (typeof core !== 'function') throw new Error('core must be a function');
  anumber(counterLength);
  anumber(rounds);
  abool(counterRight);
  abool(allowShortKeys);
  return (
    key: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    output?: TArg<Uint8Array>,
    counter = 0
  ): TRet<Uint8Array> => {
    abytes(key, undefined, 'key');
    abytes(nonce, undefined, 'nonce');
    abytes(data, undefined, 'data');
    const len = data.length;
    // Raw XorStream APIs return ciphertext/plaintext bytes directly, so caller-provided outputs
    // must match the logical result length exactly instead of returning an oversized workspace.
    output = getOutput(len, output, false);
    anumber(counter);
    // See MAX_COUNTER policy note above: reject advanced explicit-counter requests before any wrap.
    if (counter < 0 || counter >= MAX_COUNTER) throw new Error('arx: counter overflow');
    const toClean = [];

    // Key & sigma
    // key=16 -> sigma16, k=key|key
    // key=32 -> sigma32, k=key
    let l = key.length;
    let k: Uint8Array;
    let sigma: Uint32Array;
    if (l === 32) {
      // Copy caller keys too: big-endian normalization, extended-nonce subkey derivation, and
      // final clean(...) all mutate or wipe the temporary buffer in place.
      toClean.push((k = copyBytes(key)));
      sigma = sigma32_32;
    } else if (l === 16 && allowShortKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else {
      abytes(key, 32, 'arx key');
      throw new Error('invalid key size');
      // throw new Error(`"arx key" expected Uint8Array of length 32, got length=${l}`);
    }

    // Nonce
    // salsa20:      8   (8-byte counter)
    // chacha20orig: 8   (8-byte counter)
    // chacha20:     12  (4-byte counter)
    // xsalsa20:     24  (16 -> hsalsa,  8 -> old nonce)
    // xchacha20:    24  (16 -> hchacha, 8 -> old nonce)
    // Copy before taking u32(...) views on misaligned inputs, and on big-endian so later
    // swap32IfBE(...) never mutates caller nonce bytes in place.
    if (!isLE || !isAligned32(nonce)) toClean.push((nonce = copyBytes(nonce)));

    let k32 = u32(k);
    // hsalsa & hchacha: handle extended nonce
    if (extendNonceFn) {
      if (nonce.length !== 24) throw new Error(`arx: extended nonce must be 24 bytes`);
      const n16 = nonce.subarray(0, 16);
      if (isLE) extendNonceFn(sigma as TRet<Uint32Array>, k32, u32(n16), k32);
      else {
        const sigmaRaw = swap32IfBE(Uint32Array.from(sigma));
        extendNonceFn(sigmaRaw, k32, u32(n16), k32);
        clean(sigmaRaw);
        swap32IfBE(k32);
      }
      nonce = nonce.subarray(16);
    } else if (!isLE) swap32IfBE(k32);

    // Handle nonce counter
    const nonceNcLen = 16 - counterLength;
    if (nonceNcLen !== nonce.length)
      throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);

    // Normalize 64-bit-nonce layouts to the 12-byte core input: ChaCha/XChaCha prefix 4 zero
    // counter bytes, while Salsa/XSalsa append them after the nonce words.
    if (nonceNcLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      nonce = nc;
      toClean.push(nonce);
    }
    const n32 = swap32IfBE(u32(nonce));
    // Ensure temporary key/nonce copies are wiped even if the remaining
    // runtime guard in runCipher(...) throws on counter overflow.
    try {
      runCipher(core, sigma, k32, n32, data, output, counter, rounds);
      return output as TRet<Uint8Array>;
    } finally {
      clean(...toClean);
    }
  };
}

/** Internal class which wraps chacha20 or chacha8 to create CSPRNG. */
export class _XorStreamPRG implements PRG {
  readonly blockLen: number;
  readonly keyLen: number;
  readonly nonceLen: number;
  private state: TRet<Uint8Array>;
  private buf: TRet<Uint8Array>;
  private key: TRet<Uint8Array>;
  private nonce: TRet<Uint8Array>;
  private pos: number;
  private ctr: number;
  private cipher: TArg<XorStream>;
  constructor(
    cipher: TArg<XorStream>,
    blockLen: number,
    keyLen: number,
    nonceLen: number,
    seed: TArg<Uint8Array>
  ) {
    this.cipher = cipher;
    this.blockLen = blockLen;
    this.keyLen = keyLen;
    this.nonceLen = nonceLen;
    this.state = new Uint8Array(this.keyLen + this.nonceLen) as TRet<Uint8Array>;
    this.reseed(seed);
    this.ctr = 0;
    this.pos = this.blockLen;
    this.buf = new Uint8Array(this.blockLen) as TRet<Uint8Array>;
    // Keep a single key||nonce backing buffer so reseed/addEntropy/clean update the live cipher
    // inputs in place through these subarray views.
    this.key = this.state.subarray(0, this.keyLen) as TRet<Uint8Array>;
    this.nonce = this.state.subarray(this.keyLen) as TRet<Uint8Array>;
  }
  private reseed(seed: TArg<Uint8Array>) {
    abytes(seed);
    if (!seed || seed.length === 0) throw new Error('entropy required');
    // Mix variable-length entropy cyclically across the whole key||nonce state, then restart the
    // keystream so buffered leftovers from the previous state are never reused.
    for (let i = 0; i < seed.length; i++) this.state[i % this.state.length] ^= seed[i];
    this.ctr = 0;
    this.pos = this.blockLen;
  }
  addEntropy(seed: TArg<Uint8Array>): void {
    // Reject empty entropy before re-keying, otherwise a throwing call would still advance state.
    abytes(seed);
    if (seed.length === 0) throw new Error('entropy required');
    // Re-key from the current stream first, then mix external entropy into the fresh key||nonce
    // state through reseed() so stale buffered bytes are discarded.
    this.state.set(this.randomBytes(this.state.length));
    this.reseed(seed);
  }
  randomBytes(len: number): TRet<Uint8Array> {
    anumber(len);
    if (len === 0) return new Uint8Array(0) as TRet<Uint8Array>;
    const avail = this.pos < this.blockLen ? this.blockLen - this.pos : 0;
    const blocks = Math.ceil(Math.max(0, len - avail) / this.blockLen);
    // Preflight overflow so failed reads don't partially consume keystream
    // and leave the PRG repeating blocks.
    if (blocks > 0 && this.ctr > MAX_COUNTER - blocks) throw new Error('arx: counter overflow');
    const out = new Uint8Array(len);
    let outPos = 0;
    // `out` starts zero-filled, and `buf.fill(0)` below does the same for leftovers: XOR-stream
    // ciphers then emit raw keystream bytes directly into those buffers.
    // Serve buffered leftovers first so split reads stay identical to one larger read.
    if (this.pos < this.blockLen) {
      const take = Math.min(len, this.blockLen - this.pos);
      out.set(this.buf.subarray(this.pos, this.pos + take), 0);
      this.pos += take;
      outPos += take;
      if (outPos === len) return out as TRet<Uint8Array>; // fast path
    }
    // Full blocks directly to out
    const full = Math.floor((len - outPos) / this.blockLen);
    if (full > 0) {
      const blockBytes = full * this.blockLen;
      const b = out.subarray(outPos, outPos + blockBytes);
      this.cipher(this.key, this.nonce, b as TRet<Uint8Array>, b as TRet<Uint8Array>, this.ctr);
      this.ctr += full;
      outPos += blockBytes;
    }
    // Save leftovers
    const left = len - outPos;
    if (left > 0) {
      this.buf.fill(0);
      // NOTE: cipher will handle overflow
      this.cipher(
        this.key,
        this.nonce,
        this.buf as TRet<Uint8Array>,
        this.buf as TRet<Uint8Array>,
        this.ctr++
      );
      out.set(this.buf.subarray(0, left), outPos);
      this.pos = left;
    }
    return out as TRet<Uint8Array>;
  }
  // Clone seeds the new instance from this stream, so the source PRG advances too.
  clone(): _XorStreamPRG {
    return new _XorStreamPRG(
      this.cipher,
      this.blockLen,
      this.keyLen,
      this.nonceLen,
      this.randomBytes(this.state.length)
    );
  }
  // Zeroes the current state and leftover buffer, but does not make the instance unusable:
  // Later reads first drain zeros from the cleared buffer and then continue
  // from zero key||nonce state.
  clean(): void {
    this.pos = 0;
    this.ctr = 0;
    this.buf.fill(0);
    this.state.fill(0);
  }
}

/**
 * PRG constructor backed by an ARX stream cipher.
 * @param seed - Optional seed bytes mixed into the initial state. When omitted, exactly 32
 * random bytes are mixed in by default: larger states keep a zero tail, while smaller states
 * wrap those bytes through `reseed()`'s XOR schedule.
 * @returns Seeded concrete `_XorStreamPRG` instance, including `clone()`.
 */
export type XorPRG = (seed?: TArg<Uint8Array>) => TRet<_XorStreamPRG>;

/**
 * Creates a PRG constructor from a stream cipher.
 * @param cipher - Stream cipher used to fill output blocks.
 * @param blockLen - Keystream block length in bytes.
 * @param keyLen - Internal key length in bytes.
 * @param nonceLen - Internal nonce length in bytes.
 * @returns PRG factory for seeded concrete `_XorStreamPRG` instances.
 * @example
 * Builds a PRG from XChaCha20 and reads bytes from a randomly seeded instance.
 * ```ts
 * import { xchacha20 } from '@noble/ciphers/chacha.js';
 * import { createPRG } from '@noble/ciphers/_arx.js';
 * import { randomBytes } from '@noble/ciphers/utils.js';
 * const seed = randomBytes(32);
 * const init = createPRG(xchacha20, 64, 32, 24);
 * const prg = init(seed);
 * prg.randomBytes(8);
 * ```
 */
export const createPRG = (
  cipher: TArg<XorStream>,
  blockLen: number,
  keyLen: number,
  nonceLen: number
): TRet<XorPRG> => {
  return ((seed: TArg<Uint8Array> = randomBytes(32)): TRet<_XorStreamPRG> =>
    new _XorStreamPRG(
      cipher,
      blockLen,
      keyLen,
      nonceLen,
      seed
    ) as TRet<_XorStreamPRG>) as TRet<XorPRG>;
};
