import { AsyncCipher, createView, setBigUint64 } from '../utils.js';
import { polyval } from '../_polyval.js';
import { getWebcryptoSubtle } from './utils.js';
/**
 * AES-GCM-SIV: classic AES-GCM with nonce-misuse resistance.
 * RFC 8452, https://datatracker.ietf.org/doc/html/rfc8452
 */

// AES stuff (same as ff1)
const BLOCK_LEN = 16;
const IV = new Uint8Array(BLOCK_LEN);
async function encryptBlock(msg: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 16 && key.length !== 32) throw new Error('Invalid key length');
  const mode = { name: `AES-CBC`, length: key.length * 8 };
  const cr = getWebcryptoSubtle();
  const wKey = await cr.importKey('raw', key, mode, true, ['encrypt']);
  const cipher = await cr.encrypt({ name: `aes-cbc`, iv: IV, counter: IV, length: 64 }, wKey, msg);
  return new Uint8Array(cipher).subarray(0, 16);
}

// Kinda constant-time equality
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Should not happen
  if (a.length !== b.length) throw new Error('equalBytes: Different size of Uint8Arrays');
  let flag = true;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) flag &&= false;
  return flag;
}
// Wrap position so it will be in padded to blockSize
const wrapPos = (pos: number, blockSize: number) => Math.ceil(pos / blockSize) * blockSize;

const limit = (name: string, min: number, max: number) => (value: number) => {
  if (!Number.isSafeInteger(value) || min > value || value > max)
    throw new Error(`${name}: invalid value=${value}, should be [${min}..${max}]`);
};

// From RFC 8452: Section 6
const AAD_LIMIT = limit('AAD', 0, 2 ** 36);
const PLAIN_LIMIT = limit('Plaintext', 0, 2 ** 36);
const NONCE_LIMIT = limit('Nonce', 12, 12);
const CIPHER_LIMIT = limit('Ciphertext', 16, 2 ** 36 + 16);

// nodejs api doesn't support 32bit counters, browser does
async function ctr(key: Uint8Array, tag: Uint8Array, input: Uint8Array) {
  // The initial counter block is the tag with the most significant bit of the last byte set to one.
  let block = tag.slice();
  block[15] |= 0x80;
  let view = createView(block);
  let output = new Uint8Array(input.length);
  for (let pos = 0; pos < input.length; ) {
    const encryptedBlock = await encryptBlock(block, key);
    view.setUint32(0, view.getUint32(0, true) + 1, true);
    const take = Math.min(input.length, encryptedBlock.length);
    for (let j = 0; j < take; j++, pos++) output[pos] = encryptedBlock[j] ^ input[pos];
  }
  return new Uint8Array(output);
}

export async function deriveKeys(key: Uint8Array, nonce: Uint8Array) {
  NONCE_LIMIT(nonce.length);
  if (key.length !== 16 && key.length !== 32)
    throw new Error(`Key length should be 16 or 32 bytes, got: ${key.length} bytes.`);
  const encKey = new Uint8Array(key.length);
  const authKey = new Uint8Array(16);
  let counter = 0;
  const deriveBlock = new Uint8Array(nonce.length + 4);
  deriveBlock.set(nonce, 4);
  const view = createView(deriveBlock);
  for (const derivedKey of [authKey, encKey]) {
    for (let i = 0; i < derivedKey.length; i += 8) {
      view.setUint32(0, counter++, true);
      const block = await encryptBlock(deriveBlock, key);
      derivedKey.set(block.subarray(0, 8), i);
    }
  }
  return { authKey, encKey };
}

export async function aes_256_gcm_siv(
  key: Uint8Array,
  nonce: Uint8Array,
  AAD: Uint8Array
): Promise<AsyncCipher> {
  const { encKey, authKey } = await deriveKeys(key, nonce);
  const computeTag = async (data: Uint8Array, AAD: Uint8Array) => {
    const dataPos = wrapPos(AAD.length, 16);
    const lenPos = wrapPos(dataPos + data.length, 16);
    const block = new Uint8Array(lenPos + 16);
    const view = createView(block);
    block.set(AAD);
    block.set(data, dataPos);
    setBigUint64(view, lenPos, BigInt(AAD.length * 8), true);
    setBigUint64(view, lenPos + 8, BigInt(data.length * 8), true);
    // Compute the expected tag by XORing S_s and the nonce, clearing the
    // most significant bit of the last byte and encrypting with the
    // message-encryption key.
    const tag = polyval(authKey, block);
    for (let i = 0; i < 12; i++) tag[i] ^= nonce[i];
    // Clear the highest bit
    tag[15] &= 0x7f;
    return await encryptBlock(tag, encKey);
  };
  return {
    //    computeTag,
    encrypt: async (plaintext: Uint8Array) => {
      AAD_LIMIT(AAD.length);
      PLAIN_LIMIT(plaintext.length);
      const tag = await computeTag(plaintext, AAD);
      const out = new Uint8Array(plaintext.length + 16);
      out.set(tag, plaintext.length);
      out.set(await ctr(encKey, tag, plaintext));
      return out;
    },
    decrypt: async (ciphertext: Uint8Array) => {
      CIPHER_LIMIT(ciphertext.length);
      AAD_LIMIT(AAD.length);
      const tag = ciphertext.subarray(-16);
      const plaintext = await ctr(encKey, tag, ciphertext.subarray(0, -16));
      const expectedTag = await computeTag(plaintext, AAD);
      if (!equalBytes(tag, expectedTag)) throw new Error('Wrong TAG');
      return plaintext;
    },
  };
}
