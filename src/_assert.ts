function anumber(n: number) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`positive integer expected, not ${n}`);
}

function abool(b: boolean) {
  if (typeof b !== 'boolean') throw new Error(`boolean expected, not ${b}`);
}

export function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}

function abytes(b: Uint8Array | undefined, ...lengths: number[]) {
  if (!isBytes(b)) throw new Error('Uint8Array expected');
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}

export type Hash = {
  (data: Uint8Array): Uint8Array;
  blockLen: number;
  outputLen: number;
  create: any;
};
function ahash(hash: Hash) {
  if (typeof hash !== 'function' || typeof hash.create !== 'function')
    throw new Error('hash must be wrapped by utils.wrapConstructor');
  anumber(hash.outputLen);
  anumber(hash.blockLen);
}

function aexists(instance: any, checkFinished = true) {
  if (instance.destroyed) throw new Error('Hash instance has been destroyed');
  if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}

function aoutput(out: any, instance: any) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`);
  }
}

export { anumber, abool, abytes, ahash, aexists, aoutput };
const assert = {
  number: anumber,
  bool: abool,
  bytes: abytes,
  hash: ahash,
  exists: aexists,
  output: aoutput,
};
export default assert;
