import { pathToFileURL } from 'node:url';
export function resolve(url, context, nextResolve) {
  const file = Number.parseInt(process.version.slice(1, 3)) === 18 ? 'cryptoNode.js' : 'crypto.js';
  if (url === '@noble/ciphers/crypto') url = pathToFileURL('./esm/' + file).toString();
  return nextResolve(url, context);
}
