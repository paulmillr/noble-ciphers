# Changelog for noble-ciphers

## 2.4.0 (2026-08-27)

- ChaCha / Salsa: reject output buffers that partially overlap unread input
- PRG: using after clean now throws
- Webcrypto: snapshot keys and params
- FF1: sizing for very large domains

## 2.3.0 (2026-08-08)

### Hardening

- AEAD strictness: passing AAD to a cipher that doesn't support it now throws `AAD not supported` instead of silently ignoring it. Applies to both native ciphers and the WebCrypto wrappers via a new `withAAD` cipher parameter.
- CBC/ECB padding failures now surface as a generic `aes: bad decrypt` instead of a padding-specific message, reducing padding-oracle signal.
- FF1: `minLen` now enforces the NIST SP 800-38G minimum of 2 in addition to `radix ** minLen >= 100`; stricter radix encoding guards.
- Correctness fixes for big-endian CPUs (POLYVAL tag normalization and AES-CTR partial-block tails).
- Other minor corrections.
- Reduce on-disk package size from 710 KB to 531 KB by disabling source maps, which have become less relevant.
- Boost AES-SIV speed by 20%.

## 2.2.0 (2026-04-11)

- **March 2026 self-audit** (all files): no major issues found.
  - Audited for specification compliance and security.
  - Fixed the `ctr` implementation from the `webcrypto` submodule using incorrect counter wrapping.
  - Fixed MAC corrupting oversized outputs.
  - Aligned the CMAC API with other MACs.
- Fixed all byte-array types to work properly in both TypeScript 5.6 and TypeScript 5.9+.
  - TypeScript 5.6 has `Uint8Array`, while TypeScript 5.9+ made it generic: `Uint8Array<ArrayBuffer>`.
  - This created incompatibilities between TypeScript versions.
  - Previously, usage was difficult and constantly emitted errors similar to `TS2345`.
  - See [TypeScript issue #62240](https://github.com/microsoft/TypeScript/issues/62240) for more context.
- Fixed compilation issues on TypeScript 6.
- Zeroization improvements by @ChALkeR in [#67](https://github.com/paulmillr/noble-ciphers/pull/67) and [#68](https://github.com/paulmillr/noble-ciphers/pull/68).
- Made the package big-endian friendly. All tests pass on s390x.
- Improved tree-shaking and reduced bundle sizes.
- Added extensive documentation throughout the codebase.

## 2.1.1 (2025-12-07)

- Implemented AES-SIV by @overheadhunter in [#62](https://github.com/paulmillr/noble-ciphers/pull/62).
  - AES-SIV (RFC 5297) is different from AES-GCM-SIV (RFC 8452).
  - Deprecated the old `siv` export in `aes.js` because it was an alias for `gcmsiv`.
- Published the provenance statement that was missed in 2.0.1 due to GitHub bugs.

### New Contributors

- @overheadhunter made their first contribution in [#62](https://github.com/paulmillr/noble-ciphers/pull/62).

## 2.0.1 (2025-09-22)

- Disabled extensionless imports. If you used `/chacha`, switch to `/chacha.js`. See [2.0.0](https://github.com/paulmillr/noble-ciphers/releases/tag/2.0.0) for more details.
- Specified exported submodules in `package.json` to ensure TypeScript autocompletion.

### GitHub Immutable Releases

This GitHub release does not include NPM and JSR attestations due to bugs related to newly added GitHub Immutable Releases.

## 2.0.0 (2025-08-25)

### High-level changes

- The package is now ESM-only. ESM can be loaded from CommonJS on Node.js 20.19+.
  - Node.js 20.19 is now the minimum required version.
  - Package imports now work correctly in bundlerless environments, such as browsers.
  - Reduced NPM package size from 118 KB to 99 KB.
  - Reduced unpacked NPM size from 753 KB to 458 KB.
- Made bundle sizes smaller compared to v1.x.
- The `.js` extension must be used for all modules.
  - Old: `@noble/ciphers/aes`
  - New: `@noble/ciphers/aes.js`
  - This simplifies native browser usage without transpilers.

### Changes

- Moved `randomBytes` and `managedNonce` from WebCrypto to `utils.js`.
- Restricted GHASH, Poly1305, and POLYVAL hash inputs to `Uint8Array`; strings are prohibited.
- Added `abytes` to utils and removed `ahash` and `toBytes`.
- Removed the `_assert` module (use `utils`), `_micro`, and `crypto` (use `webcrypto`).
- Upgraded the TypeScript compilation environment to TypeScript 5.9 and ES2022.
- Made error messages substantially more descriptive.

## 1.3.0 (2025-04-24)

- Modules are now available with a `.js` extension.
  - Old: `@noble/ciphers/chacha`
  - New: `@noble/ciphers/chacha.js`
  - The old path remains available.
  - This simplifies native browser usage without transpilers.
- Updated utils to use built-in `Uint8Array` `toHex` and `fromHex` [when available](https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex), providing a 13× speed-up on 256-byte arrays and a 20× speed-up on 32 KB arrays.
- Ensured `utils.randomBytes` has the same `Uint8Array` return type in older Node.js versions.
- Moved `_assert` into utils.
- Renamed `siv` to `gcmsiv`.
- Standalone build files are now attested in CI. See the README for the verification guide.
- TypeScript source can now be used without compilation in Node.js 24 due to [`erasableSyntaxOnly`](https://devblogs.microsoft.com/typescript/announcing-typescript-5-8/#the---erasablesyntaxonly-option).

## 1.2.1 (2025-01-18)

- Enabled TypeScript's `verbatimModuleSyntax` to support future Node.js type stripping.

## 1.2.0 (2025-01-03)

- The package is now available [on JSR](https://jsr.io/@noble/ciphers).
- Enabled TypeScript's [`isolatedDeclarations`](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-5-5.html#isolated-declarations) option, which substantially simplifies automatic documentation generation and more.
  - See the JSR page for an example.
- Added extensive comments throughout the codebase to improve autocompletion, LLM code generation, and general code understanding.
- Removed some exports from the internal `_assert` module.

## 1.1.3 (2024-11-30)

- Hardened input and output buffer checks.
  - Ensured all ciphers prohibit overlaps.
  - Ensured SalsaPoly supports overlapping input and output.
  - Ensured ChaChaPoly supports overlapping input and output, restoring the 1.0.0 behavior.

## 1.1.2 (2024-11-28)

- Prohibited input and output overlaps.
  - Reusing the same buffer still works when indexes do not overlap.

## 1.1.1 (2024-11-26)

- Fixed usage with unaligned `output`. Closes #47.
- Ensured `output` is zeroized before use.

## 1.1.0 (2024-11-23)

- Improved input validation by moving key, nonce, and input validation into `wrapCipher`.
  - Explicitly prohibited calling a cipher more than once.
- Sped up byte-array checks.
- Decreased bundle size and improved tree-shaking.

### New Contributors

- @ChALkeR made their first contribution in [#44](https://github.com/paulmillr/noble-ciphers/pull/44).

## 1.0.0 (2024-09-12)

- First audited version.
- Prohibited AES-GCM nonces smaller than 8 bytes.
- Hid unnecessary data exposure in AES errors.
- Improved FF1 type checks.
- Added support for Node.js 14.

## 0.1.0 (2023-06-28)

- Initial release
