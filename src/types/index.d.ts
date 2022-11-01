/**
 * Crypto type used to support Node crypto functionality.
 */
declare module 'crypto' {
  namespace webcrypto {
    const subtle: SubtleCrypto;
  }
}