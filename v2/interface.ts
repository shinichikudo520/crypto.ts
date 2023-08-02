/** RSA 算法加密解密工具的参数 */
export interface RSACryptoOps {
  publicKey: string;
  privateKey?: string;
}
/** AES 算法加密解密工具的参数 */
export interface AESCryptoOps {
  key: ArrayBuffer;
  iv: ArrayBuffer;
}
