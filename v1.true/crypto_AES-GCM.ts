class CryptoHelper {
  constructor(readonly enabled = false) {}
  private key: CryptoKey; // 密钥
  private iv: Uint8Array; // 向量
  /**
   * 将 str 格式的数据转化为 uint8Array
   * @param str
   */
  private stringToUint8Array(str: string): Uint8Array {
    var arr = [];
    for (let i = 0, j = str.length; i < j; i++) {
      arr.push(str.charCodeAt(i));
    }
    return new Uint8Array(arr);
  }
  /** 是否能使用 crypto 进行加密解密 */
  private cryptoSwitch() {
    // 如果是本地测试，只能使用 localhost , 使用 127.0.0.1 或者其他，则 window.crypto.subtle 为 undefined
    return this.enabled && window.crypto.subtle !== undefined;
  }
  /** 生成密钥 */
  async deriveKey(str: string) {
    const rawKey = this.stringToUint8Array(str);
    return window.crypto.subtle.importKey('raw', rawKey, 'AES-GCM', true, [
      'encrypt',
      'decrypt',
    ]);
  }

  /**
   * 根据凭证，生成密钥，向量
   * @param keyToken 密钥凭证，可自定义
   * @param ivToken 向量凭证，可自定义
   */
  public async generateKey(keyToken: string, ivToken: string) {
    if (!this.cryptoSwitch()) return;

    this.key = await this.deriveKey(keyToken);
    this.iv = this.stringToUint8Array(ivToken);
  }
  /** 加密 API */
  private async enCryptoApi(
    ciphertext: string,
    key: CryptoKey,
    iv: Uint8Array
  ) {
    const enc = new TextEncoder();
    const encoded = enc.encode(ciphertext);
    return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  }
  /**解密 API */
  private async deCryptoApi(ciphertext: any, key: CryptoKey, iv: Uint8Array) {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  }
  /**
   * 加密
   * @param messageJSON 需要加密的数据
   * @returns
   */
  public async encrypt(messageJSON: string) {
    return this.cryptoSwitch() && messageJSON
      ? this.enCryptoApi(messageJSON, this.key, this.iv)
      : null;
  }
  /**
   * 解密
   * @param messageJSON 经过加密后需要解密的数据
   * @returns
   */
  public async decrypt(messageJSON: any) {
    return this.cryptoSwitch() && messageJSON
      ? this.deCryptoApi(messageJSON, this.key, this.iv)
      : null;
  }
}

const cryptoHelper = new CryptoHelper();
export default cryptoHelper;
