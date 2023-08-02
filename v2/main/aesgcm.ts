import { CRYPTO_ALGORITHM } from "../enum";
import { AESCryptoOps } from "../interface";
import Helper from "./helper";

/**
 * 基于 AES-GCM 进行加密解密的工具类
 */
export default class AESCrypto extends Helper {
  private keyBuffer: ArrayBuffer;
  private key: CryptoKey;
  private iv: ArrayBuffer;

  constructor() {
    super();
  }

  /**
   * 初始化
   * @param options
   * @returns
   */
  public async init(options: AESCryptoOps): Promise<this> {
    try {
      this.keyBuffer = options.key;
      this.key = await this.setKey(this.keyBuffer);
      this.iv = await this.setIV(options.iv);
      return this;
    } catch (error) {
      throw new Error(`invalid key or iv! ${options}`);
    }
  }
  /**
   * 导入公共密钥
   * @param buffer
   * @returns
   */
  private setKey(
    buffer: ArrayBuffer
  ): Promise<CryptoKey> | PromiseLike<CryptoKey> {
    if (buffer instanceof ArrayBuffer) {
      return this.tool.importKey(
        "raw",
        buffer,
        CRYPTO_ALGORITHM.AES_GCM,
        true,
        ["encrypt", "decrypt"]
      );
    } else {
      throw new Error(`invalid key! ${buffer}`);
    }
  }
  /**
   * 导入向量
   * @param buffer
   * @returns
   */
  private setIV(buffer: ArrayBuffer): ArrayBuffer {
    if (buffer instanceof ArrayBuffer) {
      return buffer;
    } else {
      throw new Error(`invalid iv! ${buffer}`);
    }
  }
  /**
   * AES-GCM 算法加密
   * @param buffer 内容
   * @returns
   */
  public encrypt(
    buffer: ArrayBuffer
  ): Promise<ArrayBuffer> | PromiseLike<ArrayBuffer> {
    return this.tool.encrypt(
      { name: CRYPTO_ALGORITHM.AES_GCM, iv: this.iv },
      this.key,
      buffer
    );
  }
  /**
   * AES-GCM 算法解密
   * @param buffer 内容
   * @returns
   */
  public decrypt(
    buffer: ArrayBuffer
  ): Promise<ArrayBuffer> | PromiseLike<ArrayBuffer> {
    return this.tool.decrypt(
      { name: CRYPTO_ALGORITHM.AES_GCM, iv: this.iv },
      this.key,
      buffer
    );
  }

  /**
   * 获取公共密钥
   * @returns ArrayBuffer
   */
  public getKey(): ArrayBuffer {
    return this.keyBuffer;
  }
  /**
   * 获取公共向量
   * @returns ArrayBuffer
   */
  public getIV(): ArrayBuffer {
    return this.iv;
  }
}
