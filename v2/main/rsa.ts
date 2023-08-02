import { RSACryptoOps } from "../interface";
import { buffer2str, str2buffer } from "../util/util";
import Helper from "./helper";

export default class RSACrypto extends Helper {
  /** 加密内容切割长度（单位加密长度），超过规定长度的内容将无法正常加密 */
  private readonly CONTENT_SPLIT_LENGTH = 190;
  /** 解密内容单位长度 */
  private readonly DECRYPT_SPLIT_LENGTH = 256;
  /** 公钥：用于加密内容 */
  private key: CryptoKey;
  /** 私钥：用于解密内容 */
  private privateKey: CryptoKey;

  constructor() {
    super();
  }
  /**
   * 初始化函数
   * @param options
   */
  public async init(options: RSACryptoOps): Promise<this> {
    try {
      this.key = await this.setPublicKey(options.publicKey);
      if (options.privateKey != null) {
        this.privateKey = await this.setPrivateKey(options.privateKey);
      }
      return this;
    } catch (error) {
      throw new Error(`RSACryptoHelper init error! ${error}`);
    }
  }
  /**
   * 导入公钥
   * @param {string} str string 类型，传入 base-64 编码后的字符串
   */
  private setPublicKey(
    str: string
  ): Promise<CryptoKey> | PromiseLike<CryptoKey> {
    const invalidKey = [
      `-----BEGIN PUBLIC KEY-----`,
      `-----END PUBLIC KEY-----`,
      `\\s`,
    ];
    const reg = new RegExp(invalidKey.join("|"), "ig");
    const resStr = str.replace(reg, "");
    const binaryStr = atob(resStr); // 将 base-64 编码转化成 str
    const buffer = str2buffer(binaryStr);
    return this.tool.importKey(
      FORMAT_TYPE.SPKI, // 描述要导入的密钥的数据格式，"jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
      buffer,
      {
        name: CRYPTO_ALGORITHM.RSA,
        hash: "SHA-256",
      },
      true,
      ["encrypt"] // 公钥，用于加密
    );
  }
  /**
   * 导入私钥
   * @param {string} str string 类型，传入 base-64 编码后的字符串
   */
  private setPrivateKey(
    str: string
  ): Promise<CryptoKey> | PromiseLike<CryptoKey> {
    const invalidKey = [
      `-----BEGIN PRIVATE KEY-----`,
      `-----END PRIVATE KEY-----`,
      `\\s`,
    ];
    const reg = new RegExp(invalidKey.join("|"), "ig");
    const regStr = str.replace(reg, "");
    const binaryStr = atob(regStr); // 将 base-64 编码转化成 str
    const buffer = str2buffer(binaryStr);
    return this.tool.importKey(
      FORMAT_TYPE.PKCS8, // 描述要导入的密钥的数据格式，"jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
      buffer,
      {
        name: CRYPTO_ALGORITHM.RSA,
        hash: "SHA-256",
      },
      true,
      ["decrypt"] // 私钥，用于解密
    );
  }

  /**
   * RSA 加密
   * @param content 需要加密的数据
   * @param callback 加密处理时 需要操作的回调函数
   */
  public async encrypt(
    content: string | ArrayBuffer,
    callback?: (args: any) => void
  ): Promise<ArrayBuffer> {
    try {
      if (!this.switchTool) {
        throw new Error("加密工具开关已被关闭，请打开开关后再进行操作");
      }
      const buffer =
        content instanceof ArrayBuffer ? content : str2buffer(content);
      const tasks = [] as Array<
        Promise<ArrayBuffer> | PromiseLike<ArrayBuffer>
      >;
      for (
        let i = 0, len = buffer.byteLength;
        i < len;
        i += this.CONTENT_SPLIT_LENGTH
      ) {
        const start = i;
        const end = Math.min(i + this.CONTENT_SPLIT_LENGTH, len);
        tasks.push(
          this.tool
            .encrypt(
              { name: CRYPTO_ALGORITHM.RSA },
              this.key,
              buffer.slice(start, end)
            )
            .then(
              (buf) => {
                callback && callback(buf); // args 可以自定义，比如 buf , 比如 end / len
                return buf;
              },
              (err) => {
                console.error("encrypt error", err);
                throw err;
              }
            )
        );
      }
      const bufferArr = await Promise.all(tasks);
      callback && callback(true); // args 可以自定义，比如 buf , 比如 end / len
      return concatArrayBuffer(bufferArr);
    } catch (error) {
      console.error("encrypt error", error);
      throw error;
    }
  }

  /**
   * RSA 解密
   * @param content 需要解密的数据
   * @param callback 解密处理时 需要操作的回调函数
   */
  public async decrypt(
    content: string | ArrayBuffer,
    callback?: (args: any) => void
  ): Promise<ArrayBuffer> {
    try {
      if (!this.switchTool) {
        throw new Error("加密工具开关已被关闭，请打开开关后再进行操作");
      }

      if (this.privateKey == null) {
        throw new Error("没有私钥数据, 中止解密操作");
      }

      const buf =
        content instanceof ArrayBuffer ? content : str2buffer(content);
      const buffers: Array<ArrayBuffer> = [];
      for (
        let i = 0, len = buf.byteLength;
        i < len;
        i += this.DECRYPT_SPLIT_LENGTH
      ) {
        const start = i;
        const end = Math.min(i + this.DECRYPT_SPLIT_LENGTH, len);
        buffers.push(buf.slice(start, end));
      }

      const tasks = [] as Array<
        Promise<ArrayBuffer> | PromiseLike<ArrayBuffer>
      >;
      for (const buffer of buffers) {
        tasks.push(
          this.tool.decrypt(
            { name: CRYPTO_ALGORITHM.RSA },
            this.privateKey,
            buffer
          )
        );
      }

      const bufferArr = await Promise.all(tasks);
      return concatArrayBuffer(bufferArr);
    } catch (error) {
      console.error("decrypt error", error);
      throw error;
    }
  }
}
