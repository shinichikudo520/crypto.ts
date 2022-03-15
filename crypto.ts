/** crypto 支持的加密/解密算法 */
enum CRYPTO_ALGORITHM {
  /** RSA-OAEP算法 */
  RSA = 'RSA-OAEP', // RSA 是非对称密钥加密的算法
  /** CTR 模式下的 AES 算法*/
  AES_CTR = 'AES-CTR', // AES 是对称密钥加密的算法，CTR 是一种分组加密的操作模式（mode）
  /** CBC 模式下的 AES 算法*/
  AES_CBC = 'AES-CBC', // AES 是对称密钥加密的算法，CBC 是一种分组加密的操作模式（mode）
  /** GCM 模式下的 AES 算法*/
  AES_GCM = 'AES-GCM', // AES 是对称密钥加密的算法，GCM 是一种分组加密的操作模式（mode）
}
/** RSA 算法加密解密工具的参数 */
interface rsa_crypto_options {
  switchTool: boolean;
  public_key: string;
  private_key: string;
}
/** AES 算法加密解密工具的参数 */
interface aes_crypto_options {
  switchTool: boolean;
  key: string | ArrayBuffer;
  iv: string | ArrayBuffer;
}
/** 支持 ArrayBuffer 的几种类型与 string 类型互转 */
enum buffer_type {
  UINT8,
  UINT16,
}
/**
 * 支持的加密算法
1. RSA 是非对称加密，有一个公钥一个私钥
    私钥的作用是
        1. 解密
        2. 签名
    公钥的作用是
        1. 加密
        2. 验证签名

2. AES 就纯粹是加密用的，需要一个 key 一个 iv 进行加密

区别：
    1. RSA 可以直接用于加密，但是要实现加密解密不同密钥（非对称加密）速度很慢
    2. AES 就比 RSA，从加密性能来说高很多，但是加密解密必须传递密钥，无法实现全程保密
 */
enum crypto_type {
  RSA,
  AES,
}

/**
 * 加密工具抽象类
 */
abstract class CryptoHelper {
  protected switchTool: boolean;
  protected tool: SubtleCrypto;
  constructor() {
    if (!window.crypto || !window.crypto.subtle) {
      // // 如果是本地测试，只能使用 localhost , 使用 127.0.0.1 或者其他，则 window.crypto.subtle 为 undefined
      throw new Error('您的浏览器不支持 crypto api，无法为您提供加密处理');
    }
    this.tool = window.crypto.subtle;
  }
  /** 初始化函数，生成密钥对，设置开关 */
  abstract init(ops: rsa_crypto_options | aes_crypto_options): Promise<this>;
}
