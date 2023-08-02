/** crypto 支持的加密/解密算法 */
export enum CRYPTO_ALGORITHM {
  /** RSA-OAEP算法 */
  RSA = "RSA-OAEP", // RSA 是非对称密钥加密的算法
  /** CTR 模式下的 AES 算法*/
  AES_CTR = "AES-CTR", // AES 是对称密钥加密的算法，CTR 是一种分组加密的操作模式（mode）
  /** CBC 模式下的 AES 算法*/
  AES_CBC = "AES-CBC", // AES 是对称密钥加密的算法，CBC 是一种分组加密的操作模式（mode）
  /** GCM 模式下的 AES 算法*/
  AES_GCM = "AES-GCM", // AES 是对称密钥加密的算法，GCM 是一种分组加密的操作模式（mode）
}

/** 支持 ArrayBuffer 的几种类型与 string 类型互转 */
enum BUFFER_TYPE {
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
enum CRYPTO_TYPE {
  RSA,
  AES,
}
