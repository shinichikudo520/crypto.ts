var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/** crypto 支持的加密/解密算法 */
var CRYPTO_ALGORITHM;
(function (CRYPTO_ALGORITHM) {
    /** RSA-OAEP算法 */
    CRYPTO_ALGORITHM["RSA"] = "RSA-OAEP";
    /** CTR 模式下的 AES 算法*/
    CRYPTO_ALGORITHM["AES_CTR"] = "AES-CTR";
    /** CBC 模式下的 AES 算法*/
    CRYPTO_ALGORITHM["AES_CBC"] = "AES-CBC";
    /** GCM 模式下的 AES 算法*/
    CRYPTO_ALGORITHM["AES_GCM"] = "AES-GCM";
})(CRYPTO_ALGORITHM || (CRYPTO_ALGORITHM = {}));
/** 支持 ArrayBuffer 的几种类型与 string 类型互转 */
var BUFFER_TYPE;
(function (BUFFER_TYPE) {
    BUFFER_TYPE[BUFFER_TYPE["UINT8"] = 0] = "UINT8";
    BUFFER_TYPE[BUFFER_TYPE["UINT16"] = 1] = "UINT16";
})(BUFFER_TYPE || (BUFFER_TYPE = {}));
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
var CRYPTO_TYPE;
(function (CRYPTO_TYPE) {
    CRYPTO_TYPE[CRYPTO_TYPE["RSA"] = 0] = "RSA";
    CRYPTO_TYPE[CRYPTO_TYPE["AES"] = 1] = "AES";
})(CRYPTO_TYPE || (CRYPTO_TYPE = {}));
var FORMAT_TYPE;
(function (FORMAT_TYPE) {
    FORMAT_TYPE["RAW"] = "raw";
    FORMAT_TYPE["PKCS8"] = "pkcs8";
    FORMAT_TYPE["SPKI"] = "spki";
    FORMAT_TYPE["JWK"] = "jwk";
})(FORMAT_TYPE || (FORMAT_TYPE = {}));
/**
 * 加密工具抽象类
 */
class CryptoHelper {
    constructor() {
        this._switchTool = true;
        if (!window.crypto || !window.crypto.subtle) {
            // // 如果是本地测试，只能使用 localhost , 使用 127.0.0.1 或者其他，则 window.crypto.subtle 为 undefined
            throw new Error('您的浏览器不支持 crypto api，无法为您提供加密处理');
        }
        this.tool = window.crypto.subtle;
    }
    /**
     * str ==> ArrayBuffer
     * @param str 需要转化的 string 类型数据
     * @param bufType 需要转化的 ArrayBuffer 数据类型
     */
    str2buffer(str, bufType = BUFFER_TYPE.UINT8) {
        let buf;
        let bufView;
        switch (bufType) {
            case BUFFER_TYPE.UINT8: {
                buf = new ArrayBuffer(str.length);
                bufView = new Uint8Array(buf);
                break;
            }
            case BUFFER_TYPE.UINT16: {
                buf = new ArrayBuffer(str.length);
                bufView = new Uint16Array(buf);
                break;
            }
            default: {
                console.warn('bufType参数错误，使用默认 uint8');
                buf = new ArrayBuffer(str.length);
                bufView = new Uint8Array(buf);
                break;
            }
        }
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }
    /**
     * ArrayBuffer => string
     * @param buffer 需要转化的 ArrayBuffer 类型数据
     * @param bufType 需要转化的 ArrayBuffer 数据类型
     */
    buffer2str(buffer, bufType = BUFFER_TYPE.UINT8) {
        let arr;
        switch (bufType) {
            case BUFFER_TYPE.UINT8: {
                arr = new Uint8Array(buffer);
                break;
            }
            case BUFFER_TYPE.UINT16: {
                arr = new Uint16Array(buffer);
                break;
            }
            default: {
                console.warn('bufType参数错误，使用默认 uint8');
                arr = new Uint8Array(buffer);
                break;
            }
        }
        return String.fromCharCode.apply(null, arr);
    }
    /** 设置开关 */
    set switchTool(val) {
        this._switchTool = val;
    }
    /** 获取开关 */
    get switchTool() {
        return this._switchTool;
    }
}
class RSACryptoHelper extends CryptoHelper {
    constructor() {
        super();
        /** 加密内容切割长度（单位加密长度），超过规定长度的内容将无法正常加密 */
        this.ENCRYPT_SPLIT_LENGTH = 190;
        /** 解密内容单位长度 */
        this.DECRYPT_SPLIT_LENGTH = 256;
    }
    /**
     * 导入公钥
     * @param str string 类型，传入 base-64 编码后的字符串
     */
    setPublicKey(str) {
        const invalidKey = [
            `-----BEGIN PUBLIC KEY-----`,
            `-----END PUBLIC KEY-----`,
            `\\s`,
        ];
        const reg = new RegExp(invalidKey.join('|'), 'ig');
        const resStr = str.replace(reg, '');
        const binaryStr = atob(resStr); // 将 base-64 编码转化成 str
        const buffer = this.str2buffer(binaryStr, BUFFER_TYPE.UINT8);
        return this.tool.importKey(FORMAT_TYPE.SPKI, // 描述要导入的密钥的数据格式，"jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
        buffer, {
            name: CRYPTO_ALGORITHM.RSA,
            hash: 'SHA-256',
        }, true, ['encrypt'] // 公钥，用于加密
        );
    }
    /**
     * 导入私钥
     * @param str string 类型，传入 base-64 编码后的字符串
     */
    setPrivateKey(str) {
        const invalidKey = [
            `-----BEGIN PRIVATE KEY-----`,
            `-----END PRIVATE KEY-----`,
            `\\s`,
        ];
        const reg = new RegExp(invalidKey.join('|'), 'ig');
        const regStr = str.replace(reg, '');
        const binaryStr = atob(regStr); // 将 base-64 编码转化成 str
        const buffer = this.str2buffer(binaryStr, BUFFER_TYPE.UINT8);
        return this.tool.importKey(FORMAT_TYPE.PKCS8, // 描述要导入的密钥的数据格式，"jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
        buffer, {
            name: CRYPTO_ALGORITHM.RSA,
            hash: 'SHA-256',
        }, true, ['decrypt'] // 私钥，用于解密
        );
    }
    /**
     * 初始化函数，生成密钥对
     * @param ops
     */
    init(ops) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this.publicKey = yield this.setPublicKey(ops.public_key);
                this.privateKey = yield this.setPrivateKey(ops.private_key);
                console.log('RSACryptoHelper init...完毕!!!');
                return this;
            }
            catch (error) {
                console.error('RSACryptoHelper init...error', error);
            }
        });
    }
    /**
     * RSA 加密
     * @param content 需要加密的数据
     * @param cb 加密处理时 需要操作的回调函数
     */
    encrypt(content, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!this.switchTool) {
                    throw new Error('加密工具开关已被关闭，请打开开关后再进行操作');
                }
                const buffer = content instanceof ArrayBuffer ? content : this.str2buffer(content);
                const tasks = [];
                for (let i = 0, len = buffer.byteLength; i < len; i += this.ENCRYPT_SPLIT_LENGTH) {
                    const start = i;
                    const end = Math.min(i + this.ENCRYPT_SPLIT_LENGTH, len);
                    tasks.push(this.tool
                        .encrypt({ name: CRYPTO_ALGORITHM.RSA }, this.publicKey, buffer.slice(start, end))
                        .then((buf) => {
                        cb && cb(buf); // args 可以自定义，比如 buf , 比如 end / len
                        return buf;
                    }, (err) => {
                        console.error('encrypt error', err);
                        throw err;
                    }));
                    const bufferArr = yield Promise.all(tasks);
                    cb && cb(true); // args 可以自定义，比如 buf , 比如 end / len
                    return concatArrayBuffer(bufferArr);
                }
            }
            catch (error) {
                console.error('encrypt error', error);
            }
        });
    }
    /**
     * RSA 解密
     * @param content 需要解密的数据
     * @param cb 解密处理时 需要操作的回调函数
     */
    decrypt(content, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!this.switchTool) {
                    throw new Error('加密工具开关已被关闭，请打开开关后再进行操作');
                }
                const buf = content instanceof ArrayBuffer ? content : this.str2buffer(content);
                const buffers = [];
                for (let i = 0, len = buf.byteLength; i < len; i += this.DECRYPT_SPLIT_LENGTH) {
                    const start = i;
                    const end = Math.min(i + this.DECRYPT_SPLIT_LENGTH, len);
                    buffers.push(buf.slice(start, end));
                }
                const tasks = [];
                for (const buffer of buffers) {
                    tasks.push(this.tool.decrypt({ name: CRYPTO_ALGORITHM.RSA }, this.privateKey, buffer));
                }
                const bufferArr = yield Promise.all(tasks);
                return this.buffer2str(concatArrayBuffer(bufferArr));
            }
            catch (error) {
                console.error('decrypt error', error);
            }
        });
    }
}
class AESGCMCryptoHelper extends CryptoHelper {
    constructor() {
        super();
    }
    /**
     * 初始化密钥的 ArrayBuffer 格式
     * @param key 作为密钥的数据
     * @returns
     */
    setKeyBuffer(key) {
        return typeof key === 'string'
            ? this.str2buffer(key, BUFFER_TYPE.UINT8)
            : key;
    }
    /**
     * 导入密钥
     * @param key 作为密钥的数据
     */
    setKey(key) {
        const buffer = typeof key === 'string' ? this.str2buffer(key, BUFFER_TYPE.UINT8) : key;
        return this.tool.importKey(FORMAT_TYPE.RAW, buffer, CRYPTO_ALGORITHM.AES_GCM, true, ['encrypt', 'decrypt']); // 使用 AES 算法时导入密钥使用 'raw' 数据格式
    }
    /**
     * 导入向量
     * @param iv 作为向量的数据
     */
    setIv(iv) {
        return typeof iv === 'string' ? this.str2buffer(iv, BUFFER_TYPE.UINT8) : iv;
    }
    /**
     * 初始化函数，生成密钥和向量
     * @param ops
     */
    init(ops) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this._keyBuffer = this.setKeyBuffer(ops.key);
                this._key = yield this.setKey(this._keyBuffer);
                this._iv = this.setIv(ops.iv);
                console.log('AESGCMCryptoHelper init...完毕!!!');
                return this;
            }
            catch (error) {
                console.error('AESGCMCryptoHelper init...error', error);
            }
        });
    }
    /**
     * AES-GCM 加密
     * @param content 需要加密的数据
     * @param cb 加密处理时 需要操作的回调函数
     */
    encrypt(content, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!this.switchTool) {
                    throw new Error('加密工具开关已被关闭，请打开开关后再进行操作');
                }
                const buffer = content instanceof ArrayBuffer ? content : this.str2buffer(content);
                cb && cb(true);
                return this.tool.encrypt({ name: CRYPTO_ALGORITHM.AES_GCM, iv: this._iv }, this._key, buffer);
            }
            catch (error) {
                console.error('encrypt error', error);
            }
        });
    }
    /**
     * AES-GCM 解密
     * @param content 需要解密的数据
     * @param cb 解密处理时 需要操作的回调函数
     */
    decrypt(content, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!this.switchTool) {
                    throw new Error('加密工具开关已被关闭，请打开开关后再进行操作');
                }
                const buffer = content instanceof ArrayBuffer ? content : this.str2buffer(content);
                cb && cb(true);
                const decrypted = yield this.tool.decrypt({ name: CRYPTO_ALGORITHM.AES_GCM, iv: this._iv }, this._key, buffer);
                return this.buffer2str(decrypted);
            }
            catch (error) {
                console.error('decrypt error', error);
            }
        });
    }
    get keyBuffer() {
        return this._keyBuffer;
    }
    get key() {
        return this._key;
    }
    get iv() {
        return this._iv;
    }
}
/**
 * 合并 ArrayBuffer
 * @param bufferArr ArrayBuffer 数据数组
 */
function concatArrayBuffer(bufferArr) {
    const len = bufferArr.reduce((len, buffer) => len + buffer.byteLength, 0);
    const u8arr = new Uint8Array(len);
    let start = 0;
    for (const buffer of bufferArr) {
        u8arr.set(new Uint8Array(buffer), start);
        start += buffer.byteLength;
    }
    return u8arr.buffer;
}
// 生成 RSA 算法--spki 公钥--pkcs8 私钥
function getRsaKeys() {
    return new Promise((resolve, reject) => {
        window.crypto.subtle
            .generateKey({
            name: CRYPTO_ALGORITHM.RSA,
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        }, true, //whether the key is extractable (i.e. can be used in exportKey)
        ['encrypt', 'decrypt'] //must be ["encrypt", "decrypt"] or ["wrapKey", "unwrapKey"]
        )
            .then(function (key) {
            window.crypto.subtle
                .exportKey(FORMAT_TYPE.PKCS8, key.privateKey) // pkcs8 格式私钥 ,PKCS8（ASN.1的PrivateKeyInfo，私钥
                .then(function (keydata1) {
                window.crypto.subtle
                    .exportKey(FORMAT_TYPE.SPKI, key.publicKey) // spki 格式公钥，使用 spki ，它代表“受管主题”，标准ASN.1序列化公钥的结构
                    .then(function (keydata2) {
                    var privateKey = RSA2text(keydata1, 1);
                    var publicKey = RSA2text(keydata2);
                    resolve({ privateKey, publicKey });
                })
                    .catch(function (err) {
                    reject(err);
                });
            })
                .catch(function (err) {
                reject(err);
            });
        })
            .catch(function (err) {
            reject(err);
        });
    });
}
function RSA2text(buffer, isPrivate = 0) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    var base64 = window.btoa(binary);
    var text = '-----BEGIN ' + (isPrivate ? 'PRIVATE' : 'PUBLIC') + ' KEY-----\n';
    text += base64
        .replace(/[^\x00-\xff]/g, '$&\x01')
        .replace(/.{64}\x01?/g, '$&\n');
    text += '\n-----END ' + (isPrivate ? 'PRIVATE' : 'PUBLIC') + ' KEY-----';
    return text;
}
/**-------------- test code--------------------------- */
/** test RSA 算法加密... */
// 可以使用任意网络工具生成，比如：http://www.metools.info/code/c80.html
const KEY = {
    PUBLIC: `
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5EeM7xS4zlkC1pf5aRVB
  bGRFU6bzXYzmevlhtzuqsW2oGYoZFmvviY73d1YIuXwB8kjZKbF7jqBH7fFax6Bv
  D0x9rVdySFiczYkJ4hEEsTKxG1Chtu/7qz2Q4YrOaGprP74OYSi8DIbLv2WeqsZH
  Q1y+ksf0Wuwg4DmBs6aN7p7uv2eUX3R98XiIN58NrZsSFg3O4/v97suL4t9FvREq
  yc3dmJWOPMdOPoTIJDaotBJ+yMPgwmUR7SIjGnl5KH4ArDZcHhmVTI1JK2lVKPWn
  FfsnFnRNkDfE4Ipq/mUbTsom9LoKFf0v7GiyUSZter8zNiIv3vXd7dMGIBPFtijk
  ZwIDAQAB
  -----END PUBLIC KEY-----
  `,
    PRIVATE: `
  -----BEGIN PRIVATE KEY-----
  MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkR4zvFLjOWQLW
  l/lpFUFsZEVTpvNdjOZ6+WG3O6qxbagZihkWa++Jjvd3Vgi5fAHySNkpsXuOoEft
  8VrHoG8PTH2tV3JIWJzNiQniEQSxMrEbUKG27/urPZDhis5oams/vg5hKLwMhsu/
  ZZ6qxkdDXL6Sx/Ra7CDgOYGzpo3unu6/Z5RfdH3xeIg3nw2tmxIWDc7j+/3uy4vi
  30W9ESrJzd2YlY48x04+hMgkNqi0En7Iw+DCZRHtIiMaeXkofgCsNlweGZVMjUkr
  aVUo9acV+ycWdE2QN8Tgimr+ZRtOyib0ugoV/S/saLJRJm16vzM2Ii/e9d3t0wYg
  E8W2KORnAgMBAAECggEAPNkpouzWGgK18/eMfsswpjDQHe0pf604Hl1tA4d/B05g
  eXZLG6PntLYMFp4zMyXv6uIqKKfrdGga5DzqYr3L/Lr54QOnLcuY+Fxn6v94Tbdi
  aBKFGJs9bTa68LOsMz7ymYoSkSlnfrtLghgXRBQYGMeW8M8lvjqkxL/vZ7Ckso7f
  yolS8rUf4zbgykhro1QPCsWwSvjiWyKpn2NPlXCWM3VC754xkqxgw352ssC7xoe1
  5sQuenSme6kDd6J+7VlW8zr2NpC9C2eQ0PM69BVl7cmoKCppQnwBpJsyrKTuNh0r
  GXgbPVFvksJbqwS13boY/6BcEWZM+xU3equY9Z5JKQKBgQD5ah2Oc9d2yJqwkPw8
  e4g7UB2ogRIPiNhE43lOknD2sAGw+H1c4POswt3yXIZb1AnvJgSYnA4xHJaqGjz5
  MEpsFbOU45Kk4ygtf3PCl3MYwGAuP+JjCrLIMK36wJ0G5RfW96P81ObJdGL9zNxN
  SdOjZkeH8uG25I9gt10hObfUywKBgQDqTpNgaWCkgBgBkz62li7h3oDGSXTOs0Cv
  pRkaV04R9H64JyYVHxHY94mrdF8P/xCKney1EUsny++ertD4qqGSrKt3pZRECwLF
  4GR6vEvKtVW3LH7up9nkv0PstF8vSeQAukIqitz4g1YqurX/21aWe9le7nZGDeCl
  g2XyCOMXVQKBgQDDMNnKtzvjeSEel4jfaKn4CT38tm5E/AqM9xzjcdW4KYxZTE8H
  1gC9ro918hUwXmQb5bvpFxBAPShoHTqkpbdImT8+gU8tfZze5oTYwB/SOhPLfjGU
  4zWBWB+AQydg0v9yO8H5x0CKXmxuRdoPHnzjvtKyQVGGCZ9vyHC45OvKOwKBgFfv
  bXg9lDuop1nP/TVhX+79Jq9EWkZJF/nTqHwuT+qFLBnI943tvzEClfR3FEZYn8im
  RHQgLWieLSwMx/jLcSAvFZst1VtEFqJU+ODnUjqdm7HHTUwcSraC4ecwOpjwzlVH
  khWNUCkkgW4/7JY9p12K1aW/MTxRcQItMlGH7FKRAoGBAJ1rjojUB5Z7zWYt+edF
  XzvwwAppIgv2C/n1cTdLJnOOBYBiFFAA18/rhVIem/uw2/7ezV8GN9YH0vy74LXf
  I0Lxae85s1mPpQRxv54nQn/1csheRUV1zXIy6rU4xrEwVawNOfRDmTp3yiYRd/ct
  Z7R6xD+unAOXFCdmOEpV5R1G
  -----END PRIVATE KEY-----
  `, // 私钥可以自定义为 `-----BEGIN PRIVATE KEY-----${base-64-str}-----END PRIVATE KEY-----` 格式的字符串
};
function testRSA() {
    return __awaiter(this, void 0, void 0, function* () {
        const rsa = new RSACryptoHelper();
        const { privateKey, publicKey } = yield getRsaKeys(); // 生成 公钥私钥，如果生成失败，则使用默认密钥对
        yield rsa.init({
            public_key: publicKey || KEY.PUBLIC,
            private_key: privateKey || KEY.PRIVATE,
        });
        const data = yield rsa.encrypt('hello world');
        const str = yield rsa.decrypt(data);
        console.log('test rsa...', str);
    });
}
testRSA();
function testAES() {
    return __awaiter(this, void 0, void 0, function* () {
        const aes = new AESGCMCryptoHelper();
        const key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ||
            crypto.getRandomValues(new Uint8Array(16)).buffer; // 可以用户自定义(AES key data must be 128 or 256 bits)，可以随机生成
        const iv = 'bbbb' || crypto.getRandomValues(new Uint8Array(16)).buffer; // // 可以用户自定义，可以随机生成
        yield aes.init({ key, iv }); // AES key data must be 128 or 256 bits
        const data = yield aes.encrypt('hello world');
        const str = yield aes.decrypt(data);
        console.log('test aes...', str);
    });
}
testAES();
